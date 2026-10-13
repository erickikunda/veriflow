"""Joern discovery profile catalog: packaged, trusted-directory and approved-registry bindings."""

import hashlib
import json
import re
import stat
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from veriflow.domain import VeriFlowError

# Behaviour that needs Python support code; only packaged profiles may name these hooks.
PACKAGED_HOOKS = {"flask_endpoints", "csharp_query_source"}
SELECTIONS = {"auto", "explicit"}
MODES = ("trusted-directory", "approved")
DEFAULT_MODE = "trusted-directory"
LANGUAGES = ("java", "csharp", "python", "javascript", "typescript", "go", "rust", "c", "cpp")
MAX_DESCRIPTOR_BYTES = 32 * 1024
MAX_QUERY_BYTES = 1024 * 1024
DESCRIPTOR = "profile.json"
NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{1,78}-v[1-9][0-9]{0,3}$"


@dataclass(frozen=True)
class Binding:
    """One profile bound to one language; everything discover needs except tool paths."""

    name: str
    language: str
    rule_id: str
    query: str
    message: str
    cwe_scope: tuple[str, ...] | None
    limitations: tuple[str, ...]
    selection: str
    hooks: dict
    source: str
    query_sha256: str
    query_path: Path | None = None
    internal_pattern: dict | None = None
    draft_id: str | None = None
    review_gate: str | None = None

    @property
    def profile(self):
        """Profile value as stored on attempts; None selects the language default."""
        return None if self.name == "default" else self.name


@dataclass(frozen=True)
class Catalog:
    bindings: tuple[Binding, ...]
    mode: str = DEFAULT_MODE
    directory: str | None = None
    registry_version: int = 0
    problems: tuple[dict, ...] = ()
    ignored: tuple[str, ...] = field(default=())


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class InternalPattern(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    title: str = Field(min_length=1, max_length=200)


class Weakness(StrictModel):
    cwe: list[str] = Field(default_factory=list, max_length=10)
    internal_pattern: InternalPattern | None = None

    @model_validator(mode="after")
    def named(self):
        if any(not re.fullmatch(r"CWE-[1-9][0-9]{0,4}", c) for c in self.cwe):
            raise ValueError("CWE entries must look like CWE-79")
        if not self.cwe and self.internal_pattern is None:
            raise ValueError("a profile needs a CWE or an internal pattern")
        return self


class FixtureSpec(StrictModel):
    kind: Literal["vulnerable", "fixed", "misleading"]
    file: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
    expected_flows: int | None = Field(default=None, ge=0, le=1000)


class RuntimeDescriptor(StrictModel):
    """Operator-authored profile; it can only add a query and wording, never Python hooks."""

    schema_version: Literal["1"]
    name: str = Field(pattern=NAME_PATTERN)
    language: Literal[LANGUAGES]
    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,39}/[a-z0-9][a-z0-9._-]{2,119}$")
    query: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.sc$")
    message: str = Field(min_length=1, max_length=200)
    limitations: list[str] = Field(min_length=1, max_length=12)
    selection: Literal["auto", "explicit"] = "auto"
    # Default gate: native path consistency only; "none" leaves advisories ungated (abstain).
    review_gate: Literal["runtime-native-v1", "none"] = "runtime-native-v1"
    weakness: Weakness
    fixtures: list[FixtureSpec] = Field(default_factory=list, max_length=12)

    @model_validator(mode="after")
    def reserved(self):
        if self.rule_id.startswith("veriflow/"):
            raise ValueError("the veriflow/ rule namespace is reserved for packaged profiles")
        if any(not item.strip() or len(item) > 300 for item in self.limitations):
            raise ValueError("limitations must be nonblank and at most 300 characters")
        if not self.message.strip():
            raise ValueError("message must be nonblank")
        return self


def parse_descriptor(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return RuntimeDescriptor.model_validate(json.loads(raw, object_pairs_hook=pairs))
    except ValidationError as exc:
        # Field locations and messages only; input values are never echoed.
        detail = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'descriptor'}: {e['msg']}"
            for e in exc.errors(include_input=False, include_url=False)
        )
        raise VeriFlowError(f"Invalid profile descriptor: {detail}") from None
    except (ValueError, TypeError, RecursionError):
        raise VeriFlowError("Invalid profile descriptor: not strict JSON") from None


def runtime_binding(descriptor, source, query_path, query_sha256, draft_id=None):
    weakness = descriptor.weakness
    return Binding(
        name=descriptor.name,
        language=descriptor.language,
        rule_id=descriptor.rule_id,
        query=descriptor.query,
        message=descriptor.message,
        cwe_scope=tuple(weakness.cwe) or None,
        limitations=(
            *descriptor.limitations,
            f"Runtime profile ({source}); default native-consistency gate only; discovery only."
            if descriptor.review_gate != "none"
            else f"Runtime profile ({source}); no advisory gate; discovery only.",
        ),
        selection=descriptor.selection,
        hooks={},
        source=source,
        query_sha256=query_sha256,
        query_path=query_path,
        internal_pattern=(
            weakness.internal_pattern.model_dump() if weakness.internal_pattern else None
        ),
        draft_id=draft_id,
        review_gate=None if descriptor.review_gate == "none" else descriptor.review_gate,
    )


def _bindings(document, source):
    if document.get("schema_version") != "1" or document.get("engine") != "joern":
        raise VeriFlowError("Unsupported Joern profile catalog")
    for entry in document["profiles"]:
        hooks = entry.get("hooks") or {}
        if set(hooks) - PACKAGED_HOOKS or (hooks and source != "packaged"):
            raise VeriFlowError("Profile hooks are limited to packaged profiles")
        if entry["selection"] not in SELECTIONS or not entry["limitations"]:
            raise VeriFlowError("Profile needs a valid selection and at least one limitation")
        for language, binding in entry["bindings"].items():
            query = files("veriflow").joinpath(f"queries/{binding['query']}").read_bytes()
            yield Binding(
                name=entry["name"],
                language=language,
                rule_id=binding["rule_id"],
                query=binding["query"],
                message=entry["message"],
                cwe_scope=None if entry["cwe_scope"] is None else tuple(entry["cwe_scope"]),
                limitations=tuple(entry["limitations"]),
                selection=entry["selection"],
                hooks=hooks,
                source=source,
                query_sha256=hashlib.sha256(query).hexdigest(),
            )


@cache
def packaged():
    """Ordered bindings shipped in the wheel; order is the automatic selection order."""
    raw = files("veriflow").joinpath("profiles/joern-packaged.json").read_text()
    bindings = tuple(_bindings(json.loads(raw), "packaged"))
    seen = set()
    for binding in bindings:
        key = (binding.language, binding.name)
        if key in seen:
            raise VeriFlowError("Duplicate packaged Joern profile binding")
        seen.add(key)
    return bindings


def _regular(path, limit):
    """Bytes of an operator file that no other local user could have replaced."""
    try:
        info = path.lstat()
    except OSError:
        raise VeriFlowError(f"{path.name} is missing") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise VeriFlowError(f"{path.name} must be a regular file, not a link")
    if info.st_mode & stat.S_IWOTH:
        raise VeriFlowError(f"{path.name} is world-writable")
    if info.st_size > limit:
        raise VeriFlowError(f"{path.name} exceeds its size limit")
    return path.read_bytes()


def _directory_profile(folder):
    info = folder.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise VeriFlowError("profile entry must be a real directory")
    if info.st_mode & stat.S_IWOTH:
        raise VeriFlowError("profile directory is world-writable")
    descriptor = parse_descriptor(_regular(folder / DESCRIPTOR, MAX_DESCRIPTOR_BYTES))
    if descriptor.name != folder.name:
        raise VeriFlowError("profile directory name must equal the descriptor name")
    query = _regular(folder / descriptor.query, MAX_QUERY_BYTES)
    return runtime_binding(
        descriptor,
        "trusted_directory",
        folder / descriptor.query,
        hashlib.sha256(query).hexdigest(),
    )


def load_directory(directory, store_root):
    """Profiles from the trusted directory; a bad entry is reported, never fatal to others."""
    if directory is None or not directory.exists():
        return [], []
    root = directory.resolve(strict=True)
    if any(root.is_relative_to(store_root / part) for part in ("artifacts", "scans")):
        return [], [
            {
                "profile": None,
                "source": "trusted_directory",
                "problem": "profile directory cannot be inside scanned source or scans",
            }
        ]
    bindings, problems = [], []
    for folder in sorted(root.iterdir()):
        if folder.name.startswith("."):
            continue
        try:
            bindings.append(_directory_profile(folder))
        except (VeriFlowError, OSError) as exc:
            problem = str(exc) if isinstance(exc, VeriFlowError) else "profile is unreadable"
            problems.append(
                {"profile": folder.name, "source": "trusted_directory", "problem": problem}
            )
    return bindings, problems


def load_registry(store):
    """Approved runtime profiles from the latest registry version."""
    from sqlalchemy import select

    from veriflow.persistence import RuleRegistry

    with store.transaction() as session:
        latest = session.scalar(select(RuleRegistry).order_by(RuleRegistry.version.desc()).limit(1))
        if latest is None:
            return [], [], 0
        version, rules = latest.version, list(latest.content.get("rules", []))
    bindings, problems = [], []
    for rule in rules:
        if rule.get("engine") != "joern" or "descriptor" not in rule:
            continue
        try:
            data = dict(rule["descriptor"])
            # The gate is part of what was approved; an entry without one stays ungated.
            data.setdefault("review_gate", "none")
            descriptor = RuntimeDescriptor.model_validate(data)
            path = store.root / "profile-drafts" / rule["draft_id"] / descriptor.query
            if not path.is_file() or path.is_symlink():
                raise VeriFlowError("approved query file is missing")
            bindings.append(
                runtime_binding(
                    descriptor, "registry", path, rule["query_sha256"], rule["draft_id"]
                )
            )
        except (ValidationError, VeriFlowError) as exc:
            problem = str(exc) if isinstance(exc, VeriFlowError) else "invalid approved descriptor"
            problems.append(
                {"profile": rule.get("profile"), "source": "registry", "problem": problem}
            )
    return bindings, problems, version


def resolve(store):
    """Packaged + approved registry, plus the trusted directory unless the mode is approved."""
    mode = getattr(store, "profile_mode", None) or DEFAULT_MODE
    if mode not in MODES:
        raise VeriFlowError("Profile mode must be trusted-directory or approved")
    directory = getattr(store, "profiles_dir", None) or store.root / "profiles"
    registry, problems, version = load_registry(store)
    ignored = []
    if mode == "trusted-directory":
        local, local_problems = load_directory(directory, store.root)
        problems += local_problems
    else:
        local = []
        if directory.is_dir():
            ignored = sorted(p.name for p in directory.iterdir() if not p.name.startswith("."))
    base = packaged()
    packaged_names = {b.name for b in base}
    packaged_rules = {b.rule_id for b in base}
    approved = {b.name for b in registry}
    accepted, rules = [], set(packaged_rules)
    # Registry first: an approved profile is never displaced by a directory profile.
    for binding in registry + local:
        problem = (
            "name is reserved by a packaged profile"
            if binding.name in packaged_names
            else "name is used by an approved registry profile, which stays active"
            if binding.source == "trusted_directory" and binding.name in approved
            else "rule_id is already used by another profile"
            if binding.rule_id in rules
            else None
        )
        if problem:
            problems.append({"profile": binding.name, "source": binding.source, "problem": problem})
            continue
        rules.add(binding.rule_id)
        accepted.append(binding)
    return Catalog(
        bindings=base + tuple(accepted),
        mode=mode,
        directory=str(directory),
        registry_version=version,
        problems=tuple(problems),
        ignored=tuple(ignored),
    )


def catalog(store=None):
    """The catalog for one command; resolved once per store so a run sees one snapshot."""
    if store is None or not getattr(store, "database", None) or not store.database.is_file():
        return Catalog(bindings=packaged())
    cached = getattr(store, "_joern_catalog", None)
    if cached is None:
        cached = resolve(store)
        store._joern_catalog = cached
    return cached


def binding(language, profile=None, store=None):
    """The binding for (language, profile); profile None is the language default."""
    name = profile or "default"
    current = catalog(store)
    for candidate in current.bindings:
        if (
            candidate.language == language
            and candidate.name == name
            and (profile is None or name != "default")
        ):
            return candidate
    for problem in current.problems:
        if problem["profile"] == name:
            raise VeriFlowError(f"Profile {name} is not active: {problem['problem']}")
    raise VeriFlowError("Unsupported Joern discovery profile/language")


def auto_plan(store=None, *, runtime_only=False):
    """Language -> ordered profiles for --joern-profile auto; None is the language default."""
    plan = {}
    for candidate in catalog(store).bindings:
        if candidate.selection == "auto" and not (runtime_only and candidate.source == "packaged"):
            plan.setdefault(candidate.language, []).append(candidate.profile)
    return {language: tuple(profiles) for language, profiles in plan.items()}


def message_for(rule, language, store=None):
    """Candidate wording for a rule; unknown rules fall back to the language default."""
    for candidate in catalog(store).bindings:
        if candidate.rule_id == rule:
            return candidate.message
    return binding(language).message


def read_query(binding):
    """Query bytes, checked against the digest recorded when the catalog was loaded."""
    if binding.query_path is None:
        return files("veriflow").joinpath(f"queries/{binding.query}").read_bytes()
    payload = _regular(binding.query_path, MAX_QUERY_BYTES)
    if hashlib.sha256(payload).hexdigest() != binding.query_sha256:
        raise VeriFlowError("Runtime profile query changed after the catalog was loaded")
    return payload


def summary(store=None):
    """Operator view of the effective catalog; no tool is run."""
    current = catalog(store)
    return {
        "schema_version": "1",
        "report_kind": "joern_profile_catalog",
        "mode": current.mode,
        "directory": current.directory,
        "registry_version": current.registry_version,
        "profiles": [
            {
                "name": b.name,
                "language": b.language,
                "source": b.source,
                "selection": b.selection,
                "rule_id": b.rule_id,
                "cwe_scope": list(b.cwe_scope or []),
                "internal_pattern": b.internal_pattern,
                "query_sha256": b.query_sha256,
                "draft_id": b.draft_id,
                "review_gate": b.review_gate,
            }
            for b in current.bindings
        ],
        "problems": list(current.problems),
        "ignored_directory_profiles": list(current.ignored),
        "scope": "Profiles select candidates only; none confirms or excludes a weakness",
    }
