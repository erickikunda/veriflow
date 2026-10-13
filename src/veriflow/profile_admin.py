"""Runtime Joern profile lifecycle: scaffold, draft, executed fixture test, approval, disable."""

import hashlib
import json
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from veriflow import joern_profiles
from veriflow.bundles import canonical
from veriflow.domain import Digest, VeriFlowError
from veriflow.intake import now
from veriflow.persistence import (
    ProfileApproval,
    ProfileDraft,
    ProfileTest,
    RuleRegistry,
    Store,
    exclusive_worker,
)

MAX_FIXTURE_BYTES = 1024 * 1024
MAX_FIXTURE_TOTAL_BYTES = 4 * 1024 * 1024
MAX_FIXTURE_FILES = 50
KINDS = ("vulnerable", "fixed", "misleading")
DRAFTS = "profile-drafts"


class ProfileApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    draft_sha256: Digest
    expected_registry_version: int = Field(ge=0)
    reviewer_label: str = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def meaningful(self):
        if not self.reviewer_label.strip() or not self.rationale.strip():
            raise ValueError("reviewer and rationale must be nonblank")
        return self


def read_approval(path):
    from veriflow.rule_registry import _read_json

    return _read_json(path, ProfileApprovalRequest, "profile approval request")


def _suffixes(language):
    from veriflow.joern import SUFFIXES

    value = SUFFIXES[language]
    return value if isinstance(value, tuple) else (value,)


def _fixture_files(path):
    """(relative path, bytes) of one fixture file or folder; links are never followed."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise VeriFlowError("Fixtures cannot be links")
    if stat.S_ISREG(info.st_mode):
        return [(path.name, joern_profiles._regular(path, MAX_FIXTURE_BYTES))]
    if not stat.S_ISDIR(info.st_mode):
        raise VeriFlowError("Fixtures must be files or folders")
    found = []
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise VeriFlowError("Fixture folders cannot contain links")
        if item.is_file():
            found.append(
                (
                    item.relative_to(path).as_posix(),
                    joern_profiles._regular(item, MAX_FIXTURE_BYTES),
                )
            )
        if len(found) > MAX_FIXTURE_FILES:
            raise VeriFlowError("A fixture folder may hold at most 50 files")
    return found


def _tree_digest(entries):
    return hashlib.sha256(
        canonical([[name, hashlib.sha256(payload).hexdigest()] for name, payload in entries])
    ).hexdigest()


def read_profile_folder(folder):
    """Descriptor, query and fixtures of a profile folder, validated but not yet stored."""
    folder = Path(folder)
    descriptor = joern_profiles.parse_descriptor(
        joern_profiles._regular(
            folder / joern_profiles.DESCRIPTOR, joern_profiles.MAX_DESCRIPTOR_BYTES
        )
    )
    if descriptor.name != folder.name:
        raise VeriFlowError("Profile folder name must equal the descriptor name")
    query = joern_profiles._regular(folder / descriptor.query, joern_profiles.MAX_QUERY_BYTES)
    if sorted(f.kind for f in descriptor.fixtures) != sorted(KINDS):
        raise VeriFlowError(
            "Profile drafts need one vulnerable, one fixed and one misleading fixture"
        )
    fixtures, total = [], 0
    for spec in descriptor.fixtures:
        entries = _fixture_files(folder / "fixtures" / spec.file)
        if not any(name.endswith(_suffixes(descriptor.language)) for name, _ in entries):
            raise VeriFlowError(f"Fixture {spec.kind} holds no {descriptor.language} source")
        total += sum(len(payload) for _, payload in entries)
        if total > MAX_FIXTURE_TOTAL_BYTES:
            raise VeriFlowError("Fixtures exceed the cumulative size limit")
        fixtures.append((spec, entries))
    return descriptor, query, fixtures


def _check_names(descriptor):
    packaged = joern_profiles.packaged()
    if descriptor.name in {b.name for b in packaged}:
        raise VeriFlowError("Profile name is reserved by a packaged profile")
    if descriptor.rule_id in {b.rule_id for b in packaged}:
        raise VeriFlowError("Profile rule_id is used by a packaged profile")


def add_profile(store, folder):
    """Copy a profile folder into an immutable draft; no tool runs and nothing activates."""
    store.require_initialized()
    folder = Path(folder).resolve(strict=True)
    if folder.is_relative_to(store.root / "artifacts"):
        raise VeriFlowError("Profile drafts cannot come from captured repository source")
    descriptor, query, fixtures = read_profile_folder(folder)
    _check_names(descriptor)
    weakness = descriptor.weakness
    content = {
        "schema_version": "1",
        "report_kind": "profile_draft",
        "origin": "cwe_priority" if weakness.cwe else "internal_pattern",
        "engine": "joern",
        "language": descriptor.language,
        "cwe": list(weakness.cwe),
        "target_profile": descriptor.name,
        # model_dump writes every default, so the gate in force at draft time is recorded.
        "descriptor": descriptor.model_dump(),
        "query": {
            "filename": descriptor.query,
            "sha256": hashlib.sha256(query).hexdigest(),
            "size_bytes": len(query),
        },
        "fixtures": [
            {
                "kind": spec.kind,
                "filename": spec.file,
                "sha256": _tree_digest(entries),
                "files": len(entries),
                "size_bytes": sum(len(p) for _, p in entries),
                "expected_flows": spec.expected_flows,
            }
            for spec, entries in fixtures
        ],
        "validation": {"test_status": "not_run", "automatically_reexecuted": True},
    }
    identity = hashlib.sha256(canonical(content)).hexdigest()
    with exclusive_worker(store.root):
        with store.transaction() as session:
            existing = session.get(ProfileDraft, identity)
            if existing is not None:
                return {"draft_id": identity, **existing.content, "state": existing.state}
        root = store.root / DRAFTS / identity
        staging = store.root / DRAFTS / f".{identity}.staging"
        if root.exists():
            raise VeriFlowError("Unexpected pre-existing profile draft artifact")
        staging.mkdir(parents=True, mode=0o700)
        try:
            (staging / descriptor.query).write_bytes(query)
            for spec, entries in fixtures:
                for name, payload in entries:
                    target = staging / "fixtures" / spec.kind / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    target.write_bytes(payload)
            (staging / "manifest.json").write_bytes(canonical(content))
            staging.rename(root)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        with store.transaction() as session:
            session.add(ProfileDraft(id=identity, created_at=now(), state="draft", content=content))
    return {"draft_id": identity, **content, "state": "draft"}


def _profile_draft(session, draft_id):
    draft = session.get(ProfileDraft, draft_id)
    if draft is None:
        raise VeriFlowError("Runtime profile draft not found")
    return draft


def _verify(store, draft):
    """Stored query and fixtures still match the digests recorded at draft time."""
    root = store.root / DRAFTS / draft.id
    content = draft.content
    try:
        if (root / "manifest.json").read_bytes() != canonical(content):
            raise VeriFlowError("Profile draft manifest integrity check failed")
        query = root / content["query"]["filename"]
        if (
            hashlib.sha256(
                joern_profiles._regular(query, joern_profiles.MAX_QUERY_BYTES)
            ).hexdigest()
            != (content["query"]["sha256"])
        ):
            raise VeriFlowError("Profile draft query integrity check failed")
        fixtures = {}
        for fixture in content["fixtures"]:
            base = root / "fixtures" / fixture["kind"]
            entries = [
                (p.relative_to(base).as_posix(), joern_profiles._regular(p, MAX_FIXTURE_BYTES))
                for p in sorted(base.rglob("*"))
                if p.is_file()
            ]
            if _tree_digest(entries) != fixture["sha256"]:
                raise VeriFlowError("Profile draft fixture integrity check failed")
            fixtures[fixture["kind"]] = entries
    except OSError:
        raise VeriFlowError("Profile draft artifact is unavailable") from None
    return query, fixtures


def _binding(draft, query):
    descriptor = joern_profiles.RuntimeDescriptor.model_validate(draft.content["descriptor"])
    return joern_profiles.runtime_binding(
        descriptor, "draft", query, draft.content["query"]["sha256"], draft.id
    )


def _run_fixture(
    disposable,
    inputs,
    kind,
    entries,
    binding,
    joern_home,
    timeout,
    extraction_timeout,
    repair_dir,
    rust_home,
):
    from veriflow.artifacts import ArtifactStore
    from veriflow.intake import process, submit
    from veriflow.joern import discover

    archive = inputs / f"{kind}.zip"
    with zipfile.ZipFile(archive, "w") as out:
        for name, payload in entries:
            out.writestr(name, payload)
    manifest = inputs / f"{kind}.csv"
    manifest.write_text(
        "repo_id,source_type,source_uri,owner,classification\n"
        f"fixture-{kind},pvc,{archive},profile-test,synthetic\n"
    )
    batch = submit(disposable, manifest, inputs, f"profile-test-{kind}")
    with exclusive_worker(disposable.root):
        item = process(disposable, ArtifactStore(disposable.root), batch)["items"][0]
    if item["state"] != "snapshotted":
        raise VeriFlowError(f"Fixture intake failed ({item.get('error') or item['state']})")
    return discover(
        disposable,
        item["run_id"],
        joern_home,
        timeout,
        language=binding.language,
        extraction_timeout=extraction_timeout,
        repair_dir=repair_dir if binding.language == "csharp" else None,
        rust_home=rust_home if binding.language == "rust" else None,
        profile_binding=binding,
    )


def test_profile(
    store,
    draft_id,
    joern_home,
    *,
    timeout=180,
    extraction_timeout=None,
    repair_dir=None,
    rust_home=None,
):
    """Run the real scanner on each fixture in a disposable state; record the outcome."""
    from veriflow.joern import VERSION

    store.require_initialized()
    with store.transaction() as session:
        draft = _profile_draft(session, draft_id)
    query, fixtures = _verify(store, draft)
    binding = _binding(draft, query)
    scratch = store.root / "profile-tests"
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    results = []
    with tempfile.TemporaryDirectory(dir=scratch) as temp:
        root = Path(temp).resolve()
        inputs = root / "inputs"
        inputs.mkdir()
        disposable = Store(root / "state")
        disposable.initialize()
        try:
            for fixture in draft.content["fixtures"]:
                kind, expected = fixture["kind"], fixture["expected_flows"]
                wanted = expected if expected is not None else ">=1" if kind == "vulnerable" else 0
                try:
                    report = _run_fixture(
                        disposable,
                        inputs,
                        kind,
                        fixtures[kind],
                        binding,
                        joern_home,
                        timeout,
                        extraction_timeout,
                        repair_dir,
                        rust_home,
                    )
                except VeriFlowError as exc:
                    # A setup failure is a failed test, recorded like any other outcome.
                    results.append(
                        {
                            "kind": kind,
                            "status": "error",
                            "error": str(exc),
                            "candidates": None,
                            "expected": wanted,
                            "passed": False,
                        }
                    )
                    continue
                count = report.get("candidate_count") or 0
                passed = report["status"] == "partial" and (
                    count == expected
                    if expected is not None
                    else count >= 1
                    if kind == "vulnerable"
                    else count == 0
                )
                results.append(
                    {
                        "kind": kind,
                        "status": report["status"],
                        "failed_stage": report.get("failed_stage"),
                        "candidates": count,
                        "expected": wanted,
                        "passed": passed,
                    }
                )
        finally:
            disposable.close()
    content = {
        "schema_version": "1",
        "report_kind": "profile_test",
        "draft_id": draft.id,
        "profile": binding.name,
        "joern_version": VERSION,
        "query_sha256": binding.query_sha256,
        "fixtures": results,
        "passed": all(item["passed"] for item in results),
        "created_at": now(),
        "scope": "Fixture agreement only; not coverage, precision or a clean verdict",
    }
    identity = hashlib.sha256(canonical(content)).hexdigest()
    with store.transaction() as session:
        session.add(
            ProfileTest(
                id=identity,
                draft_id=draft.id,
                created_at=content["created_at"],
                passed=content["passed"],
                content=content,
            )
        )
    return {"test_id": identity, **content}


def _latest_registry(session):
    return session.scalar(select(RuleRegistry).order_by(RuleRegistry.version.desc()).limit(1))


def _new_registry(session, latest, rules, change):
    version = (latest.version if latest is not None else 0) + 1
    content = {
        "schema_version": "1",
        "report_kind": "approved_rule_registry",
        "version": version,
        "parent_registry_id": latest.id if latest is not None else None,
        "rules": rules,
        "change": change,
    }
    identity = hashlib.sha256(canonical(content)).hexdigest()
    session.add(RuleRegistry(id=identity, version=version, created_at=now(), content=content))
    session.flush()
    return identity, content


def _active_rule(rules, name):
    return next((rule for rule in rules if rule.get("profile") == name), None)


def approve_profile(store, draft_id, request, request_key):
    """Add a tested draft to a new registry version.

    The same key and draft return the original approval only while it is still the active one;
    after a disable, approving the draft again needs a new key.
    """
    from veriflow.joern import VERSION

    if not isinstance(request, ProfileApprovalRequest):
        raise VeriFlowError("Expected a validated profile approval request")
    if request.draft_sha256 != draft_id:
        raise VeriFlowError("Approval document does not bind the selected draft")
    if not request_key.strip() or len(request_key) > 200:
        raise VeriFlowError("Approval key must contain 1-200 characters")
    with exclusive_worker(store.root):
        with store.transaction() as session:
            draft = _profile_draft(session, draft_id)
            descriptor = draft.content["descriptor"]
            latest = _latest_registry(session)
            rules = list(latest.content["rules"]) if latest is not None else []
            active = _active_rule(rules, descriptor["name"])
            existing = session.scalar(
                select(ProfileApproval).where(ProfileApproval.request_key == request_key)
            )
            if existing is not None:
                if existing.draft_id != draft_id:
                    raise VeriFlowError("Approval key was used for a different draft")
                if active is None or active.get("approval_id") != existing.id:
                    raise VeriFlowError(
                        "This key belongs to an approval that is no longer active; "
                        "use a new key to approve the draft again"
                    )
                registry = session.get(RuleRegistry, existing.registry_id)
                return {
                    "approval_id": existing.id,
                    **existing.content,
                    "registry": registry.content,
                }
            if active is not None:
                raise VeriFlowError(
                    "A profile with this name is already approved; disable it first"
                    if active.get("draft_id") != draft_id
                    else "This draft is already the active approved profile"
                )
            if any(
                (r.get("descriptor") or {}).get("rule_id") == descriptor["rule_id"] for r in rules
            ):
                raise VeriFlowError("Another approved profile already uses this rule_id")
            test = session.scalar(
                select(ProfileTest)
                .where(ProfileTest.draft_id == draft_id)
                .order_by(ProfileTest.created_at.desc(), ProfileTest.id.desc())
                .limit(1)
            )
            if test is None or not test.passed:
                raise VeriFlowError("Run profile-test until it passes before approval")
            if (
                test.content["joern_version"] != VERSION
                or test.content["query_sha256"] != draft.content["query"]["sha256"]
            ):
                raise VeriFlowError("The passing test used another Joern version or query")
            if (latest.version if latest is not None else 0) != request.expected_registry_version:
                raise VeriFlowError("Stale rule registry version; retrieve status and retry")
        _check_names(joern_profiles.RuntimeDescriptor.model_validate(descriptor))
        query, _ = _verify(store, draft)
        with store.transaction() as session:
            latest = _latest_registry(session)
            approval = {
                "schema_version": "1",
                "draft_id": draft.id,
                "draft_sha256": request.draft_sha256,
                "reviewer_label": request.reviewer_label,
                "rationale": request.rationale,
                "test_id": test.id,
                "registry_version": (latest.version if latest is not None else 0) + 1,
                "request_key": request_key,
                "reviewer_authenticated": False,
            }
            approval_id = hashlib.sha256(canonical(approval)).hexdigest()
            rule = {
                "draft_id": draft.id,
                "approval_id": approval_id,
                "engine": "joern",
                "language": draft.content["language"],
                "cwe": draft.content["cwe"],
                "target_profile": descriptor["name"],
                "profile": descriptor["name"],
                "review_gate": descriptor["review_gate"],
                "descriptor": descriptor,
                "query_sha256": draft.content["query"]["sha256"],
                "approved_query_path": str(query),
                "test_id": test.id,
            }
            registry_id, registry = _new_registry(
                session,
                latest,
                [*rules, rule],
                {"action": "approve", "profile": descriptor["name"]},
            )
            approval["registry_id"] = registry_id
            session.add(
                ProfileApproval(
                    id=approval_id,
                    draft_id=draft.id,
                    registry_id=registry_id,
                    request_key=request_key,
                    created_at=now(),
                    content=approval,
                )
            )
            session.get(ProfileDraft, draft.id).state = "approved"
    return {"approval_id": approval_id, **approval, "registry": registry}


def disable_profile(store, name, expected_registry_version, reason):
    """New registry version without the named profile; earlier versions stay readable."""
    if not reason.strip() or len(reason) > 2000:
        raise VeriFlowError("A disable reason of 1-2000 characters is required")
    store.require_initialized()
    with exclusive_worker(store.root), store.transaction() as session:
        latest = _latest_registry(session)
        if (latest.version if latest is not None else 0) != expected_registry_version:
            raise VeriFlowError("Stale rule registry version; retrieve status and retry")
        rules = list(latest.content["rules"]) if latest is not None else []
        kept = [r for r in rules if r.get("profile") != name]
        if len(kept) == len(rules):
            raise VeriFlowError("No approved profile with this name")
        registry_id, registry = _new_registry(
            session, latest, kept, {"action": "disable", "profile": name, "reason": reason}
        )
        removed = next(r for r in rules if r.get("profile") == name)
        draft = session.get(ProfileDraft, removed["draft_id"])
        if draft is not None:
            draft.state = "disabled"
    return {"registry_id": registry_id, **registry}


def profile_status(store, draft_id):
    with store.transaction() as session:
        draft = _profile_draft(session, draft_id)
        tests = [
            {"test_id": t.id, **t.content}
            for t in session.scalars(
                select(ProfileTest)
                .where(ProfileTest.draft_id == draft_id)
                .order_by(ProfileTest.created_at, ProfileTest.id)
            )
        ]
        approvals = [
            {"approval_id": a.id, "created_at": a.created_at, **a.content}
            for a in session.scalars(
                select(ProfileApproval)
                .where(ProfileApproval.draft_id == draft_id)
                .order_by(ProfileApproval.created_at, ProfileApproval.id)
            )
        ]
    _verify(store, draft)
    return {
        "draft_id": draft.id,
        **draft.content,
        "state": draft.state,
        "tests": tests,
        "approvals": approvals,
    }


def scaffold(name, language, output, rule_id=None):
    """Write an editable profile folder; its placeholders keep it inactive until edited."""
    if language not in joern_profiles.LANGUAGES:
        raise VeriFlowError("Unsupported Joern language")
    # The descriptor name rule also keeps the folder inside --output (no separators or dots).
    if not re.fullmatch(joern_profiles.NAME_PATTERN, name):
        raise VeriFlowError("Profile name must look like acme-go-commandcontext-v1")
    folder = Path(output) / name
    if folder.exists():
        raise VeriFlowError("Scaffold target already exists")
    rule_id = rule_id or f"local/joern-{name}"
    suffixes = _suffixes(language)
    represented = " || ".join(f'n.endsWith("{s}")' for s in suffixes)
    query = f"""// Runtime VeriFlow Joern profile. Replace the TODO sources and sinks only;
// keep the output contract: schema 2, this rule_id, represented files, counts and paths.
@main def exec(cpgFile: String, outFile: String) = {{
  importCpg(cpgFile)
  // TODO: calls whose results carry untrusted input.
  def sources = cpg.call.methodFullNameExact("TODO.source")
  // TODO: the argument that must not receive untrusted input.
  def sinks = cpg.call.methodFullNameExact("TODO.sink").argument(1)
  val flows = sinks.reachableByFlows(sources).l
  val result = ujson.Obj(
    "schema_version" -> "2", "engine_id" -> "joern",
    "rule_id" -> "{rule_id}",
    "represented_{language}_files" -> ujson.Arr.from(
      cpg.file.name.l.filter(n => {represented}).distinct.sorted),
    "source_count" -> sources.size, "sink_count" -> sinks.size,
    "flow_count" -> flows.size,
    "paths" -> ujson.Arr.from(flows.map(p => ujson.Arr.from(p.elements.map(n => ujson.Obj(
      "code" -> n.code, "file" -> n.file.name.headOption.getOrElse(""),
      "line" -> n.lineNumber.getOrElse(-1)
    )))))
  )
  java.nio.file.Files.writeString(java.nio.file.Path.of(outFile), ujson.write(result, indent = 2))
}}
"""
    descriptor = {
        "schema_version": "1",
        "name": name,
        "language": language,
        "rule_id": rule_id,
        "query": "query.sc",
        "message": "TODO: source to sink in one sentence; discovery only.",
        "limitations": ["TODO: state what this profile does not cover or prove."],
        "selection": "auto",
        "weakness": {"cwe": ["CWE-TODO"], "internal_pattern": None},
        "fixtures": [
            {"kind": kind, "file": f"{kind}{suffixes[0]}", "expected_flows": None} for kind in KINDS
        ],
    }
    (folder / "fixtures").mkdir(parents=True)
    (folder / "query.sc").write_text(query)
    (folder / joern_profiles.DESCRIPTOR).write_text(json.dumps(descriptor, indent=2) + "\n")
    for kind in KINDS:
        (folder / "fixtures" / f"{kind}{suffixes[0]}").write_text(
            f"// TODO: {kind} example for {name}\n"
        )
    return {
        "folder": str(folder),
        "files": sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()),
        "next": "Edit the TODOs; CWE-TODO keeps the profile inactive until it is replaced.",
    }
