"""Governed promotion of confirmed LLM discoveries into immutable approved-rule registries."""

import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import select

from veriflow.bundles import canonical
from veriflow.domain import Digest, VeriFlowError
from veriflow.intake import now
from veriflow.persistence import (
    Candidate,
    OperatorReview,
    RuleApproval,
    RuleDraft,
    RuleRegistry,
    Run,
    ScanAttempt,
    exclusive_worker,
)
from veriflow.reviews import verified_review

MAX_REQUEST_BYTES = 32 * 1024
MAX_QUERY_BYTES = 1024 * 1024
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_FIXTURE_TOTAL_BYTES = 4 * 1024 * 1024
MAX_BATCH_ROWS = 1000
QUERY_SUFFIXES = {"joern": {".sc"}, "codeql": {".ql", ".qls"}}
FIXTURE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".py",
    ".rs",
    ".ts",
    ".tsx",
    ".txt",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class FixtureInput(StrictModel):
    kind: Literal["vulnerable", "fixed", "misleading"]
    path: str = Field(min_length=1, max_length=4096)
    sha256: Digest

    @field_validator("path")
    @classmethod
    def absolute_path(cls, value):
        if not Path(value).is_absolute() or "\x00" in value:
            raise ValueError("fixture path must be absolute")
        return value


class DraftRequest(StrictModel):
    engine: Literal["joern", "codeql"]
    language: str = Field(min_length=1, max_length=40)
    target_profile: str = Field(min_length=1, max_length=200)
    query_path: str = Field(min_length=1, max_length=4096)
    query_sha256: Digest
    fixtures: list[FixtureInput] = Field(min_length=3, max_length=12)
    test_status: Literal["passed"]
    test_evidence: str = Field(min_length=1, max_length=2000)
    benchmark_status: Literal["not_run", "passed"] = "not_run"
    benchmark_evidence: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def complete(self):
        if not Path(self.query_path).is_absolute() or "\x00" in self.query_path:
            raise ValueError("query path must be absolute")
        if {item.kind for item in self.fixtures} != {"vulnerable", "fixed", "misleading"}:
            raise ValueError("draft requires vulnerable, fixed and misleading fixtures")
        if len({item.kind for item in self.fixtures}) != len(self.fixtures):
            raise ValueError("each fixture kind must appear exactly once")
        if not self.target_profile.strip() or not self.test_evidence.strip():
            raise ValueError("profile and test evidence must be nonblank")
        if self.benchmark_status == "passed" and not self.benchmark_evidence.strip():
            raise ValueError("passed benchmark status requires evidence")
        return self


class ApprovalRequest(StrictModel):
    draft_sha256: Digest
    expected_registry_version: int = Field(ge=0)
    expected_review_revision: int = Field(ge=1)
    reviewer_label: str = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def meaningful(self):
        if not self.reviewer_label.strip() or not self.rationale.strip():
            raise ValueError("reviewer and rationale must be nonblank")
        return self


def _read_json(path, model, label):
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError()

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result

        return model.model_validate(json.loads(raw, object_pairs_hook=pairs))
    except (OSError, ValidationError, ValueError, TypeError, RecursionError):
        raise VeriFlowError(f"Invalid {label}; check schema and size limits") from None


def read_draft_request(path):
    return _read_json(path, DraftRequest, "rule draft request")


def read_approval_request(path):
    return _read_json(path, ApprovalRequest, "rule approval request")


def _file(path, expected, limit, suffixes, store):
    path = Path(path)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise VeriFlowError("Draft input file is unavailable") from None
    if path.is_symlink() or not resolved.is_file() or resolved.suffix.lower() not in suffixes:
        raise VeriFlowError("Draft input file type is not allowed")
    if resolved.is_relative_to(store.root / "artifacts"):
        raise VeriFlowError("Draft inputs cannot come from captured repository source")
    size = resolved.stat().st_size
    if size > limit:
        raise VeriFlowError("Draft input file exceeds its size limit")
    payload = resolved.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise VeriFlowError("Draft input digest does not match")
    return resolved, payload


def _confirmed_candidate(session, repo_id, attempt_id, fingerprint):
    candidate = session.scalar(
        select(Candidate)
        .join(ScanAttempt, Candidate.attempt_id == ScanAttempt.id)
        .join(Run, ScanAttempt.run_id == Run.id)
        .where(
            ScanAttempt.id == attempt_id,
            Run.repo_id == repo_id,
            Candidate.fingerprint == fingerprint,
        )
    )
    if candidate is None or candidate.evidence.get("origin") != "llm_discovery":
        raise VeriFlowError("Confirmed LLM-origin candidate not found")
    review = session.scalar(
        select(OperatorReview)
        .where(OperatorReview.candidate_id == candidate.id)
        .order_by(OperatorReview.revision.desc())
        .limit(1)
    )
    if review is None or verified_review(review)["state"] != "confirmed":
        raise VeriFlowError("Latest candidate review must be confirmed")
    return candidate, review


def create_rule_draft(store, repo_id, attempt_id, fingerprint, request):
    if not isinstance(request, DraftRequest):
        raise VeriFlowError("Expected a validated rule draft request")
    query, query_bytes = _file(
        request.query_path,
        request.query_sha256,
        MAX_QUERY_BYTES,
        QUERY_SUFFIXES[request.engine],
        store,
    )
    fixture_files, fixture_total = [], 0
    for fixture in request.fixtures:
        path, payload = _file(
            fixture.path,
            fixture.sha256,
            MAX_FIXTURE_BYTES,
            FIXTURE_SUFFIXES,
            store,
        )
        fixture_total += len(payload)
        if fixture_total > MAX_FIXTURE_TOTAL_BYTES:
            raise VeriFlowError("Draft fixtures exceed the cumulative size limit")
        fixture_files.append((fixture, path, payload))
    with exclusive_worker(store.root):
        with store.transaction() as session:
            candidate, review = _confirmed_candidate(session, repo_id, attempt_id, fingerprint)
            evidence = candidate.evidence
            content = {
                "schema_version": "1",
                "report_kind": "rule_draft",
                "candidate_id": candidate.id,
                "candidate_fingerprint": candidate.fingerprint,
                "candidate_review_id": review.id,
                "candidate_review_revision": review.revision,
                "origin": "confirmed_llm_discovery",
                "engine": request.engine,
                "language": request.language,
                "cwe": evidence.get("cwe"),
                "target_profile": request.target_profile,
                "query": {
                    "filename": query.name,
                    "sha256": request.query_sha256,
                    "size_bytes": len(query_bytes),
                },
                "fixtures": [
                    {
                        "kind": fixture.kind,
                        "filename": path.name,
                        "sha256": fixture.sha256,
                        "size_bytes": len(payload),
                    }
                    for fixture, path, payload in fixture_files
                ],
                "validation": {
                    "test_status": request.test_status,
                    "test_evidence": request.test_evidence,
                    "benchmark_status": request.benchmark_status,
                    "benchmark_evidence": request.benchmark_evidence,
                    "attested_by_operator": True,
                    "automatically_reexecuted": False,
                },
            }
            identity = hashlib.sha256(canonical(content)).hexdigest()
            existing = session.get(RuleDraft, identity)
            if existing is not None:
                return {"draft_id": existing.id, **existing.content, "state": existing.state}
        root = store.root / "rule-drafts" / identity
        staging = store.root / "rule-drafts" / f".{identity}.staging"
        if root.exists():
            raise VeriFlowError("Unexpected pre-existing rule draft artifact")
        staging.mkdir(parents=True, mode=0o700)
        try:
            (staging / query.name).write_bytes(query_bytes)
            fixture_root = staging / "fixtures"
            fixture_root.mkdir(mode=0o700)
            for fixture, path, payload in fixture_files:
                (fixture_root / f"{fixture.kind}-{path.name}").write_bytes(payload)
            (staging / "manifest.json").write_bytes(canonical(content))
            staging.rename(root)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        with store.transaction() as session:
            session.add(
                RuleDraft(
                    id=identity,
                    candidate_id=candidate.id,
                    created_at=now(),
                    state="draft",
                    content=content,
                )
            )
        return {"draft_id": identity, **content, "state": "draft"}


def _verify_draft_artifacts(store, draft):
    root = store.root / "rule-drafts" / draft.id
    manifest = root / "manifest.json"
    try:
        if root.is_symlink() or manifest.is_symlink() or not manifest.is_file():
            raise VeriFlowError("Rule draft artifact is unavailable")
        if manifest.read_bytes() != canonical(draft.content):
            raise VeriFlowError("Rule draft manifest integrity check failed")
        query = root / draft.content["query"]["filename"]
        if (
            query.is_symlink()
            or hashlib.sha256(query.read_bytes()).hexdigest() != draft.content["query"]["sha256"]
        ):
            raise VeriFlowError("Rule draft query integrity check failed")
        for fixture in draft.content["fixtures"]:
            path = root / "fixtures" / f"{fixture['kind']}-{fixture['filename']}"
            if (
                path.is_symlink()
                or hashlib.sha256(path.read_bytes()).hexdigest() != fixture["sha256"]
            ):
                raise VeriFlowError("Rule draft fixture integrity check failed")
    except OSError:
        raise VeriFlowError("Rule draft artifact is unavailable") from None
    return query


def _not_found(session, draft_id, command):
    from veriflow.persistence import ProfileDraft

    if session.get(ProfileDraft, draft_id) is not None:
        return f"Runtime profile drafts use {command}"
    return "Rule draft not found"


def rule_draft_status(store, draft_id):
    with store.transaction() as session:
        draft = session.get(RuleDraft, draft_id)
        if draft is None:
            raise VeriFlowError(_not_found(session, draft_id, "profile-status"))
        approval = session.scalar(select(RuleApproval).where(RuleApproval.draft_id == draft_id))
        result = {"draft_id": draft.id, **draft.content, "state": draft.state}
        if approval is not None:
            result["approval_id"] = approval.id
            result["registry_id"] = approval.registry_id
    _verify_draft_artifacts(store, draft)
    return result


def approve_rule_draft(store, draft_id, request, request_key):
    if not isinstance(request, ApprovalRequest):
        raise VeriFlowError("Expected a validated rule approval request")
    if request.draft_sha256 != draft_id:
        raise VeriFlowError("Approval document does not bind the selected draft")
    if not request_key.strip() or len(request_key) > 200:
        raise VeriFlowError("Approval key must contain 1-200 characters")
    with exclusive_worker(store.root):
        with store.transaction() as session:
            existing_key = session.scalar(
                select(RuleApproval).where(RuleApproval.request_key == request_key)
            )
            if existing_key is not None:
                if existing_key.draft_id != draft_id:
                    raise VeriFlowError("Approval key was used for a different draft")
                registry = session.get(RuleRegistry, existing_key.registry_id)
                return {
                    "approval_id": existing_key.id,
                    **existing_key.content,
                    "registry": registry.content,
                }
            draft = session.get(RuleDraft, draft_id)
            if draft is None:
                raise VeriFlowError(_not_found(session, draft_id, "profile-approve"))
            prior = session.scalar(select(RuleApproval).where(RuleApproval.draft_id == draft_id))
            if prior is not None:
                raise VeriFlowError("Rule draft is already approved under a different key")
            candidate = session.get(Candidate, draft.candidate_id)
            review = session.scalar(
                select(OperatorReview)
                .where(OperatorReview.candidate_id == candidate.id)
                .order_by(OperatorReview.revision.desc())
                .limit(1)
            )
            verified = verified_review(review) if review is not None else None
            if (
                verified is None
                or verified["state"] != "confirmed"
                or review.revision != request.expected_review_revision
                or review.id != draft.content["candidate_review_id"]
            ):
                raise VeriFlowError("Confirmed candidate review changed after draft creation")
            validation = draft.content["validation"]
            if validation["test_status"] != "passed":
                raise VeriFlowError("Rule draft tests are not attested as passed")
            latest = session.scalar(
                select(RuleRegistry).order_by(RuleRegistry.version.desc()).limit(1)
            )
            current_version = latest.version if latest is not None else 0
            if current_version != request.expected_registry_version:
                raise VeriFlowError("Stale rule registry version; retrieve status and retry")
        query = _verify_draft_artifacts(store, draft)
        with store.transaction() as session:
            stored_draft = session.get(RuleDraft, draft.id)
            rules = list(latest.content["rules"]) if latest is not None else []
            rule = {
                "draft_id": draft.id,
                "engine": draft.content["engine"],
                "language": draft.content["language"],
                "cwe": draft.content["cwe"],
                "target_profile": draft.content["target_profile"],
                "query_sha256": draft.content["query"]["sha256"],
                "approved_query_path": str(query),
            }
            registry_content = {
                "schema_version": "1",
                "report_kind": "approved_rule_registry",
                "version": current_version + 1,
                "parent_registry_id": latest.id if latest is not None else None,
                "rules": [*rules, rule],
            }
            registry_id = hashlib.sha256(canonical(registry_content)).hexdigest()
            approval_content = {
                "schema_version": "1",
                "draft_id": draft.id,
                "draft_sha256": request.draft_sha256,
                "reviewer_label": request.reviewer_label,
                "rationale": request.rationale,
                "candidate_review_revision": request.expected_review_revision,
                "registry_id": registry_id,
                "registry_version": current_version + 1,
                "reviewer_authenticated": False,
            }
            approval_id = hashlib.sha256(canonical(approval_content)).hexdigest()
            session.add(
                RuleRegistry(
                    id=registry_id,
                    version=current_version + 1,
                    created_at=now(),
                    content=registry_content,
                )
            )
            session.flush()
            session.add(
                RuleApproval(
                    id=approval_id,
                    draft_id=draft.id,
                    registry_id=registry_id,
                    request_key=request_key,
                    created_at=now(),
                    content=approval_content,
                )
            )
            stored_draft.state = "approved"
        return {
            "approval_id": approval_id,
            **approval_content,
            "registry": registry_content,
        }


def approve_rule_drafts(store, manifest_path):
    path = Path(manifest_path).resolve(strict=True)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise VeriFlowError("Approval manifest is unavailable or too large")
    try:
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != ["draft_id", "approval_path", "request_key"]:
                raise ValueError()
            rows = list(reader)
        if not rows or len(rows) > MAX_BATCH_ROWS:
            raise ValueError()
    except (OSError, csv.Error, ValueError):
        raise VeriFlowError("Invalid approval manifest") from None
    results = []
    for number, row in enumerate(rows, 2):
        try:
            approval_path = Path(row["approval_path"])
            if not approval_path.is_absolute():
                approval_path = path.parent / approval_path
            result = approve_rule_draft(
                store,
                row["draft_id"],
                read_approval_request(approval_path),
                row["request_key"],
            )
            results.append({"row_number": number, "status": "approved", **result})
        except VeriFlowError as exc:
            results.append({"row_number": number, "status": "rejected", "error": str(exc)})
    return {
        "schema_version": "1",
        "report_kind": "rule_approval_batch",
        "manifest": str(path),
        "total": len(results),
        "approved": sum(row["status"] == "approved" for row in results),
        "rejected": sum(row["status"] == "rejected" for row in results),
        "items": results,
    }


def registry_status(store, version=None):
    with store.transaction() as session:
        query = select(RuleRegistry)
        if version is not None:
            query = query.where(RuleRegistry.version == version)
        registry = session.scalar(query.order_by(RuleRegistry.version.desc()).limit(1))
        if registry is None:
            return {
                "schema_version": "1",
                "report_kind": "approved_rule_registry",
                "version": 0,
                "registry_id": None,
                "rules": [],
            }
        return {"registry_id": registry.id, **registry.content}
