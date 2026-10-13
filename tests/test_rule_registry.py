import hashlib
import json

import pytest
from test_llm_discovery import documents
from test_triage import evidence_fixture as evidence_fixture

from veriflow.bundles import build_bundle
from veriflow.domain import VeriFlowError
from veriflow.llm_discovery import replay_discovery
from veriflow.reviews import ReviewRequest, record_review
from veriflow.rule_registry import (
    ApprovalRequest,
    DraftRequest,
    FixtureInput,
    approve_rule_draft,
    create_rule_draft,
    registry_status,
    rule_draft_status,
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def confirmed_candidate(store, evidence_fixture, tmp_path):
    _, attempt_id, packet, response, _, _ = documents(store, evidence_fixture, tmp_path)
    replay = replay_discovery(store, attempt_id, packet, response, "rule-gap")
    fingerprint = replay["proposals"][0]["candidate_fingerprint"]
    bundle = build_bundle(store, attempt_id, fingerprint)
    record_review(
        store,
        "example",
        attempt_id,
        fingerprint,
        ReviewRequest(
            reviewer_label="security-reviewer",
            state="confirmed",
            rationale="Confirmed against retained source evidence.",
            bundle_id=bundle["bundle_id"],
            evidence_ids=["E1"],
            expected_revision=0,
        ),
        "confirm-rule-gap",
    )
    return attempt_id, fingerprint


def draft_request(tmp_path):
    query = tmp_path / "new-gap.sc"
    query.write_text("// tested Joern query\n")
    fixtures = []
    for kind, source in {
        "vulnerable": "eval(input())\n",
        "fixed": "safe_parse(input())\n",
        "misleading": "# eval(input())\n",
    }.items():
        path = tmp_path / f"{kind}.py"
        path.write_text(source)
        fixtures.append(FixtureInput(kind=kind, path=str(path), sha256=digest(path)))
    return DraftRequest(
        engine="joern",
        language="python",
        target_profile="python-core",
        query_path=str(query),
        query_sha256=digest(query),
        fixtures=fixtures,
        test_status="passed",
        test_evidence="Fixture assertions passed locally.",
    )


def test_confirmed_llm_candidate_promotes_to_immutable_registry(store, evidence_fixture, tmp_path):
    attempt_id, fingerprint = confirmed_candidate(store, evidence_fixture, tmp_path)
    draft = create_rule_draft(store, "example", attempt_id, fingerprint, draft_request(tmp_path))
    assert rule_draft_status(store, draft["draft_id"])["state"] == "draft"
    approval = ApprovalRequest(
        draft_sha256=draft["draft_id"],
        expected_registry_version=0,
        expected_review_revision=1,
        reviewer_label="rule-owner",
        rationale="Tests and source evidence justify promotion.",
    )
    result = approve_rule_draft(store, draft["draft_id"], approval, "approve-gap-1")
    assert result["registry_version"] == 1
    assert registry_status(store)["rules"][0]["draft_id"] == draft["draft_id"]
    assert rule_draft_status(store, draft["draft_id"])["state"] == "approved"
    assert approve_rule_draft(store, draft["draft_id"], approval, "approve-gap-1") == result


def test_approval_rejects_tampered_artifact(store, evidence_fixture, tmp_path):
    attempt_id, fingerprint = confirmed_candidate(store, evidence_fixture, tmp_path)
    draft = create_rule_draft(store, "example", attempt_id, fingerprint, draft_request(tmp_path))
    query_name = draft["query"]["filename"]
    (store.root / "rule-drafts" / draft["draft_id"] / query_name).write_text("changed")
    approval = ApprovalRequest(
        draft_sha256=draft["draft_id"],
        expected_registry_version=0,
        expected_review_revision=1,
        reviewer_label="rule-owner",
        rationale="Attempted approval.",
    )
    with pytest.raises(VeriFlowError, match="integrity"):
        approve_rule_draft(store, draft["draft_id"], approval, "tampered")


def test_cli_rule_contracts(store, evidence_fixture, tmp_path):
    from typer.testing import CliRunner

    from veriflow.cli import app

    attempt_id, fingerprint = confirmed_candidate(store, evidence_fixture, tmp_path)
    request = draft_request(tmp_path)
    request_path = tmp_path / "draft.json"
    request_path.write_text(json.dumps(request.model_dump()))
    base = ["--state-dir", str(store.root)]
    result = CliRunner().invoke(
        app,
        [*base, "create-rule-draft", "example", attempt_id, fingerprint, str(request_path)],
    )
    assert result.exit_code == 0, result.output
    draft_id = json.loads(result.output)["draft_id"]
    status = CliRunner().invoke(app, [*base, "rule-draft-status", draft_id])
    assert json.loads(status.output)["state"] == "draft"
    assert json.loads(CliRunner().invoke(app, [*base, "rule-registry"]).output)["version"] == 0
    approval = ApprovalRequest(
        draft_sha256=draft_id,
        expected_registry_version=0,
        expected_review_revision=1,
        reviewer_label="rule-owner",
        rationale="CLI approval after evidence and fixture review.",
    )
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval.model_dump()))
    approved = CliRunner().invoke(
        app,
        [*base, "approve-rule-draft", draft_id, str(approval_path), "cli-approval"],
    )
    assert approved.exit_code == 0, approved.output
    assert json.loads(approved.output)["registry_version"] == 1
