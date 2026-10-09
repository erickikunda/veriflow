import json

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from test_reports import scanned as scanned
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow.bundles import build_bundle
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.persistence import Candidate, OperatorReview, TriageCall
from veriflow.reports import get_report, publish_report, render_report
from veriflow.reviews import ReviewRequest, read_review, record_review, review_history


@pytest.fixture
def review_fixture(store, scanned):
    repo, _, attempt, fingerprint = scanned
    bundle = build_bundle(store, attempt, fingerprint)
    request = ReviewRequest(
        reviewer_label="synthetic-reviewer",
        state="confirmed",
        rationale="Synthetic test assertion, not a real security review.",
        bundle_id=bundle["bundle_id"],
        evidence_ids=["E1"],
        expected_revision=0,
    )
    return repo, attempt, fingerprint, request


def test_append_only_retry_and_stale_revision(store, review_fixture):
    repo, attempt, fingerprint, request = review_fixture
    first = record_review(store, repo, attempt, fingerprint, request, "one")
    assert first["revision"] == 1 and first["state"] == "confirmed"
    assert not first["reviewer_authenticated"] and not first["independently_verified"]
    assert record_review(store, repo, attempt, fingerprint, request, "one") == first
    with pytest.raises(VeriFlowError, match="Stale"):
        record_review(store, repo, attempt, fingerprint, request, "stale")
    next_request = request.model_copy(update={"state": "needs_review", "expected_revision": 1})
    second = record_review(store, repo, attempt, fingerprint, next_request, "two")
    assert second["revision"] == 2
    assert record_review(store, repo, attempt, fingerprint, request, "one") == first
    history = review_history(store, repo, attempt, fingerprint, limit=1)
    assert history["current_revision"] == 2 and history["reviews"] == [first]
    assert review_history(store, repo, attempt, fingerprint, offset=1)["reviews"] == [second]
    with store.transaction() as session:
        assert session.scalar(select(Candidate)).evidence["adjudication"] == "unreviewed"
        assert session.scalar(select(func.count()).select_from(TriageCall)) == 0


def test_key_conflict_and_ownership(store, review_fixture):
    repo, attempt, fingerprint, request = review_fixture
    record_review(store, repo, attempt, fingerprint, request, "one")
    with pytest.raises(VeriFlowError, match="different request"):
        record_review(
            store,
            repo,
            attempt,
            fingerprint,
            request.model_copy(update={"state": "false_positive"}),
            "one",
        )
    with pytest.raises(VeriFlowError, match="belong"):
        record_review(store, "other", attempt, fingerprint, request, "one")
    with pytest.raises(VeriFlowError, match="belong"):
        review_history(store, repo, "other-attempt", fingerprint)


def test_unknown_evidence_and_bundle_fail_without_writes(store, review_fixture):
    repo, attempt, fingerprint, request = review_fixture
    with pytest.raises(VeriFlowError, match="absent"):
        record_review(
            store,
            repo,
            attempt,
            fingerprint,
            request.model_copy(update={"evidence_ids": ["E999"]}),
            "bad",
        )
    with pytest.raises(VeriFlowError, match="bundle"):
        record_review(
            store,
            repo,
            attempt,
            fingerprint,
            request.model_copy(update={"bundle_id": "a" * 64}),
            "bad",
        )
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(OperatorReview)) == 0


def test_partial_bundle_allows_deferral_but_not_definitive_assertion(store, evidence_fixture):
    from veriflow.persistence import Run

    run, attempt, fingerprint, _ = evidence_fixture(
        flow_count=20, distinct_flow=True, source="".join(f"x = {n}\n" for n in range(24))
    )
    with store.transaction() as session:
        repo = session.get(Run, run).repo_id
    bundle = build_bundle(store, attempt, fingerprint)
    request = ReviewRequest(
        reviewer_label="test",
        state="false_positive",
        rationale="test",
        bundle_id=bundle["bundle_id"],
        evidence_ids=["E1"],
        expected_revision=0,
    )
    with pytest.raises(VeriFlowError, match="ready"):
        record_review(store, repo, attempt, fingerprint, request, "blocked")
    deferred = request.model_copy(update={"state": "deferred", "evidence_ids": []})
    assert (
        record_review(store, repo, attempt, fingerprint, deferred, "defer")["state"] == "deferred"
    )


def test_report_projection_preserves_candidate_and_private_notes(store, review_fixture):
    repo, attempt, fingerprint, request = review_fixture
    before = publish_report(store, repo)
    record_review(
        store,
        repo,
        attempt,
        fingerprint,
        request.model_copy(update={"state": "false_positive"}),
        "review",
    )
    after = publish_report(store, repo)
    assert before == get_report(store, repo, before["report_id"])
    assert after["report_version"] == before["report_version"] + 1
    assert after["candidate_count"] == before["candidate_count"] == 1
    assert after["candidates"][0]["operator_review_state"] == "false_positive"
    assert after["candidates"][0]["adjudication"] == "unreviewed"
    assert after["operator_review_counts"] == {"false_positive": 1}
    assert after["verified_finding_count"] is None
    for format in ("json", "markdown", "html", "candidates-csv"):
        output = render_report(after, format)
        assert "false_positive" in output
        assert request.rationale not in output and request.reviewer_label not in output


def test_corrupted_review_is_rejected_by_history_and_publication(store, review_fixture):
    repo, attempt, fingerprint, request = review_fixture
    review = record_review(store, repo, attempt, fingerprint, request, "one")
    with store.transaction() as session:
        record = session.get(OperatorReview, review["review_id"])
        record.content = {**record.content, "state": "false_positive"}
    with pytest.raises(VeriFlowError, match="integrity"):
        review_history(store, repo, attempt, fingerprint)
    with pytest.raises(VeriFlowError, match="integrity"):
        publish_report(store, repo)


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewer_label": " "},
        {"rationale": " "},
        {"evidence_ids": []},
        {"evidence_ids": ["E1", "E1"]},
        {"state": "fixed"},
        {"expected_revision": -1},
    ],
)
def test_invalid_reviews_rejected(review_fixture, changes):
    with pytest.raises(ValidationError):
        ReviewRequest.model_validate({**review_fixture[3].model_dump(), **changes})


def test_cli_and_request_limit(store, review_fixture, tmp_path):
    repo, attempt, fingerprint, request = review_fixture
    path = tmp_path / "review.json"
    path.write_text(request.model_dump_json())
    assert read_review(path) == request
    args = ["--state-dir", str(store.root)]
    runner = CliRunner()
    output = runner.invoke(
        app, [*args, "record-review", repo, attempt, fingerprint, str(path), "one"]
    )
    assert output.exit_code == 0, output.output
    assert json.loads(output.output)["revision"] == 1
    history = runner.invoke(app, [*args, "review-history", repo, attempt, fingerprint])
    assert history.exit_code == 0 and json.loads(history.output)["current_revision"] == 1
    path.write_bytes(b" " * (16 * 1024 + 1))
    with pytest.raises(VeriFlowError, match="16 KiB"):
        read_review(path)


def test_duplicate_json_and_unvalidated_copy_are_rejected(store, review_fixture, tmp_path):
    repo, attempt, fingerprint, request = review_fixture
    path = tmp_path / "duplicate.json"
    path.write_text('{"state":"false_positive",' + request.model_dump_json()[1:])
    with pytest.raises(VeriFlowError, match="Invalid review"):
        read_review(path)
    with pytest.raises(VeriFlowError, match="Invalid review"):
        record_review(
            store,
            repo,
            attempt,
            fingerprint,
            request.model_copy(update={"state": "fixed"}),
            "invalid",
        )
