import csv
import io
import json
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow.bundles import build_bundle
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.persistence import Candidate, PublishedReport, Run, ScanAttempt
from veriflow.reports import get_report, publish_report, render_report, report_history
from veriflow.triage import set_budget, triage


@pytest.fixture
def scanned(store, evidence_fixture):
    run, attempt, fingerprint, _ = evidence_fixture()
    with store.transaction() as session:
        repo = session.get(Run, run).repo_id
    return repo, run, attempt, fingerprint


def test_immutable_versions_and_exact_retrieval(store, scanned):
    repo, run, attempt, fingerprint = scanned
    first = publish_report(store, repo)
    assert first["report_version"] == 1 and first["candidate_count"] == 1
    assert first["verified_finding_count"] is None
    assert first["candidates"][0]["latest_advisory"] == "not_triaged"
    assert publish_report(store, repo) == first
    bundle = build_bundle(store, attempt, fingerprint)
    set_budget(store, run, 100000)
    adapter = FakeAdapter()
    triage(store, bundle["bundle_id"], policy(), adapter, "report-test")
    second = publish_report(store, repo)
    assert second["report_version"] == 2
    assert second["triage_call_count"] == 1 and second["simulated_micro_usd"] == 140
    assert second["candidates"][0]["latest_advisory"] == "abstain"
    assert second["candidates"][0]["triage_history"][0]["state"] == "evidence_rejected"
    assert get_report(store, repo, first["report_id"]) == first
    assert get_report(store, repo) == second
    assert adapter.calls == 1
    assert len(report_history(store, repo)["reports"]) == 2
    assert len(report_history(store, repo, limit=1)["reports"]) == 1


def test_new_failed_attempt_never_falls_back(store, scanned):
    repo, run, _, _ = scanned
    first = publish_report(store, repo)
    with store.transaction() as session:
        session.add(
            ScanAttempt(
                id=str(uuid4()),
                run_id=run,
                created_at="9999",
                report={"status": "failed", "candidate_count": None},
            )
        )
    with pytest.raises(VeriFlowError, match="Latest attempt"):
        get_report(store, repo)
    failed = publish_report(store, repo)
    assert failed["analysis_status"] == "failed" and failed["candidate_count"] is None
    assert failed["candidates"] == [] and failed["triage_call_count"] == 0
    assert get_report(store, repo, first["report_id"]) == first


def test_explicit_completed_selection_discloses_newer_work(store, scanned):
    from veriflow.indexing import build_index
    from veriflow.reports import resolve_report

    repo, run, attempt, _ = scanned
    build_index(store, run)
    with store.transaction() as session:
        scan = session.get(ScanAttempt, attempt)
        scan.report = {
            **scan.report,
            "execution_complete": True,
            "diagnostic_errors": 0,
            "unmapped_candidates": 0,
        }
    first = publish_report(store, repo)
    assert first["static_review_readiness"]["state"] == "ready_for_review"
    assert resolve_report(store, repo, "latest-completed")["report"] == first
    with store.transaction() as session:
        session.add(
            ScanAttempt(
                id="new-failed",
                run_id=run,
                created_at="9999",
                report={"status": "failed", "candidate_count": None},
            )
        )
    assert resolve_report(store, repo)["report"] is None
    selected = resolve_report(store, repo, "latest-completed")
    assert selected["report"] == first
    assert selected["latest_analysis_status"] == "failed"
    assert selected["warnings"] and not selected["selected_is_latest_attempt"]
    failed = publish_report(store, repo)
    assert resolve_report(store, repo)["report"] == failed
    assert resolve_report(store, repo, "latest-completed")["report"] == first
    assert get_report(store, repo, first["report_id"]) == first
    # Republishing an old attempt must not replace latest-work selection.
    publish_report(store, repo, attempt_id=attempt)
    assert resolve_report(store, repo)["report"] == failed
    with store.transaction() as session:
        session.add(
            Run(
                id="new-run",
                repo_id=repo,
                state="failed",
                profile="standard",
                created_at="9999",
                snapshot_id=None,
            )
        )
    envelope = resolve_report(store, repo, "latest-completed")
    assert envelope["latest_run_id"] == "new-run"
    assert envelope["latest_analysis_status"] == "not_started"
    assert envelope["warnings"] and not envelope["selected_is_latest_attempt"]
    assert resolve_report(store, repo)["report"] is None


def test_selection_rejects_invalid_mode_and_missing_repo(store, scanned):
    from veriflow.reports import resolve_report

    repo, _, _, _ = scanned
    assert resolve_report(store, repo, "latest-completed")["selected_report_id"] is None
    with pytest.raises(VeriFlowError, match="selection"):
        resolve_report(store, repo, "silent-fallback")
    with pytest.raises(VeriFlowError, match="not found"):
        resolve_report(store, "other")


def test_new_run_without_analysis_has_explicit_report(store, scanned):
    repo, _, _, _ = scanned
    previous = publish_report(store, repo)
    with store.transaction() as session:
        session.add(
            Run(
                id=str(uuid4()),
                repo_id=repo,
                state="failed",
                profile="standard",
                created_at="9999",
                snapshot_id=None,
            )
        )
    with pytest.raises(VeriFlowError, match="No published report"):
        get_report(store, repo)
    current = publish_report(store, repo)
    assert current["analysis_status"] == "not_started" and current["run_state"] == "failed"
    assert current["candidate_count"] is None and current["snapshot_id"] is None
    assert get_report(store, repo, previous["report_id"]) == previous


def test_ownership_and_integrity(store, scanned):
    repo, _, _, _ = scanned
    report = publish_report(store, repo)
    with pytest.raises(VeriFlowError, match="belong"):
        get_report(store, "other", report["report_id"])
    with pytest.raises(VeriFlowError, match="belong"):
        get_report(store, repo, report["report_id"], "other-run")
    with pytest.raises(VeriFlowError, match="Attempt"):
        publish_report(store, repo, attempt_id="other-attempt")
    with store.transaction() as session:
        record = session.get(PublishedReport, report["report_id"])
        record.content = {**record.content, "candidate_count": 0}
    with pytest.raises(VeriFlowError, match="integrity"):
        get_report(store, repo, report["report_id"])


def test_count_mismatch_fails_without_publication(store, scanned):
    repo, _, attempt, _ = scanned
    with store.transaction() as session:
        record = session.get(ScanAttempt, attempt)
        record.report = {**record.report, "candidate_count": 2}
    with pytest.raises(VeriFlowError, match="reconcile"):
        publish_report(store, repo)
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(PublishedReport)) == 0


def test_projection_omits_source_model_prose_and_local_paths(store, scanned):
    repo, _, _, _ = scanned
    report = publish_report(store, repo)
    raw = render_report(report)
    assert "raw_sarif_path" not in raw and "Untrusted input" not in raw
    assert "query_path" not in raw and "text" not in report["candidates"][0]


@pytest.mark.parametrize(
    "payload", ['=HYPERLINK("https://example.test")', "  +1", "\t@SUM(1)", "-2"]
)
def test_csv_formula_neutralization(store, scanned, payload):
    report = publish_report(store, scanned[0])
    report["candidates"][0]["path"] = payload
    rows = list(csv.DictReader(io.StringIO(render_report(report, "candidates-csv"))))
    assert rows[0]["path"] == "'" + payload
    assert rows[0]["verified_finding_count"] == ""
    assert rows[0]["candidate_count"] == "1"


def test_html_markdown_escape_and_format_agreement(store, scanned):
    report = publish_report(store, scanned[0])
    report["candidates"][0]["rule_id"] = "<script>alert(1)</script>```[link](https://bad)"
    html = render_report(report, "html")
    markdown = render_report(report, "markdown")
    assert "<script>" not in html and "<script>" not in markdown
    assert "[link](https://bad)" not in markdown.split("```text")[0]
    assert html.count("<td>") == 7
    for format in ["json", "markdown", "html", "scan-csv", "candidates-csv"]:
        assert report["report_id"] in render_report(report, format)
    assert len(list(csv.DictReader(io.StringIO(render_report(report, "scan-csv"))))) == 1


def test_zero_candidates_is_not_clean_and_csv_retains_scan(store, scanned):
    repo, _, attempt, _ = scanned
    with store.transaction() as session:
        for candidate in session.scalars(select(Candidate).where(Candidate.attempt_id == attempt)):
            session.delete(candidate)
        record = session.get(ScanAttempt, attempt)
        record.report = {**record.report, "candidate_count": 0}
    report = publish_report(store, repo)
    assert report["candidate_count"] == 0 and report["security_verdict"] == "not_adjudicated"
    assert not report["coverage_verified"]
    assert list(csv.DictReader(io.StringIO(render_report(report, "candidates-csv")))) == []
    assert len(list(csv.DictReader(io.StringIO(render_report(report, "scan-csv"))))) == 1


def test_report_size_limit_is_atomic(store, scanned, monkeypatch):
    monkeypatch.setattr("veriflow.reports.MAX_REPORT_BYTES", 20)
    with pytest.raises(VeriFlowError, match="8 MiB"):
        publish_report(store, scanned[0])
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(PublishedReport)) == 0


def test_report_cli_and_migration(store, scanned):
    runner = CliRunner()
    base = ["--state-dir", str(store.root)]
    assert json.loads(runner.invoke(app, [*base, "init"]).output)["schema"] == "0011"
    result = runner.invoke(app, [*base, "publish-report", scanned[0]])
    assert result.exit_code == 0, result.output
    identity = json.loads(result.output)["report_id"]
    result = runner.invoke(
        app, [*base, "get-report", scanned[0], "--report-id", identity, "--format", "html"]
    )
    assert result.exit_code == 0 and "<!doctype html>" in result.output
    assert runner.invoke(app, [*base, "get-report", scanned[0], "--format", "bad"]).exit_code == 1
    assert runner.invoke(app, [*base, "report-history", scanned[0]]).exit_code == 0


def test_markdown_cell_escapes_each_character_once():
    from veriflow.reports import markdown_cell

    assert markdown_cell("needs_review (x) <b>") == ("needs&#95;review &#40;x&#41; &#60;b&#62;")
    assert "&&#" not in markdown_cell("a#(b)_[c]'d'")
