import json

import pytest
from test_reports import scanned as scanned
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow import batch_triage
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.persistence import Candidate
from veriflow.triage import set_budget, triage_report


def test_durable_idempotency_and_policy_conflict(store, scanned):
    repo, run, attempt, _ = scanned
    set_budget(store, run, 100000, max_requests=2)
    adapter = FakeAdapter()
    first = batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "batch")
    assert first["status"] == "page_complete" and first["next_offset"] is None
    assert first["items"][0]["state"] == "evidence_rejected" and adapter.calls == 1
    assert batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "batch") == first
    assert adapter.calls == 1 and triage_report(store, run)["total"] == 1
    conflict = batch_triage.triage_attempt(
        store, repo, attempt, policy(max_output_tokens=128), adapter, "batch"
    )
    assert conflict["status"] == "halted" and conflict["next_offset"] == 0
    assert conflict["items"][0]["state"] == "operation_error" and adapter.calls == 1


def test_budget_and_request_stops(store, scanned):
    repo, run, attempt, _ = scanned
    set_budget(store, run, 0, max_requests=1)
    adapter = FakeAdapter()
    result = batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "batch")
    assert result["status"] == "halted" and result["items"][0]["state"] == "budget_exhausted"
    assert adapter.calls == 0
    result = batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "new-key")
    assert result["items"][0]["state"] == "operation_error" and result["next_offset"] == 0
    assert triage_report(store, run)["total"] == 1


def test_scope_and_page_validation(store, scanned):
    repo, run, attempt, _ = scanned
    adapter = FakeAdapter()
    with pytest.raises(VeriFlowError, match="budget"):
        batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "batch")
    set_budget(store, run, 100000)
    with pytest.raises(VeriFlowError, match="belong"):
        batch_triage.triage_attempt(store, "other", attempt, policy(), adapter, "batch")
    with pytest.raises(VeriFlowError, match="100"):
        batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "batch", limit=101)
    result = batch_triage.triage_attempt(store, repo, attempt, policy(), adapter, "batch", offset=1)
    assert result["items"] == [] and result["next_offset"] is None and adapter.calls == 0


def test_batch_halts_before_second_candidate(store, scanned, monkeypatch):
    repo, run, attempt, _ = scanned
    set_budget(store, run, 100000)
    with store.transaction() as session:
        session.add(Candidate(id="second", attempt_id=attempt, fingerprint="z" * 64, evidence={}))
    calls = []
    monkeypatch.setattr(batch_triage, "build_bundle", lambda *a: {"bundle_id": "fixture"})

    def uncertain(*args, **kwargs):
        calls.append(args[-1])
        return {"state": "unknown"}

    monkeypatch.setattr(batch_triage, "triage", uncertain)
    result = batch_triage.triage_attempt(
        store, repo, attempt, policy(), FakeAdapter(), "batch", limit=2
    )
    assert result["selected_candidates"] == 2 and len(result["items"]) == 1
    assert result["status"] == "halted" and result["next_offset"] == 1 and len(calls) == 1


def test_cli_policy_loading_and_repeat(store, scanned, tmp_path, monkeypatch):
    repo, run, attempt, _ = scanned
    set_budget(store, run, 100000)
    config = tmp_path / "policy.json"
    config.write_text(policy().model_dump_json())
    adapter = FakeAdapter()
    monkeypatch.setattr("veriflow.models.ReplayAdapter", lambda path: adapter)
    args = [
        "--state-dir",
        str(store.root),
        "triage-attempt",
        repo,
        attempt,
        str(config),
        "batch",
        "--replay",
        str(tmp_path / "fixture.json"),
    ]
    first = CliRunner().invoke(app, args)
    second = CliRunner().invoke(app, args)
    assert first.exit_code == second.exit_code == 0
    assert json.loads(first.output) == json.loads(second.output) and adapter.calls == 1
