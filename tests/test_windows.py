import json

import pytest
from sqlalchemy import select
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow.bundles import allocate_source, build_bundle, excerpt_options
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.envelope import Envelope
from veriflow.persistence import Run
from veriflow.triage import set_budget, triage_report
from veriflow.windows import flow_length, plan_windows, triage_windows

LONG = "".join(f"x = {n}\n" for n in range(60))
# A large intermediate region that greedy allocation would let starve the flow's endpoints.
HEAVY = "".join(("# " + "y" * 9000 + "\n") if n in (5, 6) else f"x = {n}\n" for n in range(40))


def item(sizes, priority=1):
    return {"sizes": sizes, "options": [None] * len(sizes), "priority": priority}


def test_excerpt_options_widen_from_the_region_outwards():
    lines = ["line\n"] * 20
    assert excerpt_options(lines, 10, 10, 3, False) == [(10, 10), (9, 11), (8, 12), (7, 13)]
    # Clamping collapses duplicates instead of repeating an identical window.
    assert excerpt_options(lines, 1, 1, 2, False) == [(1, 1), (1, 2), (1, 3)]
    assert excerpt_options(lines, 10, 10, 1, True)[-1] == (1, 20)


def test_allocation_serves_minimums_before_context():
    # The wide middle item cannot crowd out the others' narrowest excerpts, and the
    # leftover budget upgrades context one step at a time across every item in turn.
    assert allocate_source([item([10, 50]), item([900]), item([10, 50])], 1000) == [1, 0, 1]
    # With no leftover there is no context, but every minimum is still served.
    assert allocate_source([item([10, 100]), item([900]), item([10, 100])], 1000) == [0, 0, 0]
    # Endpoints are served first when even the minimums do not all fit.
    starved = allocate_source([item([60], 0), item([60]), item([60], 0)], 130)
    assert starved == [0, None, 0]
    assert allocate_source([item([10])], 5) == [None]


def test_fair_allocation_keeps_every_selected_location(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=10, distinct_flow=True, source=HEAVY)
    bundle = build_bundle(store, attempt, fingerprint)
    steps = [s.get("flow_step") for s in bundle["snippets"] if s.get("flow_id")]
    # Nothing was dropped for budget: context was traded instead, and both endpoints survive.
    assert not any("source_budget" in gap for gap in bundle["gaps"])
    assert steps[0] == 0 and steps[-1] == 9
    # Trimming is a note, not a gap, so the gates still judge the bundle on its merits.
    assert any(note.startswith("source_budget_trimmed:") for note in bundle["notes"])
    assert sum(len(s["text"].encode()) for s in bundle["snippets"]) <= 16 * 1024


def test_plan_windows_covers_every_step_with_overlap():
    assert plan_windows(42, 7, 1) == [
        (0, 6),
        (6, 12),
        (12, 18),
        (18, 24),
        (24, 30),
        (30, 36),
        (36, 41),
    ]
    assert plan_windows(5, 7, 1) == [(0, 4)]
    assert plan_windows(0, 7, 1) == []
    # Every step is covered exactly once when no overlap is requested.
    assert sorted({s for a, b in plan_windows(10, 4, 0) for s in range(a, b + 1)}) == list(
        range(10)
    )
    with pytest.raises(VeriFlowError, match="Window overlap"):
        plan_windows(10, 4, 4)
    with pytest.raises(VeriFlowError, match="Window size"):
        plan_windows(10, 1, 0)


def test_windows_restrict_the_materialized_flow(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    base = build_bundle(store, attempt, fingerprint)
    assert flow_length(base) == 42
    middle = build_bundle(
        store,
        attempt,
        fingerprint,
        None,
        {"index": 2, "count": 7, "flow_step_start": 12, "flow_step_end": 18},
    )
    steps = [s["flow_step"] for s in middle["snippets"] if s.get("flow_id")]
    assert steps == list(range(12, 19)) and middle["window"]["index"] == 2
    # The reported location is always retained so the window says what it belongs to.
    assert middle["snippets"][0]["role"] == "primary"
    assert middle["bundle_id"] != base["bundle_id"]


def test_windowed_triage_stays_advisory(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    set_budget(store, run.id, 1000000, max_requests=100)
    adapter = FakeAdapter()
    result = triage_windows(store, run.repo_id, attempt, policy(), adapter, "win", limit=1)
    page = result["items"][0]
    assert result["status"] == "page_complete" and result["verified"] is False
    assert page["windowed"] is True and page["flow_steps"] == 42
    assert page["window_count"] == 7 and page["covered_flow_steps"] == 42
    assert adapter.calls == 7 and page["disposition"] == "abstain"
    assert {row["flow_step_start"] for row in page["windows"]} == {0, 6, 12, 18, 24, 30, 36}
    assert all(row["evidence_degraded"] for row in page["windows"])
    assert all(row["disposition"] == "abstain" for row in page["windows"])
    # Repeating the request is idempotent: the derived keys replay the stored calls.
    again = triage_windows(store, run.repo_id, attempt, policy(), adapter, "win", limit=1)
    assert adapter.calls == 7 and again["items"][0]["windows"] == page["windows"]
    assert triage_report(store, run.id)["total"] == 7


def test_short_flow_skips_windowing(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=3, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    set_budget(store, run.id, 1000000)
    adapter = FakeAdapter()
    result = triage_windows(store, run.repo_id, attempt, policy(), adapter, "short")
    page = result["items"][0]
    assert page["windowed"] is False and page["window_count"] == 1 and adapter.calls == 1
    # An ordinary single bundle keeps the ordinary gates, so nothing is marked degraded.
    assert not page["windows"][0]["evidence_degraded"]


def test_window_count_is_bounded_and_reported(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    adapter = FakeAdapter()
    result = triage_windows(
        store, run.repo_id, attempt, policy(), adapter, "cap", unmetered=True, max_windows=3
    )
    page = result["items"][0]
    assert page["windows_truncated"] is True and page["window_count"] == 3
    assert page["covered_flow_steps"] == 19 and adapter.calls == 3
    with pytest.raises(VeriFlowError, match="Window count"):
        triage_windows(store, run.repo_id, attempt, policy(), adapter, "cap", max_windows=99)


def test_windows_cli(store, evidence_fixture, tmp_path, monkeypatch):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    config = tmp_path / "policy.json"
    config.write_text(policy().model_dump_json())
    adapter = FakeAdapter()
    monkeypatch.setattr("veriflow.models.ReplayAdapter", lambda path: adapter)
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "triage-windows",
            run.repo_id,
            attempt,
            str(config),
            "cli",
            "--replay",
            str(tmp_path / "fixture.json"),
            "--unmetered",
            "--overlap",
            "2",
            "--max-windows",
            "4",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["metered"] is False and payload["verified"] is False
    assert payload["items"][0]["window_overlap"] == 2 and adapter.calls == 4


def test_widening_the_envelope_removes_the_need_for_windows(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    adapter = FakeAdapter()
    result = triage_windows(
        store,
        run.repo_id,
        attempt,
        policy(),
        adapter,
        "wide",
        unmetered=True,
        envelope=Envelope(
            max_locations=64, max_source_bytes=64 * 1024, max_bundle_bytes=256 * 1024
        ),
    )
    assert result["items"][0]["windowed"] is False and adapter.calls == 1


def test_coverage_counts_materialized_steps_not_requested_spans(store, evidence_fixture):
    # The file ends at line 10, so steps whose region falls past it never materialize.
    _, attempt, fingerprint, _ = evidence_fixture(
        flow_count=20, distinct_flow=True, source="".join(f"x = {n}\n" for n in range(10))
    )
    with store.transaction() as session:
        run = session.scalar(select(Run))
    result = triage_windows(
        store, run.repo_id, attempt, policy(), FakeAdapter(), "short-file", unmetered=True
    )
    page = result["items"][0]
    requested = sum(row["flow_step_end"] - row["flow_step_start"] + 1 for row in page["windows"])
    assert page["flow_steps"] == 20 and requested == 20 + len(page["windows"]) - 1
    # Only the steps that bind inside the file are counted as covered.
    assert 0 < page["covered_flow_steps"] < 20


def test_truncation_reports_the_original_plan(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    page = triage_windows(
        store, run.repo_id, attempt, policy(), FakeAdapter(), "plan", unmetered=True, max_windows=2
    )["items"][0]
    assert page["planned_windows"] == 7 and page["window_count"] == 2
    assert page["windows_truncated"] is True
