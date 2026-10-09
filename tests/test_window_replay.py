"""Windowed triage over the real request path, pinning what each window actually sends."""

import json
from pathlib import Path

import pytest
from sqlalchemy import select
from test_triage import evidence_fixture as evidence_fixture

from veriflow.bundles import build_bundle, canonical
from veriflow.models import Decision, ModelConfig, ReplayAdapter, Reply, Usage, request_body
from veriflow.persistence import Run, TriageCall
from veriflow.reports import publish_report, render_report
from veriflow.windows import triage_windows

LONG = "".join(f"x = {n}\n" for n in range(60))
# A window prompt must stay well inside a modest local context; this is the budget we accept.
MAX_WINDOW_PROMPT_BYTES = 24 * 1024


@pytest.fixture
def replay(tmp_path):
    path = tmp_path / "response.json"
    path.write_text(
        Reply(
            status="completed",
            decision=Decision(
                verdict="needs_review",
                rationale="Segment reviewed",
                evidence_ids=["E1"],
                counterevidence="",
            ),
            usage=Usage(input_tokens=400, output_tokens=40),
        ).model_dump_json()
    )
    return path


def policy():
    return ModelConfig(
        provider="replay",
        model="fixture",
        input_micro_usd_per_1k=1000,
        output_micro_usd_per_1k=2000,
        allow_source_transmission=True,
    )


@pytest.fixture
def long_flow(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=42, distinct_flow=True, source=LONG)
    with store.transaction() as session:
        run = session.scalar(select(Run))
    return run, attempt, fingerprint


def test_window_request_shape_is_pinned(store, long_flow):
    _, attempt, fingerprint = long_flow
    window = {"index": 1, "count": 7, "flow_step_start": 6, "flow_step_end": 12}
    bundle = build_bundle(store, attempt, fingerprint, None, window)
    body = request_body(bundle, policy())
    sent = json.loads(canonical(body)[: len(canonical(body))].decode())
    payload = json.loads(sent["input"])["bundle"]

    # The window and its scope reach the model, so a partial view is never presented as whole.
    assert payload["window"] == window
    assert any(gap.startswith("window_scope:") for gap in payload["gaps"])
    assert payload["reachability_proven"] is False
    assert payload["trust"] == "untrusted_source_and_tool_output"
    # Every field the builder records is serialized; adding one changes every prompt.
    assert set(payload) >= {
        "candidate_fingerprint",
        "duplicate_locations_merged",
        "elided_locations",
        "envelope",
        "gaps",
        "location_limit",
        "snippets",
        "window",
    }
    assert len(canonical(body)) <= MAX_WINDOW_PROMPT_BYTES


def test_elided_index_stays_within_its_share_of_the_prompt(store, evidence_fixture):
    # A flow long enough that the index cap genuinely bites rather than passing vacuously.
    _, attempt, fingerprint, _ = evidence_fixture(
        flow_count=120, distinct_flow=True, source="".join(f"x = {n}\n" for n in range(140))
    )
    bundle = build_bundle(
        store,
        attempt,
        fingerprint,
        None,
        {"index": 0, "count": 18, "flow_step_start": 0, "flow_step_end": 6},
    )
    elided = bundle["elided_locations"]
    assert bundle["locations_total"] == 121
    # More was omitted than the index will name, and the cap is what stops it growing.
    assert len(elided) == bundle["envelope"]["max_elided_index"] == 64
    prompt = len(canonical(request_body(bundle, policy())))
    # Naming omitted steps is worth prompt budget, but it must not dominate it.
    assert len(canonical(elided)) < prompt // 3
    assert prompt <= MAX_WINDOW_PROMPT_BYTES


def test_replayed_windows_round_trip_through_the_gate(store, long_flow, replay):
    run, attempt, _ = long_flow
    adapter = ReplayAdapter(replay)
    result = triage_windows(
        store, run.repo_id, attempt, policy(), adapter, "replayed", unmetered=True
    )
    page = result["items"][0]
    assert page["windowed"] is True and page["window_count"] == 7
    # The provider answered every window, and every answer stayed advisory.
    assert all(row["state"] == "advisory_unverified" for row in page["windows"])
    assert all(row["disposition"] == "abstain" for row in page["windows"])
    assert page["model_suggested_verdicts"] == ["needs_review"]
    assert result["verified"] is False

    with store.transaction() as session:
        calls = list(session.scalars(select(TriageCall).where(TriageCall.run_id == run.id)))
    assert len(calls) == 7
    # Usage from the replayed response is accounted, not assumed.
    assert all(call.result["usage"] == {"input_tokens": 400, "output_tokens": 40} for call in calls)
    assert all(call.charged_micro_usd == 480 for call in calls)
    # Each window is a distinct request against a distinct bundle.
    assert len({call.request_sha256 for call in calls}) == 7
    assert len({call.bundle_id for call in calls}) == 7


def test_replay_identity_binds_the_stored_response(store, long_flow, replay, tmp_path):
    run, attempt, _ = long_flow
    first = triage_windows(
        store, run.repo_id, attempt, policy(), ReplayAdapter(replay), "bound", unmetered=True
    )
    changed = Path(tmp_path / "other.json")
    changed.write_text(
        Reply(
            status="completed",
            decision=Decision(
                verdict="abstain", rationale="Different", evidence_ids=[], counterevidence=""
            ),
            usage=Usage(input_tokens=400, output_tokens=40),
        ).model_dump_json()
    )
    # A different stored response is a different request, so the same key must be refused.
    second = triage_windows(
        store, run.repo_id, attempt, policy(), ReplayAdapter(changed), "bound", unmetered=True
    )
    assert first["items"][0]["windows"][0]["state"] == "advisory_unverified"
    assert second["items"][0]["windows"][0]["state"] == "operation_error"
    assert "already used" in second["items"][0]["windows"][0]["error"]


class AlternatingAdapter:
    """A provider that changes its mind between windows, which overlap must expose."""

    identity = "alternating-fixture"

    def __init__(self):
        self.calls = 0

    def invoke(self, body):
        self.calls += 1
        verdict = "needs_review" if self.calls % 2 else "likely_false_positive"
        return Reply(
            status="completed",
            decision=Decision(
                verdict=verdict,
                rationale="Segment reviewed",
                evidence_ids=["E1"],
                counterevidence="Guard unknown",
            ),
            usage=Usage(input_tokens=400, output_tokens=40),
        )


def test_overlapping_windows_report_contradictions(store, long_flow):
    run, attempt, _ = long_flow
    page = triage_windows(
        store, run.repo_id, attempt, policy(), AlternatingAdapter(), "split", unmetered=True
    )["items"][0]
    # Consecutive windows share one step, and they answered differently about it.
    assert page["overlapping_steps"] == [6, 12, 18, 24, 30, 36]
    assert page["verdicts_disagree"] is True
    assert [item["flow_step"] for item in page["contradicted_steps"]] == [
        6,
        12,
        18,
        24,
        30,
        36,
    ]
    assert page["contradicted_steps"][0]["verdicts"] == [
        "likely_false_positive",
        "needs_review",
    ]
    # Disagreement changes nothing about the outcome, which was never a verdict.
    assert page["disposition"] == "abstain"


def test_agreeing_windows_report_no_contradiction(store, long_flow, replay):
    run, attempt, _ = long_flow
    page = triage_windows(
        store, run.repo_id, attempt, policy(), ReplayAdapter(replay), "agree", unmetered=True
    )["items"][0]
    assert page["overlapping_steps"] == [6, 12, 18, 24, 30, 36]
    assert page["verdicts_disagree"] is False and page["contradicted_steps"] == []


def test_a_reduced_run_cannot_read_as_a_complete_one(store, long_flow, replay):
    run, attempt, _ = long_flow
    triage_windows(
        store, run.repo_id, attempt, policy(), ReplayAdapter(replay), "reduced", unmetered=True
    )
    report = publish_report(store, run.repo_id, run.id, attempt)
    reductions = report["advisory_reductions"]
    assert reductions["advisory_calls"] == 7
    assert reductions["unmetered_calls"] == 7
    assert reductions["degraded_evidence_calls"] == 7
    assert reductions["windowed_calls"] == 7 and reductions["windowed_candidates"] == 1
    assert reductions["partial_bundle_calls"] == 7

    entry = report["candidates"][0]["triage_history"][0]
    # Each call carries its own reduction, not just the summary.
    assert entry["metered"] is False and entry["evidence_degraded"]
    assert entry["window"]["flow_step_start"] == 0 and entry["bundle_status"] == "partial"

    summary = render_report(report, "markdown")
    assert "Reduced advisory evidence" in summary
    assert "7 windowed" in summary and "7 unmetered" in summary
