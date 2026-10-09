import json

import pytest
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow.bundles import build_bundle, elided_index, merge_duplicates, select_references
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.envelope import Envelope, resolve
from veriflow.persistence import Run
from veriflow.triage import set_budget, triage, triage_report

LONG = "".join(f"x = {n}\n" for n in range(40))


def reference(path, line, role="flow", **metadata):
    return (role, {"path": path, "line": line, "end_line": line}, metadata)


def test_duplicate_regions_merge_and_retain_every_step():
    merged = merge_duplicates(
        [
            reference("a.rs", 1, flow_step=0),
            reference("a.rs", 7, flow_step=1),
            reference("a.rs", 7, flow_step=2),
            reference("a.rs", 7, flow_step=3),
        ]
    )
    assert len(merged) == 2
    assert merged[1][2]["flow_steps_covered"] == [1, 2, 3]
    # A primary location never merges into a flow step that shares its region.
    assert len(merge_duplicates([reference("a.rs", 1, "primary"), reference("a.rs", 1)])) == 2
    # Unmapped references are never collapsed into each other.
    assert len(merge_duplicates([("flow", None, {}), ("flow", None, {})])) == 2


def test_selection_keeps_both_flow_endpoints():
    items = [reference("a.rs", 1, "primary")] + [
        reference("a.rs", n + 2, flow_step=n) for n in range(42)
    ]
    kept, elided = select_references(items, 8)
    steps = [item[2].get("flow_step") for item in kept if item[0] == "flow"]
    assert len(kept) == 8 and steps == [0, 1, 2, 3, 39, 40, 41]
    assert len(elided) == 35
    assert elided_index(elided, 2) == [
        {"role": "flow", "path": "a.rs", "line": 6, "flow_step": 4},
        {"role": "flow", "path": "a.rs", "line": 7, "flow_step": 5},
    ]
    # A single-slot budget still keeps the reported location rather than a flow step.
    kept, _ = select_references(items, 1)
    assert [item[0] for item in kept] == ["primary"]


def test_envelope_precedence_and_validation(tmp_path):
    config = tmp_path / "envelope.json"
    config.write_text(
        json.dumps(
            {
                "defaults": {"max_locations": 12},
                "profiles": {"veriflow/custom": {"max_locations": 30, "context_lines": 6}},
            }
        )
    )
    envelope = resolve(config, {}, {})
    assert envelope.for_rule("other").max_locations == 12
    assert envelope.for_rule("veriflow/custom").max_locations == 30
    assert envelope.for_rule("veriflow/custom").context_lines == 6
    # Environment beats the file; an explicit override beats the environment.
    environment = {"VERIFLOW_ENVELOPE_MAX_LOCATIONS": "20"}
    assert resolve(config, {}, environment).max_locations == 20
    assert resolve(config, {"max_locations": 25}, environment).max_locations == 25
    assert resolve(None, {}, {"VERIFLOW_ENVELOPE_CONFIG": str(config)}).max_locations == 12
    with pytest.raises(VeriFlowError, match="max_locations"):
        resolve(None, {"max_locations": 0}, {})
    with pytest.raises(VeriFlowError, match="below max_bundle_bytes"):
        resolve(None, {"max_source_bytes": 65536, "max_bundle_bytes": 32768}, {})
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"defaults": {"nope": 1}}))
    with pytest.raises(VeriFlowError, match="Unsupported envelope field"):
        resolve(bad, {}, {})


def test_envelope_widens_a_truncated_bundle(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=20, distinct_flow=True, source=LONG)
    narrow = build_bundle(store, attempt, fingerprint)
    assert narrow["status"] == "partial"
    assert any(gap.startswith("location_limit:") for gap in narrow["gaps"])
    assert narrow["elided_locations"] and narrow["envelope"]["max_locations"] == 8
    wide = build_bundle(store, attempt, fingerprint, Envelope(max_locations=32))
    assert wide["status"] == "ready" and wide["gaps"] == []
    assert len(wide["snippets"]) == 21 and wide["location_limit"] == 32
    # A different envelope is a different bundle, so the digest keeps them apart.
    assert wide["bundle_id"] != narrow["bundle_id"]


def test_unmetered_skips_every_budget_check_but_still_accounts(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture()
    bundle = build_bundle(store, attempt, fingerprint)
    adapter = FakeAdapter()
    # No budget row exists at all, which normally refuses the request outright.
    with pytest.raises(VeriFlowError, match="budget"):
        triage(store, bundle["bundle_id"], policy(), adapter, "metered")
    result = triage(store, bundle["bundle_id"], policy(), adapter, "free", unmetered=True)
    assert result["state"] == "evidence_rejected" and adapter.calls == 1
    assert result["accounted_micro_usd"] == 140 and result["metered"] is False
    assert result["verified"] is False
    # An exhausted budget no longer stops the call, and the spend is still recorded.
    set_budget(store, bundle["run_id"], 1, max_requests=1)
    second = triage(store, bundle["bundle_id"], policy(), adapter, "free-2", unmetered=True)
    assert second["state"] == "evidence_rejected" and adapter.calls == 2
    ledger = triage_report(store, bundle["run_id"])
    assert ledger["accounted_micro_usd"] == 280 and ledger["overrun_micro_usd"] == 279
    assert ledger["remaining_requests"] == 0


def test_degraded_evidence_reaches_the_model_without_becoming_verified(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=20, distinct_flow=True, source=LONG)
    bundle = build_bundle(store, attempt, fingerprint)
    assert bundle["status"] == "partial"
    set_budget(store, bundle["run_id"], 100000)
    blocked = triage(store, bundle["bundle_id"], policy(), FakeAdapter(), "blocked")
    assert blocked["state"] == "incomplete_evidence" and blocked["evidence_degraded"]
    adapter = FakeAdapter()
    allowed = triage(
        store,
        bundle["bundle_id"],
        policy(),
        adapter,
        "allowed",
        allow_degraded_evidence=True,
    )
    assert adapter.calls == 1 and allowed["state"] in {"advisory_unverified", "evidence_rejected"}
    assert allowed["disposition"] == "abstain" and allowed["verified"] is False
    assert allowed["decision"] is not None and allowed["evidence_degraded"]


def test_cli_exposes_envelope_and_unmetered(store, evidence_fixture, tmp_path, monkeypatch):
    run, attempt, fingerprint, _ = evidence_fixture(flow_count=20, distinct_flow=True, source=LONG)
    config = tmp_path / "policy.json"
    config.write_text(policy().model_dump_json())
    adapter = FakeAdapter()
    monkeypatch.setattr("veriflow.models.ReplayAdapter", lambda path: adapter)
    built = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "build-bundle",
            attempt,
            fingerprint,
            "--max-locations",
            "32",
        ],
    )
    assert built.exit_code == 0 and json.loads(built.output)["status"] == "ready"
    with store.transaction() as session:
        repo = session.get(Run, run).repo_id
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "triage-attempt",
            repo,
            attempt,
            str(config),
            "batch",
            "--replay",
            str(tmp_path / "fixture.json"),
            "--unmetered",
            "--allow-degraded-evidence",
            "--max-locations",
            "32",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["metered"] is False and payload["degraded_evidence_allowed"] is True
    assert adapter.calls == 1


def test_expansion_honours_the_parent_envelope(store, evidence_fixture):
    from veriflow.expansion import ExpansionItem, expand_bundle

    wide = Envelope(max_locations=32, max_source_bytes=48 * 1024, max_bundle_bytes=128 * 1024)
    # Wide lines around the flow so the parent genuinely exceeds the packaged 16 KiB default.
    big = (
        "".join(("# " + "w" * 1200 + "\n") if n < 10 else f"x = {n}\n" for n in range(900))
        + "guard = 1\n"
    )
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=2, distinct_flow=True, source=big)
    parent = build_bundle(store, attempt, fingerprint, wide)
    # The parent already holds more source than the packaged 16 KiB default allows.
    assert sum(len(s["text"].encode()) for s in parent["snippets"]) > 16 * 1024
    child = expand_bundle(
        store,
        parent["bundle_id"],
        [ExpansionItem(path="app.py", line=901, end_line=901, reason="guard")],
    )
    assert len(child["snippets"]) == len(parent["snippets"]) + 1
    assert child["envelope"]["max_source_bytes"] == 48 * 1024
