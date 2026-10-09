import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_joern_advisory import adapter_for
from test_joern_claims import review_decision
from test_slice03 import captured_source as captured_source
from test_triage import policy

from veriflow import joern, pipeline
from veriflow.bundles import build_bundle
from veriflow.claims import assess_evidence
from veriflow.domain import VeriFlowError
from veriflow.joern_claims import RUST_POLICY, assess_review_evidence, review_preflight
from veriflow.models import request_body
from veriflow.reports import get_report
from veriflow.scan_advisory import AdvisoryOptions
from veriflow.scanning import scan_report
from veriflow.triage import set_budget, triage


@pytest.fixture
def rust_bundle(store, captured_source, tmp_path, monkeypatch):
    fixtures = Path(__file__).parent / "fixtures"
    run = captured_source(
        {
            "main.rs": (fixtures / "joern-rust-env/vulnerable/main.rs").read_text(),
            "Cargo.toml": (fixtures / "joern-rust-env/vulnerable/Cargo.toml").read_text(),
        }
    )
    monkeypatch.setattr("veriflow.joern_rust.trusted_toolchain", lambda *args: tmp_path)
    home = tmp_path / "tools"
    (home / "lib").mkdir(parents=True)
    (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()

    def fake(command, root, name, timeout, **kwargs):
        if name == "analyze":
            (root / "flows.json").write_bytes(
                (fixtures / "joern-rust-advisory/native-flow.json").read_bytes()
            )

    monkeypatch.setattr(joern, "stage", fake)
    result = joern.discover(
        store, run, home, language="rust", discovery_profile="rust-env-shell-v1", rust_home=tmp_path
    )
    report = scan_report(store, "example", run, result["attempt_id"])
    return build_bundle(store, result["attempt_id"], report["candidates"][0]["fingerprint"])


def test_literal_native_path_and_explicit_gate_only(rust_bundle):
    b = rust_bundle
    assert b["joern_native_audit"]["status"] == "validated"
    gate = assess_review_evidence(b, review_decision(b), RUST_POLICY)
    assert gate["passed"] and not gate["reachability_proven"]
    assert not gate["automatic_triage_enabled"]
    assert assess_evidence(b, review_decision(b))["status"] == "unsupported_engine"
    assert not review_preflight(b)["passed"]


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "query",
        "hash",
        "order",
        "truncated",
        "context",
        "source",
        "sink",
        "intermediate",
        "negative",
        "quote",
    ],
)
def test_bad_evidence_and_claims_fail_closed(rust_bundle, change):
    b = deepcopy(rust_bundle)
    decision = review_decision(b)
    audit = b["joern_native_audit"]
    if change == "missing":
        b.pop("joern_native_audit")
    elif change == "query":
        audit["query_sha256"] = "wrong"
    elif change == "hash":
        audit["nodes"][0]["sha256"] = "wrong"
    elif change == "order":
        audit["nodes"].reverse()
    elif change == "truncated":
        b["snippets"].pop()
    elif change == "context":
        for s in b["snippets"]:
            s["source_line_count"] += 1
    elif change in {"source", "sink"}:
        # Keep the alternate full context internally hash-consistent to exercise syntax binding.
        old, new = (
            ("std::env::var", "bad::env::var")
            if change == "source"
            else ("std::process::Command", "bad::process::Command")
        )
        for s in b["snippets"]:
            s["text"] = s["text"].replace(old, new)
            s["sha256"] = hashlib.sha256(s["text"].encode()).hexdigest()
        for n in audit["nodes"]:
            n["sha256"] = b["snippets"][0]["sha256"]
    elif change == "intermediate":
        audit["nodes"][1]["code"] = "fabricated"
    elif change == "negative":
        decision = decision.model_copy(update={"verdict": "likely_false_positive"})
    else:
        decision = decision.model_copy(
            update={
                "claims": [
                    decision.claims[0].model_copy(update={"quote": "fabricated"}),
                    *decision.claims[1:],
                ]
            }
        )
    assert not assess_review_evidence(b, decision, RUST_POLICY)["passed"]


def test_sink_argument_alone_does_not_satisfy_call_quote(rust_bundle):
    decision = review_decision(rust_bundle)
    decision = decision.model_copy(
        update={
            "claims": [
                decision.claims[0],
                decision.claims[1].model_copy(update={"quote": "command"}),
                *decision.claims[2:],
            ]
        }
    )
    assert not assess_review_evidence(rust_bundle, decision, RUST_POLICY)["passed"]


@pytest.mark.parametrize("stop", [None, "budget", "evidence"])
def test_opt_in_cost_gates_and_idempotency(store, rust_bundle, monkeypatch, stop):
    b = rust_bundle
    set_budget(store, b["run_id"], 0 if stop == "budget" else 100000)
    adapter = adapter_for(b)
    if stop == "evidence":
        altered = deepcopy(b)
        altered.pop("joern_native_audit")
        monkeypatch.setattr("veriflow.triage.get_bundle", lambda *args: altered)
    result = triage(store, b["bundle_id"], policy(), adapter, "rust", review_policy=RUST_POLICY)
    assert (
        result["state"]
        == {None: "completed", "budget": "budget_exhausted", "evidence": "incomplete_evidence"}[
            stop
        ]
    )
    assert adapter.calls == (0 if stop else 1)
    assert not result["verified"]
    assert result["accounted_micro_usd"] == (0 if stop else 140)
    assert (
        triage(store, b["bundle_id"], policy(), adapter, "rust", review_policy=RUST_POLICY)
        == result
    )
    assert adapter.calls <= 1


def test_main_workflow_and_policy_scope(store, rust_bundle, tmp_path):
    b = rust_bundle
    advisory = AdvisoryOptions(policy(), adapter_for(b), "workflow", RUST_POLICY)
    with pytest.raises(VeriFlowError, match="profile"):
        advisory.validate_scope("rust", None)
    with pytest.raises(VeriFlowError, match="profile"):
        advisory.validate_scope("java", "rust-env-shell-v1")
    set_budget(store, b["run_id"], 100000)
    result = pipeline.scan_run(
        store,
        b["run_id"],
        engine="joern",
        language="auto",
        joern_home=tmp_path / "tools",
        rust_home=tmp_path,
        joern_profile="rust-env-shell-v1",
        advisory=advisory,
    )
    assert result["model_calls"] == 1 and result["live_model_calls"] == 0
    report = get_report(store, b["repo_id"], report_id=result["report_id"])
    assert report["candidates"][0]["latest_advisory"] == "needs_review"
    assert report["static_review_readiness"]["state"] == "incomplete"


def test_policy_in_provider_request_and_cli(store, rust_bundle, tmp_path):
    from typer.testing import CliRunner

    from veriflow.cli import app

    b = rust_bundle
    body = request_body(b, policy(), review_policy=RUST_POLICY)
    assert RUST_POLICY in json.dumps(body)
    decision = tmp_path / "decision.json"
    decision.write_text(review_decision(b).model_dump_json())
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "check-evidence",
            b["bundle_id"],
            str(decision),
            "--review-policy",
            RUST_POLICY,
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["passed"]


def test_eight_node_crossfile_path_is_retained(store, captured_source, tmp_path, monkeypatch):
    fixtures = Path(__file__).parent / "fixtures"
    run = captured_source(
        {
            p.name: p.read_text()
            for p in (fixtures / "joern-rust-env/crossfile-vulnerable").iterdir()
            if p.is_file()
        }
    )
    monkeypatch.setattr("veriflow.joern_rust.trusted_toolchain", lambda *args: tmp_path)
    home = tmp_path / "tools"
    (home / "lib").mkdir(parents=True)
    (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()

    def fake(command, root, name, timeout, **kwargs):
        if name == "analyze":
            (root / "flows.json").write_bytes(
                (fixtures / "joern-rust-advisory/crossfile-native.json").read_bytes()
            )

    monkeypatch.setattr(joern, "stage", fake)
    result = joern.discover(
        store, run, home, language="rust", rust_home=tmp_path, discovery_profile="rust-env-shell-v1"
    )
    report = scan_report(store, "example", run, result["attempt_id"])
    b = build_bundle(store, result["attempt_id"], report["candidates"][0]["fingerprint"])
    # Repeated regions are merged, so every one of the eight steps is still mapped by a snippet.
    assert b["status"] == "ready" and b["locations_total"] == 9
    covered = sorted(
        step
        for snippet in b["snippets"]
        if snippet.get("flow_id") is not None
        for step in (snippet.get("flow_steps_covered") or [snippet["flow_step"]])
    )
    assert covered == list(range(8)) and b["duplicate_locations_merged"] == 3
    assert assess_review_evidence(b, review_decision(b), RUST_POLICY)["passed"]
    # Larger paths still fail the explicit gate rather than dropping their intermediate nodes.
    b["joern_native_audit"]["nodes"].append(b["joern_native_audit"]["nodes"][-1])
    assert not review_preflight(b, RUST_POLICY)["passed"]
