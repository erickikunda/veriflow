import json

import pytest
from sqlalchemy import func, select
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow import llm_discovery, pipeline
from veriflow.bundles import build_bundle
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.llm_discovery import (
    DiscoveryReply,
    DiscoveryResponse,
    build_packet,
    discovery_report,
    load_options,
    parse_discovery_response,
    replay_discovery,
    run_hybrid_discovery,
)
from veriflow.models import Decision, ModelConfig, Reply, Usage
from veriflow.persistence import DiscoveryCall, Run, ScanAttempt
from veriflow.reports import publish_report
from veriflow.reviews import ReviewRequest, record_review
from veriflow.triage import set_budget, triage, triage_report


def documents(store, evidence_fixture, tmp_path):
    run_id, attempt_id, _, _ = evidence_fixture()
    _, manifest, tree = verified_source(store, run_id)
    record = next(item for item in manifest.files if item.path == "app.py")
    text = (tree / record.path).read_text()
    with store.transaction() as session:
        attempt = session.get(ScanAttempt, attempt_id)
        attempt.report = {
            **attempt.report,
            "snapshot_id": manifest.snapshot_id,
            "language": "python",
        }
    packet = {
        "schema_version": "1",
        "run_id": run_id,
        "attempt_id": attempt_id,
        "snapshot_id": manifest.snapshot_id,
        "language": "python",
        "classification": manifest.classification,
        "selection_policy": "risk-markers-plus-deterministic-sample-v1",
        "eligible_files": 1,
        "examined_files": 1,
        "deferred_files": 0,
        "selection_reasons": ["security-sensitive API sample"],
        "excerpts": [
            {
                "evidence_id": "E1",
                "path": record.path,
                "sha256": record.sha256,
                "line": 1,
                "end_line": 2,
                "text": text,
            }
        ],
    }
    response = {
        "schema_version": "1",
        "proposals": [
            {
                "cwe": "CWE-95",
                "weakness": "Potential evaluation of attacker-controlled input",
                "primary": {
                    "evidence_id": "E1",
                    "path": "app.py",
                    "line": 2,
                    "end_line": 2,
                },
                "related": [],
                "attacker_control_hypothesis": (
                    "The function parameter may be externally controlled."
                ),
                "impact_hypothesis": "Evaluation may execute supplied Python expressions.",
                "unknowns": ["Callers and deployment routing are not present."],
                "confidence": "medium",
            }
        ],
        "coverage_notes": ["Only the supplied packet was considered."],
    }
    packet_path = tmp_path / "packet.json"
    response_path = tmp_path / "response.json"
    packet_path.write_text(json.dumps(packet))
    response_path.write_text(json.dumps(response))
    return run_id, attempt_id, packet_path, response_path, packet, response


def test_replay_records_validated_proposals_and_candidates(store, evidence_fixture, tmp_path):
    run_id, attempt_id, packet, response, _, _ = documents(store, evidence_fixture, tmp_path)
    result = replay_discovery(store, attempt_id, packet, response, "discovery-1")
    assert result["state"] == "completed"
    assert result["proposal_count"] == 1
    assert result["proposals"][0]["origin"] == "llm_discovery"
    assert result["proposals"][0]["adjudication"] == "not_adjudicated"
    assert result["candidate_rows_created"] == 1
    assert replay_discovery(store, attempt_id, packet, response, "discovery-1") == result
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(DiscoveryCall)) == 1
        assert session.scalar(select(DiscoveryCall)).run_id == run_id
    history = discovery_report(store, run_id, attempt_id)
    assert history["total"] == 1 and history["calls"] == [result]


def test_llm_candidate_builds_evidence_and_accepts_explicit_review(
    store, evidence_fixture, tmp_path
):
    _, attempt_id, packet, response, _, _ = documents(store, evidence_fixture, tmp_path)
    result = replay_discovery(store, attempt_id, packet, response, "candidate-review")
    fingerprint = result["proposals"][0]["candidate_fingerprint"]
    bundle = build_bundle(store, attempt_id, fingerprint)
    assert bundle["engine_id"] == "llm_discovery"
    assert bundle["status"] == "ready" and bundle["snippets"][0]["path"] == "app.py"
    review = record_review(
        store,
        "example",
        attempt_id,
        fingerprint,
        ReviewRequest(
            reviewer_label="security-reviewer",
            state="confirmed",
            rationale="Confirmed against the retained immutable source excerpt.",
            bundle_id=bundle["bundle_id"],
            evidence_ids=["E1"],
            expected_revision=0,
        ),
        "confirm-llm-candidate",
    )
    assert review["state"] == "confirmed"


def test_llm_candidate_supports_exploratory_triage(store, evidence_fixture, tmp_path):
    run_id, attempt_id, packet, response, _, _ = documents(store, evidence_fixture, tmp_path)
    result = replay_discovery(store, attempt_id, packet, response, "candidate-triage")
    fingerprint = result["proposals"][0]["candidate_fingerprint"]
    bundle = build_bundle(store, attempt_id, fingerprint)
    quote = "return eval(x)"
    claims = [
        {
            "obligation": obligation,
            "evidence_id": "E1",
            "line": 2,
            "end_line": 2,
            "quote": quote,
            "assessment": "unknown" if obligation == "guard" else "present",
            "explanation": f"Exploratory {obligation} claim requires operator review.",
        }
        for obligation in ("source", "sink", "flow", "guard")
    ]
    adapter = FakeAdapter(
        Reply(
            status="completed",
            decision=Decision(
                verdict="needs_review",
                rationale="The cited code warrants explicit review.",
                evidence_ids=["E1"],
                counterevidence="",
                claims=claims,
            ),
            usage=Usage(input_tokens=100, output_tokens=20),
        )
    )
    set_budget(store, run_id, 100000)
    triaged = triage(store, bundle["bundle_id"], policy(), adapter, "llm-exploratory")
    assert triaged["state"] == "completed"
    assert triaged["disposition"] == "needs_review"
    assert triaged["verified"] is False
    assert triaged["evidence_gate"]["status"] == "exploratory_supported_for_review"
    assert triaged["evidence_gate"]["reachability_proven"] is False


def test_replay_rejects_changed_source_packet_and_bad_citation(store, evidence_fixture, tmp_path):
    _, attempt_id, packet_path, response_path, packet, response = documents(
        store, evidence_fixture, tmp_path
    )
    packet["excerpts"][0]["text"] = "def changed():\n    pass\n"
    packet_path.write_text(json.dumps(packet))
    with pytest.raises(VeriFlowError, match="does not match"):
        replay_discovery(store, attempt_id, packet_path, response_path, "changed")

    _, attempt_id, packet_path, response_path, _, response = documents(
        store, evidence_fixture, tmp_path
    )
    response["proposals"][0]["primary"]["line"] = 3
    response["proposals"][0]["primary"]["end_line"] = 3
    response_path.write_text(json.dumps(response))
    with pytest.raises(VeriFlowError, match="outside"):
        replay_discovery(store, attempt_id, packet_path, response_path, "outside")


def test_replay_key_conflict_and_cli(store, evidence_fixture, tmp_path):
    _, attempt_id, packet, response, packet_doc, _ = documents(store, evidence_fixture, tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "discovery-replay",
            attempt_id,
            str(packet),
            str(response),
            "--request-key",
            "cli-discovery",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["proposal_count"] == 1
    packet_doc["selection_reasons"] = ["different selection"]
    packet.write_text(json.dumps(packet_doc))
    with pytest.raises(VeriFlowError, match="already used"):
        replay_discovery(store, attempt_id, packet, response, "cli-discovery")


def test_packet_must_match_attempt_and_completed_scan(store, evidence_fixture, tmp_path):
    run_id, attempt_id, packet, response, packet_doc, _ = documents(
        store, evidence_fixture, tmp_path
    )
    packet_doc["run_id"] = "00000000-0000-0000-0000-000000000000"
    packet.write_text(json.dumps(packet_doc))
    with pytest.raises(VeriFlowError, match="does not belong"):
        replay_discovery(store, attempt_id, packet, response, "wrong-run")

    packet_doc["run_id"] = run_id
    packet.write_text(json.dumps(packet_doc))
    with store.transaction() as session:
        attempt = session.get(ScanAttempt, attempt_id)
        attempt.report = {**attempt.report, "status": "failed"}
    with pytest.raises(VeriFlowError, match="must complete"):
        replay_discovery(store, attempt_id, packet, response, "failed-scan")


def test_migration_preserves_existing_database(store):
    with store.transaction() as session:
        before = session.scalar(select(func.count()).select_from(Run))
    store.initialize()
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(Run)) == before


def test_deterministic_packet_selection_and_hybrid_wrapper(
    store, evidence_fixture, tmp_path, monkeypatch
):
    run_id, attempt_id, _, response, _, _ = documents(store, evidence_fixture, tmp_path)
    packet = build_packet(store, attempt_id, 8)
    assert packet.eligible_files == packet.examined_files == 1
    assert packet.deferred_files == 0
    assert packet.excerpts[0].path == "app.py"
    options = load_options(True, response, "hybrid-1", 8)
    monkeypatch.setattr(
        pipeline,
        "_deterministic_scan_run",
        lambda *a, **k: {
            "run_id": run_id,
            "repo_id": "example",
            "attempt_id": attempt_id,
            "status": "ready_for_review",
            "model_calls": 0,
        },
    )
    result = pipeline.scan_run(store, run_id, llm_discovery=options)
    assert result["hybrid_status"] == "completed"
    assert result["model_calls"] == 1 and result["live_model_calls"] == 0
    assert result["llm_discovery"]["selection"] == {
        "policy": "risk-markers-plus-deterministic-sample-v1",
        "eligible_files": 1,
        "examined_files": 1,
        "deferred_files": 0,
    }


def test_hybrid_failure_preserves_deterministic_result(
    store, evidence_fixture, tmp_path, monkeypatch
):
    run_id, attempt_id, _, response, _, _ = documents(store, evidence_fixture, tmp_path)
    response.write_text("not json")
    monkeypatch.setattr(
        pipeline,
        "_deterministic_scan_run",
        lambda *a, **k: {
            "run_id": run_id,
            "repo_id": "example",
            "attempt_id": attempt_id,
            "status": "ready_for_review",
            "report_id": "deterministic-report",
        },
    )
    result = pipeline.scan_run(
        store,
        run_id,
        llm_discovery=load_options(True, response, "hybrid-failure"),
    )
    assert result["report_id"] == "deterministic-report"
    assert result["status"] == "ready_for_review"
    assert result["hybrid_status"] == "partial"
    assert result["llm_discovery"]["state"] == "failed"


def test_discovery_cli_options_are_explicit(store, tmp_path, monkeypatch):
    replay = tmp_path / "reply.json"
    replay.write_text("{}")
    seen = {}

    def fake(*args, **kwargs):
        seen["options"] = kwargs["llm_discovery"]
        return {"status": "synthetic"}

    monkeypatch.setattr(pipeline, "scan_run", fake)
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "scan-run",
            "run",
            "--engine",
            "joern",
            "--joern-home",
            str(tmp_path),
            "--llm-discovery",
            "--llm-discovery-replay",
            str(replay),
            "--llm-discovery-key",
            "cli-hybrid",
            "--llm-discovery-max-excerpts",
            "4",
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen["options"].request_key == "cli-hybrid"
    assert seen["options"].max_excerpts == 4


def test_discovery_options_require_explicit_flag(tmp_path):
    with pytest.raises(VeriFlowError, match="require --llm-discovery"):
        load_options(False, tmp_path / "reply.json", None)


def test_live_discovery_uses_shared_budget(store, evidence_fixture, tmp_path, monkeypatch):
    run_id, attempt_id, _, response_path, _, response_doc = documents(
        store, evidence_fixture, tmp_path
    )
    config = ModelConfig(
        provider="openai",
        model="approved-security-model",
        endpoint="https://models.example.test/v1/responses",
        allowed_endpoint_hosts=["models.example.test"],
        allowed_classifications=["synthetic"],
        allow_source_transmission=True,
        input_micro_usd_per_1k=1000,
        output_micro_usd_per_1k=2000,
    )
    config_path = tmp_path / "live-config.json"
    config_path.write_text(config.model_dump_json())
    options = load_options(True, None, "live-discovery", 8, config_path)
    reply = DiscoveryReply(
        status="completed",
        response=DiscoveryResponse.model_validate(response_doc),
        usage=Usage(input_tokens=100, output_tokens=20),
    )
    monkeypatch.setenv("TRACEPROOF_OPENAI_API_KEY", "test-secret")
    monkeypatch.setattr(llm_discovery, "invoke_live", lambda config, body: reply)
    set_budget(store, run_id, 100000, max_requests=2)
    result = run_hybrid_discovery(store, attempt_id, options)
    assert result["state"] == "completed" and result["live_model_calls"] == 1
    assert result["candidate_rows_created"] == 1
    ledger = triage_report(store, run_id)
    assert ledger["discovery_call_count"] == ledger["request_count"] == 1
    assert ledger["accounted_micro_usd"] == 140
    assert ledger["remaining_requests"] == 1
    report = publish_report(store, "example", run_id, attempt_id)
    assert report["discovery_call_count"] == 1
    assert report["live_accounted_micro_usd"] == 140
    assert response_path.is_file()


def test_live_discovery_request_limit_prevents_provider(
    store, evidence_fixture, tmp_path, monkeypatch
):
    run_id, attempt_id, _, _, _, _ = documents(store, evidence_fixture, tmp_path)
    config = ModelConfig(
        provider="ollama",
        model="local-security-model",
        endpoint="http://127.0.0.1:11434/api/chat",
        allowed_endpoint_hosts=["127.0.0.1"],
        allowed_classifications=["synthetic"],
        allow_source_transmission=True,
    )
    config_path = tmp_path / "ollama-config.json"
    config_path.write_text(config.model_dump_json())
    options = load_options(True, None, "limited-discovery", 8, config_path)
    set_budget(store, run_id, 100000, max_requests=0)
    monkeypatch.setattr(
        llm_discovery,
        "invoke_live",
        lambda *a: pytest.fail("Provider invoked after request limit"),
    )
    result = run_hybrid_discovery(store, attempt_id, options)
    assert result["state"] == "request_limit_exhausted"
    assert result["provider_invocations"] == result["live_model_calls"] == 0


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama"])
def test_provider_response_parsing(provider):
    response = {
        "schema_version": "1",
        "proposals": [],
        "coverage_notes": ["bounded"],
    }
    encoded = json.dumps(response)
    if provider == "openai":
        wire = {
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": encoded}]}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    elif provider == "anthropic":
        wire = {
            "type": "message",
            "role": "assistant",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": encoded}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    else:
        wire = {
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": encoded},
            "prompt_eval_count": 10,
            "eval_count": 5,
        }
    parsed = parse_discovery_response(provider, json.dumps(wire))
    assert parsed.status == "completed"
    assert parsed.response.coverage_notes == ["bounded"]
    assert parsed.usage.input_tokens == 10
