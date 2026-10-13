import json
from copy import deepcopy

import pytest
from test_joern_claims import audited_bundle as audited_bundle
from test_joern_claims import review_decision
from test_slice03 import captured_source as captured_source
from test_triage import FakeAdapter, policy

from veriflow import batch_triage
from veriflow.domain import VeriFlowError
from veriflow.joern_claims import POLICY, spring_preflight
from veriflow.models import Reply, Usage, request_body
from veriflow.reports import publish_report
from veriflow.triage import set_budget, triage, triage_report


def adapter_for(bundle, verdict="needs_review"):
    decision = review_decision(bundle).model_copy(update={"verdict": verdict})
    return FakeAdapter(
        Reply(
            status="completed", decision=decision, usage=Usage(input_tokens=100, output_tokens=20)
        )
    )


def test_opt_in_advisory_idempotency_and_report(store, audited_bundle):
    b = audited_bundle
    set_budget(store, b["run_id"], 100000)
    adapter = adapter_for(b)
    default = triage(store, b["bundle_id"], policy(), adapter, "default")
    assert default["state"] == "unsupported_rule" and adapter.calls == 0
    result = triage(store, b["bundle_id"], policy(), adapter, "explicit", review_policy=POLICY)
    assert result["state"] == "completed" and result["disposition"] == "needs_review"
    assert result["simulated"] and not result["verified"] and adapter.calls == 1
    assert result["review_preflight"]["passed"] and result["evidence_gate"]["passed"]
    assert result["accounted_micro_usd"] == 140
    assert (
        triage(store, b["bundle_id"], policy(), adapter, "explicit", review_policy=POLICY) == result
    )
    assert adapter.calls == 1
    with pytest.raises(VeriFlowError, match="different request"):
        triage(store, b["bundle_id"], policy(), adapter, "default", review_policy=POLICY)
    report = publish_report(store, b["repo_id"], b["run_id"], b["attempt_id"])
    assert report["candidates"][0]["triage_history"][-1]["review_policy"] == POLICY
    assert report["static_review_readiness"]["state"] == "incomplete"


@pytest.mark.parametrize("failure", ["preflight", "budget", "timeout", "negative", "quote"])
def test_gates_cost_accounting_and_no_automatic_retry(store, audited_bundle, monkeypatch, failure):
    b = audited_bundle
    set_budget(store, b["run_id"], 0 if failure == "budget" else 100000)
    adapter = adapter_for(b, "likely_false_positive" if failure == "negative" else "needs_review")
    if failure == "preflight":
        altered = deepcopy(b)
        altered.pop("joern_native_audit")
        monkeypatch.setattr("veriflow.triage.get_bundle", lambda *args: altered)
    elif failure == "timeout":
        adapter.error = TimeoutError("transport uncertain")
    elif failure == "quote":
        decision = adapter.reply.decision
        adapter.reply = adapter.reply.model_copy(
            update={
                "decision": decision.model_copy(
                    update={
                        "claims": [
                            decision.claims[0].model_copy(update={"quote": "fabricated"}),
                            *decision.claims[1:],
                        ]
                    }
                )
            }
        )
    result = triage(store, b["bundle_id"], policy(), adapter, "test", review_policy=POLICY)
    assert (
        result["state"]
        == {
            "preflight": "incomplete_evidence",
            "budget": "budget_exhausted",
            "timeout": "unknown",
            "negative": "evidence_rejected",
            "quote": "evidence_rejected",
        }[failure]
    )
    assert result["disposition"] == "abstain" and not result["verified"]
    assert adapter.calls == (0 if failure in {"preflight", "budget"} else 1)
    if failure in {"preflight", "budget"}:
        assert result["accounted_micro_usd"] == 0
    if failure == "timeout":
        assert result["accounted_micro_usd"] == result["reserved_micro_usd"] > 0
    triage(store, b["bundle_id"], policy(), adapter, "test", review_policy=POLICY)
    assert adapter.calls <= 1
    assert triage_report(store, b["run_id"])["total"] == 1


def test_preflight_rejects_endpoint_syntax_before_provider(store, audited_bundle):
    import hashlib

    b = deepcopy(audited_bundle)
    path = b["joern_native_audit"]["nodes"][0]["path"]
    for s in b["snippets"]:
        if s["path"] == path:
            s["text"] = s["text"].replace("org.springframework", "other.springframework")
            s["sha256"] = hashlib.sha256(s["text"].encode()).hexdigest()
    digest = next(s["sha256"] for s in b["snippets"] if s["path"] == path)
    for node in b["joern_native_audit"]["nodes"]:
        if node["path"] == path:
            node["sha256"] = digest
    assert spring_preflight(b)["status"] == "unsupported_endpoint_syntax"


def test_request_identity_and_batch_policy_separation(store, audited_bundle):
    b = audited_bundle
    default = request_body(b, policy())
    explicit = request_body(b, policy(), review_policy=POLICY)
    assert default != explicit
    assert json.loads(explicit["input"])["requirements"]["policy_id"] == POLICY
    set_budget(store, b["run_id"], 100000)
    adapter = adapter_for(b)
    first = batch_triage.triage_attempt(
        store, b["repo_id"], b["attempt_id"], policy(), adapter, "batch"
    )
    second = batch_triage.triage_attempt(
        store, b["repo_id"], b["attempt_id"], policy(), adapter, "batch", review_policy=POLICY
    )
    assert first["items"][0]["state"] == "unsupported_rule"
    assert second["items"][0]["state"] == "completed" and adapter.calls == 1
    assert second["items"][0]["request_key"] != first["items"][0]["request_key"]


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama"])
def test_explicit_provider_prompt_contract_without_network(audited_bundle, provider):
    from veriflow.models import ModelConfig

    local = provider == "ollama"
    config = ModelConfig(
        provider=provider,
        model="test-local",
        endpoint="http://127.0.0.1:11434/api/chat" if local else "https://example.com/api",
        allowed_endpoint_hosts=["127.0.0.1" if local else "example.com"],
        input_micro_usd_per_1k=1000,
    )
    body = request_body(audited_bundle, config, review_policy=POLICY)
    content = body["input"] if provider == "openai" else body["messages"][-1]["content"]
    payload = json.loads(content)
    assert payload["requirements"]["policy_id"] == POLICY
    assert payload["requirements"]["query_sha256"]
    assert payload["bundle"]["engine_id"] == "joern"


def test_cli_explicit_replay_advisory(store, audited_bundle, tmp_path):
    from typer.testing import CliRunner

    from veriflow.cli import app

    b = audited_bundle
    set_budget(store, b["run_id"], 100000)
    config_path, replay_path = tmp_path / "model.json", tmp_path / "reply.json"
    config_path.write_text(policy().model_dump_json())
    replay_path.write_text(adapter_for(b).reply.model_dump_json())
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "triage",
            b["bundle_id"],
            str(config_path),
            "cli-advice",
            "--replay",
            str(replay_path),
            "--review-policy",
            POLICY,
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["disposition"] == "needs_review"


def test_changed_preflight_does_not_reuse_prior_advice(store, audited_bundle, monkeypatch):
    b = audited_bundle
    set_budget(store, b["run_id"], 100000)
    adapter = adapter_for(b)
    triage(store, b["bundle_id"], policy(), adapter, "same", review_policy=POLICY)
    monkeypatch.setattr(
        "veriflow.joern_claims.review_preflight",
        lambda bundle, policy, store=None: {
            "passed": False,
            "status": "insufficient_native_evidence",
            "policy_id": POLICY,
        },
    )
    with pytest.raises(VeriFlowError, match="different request"):
        triage(store, b["bundle_id"], policy(), adapter, "same", review_policy=POLICY)
    assert adapter.calls == 1
