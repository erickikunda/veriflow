import hashlib
import io
import json
import subprocess
import sys
import zipfile
from uuid import uuid4

import pytest
from conftest import row
from pydantic import ValidationError
from sqlalchemy import func, select
from typer.testing import CliRunner

from veriflow.artifacts import ArtifactStore
from veriflow.bundles import build_bundle, get_bundle
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.intake import now, process, submit
from veriflow.models import (
    Decision,
    ModelConfig,
    NoRedirect,
    OpenAIAdapter,
    Reply,
    Usage,
    parse_openai_response,
    request_body,
)
from veriflow.persistence import Candidate, EvidenceBundle, ScanAttempt, TriageCall
from veriflow.sarif import normalize
from veriflow.triage import cost_micro_usd, set_budget, triage, triage_report


@pytest.fixture
def evidence_fixture(store, archive, manifest):
    def make(
        flow_count=1,
        uri="app.py",
        source="def f(x):\n    return eval(x)\n",
        rule_id="py/code-injection",
        distinct_flow=False,
    ):
        with zipfile.ZipFile(archive, "w") as out:
            out.writestr("app.py", source)
        batch = submit(store, manifest([row(archive)]), archive.parent, str(uuid4()))
        run_id = process(store, ArtifactStore(store.root), batch)["items"][0]["run_id"]
        _, snapshot, tree = verified_source(store, run_id)
        physical = {"artifactLocation": {"uri": uri}, "region": {"startLine": 2}}

        def step(index):
            # Distinct steps exercise truncation; repeated ones exercise duplicate merging.
            line = index + 2 if distinct_flow else 2
            return {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}

        result = {
            "ruleId": rule_id,
            "message": {"text": "Untrusted input"},
            "locations": [{"physicalLocation": physical}],
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {"location": {"physicalLocation": step(index)}}
                                for index in range(flow_count)
                            ]
                        }
                    ]
                }
            ],
        }
        raw = json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "CodeQL"}},
                        "invocations": [{"executionSuccessful": True}],
                        "results": [result],
                    }
                ],
            }
        ).encode()
        attempt_id = str(uuid4())
        path = store.root / "scans" / attempt_id / "results.sarif"
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
        normalized, summary = normalize(raw, snapshot, tree)
        with store.transaction() as session:
            session.add(
                ScanAttempt(
                    id=attempt_id,
                    run_id=run_id,
                    created_at=now(),
                    report={
                        "raw_sarif_path": str(path),
                        "sarif_sha256": hashlib.sha256(raw).hexdigest(),
                        "status": "completed",
                        **summary,
                    },
                )
            )
            session.flush()
            candidate = Candidate(
                id=str(uuid4()),
                attempt_id=attempt_id,
                fingerprint=normalized[0]["fingerprint"],
                evidence=normalized[0],
            )
            session.add(candidate)
        return run_id, attempt_id, normalized[0]["fingerprint"], path

    return make


@pytest.fixture
def ready(store, evidence_fixture):
    run, attempt, fingerprint, _ = evidence_fixture()
    return run, build_bundle(store, attempt, fingerprint)


def policy(**changes):
    return ModelConfig(
        provider="replay",
        model="fixture",
        input_micro_usd_per_1k=1000,
        output_micro_usd_per_1k=2000,
        **changes,
    )


class FakeAdapter:
    identity = "test-fixture"
    calls = 0

    def __init__(self, reply=None, error=None):
        self.reply = reply or Reply(
            status="completed",
            decision=Decision(
                verdict="needs_review",
                rationale="Review E1",
                evidence_ids=["E1"],
                counterevidence="",
            ),
            usage=Usage(input_tokens=100, output_tokens=20),
        )
        self.error = error

    def invoke(self, body):
        self.calls += 1
        if self.error:
            raise self.error
        return self.reply


def test_bundle_pinned_idempotent_and_read_only(store, evidence_fixture):
    run, attempt, fingerprint, path = evidence_fixture()
    bundle = build_bundle(store, attempt, fingerprint)
    assert bundle["status"] == "ready"
    assert {snippet["role"] for snippet in bundle["snippets"]} == {"primary", "flow"}
    assert bundle["snippets"][0]["text"] == "def f(x):\n    return eval(x)\n"
    assert build_bundle(store, attempt, fingerprint) == bundle
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceBundle)) == 1
    path.write_bytes(b"changed")
    assert get_bundle(store, bundle["bundle_id"]) == bundle
    with pytest.raises(VeriFlowError, match="SARIF integrity"):
        build_bundle(store, attempt, fingerprint)


@pytest.mark.parametrize(
    "kwargs,gap",
    [
        (
            {
                "flow_count": 20,
                "distinct_flow": True,
                "source": "".join(f"x = {n}\n" for n in range(24)),
            },
            "location_limit",
        ),
        ({"uri": "../app.py"}, "unmapped"),
        ({"source": "x=1\n"}, "range_limit"),
        ({"source": "def f():\n #" + "x" * 20000 + "\n pass"}, "source_budget"),
    ],
)
def test_bundle_gaps_skip_model(store, evidence_fixture, kwargs, gap):
    run, attempt, fingerprint, _ = evidence_fixture(**kwargs)
    bundle = build_bundle(store, attempt, fingerprint)
    assert bundle["status"] == "partial" and any(gap in item for item in bundle["gaps"])
    set_budget(store, run, 100000)
    adapter = FakeAdapter()
    result = triage(store, bundle["bundle_id"], policy(), adapter, "gap")
    assert result["state"] == "incomplete_evidence" and adapter.calls == 0
    assert result["accounted_micro_usd"] == 0


def test_reservation_usage_idempotency_and_candidate_immutability(store, ready):
    run, bundle = ready
    set_budget(store, run, 100000)
    adapter = FakeAdapter()
    first = triage(store, bundle["bundle_id"], policy(), adapter, "key")
    assert first["state"] == "evidence_rejected" and first["accounted_micro_usd"] == 140
    assert first["disposition"] == "abstain"
    assert first["reserved_micro_usd"] > 140
    assert triage(store, bundle["bundle_id"], policy(), adapter, "key") == first
    assert adapter.calls == 1
    assert triage_report(store, run)["remaining_micro_usd"] == 99860
    with store.transaction() as session:
        assert session.scalar(select(Candidate)).evidence["adjudication"] == "unreviewed"
    with pytest.raises(VeriFlowError, match="different request"):
        triage(store, bundle["bundle_id"], policy(max_output_tokens=2048), adapter, "key")


def test_budget_exhausted_and_no_reset(store, ready):
    run, bundle = ready
    set_budget(store, run, 1)
    adapter = FakeAdapter()
    result = triage(store, bundle["bundle_id"], policy(), adapter, "low")
    assert result["state"] == "budget_exhausted" and adapter.calls == 0
    with pytest.raises(VeriFlowError, match="already fixed"):
        set_budget(store, run, 100000)


@pytest.mark.parametrize(
    "reply,state",
    [
        (Reply(status="refused", usage=Usage(input_tokens=10, output_tokens=1)), "refused"),
        (Reply(status="incomplete"), "incomplete"),
        (Reply(status="completed"), "invalid_output"),
        (
            Reply(
                status="completed",
                decision=Decision(
                    verdict="needs_review",
                    rationale="x",
                    evidence_ids=["missing"],
                    counterevidence="",
                ),
            ),
            "invalid_citations",
        ),
        (
            Reply(
                status="completed",
                decision=Decision(
                    verdict="likely_false_positive",
                    rationale="x",
                    evidence_ids=[],
                    counterevidence="",
                ),
            ),
            "invalid_citations",
        ),
    ],
)
def test_invalid_refused_or_incomplete_abstains(store, ready, reply, state):
    run, bundle = ready
    set_budget(store, run, 100000)
    result = triage(store, bundle["bundle_id"], policy(), FakeAdapter(reply), "response")
    assert result["state"] == state and result["disposition"] == "abstain"
    if reply.usage is None:
        assert result["accounted_micro_usd"] == result["reserved_micro_usd"]


def test_timeout_and_actual_overrun(store, ready):
    run, bundle = ready
    set_budget(store, run, 100000)
    result = triage(
        store, bundle["bundle_id"], policy(), FakeAdapter(error=TimeoutError()), "timeout"
    )
    assert result["state"] == "unknown"
    assert result["accounted_micro_usd"] == result["reserved_micro_usd"]
    huge = Reply(status="incomplete", usage=Usage(input_tokens=200000, output_tokens=1))
    result = triage(store, bundle["bundle_id"], policy(), FakeAdapter(huge), "overrun")
    assert result["state"] == "reservation_exceeded"
    assert triage_report(store, run)["overrun_micro_usd"] > 0


def test_process_death_preserves_reservation_and_never_retries(store, ready):
    run, bundle = ready
    set_budget(store, run, 100000)
    program = """
import os, sys
from pathlib import Path
from veriflow.persistence import Store
from veriflow.models import ModelConfig
from veriflow.triage import triage
class Die:
    identity = 'test-fixture'
    def invoke(self, body): os._exit(42)
triage(Store(Path(sys.argv[1])),sys.argv[2],ModelConfig(provider='replay',model='fixture',
       input_micro_usd_per_1k=1000,output_micro_usd_per_1k=2000),Die(),'death')
"""
    child = subprocess.run(
        [sys.executable, "-c", program, str(store.root), bundle["bundle_id"]], timeout=20
    )
    assert child.returncode == 42
    adapter = FakeAdapter()
    result = triage(store, bundle["bundle_id"], policy(), adapter, "death")
    assert result["state"] == "unknown" and adapter.calls == 0
    assert result["accounted_micro_usd"] == result["reserved_micro_usd"] > 0


def test_classification_and_transmission_policy(store, ready):
    run, bundle = ready
    set_budget(store, run, 100000)
    with pytest.raises(VeriFlowError, match="classification"):
        triage(
            store, bundle["bundle_id"], policy(allowed_classifications=[]), FakeAdapter(), "deny"
        )
    config = ModelConfig(
        provider="openai",
        model="operator-selected",
        endpoint="https://example.com/v1/responses",
        allowed_endpoint_hosts=["example.com"],
        input_micro_usd_per_1k=1000,
    )
    with pytest.raises(VeriFlowError, match="disabled"):
        triage(store, bundle["bundle_id"], config, OpenAIAdapter(config), "deny")
    assert triage_report(store, run)["total"] == 0


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.com/v1/responses",
        "https://evil.test/x",
        "https://user:secret@example.com/x",
        "https://example.com/x?q=secret",
    ],
)
def test_live_endpoint_policy(endpoint):
    with pytest.raises(ValidationError):
        ModelConfig(
            provider="openai",
            model="operator-selected",
            endpoint=endpoint,
            allowed_endpoint_hosts=["example.com"],
            input_micro_usd_per_1k=1,
        )


def test_openai_payload_and_reply_contract(ready):
    _, bundle = ready
    body = request_body(bundle, policy())
    assert body["store"] is False and body["tools"] == [] and body["truncation"] == "disabled"
    assert body["text"]["format"]["strict"]
    decision = {
        "verdict": "abstain",
        "rationale": "Missing proof",
        "evidence_ids": [],
        "counterevidence": "",
    }
    doc = {
        "status": "completed",
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": json.dumps(decision)}]}
        ],
    }
    assert parse_openai_response(json.dumps(doc)).decision.verdict == "abstain"
    doc["output"][0]["content"] = [{"type": "refusal", "refusal": "No"}]
    assert parse_openai_response(json.dumps(doc)).status == "refused"
    doc["output"][0]["content"] = [{"type": "output_text", "text": "not json"}]
    assert parse_openai_response(json.dumps(doc)).status == "invalid_output"
    with pytest.raises(VeriFlowError, match="redirect"):
        NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.test")


def test_cli_replay_and_read_only_ledger(store, ready, tmp_path):
    run, bundle = ready
    config_path = tmp_path / "config.json"
    config_path.write_text(policy().model_dump_json())
    response_path = tmp_path / "reply.json"
    response_path.write_text(FakeAdapter().reply.model_dump_json())
    runner = CliRunner()
    base = ["--state-dir", str(store.root)]
    for command in [
        ["triage-budget", run, "100000"],
        ["triage", bundle["bundle_id"], str(config_path), "cli", "--replay", str(response_path)],
        ["triage-report", run],
        ["bundle-status", bundle["bundle_id"]],
    ]:
        response = runner.invoke(app, [*base, *command])
        assert response.exit_code == 0, response.output
        assert json.loads(response.output)["schema_version"] == "1"
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(TriageCall)) == 1
    assert (
        cost_micro_usd(1, 0, ModelConfig(provider="replay", model="x", input_micro_usd_per_1k=1))
        == 1
    )


def test_bundle_tampering_detected(store, ready):
    _, bundle = ready
    with store.transaction() as session:
        record = session.get(EvidenceBundle, bundle["bundle_id"])
        record.content = {**record.content, "classification": "public"}
    with pytest.raises(VeriFlowError, match="digest"):
        get_bundle(store, bundle["bundle_id"])


def live_policy():
    return ModelConfig(
        provider="openai",
        model="operator-selected",
        endpoint="https://approved.example/v1/responses",
        allowed_endpoint_hosts=["approved.example"],
        allow_source_transmission=True,
        input_micro_usd_per_1k=1000,
    )


def test_https_request_is_bounded_and_secret_not_in_body(monkeypatch, ready):
    from veriflow import models

    _, bundle = ready
    config = live_policy()
    monkeypatch.setenv(config.api_key_env, "synthetic-test-key")
    captured = {}

    class Opener:
        def open(self, request, timeout):
            captured.update(request=request, timeout=timeout)
            return io.BytesIO(
                b'{"status":"incomplete","usage":{"input_tokens":4,"output_tokens":2}}'
            )

    monkeypatch.setattr(models.urllib.request, "build_opener", lambda *args: Opener())
    reply = OpenAIAdapter(config)._invoke_https(request_body(bundle, config))
    assert reply.status == "incomplete"
    assert captured["request"].get_header("Authorization") == "Bearer synthetic-test-key"
    assert b"synthetic-test-key" not in captured["request"].data
    assert captured["timeout"] == config.timeout_seconds
    assert captured["request"].full_url == config.endpoint


def test_live_child_has_total_timeout_and_minimal_environment(monkeypatch, ready):
    from veriflow import models

    _, bundle = ready
    config = live_policy()
    monkeypatch.setenv(config.api_key_env, "synthetic-test-key")
    monkeypatch.setenv("UNRELATED_SECRET", "not-forwarded")
    captured = {}

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        return subprocess.CompletedProcess(
            command, 0, Reply(status="refused").model_dump_json().encode()
        )

    monkeypatch.setattr(models.subprocess, "run", run)
    assert OpenAIAdapter(config).invoke(request_body(bundle, config)).status == "refused"
    assert captured["env"] == {config.api_key_env: "synthetic-test-key"}
    assert captured["timeout"] == config.timeout_seconds + 3
    assert "-I" in captured["command"]


def test_false_positive_suggestion_requires_counterevidence(store, ready):
    run, bundle = ready
    set_budget(store, run, 100000)
    reply = Reply(
        status="completed",
        decision=Decision(
            verdict="likely_false_positive",
            evidence_ids=["E1"],
            rationale="Probably safe",
            counterevidence="",
        ),
    )
    result = triage(store, bundle["bundle_id"], policy(), FakeAdapter(reply), "counterevidence")
    assert result["state"] == "invalid_rationale" and result["disposition"] == "abstain"


def test_unicode_separators_do_not_shift_source_lines(store, evidence_fixture):
    from veriflow.evidence import source_evidence

    source = "# comment\u2028still line one\ndef f(): pass\n"
    run, attempt, fingerprint, _ = evidence_fixture(source=source)
    bundle = build_bundle(store, attempt, fingerprint)
    assert bundle["snippets"][0]["excerpt_end_line"] == 2
    assert source_evidence(store, run, "app.py", 2, 2)["text"] == "def f(): pass\n"
