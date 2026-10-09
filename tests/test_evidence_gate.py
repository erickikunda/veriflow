import copy
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow.bundles import MAX_BUNDLE_BYTES, build_bundle, canonical, get_bundle
from veriflow.claims import EvidenceClaim, assess_evidence, requirements
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.expansion import ExpansionItem, expand_bundle, read_expansion
from veriflow.models import Decision, Reply, Usage, request_body
from veriflow.persistence import EvidenceBundle, TriageCall
from veriflow.triage import set_budget, triage

SOURCE = "def f():\n    x = request.args['expr']\n    return eval(x)\n"
QUOTE = "return eval(x)"
SOURCE_QUOTE = "x = request.args['expr']"
# E2 is the taint source step; E1/E3 sit on the sink line.
CITED = {"E2": (2, SOURCE_QUOTE)}


def claim(obligation, evidence_id, **changes):
    line, quote = CITED.get(evidence_id, (3, QUOTE))
    return EvidenceClaim(
        obligation=obligation,
        evidence_id=evidence_id,
        **{
            "line": line,
            "end_line": line,
            "quote": quote,
            "assessment": "unknown" if obligation == "guard" else "present",
            "explanation": "Inspect the cited source and retained flow.",
            **changes,
        },
    )


def decision(**changes):
    return Decision(
        **{
            "verdict": "needs_review",
            "rationale": "Review possible code injection",
            "evidence_ids": ["E1", "E2", "E3"],
            "counterevidence": "Not established",
            "claims": [
                claim("source", "E2"),
                claim("sink", "E3"),
                claim("flow", "E2"),
                claim("guard", "E1"),
            ],
            **changes,
        }
    )


@pytest.fixture
def bundle(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=2, source=SOURCE, distinct_flow=True)
    return build_bundle(store, attempt, fingerprint)


def test_source_backed_claims_support_review_not_confirmation(bundle):
    gate = assess_evidence(bundle, decision())
    assert gate["passed"] and gate["status"] == "supported_for_review"
    assert not gate["reachability_proven"] and gate["unknowns"]
    assert bundle["snippets"][1]["flow_step"] == 0
    assert bundle["snippets"][2]["flow_step"] == 1


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"quote": "return safe()"}, "quote_mismatch"),
        ({"evidence_id": "E999"}, "unknown_or_uncited_evidence"),
        ({"line": 200, "end_line": 200}, "invalid_range_or_empty_claim"),
        ({"quote": " "}, "invalid_range_or_empty_claim"),
        ({"assessment": "unknown"}, "positive_evidence_required"),
    ],
)
def test_invalid_claims_fail_closed(bundle, changes, reason):
    proposed = decision()
    claims = list(proposed.claims)
    data = {**claims[0].model_dump(), **changes}
    claims[0] = EvidenceClaim.model_validate(data)
    gate = assess_evidence(bundle, decision(claims=claims))
    assert not gate["passed"] and gate["checks"][0]["reason"] == reason


@pytest.mark.parametrize("wrap", ["# {}", '"{}"'])
def test_comments_and_strings_cannot_supply_source_or_sink(bundle, wrap):
    changed = copy.deepcopy(bundle)
    for snippet in changed["snippets"]:
        snippet["text"] = (
            "def f():\n    " + wrap.format(SOURCE_QUOTE) + "\n    " + wrap.format(QUOTE) + "\n"
        )
    result = assess_evidence(changed, decision())
    assert not result["passed"]
    assert any(item["reason"] == "supported_syntax_not_in_quote" for item in result["checks"])


def test_unrelated_or_reversed_flows_cannot_be_joined(bundle):
    changed = copy.deepcopy(bundle)
    changed["snippets"][2]["flow_id"] = "F1T0"
    assert "source_to_sink_recorded_flow" in assess_evidence(changed, decision())["missing"]
    changed = copy.deepcopy(bundle)
    changed["snippets"][1]["flow_step"] = 1
    changed["snippets"][2]["flow_step"] = 0
    assert not assess_evidence(changed, decision())["passed"]


def test_missing_claims_and_legacy_bundle_abstain(bundle):
    assert not assess_evidence(bundle, decision(claims=[]))["passed"]
    legacy = copy.deepcopy(bundle)
    for snippet in legacy["snippets"]:
        snippet.pop("flow_id", None)
    assert not assess_evidence(legacy, decision())["passed"]
    assert assess_evidence(bundle, decision(verdict="abstain", claims=[]))["status"] == "abstained"


def test_negative_suggestion_requires_present_guard_and_counterevidence(bundle):
    gate = assess_evidence(bundle, decision(verdict="likely_false_positive"))
    assert not gate["passed"]
    assert {"present_guard", "counterevidence"}.issubset(gate["missing"])


@pytest.mark.parametrize("shell,passed", [(True, True), (False, False)])
def test_command_sink_checks_shell_flag(store, evidence_fixture, shell, passed):
    sink = f"return subprocess.run(x, shell={shell})"
    _, attempt, fingerprint, _ = evidence_fixture(
        flow_count=2,
        rule_id="py/command-line-injection",
        source=f"def f():\n    {SOURCE_QUOTE}\n    {sink}\n",
        distinct_flow=True,
    )
    bundle = build_bundle(store, attempt, fingerprint)
    claims = [
        EvidenceClaim.model_validate(
            {**item.model_dump(), **({"quote": sink} if item.evidence_id != "E2" else {})}
        )
        for item in decision().claims
    ]
    assert assess_evidence(bundle, decision(claims=claims))["passed"] is passed


def test_gate_is_persisted_with_advisory_decision(store, bundle):
    set_budget(store, bundle["run_id"], 100000)
    reply = Reply(
        status="completed", decision=decision(), usage=Usage(input_tokens=100, output_tokens=20)
    )
    result = triage(store, bundle["bundle_id"], policy(), FakeAdapter(reply), "claims")
    assert result["state"] == "completed" and result["disposition"] == "needs_review"
    assert result["evidence_gate"]["passed"] and result["verified"] is False
    with store.transaction() as session:
        assert session.scalar(select(TriageCall)).result["gate_version"] == "8"


def test_unsupported_rule_skips_paid_work(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(rule_id="py/not-supported")
    bundle = build_bundle(store, attempt, fingerprint)
    set_budget(store, bundle["run_id"], 100000)
    adapter = FakeAdapter()
    result = triage(store, bundle["bundle_id"], policy(), adapter, "unsupported")
    assert result["state"] == "unsupported_rule" and result["accounted_micro_usd"] == 0
    assert adapter.calls == 0 and not requirements("py/not-supported")["supported"]


def test_expansion_is_bounded_immutable_and_idempotent(store, evidence_fixture):
    source = SOURCE + "\n" * 8 + "if allowed:\n    print('guard')\n" + "\n" * 8 + "assert allowed\n"
    _, attempt, fingerprint, _ = evidence_fixture(flow_count=2, source=source)
    parent = build_bundle(store, attempt, fingerprint)
    request = ExpansionItem(path="app.py", line=11, end_line=12, reason="Inspect guard")
    child = expand_bundle(store, parent["bundle_id"], [request])
    assert child["parent_bundle_id"] == parent["bundle_id"] and child["expansion_depth"] == 1
    assert (
        child["snippets"][-1]["role"] == "expansion"
        and "if allowed" in child["snippets"][-1]["text"]
    )
    assert expand_bundle(store, parent["bundle_id"], [request]) == child
    assert expand_bundle(store, child["bundle_id"], [request]) == child
    assert get_bundle(store, parent["bundle_id"]) == parent
    assert len(canonical(child)) <= MAX_BUNDLE_BYTES
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceBundle)) == 2
        assert session.scalar(select(func.count()).select_from(TriageCall)) == 0


def test_expansion_depth_and_source_budget(store, evidence_fixture):
    source = (
        SOURCE + "\n" * 8 + "x = 1\n" + "\n" * 8 + "x = 2\n" + "\n" * 8 + "#" + "x" * 17000 + "\n"
    )
    _, attempt, fingerprint, _ = evidence_fixture(source=source)
    parent = build_bundle(store, attempt, fingerprint)
    with pytest.raises(VeriFlowError, match="source budget"):
        expand_bundle(
            store,
            parent["bundle_id"],
            [ExpansionItem(path="app.py", line=30, end_line=30, reason="large")],
        )
    child = expand_bundle(
        store,
        parent["bundle_id"],
        [ExpansionItem(path="app.py", line=12, end_line=12, reason="one")],
    )
    grandchild = expand_bundle(
        store,
        child["bundle_id"],
        [ExpansionItem(path="app.py", line=21, end_line=21, reason="two")],
    )
    with pytest.raises(VeriFlowError, match="depth"):
        expand_bundle(
            store,
            grandchild["bundle_id"],
            [ExpansionItem(path="app.py", line=21, end_line=21, reason="three")],
        )


def test_expansion_preserves_gaps(store, evidence_fixture):
    _, attempt, fingerprint, _ = evidence_fixture(
        flow_count=20, source=SOURCE + "\n" * 8 + "assert allowed\n", distinct_flow=True
    )
    parent = build_bundle(store, attempt, fingerprint)
    child = expand_bundle(
        store,
        parent["bundle_id"],
        [ExpansionItem(path="app.py", line=12, end_line=12, reason="guard")],
    )
    assert child["status"] == "partial" and child["gaps"] == parent["gaps"]


@pytest.mark.parametrize(
    "value",
    [
        {"path": "../outside", "line": 1, "end_line": 1, "reason": "x"},
        {"path": "app.py", "line": 1, "end_line": 100, "reason": "x"},
    ],
)
def test_expansion_validation(value):
    with pytest.raises(ValidationError):
        ExpansionItem.model_validate(value)


def test_cli_and_required_schema(store, bundle, tmp_path):
    path = tmp_path / "decision.json"
    path.write_text(decision().model_dump_json())
    runner = CliRunner()
    base = ["--state-dir", str(store.root)]
    result = runner.invoke(app, [*base, "check-evidence", bundle["bundle_id"], str(path)])
    assert result.exit_code == 0 and json.loads(result.output)["passed"]
    result = runner.invoke(app, [*base, "evidence-policy", "py/code-injection"])
    assert result.exit_code == 0 and json.loads(result.output)["supported"]
    schema = request_body(bundle, policy())["text"]["format"]["schema"]
    assert set(schema["required"]) == set(schema["properties"])
    claim_schema = schema["$defs"]["EvidenceClaim"]
    assert set(claim_schema["required"]) == set(claim_schema["properties"])
    path.write_text("[]")
    with pytest.raises(VeriFlowError):
        read_expansion(path)
