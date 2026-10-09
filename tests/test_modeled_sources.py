"""Regression shape taken from the saved CodeQL 2.27.0 Flask injection trace."""

import copy

import pytest

from veriflow.claims import assess_evidence
from veriflow.models import Decision

SOURCE = (
    "from flask import Flask, request\napp = Flask(__name__)\n"
    '@app.route("/run")\ndef run():\n    return str(eval(request.args["expr"]))\n'
)


def fixture(source=SOURCE):
    lines = source.splitlines(keepends=True)
    snippets = []
    for step, line in enumerate([1, 1, 5, 5]):
        snippets.append(
            {
                "id": f"E{step + 1}",
                "path": "app.py",
                "sha256": "pinned",
                "text": source,
                "line": line,
                "end_line": line,
                "excerpt_line": 1,
                "excerpt_end_line": len(lines),
                "source_line_count": len(lines),
                "flow_id": "F0T0",
                "flow_step": step,
                "flow_steps": 4,
            }
        )
    bundle = {"rule_id": "py/code-injection", "status": "ready", "snippets": snippets}
    quote = lines[4].strip()
    claims = [
        {
            "obligation": obligation,
            "evidence_id": evidence,
            "line": 5,
            "end_line": 5,
            "quote": quote,
            "assessment": "unknown" if obligation == "guard" else "present",
            "explanation": "Review the retained evidence.",
        }
        for obligation, evidence in [
            ("source", "E3"),
            ("sink", "E4"),
            ("flow", "E3"),
            ("guard", "E3"),
        ]
    ]
    return bundle, Decision(
        verdict="needs_review",
        rationale="Review injection",
        evidence_ids=["E3", "E4"],
        counterevidence="Unknown",
        claims=claims,
    )


def merged_fixture():
    """The same trace after repeated regions collapse, as the bundler now emits it."""
    bundle, _ = fixture()
    first, second = bundle["snippets"][0], bundle["snippets"][2]
    bundle["snippets"] = [
        {**first, "id": "E1", "flow_steps_covered": [0, 1]},
        {**second, "id": "E2", "flow_steps_covered": [2, 3]},
    ]
    quote = SOURCE.splitlines(keepends=True)[4].strip()
    claims = [
        {
            "obligation": obligation,
            "evidence_id": "E2",
            "line": 5,
            "end_line": 5,
            "quote": quote,
            "assessment": "unknown" if obligation == "guard" else "present",
            "explanation": "Review the retained evidence.",
        }
        for obligation in ("source", "sink", "flow", "guard")
    ]
    return bundle, Decision(
        verdict="needs_review",
        rationale="Review injection",
        evidence_ids=["E1", "E2"],
        counterevidence="Unknown",
        claims=claims,
    )


def test_merged_flow_steps_keep_the_flask_import_prefix():
    bundle, decision = merged_fixture()
    gate = assess_evidence(bundle, decision)
    assert gate["passed"], gate
    # The import prefix is still proven even though two steps share one snippet.
    assert gate["source_mappings"][0]["kind"] == "flask_request_import"
    assert "source_to_sink_recorded_flow" not in gate["missing"]


def test_flask_import_prefix_supports_advisory_review():
    bundle, decision = fixture()
    gate = assess_evidence(bundle, decision)
    assert gate["passed"] and not gate["reachability_proven"]
    assert gate["source_mappings"] == [
        {
            "kind": "flask_request_import",
            "flow_id": "F0T0",
            "import_evidence_ids": ["E1", "E2"],
            "access_evidence_id": "E3",
            "binding_proven": False,
        }
    ]


@pytest.mark.parametrize(
    "suffix",
    [
        "request = other\n",
        "del request\n",
        "def other(request): pass\n",
        "from elsewhere import request\n",
        "import elsewhere as request\n",
        "from elsewhere import *\n",
        "def request(): pass\n",
        "try:\n    pass\nexcept Exception as request:\n    pass\n",
        "match value:\n    case {'x': request}: pass\n",
    ],
)
def test_rebinding_anywhere_in_retained_file_abstains(suffix):
    bundle, decision = fixture(SOURCE + suffix)
    assert not assess_evidence(bundle, decision)["passed"]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_prefix",
        "different_thread",
        "non_import",
        "truncated",
        "legacy",
        "wrong_import",
        "conflict",
    ],
)
def test_unsupported_mapping_abstains(mutation):
    bundle, decision = fixture()
    snippets = bundle["snippets"]
    if mutation == "missing_prefix":
        snippets.pop(0)
    elif mutation == "different_thread":
        snippets[0]["flow_id"] = "F1T0"
    elif mutation == "non_import":
        snippets[1]["line"] = snippets[1]["end_line"] = 2
    elif mutation == "truncated":
        for item in snippets:
            item["source_line_count"] += 1
    elif mutation == "legacy":
        for item in snippets:
            item.pop("source_line_count")
    elif mutation == "wrong_import":
        for item in snippets:
            item["text"] = item["text"].replace("from flask", "from other")
    elif mutation == "conflict":
        snippets[0]["text"] = snippets[0]["text"].replace("Flask(__name__)", "Flask('other')")
    assert not assess_evidence(bundle, decision)["passed"]


def test_split_overlapping_excerpts_can_supply_complete_file():
    bundle, decision = fixture()
    for item in bundle["snippets"]:
        lines = item["text"].splitlines(keepends=True)
        if item["flow_step"] < 2:
            item["text"] = "".join(lines[:4])
            item["excerpt_end_line"] = 4
        else:
            item["text"] = "".join(lines[1:])
            item["excerpt_line"] = 2
    original = copy.deepcopy(bundle)
    assert assess_evidence(bundle, decision)["passed"]
    assert bundle == original


ALIASED_SOURCE = SOURCE.replace("Flask, request", "Flask, request as req").replace(
    "request.args", "req.args"
)


def test_flask_alias_support_is_advisory_only():
    bundle, decision = fixture(ALIASED_SOURCE)
    original = copy.deepcopy(bundle)
    gate = assess_evidence(bundle, decision)
    assert gate["passed"] and gate["gate_version"] == "8"
    assert gate["source_mappings"][0]["binding_name"] == "req"
    assert not gate["reachability_proven"] and not gate["source_mappings"][0]["binding_proven"]
    assert bundle == original


@pytest.mark.parametrize(
    "suffix",
    [
        "req = other\n",
        "del req\n",
        "def other(req): pass\n",
        "from elsewhere import x as req\n",
        "import elsewhere as req\n",
        "from elsewhere import *\n",
        "def req(): pass\n",
        "try:\n    pass\nexcept Exception as req:\n    pass\n",
        "match value:\n    case {'x': req}: pass\n",
    ],
)
def test_rebound_alias_is_not_supported(suffix):
    bundle, decision = fixture(ALIASED_SOURCE + suffix)
    assert not assess_evidence(bundle, decision)["passed"]


@pytest.mark.parametrize(
    "mutation", ["wrong_module", "missing_context", "missing_prefix", "ambiguous"]
)
def test_alias_does_not_bypass_source_constraints(mutation):
    source = ALIASED_SOURCE
    if mutation == "wrong_module":
        source = source.replace("from flask", "from elsewhere")
    if mutation == "ambiguous":
        source = source.replace('req.args["expr"]', 'req.args["expr"] + other.args["expr"]')
    bundle, decision = fixture(source)
    if mutation == "missing_context":
        for item in bundle["snippets"]:
            item["source_line_count"] += 1
    if mutation == "missing_prefix":
        bundle["snippets"].pop(0)
    assert not assess_evidence(bundle, decision)["passed"]
