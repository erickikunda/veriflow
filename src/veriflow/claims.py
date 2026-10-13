"""Source-anchored claim checks; passing is not a proof of exploitability or safety."""

import ast
import io
import textwrap
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from veriflow.source_context import covered_steps

GATE_VERSION = "8"
POLICIES = {
    "cs/sql-injection": {
        "class": "sql_injection",
        "sinks": ["CommandText"],
        "language": "csharp",
    },
    "java/sql-injection": {"class": "sql_injection", "sinks": ["executeQuery"], "language": "java"},
    "py/code-injection": {"class": "code_injection", "sinks": ["eval", "exec"]},
    "py/command-line-injection": {
        "class": "command_injection",
        "sinks": [
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        ],
    },
}


class EvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    obligation: Literal["source", "sink", "flow", "guard", "counterevidence"]
    evidence_id: str = Field(min_length=1, max_length=20)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    quote: str = Field(min_length=1, max_length=2000)
    assessment: Literal["present", "unknown"]
    explanation: str = Field(min_length=1, max_length=1000)


def bundle_engine(bundle):
    # Missing identity is legacy only for the pre-engine bundle schema.
    if "engine_id" in bundle:
        return bundle["engine_id"]
    if bundle.get("builder_version", "1") in {"1", "2", "3", "4", "5"}:
        return "codeql"
    return "unknown"


def requirements(rule_id, engine="codeql"):
    if engine == "llm_discovery":
        return {
            "gate_version": GATE_VERSION,
            "engine_id": engine,
            "supported": True,
            "policy": "exploratory-source-anchoring-v1",
            "required": ["source", "sink", "flow", "guard"],
            "negative_requires": "present guard and quoted counterevidence",
            "modeled_source": "No source model; cite only retained packet evidence",
            "scope": "quote and range consistency only; no semantic or reachability proof",
        }
    return {
        "gate_version": GATE_VERSION,
        "engine_id": engine,
        "supported": engine == "codeql" and rule_id in POLICIES,
        "policy": POLICIES.get(rule_id) if engine == "codeql" else None,
        "required": ["source", "sink", "flow", "guard"],
        "negative_requires": "Java/C# negative suggestions unsupported"
        if rule_id in ("java/sql-injection", "cs/sql-injection")
        else "present guard and quoted counterevidence",
        "modeled_source": "Core FromQuery or classic public HttpGet string action; complete file"
        if rule_id == "cs/sql-injection"
        else "Explicit Spring RequestParam syntax; complete file required"
        if rule_id == "java/sql-injection"
        else "Flask request or alias import prefix; full-file evidence, no rebinding",
        "scope": "quote, syntax and recorded flow consistency only; not runtime proof",
    }


def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{name(node.value)}.{node.attr}"
    return "<dynamic>"


def anchors(window, claim, policy, source_binding=None):
    """Recognize only a narrow syntax vocabulary, excluding comments/string literals."""
    text = textwrap.dedent(window)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    result = []
    for node in ast.walk(tree):
        match = False
        if claim.obligation == "source":
            match = (
                isinstance(node, ast.Attribute)
                and name(node)
                in {
                    "request.args",
                    "request.form",
                    "request.data",
                    "request.json",
                    "request.GET",
                    "request.POST",
                }
            ) or (isinstance(node, ast.Call) and name(node.func) in {"input", "request.get_json"})
            if source_binding:
                match |= isinstance(node, ast.Attribute) and name(node) in {
                    f"{source_binding}.{attribute}"
                    for attribute in ("args", "form", "data", "json")
                }
                match |= (
                    isinstance(node, ast.Call) and name(node.func) == f"{source_binding}.get_json"
                )
        elif claim.obligation == "sink" and isinstance(node, ast.Call):
            target = name(node.func)
            match = target in policy["sinks"]
            if target.startswith("subprocess."):
                match &= any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
        elif claim.obligation in {"guard", "counterevidence"}:
            match = isinstance(node, (ast.If, ast.Assert, ast.Compare))
        if match:
            segment = ast.get_source_segment(text, node)
            if segment and segment in claim.quote:
                result.append((claim.line + node.lineno - 1, claim.line + node.end_lineno - 1))
    return result


def flow_nodes(bundle, snippet, ranges):
    return [
        node
        for node in bundle["snippets"]
        if node.get("flow_id") is not None
        and (
            snippet.get("flow_id") is None
            or (node["flow_id"] == snippet["flow_id"] and node["flow_step"] == snippet["flow_step"])
        )
        and node["path"] == snippet["path"]
        and node["sha256"] == snippet["sha256"]
        and any(start <= node["end_line"] and end >= node["line"] for start, end in ranges)
    ]


def flask_mapping(bundle, source):
    """Map only a complete retained import prefix, using complete bounded file context."""
    steps = covered_steps(source)
    if not steps or min(steps) == 0:
        return None
    snippets = [
        item
        for item in bundle["snippets"]
        if item["path"] == source["path"] and item["sha256"] == source["sha256"]
    ]
    counts = {item["source_line_count"] for item in snippets if "source_line_count" in item}
    if len(counts) != 1:
        return None
    total = counts.pop()
    lines = {}
    for item in snippets:
        for number, text in enumerate(
            io.StringIO(item["text"], newline="").readlines(), item["excerpt_line"]
        ):
            if number in lines and lines[number] != text:
                return None
            lines[number] = text
    if set(lines) != set(range(1, total + 1)):
        return None
    try:
        tree = ast.parse("".join(lines[number] for number in range(1, total + 1)))
    except (SyntaxError, ValueError, RecursionError):
        return None
    # Require a single simple receiver at the retained source location. Ambiguous or
    # dynamic access stays unsupported rather than selecting an arbitrary binding.
    bindings = {
        node.value.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.attr in {"args", "form", "data", "json", "get_json"}
        and source["line"] <= node.lineno <= source["end_line"]
    }
    if len(bindings) != 1:
        return None
    binding = bindings.pop()
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return None
                if (alias.asname or alias.name) == binding:
                    if node.module != "flask" or node.level or alias.name != "request":
                        return None
                    imports.append(node)
        if (
            isinstance(node, ast.Name)
            and node.id == binding
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ) or (isinstance(node, ast.arg) and node.arg == binding):
            return None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == binding:
                return None
        if isinstance(node, ast.Import) and any(
            (alias.asname or alias.name.split(".")[0]) == binding for alias in node.names
        ):
            return None
        if isinstance(node, ast.ExceptHandler) and node.name == binding:
            return None
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == binding:
            return None
        if isinstance(node, ast.MatchMapping) and node.rest == binding:
            return None
    if len(imports) != 1 or imports[0] not in tree.body:
        return None
    imported = imports[0]
    # Merged regions stand for several steps, so the prefix is compared by coverage.
    first = min(covered_steps(source))
    prefix = [
        item
        for item in snippets
        if item.get("flow_id") == source["flow_id"]
        and covered_steps(item)
        and min(covered_steps(item)) < first
    ]
    if {step for item in prefix for step in covered_steps(item)} != set(range(first)):
        return None
    if any(
        item["line"] != imported.lineno or item["end_line"] != imported.end_lineno
        for item in prefix
    ):
        return None
    accesses = [
        node
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Attribute)
            and name(node)
            in {
                f"{binding}.{attribute}"
                for attribute in ("args", "form", "data", "json", "get_json")
            }
        )
        and source["line"] <= node.lineno <= source["end_line"]
    ]
    if not accesses:
        return None
    return {
        "kind": "flask_request_import",
        "flow_id": source["flow_id"],
        "import_evidence_ids": [item["id"] for item in prefix],
        "access_evidence_id": source["id"],
        "binding_proven": False,
        **({"binding_name": binding} if binding != "request" else {}),
    }


def assess_evidence(bundle, decision):
    if decision.verdict == "abstain":
        return _assess_supported(bundle, decision, None)
    if bundle["status"] != "ready":
        return _assess_supported(bundle, decision, None)
    if bundle_engine(bundle) == "llm_discovery":
        return _assess_exploratory(bundle, decision)
    if bundle_engine(bundle) != "codeql":
        return {**_assess_supported(bundle, decision, None), "status": "unsupported_engine"}
    return _assess_supported(bundle, decision, POLICIES.get(bundle["rule_id"]))


def _assess_exploratory(bundle, decision):
    """Check citations and quotes only; this gate never proves a modeled flow."""
    report = {
        "gate_version": GATE_VERSION,
        "rule_id": bundle["rule_id"],
        "status": "insufficient_evidence",
        "passed": False,
        "checks": [],
        "missing": [],
        "unknowns": [],
        "source_mappings": [],
        "reachability_proven": False,
        "scope": "exploratory quote/range consistency, not semantic or exploitability proof",
    }
    if decision.verdict == "abstain":
        return {**report, "status": "abstained"}
    if bundle["status"] != "ready":
        return {**report, "status": "incomplete_bundle"}
    snippets = {item["id"]: item for item in bundle["snippets"]}
    satisfied = set()
    for claim in decision.claims:
        snippet = snippets.get(claim.evidence_id)
        reason = None
        if snippet is None or claim.evidence_id not in decision.evidence_ids:
            reason = "unknown_or_uncited_evidence"
        elif (
            not claim.quote.strip()
            or not claim.explanation.strip()
            or not snippet["excerpt_line"]
            <= claim.line
            <= claim.end_line
            <= snippet["excerpt_end_line"]
            or claim.end_line - claim.line >= 40
        ):
            reason = "invalid_range_or_empty_claim"
        else:
            lines = io.StringIO(snippet["text"], newline="").readlines()
            window = "".join(
                lines[
                    claim.line - snippet["excerpt_line"] : claim.end_line
                    - snippet["excerpt_line"]
                    + 1
                ]
            )
            if claim.quote not in window:
                reason = "quote_mismatch"
            elif claim.assessment == "unknown" and claim.obligation != "guard":
                reason = "positive_evidence_required"
            else:
                satisfied.add(claim.obligation)
                if claim.assessment == "unknown":
                    report["unknowns"].append("Guard effectiveness is unknown")
        report["checks"].append(
            {
                "obligation": claim.obligation,
                "evidence_id": claim.evidence_id,
                "passed": reason is None,
                "reason": reason,
            }
        )
    needed = {"source", "sink", "flow", "guard"}
    report["missing"] = sorted(needed - satisfied)
    invalid = any(not check["passed"] for check in report["checks"])
    report["status"] = (
        "invalid_claims"
        if invalid
        else "insufficient_evidence"
        if report["missing"]
        else "exploratory_supported_for_review"
    )
    report["passed"] = report["status"] == "exploratory_supported_for_review"
    return report


def _assess_supported(bundle, decision, policy):
    """Shared quote/syntax/path checks; callers must gate engine and provenance first."""
    report = {
        "gate_version": GATE_VERSION,
        "rule_id": bundle["rule_id"],
        "status": "insufficient_evidence",
        "passed": False,
        "checks": [],
        "missing": [],
        "unknowns": [],
        "source_mappings": [],
        "reachability_proven": False,
        "scope": "quoted syntax and retained SARIF flow, not semantic entailment",
    }
    if decision.verdict == "abstain":
        return {**report, "status": "abstained"}
    if bundle["status"] != "ready":
        return {**report, "status": "incomplete_bundle"}
    if policy is None:
        return {**report, "status": "unsupported_rule"}
    snippets = {item["id"]: item for item in bundle["snippets"]}
    satisfied, source_nodes, sink_nodes, flow_ids = set(), [], [], set()
    guard_present = False
    for claim in decision.claims:
        snippet = snippets.get(claim.evidence_id)
        reason = None
        located = []
        if snippet is None or claim.evidence_id not in decision.evidence_ids:
            reason = "unknown_or_uncited_evidence"
        elif (
            not claim.quote.strip()
            or not claim.explanation.strip()
            or not snippet["excerpt_line"]
            <= claim.line
            <= claim.end_line
            <= snippet["excerpt_end_line"]
            or claim.end_line - claim.line >= 40
        ):
            reason = "invalid_range_or_empty_claim"
        else:
            lines = io.StringIO(snippet["text"], newline="").readlines()
            window = "".join(
                lines[
                    claim.line - snippet["excerpt_line"] : claim.end_line
                    - snippet["excerpt_line"]
                    + 1
                ]
            )
            if claim.quote not in window:
                reason = "quote_mismatch"
            elif claim.assessment == "unknown":
                if claim.obligation == "guard":
                    satisfied.add("guard")
                    report["unknowns"].append("Guard effectiveness is unknown")
                else:
                    reason = "positive_evidence_required"
            elif claim.obligation == "flow":
                if (
                    snippet.get("flow_id") is None
                    or claim.line > snippet["end_line"]
                    or claim.end_line < snippet["line"]
                ):
                    reason = "not_a_recorded_flow_location"
                else:
                    flow_ids.add(snippet["flow_id"])
                    satisfied.add("flow")
            else:
                mapping = flask_mapping(bundle, snippet) if claim.obligation == "source" else None
                if policy.get("language") == "java":
                    from veriflow.java_claims import anchors as java_anchors

                    located = java_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_c_family":
                    from veriflow.joern_c_family_claims import anchors as c_family_anchors

                    located = c_family_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_rust":
                    from veriflow.joern_rust_claims import anchors as rust_anchors

                    located = rust_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_go":
                    from veriflow.joern_go_claims import anchors as go_anchors

                    located = go_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_csharp":
                    from veriflow.joern_csharp_claims import anchors as joern_csharp_anchors

                    located = joern_csharp_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_express":
                    from veriflow.joern_express_claims import anchors as express_anchors

                    located = express_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_flask":
                    from veriflow.joern_flask_claims import anchors as flask_anchors

                    located = flask_anchors(bundle, snippet, claim)
                elif policy.get("language") == "joern_runtime":
                    from veriflow.joern_claims import runtime_anchors

                    located = runtime_anchors(bundle, snippet, claim)
                elif policy.get("language") == "csharp":
                    from veriflow.csharp_claims import anchors as csharp_anchors

                    located = csharp_anchors(bundle, snippet, claim)
                else:
                    located = anchors(
                        window, claim, policy, mapping.get("binding_name") if mapping else None
                    )
                if not located:
                    reason = "supported_syntax_not_in_quote"
                else:
                    satisfied.add(claim.obligation)
                    if claim.obligation == "source":
                        source_nodes.extend(flow_nodes(bundle, snippet, located))
                    elif claim.obligation == "sink":
                        sink_nodes.extend(flow_nodes(bundle, snippet, located))
                    elif claim.obligation == "guard":
                        guard_present = True
        report["checks"].append(
            {
                "obligation": claim.obligation,
                "evidence_id": claim.evidence_id,
                "passed": reason is None,
                "reason": reason,
            }
        )
    linked = False
    for source in source_nodes:
        for sink in sink_nodes:
            # Compare the steps a snippet covers: merged regions still span source to sink.
            source_steps, sink_steps = covered_steps(source), covered_steps(sink)
            if (
                source["flow_id"] != sink["flow_id"]
                or source["flow_id"] not in flow_ids
                or not source_steps
                or not sink_steps
                or min(source_steps) > max(sink_steps)
                or max(sink_steps) != sink["flow_steps"] - 1
            ):
                continue
            if policy.get("language") in ("java", "csharp"):
                thread = [n for n in bundle["snippets"] if n.get("flow_id") == source["flow_id"]]
                spanned = {step for n in thread for step in covered_steps(n)}
                if spanned != set(range(sink["flow_steps"])):
                    continue
            if 0 in source_steps:
                linked = True
            elif mapping := flask_mapping(bundle, source):
                linked = True
                if mapping not in report["source_mappings"]:
                    report["source_mappings"].append(mapping)
    needed = {"source", "sink", "flow", "guard"}
    if decision.verdict == "likely_false_positive":
        needed.add("counterevidence")
        if not guard_present:
            report["missing"].append("present_guard")
    report["missing"].extend(sorted(needed - satisfied))
    if not linked:
        report["missing"].append("source_to_sink_recorded_flow")
    invalid = any(not check["passed"] for check in report["checks"])
    report["status"] = (
        "invalid_claims"
        if invalid
        else "insufficient_evidence"
        if report["missing"]
        else "supported_for_review"
    )
    report["passed"] = report["status"] == "supported_for_review"
    return report
