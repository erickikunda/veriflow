"""Go HTTP/shell endpoint claim binding; generated intermediate code is never an anchor."""

from veriflow.go_http_parser import parse_isolated
from veriflow.source_context import complete_context, covers_flow_step


def anchors(bundle, snippet, claim):
    if claim.obligation not in {"source", "sink"}:
        return []  # Guard presence/safety is deliberately unsupported; use unknown.
    nodes = bundle.get("joern_native_audit", {}).get("nodes", [])
    if not nodes:
        return []
    node = nodes[0 if claim.obligation == "source" else -1]
    if (
        snippet.get("path") != node.get("path")
        or snippet.get("sha256") != node.get("sha256")
        or not covers_flow_step(snippet, node.get("flow_step"))
        or claim.line != node.get("line")
        or claim.end_line != claim.line
        or not node.get("code")
        or node["code"] not in claim.quote
    ):
        return []
    context = complete_context(bundle, snippet, ".go")
    if context is None:
        return []
    parsed = parse_isolated(context.encode())
    selected = [p for p in parsed.get(claim.obligation + "s", []) if p["line"] == claim.line]
    if (
        parsed.get("status") != "parsed"
        or len(selected) != 1
        or selected[0].get("argument_code" if claim.obligation == "sink" else "code")
        != node["code"]
        or selected[0].get("code", "") not in claim.quote
    ):
        return []
    return [(claim.line, claim.line)]
