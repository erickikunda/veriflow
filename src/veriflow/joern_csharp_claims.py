"""C# endpoint claims must overlap the mapped framework syntax fact, not just its line."""

from veriflow.csharp_claims import anchors as syntax_anchors
from veriflow.csharp_locations import validate_locations
from veriflow.source_context import complete_context, covers_flow_step


def anchors(bundle, snippet, claim):
    if claim.obligation not in {"source", "sink"}:
        return []
    nodes = bundle.get("joern_native_audit", {}).get("nodes", [])
    if not nodes:
        return []
    node = nodes[0 if claim.obligation == "source" else -1]
    if (
        not covers_flow_step(snippet, node.get("flow_step"))
        or snippet.get("path") != node.get("path")
        or snippet.get("sha256") != node.get("sha256")
        or claim.line != node.get("line")
        or claim.end_line != claim.line
        or not node.get("code")
        or node["code"] not in claim.quote
    ):
        return []
    context = complete_context(bundle, snippet, ".cs")
    if context is None:
        return []
    mapped = validate_locations(context.encode(), node["sha256"], [node], framework_facts=True)
    if mapped.get("status") != "parsed" or len(mapped.get("nodes", [])) != 1:
        return []
    result = mapped["nodes"][0]
    span = result.get("span") or {}
    if (
        result.get("status") != "validated_span"
        or span.get("line") != claim.line
        or span.get("end_line") != claim.end_line
        or not any(
            f.get("category") == claim.obligation + "s" for f in result.get("framework_facts", [])
        )
    ):
        return []
    return syntax_anchors(bundle, snippet, claim)
