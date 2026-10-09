"""Complete bounded source reconstruction from consistent evidence excerpts."""

import io

DEFAULT_CONTEXT_BYTES = 16 * 1024


def complete_context(bundle, snippet, suffix=".java"):
    """Join only consistent, snapshot-bound excerpts; never fill unseen lines."""
    if not snippet.get("path", "").endswith(suffix):
        return None
    pieces = [
        s
        for s in bundle["snippets"]
        if s["path"] == snippet["path"]
        and s["sha256"] == snippet["sha256"]
        and s.get("snapshot_id") == snippet.get("snapshot_id")
    ]
    totals = {s["source_line_count"] for s in pieces if "source_line_count" in s}
    if len(totals) != 1:
        return None
    total = totals.pop()
    if not isinstance(total, int) or not 1 <= total <= 16384:
        return None
    lines = {}
    for piece in pieces:
        text = io.StringIO(piece["text"], newline="").readlines()
        start, end = piece["excerpt_line"], piece["excerpt_end_line"]
        if not 1 <= start <= end <= total or len(text) != end - start + 1:
            return None
        for number, line in enumerate(text, start):
            if number in lines and lines[number] != line:
                return None
            lines[number] = line
    if set(lines) != set(range(1, total + 1)):
        return None
    source = "".join(lines[number] for number in range(1, total + 1))
    # Track the envelope the bundle was built under; a second constant would silently
    # refuse exactly the wider bundles an operator widened the envelope to allow.
    limit = (bundle.get("envelope") or {}).get("max_source_bytes", DEFAULT_CONTEXT_BYTES)
    if len(source.encode("utf-8")) > limit:
        return None
    return source


def covered_steps(item):
    """Every flow step one region stands for, after repeats are merged.

    Accepts a materialized snippet or the location metadata it was built from; both carry
    `flow_step` and, once merged, `flow_steps_covered`.
    """
    covered = item.get("flow_steps_covered")
    if covered:
        return sorted(covered)
    step = item.get("flow_step")
    return [] if step is None else [step]


def covers_flow_step(item, step):
    """One region may stand for several steps; every one of them still maps to it."""
    return step in covered_steps(item)
