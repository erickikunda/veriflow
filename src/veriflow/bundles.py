"""Deterministic, bounded evidence bundles from immutable scan results."""

import hashlib
import io
import json
import tokenize
from pathlib import Path

from sqlalchemy import select

from veriflow.domain import VeriFlowError
from veriflow.envelope import resolve as resolve_envelope
from veriflow.indexing import verified_source
from veriflow.joern_claims import native_audit, policy_for_rule
from veriflow.persistence import Candidate, EvidenceBundle, ScanAttempt, exclusive_worker
from veriflow.python_parser import MAX_BYTES
from veriflow.sarif import MAX_SARIF_BYTES, bind_location, fingerprint, indexed
from veriflow.source_context import covered_steps

BUILDER_VERSION = "15"
MAX_BUNDLE_BYTES = 32 * 1024
MAX_SOURCE_BYTES = 16 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def merge_duplicates(references):
    """Collapse references that bind to one source region; no evidence is discarded."""
    merged, seen = [], {}
    for role, reference, metadata in references:
        identity = (
            None
            if reference is None
            else (role, reference["path"], reference["line"], reference["end_line"])
        )
        position = seen.get(identity) if identity is not None else None
        if position is None:
            if identity is not None:
                seen[identity] = len(merged)
            merged.append([role, reference, dict(metadata), []])
            continue
        covered = merged[position][3]
        for item in (metadata, merged[position][2]):
            step = item.get("flow_step")
            if step is not None and step not in covered:
                covered.append(step)
    return [
        (
            role,
            reference,
            {**metadata, **({"flow_steps_covered": sorted(covered)} if covered else {})},
        )
        for role, reference, metadata, covered in merged
    ]


def select_references(references, limit):
    """Keep the reported location, the flow head and the flow tail; elide the middle only."""
    # Positions, not object identity, carry the original order through the partition.
    kept, elided = [], []
    by_role = {role: [] for role in ("primary", "flow", "related")}
    for position, item in enumerate(references):
        by_role.setdefault(item[0], []).append(position)
    primary, flow, related = by_role["primary"], by_role["flow"], by_role["related"]
    kept.extend(primary[:limit])
    elided.extend(primary[limit:])
    budget = limit - len(kept)
    if len(flow) <= budget:
        kept.extend(flow)
    else:
        head = (budget + 1) // 2
        tail = budget - head
        kept.extend(flow[:head])
        elided.extend(flow[head : len(flow) - tail] if tail else flow[head:])
        if tail:
            kept.extend(flow[len(flow) - tail :])
    budget = limit - len(kept)
    kept.extend(related[:budget])
    elided.extend(related[budget:])
    return (
        [references[position] for position in sorted(kept)],
        [references[position] for position in sorted(elided)],
    )


def elided_index(elided, limit):
    """Name the omitted steps without their source so the omission stays legible, not hidden."""
    index = []
    for role, reference, metadata in elided[:limit]:
        if reference is None:
            continue
        entry = {"role": role, "path": reference["path"], "line": reference["line"]}
        if metadata.get("flow_step") is not None:
            entry["flow_step"] = metadata["flow_step"]
        index.append(entry)
    return index


def within_window(references, window):
    """Split into the span's locations and the rest; reported and related locations always stay."""
    if window is None:
        return list(references), []
    first, last = window["flow_step_start"], window["flow_step_end"]
    inside, outside = [], []
    for item in references:
        in_span = item[0] != "flow" or any(first <= step <= last for step in covered_steps(item[2]))
        (inside if in_span else outside).append(item)
    return inside, outside


def excerpt_options(lines, start, end, context, whole_file):
    """Excerpt widths for one region, narrowest first; allocation picks the widest that fits."""
    options, seen = [], set()
    for pad in range(context + 1):
        window = (max(1, start - pad), min(len(lines), end + pad))
        if window not in seen:
            seen.add(window)
            options.append(window)
    if whole_file and (1, len(lines)) not in seen:
        options.append((1, len(lines)))
    return options


def allocate_source(items, budget):
    """Max-min fair: every retained location gets its narrowest excerpt before any gets context.

    Endpoints are served first so a large intermediate region cannot starve the flow's source or
    sink, which is exactly what bounded head/tail retention set out to keep. One whole-file
    excerpt per file is then funded before general context, because the syntax gates rebuild a
    file from its excerpts and a file covered only in part cannot be rebuilt at all.
    """
    levels = [None] * len(items)
    order = sorted(
        range(len(items)),
        key=lambda index: (items[index]["priority"], items[index]["sizes"][0], index),
    )
    remaining = budget
    for index in order:
        if remaining >= items[index]["sizes"][0]:
            levels[index] = 0
            remaining -= items[index]["sizes"][0]
    # Fund one complete excerpt per file; the others stay narrow rather than repeat it.
    complete = {}
    for index in order:
        item = items[index]
        whole = item.get("whole_file_level")
        if levels[index] is None or whole is None or item["file_key"] in complete:
            continue
        extra = item["sizes"][whole] - item["sizes"][levels[index]]
        if extra <= remaining:
            remaining, levels[index] = remaining - extra, whole
            complete[item["file_key"]] = index
    upgraded = True
    while upgraded:
        upgraded = False
        for index, item in enumerate(items):
            level = levels[index]
            if level is None or level + 1 >= len(item["sizes"]):
                continue
            extra = item["sizes"][level + 1] - item["sizes"][level]
            if extra <= remaining:
                remaining, levels[index], upgraded = remaining - extra, level + 1, True
    return levels


def get_bundle(store, bundle_id):
    with store.transaction() as session:
        bundle = session.get(EvidenceBundle, bundle_id)
        if bundle is None:
            raise VeriFlowError("Evidence bundle not found")
        if hashlib.sha256(canonical(bundle.content)).hexdigest() != bundle.id:
            raise VeriFlowError("Evidence bundle digest mismatch")
        return {"bundle_id": bundle.id, **bundle.content}


def build_bundle(store, attempt_id, candidate_fingerprint, envelope=None, window=None):
    store.require_initialized()
    with exclusive_worker(store.root):
        return _build_bundle(store, attempt_id, candidate_fingerprint, envelope, window)


def _build_bundle(store, attempt_id, candidate_fingerprint, envelope=None, window=None):
    with store.transaction() as session:
        attempt = session.get(ScanAttempt, attempt_id)
        candidate = session.scalar(
            select(Candidate).where(
                Candidate.attempt_id == attempt_id, Candidate.fingerprint == candidate_fingerprint
            )
        )
    if attempt is None or candidate is None:
        raise VeriFlowError("Scan candidate not found")
    run, manifest, tree = verified_source(store, attempt.run_id)
    bounds = (envelope or resolve_envelope()).for_rule(candidate.evidence.get("rule_id"))
    if candidate.evidence.get("origin") == "llm_discovery":
        return _build_llm_bundle(
            store, attempt, candidate, run, manifest, tree, candidate_fingerprint, bounds
        )
    raw_path = store.root / "scans" / attempt.id / "results.sarif"
    if (
        Path(attempt.report["raw_sarif_path"]).resolve() != raw_path.resolve()
        or raw_path.is_symlink()
    ):
        raise VeriFlowError("Unexpected SARIF artifact path")
    with raw_path.open("rb") as handle:
        raw = handle.read(MAX_SARIF_BYTES + 1)
    if len(raw) > MAX_SARIF_BYTES or hashlib.sha256(raw).hexdigest() != attempt.report.get(
        "sarif_sha256"
    ):
        raise VeriFlowError("SARIF integrity check failed")
    matched = None
    try:
        for sarif_run in json.loads(raw)["runs"]:
            driver = sarif_run["tool"]["driver"]
            for result in sarif_run.get("results", []):
                rule = result.get("ruleId") or indexed(driver["rules"], result["ruleIndex"])["id"]
                if fingerprint(manifest.snapshot_id, driver, rule, result) == candidate_fingerprint:
                    matched = sarif_run, result
                    break
            if matched:
                break
        if matched is None:
            raise VeriFlowError("Candidate is absent from pinned SARIF")
        sarif_run, result = matched
        # Preserve primary locations and every flow in SARIF order; cap materialized snippets.
        locations = [
            ("primary", item.get("physicalLocation", {}), {})
            for item in result.get("locations", [])
        ]
        for flow_number, flow in enumerate(result.get("codeFlows", [])):
            for thread_number, thread in enumerate(flow.get("threadFlows", [])):
                steps = thread.get("locations", [])
                locations.extend(
                    (
                        "flow",
                        item.get("location", {}).get("physicalLocation", {}),
                        {
                            "flow_id": f"F{flow_number}T{thread_number}",
                            "flow_step": step,
                            "flow_steps": len(steps),
                        },
                    )
                    for step, item in enumerate(steps)
                )
        for location in result.get("relatedLocations", []):
            locations.append(("related", location.get("physicalLocation", {}), {}))
        location_limit = bounds.max_locations + int(
            candidate.evidence["rule_id"] == "veriflow/joern-rust-env-shell-v1"
            and attempt.report.get("scanner", {}).get("engine_id") == "joern"
        )
        # Bind every location first: duplicates must be collapsed before the budget is spent.
        bound = [
            (role, bind_location(location, sarif_run, manifest, tree), metadata)
            for role, location, metadata in locations
        ]
        distinct = merge_duplicates(bound)
        scoped, outside = within_window(distinct, window)
        references, elided = select_references(scoped, location_limit)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, RecursionError):
        raise VeriFlowError("Cannot interpret candidate SARIF evidence") from None
    snippets, gaps, notes, source_bytes = [], [], [], 0
    if not result.get("locations"):
        gaps.append("primary_location_missing")
    if not references:
        gaps.append("no_locations")
    if elided:
        gaps.append(f"location_limit:{len(elided)}_elided")
    if outside:
        gaps.append(f"window_scope:{len(outside)}_outside")
    endpoints = {0, len(references) - 1}
    resolved = []
    for position, (role, reference, metadata) in enumerate(references):
        if reference is None:
            gaps.append(f"location_{position}:unmapped")
            continue
        try:
            record = next(file for file in manifest.files if file.path == reference["path"])
            if record.size_bytes > MAX_BYTES:
                raise VeriFlowError("file_limit")
            with (tree / record.path).open("rb") as handle:
                contents = handle.read(MAX_BYTES + 1)
            if hashlib.sha256(contents).hexdigest() != record.sha256:
                raise VeriFlowError("source_integrity")
            encoding = tokenize.detect_encoding(io.BytesIO(contents).readline)[0]
            lines = io.StringIO(contents.decode(encoding), newline="").readlines()
            start, end = reference["line"], reference["end_line"]
            if end > len(lines) or end - start + 1 > bounds.max_region_lines:
                raise VeriFlowError("range_limit")
            # Small Java/C# files retain imports and declaration context for syntax gates.
            # Existing cumulative source/envelope limits still apply.
            whole_file = len(lines) <= bounds.max_region_lines and (
                record.path.endswith((".java", ".cs"))
                or (
                    record.path.endswith(
                        (".py", ".js", ".ts", ".go", ".rs", ".c", ".h", ".cpp", ".hpp")
                    )
                    and policy_for_rule(candidate.evidence["rule_id"], store)
                    and attempt.report.get("scanner", {}).get("engine_id") == "joern"
                )
            )
            options = excerpt_options(lines, start, end, bounds.context_lines, whole_file)
            texts = ["".join(lines[first - 1 : last]) for first, last in options]
            resolved.append(
                {
                    "file_key": (reference["path"], reference["sha256"]),
                    "whole_file_level": (
                        options.index((1, len(lines))) if (1, len(lines)) in options else None
                    ),
                    "position": position,
                    "role": role,
                    "reference": reference,
                    "metadata": metadata,
                    "line_count": len(lines),
                    "priority": 0 if role == "primary" or position in endpoints else 1,
                    "options": options,
                    "texts": texts,
                    "sizes": [len(text.encode()) for text in texts],
                }
            )
        except VeriFlowError as exc:
            if str(exc) == "source_integrity":
                raise
            gaps.append(f"location_{position}:{exc}")
        except (UnicodeError, SyntaxError, LookupError):
            gaps.append(f"location_{position}:encoding")
    trimmed = 0
    for item, level in zip(
        resolved, allocate_source(resolved, bounds.max_source_bytes), strict=True
    ):
        if level is None:
            gaps.append(f"location_{item['position']}:source_budget")
            continue
        trimmed += level < len(item["options"]) - 1
        first, last = item["options"][level]
        source_bytes += item["sizes"][level]
        snippets.append(
            {
                "id": f"E{item['position'] + 1}",
                "role": item["role"],
                **item["metadata"],
                **item["reference"],
                "excerpt_line": first,
                "excerpt_end_line": last,
                "source_line_count": item["line_count"],
                "text": item["texts"][level],
            }
        )
    if trimmed:
        # Narrower context is a reduction, not a loss: every location is still materialized.
        # It stays visible as a note so the gates, not a proxy, decide on sufficiency.
        notes.append(f"source_budget_trimmed:{trimmed}")
    message = candidate.evidence["message"]
    if len(message.encode()) > 2048:
        message = message.encode()[:2048].decode(errors="ignore")
        gaps.append("message_limit")
    content = {
        "schema_version": "1",
        "builder_version": BUILDER_VERSION,
        "engine_id": (
            attempt.report["scanner"].get("engine_id", "unknown")
            if isinstance(attempt.report.get("scanner"), dict)
            else "codeql"
            if "scanner" not in attempt.report
            else "unknown"
        ),
        "expansion_depth": 0,
        "run_id": run.id,
        "repo_id": run.repo_id,
        "snapshot_id": manifest.snapshot_id,
        "classification": manifest.classification,
        "attempt_id": attempt_id,
        "candidate_fingerprint": candidate_fingerprint,
        "rule_id": candidate.evidence["rule_id"],
        "message": message,
        "suppressed": candidate.evidence["suppressed"],
        "sarif_sha256": attempt.report["sarif_sha256"],
        "snippets": snippets,
        "gaps": gaps,
        "notes": notes,
        "status": "partial" if gaps else "ready",
        "locations_total": len(locations),
        "locations_considered": len(references),
        "duplicate_locations_merged": len(bound) - len(distinct),
        "location_limit": location_limit,
        "elided_locations": elided_index(elided + outside, bounds.max_elided_index),
        "envelope": bounds.record(),
        "window": window,
        "trust": "untrusted_source_and_tool_output",
        "reachability_proven": False,
    }
    gate_policy = policy_for_rule(content["rule_id"], store)
    if content["engine_id"] == "joern" and gate_policy:
        content["joern_native_audit"] = native_audit(
            store.root / "scans" / attempt.id,
            attempt.report,
            manifest,
            tree,
            raw,
            result,
            policy=gate_policy,
            max_nodes=location_limit - 1,
            store=store,
        )
    if len(canonical(content)) > bounds.max_bundle_bytes:
        raise VeriFlowError("Evidence bundle exceeds the configured envelope limit")
    verified_source(store, run.id)
    identity = hashlib.sha256(canonical(content)).hexdigest()
    with store.transaction() as session:
        if session.get(EvidenceBundle, identity) is None:
            session.add(EvidenceBundle(id=identity, candidate_id=candidate.id, content=content))
    return get_bundle(store, identity)


def _build_llm_bundle(
    store, attempt, candidate, run, manifest, tree, candidate_fingerprint, bounds
):
    """Build snapshot-bound evidence without pretending the proposal came from SARIF."""
    proposal = candidate.evidence.get("llm_discovery", {})
    locations = proposal.get("locations", [])
    if not locations or len(locations) > bounds.max_locations:
        raise VeriFlowError("LLM discovery candidate has invalid location count")
    records = {record.path: record for record in manifest.files}
    snippets, gaps, source_bytes = [], [], 0
    for position, location in enumerate(locations):
        try:
            record = records.get(location["path"])
            if (
                record is None
                or record.sha256 != location["sha256"]
                or type(location["line"]) is not int
                or type(location["end_line"]) is not int
                or not 1 <= location["line"] <= location["end_line"]
                or location["end_line"] - location["line"] >= bounds.max_region_lines
            ):
                raise VeriFlowError("unverified_location")
            payload = (tree / record.path).read_bytes()
            if hashlib.sha256(payload).hexdigest() != record.sha256:
                raise VeriFlowError("source_integrity")
            lines = payload.decode("utf-8").splitlines(keepends=True)
            if location["end_line"] > len(lines):
                raise VeriFlowError("range_limit")
            start = max(1, location["line"] - bounds.context_lines)
            end = min(len(lines), location["end_line"] + bounds.context_lines)
            text = "".join(lines[start - 1 : end])
            size = len(text.encode())
            if source_bytes + size > bounds.max_source_bytes:
                raise VeriFlowError("source_budget")
            source_bytes += size
            snippets.append(
                {
                    "id": f"E{position + 1}",
                    "role": location["role"],
                    "snapshot_id": manifest.snapshot_id,
                    "path": record.path,
                    "sha256": record.sha256,
                    "line": location["line"],
                    "end_line": location["end_line"],
                    "excerpt_line": start,
                    "excerpt_end_line": end,
                    "source_line_count": len(lines),
                    "text": text,
                }
            )
        except VeriFlowError as exc:
            if str(exc) == "source_integrity":
                raise
            gaps.append(f"location_{position}:{exc}")
        except (KeyError, TypeError, UnicodeError):
            gaps.append(f"location_{position}:invalid")
    content = {
        "schema_version": "1",
        "builder_version": BUILDER_VERSION,
        "engine_id": "llm_discovery",
        "expansion_depth": 0,
        "run_id": run.id,
        "repo_id": run.repo_id,
        "snapshot_id": manifest.snapshot_id,
        "classification": manifest.classification,
        "attempt_id": attempt.id,
        "candidate_fingerprint": candidate_fingerprint,
        "rule_id": candidate.evidence["rule_id"],
        "message": candidate.evidence["message"][:2048],
        "suppressed": False,
        "sarif_sha256": None,
        "discovery_proposal_sha256": proposal.get("proposal_sha256"),
        "cwe": candidate.evidence.get("cwe"),
        "snippets": snippets,
        "gaps": gaps,
        "notes": [],
        "status": "partial" if gaps or not snippets else "ready",
        "locations_total": len(locations),
        "locations_considered": len(locations),
        "duplicate_locations_merged": 0,
        "location_limit": bounds.max_locations,
        "elided_locations": [],
        "window": None,
        "envelope": bounds.record(),
        "trust": "untrusted_source_and_model_proposal",
        "reachability_proven": False,
    }
    if len(canonical(content)) > bounds.max_bundle_bytes:
        raise VeriFlowError("Evidence bundle exceeds the configured envelope limit")
    verified_source(store, run.id)
    identity = hashlib.sha256(canonical(content)).hexdigest()
    with store.transaction() as session:
        if session.get(EvidenceBundle, identity) is None:
            session.add(EvidenceBundle(id=identity, candidate_id=candidate.id, content=content))
    return get_bundle(store, identity)
