"""Overlapping flow windows for candidates larger than the evidence envelope; advisory only."""

import hashlib

from sqlalchemy import func, select

from veriflow.batch_triage import CONTINUE_STATES
from veriflow.bundles import build_bundle, canonical
from veriflow.domain import VeriFlowError
from veriflow.envelope import compatibility
from veriflow.envelope import resolve as resolve_envelope
from veriflow.history import validate_page
from veriflow.persistence import Candidate, Run, ScanAttempt, TriageBudget
from veriflow.source_context import covered_steps
from veriflow.triage import triage

MAX_WINDOWS = 32


def plan_windows(total_steps, size, overlap):
    """Contiguous overlapping spans covering every flow step exactly once or twice."""
    if type(size) is not int or size < 2:
        raise VeriFlowError("Window size must be an integer of at least 2 flow steps")
    if type(overlap) is not int or not 0 <= overlap < size:
        raise VeriFlowError("Window overlap must be an integer below the window size")
    if total_steps <= 0:
        return []
    spans, start = [], 0
    while True:
        end = min(start + size - 1, total_steps - 1)
        spans.append((start, end))
        if end >= total_steps - 1:
            return spans
        start = end - overlap + 1


def flow_length(bundle):
    """Total steps the engine recorded, which may exceed what one bundle can materialize."""
    lengths = {
        snippet["flow_steps"]
        for snippet in bundle["snippets"]
        if snippet.get("flow_id") is not None and isinstance(snippet.get("flow_steps"), int)
    }
    return max(lengths) if len(lengths) == 1 else 0


def _window_key(key, attempt_id, fingerprint, review_policy, index, span):
    identity = [key, attempt_id, fingerprint, review_policy, "window", index, *span]
    return "window:" + hashlib.sha256(canonical(identity)).hexdigest()


def triage_candidate_windows(
    store,
    attempt_id,
    fingerprint,
    config,
    adapter,
    key,
    *,
    review_policy=None,
    unmetered=False,
    envelope=None,
    overlap=1,
    max_windows=8,
):
    """Walk one candidate's flow in bounded spans; no span is a complete source-to-sink view."""
    base = build_bundle(store, attempt_id, fingerprint, envelope)
    steps = flow_length(base)
    size = max(2, base.get("location_limit", 8) - 1)
    record = {
        "candidate_fingerprint": fingerprint,
        "flow_steps": steps,
        "window_size": size,
        "window_overlap": overlap,
        "disposition": "abstain",
        "verified": False,
    }
    if steps <= size:
        # The flow already fits, so the ordinary single-bundle gates apply unchanged.
        result = triage(
            store,
            base["bundle_id"],
            config,
            adapter,
            key,
            review_policy=review_policy,
            unmetered=unmetered,
        )
        return {
            **record,
            "windowed": False,
            "window_count": 1,
            "covered_flow_steps": steps,
            "windows": [
                {
                    "index": 0,
                    "flow_step_start": 0,
                    "flow_step_end": max(0, steps - 1),
                    "bundle_id": base["bundle_id"],
                    "request_key": key,
                    **{
                        field: result.get(field)
                        for field in ("triage_id", "state", "disposition", "evidence_degraded")
                    },
                }
            ],
            "model_suggested_verdicts": sorted(
                {result["decision"]["verdict"]} if result.get("decision") else set()
            ),
            "disposition": result.get("disposition", "abstain"),
            "verified": False,
            "status": "page_complete" if result["state"] in CONTINUE_STATES else "halted",
            "scope": "Single bounded bundle; ordinary evidence gates applied",
        }
    spans = plan_windows(steps, size, overlap)
    planned = len(spans)
    truncated = planned > max_windows
    spans = spans[:max_windows]
    rows, verdicts, covered, halted = [], set(), set(), False
    per_step, coverage = {}, {}
    for index, span in enumerate(spans):
        window = {
            "index": index,
            "count": len(spans),
            "flow_step_start": span[0],
            "flow_step_end": span[1],
        }
        request_key = _window_key(key, attempt_id, fingerprint, review_policy, index, span)
        row = {**window, "request_key": request_key}
        try:
            bundle = build_bundle(store, attempt_id, fingerprint, envelope, window)
            # Every window is a partial view by construction, so the gate can never be satisfied.
            result = triage(
                store,
                bundle["bundle_id"],
                config,
                adapter,
                request_key,
                review_policy=review_policy,
                unmetered=unmetered,
                allow_degraded_evidence=True,
            )
        except VeriFlowError as exc:
            rows.append({**row, "state": "operation_error", "error": str(exc)})
            halted = True
            break
        # Count the steps a window actually materialized, never the span it asked for.
        covered.update(
            step
            for snippet in bundle["snippets"]
            if snippet.get("flow_id") is not None
            for step in covered_steps(snippet)
        )
        rows.append(
            {
                **row,
                "bundle_id": bundle["bundle_id"],
                **{
                    field: result.get(field)
                    for field in (
                        "triage_id",
                        "state",
                        "disposition",
                        "evidence_degraded",
                        "accounted_micro_usd",
                    )
                },
            }
        )
        for step in range(span[0], span[1] + 1):
            coverage[step] = coverage.get(step, 0) + 1
        if result.get("decision"):
            verdict = result["decision"]["verdict"]
            verdicts.add(verdict)
            for step in range(span[0], span[1] + 1):
                per_step.setdefault(step, set()).add(verdict)
        if result["state"] not in CONTINUE_STATES:
            halted = True
            break
    return {
        **record,
        "windowed": True,
        "window_count": len(rows),
        "planned_windows": planned,
        "windows_truncated": truncated,
        "covered_flow_steps": len(covered),
        "windows": rows,
        "model_suggested_verdicts": sorted(verdicts),
        # Overlapping spans ask about the same step twice; disagreement is reported, not hidden.
        "overlapping_steps": sorted(step for step, seen in coverage.items() if seen > 1),
        "contradicted_steps": [
            {"flow_step": step, "verdicts": sorted(per_step[step])}
            for step in sorted(per_step)
            if len(per_step[step]) > 1
        ],
        "verdicts_disagree": any(len(seen) > 1 for seen in per_step.values()),
        "status": "halted" if halted else "page_complete",
        "scope": (
            "Overlapping partial views of one flow; no window observes the complete "
            "source-to-sink path, so every outcome is advisory and unverified"
        ),
    }


def triage_windows(
    store,
    repo_id,
    attempt_id,
    config,
    adapter,
    key,
    offset=0,
    limit=1,
    *,
    review_policy=None,
    unmetered=False,
    envelope=None,
    overlap=1,
    max_windows=8,
):
    """Bounded windowed advisory over a candidate page; never a verdict and never a dismissal."""
    if review_policy is not None:
        from veriflow.joern_claims import require_policy

        require_policy(review_policy)
    notes = compatibility(envelope or resolve_envelope(), config)
    validate_page(offset, limit)
    if not key.strip() or len(key) > 200:
        raise VeriFlowError("Window key must contain 1–200 characters")
    if type(max_windows) is not int or not 1 <= max_windows <= MAX_WINDOWS:
        raise VeriFlowError(f"Window count must be an integer between 1 and {MAX_WINDOWS}")
    with store.transaction() as session:
        attempt = session.scalar(
            select(ScanAttempt)
            .join(Run)
            .where(ScanAttempt.id == attempt_id, Run.repo_id == repo_id)
        )
        if attempt is None:
            raise VeriFlowError("Analysis attempt does not belong to repository")
        if attempt.report.get("status") not in {"completed", "partial"}:
            raise VeriFlowError("Windowed triage requires a completed or partial query attempt")
        if session.get(TriageBudget, attempt.run_id) is None and not unmetered:
            raise VeriFlowError("Configure a run triage budget before requesting triage")
        run_id = attempt.run_id
        scope = Candidate.attempt_id == attempt_id
        total = session.scalar(select(func.count()).select_from(Candidate).where(scope))
        fingerprints = list(
            session.scalars(
                select(Candidate.fingerprint)
                .where(scope)
                .order_by(Candidate.fingerprint)
                .offset(offset)
                .limit(limit)
            )
        )
    items, halted, next_offset = [], False, offset
    for fingerprint in fingerprints:
        try:
            item = triage_candidate_windows(
                store,
                attempt_id,
                fingerprint,
                config,
                adapter,
                key,
                review_policy=review_policy,
                unmetered=unmetered,
                envelope=envelope,
                overlap=overlap,
                max_windows=max_windows,
            )
        except VeriFlowError as exc:
            items.append(
                {
                    "candidate_fingerprint": fingerprint,
                    "status": "operation_error",
                    "error": str(exc),
                }
            )
            halted = True
            break
        items.append(item)
        next_offset += 1
        if item["status"] != "page_complete":
            halted = True
            break
    return {
        "schema_version": "1",
        "repo_id": repo_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "status": "halted" if halted else "page_complete",
        "offset": offset,
        "limit": limit,
        "total_candidates": total,
        "selected_candidates": len(fingerprints),
        "metered": not unmetered,
        "envelope_notes": notes,
        "items": items,
        "next_offset": next_offset if next_offset < total else None,
        "disposition": "abstain",
        "verified": False,
        "scope": (
            "Windowed advisory triage only; partial views never confirm, dismiss or "
            "complete a candidate"
        ),
    }
