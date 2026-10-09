"""Sequential, explicitly requested candidate triage using existing budget/evidence gates."""

import hashlib

from sqlalchemy import func, select

from veriflow.bundles import build_bundle, canonical
from veriflow.domain import VeriFlowError
from veriflow.envelope import compatibility
from veriflow.envelope import resolve as resolve_envelope
from veriflow.history import validate_page
from veriflow.persistence import Candidate, Run, ScanAttempt, TriageBudget
from veriflow.triage import triage

CONTINUE_STATES = {
    "completed",
    "evidence_rejected",
    "unsupported_rule",
    "incomplete_evidence",
    "advisory_unverified",
}


def triage_attempt(
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
    allow_degraded_evidence=False,
    envelope=None,
):
    if review_policy is not None:
        from veriflow.joern_claims import require_policy

        require_policy(review_policy)
    notes = compatibility(envelope or resolve_envelope(), config)
    validate_page(offset, limit)
    if limit > 100:
        raise VeriFlowError("Batch triage limit must not exceed 100 candidates")
    if not key.strip() or len(key) > 200:
        raise VeriFlowError("Batch key must contain 1–200 characters")
    with store.transaction() as session:
        attempt = session.scalar(
            select(ScanAttempt)
            .join(Run)
            .where(ScanAttempt.id == attempt_id, Run.repo_id == repo_id)
        )
        if attempt is None:
            raise VeriFlowError("Analysis attempt does not belong to repository")
        if attempt.report.get("status") not in {"completed", "partial"}:
            raise VeriFlowError("Batch triage requires a completed or partial query attempt")
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
    rows = []
    halted = False
    next_offset = offset
    for fingerprint in fingerprints:
        identity = [key, attempt_id, fingerprint]
        if review_policy is not None:
            identity.append(review_policy)
        request_key = "batch:" + hashlib.sha256(canonical(identity)).hexdigest()
        row = {"candidate_fingerprint": fingerprint, "request_key": request_key}
        try:
            bundle = build_bundle(store, attempt_id, fingerprint, envelope)
            result = triage(
                store,
                bundle["bundle_id"],
                config,
                adapter,
                request_key,
                unmetered=unmetered,
                allow_degraded_evidence=allow_degraded_evidence,
                **({"review_policy": review_policy} if review_policy else {}),
            )
        except VeriFlowError as exc:
            rows.append({**row, "state": "operation_error", "error": str(exc)})
            halted = True
            break
        rows.append(
            {
                **row,
                **{
                    field: result.get(field)
                    for field in (
                        "triage_id",
                        "bundle_id",
                        "state",
                        "disposition",
                        "evidence_degraded",
                        "accounted_micro_usd",
                    )
                },
            }
        )
        next_offset += 1
        if result["state"] not in CONTINUE_STATES:
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
        "degraded_evidence_allowed": allow_degraded_evidence,
        "envelope_notes": notes,
        "items": rows,
        "next_offset": next_offset if next_offset < total else None,
        "scope": "Advisory triage only; outcomes do not confirm or suppress vulnerabilities",
    }
