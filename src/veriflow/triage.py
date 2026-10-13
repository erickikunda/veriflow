"""Single-worker triage with durable reservations and conservative abstention."""

import hashlib
import os
import subprocess
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import func, select

from veriflow.bundles import canonical, get_bundle
from veriflow.claims import GATE_VERSION, assess_evidence, bundle_engine, requirements
from veriflow.domain import VeriFlowError
from veriflow.intake import now
from veriflow.models import PROMPT_VERSION, Adapter, Decision, ModelConfig, request_body
from veriflow.persistence import DiscoveryCall, Run, TriageBudget, TriageCall, exclusive_worker


def cost_micro_usd(input_tokens, output_tokens, config):
    # Integer arithmetic, rounded up; configured rates are micro-USD per 1,000 tokens.
    return (
        input_tokens * config.input_micro_usd_per_1k
        + output_tokens * config.output_micro_usd_per_1k
        + 999
    ) // 1000


def set_budget(store, run_id, limit_micro_usd, max_requests=None):
    if type(limit_micro_usd) is not int or not 0 <= limit_micro_usd <= 10**12:
        raise VeriFlowError("Budget must be an integer between 0 and 10^12 micro-USD")
    if max_requests is not None and (
        type(max_requests) is not int or not 0 <= max_requests <= 10000
    ):
        raise VeriFlowError("Request limit must be an integer between 0 and 10000")
    store.require_initialized()
    with exclusive_worker(store.root), store.transaction() as session:
        if session.get(Run, run_id) is None:
            raise VeriFlowError("Run not found")
        existing = session.get(TriageBudget, run_id)
        if existing and existing.limit_micro_usd != limit_micro_usd:
            raise VeriFlowError("Run budget is already fixed; changing it is not supported")
        if existing and max_requests is not None and existing.max_requests != max_requests:
            raise VeriFlowError("Run request limit is already fixed; changing it is not supported")
        if existing is None:
            session.add(
                TriageBudget(
                    run_id=run_id,
                    limit_micro_usd=limit_micro_usd,
                    max_requests=100 if max_requests is None else max_requests,
                )
            )
    return triage_report(store, run_id)


def triage_report(store, run_id, offset=0, limit=100):
    if offset < 0 or not 1 <= limit <= 1000:
        raise VeriFlowError("Invalid triage pagination")
    with store.transaction() as session:
        # An unmetered run records charges without a budget row; spend must stay readable.
        budget = session.get(TriageBudget, run_id)
        charged = session.scalar(
            select(func.coalesce(func.sum(TriageCall.charged_micro_usd), 0)).where(
                TriageCall.run_id == run_id
            )
        )
        discovery_charged = session.scalar(
            select(func.coalesce(func.sum(DiscoveryCall.charged_micro_usd), 0)).where(
                DiscoveryCall.run_id == run_id
            )
        )
        calls = list(
            session.scalars(
                select(TriageCall)
                .where(TriageCall.run_id == run_id)
                .order_by(TriageCall.created_at, TriageCall.id)
                .offset(offset)
                .limit(limit)
            )
        )
        total = session.scalar(
            select(func.count()).select_from(TriageCall).where(TriageCall.run_id == run_id)
        )
        discovery_total = session.scalar(
            select(func.count()).select_from(DiscoveryCall).where(DiscoveryCall.run_id == run_id)
        )
        return {
            "schema_version": "1",
            "run_id": run_id,
            "report_kind": "triage_ledger",
            "budget_micro_usd": budget.limit_micro_usd if budget else None,
            "metered": budget is not None,
            "accounted_micro_usd": charged + discovery_charged,
            "remaining_micro_usd": (
                max(0, budget.limit_micro_usd - charged - discovery_charged) if budget else None
            ),
            "overrun_micro_usd": (
                max(0, charged + discovery_charged - budget.limit_micro_usd) if budget else None
            ),
            "verified_finding_count": None,
            "total": total,
            "discovery_call_count": discovery_total,
            "request_count": total + discovery_total,
            "max_requests": budget.max_requests if budget else None,
            "remaining_requests": (
                max(0, budget.max_requests - total - discovery_total) if budget else None
            ),
            "offset": offset,
            "limit": limit,
            "calls": [
                {**call.result, "state": call.state, "accounted_micro_usd": call.charged_micro_usd}
                for call in calls
            ],
        }


def triage(
    store,
    bundle_id: str,
    config: ModelConfig,
    adapter: Adapter,
    key: str,
    *,
    review_policy=None,
    unmetered=False,
    allow_degraded_evidence=False,
):
    if not key.strip() or len(key) > 200:
        raise VeriFlowError("Triage key must contain 1–200 characters")
    store.require_initialized()
    with exclusive_worker(store.root):
        bundle = get_bundle(store, bundle_id)
        if bundle["classification"] not in config.allowed_classifications:
            raise VeriFlowError("Bundle classification is not allowed by model policy")
        if config.provider != "replay":
            if not config.allow_source_transmission:
                raise VeriFlowError("Live source transmission is disabled")
            if config.provider in {"openai", "anthropic"} and not os.environ.get(
                config.api_key_env
            ):
                raise VeriFlowError(
                    "Set the configured API-key environment variable before live triage"
                )
        preflight = None
        if review_policy is not None:
            from veriflow.joern_claims import require_policy, review_preflight

            require_policy(review_policy, store)
            preflight = review_preflight(bundle, review_policy, store)
        body = request_body(bundle, config, review_policy=review_policy, store=store)
        # Preserve existing replay/cloud idempotency hashes when adding local-only settings.
        policy_identity = config.model_dump(
            exclude={"ollama_context_tokens"} if config.provider != "ollama" else set()
        )
        digest = hashlib.sha256(
            canonical(
                {
                    "body": body,
                    "config": policy_identity,
                    "adapter": adapter.identity,
                    "prompt_version": PROMPT_VERSION,
                    "gate_version": GATE_VERSION,
                    **(
                        {"review_policy": review_policy, "review_preflight": preflight}
                        if review_policy is not None
                        else {}
                    ),
                }
            )
        ).hexdigest()
        # Deliberately conservative estimate; includes schema, prompt and framing allowance.
        estimated_input = len(canonical(body)) + 4096
        reservation = cost_micro_usd(estimated_input, config.max_output_tokens, config)
        run_id = bundle["run_id"]
        with store.transaction() as session:
            for prior in session.scalars(
                select(TriageCall).where(TriageCall.run_id == run_id, TriageCall.state == "running")
            ):
                prior.state = "unknown"
                prior.result = {**prior.result, "reason": "interrupted; reservation retained"}
            existing = session.scalar(
                select(TriageCall).where(TriageCall.run_id == run_id, TriageCall.request_key == key)
            )
            if existing:
                if existing.request_sha256 != digest:
                    raise VeriFlowError("Triage key was already used for a different request")
                return {
                    **existing.result,
                    "state": existing.state,
                    "accounted_micro_usd": existing.charged_micro_usd,
                }
            budget = session.get(TriageBudget, run_id)
            if budget is None and not unmetered:
                raise VeriFlowError("Configure a run triage budget before requesting triage")
            requests = session.scalar(
                select(func.count()).select_from(TriageCall).where(TriageCall.run_id == run_id)
            ) + session.scalar(
                select(func.count())
                .select_from(DiscoveryCall)
                .where(DiscoveryCall.run_id == run_id)
            )
            if not unmetered and requests >= budget.max_requests:
                raise VeriFlowError("Run triage request limit exhausted; no provider was invoked")
            spent = session.scalar(
                select(func.coalesce(func.sum(TriageCall.charged_micro_usd), 0)).where(
                    TriageCall.run_id == run_id
                )
            ) + session.scalar(
                select(func.coalesce(func.sum(DiscoveryCall.charged_micro_usd), 0)).where(
                    DiscoveryCall.run_id == run_id
                )
            )
            degraded = []
            if bundle["status"] != "ready":
                degraded.append("bundle_" + ";".join(bundle.get("gaps", []) or ["partial"]))
            if not bundle["snippets"]:
                degraded.append("no_snippets")
            if preflight is not None and not preflight["passed"]:
                degraded.append("preflight_" + preflight["status"])
            unsupported = (
                preflight is None
                and not requirements(bundle["rule_id"], bundle_engine(bundle))["supported"]
            )
            state = "running"
            if degraded and not allow_degraded_evidence:
                state, reservation = "incomplete_evidence", 0
            elif unsupported and not allow_degraded_evidence:
                state, reservation = "unsupported_rule", 0
            elif not unmetered and spent + reservation > budget.limit_micro_usd:
                state, reservation = "budget_exhausted", 0
            identity = str(uuid4())
            result = {
                "schema_version": "1",
                "triage_id": identity,
                "run_id": run_id,
                "bundle_id": bundle_id,
                "candidate_fingerprint": bundle["candidate_fingerprint"],
                "request_sha256": digest,
                "prompt_version": PROMPT_VERSION,
                "gate_version": GATE_VERSION,
                "provider": config.provider,
                "model": config.model,
                "created_at": now(),
                "input_micro_usd_per_1k": config.input_micro_usd_per_1k,
                "output_micro_usd_per_1k": config.output_micro_usd_per_1k,
                "max_output_tokens": config.max_output_tokens,
                "classification": bundle["classification"],
                "config_sha256": hashlib.sha256(canonical(policy_identity)).hexdigest(),
                "adapter_identity": adapter.identity,
                "simulated": config.provider == "replay",
                "reserved_micro_usd": reservation,
                "estimated_input_tokens": estimated_input,
                "usage": None,
                "decision": None,
                "disposition": "abstain",
                "verified": False,
                "evidence_degraded": sorted(degraded),
                "unsupported_rule_accepted": bool(unsupported and allow_degraded_evidence),
                "metered": not unmetered,
            }
            if review_policy is not None:
                result.update(
                    review_policy=review_policy,
                    engine_id=bundle_engine(bundle),
                    review_preflight=preflight,
                )
            session.add(
                TriageCall(
                    id=identity,
                    run_id=run_id,
                    bundle_id=bundle_id,
                    request_key=key,
                    request_sha256=digest,
                    state=state,
                    created_at=result["created_at"],
                    charged_micro_usd=reservation,
                    result=result,
                )
            )
        if state != "running":
            return {**result, "state": state, "accounted_micro_usd": 0}
        charged = reservation
        try:
            reply = adapter.invoke(body)
            state = reply.status
            if reply.usage is not None:
                charged = cost_micro_usd(
                    reply.usage.input_tokens, reply.usage.output_tokens, config
                )
                result["usage"] = reply.usage.model_dump()
            if reply.status == "completed" and reply.decision is not None:
                decision = Decision.model_validate(reply.decision.model_dump())
                allowed = {snippet["id"] for snippet in bundle["snippets"]}
                if not set(decision.evidence_ids).issubset(allowed) or (
                    decision.verdict != "abstain" and not decision.evidence_ids
                ):
                    state = "invalid_citations"
                elif not decision.rationale.strip() or (
                    decision.verdict == "likely_false_positive"
                    and not decision.counterevidence.strip()
                ):
                    state = "invalid_rationale"
                else:
                    result.update(decision=decision.model_dump(), disposition=decision.verdict)
                    if review_policy is not None:
                        from veriflow.joern_claims import assess_review_evidence

                        gate = assess_review_evidence(bundle, decision, review_policy, store)
                    else:
                        gate = assess_evidence(bundle, decision)
                    result["evidence_gate"] = gate
                    if decision.verdict != "abstain" and not gate["passed"]:
                        # Keep the model's rationale for an operator; never treat it as verified.
                        state = "evidence_rejected"
                        result["disposition"] = "abstain"
                    if result["evidence_degraded"] and decision.verdict != "abstain":
                        state = "advisory_unverified"
                        result["disposition"] = "abstain"
            elif reply.status == "completed":
                state = "invalid_output"
            if charged > reservation:
                state = "reservation_exceeded"
                result["disposition"] = "abstain"
            if reply.usage is None:
                result["accounting_note"] = "Usage missing; full reservation retained"
        except (ValidationError, ValueError, TypeError, KeyError, AttributeError):
            state = "invalid_output"
        except (OSError, VeriFlowError, subprocess.SubprocessError):
            # Includes timeouts and ambiguous transport errors; do not retry or release.
            state = "unknown"
        with store.transaction() as session:
            call = session.get(TriageCall, identity)
            call.state, call.charged_micro_usd, call.result = state, charged, result
        return {**result, "state": state, "accounted_micro_usd": charged}
