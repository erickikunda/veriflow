"""Pipeline summaries rendered from published reports; candidates and advisories, never verdicts."""

import html
import json
from collections import Counter
from datetime import UTC, datetime

from veriflow.reports import markdown_cell

NOTICE = (
    "Candidates and advisory outcomes only. No entry is a confirmed vulnerability, "
    "and zero candidates is not a clean security result."
)
CATEGORIES = (
    (
        "needs_review",
        "The model advisory suggests operator review. It is a candidate, not a confirmed "
        "vulnerability.",
    ),
    (
        "likely_false_positive",
        "The model advisory leans false positive. The candidate is never dismissed and "
        "stays in every report.",
    ),
    (
        "abstain",
        "No usable advisory: a gate failed, evidence was incomplete, the rule is unsupported "
        "or the model abstained.",
    ),
    ("not_triaged", "No advisory call is recorded for this candidate."),
)
LIMITATIONS = (
    "Advisory outcomes are model suggestions; verified_finding_count stays null.",
    "Profiles without a reviewed evidence gate send ungated requests; those outcomes are "
    "unverified even when the model completes.",
    "Unmetered and degraded-evidence runs are named per call in each report's advisory_reductions.",
    "Each report covers one language/profile attempt; there is no cross-language flow.",
    "Accounted cost uses configured rates and is not a provider invoice.",
)
PROBLEM_STATUSES = {"scope_error", "scan_error", "scan_failed"}
# Triage states that carry no model answer; the candidate still needs an LLM pass.
NO_RESULT_STATES = {
    "unknown",
    "budget_exhausted",
    "request_limit_exhausted",
    "unsupported_rule",
    "incomplete_evidence",
    "running",
}
VERDICT_NOTE = (
    "Model verdict is the raw, unverified model answer. Without a reviewed gate, or when the "
    "gate rejects it, the advisory outcome stays abstain."
)


def usd(micro):
    return None if micro is None else f"{micro / 1_000_000:.4f}"


def repository_summary(state, options):
    findings, gaps, problems = [], [], []
    for entry in state["profiles"]:
        label = f"{entry['language']}/{entry['discovery_profile']}"
        status = entry.get("status")
        if status == "unsupported_language":
            gaps.append(f"{label}: no Joern discovery profile exists for this language")
        elif status in {"scope_error", "scan_error"}:
            problems.append(f"{label}: not scanned ({entry.get('error')})")
        elif status == "scan_failed":
            problems.append(f"{label}: scan ended {entry.get('analysis_status')}")
        if entry.get("export_error"):
            problems.append(f"{label}: report not published ({entry['export_error']})")
        if status == "scanned" and entry["review_policy"] is None and entry.get("candidate_count"):
            gaps.append(f"{label}: no reviewed evidence gate; advisory outcomes stay unverified")
        elif (entry.get("review_policy") or "").startswith("runtime-native-v1:") and entry.get(
            "candidate_count"
        ):
            gaps.append(
                f"{label}: default runtime gate; path consistency only, endpoint syntax unchecked"
            )
        triage = entry.get("triage") or {}
        if triage.get("status") in {"failed", "stopped", "not_started"}:
            problems.append(
                f"{label}: triage {triage['status']} "
                f"({triage.get('error') or triage.get('reason') or 'run stop state'})"
            )
        report = entry.get("report")
        verdicts = entry.get("model_verdicts") or {}
        for candidate in (report or {}).get("candidates", []):
            history = candidate["triage_history"]
            last = history[-1] if history else {}
            findings.append(
                {
                    "advisory": candidate["latest_advisory"],
                    "model_verdict": verdicts.get(candidate["fingerprint"]),
                    "triage_state": last.get("state", "not_triaged"),
                    "rule_id": candidate["rule_id"],
                    "cwe": candidate.get("cwe"),
                    "path": candidate.get("path"),
                    "line": candidate.get("line"),
                    "origin": candidate.get("origin"),
                    "language": entry["language"],
                    "discovery_profile": entry["discovery_profile"],
                    "review_gate": entry["review_policy"] or "none",
                    "evidence_degraded": bool(last.get("evidence_degraded")),
                    "simulated": candidate.get("latest_simulated"),
                    "fingerprint": candidate["fingerprint"],
                    "report_id": report["report_id"],
                    "verified": False,
                }
            )
    for item in state.get("discovery") or []:
        if item["state"] != "completed":
            problem = item["state"] in {"failed", "unknown", "invalid_output"}
            (problems if problem else gaps).append(
                f"LLM discovery {item['language']}: {item['state']}"
                + (f" ({item['reason']})" if item.get("reason") else "")
            )
        deferred = (item.get("selection") or {}).get("deferred_files")
        if deferred:
            gaps.append(f"LLM discovery {item['language']}: {deferred} eligible files not examined")
    unanswered = Counter(
        f["triage_state"]
        for f in findings
        if f["advisory"] == "not_triaged" or f["triage_state"] in NO_RESULT_STATES
    )
    if unanswered:
        problems.append(
            f"{sum(unanswered.values())} candidates have no model answer ("
            + ", ".join(f"{k}: {v}" for k, v in sorted(unanswered.items()))
            + "); rerun to resume, with --retry-unknown for unknown"
        )
    failure = state.get("failure")
    if failure:
        problems.append(f"Stopped at step {failure['step']}: {failure['error']}")
    ledger = state.get("ledger") or {}
    triage = state.get("triage") or {}
    discovery_calls = sum(item.get("live_model_calls", 0) for item in state.get("discovery") or [])
    stats = {
        "profiles_planned": len(state["profiles"]),
        "profiles_scanned": sum(1 for e in state["profiles"] if e.get("status") == "scanned"),
        "profiles_not_scanned": sum(
            1 for e in state["profiles"] if e.get("status") in PROBLEM_STATUSES
        ),
        "candidates": len(findings),
        "triaged": sum(1 for f in findings if f["advisory"] != "not_triaged"),
        "by_advisory": dict(Counter(f["advisory"] for f in findings)),
        "by_model_verdict": dict(Counter(f["model_verdict"] or "none" for f in findings)),
        "without_model_answer": sum(unanswered.values()),
        "by_triage_state": dict(Counter(f["triage_state"] for f in findings)),
        "by_origin": dict(Counter(f["origin"] or "unknown" for f in findings)),
        "ungated_candidates": sum(1 for f in findings if f["review_gate"] == "none"),
        # needs_review under the default runtime gate rests on path citation only.
        "needs_review_runtime_gate": sum(
            1
            for f in findings
            if f["advisory"] == "needs_review" and f["review_gate"].startswith("runtime-native-v1:")
        ),
        "provider_calls_this_run": triage.get("provider_calls", 0) + discovery_calls,
        "accounted_micro_usd": ledger.get("accounted_micro_usd"),
        "accounted_usd": usd(ledger.get("accounted_micro_usd")),
    }
    return {
        "schema_version": "1",
        "report_kind": "pipeline_repository_summary",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "status": "failed" if failure else "partial" if problems else "completed",
        "repo_id": state["repo_id"],
        "row_number": state["row_number"],
        "directory": state.get("directory"),
        "run_id": state["run_id"],
        "snapshot_id": state["snapshot_id"],
        "detected_languages": state["detected_languages"],
        "duration_seconds": state.get("duration_seconds"),
        "provider": options.config.provider,
        "model": options.config.model,
        "unmetered": options.unmetered,
        "degraded_evidence_allowed": options.allow_degraded_evidence,
        "llm_discovery": options.discovery is not None,
        "stats": stats,
        "profiles": [
            {
                key: entry.get(key)
                for key in (
                    "language",
                    "discovery_profile",
                    "profile_source",
                    "review_policy",
                    "status",
                    "action",
                    "attempt_id",
                    "analysis_status",
                    "candidate_count",
                    "report_id",
                    "error",
                )
            }
            | {"triage": entry.get("triage")}
            for entry in state["profiles"]
        ],
        "llm_discovery_passes": state.get("discovery"),
        "steps": state.get("steps", []),
        "findings": findings,
        "problems": problems,
        "coverage_gaps": gaps,
        "failure": failure,
        "verified_finding_count": None,
        "security_verdict": "not_adjudicated",
        "categories": [{"advisory": a, "description": d} for a, d in CATEGORIES],
        "model_verdict_note": VERDICT_NOTE,
        "limitations": list(LIMITATIONS),
    }


def run_summary(
    results,
    options,
    *,
    started_at,
    duration_seconds,
    manifest_name,
    provider_unavailable=False,
    profile_catalog=None,
):
    statuses = Counter(item["status"] for item in results)
    accounted = [item["stats"]["accounted_micro_usd"] for item in results]
    return {
        "schema_version": "1",
        "report_kind": "pipeline_run_summary",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "started_at": started_at,
        "duration_seconds": duration_seconds,
        "manifest": manifest_name,
        "status": "failed"
        if statuses["failed"]
        else "partial"
        if statuses["partial"]
        else "completed",
        "provider": options.config.provider,
        "model": options.config.model,
        "unmetered": options.unmetered,
        "degraded_evidence_allowed": options.allow_degraded_evidence,
        "llm_discovery": options.discovery is not None,
        "repository_statuses": dict(statuses),
        "provider_unavailable": provider_unavailable,
        "profile_catalog": profile_catalog,
        "totals": {
            "repositories": len(results),
            "candidates": sum(item["stats"]["candidates"] for item in results),
            "triaged": sum(item["stats"]["triaged"] for item in results),
            "by_advisory": dict(
                sum((Counter(item["stats"]["by_advisory"]) for item in results), Counter())
            ),
            "provider_calls_this_run": sum(
                item["stats"]["provider_calls_this_run"] for item in results
            ),
            "accounted_micro_usd": sum(a for a in accounted if a is not None),
        },
        "repositories": [
            {
                "repo_id": item["repo_id"],
                "status": item["status"],
                "run_id": item["run_id"],
                "detected_languages": item["detected_languages"],
                "candidates": item["stats"]["candidates"],
                "by_advisory": item["stats"]["by_advisory"],
                "problems": len(item["problems"]),
                "accounted_usd": item["stats"]["accounted_usd"],
                "failure": item["failure"],
            }
            for item in results
        ],
        "verified_finding_count": None,
        "security_verdict": "not_adjudicated",
        "categories": [{"advisory": a, "description": d} for a, d in CATEGORIES],
        "limitations": list(LIMITATIONS),
    }


def _sections(summary):
    yes = {True: "yes", False: "no"}
    settings = [
        ["Status", summary["status"]],
        ["Provider / model", f"{summary['provider']} / {summary['model']}"],
        ["Unmetered", yes[summary["unmetered"]]],
        ["Degraded evidence allowed", yes[summary["degraded_evidence_allowed"]]],
        ["LLM discovery", yes[summary["llm_discovery"]]],
        ["Duration (s)", summary["duration_seconds"]],
    ]
    legend = [[a, d] for a, d in CATEGORIES]
    if summary["report_kind"] == "pipeline_run_summary":
        totals = summary["totals"]
        settings[1:1] = [["Manifest", summary["manifest"]], ["Started", summary["started_at"]]]
        profile_catalog = summary.get("profile_catalog") or {}
        settings += [
            ["Profile mode", profile_catalog.get("mode", "trusted-directory")],
            ["Approved registry version", profile_catalog.get("registry_version", 0)],
            ["Runtime profiles", ", ".join(profile_catalog.get("runtime_profiles", [])) or "none"],
            ["Runtime profiles skipped", len(profile_catalog.get("problems", []))],
            [
                "Provider stopped after repeated unknown outcomes",
                yes[summary["provider_unavailable"]],
            ],
            ["Repositories", totals["repositories"]],
            ["Candidates", totals["candidates"]],
            ["Triaged", totals["triaged"]],
            ["Provider calls this run", totals["provider_calls_this_run"]],
            ["Accounted USD", usd(totals["accounted_micro_usd"])],
        ]
        repos = [
            [
                r["repo_id"],
                r["status"],
                ", ".join(r["detected_languages"]) or "none",
                r["candidates"],
                ", ".join(f"{k}: {v}" for k, v in sorted(r["by_advisory"].items())) or "none",
                r["problems"],
                r["accounted_usd"],
                (r["failure"] or {}).get("error"),
            ]
            for r in summary["repositories"]
        ]
        return "VeriFlow pipeline run summary", [
            ("Run", "table", (["Field", "Value"], settings)),
            (
                "Repositories",
                "table",
                (
                    [
                        "Repository",
                        "Status",
                        "Languages",
                        "Candidates",
                        "Advisory outcomes",
                        "Problems",
                        "Accounted USD",
                        "Failure",
                    ],
                    repos,
                ),
            ),
            ("Advisory categories", "table", (["Outcome", "Meaning"], legend)),
            ("Limitations", "list", summary["limitations"]),
        ]
    stats = summary["stats"]
    settings[1:1] = [
        ["Repository", summary["repo_id"]],
        ["Run", summary["run_id"]],
        ["Snapshot", summary["snapshot_id"]],
        ["Detected languages", ", ".join(summary["detected_languages"]) or "none"],
    ]
    settings += [
        [
            "Profiles planned / scanned / not scanned",
            "{} / {} / {}".format(
                stats["profiles_planned"], stats["profiles_scanned"], stats["profiles_not_scanned"]
            ),
        ],
        ["Candidates (triaged)", f"{stats['candidates']} ({stats['triaged']})"],
        ["Candidates without a reviewed gate", stats["ungated_candidates"]],
        ["needs_review under the default runtime gate", stats["needs_review_runtime_gate"]],
        ["Candidates without a model answer", stats["without_model_answer"]],
        [
            "Model verdicts (unverified)",
            ", ".join(f"{k}: {v}" for k, v in sorted(stats["by_model_verdict"].items())) or "none",
        ],
        ["Provider calls this run", stats["provider_calls_this_run"]],
        ["Accounted USD (run ledger)", stats["accounted_usd"]],
    ]
    sections = [("Overview", "table", (["Field", "Value"], settings))]
    for advisory, _ in CATEGORIES:
        rows = [
            [
                f["rule_id"],
                f["cwe"] or "unknown",
                f"{f['path']}:{f['line']}",
                f["origin"],
                f"{f['language']}/{f['discovery_profile']}",
                f["review_gate"],
                f["triage_state"],
                f["model_verdict"] or "none",
                yes[f["evidence_degraded"]],
            ]
            for f in summary["findings"]
            if f["advisory"] == advisory
        ]
        if rows:
            sections.append(
                (
                    f"Candidates: {advisory} ({len(rows)})",
                    "table",
                    (
                        [
                            "Rule",
                            "CWE",
                            "Location",
                            "Origin",
                            "Profile",
                            "Review gate",
                            "Triage state",
                            "Model verdict (unverified)",
                            "Degraded",
                        ],
                        rows,
                    ),
                )
            )
    profiles = [
        [
            p["language"],
            p["discovery_profile"],
            p["review_policy"] or "none",
            p["status"],
            p["action"],
            p["candidate_count"],
            (p["triage"] or {}).get("status", "not_needed"),
            p["report_id"] and p["report_id"][:16],
        ]
        for p in summary["profiles"]
    ]
    steps = [
        [s["step"], s["status"], s.get("duration_seconds"), s.get("error")]
        for s in summary["steps"]
    ]
    sections += [
        (
            "Discovery profiles",
            "table",
            (
                [
                    "Language",
                    "Profile",
                    "Review gate",
                    "Status",
                    "Action",
                    "Candidates",
                    "Triage",
                    "Report",
                ],
                profiles,
            ),
        ),
        ("Pipeline steps", "table", (["Step", "Status", "Seconds", "Error"], steps)),
        ("Problems", "list", summary["problems"] or ["none recorded"]),
        ("Coverage gaps", "list", summary["coverage_gaps"] or ["none recorded"]),
        ("Advisory categories", "table", (["Outcome", "Meaning"], legend)),
        ("Model verdict", "list", [summary["model_verdict_note"]]),
        ("Limitations", "list", summary["limitations"]),
    ]
    return f"VeriFlow pipeline summary: {summary['repo_id']}", sections


def render_markdown(summary):
    title, sections = _sections(summary)
    lines = [f"# {markdown_cell(title)}", "", f"**{NOTICE}**", ""]
    for heading, kind, payload in sections:
        lines += [f"## {markdown_cell(heading)}", ""]
        if kind == "list":
            lines += [f"- {markdown_cell(item)}" for item in payload]
        else:
            headers, rows = payload
            lines.append("| " + " | ".join(headers) + " |")
            lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
            lines += [
                "| " + " | ".join(markdown_cell("" if c is None else c) for c in row) + " |"
                for row in rows
            ]
        lines.append("")
    return "\n".join(lines)


def render_html(summary):
    title, sections = _sections(summary)
    body = []
    for heading, kind, payload in sections:
        body.append(f"<h2>{html.escape(heading)}</h2>")
        if kind == "list":
            body.append(
                "<ul>" + "".join(f"<li>{html.escape(str(i))}</li>" for i in payload) + "</ul>"
            )
            continue
        headers, rows = payload
        body.append(
            "<table><thead><tr>"
            + "".join(f"<th>{html.escape(h)}</th>" for h in headers)
            + "</tr></thead><tbody>"
            + "".join(
                "<tr>"
                + "".join(f"<td>{html.escape('' if c is None else str(c))}</td>" for c in row)
                + "</tr>"
                for row in rows
            )
            + "</tbody></table>"
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;">'
        f"<title>{html.escape(title)}</title><style>body{{font:15px system-ui;"
        "max-width:1200px;margin:2rem auto;padding:1rem}"
        "table{border-collapse:collapse;width:100%;margin-bottom:1rem}th,td{text-align:left;"
        "border-bottom:1px solid #ddd;padding:.5rem;overflow-wrap:anywhere}"
        ".notice{background:#fef3c7;padding:.75rem}</style>"
        f"<h1>{html.escape(title)}</h1><p class=notice><strong>{html.escape(NOTICE)}</strong></p>"
        + "".join(body)
        + "</html>"
    )


def write_summary(stem, summary):
    stem.with_suffix(".json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    stem.with_suffix(".md").write_text(render_markdown(summary), encoding="utf-8")
    stem.with_suffix(".html").write_text(render_html(summary), encoding="utf-8")
