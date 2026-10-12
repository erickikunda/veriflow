"""Local scan orchestration with explicit, bounded Joern advisory opt-in."""

from sqlalchemy import func, select

from veriflow.codeql_resources import resource_settings
from veriflow.csharp_dependencies import load_profile
from veriflow.domain import VeriFlowError
from veriflow.indexing import build_index, verified_source
from veriflow.java_dependencies import load_java_profile
from veriflow.java_index import build_java_index
from veriflow.languages import (
    adapter_for,
    select_language,
    validate_extraction_scope,
    validate_selection,
)
from veriflow.network_isolation import MODE, validate_offline
from veriflow.persistence import Run, ScanAttempt, exclusive_worker
from veriflow.reports import publish_report
from veriflow.scanner_backends import backend_for
from veriflow.scanning import analyze, query_entry


def _deterministic_scan_run(
    store,
    run_id,
    queries=None,
    extraction_timeout=300,
    query_timeout=600,
    *,
    skip_existing=False,
    threads=2,
    ram_mb=2048,
    language="python",
    java_profile="dependency-free",
    java_dependency_profile=None,
    allow_csharp_downloads=False,
    csharp_dependency_profile=None,
    csharp_offline=False,
    engine="codeql",
    joern_home=None,
    joern_repair_dir=None,
    rust_home=None,
    joern_profile=None,
    advisory=None,
):
    if engine == "joern":
        from veriflow import joern_pipeline

        joern_pipeline.validate_options(
            queries,
            language,
            joern_home,
            threads,
            ram_mb,
            java_profile=java_profile,
            java_dependency_profile=java_dependency_profile,
            allow_csharp_downloads=allow_csharp_downloads,
            csharp_dependency_profile=csharp_dependency_profile,
            csharp_offline=csharp_offline,
        )
        if not 1 <= extraction_timeout <= 3600 or not 1 <= query_timeout <= 3600:
            raise VeriFlowError("Stage timeouts must be between 1 and 3600 seconds")
        return joern_pipeline.scan_run(
            store,
            run_id,
            language,
            joern_home,
            joern_repair_dir,
            rust_home,
            extraction_timeout,
            query_timeout,
            skip_existing,
            joern_profile,
            advisory=advisory,
        )
    if advisory is not None:
        raise VeriFlowError("Scan advisory options require engine joern")
    if any(x is not None for x in (joern_home, joern_repair_dir, rust_home, joern_profile)):
        raise VeriFlowError("Joern tooling options require engine joern")
    if queries is None:
        raise VeriFlowError("CodeQL requires the queries argument")
    backend = backend_for(engine)
    resources = resource_settings(threads, ram_mb)
    validate_selection(language, java_profile)
    requested_language = language
    if not 1 <= extraction_timeout <= 3600 or not 1 <= query_timeout <= 3600:
        raise VeriFlowError("Stage timeouts must be between 1 and 3600 seconds")
    store.require_initialized()
    query = query_entry(store, queries)
    with exclusive_worker(store.root):
        if language == "auto":
            _, manifest, _ = verified_source(store, run_id)
            language = select_language(manifest, language)
            validate_selection(language, java_profile)
        validate_offline(
            language, csharp_dependency_profile, allow_csharp_downloads, csharp_offline
        )
        if java_dependency_profile is not None and language != "java":
            raise VeriFlowError("Java dependency profiles require java")
        java_dependency_id = (
            load_java_profile(java_dependency_profile)["id"] if java_dependency_profile else ""
        )
        dependency_id = None
        if csharp_dependency_profile is not None:
            if language != "csharp":
                raise VeriFlowError("C# dependency profiles require csharp")
            dependency_id = load_profile(csharp_dependency_profile)["id"]
        with store.transaction() as session:
            run = session.get(Run, run_id)
            if run is None:
                raise VeriFlowError("Run not found")
            repo_id = run.repo_id
            if skip_existing:
                previous = session.scalar(
                    select(ScanAttempt)
                    .where(
                        ScanAttempt.run_id == run_id,
                        func.coalesce(
                            ScanAttempt.report["scanner"]["engine_id"].as_string(), "codeql"
                        )
                        == backend.engine_id,
                        func.coalesce(
                            ScanAttempt.report["language_scope"]["java_dependency_profile"][
                                "id"
                            ].as_string(),
                            "",
                        )
                        == java_dependency_id,
                        func.coalesce(
                            ScanAttempt.report["language_scope"]["network_isolation"].as_string(),
                            "none",
                        )
                        == (MODE if csharp_offline else "none"),
                        func.coalesce(
                            ScanAttempt.report["language_scope"]["dependency_profile"][
                                "id"
                            ].as_string(),
                            "",
                        )
                        == (dependency_id or ""),
                        func.coalesce(ScanAttempt.report["language"].as_string(), "python")
                        == language,
                        func.coalesce(
                            ScanAttempt.report["language_scope"]["adapter_profile"].as_string(),
                            adapter_for(language).profile,
                        )
                        == (
                            f"java-{java_profile}-v1"
                            if language == "java"
                            else adapter_for(language).profile
                        ),
                    )
                    .order_by(ScanAttempt.created_at.desc(), ScanAttempt.id.desc())
                    .limit(1)
                )
                if previous is not None:
                    return {
                        "schema_version": "1",
                        "language": language,
                        "requested_language": requested_language,
                        "repo_id": repo_id,
                        "run_id": run_id,
                        "status": "skipped_existing_attempt",
                        "attempt_id": previous.id,
                        "analysis_status": previous.report.get("status", "unknown"),
                        "report_id": None,
                        "model_calls": 0,
                        "reason": "Existing attempt retained; use explicit rescan to run again",
                    }
        result = {
            "schema_version": "1",
            "repo_id": repo_id,
            "run_id": run_id,
            "status": "blocked",
            "stopped_after": "index",
            "extraction_id": None,
            "attempt_id": None,
            "report_id": None,
            "model_calls": 0,
            "security_completion_verified": False,
            "language": language,
            "requested_language": requested_language,
        }
        if language == "python":
            index = build_index(store, run_id)
            result["python_index_gate"] = index["python_index_gate"]
            if index["python_index_gate"] != "ready":
                return {**result, "reason": "Python index is not ready; inspect repo-report"}
        else:
            _, manifest, _ = verified_source(store, run_id)
            result["language_scope"] = validate_extraction_scope(manifest, language, java_profile)
            if language == "java":
                result["java_syntax_index"] = build_java_index(store, run_id)
                if result["java_syntax_index"]["syntax_gate"] != "ready":
                    return {**result, "reason": "Java syntax index is blocked"}
        extraction = backend.prepare(
            store,
            run_id,
            timeout=extraction_timeout,
            language=requested_language,
            java_profile=java_profile,
            java_dependency_profile=java_dependency_profile,
            allow_csharp_downloads=allow_csharp_downloads,
            csharp_dependency_profile=csharp_dependency_profile,
            csharp_offline=csharp_offline,
            **resources,
        )
        result.update(
            extraction_id=extraction["attempt_id"],
            stopped_after="extraction",
            extraction_status=extraction["status"],
        )
        if extraction["status"] != "extracted":
            return {**result, "reason": "Extraction did not succeed; inspect codeql-status"}
        scan = analyze(store, extraction["attempt_id"], query, timeout=query_timeout, **resources)
        result.update(attempt_id=scan["attempt_id"], analysis_status=scan["status"])
    # Publication owns its own lock. Pin the attempt even if other work starts between stages.
    report = publish_report(store, repo_id, run_id, scan["attempt_id"])
    ready = report["static_review_readiness"]["state"] == "ready_for_review"
    return {
        **result,
        "status": "ready_for_review" if ready else "incomplete",
        "stopped_after": "publication",
        "report_id": report["report_id"],
        "candidate_count": report["candidate_count"],
        "reason": "Static review readiness only; not a clean security verdict",
    }


def scan_run(store, run_id, *args, llm_discovery=None, **kwargs):
    """Run deterministic discovery first, then optional additive LLM exploration."""
    result = _deterministic_scan_run(store, run_id, *args, **kwargs)
    if llm_discovery is None:
        return result
    if "items" in result:
        return _selected_discovery(store, run_id, result, llm_discovery)
    attempt_id = result.get("attempt_id")
    if not attempt_id:
        return {
            **result,
            "llm_discovery": {
                "state": "skipped_deterministic_incomplete",
                "provider_invocations": 0,
                "live_model_calls": 0,
            },
            "hybrid_status": "partial",
        }
    from veriflow.llm_discovery import run_hybrid_discovery

    try:
        discovery = run_hybrid_discovery(store, attempt_id, llm_discovery)
    except VeriFlowError as exc:
        return {
            **result,
            "llm_discovery": {
                "state": "failed",
                "reason": str(exc),
                "provider_invocations": 0,
                "live_model_calls": 0,
            },
            "hybrid_status": "partial",
        }
    refreshed = publish_report(store, result["repo_id"], run_id, attempt_id)
    return {
        **result,
        "model_calls": result.get("model_calls", 0) + discovery["provider_invocations"],
        "live_model_calls": result.get("live_model_calls", 0) + discovery["live_model_calls"],
        "report_id": refreshed["report_id"],
        "candidate_count": refreshed["candidate_count"],
        "llm_discovery": discovery,
        "hybrid_status": "completed" if discovery["state"] == "completed" else "partial",
    }


def discovery_anchor(items, language):
    """First usable attempt of one language; LLM candidates attach to it, not to every profile."""
    return next(
        (
            item
            for item in items
            if item.get("language") == language
            and item.get("attempt_id")
            and item.get("analysis_status") in {"partial", "completed"}
        ),
        None,
    )


def _selected_discovery(store, run_id, result, options):
    """Run one additive LLM pass per detected language after automatic profile selection."""
    from dataclasses import replace

    from veriflow.llm_discovery import DISCOVERY_SUFFIXES, run_hybrid_discovery

    items = [dict(item) for item in result["items"]]
    passes = []
    # Only languages this selection scanned; detected but unrequested ones are not gaps here.
    for language in dict.fromkeys(item["language"] for item in items):
        entry = {"language": language, "provider_invocations": 0, "live_model_calls": 0}
        anchor = discovery_anchor(items, language)
        if language not in DISCOVERY_SUFFIXES:
            passes.append({**entry, "state": "unsupported_language"})
            continue
        if anchor is None:
            passes.append({**entry, "state": "skipped_deterministic_incomplete"})
            continue
        entry.update(attempt_id=anchor["attempt_id"], discovery_profile=anchor["discovery_profile"])
        try:
            discovery = run_hybrid_discovery(
                store,
                anchor["attempt_id"],
                replace(options, request_key=f"{options.request_key}:{language}"),
            )
        except VeriFlowError as exc:
            passes.append({**entry, "state": "failed", "reason": str(exc)})
            continue
        refreshed = publish_report(store, result["repo_id"], run_id, anchor["attempt_id"])
        anchor.update(
            report_id=refreshed["report_id"], candidate_count=refreshed["candidate_count"]
        )
        passes.append({**entry, **discovery})
    invocations = sum(item["provider_invocations"] for item in passes)
    return {
        **result,
        "items": items,
        "report_ids": [item["report_id"] for item in items if item.get("report_id")],
        "model_calls": result.get("model_calls", 0) + invocations,
        "live_model_calls": result.get("live_model_calls", 0)
        + sum(item["live_model_calls"] for item in passes),
        "llm_discovery": {"passes": passes, "provider_invocations": invocations},
        "hybrid_status": (
            "completed" if passes and all(p["state"] == "completed" for p in passes) else "partial"
        ),
    }
