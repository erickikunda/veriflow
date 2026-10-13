"""Explicit main-workflow routing to bounded Joern discovery profiles."""

from pathlib import Path

from sqlalchemy import func, select

from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.joern import SUFFIXES, discover
from veriflow.languages import EXTENSIONS
from veriflow.persistence import ScanAttempt
from veriflow.reports import publish_report


def validate_options(queries, language, joern_home, threads, ram_mb, **options):
    if queries is not None:
        raise VeriFlowError("Joern uses packaged profiles; omit the CodeQL queries argument")
    if language != "auto" and language not in SUFFIXES:
        raise VeriFlowError("Unsupported Joern language")
    if joern_home is None:
        raise VeriFlowError("Joern requires --joern-home")
    if threads != 2 or ram_mb != 2048:
        raise VeriFlowError("Joern profiles currently require default threads/ram options")
    if options.get("java_profile", "dependency-free") != "dependency-free" or any(
        options.get(key)
        for key in (
            "java_dependency_profile",
            "allow_csharp_downloads",
            "csharp_dependency_profile",
            "csharp_offline",
        )
    ):
        raise VeriFlowError("CodeQL preparation options do not apply to Joern")


def selected_language(manifest, requested):
    if requested != "auto":
        return requested
    extensions = {**EXTENSIONS, ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp"}
    detected = {extensions.get(Path(f.path).suffix.lower()) for f in manifest.files} - {None}
    if len(detected) != 1 or not detected.issubset(SUFFIXES):
        raise VeriFlowError("Joern auto requires one supported source language; select explicitly")
    return next(iter(detected))


def scan_run(
    store,
    run_id,
    language,
    joern_home,
    repair_dir,
    rust_home,
    extraction_timeout,
    query_timeout,
    skip_existing=False,
    discovery_profile=None,
    *,
    advisory=None,
):
    if discovery_profile == "auto":
        from veriflow.joern_selection import scan_selected

        return scan_selected(
            store,
            run_id,
            language,
            joern_home,
            repair_dir,
            rust_home,
            extraction_timeout,
            query_timeout,
            skip_existing,
            advisory=advisory,
        )
    if discovery_profile == "default":
        discovery_profile = None
    run, manifest, _ = verified_source(store, run_id)
    requested = language
    language = selected_language(manifest, requested)
    if advisory is not None:
        advisory = advisory.for_profile(language, discovery_profile, store)
        advisory.validate_scope(language, discovery_profile, store)
    if language == "csharp" and repair_dir is None:
        raise VeriFlowError("C# Joern requires --joern-repair-dir")
    if language == "rust" and rust_home is None:
        raise VeriFlowError("Rust Joern requires --rust-home")
    result = {
        "schema_version": "1",
        "engine": "joern",
        "repo_id": run.repo_id,
        "run_id": run_id,
        "language": language,
        "requested_language": requested,
        "extraction_id": None,
        "report_id": None,
        "model_calls": 0,
        "security_completion_verified": False,
    }
    if skip_existing:
        from veriflow.joern_profiles import binding

        # An attempt made with a different query text is not a result of this profile.
        digest = binding(language, discovery_profile, store).query_sha256
        with store.transaction() as session:
            previous = session.scalar(
                select(ScanAttempt)
                .where(
                    ScanAttempt.run_id == run_id,
                    ScanAttempt.report["scanner"]["engine_id"].as_string() == "joern",
                    ScanAttempt.report["language"].as_string() == language,
                    func.coalesce(ScanAttempt.report["discovery_profile"].as_string(), "default")
                    == (discovery_profile or "default"),
                    ScanAttempt.report["query_sha256"].as_string() == digest,
                )
                .order_by(ScanAttempt.created_at.desc(), ScanAttempt.id.desc())
                .limit(1)
            )
            if previous is not None:
                return {
                    **result,
                    "status": "skipped_existing_attempt",
                    "attempt_id": previous.id,
                    "analysis_status": previous.report.get("status", "unknown"),
                    "reason": (
                        "Retry suppression; use triage-attempt for existing advisory work"
                        if advisory is not None
                        else "Retry suppression; --rescan after failure or tooling changes"
                    ),
                    **(
                        {
                            "advisory": {
                                "status": "skipped_existing_attempt",
                                "review_policy": advisory.review_policy,
                            }
                        }
                        if advisory is not None
                        else {}
                    ),
                }
    if advisory is not None:
        advisory.validate_budget(store, run_id)
    scan = discover(
        store,
        run_id,
        joern_home,
        timeout=query_timeout,
        language=language,
        repair_dir=repair_dir if language == "csharp" else None,
        rust_home=rust_home if language == "rust" else None,
        extraction_timeout=extraction_timeout,
        discovery_profile=discovery_profile,
    )
    report = publish_report(store, run.repo_id, run_id, scan["attempt_id"])
    if advisory is not None:
        from veriflow.scan_advisory import run_advisory

        if scan["status"] == "partial":
            advice = run_advisory(store, run.repo_id, scan["attempt_id"], advisory)
            report = publish_report(store, run.repo_id, run_id, scan["attempt_id"])
        else:
            advice = {
                "status": "skipped_analysis_failed",
                "review_policy": advisory.review_policy,
                "provider_invocations": 0,
                "live_model_calls": 0,
            }
        result.update(
            advisory=advice,
            model_calls=advice["provider_invocations"],
            live_model_calls=advice["live_model_calls"],
        )

    return {
        **result,
        "status": "incomplete",
        "stopped_after": "publication",
        "attempt_id": scan["attempt_id"],
        "analysis_status": scan["status"],
        "report_id": report["report_id"],
        "candidate_count": report["candidate_count"],
        "reason": (
            "Explicit advisory page processed; inspect advisory status; no clean verdict"
            if advisory is not None
            else "Bounded Joern discovery only; no qualified triage or clean verdict"
        ),
    }
