"""Deterministic, sequential discovery selection; inventory is not coverage."""

from pathlib import Path

from veriflow import joern_profiles
from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.languages import EXTENSIONS

# Language -> ordered profiles for --joern-profile auto, from the profile catalog.
PROFILES = joern_profiles.auto_plan()
EXTENSIONS = {**EXTENSIONS, ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp"}


def plan_for(store=None):
    """Packaged automatic plan, then active runtime profiles marked auto, per language."""
    plan = {language: list(profiles) for language, profiles in PROFILES.items()}
    for language, profiles in joern_profiles.auto_plan(store, runtime_only=True).items():
        plan.setdefault(language, []).extend(profiles)
    return plan


def selection(manifest, requested="auto", store=None):
    detected = sorted(
        {
            EXTENSIONS[Path(f.path).suffix.lower()]
            for f in manifest.files
            if Path(f.path).suffix.lower() in EXTENSIONS
        }
    )
    languages = detected if requested == "auto" else [requested]
    if not languages:
        raise VeriFlowError(
            "No recognized source language; select --language explicitly for header-only C"
        )
    plan = plan_for(store)
    return detected, [
        (language, profile) for language in languages for profile in plan.get(language, (None,))
    ]


def scan_selected(
    store,
    run_id,
    language,
    joern_home,
    repair_dir,
    rust_home,
    extraction_timeout,
    query_timeout,
    skip_existing=False,
    *,
    advisory=None,
):
    from veriflow.joern_pipeline import scan_run
    from veriflow.scan_advisory import AUTO_POLICY

    if advisory is not None and advisory.review_policy != AUTO_POLICY:
        raise VeriFlowError(
            "Automatic profile selection requires --review-policy auto; "
            "an explicit policy needs an explicit --joern-profile"
        )
    run, manifest, _ = verified_source(store, run_id)
    detected, plan = selection(manifest, language, store)
    items = []
    for selected, profile in plan:
        item = {"language": selected, "discovery_profile": profile or "default"}
        if selected not in joern_profiles.LANGUAGES:
            items.append({**item, "status": "unsupported_language", "report_id": None})
            continue
        try:
            result = scan_run(
                store,
                run_id,
                selected,
                joern_home,
                repair_dir,
                rust_home,
                extraction_timeout,
                query_timeout,
                skip_existing,
                profile,
                advisory=None
                if advisory is None
                else advisory.for_profile(selected, profile, store),
            )
        except VeriFlowError as exc:
            result = {"status": "scope_error", "error": str(exc), "report_id": None}
        items.append({**result, **item})
    model_calls = sum(item.get("model_calls", 0) for item in items)
    return {
        "schema_version": "1",
        "engine": "joern",
        "repo_id": run.repo_id,
        "run_id": run_id,
        "requested_language": language,
        "selection_policy": "all-bounded-profiles-v1",
        "detected_languages": detected,
        "items": items,
        "report_id": None,
        "report_ids": [item["report_id"] for item in items if item.get("report_id")],
        "status": "incomplete",
        "model_calls": model_calls,
        "live_model_calls": sum(item.get("live_model_calls", 0) for item in items),
        "security_completion_verified": False,
        "scope": (
            "Separate per-language/profile reports; no cross-language flow or clean verdict. "
            "Unknown file extensions are not detected; "
            "profile extraction limitations remain applicable."
        ),
    }
