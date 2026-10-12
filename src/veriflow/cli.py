"""Local operator CLI. JSON or requested Markdown; errors never echo source contents."""

from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy.exc import SQLAlchemyError

from veriflow.artifacts import ArtifactStore
from veriflow.domain import VeriFlowError
from veriflow.indexing import (
    build_index,
    compare_indexes,
    query_index,
    report_markdown,
    repository_report,
)
from veriflow.intake import import_status, process, render_json, run_status, submit
from veriflow.persistence import Store, exclusive_worker

app = typer.Typer(no_args_is_help=True, help="VeriFlow — local intake and security scan coverage")


@app.callback()
def configure(
    ctx: typer.Context,
    state_dir: Annotated[
        Path, typer.Option(help="Local state directory; never use shared network storage")
    ] = Path(".veriflow"),
):
    ctx.obj = Store(state_dir)
    ctx.call_on_close(ctx.obj.close)


def perform(operation):
    try:
        result = operation()
        if isinstance(result, bytes):
            typer.echo(result, nl=False)
        else:
            typer.echo(result if isinstance(result, str) else render_json(result))
    except VeriFlowError as exc:
        typer.echo(render_json({"error": str(exc)}), err=True)
        raise typer.Exit(1) from exc
    except (OSError, SQLAlchemyError):
        typer.echo(
            render_json(
                {"error": "Local storage operation failed; check paths and initialization"}
            ),
            err=True,
        )
        raise typer.Exit(1) from None


@app.command()
def init(ctx: typer.Context):
    """Initialize or upgrade the local SQLite schema."""

    def operation():
        ctx.obj.initialize()
        return {"state_dir": str(ctx.obj.root), "schema": "0011", "status": "initialized"}

    perform(operation)


@app.command("index-run")
def index_run(
    ctx: typer.Context,
    run_id: str,
    backend: Annotated[str, typer.Option(help="Inventory backend: syntax or joern")] = "syntax",
    joern_home: Annotated[Path | None, typer.Option(help="Pinned Joern CLI directory")] = None,
    timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300,
):
    """Build a selected Python inventory backend; no vulnerability discovery."""

    def operation():
        ctx.obj.require_initialized()
        with exclusive_worker(ctx.obj.root):
            return build_index(ctx.obj, run_id, backend, joern_home, timeout)

    perform(operation)


@app.command("compare-indexes")
def compare_indexes_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Annotated[Path, typer.Option(help="Pinned Joern CLI directory")],
    timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300,
):
    """Compare syntax and Joern Python inventories from the exact same snapshot."""

    def operation():
        ctx.obj.require_initialized()
        with exclusive_worker(ctx.obj.root):
            return compare_indexes(ctx.obj, run_id, joern_home, timeout)

    perform(operation)


@app.command("doctor")
def doctor_command(ctx: typer.Context, query: Path | None = None):
    """Inspect local prerequisites without running tools, migrations, scans or models."""
    from veriflow.doctor import diagnose

    def operation():
        result = diagnose(ctx.obj, query)
        if result["status"] == "blocked":
            typer.echo(render_json(result))
            raise typer.Exit(1)
        return result

    perform(operation)


@app.command("record-review")
def record_review_command(
    ctx: typer.Context, repo_id: str, attempt_id: str, fingerprint: str, request: Path, key: str
):
    """Append an explicit operator assertion against exact candidate evidence."""
    from veriflow.reviews import read_review, record_review

    perform(
        lambda: record_review(ctx.obj, repo_id, attempt_id, fingerprint, read_review(request), key)
    )


@app.command("review-history")
def review_history_command(
    ctx: typer.Context,
    repo_id: str,
    attempt_id: str,
    fingerprint: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Retrieve operator notes and revision without running analysis."""
    from veriflow.reviews import review_history

    perform(lambda: review_history(ctx.obj, repo_id, attempt_id, fingerprint, offset, limit))


@app.command("create-rule-draft")
def create_rule_draft_command(
    ctx: typer.Context, repo_id: str, attempt_id: str, fingerprint: str, request: Path
):
    """Capture a tested rule proposal for a confirmed LLM-origin candidate."""
    from veriflow.rule_registry import create_rule_draft, read_draft_request

    perform(
        lambda: create_rule_draft(
            ctx.obj, repo_id, attempt_id, fingerprint, read_draft_request(request)
        )
    )


@app.command("rule-draft-status")
def rule_draft_status_command(ctx: typer.Context, draft_id: str):
    """Retrieve and integrity-check one immutable rule draft."""
    from veriflow.rule_registry import rule_draft_status

    perform(lambda: rule_draft_status(ctx.obj, draft_id))


@app.command("approve-rule-draft")
def approve_rule_draft_command(ctx: typer.Context, draft_id: str, approval: Path, key: str):
    """Approve one tested draft into the next immutable registry version."""
    from veriflow.rule_registry import approve_rule_draft, read_approval_request

    perform(lambda: approve_rule_draft(ctx.obj, draft_id, read_approval_request(approval), key))


@app.command("approve-rule-drafts")
def approve_rule_drafts_command(ctx: typer.Context, manifest: Path):
    """Process a bounded CSV of independent rule approvals."""
    from veriflow.rule_registry import approve_rule_drafts

    perform(lambda: approve_rule_drafts(ctx.obj, manifest))


@app.command("rule-registry")
def rule_registry_command(ctx: typer.Context, version: int | None = None):
    """Retrieve the latest or an exact approved-rule registry version."""
    from veriflow.rule_registry import registry_status

    perform(lambda: registry_status(ctx.obj, version))


@app.command("acceptance-run")
def acceptance_run_command(
    output_dir: Path, query: Path, timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300
):
    """Run real CodeQL on isolated synthetic fixtures; no paid model calls."""
    from veriflow.acceptance import run_acceptance

    def operation():
        result = run_acceptance(output_dir, query, timeout)
        if not result["passed"]:
            typer.echo(render_json(result))
            raise typer.Exit(1)
        return result

    perform(operation)


@app.command("benchmark-schema")
def benchmark_schema_command():
    """Print the separate manifest and evaluator-label JSON schemas."""
    from veriflow.benchmark import BenchmarkLabels, BenchmarkManifest
    from veriflow.evaluation import EvaluationPlan

    perform(
        lambda: {
            "manifest": BenchmarkManifest.model_json_schema(),
            "labels": BenchmarkLabels.model_json_schema(),
            "evaluation_plan": EvaluationPlan.model_json_schema(),
        }
    )


@app.command("benchmark-evaluate")
def benchmark_evaluate_command(
    ctx: typer.Context, manifest: Path, labels: Path, plan: Path, format: str = "json"
):
    """Compare stored reports to evaluator-only labels without running scans."""
    from veriflow.evaluation import evaluate_benchmark, render_scorecard

    perform(lambda: render_scorecard(evaluate_benchmark(ctx.obj, manifest, labels, plan), format))


@app.command("benchmark-check")
def benchmark_check_command(
    ctx: typer.Context,
    manifest: Path,
    labels: Path | None = None,
    check_local_snapshots: bool = False,
):
    """Validate evaluator contracts; never dispatch scans or pass labels to models."""
    from veriflow.benchmark import check_benchmark

    def operation():
        result = check_benchmark(manifest, labels, ctx.obj if check_local_snapshots else None)
        if result["status"] != "valid_contract":
            typer.echo(render_json(result))
            raise typer.Exit(1)
        return result

    perform(operation)


@app.command("benchmark-publish")
def benchmark_publish_command(ctx: typer.Context, manifest: Path, labels: Path, plan: Path):
    """Evaluate pinned inputs and persist an immutable scorecard; no scans or model calls."""
    from veriflow.scorecards import publish_scorecard

    perform(lambda: publish_scorecard(ctx.obj, manifest, labels, plan))


@app.command("benchmark-get")
def benchmark_get_command(
    ctx: typer.Context, dataset_id: str, scorecard_id: str, format: str = "json"
):
    """Retrieve an exact stored scorecard without reading labels or reevaluating."""
    from veriflow.evaluation import render_scorecard
    from veriflow.scorecards import get_scorecard

    perform(lambda: render_scorecard(get_scorecard(ctx.obj, dataset_id, scorecard_id), format))


@app.command("benchmark-history")
def benchmark_history_command(
    ctx: typer.Context,
    dataset_id: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """List stored scorecard IDs for a dataset; does not evaluate or run scans."""
    from veriflow.scorecards import scorecard_history

    perform(lambda: scorecard_history(ctx.obj, dataset_id, offset, limit))


@app.command("benchmark-compare")
def benchmark_compare_command(
    ctx: typer.Context, dataset_id: str, baseline_id: str, current_id: str, format: str = "json"
):
    """Compare two exact saved scorecards with explicit comparability gates."""
    from veriflow.benchmark_comparison import compare_scorecards, render_comparison

    perform(
        lambda: render_comparison(
            compare_scorecards(ctx.obj, dataset_id, baseline_id, current_id), format
        )
    )


@app.command("publish-report")
def publish_report_command(
    ctx: typer.Context, repo_id: str, run_id: str | None = None, attempt_id: str | None = None
):
    """Materialize an immutable summary from stored state; no analysis or model calls."""
    from veriflow.reports import publish_report

    perform(lambda: publish_report(ctx.obj, repo_id, run_id, attempt_id))


@app.command("get-report")
def get_report_command(
    ctx: typer.Context,
    repo_id: str,
    report_id: str | None = None,
    run_id: str | None = None,
    format: str = "json",
):
    """Retrieve an exact report or the latest published version of the selected run."""
    from veriflow.reports import get_report, render_report

    perform(lambda: render_report(get_report(ctx.obj, repo_id, report_id, run_id), format))


@app.command("get-sarif")
def get_sarif_command(ctx: typer.Context, repo_id: str, attempt_id: str):
    """Export original verified SARIF bytes for an exact attempt; may contain sensitive detail."""
    from veriflow.sarif_export import get_sarif

    perform(lambda: get_sarif(ctx.obj, repo_id, attempt_id))


@app.command("get-sbom")
def get_sbom_command(
    ctx: typer.Context,
    repo_id: str,
    snapshot_id: str,
    verify: bool = False,
    packages: bool = False,
    database: Path | None = None,
    usage: bool = False,
    cache: bool = False,
    refresh_cache: bool = False,
):
    """Export a CycloneDX inventory; --packages adds candidates, --database adds OSV candidates."""
    from veriflow.sbom_export import export_sbom

    perform(
        lambda: export_sbom(
            ctx.obj, repo_id, snapshot_id, verify, packages, database, usage, cache, refresh_cache
        )
    )


@app.command("acquire-osv")
def acquire_osv_command(
    ctx: typer.Context,
    base_url: str,
    output: Path,
    ecosystem: Annotated[list[str], typer.Option()],
    allowed_host: Annotated[list[str], typer.Option()],
    expected_sha256: Annotated[list[str] | None, typer.Option()] = None,
    allow_unpinned: bool = False,
    ca_bundle: Path | None = None,
    proxy: str | None = None,
    timeout: Annotated[int, typer.Option(min=1, max=900)] = 300,
):
    """Fetch and pin an OSV export over HTTPS; this is the only networked OSV step."""
    from veriflow.osv_acquisition import acquire_osv
    from veriflow.osv_reader import OSVReader

    def run():
        digests = {}
        for item in expected_sha256 or []:
            name, separator, value = item.partition("=")
            if not separator:
                raise VeriFlowError("Expected digests use ECOSYSTEM=SHA256")
            digests[name] = value
        return acquire_osv(
            OSVReader(ca_bundle=ca_bundle, proxy=proxy, timeout=timeout),
            base_url=base_url,
            ecosystems=ecosystem,
            allowed_hosts=allowed_host,
            output=output,
            expected_sha256=digests,
            allow_unpinned=allow_unpinned,
        )

    perform(run)


@app.command("get-osv")
def get_osv_command(
    ctx: typer.Context,
    repo_id: str,
    snapshot_id: str,
    database: Path,
    verify: bool = False,
    usage: bool = False,
    cache: bool = False,
    refresh_cache: bool = False,
):
    """Match declared packages against a pinned OSV export; matches are candidates, not verdicts."""
    from veriflow.osv_export import export_osv

    perform(
        lambda: export_osv(
            ctx.obj, repo_id, snapshot_id, database, verify, usage, cache, refresh_cache
        )
    )


@app.command("report-history")
def report_history_command(
    ctx: typer.Context,
    repo_id: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """List published report IDs without running analysis."""
    from veriflow.reports import report_history

    perform(lambda: report_history(ctx.obj, repo_id, offset, limit))


@app.command("resolve-report")
def resolve_report_command(ctx: typer.Context, repo_id: str, selection: str = "latest-attempt"):
    """Select a published report with current-work disclosure in a JSON envelope."""
    from veriflow.reports import resolve_report

    perform(lambda: resolve_report(ctx.obj, repo_id, selection))


@app.command("import-reports")
def import_reports_command(
    ctx: typer.Context,
    import_id: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
    format: str = "json",
):
    """Inventory report availability for admitted import runs, without starting work."""
    from veriflow.batch_reports import import_reports, render_import_reports

    perform(
        lambda: render_import_reports(import_reports(ctx.obj, import_id, offset, limit), format)
    )


@app.command("compare-reports")
def compare_reports_command(
    ctx: typer.Context, repo_id: str, baseline_id: str, current_id: str, format: str = "json"
):
    """Compare two exact reports without inferring fixes from missing observations."""
    from veriflow.comparison import compare_reports, render_comparison

    perform(
        lambda: render_comparison(
            compare_reports(ctx.obj, repo_id, baseline_id, current_id), format
        )
    )


@app.command("query-index")
def index_query(
    ctx: typer.Context,
    run_id: str,
    kind: str = "symbols",
    path: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
    index_id: str | None = None,
):
    """Retrieve paginated symbols or unresolved calls with immutable evidence references."""
    perform(lambda: query_index(ctx.obj, run_id, kind, path, offset, limit, index_id))


@app.command("repo-report")
def repo_report(
    ctx: typer.Context,
    repo_id: str,
    run_id: str | None = None,
    format: str = "json",
    index_id: str | None = None,
):
    """Retrieve coverage for a repo's latest admitted run, or an explicit historical run."""
    if format == "json":
        perform(lambda: repository_report(ctx.obj, repo_id, run_id, index_id))
    elif format == "markdown":
        try:
            typer.echo(report_markdown(repository_report(ctx.obj, repo_id, run_id, index_id)))
        except (VeriFlowError, OSError, SQLAlchemyError):
            typer.echo(
                "Cannot retrieve report; check repository, run, and initialization.", err=True
            )
            raise typer.Exit(1) from None
    else:
        typer.echo("Format must be json or markdown", err=True)
        raise typer.Exit(1)


@app.command("codeql-extract")
def codeql_extract(
    ctx: typer.Context,
    run_id: str,
    timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300,
    skip_baseline: Annotated[
        bool, typer.Option(help="Skip optional CodeQL line-count baseline")
    ] = False,
    threads: Annotated[int, typer.Option(min=1, max=64)] = 2,
    ram_mb: Annotated[int, typer.Option(min=2048, max=262144)] = 2048,
    language: str = "python",
    java_profile: str = "dependency-free",
    java_dependency_profile: Path | None = None,
    allow_csharp_downloads: bool = False,
    csharp_dependency_profile: Path | None = None,
    csharp_offline: bool = False,
):
    """Opt-in local extraction; creates diagnostics, not security findings."""
    from veriflow.codeql import extract

    def operation():
        ctx.obj.require_initialized()
        with exclusive_worker(ctx.obj.root):
            return extract(
                ctx.obj,
                run_id,
                timeout,
                skip_baseline,
                threads=threads,
                ram_mb=ram_mb,
                language=language,
                java_profile=java_profile,
                java_dependency_profile=java_dependency_profile,
                allow_csharp_downloads=allow_csharp_downloads,
                csharp_dependency_profile=csharp_dependency_profile,
                csharp_offline=csharp_offline,
            )

    perform(operation)


@app.command("codeql-status")
def codeql_status(ctx: typer.Context, attempt_id: str):
    """Retrieve an extraction attempt without executing CodeQL."""
    from veriflow.codeql import extraction_status

    perform(lambda: extraction_status(ctx.obj, attempt_id))


@app.command("storage-audit")
def storage_audit_command(
    ctx: typer.Context,
    max_entries: Annotated[int, typer.Option(min=1, max=10000)] = 1000,
    max_nodes: Annotated[int, typer.Option(min=1, max=1000000)] = 100000,
):
    """Inspect retained artifact references and bounded file sizes; never deletes data."""
    from veriflow.storage_audit import storage_audit

    perform(lambda: storage_audit(ctx.obj, max_entries, max_nodes))


@app.command("extraction-history")
def extraction_history_command(
    ctx: typer.Context,
    repo_id: str,
    run_id: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Discover CodeQL extraction attempts, including failures before query analysis."""
    from veriflow.history import extraction_history

    perform(lambda: extraction_history(ctx.obj, repo_id, run_id, offset, limit))


@app.command("scan-run")
def scan_run_command(
    ctx: typer.Context,
    run_id: str,
    queries: Annotated[Path | None, typer.Argument()] = None,
    extraction_timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300,
    query_timeout: Annotated[int, typer.Option(min=1, max=3600)] = 600,
    threads: Annotated[int, typer.Option(min=1, max=64)] = 2,
    ram_mb: Annotated[int, typer.Option(min=2048, max=262144)] = 2048,
    language: str = "auto",
    java_profile: str = "dependency-free",
    java_dependency_profile: Path | None = None,
    allow_csharp_downloads: bool = False,
    csharp_dependency_profile: Path | None = None,
    csharp_offline: bool = False,
    engine: str = "codeql",
    joern_home: Path | None = None,
    joern_repair_dir: Path | None = None,
    rust_home: Path | None = None,
    joern_profile: str | None = None,
    advisory_config: Path | None = None,
    review_policy: str | None = None,
    advisory_key: str | None = None,
    replay: Path | None = None,
    advisory_offset: Annotated[int, typer.Option(min=0)] = 0,
    advisory_limit: Annotated[int, typer.Option(min=1, max=100)] = 1,
    unmetered: Annotated[
        bool, typer.Option(help="Bypass every budget check; charges are still recorded")
    ] = False,
    allow_degraded_evidence: Annotated[
        bool, typer.Option(help="Send incomplete bundles anyway; results stay unverified")
    ] = False,
    envelope_config: Path | None = None,
    max_locations: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    max_source_bytes: Annotated[int | None, typer.Option(min=1024, max=1048576)] = None,
    max_bundle_bytes: Annotated[int | None, typer.Option(min=2048, max=2097152)] = None,
    max_elided_index: Annotated[int | None, typer.Option(min=0, max=512)] = None,
    context_lines: Annotated[int | None, typer.Option(min=0, max=40)] = None,
    max_region_lines: Annotated[int | None, typer.Option(min=1, max=400)] = None,
    llm_discovery: bool = False,
    llm_discovery_config: Path | None = None,
    llm_discovery_replay: Path | None = None,
    llm_discovery_key: str | None = None,
    llm_discovery_max_excerpts: Annotated[int, typer.Option(min=1, max=12)] = 8,
):
    """Scan and publish, with optional replay-backed additive LLM discovery."""
    from veriflow.envelope import resolve as resolve_envelope
    from veriflow.llm_discovery import load_options
    from veriflow.pipeline import scan_run
    from veriflow.scan_advisory import load_advisory

    perform(
        lambda: scan_run(
            ctx.obj,
            run_id,
            queries,
            extraction_timeout,
            query_timeout,
            threads=threads,
            ram_mb=ram_mb,
            language=language,
            java_profile=java_profile,
            java_dependency_profile=java_dependency_profile,
            allow_csharp_downloads=allow_csharp_downloads,
            csharp_dependency_profile=csharp_dependency_profile,
            csharp_offline=csharp_offline,
            engine=engine,
            joern_home=joern_home,
            joern_repair_dir=joern_repair_dir,
            rust_home=rust_home,
            joern_profile=(joern_profile or "auto") if engine == "joern" else joern_profile,
            advisory=load_advisory(
                advisory_config,
                review_policy,
                advisory_key,
                replay,
                advisory_offset,
                advisory_limit,
                unmetered,
                allow_degraded_evidence,
                resolve_envelope(
                    envelope_config,
                    {
                        "max_locations": max_locations,
                        "max_source_bytes": max_source_bytes,
                        "max_bundle_bytes": max_bundle_bytes,
                        "max_elided_index": max_elided_index,
                        "context_lines": context_lines,
                        "max_region_lines": max_region_lines,
                    },
                ),
            ),
            llm_discovery=load_options(
                llm_discovery,
                llm_discovery_replay,
                llm_discovery_key,
                llm_discovery_max_excerpts,
                llm_discovery_config,
                unmetered=unmetered,
            ),
        )
    )


@app.command("run-pipeline-from-csv")
def run_pipeline_from_csv_command(
    ctx: typer.Context,
    manifest: Path,
    input_root: Annotated[
        Path, typer.Option(help="Only archives under this absolute root are allowed")
    ],
    advisory_config: Annotated[Path, typer.Option(help="Model config for advisory triage")],
    joern_home: Annotated[Path, typer.Option(help="Joern installation directory")],
    output_dir: Annotated[
        Path | None,
        typer.Option(help="Logs and reports; default work/pipeline/<UTC timestamp>"),
    ] = None,
    joern_repair_dir: Path | None = None,
    rust_home: Path | None = None,
    replay: Annotated[Path | None, typer.Option(help="Replay response for a replay config")] = None,
    unmetered: Annotated[
        bool, typer.Option(help="Bypass every budget check; charges are still recorded")
    ] = True,
    allow_degraded_evidence: Annotated[
        bool, typer.Option(help="Send incomplete or ungated bundles; results stay unverified")
    ] = True,
    budget_micro_usd: Annotated[
        int | None, typer.Option(min=0, help="Per-run budget; required with --no-unmetered")
    ] = None,
    max_requests: Annotated[int | None, typer.Option(min=0, max=10000)] = None,
    rescan_empty: Annotated[
        bool, typer.Option(help="Scan profiles again whose last attempt found zero candidates")
    ] = False,
    reimport: Annotated[
        bool, typer.Option(help="Import again rows whose archive changed or whose import failed")
    ] = False,
    force_reimport: Annotated[
        bool, typer.Option(help="Import every row again, even unchanged ones (full rescan)")
    ] = False,
    retry_unknown: Annotated[
        bool, typer.Option(help="Send again calls stored as unknown; the provider may charge twice")
    ] = False,
    ungated_triage: Annotated[
        bool, typer.Option(help="Send candidates of profiles without a reviewed gate to the model")
    ] = True,
    llm_discovery: Annotated[
        bool, typer.Option(help="Also run additive LLM discovery for each detected language")
    ] = False,
    llm_discovery_config: Annotated[
        Path | None, typer.Option(help="Discovery model config; default --advisory-config")
    ] = None,
    llm_discovery_replay: Path | None = None,
    llm_discovery_max_excerpts: Annotated[int, typer.Option(min=1, max=12)] = 8,
    extraction_timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300,
    query_timeout: Annotated[int, typer.Option(min=1, max=3600)] = 600,
    check_connectivity: Annotated[
        bool, typer.Option(help="Probe live provider endpoints before any scan work")
    ] = True,
    envelope_config: Path | None = None,
    max_locations: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    max_source_bytes: Annotated[int | None, typer.Option(min=1024, max=1048576)] = None,
    max_bundle_bytes: Annotated[int | None, typer.Option(min=2048, max=2097152)] = None,
    max_elided_index: Annotated[int | None, typer.Option(min=0, max=512)] = None,
    context_lines: Annotated[int | None, typer.Option(min=0, max=40)] = None,
    max_region_lines: Annotated[int | None, typer.Option(min=1, max=400)] = None,
):
    """Import, scan all Joern profiles, triage every candidate and export reports per CSV row."""
    from datetime import UTC, datetime

    from veriflow.csv_pipeline import PipelineOptions, run_pipeline
    from veriflow.envelope import resolve as resolve_envelope
    from veriflow.llm_discovery import load_options
    from veriflow.models import ReplayAdapter, live_adapter, read_config

    outcome = {}

    def operation():
        if unmetered and (budget_micro_usd is not None or max_requests is not None):
            raise VeriFlowError("Budget options require --no-unmetered")
        config = read_config(advisory_config)
        if config.provider == "replay":
            if replay is None:
                raise VeriFlowError("Replay policy requires --replay RESPONSE_JSON")
            adapter = ReplayAdapter(replay)
        else:
            if replay is not None:
                raise VeriFlowError("A live policy cannot use a replay fixture")
            adapter = live_adapter(config)
        options = PipelineOptions(
            config=config,
            adapter=adapter,
            joern_home=joern_home,
            joern_repair_dir=joern_repair_dir,
            rust_home=rust_home,
            unmetered=unmetered,
            allow_degraded_evidence=allow_degraded_evidence,
            rescan_empty=rescan_empty,
            reimport=reimport,
            force_reimport=force_reimport,
            retry_unknown=retry_unknown,
            ungated_triage=ungated_triage,
            discovery=load_options(
                llm_discovery,
                llm_discovery_replay,
                "pipeline" if llm_discovery else None,
                llm_discovery_max_excerpts,
                (llm_discovery_config or advisory_config) if llm_discovery else None,
                unmetered=unmetered,
            ),
            envelope=resolve_envelope(
                envelope_config,
                {
                    "max_locations": max_locations,
                    "max_source_bytes": max_source_bytes,
                    "max_bundle_bytes": max_bundle_bytes,
                    "max_elided_index": max_elided_index,
                    "context_lines": context_lines,
                    "max_region_lines": max_region_lines,
                },
            ),
            extraction_timeout=extraction_timeout,
            query_timeout=query_timeout,
            budget_micro_usd=budget_micro_usd,
            max_requests=max_requests,
            check_connectivity=check_connectivity,
        )
        target = output_dir or Path("work/pipeline") / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        outcome.update(run_pipeline(ctx.obj, manifest, input_root, target, options))
        return outcome

    perform(operation)
    if outcome.get("status") == "failed":
        raise typer.Exit(1)


@app.command("scan-import")
def scan_import_command(
    ctx: typer.Context,
    import_id: str,
    queries: Annotated[Path | None, typer.Argument()] = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 1,
    rescan: bool = False,
    extraction_timeout: Annotated[int, typer.Option(min=1, max=3600)] = 300,
    query_timeout: Annotated[int, typer.Option(min=1, max=3600)] = 600,
    threads: Annotated[int, typer.Option(min=1, max=64)] = 2,
    ram_mb: Annotated[int, typer.Option(min=2048, max=262144)] = 2048,
    language: str = "auto",
    java_profile: str = "dependency-free",
    java_dependency_profile: Path | None = None,
    allow_csharp_downloads: bool = False,
    csharp_dependency_profile: Path | None = None,
    csharp_offline: bool = False,
    engine: str = "codeql",
    joern_home: Path | None = None,
    joern_repair_dir: Path | None = None,
    rust_home: Path | None = None,
    joern_profile: str | None = None,
    advisory_config: Path | None = None,
    review_policy: str | None = None,
    advisory_key: str | None = None,
    replay: Path | None = None,
    advisory_offset: Annotated[int, typer.Option(min=0)] = 0,
    advisory_limit: Annotated[int, typer.Option(min=1, max=100)] = 1,
    unmetered: Annotated[
        bool, typer.Option(help="Bypass every budget check; charges are still recorded")
    ] = False,
    allow_degraded_evidence: Annotated[
        bool, typer.Option(help="Send incomplete bundles anyway; results stay unverified")
    ] = False,
    envelope_config: Path | None = None,
    max_locations: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    max_source_bytes: Annotated[int | None, typer.Option(min=1024, max=1048576)] = None,
    max_bundle_bytes: Annotated[int | None, typer.Option(min=2048, max=2097152)] = None,
    max_elided_index: Annotated[int | None, typer.Option(min=0, max=512)] = None,
    context_lines: Annotated[int | None, typer.Option(min=0, max=40)] = None,
    max_region_lines: Annotated[int | None, typer.Option(min=1, max=400)] = None,
):
    """Sequentially scan selected import rows; existing query attempts are skipped by default."""
    from veriflow.batch_scan import scan_import
    from veriflow.envelope import resolve as resolve_envelope
    from veriflow.scan_advisory import load_advisory

    perform(
        lambda: scan_import(
            ctx.obj,
            import_id,
            queries,
            offset,
            limit,
            rescan,
            extraction_timeout,
            query_timeout,
            threads=threads,
            ram_mb=ram_mb,
            language=language,
            java_profile=java_profile,
            java_dependency_profile=java_dependency_profile,
            allow_csharp_downloads=allow_csharp_downloads,
            csharp_dependency_profile=csharp_dependency_profile,
            csharp_offline=csharp_offline,
            engine=engine,
            joern_home=joern_home,
            joern_repair_dir=joern_repair_dir,
            rust_home=rust_home,
            joern_profile=(joern_profile or "auto") if engine == "joern" else joern_profile,
            advisory=load_advisory(
                advisory_config,
                review_policy,
                advisory_key,
                replay,
                advisory_offset,
                advisory_limit,
                unmetered,
                allow_degraded_evidence,
                resolve_envelope(
                    envelope_config,
                    {
                        "max_locations": max_locations,
                        "max_source_bytes": max_source_bytes,
                        "max_bundle_bytes": max_bundle_bytes,
                        "max_elided_index": max_elided_index,
                        "context_lines": context_lines,
                        "max_region_lines": max_region_lines,
                    },
                ),
            ),
        )
    )


@app.command("source-evidence")
def evidence(
    ctx: typer.Context, run_id: str, path: str, line: int, end_line: int, sha256: str | None = None
):
    """Read at most 200 lines/32 KiB from verified snapshot source."""
    from veriflow.evidence import source_evidence

    perform(lambda: source_evidence(ctx.obj, run_id, path, line, end_line, sha256))


@app.command("call-context")
def calls(
    ctx: typer.Context,
    run_id: str,
    path: str,
    module_root: str = ".",
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Retrieve conservative direct/import candidates; does not prove reachability."""
    from veriflow.calls import call_context

    perform(lambda: call_context(ctx.obj, run_id, path, module_root, offset, limit))


@app.command("codeql-analyze")
def codeql_analyze(
    ctx: typer.Context,
    extraction_id: str,
    queries: Path,
    timeout: Annotated[int, typer.Option(min=1, max=3600)] = 600,
    threads: Annotated[int, typer.Option(min=1, max=64)] = 2,
    ram_mb: Annotated[int, typer.Option(min=2048, max=262144)] = 2048,
):
    """Run an operator-provided local query/suite; publish unreviewed SARIF candidates."""
    from veriflow.scanning import analyze

    def operation():
        ctx.obj.require_initialized()
        with exclusive_worker(ctx.obj.root):
            return analyze(ctx.obj, extraction_id, queries, timeout, threads=threads, ram_mb=ram_mb)

    perform(operation)


@app.command("scan-report")
def scan_report_command(
    ctx: typer.Context,
    repo_id: str,
    run_id: str | None = None,
    attempt_id: str | None = None,
    format: str = "json",
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Read the latest static-analysis attempt, or an explicitly selected attempt."""
    from veriflow.scanning import scan_report, scan_report_markdown

    def operation():
        if format not in {"json", "markdown"}:
            raise VeriFlowError("Format must be json or markdown")
        report = scan_report(ctx.obj, repo_id, run_id, attempt_id, offset, limit)
        return scan_report_markdown(report) if format == "markdown" else report

    perform(operation)


@app.command("discovery-replay")
def discovery_replay_command(
    ctx: typer.Context,
    attempt_id: str,
    packet: Path,
    response: Path,
    request_key: Annotated[str, typer.Option(help="Unique idempotency key for this request")],
):
    """Validate replay proposals and persist snapshot-bound exploratory candidates."""
    from veriflow.llm_discovery import replay_discovery

    perform(lambda: replay_discovery(ctx.obj, attempt_id, packet, response, request_key))


@app.command("discovery-report")
def discovery_report_command(
    ctx: typer.Context,
    run_id: str,
    attempt_id: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Retrieve replay/live discovery provenance without invoking a model."""
    from veriflow.llm_discovery import discovery_report

    perform(lambda: discovery_report(ctx.obj, run_id, attempt_id, offset, limit))


@app.command("build-bundle")
def bundle_build(
    ctx: typer.Context,
    attempt_id: str,
    fingerprint: str,
    envelope_config: Path | None = None,
    max_locations: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    max_source_bytes: Annotated[int | None, typer.Option(min=1024, max=1048576)] = None,
    max_bundle_bytes: Annotated[int | None, typer.Option(min=2048, max=2097152)] = None,
    max_elided_index: Annotated[int | None, typer.Option(min=0, max=512)] = None,
    context_lines: Annotated[int | None, typer.Option(min=0, max=40)] = None,
    max_region_lines: Annotated[int | None, typer.Option(min=1, max=400)] = None,
):
    """Materialize bounded primary/flow evidence for one static candidate."""
    from veriflow.bundles import build_bundle
    from veriflow.envelope import resolve as resolve_envelope

    perform(
        lambda: build_bundle(
            ctx.obj,
            attempt_id,
            fingerprint,
            resolve_envelope(
                envelope_config,
                {
                    "max_locations": max_locations,
                    "max_source_bytes": max_source_bytes,
                    "max_bundle_bytes": max_bundle_bytes,
                    "max_elided_index": max_elided_index,
                    "context_lines": context_lines,
                    "max_region_lines": max_region_lines,
                },
            ),
        )
    )


@app.command("bundle-status")
def bundle_status(ctx: typer.Context, bundle_id: str):
    """Retrieve a materialized evidence bundle without reading source or invoking a model."""
    from veriflow.bundles import get_bundle

    perform(lambda: get_bundle(ctx.obj, bundle_id))


@app.command("expand-bundle")
def bundle_expand(ctx: typer.Context, bundle_id: str, request: Path):
    """Add explicitly requested context within the original bundle's fixed byte budget."""
    from veriflow.expansion import expand_bundle, read_expansion

    perform(lambda: expand_bundle(ctx.obj, bundle_id, read_expansion(request)))


@app.command("evidence-policy")
def evidence_policy(ctx: typer.Context, rule_id: str):
    """Show supported evidence obligations for a CodeQL rule."""
    from veriflow.claims import requirements

    perform(lambda: requirements(rule_id))


@app.command("check-evidence")
def evidence_check(
    ctx: typer.Context, bundle_id: str, decision: Path, review_policy: str | None = None
):
    """Validate a decision's claims against a materialized bundle; no provider invocation."""
    from pydantic import ValidationError

    from veriflow.bundles import get_bundle
    from veriflow.claims import assess_evidence
    from veriflow.models import Decision

    def operation():
        with decision.open("rb") as handle:
            raw = handle.read(32 * 1024 + 1)
        if len(raw) > 32 * 1024:
            raise VeriFlowError("Decision exceeds the 32 KiB limit")
        try:
            parsed = Decision.model_validate_json(raw)
        except ValidationError:
            raise VeriFlowError("Decision does not match the supported claim schema") from None
        bundle = get_bundle(ctx.obj, bundle_id)
        if review_policy is not None:
            from veriflow.joern_claims import assess_review_evidence, require_policy

            require_policy(review_policy)
            return assess_review_evidence(bundle, parsed, review_policy)
        return assess_evidence(bundle, parsed)

    perform(operation)


@app.command("triage-budget")
def budget_set(
    ctx: typer.Context,
    run_id: str,
    micro_usd: int,
    max_requests: Annotated[int | None, typer.Option(min=0, max=10000)] = None,
):
    """Set an immutable per-run triage cap; 1,000,000 micro-USD equals one USD."""
    from veriflow.triage import set_budget

    perform(lambda: set_budget(ctx.obj, run_id, micro_usd, max_requests))


@app.command("triage")
def triage_command(
    ctx: typer.Context,
    bundle_id: str,
    config: Path,
    key: str,
    replay: Path | None = None,
    review_policy: str | None = None,
    unmetered: Annotated[
        bool, typer.Option(help="Bypass every budget check; charges are still recorded")
    ] = False,
    allow_degraded_evidence: Annotated[
        bool, typer.Option(help="Send incomplete bundles anyway; results stay unverified")
    ] = False,
):
    """Triage one bundle; replay is offline and live providers require explicit opt-in."""
    from veriflow.models import ReplayAdapter, live_adapter, read_config
    from veriflow.triage import triage

    def operation():
        policy = read_config(config)
        if policy.provider == "replay":
            if replay is None:
                raise VeriFlowError("Replay policy requires --replay RESPONSE_JSON")
            adapter = ReplayAdapter(replay)
        else:
            if replay is not None:
                raise VeriFlowError("A live policy cannot use a replay fixture")
            adapter = live_adapter(policy)
        return triage(
            ctx.obj,
            bundle_id,
            policy,
            adapter,
            key,
            review_policy=review_policy,
            unmetered=unmetered,
            allow_degraded_evidence=allow_degraded_evidence,
        )

    perform(operation)


@app.command("triage-attempt")
def triage_attempt_command(
    ctx: typer.Context,
    repo_id: str,
    attempt_id: str,
    config: Path,
    key: str,
    replay: Path | None = None,
    review_policy: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=100)] = 1,
    unmetered: Annotated[
        bool, typer.Option(help="Bypass every budget check; charges are still recorded")
    ] = False,
    allow_degraded_evidence: Annotated[
        bool, typer.Option(help="Send incomplete bundles anyway; results stay unverified")
    ] = False,
    envelope_config: Path | None = None,
    max_locations: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    max_source_bytes: Annotated[int | None, typer.Option(min=1024, max=1048576)] = None,
    max_bundle_bytes: Annotated[int | None, typer.Option(min=2048, max=2097152)] = None,
    max_elided_index: Annotated[int | None, typer.Option(min=0, max=512)] = None,
    context_lines: Annotated[int | None, typer.Option(min=0, max=40)] = None,
    max_region_lines: Annotated[int | None, typer.Option(min=1, max=400)] = None,
):
    """Triage a bounded candidate page with per-run budgets and stable request keys."""
    from veriflow.batch_triage import triage_attempt
    from veriflow.envelope import resolve as resolve_envelope
    from veriflow.models import ReplayAdapter, live_adapter, read_config

    def operation():
        envelope = resolve_envelope(
            envelope_config,
            {
                "max_locations": max_locations,
                "max_source_bytes": max_source_bytes,
                "max_bundle_bytes": max_bundle_bytes,
                "max_elided_index": max_elided_index,
                "context_lines": context_lines,
                "max_region_lines": max_region_lines,
            },
        )
        policy = read_config(config)
        if policy.provider == "replay":
            if replay is None:
                raise VeriFlowError("Replay policy requires --replay RESPONSE_JSON")
            adapter = ReplayAdapter(replay)
        else:
            if replay is not None:
                raise VeriFlowError("A live policy cannot use a replay fixture")
            adapter = live_adapter(policy)
        return triage_attempt(
            ctx.obj,
            repo_id,
            attempt_id,
            policy,
            adapter,
            key,
            offset,
            limit,
            review_policy=review_policy,
            unmetered=unmetered,
            allow_degraded_evidence=allow_degraded_evidence,
            envelope=envelope,
        )

    perform(operation)


@app.command("triage-windows")
def triage_windows_command(
    ctx: typer.Context,
    repo_id: str,
    attempt_id: str,
    config: Path,
    key: str,
    replay: Path | None = None,
    review_policy: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=100)] = 1,
    overlap: Annotated[int, typer.Option(min=0, max=32)] = 1,
    max_windows: Annotated[int, typer.Option(min=1, max=32)] = 8,
    unmetered: Annotated[
        bool, typer.Option(help="Bypass every budget check; charges are still recorded")
    ] = False,
    envelope_config: Path | None = None,
    max_locations: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    max_source_bytes: Annotated[int | None, typer.Option(min=1024, max=1048576)] = None,
    max_bundle_bytes: Annotated[int | None, typer.Option(min=2048, max=2097152)] = None,
    max_elided_index: Annotated[int | None, typer.Option(min=0, max=512)] = None,
    context_lines: Annotated[int | None, typer.Option(min=0, max=40)] = None,
    max_region_lines: Annotated[int | None, typer.Option(min=1, max=400)] = None,
):
    """Walk a long flow in overlapping windows; partial views stay advisory and unverified."""
    from veriflow.envelope import resolve as resolve_envelope
    from veriflow.models import ReplayAdapter, live_adapter, read_config
    from veriflow.windows import triage_windows

    def operation():
        envelope = resolve_envelope(
            envelope_config,
            {
                "max_locations": max_locations,
                "max_source_bytes": max_source_bytes,
                "max_bundle_bytes": max_bundle_bytes,
                "max_elided_index": max_elided_index,
                "context_lines": context_lines,
                "max_region_lines": max_region_lines,
            },
        )
        policy = read_config(config)
        if policy.provider == "replay":
            if replay is None:
                raise VeriFlowError("Replay policy requires --replay RESPONSE_JSON")
            adapter = ReplayAdapter(replay)
        else:
            if replay is not None:
                raise VeriFlowError("A live policy cannot use a replay fixture")
            adapter = live_adapter(policy)
        return triage_windows(
            ctx.obj,
            repo_id,
            attempt_id,
            policy,
            adapter,
            key,
            offset,
            limit,
            review_policy=review_policy,
            unmetered=unmetered,
            envelope=envelope,
            overlap=overlap,
            max_windows=max_windows,
        )

    perform(operation)


@app.command("triage-report")
def triage_status(
    ctx: typer.Context,
    run_id: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Retrieve advisory decisions and the durable cost ledger without model calls."""
    from veriflow.triage import triage_report

    perform(lambda: triage_report(ctx.obj, run_id, offset, limit))


@app.command("import-history")
def import_history_command(
    ctx: typer.Context,
    state: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Find prior imports with dispatch state and intake counts; does not start work."""
    from veriflow.import_history import import_history

    perform(lambda: import_history(ctx.obj, state, offset, limit))


@app.command("import-control")
def import_control_command(
    ctx: typer.Context,
    import_id: str,
    state: str,
    key: str,
    reason: str,
    expected_revision: Annotated[int, typer.Option(min=0)],
):
    """Pause, resume or permanently cancel import dispatch at row boundaries."""
    from veriflow.import_controls import set_control

    perform(lambda: set_control(ctx.obj, import_id, state, key, reason, expected_revision))


@app.command("import-control-status")
def import_control_status_command(
    ctx: typer.Context,
    import_id: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """Read current import dispatch state and append-only transition history."""
    from veriflow.import_controls import control_status

    perform(lambda: control_status(ctx.obj, import_id, offset, limit))


@app.command("import-csv")
def import_csv(
    ctx: typer.Context,
    manifest: Path,
    input_root: Annotated[
        Path, typer.Option(help="Only archives under this absolute root are allowed")
    ],
    key: Annotated[str, typer.Option(help="Stable idempotency key for this submission")],
):
    """Admit local TAR/TAR.GZ/ZIP rows; process them separately with worker."""
    perform(lambda: import_status(ctx.obj, submit(ctx.obj, manifest, input_root, key)))


@app.command("import-status")
def status(ctx: typer.Context, import_id: str):
    """Retrieve durable per-row results without processing source."""
    perform(lambda: import_status(ctx.obj, import_id))


@app.command("run-status")
def run(ctx: typer.Context, run_id: str):
    """Retrieve an intake run; snapshot readiness does not imply a security scan."""
    perform(lambda: run_status(ctx.obj, run_id))


@app.command("run-history")
def run_history_command(
    ctx: typer.Context,
    repo_id: str,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """List admitted runs, including work without a scan or published report."""
    from veriflow.history import run_history

    perform(lambda: run_history(ctx.obj, repo_id, offset, limit))


@app.command("scan-history")
def scan_history_command(
    ctx: typer.Context,
    repo_id: str,
    run_id: str | None = None,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 100,
):
    """List query attempts, including failed and unpublished work; never executes scans."""
    from veriflow.history import scan_history

    perform(lambda: scan_history(ctx.obj, repo_id, run_id, offset, limit))


@app.command()
def worker(
    ctx: typer.Context,
    import_id: str,
    max_items: Annotated[int, typer.Option(min=1, max=1000)] = 1000,
):
    """Capture admitted archives; restart this command to resume interrupted intake."""

    def operation():
        store = ctx.obj
        store.require_initialized()
        with exclusive_worker(store.root):
            return process(store, ArtifactStore(store.root), import_id, max_items)

    perform(operation)


@app.command("verify-snapshot")
def verify(ctx: typer.Context, snapshot_id: str):
    """Recheck the manifest, original archive and every source-file digest."""

    def operation():
        ctx.obj.require_initialized()
        manifest = ArtifactStore(ctx.obj.root).verify(snapshot_id)
        return {"snapshot_id": manifest.snapshot_id, "files": len(manifest.files), "valid": True}

    perform(operation)


@app.command("joern-java-discover")
def joern_java_discover_command(
    ctx: typer.Context, run_id: str, joern_home: Path, timeout: int = 180
):
    """Experimental bounded Spring/JDBC discovery; no qualified triage."""
    from veriflow.joern import discover

    perform(lambda: discover(ctx.obj, run_id, joern_home, timeout))


@app.command("joern-csharp-discover")
def joern_csharp_discover_command(
    ctx: typer.Context, run_id: str, joern_home: Path, repair_dir: Path, timeout: int = 180
):
    """Experimental Lookup(name)/CommandText discovery using a trusted repair build."""
    from veriflow.joern import discover

    perform(lambda: discover(ctx.obj, run_id, joern_home, timeout, repair_dir=repair_dir))


@app.command("joern-python-discover")
def joern_python_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental lookup(input)/system discovery; no qualified triage."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj,
            run_id,
            joern_home,
            timeout,
            language="python",
            discovery_profile=discovery_profile,
        )
    )


@app.command("joern-javascript-discover")
def joern_javascript_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental javascript lookup(input)/eval discovery; no qualified triage."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj,
            run_id,
            joern_home,
            timeout,
            language="javascript",
            discovery_profile=discovery_profile,
        )
    )


@app.command("joern-typescript-discover")
def joern_typescript_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental typescript lookup(input)/eval discovery; no qualified triage."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj,
            run_id,
            joern_home,
            timeout,
            language="typescript",
            discovery_profile=discovery_profile,
        )
    )


@app.command("joern-go-discover")
def joern_go_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental Go discovery with optional HTTP profile; no qualified triage."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj, run_id, joern_home, timeout, language="go", discovery_profile=discovery_profile
        )
    )


@app.command("joern-rust-discover")
def joern_rust_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    rust_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental dependency-free Cargo discovery with optional environment profile."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj,
            run_id,
            joern_home,
            timeout,
            language="rust",
            rust_home=rust_home,
            discovery_profile=discovery_profile,
        )
    )


@app.command("joern-c-discover")
def joern_c_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental c discovery with optional argv profile; no qualified triage."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj, run_id, joern_home, timeout, language="c", discovery_profile=discovery_profile
        )
    )


@app.command("joern-cpp-discover")
def joern_cpp_discover_command(
    ctx: typer.Context,
    run_id: str,
    joern_home: Path,
    timeout: int = 180,
    discovery_profile: str | None = None,
):
    """Experimental cpp discovery with optional argv profile; no qualified triage."""
    from veriflow.joern import discover

    perform(
        lambda: discover(
            ctx.obj,
            run_id,
            joern_home,
            timeout,
            language="cpp",
            discovery_profile=discovery_profile,
        )
    )


@app.command("acquire-git")
def acquire_git_command(
    url: str,
    revision: str,
    output: Path,
    repo_id: str,
    owner: str,
    classification: str,
    allowed_host: Annotated[list[str], typer.Option(help="Explicit HTTPS host allowlist")],
    timeout: Annotated[int, typer.Option(min=1, max=900)] = 300,
    ca_bundle: Path | None = None,
    proxy: str | None = None,
    credential_file: Path | None = None,
):
    """Acquire one HTTPS Git revision as a local archive/CSV; does not scan."""
    from veriflow.git_acquisition import acquire

    perform(
        lambda: acquire(
            url,
            revision,
            allowed_host,
            output,
            repo_id,
            owner,
            classification,
            timeout,
            ca_bundle=ca_bundle,
            proxy=proxy,
            credential_file=credential_file,
        )
    )


@app.command("acquire-git-csv")
def acquire_git_csv_command(
    manifest: Path,
    output: Path,
    allowed_host: Annotated[list[str], typer.Option(help="Operator-supplied HTTPS host allowlist")],
    max_rows: Annotated[int, typer.Option(min=1, max=10)] = 10,
    timeout: Annotated[int, typer.Option(min=1, max=3600)] = 900,
    ca_bundle: Path | None = None,
    proxy: str | None = None,
    credential_file: Path | None = None,
):
    """Acquire a bounded repositories.csv batch; export archives.csv without scanning."""
    from veriflow.git_batch import acquire_csv

    def operation():
        result = acquire_csv(
            manifest,
            output,
            allowed_host,
            max_rows,
            timeout,
            ca_bundle=ca_bundle,
            proxy=proxy,
            credential_file=credential_file,
        )
        if result["state"] != "acquired":
            typer.echo(render_json(result))
            raise typer.Exit(1)
        return result

    perform(operation)


@app.command("acquire-gcs")
def acquire_gcs_command(
    bucket: str,
    object_name: str,
    generation: str,
    sha256: str,
    output: Path,
    repo_id: str,
    owner: str,
    classification: str,
    allowed_bucket: Annotated[list[str], typer.Option(help="Operator-approved bucket allowlist")],
    use_adc: bool = False,
    max_bytes: Annotated[int, typer.Option(min=1, max=1073741824)] = 104857600,
    timeout: Annotated[int, typer.Option(min=1, max=900)] = 300,
):
    """Download one pinned GCS archive; emits archives.csv without scanning."""
    from veriflow.gcs_acquisition import acquire_archive
    from veriflow.gcs_reader import GCSReader

    def operation():
        reader = GCSReader(use_adc=use_adc, timeout=timeout)
        try:
            return acquire_archive(
                reader,
                bucket=bucket,
                name=object_name,
                generation=generation,
                expected_sha256=sha256,
                allowed_buckets=allowed_bucket,
                output=output,
                repo_id=repo_id,
                owner=owner,
                classification=classification,
                max_bytes=max_bytes,
                timeout=timeout,
            )
        finally:
            reader.close()

    perform(operation)
