"""Sequential per-repository CSV run from intake to exported reports; no verdicts."""

import csv
import fcntl
import hashlib
import io
import json
import os
import re
import socket
import sys
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from veriflow import joern_pipeline, joern_profiles, joern_selection
from veriflow.artifacts import ArtifactStore, open_scoped_source
from veriflow.bundles import build_bundle, canonical
from veriflow.claims import bundle_engine
from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.intake import MAX_CSV_BYTES, MAX_ROWS, process, render_json, submit
from veriflow.joern_claims import policy_for
from veriflow.llm_discovery import DISCOVERY_SUFFIXES, DiscoveryOptions, run_hybrid_discovery
from veriflow.models import ModelConfig
from veriflow.persistence import (
    Candidate,
    ImportItem,
    Run,
    ScanAttempt,
    Snapshot,
    TriageCall,
    exclusive_worker,
)
from veriflow.pipeline import discovery_anchor
from veriflow.pipeline_summary import repository_summary, run_summary, write_summary
from veriflow.reports import get_report, publish_report, render_report
from veriflow.scan_advisory import CountingAdapter
from veriflow.scanning import scan_report, scan_report_markdown
from veriflow.triage import set_budget, triage, triage_report

USABLE = {"partial", "completed"}
# Every later request in the run would stop the same way; continuing only adds log noise.
RUN_STOP_STATES = {"budget_exhausted", "request_limit_exhausted"}
REPORT_FILES = {
    "report.json": "json",
    "report.md": "markdown",
    "report.html": "html",
    "scan.csv": "scan-csv",
    "candidates.csv": "candidates-csv",
}
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
PAGE = 1000
# Consecutive fresh provider calls ending "unknown" before triage stops for the whole run.
BREAKER_LIMIT = 3
WORKER_BUSY = "A local worker already owns this state directory"
sleep = time.sleep


@dataclass(frozen=True)
class PipelineOptions:
    config: ModelConfig
    adapter: object
    joern_home: Path
    joern_repair_dir: Path | None = None
    rust_home: Path | None = None
    unmetered: bool = True
    allow_degraded_evidence: bool = True
    rescan_empty: bool = False
    reimport: bool = False
    force_reimport: bool = False
    retry_unknown: bool = False
    ungated_triage: bool = True
    discovery: DiscoveryOptions | None = None
    envelope: object = None
    extraction_timeout: int = 300
    query_timeout: int = 600
    budget_micro_usd: int | None = None
    max_requests: int | None = None
    check_connectivity: bool = True


class ProviderBreaker:
    """Stops provider traffic for the run after repeated ambiguous outcomes."""

    def __init__(self, limit=None):
        self.limit, self.consecutive = limit or BREAKER_LIMIT, 0

    @property
    def tripped(self):
        return self.consecutive >= self.limit

    def record(self, state):
        self.consecutive = self.consecutive + 1 if state == "unknown" else 0


def now():
    return datetime.now(UTC).isoformat(timespec="seconds")


def safe_error(exc):
    # VeriFlowError text never carries source; other exceptions may, so only name their type.
    if isinstance(exc, VeriFlowError):
        return str(exc)
    return f"{type(exc).__name__}: local operation failed"


def transient(exc):
    if isinstance(exc, OperationalError):
        text = str(exc.orig).lower()
        return "locked" in text or "busy" in text
    return isinstance(exc, VeriFlowError) and str(exc) == WORKER_BUSY


def with_retry(log, label, operation, attempts=6):
    """Retry lock contention only; every wrapped stage is idempotent or resumable."""
    delay = 1
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except (VeriFlowError, OperationalError) as exc:
            if not transient(exc) or attempt == attempts:
                raise
            reason = "worker_lock" if isinstance(exc, VeriFlowError) else "sqlite_busy"
            log.write(step=label, status="retrying", reason=reason, attempt=attempt)
            sleep(delay)
            delay = min(delay * 2, 30)


class PipelineLog:
    """JSON-lines step log for the run and for the current repository."""

    def __init__(self, output, echo=None):
        self.path = output / "pipeline.log"
        self.repo_path = None
        self.repo_id = None
        self.steps = []
        self.echo = echo or (lambda line: print(line, file=sys.stderr, flush=True))

    def begin_repo(self, repo_id, directory):
        self.repo_id, self.repo_path, self.steps = repo_id, directory / "steps.log", []

    def end_repo(self):
        self.repo_id, self.repo_path = None, None

    def write(self, **event):
        event = {"ts": now(), "repo_id": self.repo_id, **event}
        line = json.dumps(event, sort_keys=True, default=str) + "\n"
        for path in (self.path, self.repo_path):
            if path is not None:
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
        detail = " ".join(
            f"{k}={v}"
            for k, v in event.items()
            if k not in {"ts", "repo_id", "step", "status"} and v is not None
        )
        self.echo(
            f"[{event['ts']}] {self.repo_id or '-'} {event.get('step')} "
            f"{event.get('status')} {detail}".rstrip()
        )

    @contextmanager
    def step(self, name, **fields):
        started_at, started = now(), time.monotonic()
        self.write(step=name, status="started", **fields)
        record = {"step": name, "status": "completed", "started_at": started_at, **fields}
        try:
            yield record
        except Exception as exc:
            record.update(status="failed", error=safe_error(exc))
            raise
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            self.steps.append(record)
            self.write(**{k: v for k, v in record.items() if k != "started_at"})


@contextmanager
def pipeline_lock(root):
    """One pipeline per state directory; scanner stages still take exclusive_worker."""
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "pipeline.lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise VeriFlowError("Another pipeline run already owns this state directory") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read_manifest(path):
    with path.open("rb") as source:
        raw = source.read(MAX_CSV_BYTES + 1)
    if len(raw) > MAX_CSV_BYTES:
        raise VeriFlowError("CSV exceeds 1 MiB limit")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
        header = reader.fieldnames
        rows = list(enumerate(reader, start=2))
    except (UnicodeError, csv.Error) as exc:
        raise VeriFlowError("CSV must be valid UTF-8 with well-formed quoted fields") from exc
    if not header or "repo_id" not in header:
        raise VeriFlowError("CSV must include a repo_id column")
    if not rows:
        raise VeriFlowError("CSV has no data rows")
    if len(rows) > MAX_ROWS:
        raise VeriFlowError("CSV exceeds 1,000 data rows")
    return header, rows


def config_digest(config):
    return hashlib.sha256(canonical(config.model_dump())).hexdigest()


def check_endpoint(config, label):
    """Fail before scanning when a live provider cannot be reached at all."""
    url = urlsplit(config.endpoint)
    if config.provider == "replay" or not url.hostname:
        return
    if url.scheme == "https" and any(
        os.environ.get(name) for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY")
    ):
        return
    port = url.port or (443 if url.scheme == "https" else 80)
    try:
        socket.create_connection((url.hostname, port), timeout=5).close()
    except OSError as exc:
        raise VeriFlowError(f"{label} endpoint is unreachable; check the provider") from exc


def preflight(options):
    if not options.joern_home.is_dir():
        raise VeriFlowError("Joern home is not a directory")
    configs = [("Advisory", options.config)]
    if options.discovery is not None:
        configs.append(("LLM discovery", options.discovery.config))
    for label, config in configs:
        if config.provider == "replay":
            continue
        if not config.allow_source_transmission:
            raise VeriFlowError(f"{label} config disables live source transmission")
        if config.provider in {"openai", "anthropic"} and not os.environ.get(config.api_key_env):
            raise VeriFlowError(f"Set {config.api_key_env} before the {label} provider runs")
        if options.check_connectivity:
            check_endpoint(config, label)
    if not options.unmetered and options.budget_micro_usd is None:
        raise VeriFlowError("A metered run requires --budget-micro-usd")


def latest_import(store, repo_id):
    with store.transaction() as session:
        found = session.execute(
            select(ImportItem, Run, Snapshot)
            .join(Run, ImportItem.run_id == Run.id)
            .join(Snapshot, Run.snapshot_id == Snapshot.id)
            .where(Run.repo_id == repo_id, ImportItem.state == "snapshotted")
            .order_by(Run.created_at.desc(), Run.id.desc())
            .limit(1)
        ).first()
        if found is None:
            return None
        item, run, snapshot = found
        return {
            "run_id": run.id,
            "source_uri": (item.spec or {}).get("source_uri"),
            "archive_sha256": snapshot.manifest["archive_sha256"],
        }


def archive_digest(source_uri, input_root):
    digest = hashlib.sha256()
    with open_scoped_source(source_uri, input_root) as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_import(store, header, row, input_root, directory, options, stamp, record, log):
    previous = None if options.force_reimport else latest_import(store, row["repo_id"])
    if previous is not None:
        try:
            current = archive_digest(row.get("source_uri", ""), input_root)
        except (OSError, VeriFlowError) as exc:
            raise VeriFlowError("Source archive is unavailable under the input root") from exc
        if (previous["source_uri"], previous["archive_sha256"]) == (row.get("source_uri"), current):
            record.update(action="reused", run_id=previous["run_id"])
            return previous["run_id"]
        if not options.reimport:
            raise VeriFlowError("Archive changed since the last import; rerun with --reimport")
        record["reason"] = "archive_changed"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
    raw = buffer.getvalue().encode("utf-8")
    intake = directory / "intake.csv"
    intake.write_bytes(raw)
    # Same bytes and root give the same key, so an interrupted import resumes, never duplicates.
    key = "pipeline:" + hashlib.sha256(raw + b"\x00" + str(input_root).encode()).hexdigest()[:48]
    if options.force_reimport or options.reimport:
        key += f":{stamp}"
    import_id = with_retry(log, "import", lambda: submit(store, intake, input_root, key))

    def capture():
        with exclusive_worker(store.root):
            return process(store, ArtifactStore(store.root), import_id, max_items=1)

    item = with_retry(log, "import", capture)["items"][0]
    record.update(action="imported", import_id=import_id, run_id=item["run_id"])
    if item["state"] != "snapshotted" or not item["run_id"]:
        reason = item.get("error") or item["state"]
        raise VeriFlowError(f"Intake did not produce a snapshot ({reason}); fix it, use --reimport")
    return item["run_id"]


def attempt_state(store, attempt_id, with_digest=False):
    with store.transaction() as session:
        attempt = session.get(ScanAttempt, attempt_id)
        count = session.scalar(
            select(func.count()).select_from(Candidate).where(Candidate.attempt_id == attempt_id)
        )
        state = attempt.report.get("status", "unknown"), count
        return (*state, attempt.report.get("query_sha256")) if with_digest else state


def prior_attempts(store, run_id):
    latest = {}
    with store.transaction() as session:
        for attempt in session.scalars(
            select(ScanAttempt)
            .where(ScanAttempt.run_id == run_id)
            .order_by(ScanAttempt.created_at, ScanAttempt.id)
        ):
            report = attempt.report
            if (report.get("scanner") or {}).get("engine_id") != "joern":
                continue
            latest[(report.get("language"), report.get("discovery_profile") or "default")] = (
                attempt.id
            )
    return latest


def scan_profiles(store, run_id, plan, options, log, profiles):
    """Append to profiles as each pair finishes, so a later crash keeps earlier results."""
    previous = prior_attempts(store, run_id)
    for language, profile in plan:
        name = profile or "default"
        entry = {
            "language": language,
            "discovery_profile": name,
            "review_policy": policy_for(language, profile, store),
            "attempt_id": None,
            "report_id": None,
        }
        profiles.append(entry)
        if language not in joern_profiles.LANGUAGES:
            entry.update(status="unsupported_language", action="none")
            log.write(step=f"scan {language}/{name}", status="skipped", reason=entry["status"])
            continue
        selected = joern_profiles.binding(language, profile, store)
        entry["profile_source"] = selected.source
        prior = previous.get((language, name))
        reason = "not_scanned"
        if prior is not None:
            status, count, digest = attempt_state(store, prior, with_digest=True)
            # A failed attempt may not have recorded a query; report the failure first.
            if status not in USABLE:
                reason = "previous_attempt_failed"
            elif digest != selected.query_sha256:
                reason = "query_changed"
            elif count == 0 and options.rescan_empty:
                reason = "empty_rescan_requested"
            else:
                reason = None
        with log.step(f"scan {language}/{name}") as record:
            if reason is None:
                entry.update(action="reused", attempt_id=prior)
            else:
                entry["action"] = "scanned"
                record["reason"] = reason
                try:
                    result = with_retry(
                        log,
                        f"scan {language}/{name}",
                        lambda language=language, profile=profile: joern_pipeline.scan_run(
                            store,
                            run_id,
                            language,
                            options.joern_home,
                            options.joern_repair_dir,
                            options.rust_home,
                            options.extraction_timeout,
                            options.query_timeout,
                            False,
                            profile,
                        ),
                    )
                except Exception as exc:
                    status = "scope_error" if isinstance(exc, VeriFlowError) else "scan_error"
                    entry.update(status=status, error=safe_error(exc))
                    record.update(status="failed", error=safe_error(exc))
                    continue
                entry["attempt_id"] = result["attempt_id"]
            status, count = attempt_state(store, entry["attempt_id"])
            entry.update(
                analysis_status=status,
                candidate_count=count,
                status="scanned" if status in USABLE else "scan_failed",
            )
            record.update(
                action=entry["action"],
                attempt_id=entry["attempt_id"],
                analysis_status=status,
                candidates=count,
            )
            if status not in USABLE:
                record["status"] = "failed"


def discover(store, detected, profiles, options, log, passes, breaker):
    digest = config_digest(options.discovery.config)[:16]
    for language in detected:
        anchor = discovery_anchor(profiles, language)
        if language not in DISCOVERY_SUFFIXES or anchor is None or breaker.tripped:
            state = (
                "unsupported_language"
                if language not in DISCOVERY_SUFFIXES
                else "no_usable_attempt"
                if anchor is None
                else "provider_unavailable"
            )
            passes.append({"language": language, "state": state})
            log.write(step=f"llm-discovery {language}", status="skipped", reason=state)
            continue
        with log.step(f"llm-discovery {language}", attempt_id=anchor["attempt_id"]) as record:
            key = f"pipeline-discovery:{anchor['attempt_id']}:{digest}"
            try:
                result = with_retry(
                    log,
                    f"llm-discovery {language}",
                    lambda anchor=anchor, key=key: run_hybrid_discovery(
                        store, anchor["attempt_id"], replace(options.discovery, request_key=key)
                    ),
                )
            except Exception as exc:
                passes.append({"language": language, "state": "failed", "reason": safe_error(exc)})
                record.update(status="failed", error=safe_error(exc))
                continue
            if result.get("provider_invocations"):
                breaker.record(result["state"])
            _, anchor["candidate_count"] = attempt_state(store, anchor["attempt_id"])
            passes.append(
                {
                    "language": language,
                    "attempt_id": anchor["attempt_id"],
                    "state": result["state"],
                    "candidate_rows_created": result.get("candidate_rows_created", 0),
                    "live_model_calls": result.get("live_model_calls", 0),
                    "selection": result.get("selection"),
                }
            )
            record.update(
                state=result["state"],
                candidates_created=result.get("candidate_rows_created", 0),
            )
            if result["state"] != "completed":
                record["status"] = "failed"


def request_key(store, run_id, identity, retry_unknown):
    """Stable per request identity; a new generation only when an unknown call is retried."""
    base = "pipeline-triage:" + hashlib.sha256(canonical(identity)).hexdigest()[:56]
    with store.transaction() as session:
        stored = dict(
            session.execute(
                select(TriageCall.request_key, TriageCall.state).where(
                    TriageCall.run_id == run_id, TriageCall.request_key.startswith(base + ":")
                )
            ).all()
        )
    generation = len(stored)
    if generation and not (retry_unknown and stored.get(f"{base}:{generation - 1}") == "unknown"):
        generation -= 1
    return f"{base}:{generation}"


def fingerprints(store, attempt_id):
    with store.transaction() as session:
        return list(
            session.scalars(
                select(Candidate.fingerprint)
                .where(Candidate.attempt_id == attempt_id)
                .order_by(Candidate.fingerprint)
            )
        )


def triage_candidates(store, run_id, entry, options, adapter, log, name, states, breaker):
    """Triage each candidate with the gate matching its origin; returns a stop reason."""
    config = config_digest(options.config)
    for fingerprint in fingerprints(store, entry["attempt_id"]):
        if breaker.tripped:
            return "provider_unavailable"
        try:
            bundle = with_retry(
                log,
                name,
                lambda fingerprint=fingerprint: build_bundle(
                    store, entry["attempt_id"], fingerprint, options.envelope
                ),
            )
        except Exception as exc:
            states["operation_error"] += 1
            log.write(
                step=name,
                status="candidate_failed",
                candidate=fingerprint[:16],
                error=safe_error(exc),
            )
            continue
        # Exploratory candidates must meet the exploratory gate, never a Joern profile gate.
        llm_origin = bundle_engine(bundle) == "llm_discovery"
        policy = None if llm_origin else entry["review_policy"]
        if policy is None and not llm_origin and not options.ungated_triage:
            states["skipped_ungated"] += 1
            continue
        identity = [
            config,
            adapter.identity,
            entry["attempt_id"],
            fingerprint,
            bundle["bundle_id"],
            policy,
            options.unmetered,
            options.allow_degraded_evidence,
        ]
        before = adapter.calls
        try:
            key = request_key(store, run_id, identity, options.retry_unknown)
            result = with_retry(
                log,
                name,
                lambda key=key, policy=policy, bundle_id=bundle["bundle_id"]: triage(
                    store,
                    bundle_id,
                    options.config,
                    adapter,
                    key,
                    review_policy=policy,
                    unmetered=options.unmetered,
                    allow_degraded_evidence=options.allow_degraded_evidence,
                ),
            )
        except Exception as exc:
            states["operation_error"] += 1
            log.write(
                step=name,
                status="candidate_failed",
                candidate=fingerprint[:16],
                error=safe_error(exc),
            )
            continue
        state = result["state"]
        states[state] += 1
        if adapter.calls > before:
            breaker.record(state)
        if state not in {"completed", "evidence_rejected", "advisory_unverified"}:
            log.write(step=name, status="candidate_result", candidate=fingerprint[:16], state=state)
        if state in RUN_STOP_STATES:
            return state
    return None


def triage_profiles(store, run_id, profiles, options, log, breaker):
    adapter = CountingAdapter(options.adapter)
    totals = Counter()
    stopped = None
    for entry in profiles:
        if entry.get("status") != "scanned" or not entry.get("candidate_count"):
            continue
        name = f"triage {entry['language']}/{entry['discovery_profile']}"
        reason = stopped or ("provider_unavailable" if breaker.tripped else None)
        if reason:
            entry["triage"] = {"status": "not_started", "reason": reason}
            log.write(step=name, status="skipped", reason=reason)
            continue
        with log.step(name, review_policy=entry["review_policy"] or "none (ungated)") as record:
            before = adapter.calls
            states = Counter()
            try:
                stopped = triage_candidates(
                    store, run_id, entry, options, adapter, log, name, states, breaker
                )
            except Exception as exc:
                entry["triage"] = {
                    "status": "failed",
                    "error": safe_error(exc),
                    "states": dict(states),
                }
                record.update(status="failed", error=safe_error(exc))
                continue
            entry["triage"] = {
                "status": "stopped" if stopped else "completed",
                "states": dict(states),
                "provider_calls": adapter.calls - before,
                **({"reason": stopped} if stopped else {}),
            }
            totals.update(states)
            record.update(states=dict(states), provider_calls=adapter.calls - before)
            if stopped:
                record.update(status="stopped", reason=stopped)
            elif set(states) - {"completed", "evidence_rejected", "advisory_unverified"}:
                record["status"] = "completed_with_gaps"
    return {"states": dict(totals), "provider_calls": adapter.calls, "stopped": stopped}


def model_verdicts(store, report):
    """Unverified model verdicts by candidate; gates may still have recorded abstain."""
    calls = {
        row["fingerprint"]: row["triage_history"][-1]["call_id"]
        for row in report["candidates"]
        if row["triage_history"]
    }
    if not calls:
        return {}
    with store.transaction() as session:
        results = dict(
            session.execute(
                select(TriageCall.id, TriageCall.result).where(TriageCall.id.in_(calls.values()))
            ).all()
        )
    return {
        fingerprint: ((results.get(call) or {}).get("decision") or {}).get("verdict")
        for fingerprint, call in calls.items()
    }


def paged(fetch, key):
    """Collect every page of a bounded history call into one document."""
    first = fetch(0)
    items = list(first[key])
    while len(items) < first["total"]:
        page = fetch(len(items))[key]
        if not page:
            break
        items.extend(page)
    return {**first, key: items, "offset": 0, "limit": len(items)}


def export_profile(store, repo_id, run_id, entry, directory, log):
    name = f"{entry['language']}-{entry['discovery_profile']}"
    with log.step(f"export {name}", attempt_id=entry["attempt_id"]) as record:
        try:
            published = with_retry(
                log,
                f"export {name}",
                lambda: publish_report(store, repo_id, run_id, entry["attempt_id"]),
            )
            report = get_report(store, repo_id, report_id=published["report_id"])
        except Exception as exc:
            entry["export_error"] = safe_error(exc)
            record.update(status="failed", error=safe_error(exc))
            return
        entry.update(report_id=published["report_id"], report=report)
        entry["model_verdicts"] = model_verdicts(store, report)
        target = directory / name
        target.mkdir(exist_ok=True)
        for filename, fmt in REPORT_FILES.items():
            (target / filename).write_text(render_report(report, fmt), encoding="utf-8")
        files = list(REPORT_FILES)
        total = entry.get("candidate_count") or 0
        pages = max(1, -(-total // PAGE))
        for page in range(pages):
            scan = scan_report(store, repo_id, run_id, entry["attempt_id"], page * PAGE, PAGE)
            filename = "scan-report.md" if pages == 1 else f"scan-report-{page + 1:03d}.md"
            (target / filename).write_text(scan_report_markdown(scan), encoding="utf-8")
            files.append(filename)
        if entry.get("analysis_status") in USABLE:
            from veriflow.sarif_export import get_sarif

            try:
                (target / "results.sarif").write_bytes(
                    get_sarif(store, repo_id, entry["attempt_id"])
                )
                files.append("results.sarif")
            except VeriFlowError as exc:
                record["sarif"] = str(exc)
        record.update(report_id=published["report_id"], files=files)


def export(store, repo_id, run_id, profiles, directory, discovery_used, log):
    for entry in profiles:
        if entry.get("attempt_id"):
            export_profile(store, repo_id, run_id, entry, directory, log)
    with log.step("export run ledgers", run_id=run_id) as record:
        ledger = paged(lambda offset: triage_report(store, run_id, offset, PAGE), "calls")
        (directory / "triage-ledger.json").write_text(render_json(ledger), encoding="utf-8")
        files = ["triage-ledger.json"]
        if discovery_used:
            from veriflow.llm_discovery import discovery_report

            history = paged(
                lambda offset: discovery_report(store, run_id, None, offset, PAGE), "calls"
            )
            (directory / "discovery-report.json").write_text(render_json(history), encoding="utf-8")
            files.append("discovery-report.json")
        record.update(files=files, triage_calls=len(ledger["calls"]))
    return ledger


def normalized(row):
    if None in row or any(value is None for value in row.values()):
        raise VeriFlowError("CSV row has a different field count from its header")
    # Intake strips whitespace; comparing raw values would break every later resume.
    return {key: value.strip() for key, value in row.items()}


def run_repository(
    store, header, number, row, input_root, output, options, log, stamp, seen, breaker
):
    repo_id = (row.get("repo_id") or "").strip()
    duplicate = seen.get(repo_id.lower()) if repo_id else None
    folder = repo_id if SAFE_NAME.fullmatch(repo_id) and duplicate is None else f"row-{number:06d}"
    if repo_id and duplicate is None:
        seen[repo_id.lower()] = number
    directory = output / folder
    directory.mkdir(parents=True, exist_ok=True)
    log.begin_repo(repo_id or folder, directory)
    started = time.monotonic()
    state = {
        "repo_id": repo_id or None,
        "row_number": number,
        "directory": folder,
        "run_id": None,
        "snapshot_id": None,
        "detected_languages": [],
        "profiles": [],
        "discovery": None,
        "triage": None,
        "ledger": None,
        "failure": None,
    }
    try:
        with log.step("preflight") as record:
            if not repo_id:
                raise VeriFlowError("CSV row has no repo_id")
            if duplicate is not None:
                raise VeriFlowError(f"Duplicate repo_id; row {duplicate} already processed it")
            row = normalized(row)
            classification = row.get("classification")
            for label, config in [("advisory", options.config)] + (
                [("LLM discovery", options.discovery.config)] if options.discovery else []
            ):
                if classification not in config.allowed_classifications:
                    raise VeriFlowError(
                        f"Classification is not allowed by the {label} config; "
                        "add it to allowed_classifications"
                    )
            record["classification"] = classification
        with log.step("import") as record:
            state["run_id"] = ensure_import(
                store, header, row, input_root, directory, options, stamp, record, log
            )
        if not options.unmetered:
            with log.step("budget", run_id=state["run_id"]):
                with_retry(
                    log,
                    "budget",
                    lambda: set_budget(
                        store, state["run_id"], options.budget_micro_usd, options.max_requests
                    ),
                )
        with log.step("select", run_id=state["run_id"]) as record:
            run, manifest, _ = verified_source(store, state["run_id"])
            state["snapshot_id"] = manifest.snapshot_id
            detected, plan = joern_selection.selection(manifest, "auto", store)
            state["detected_languages"] = detected
            record.update(detected_languages=detected, profiles=len(plan))
        scan_profiles(store, state["run_id"], plan, options, log, state["profiles"])
        if options.discovery is not None:
            state["discovery"] = []
            discover(store, detected, state["profiles"], options, log, state["discovery"], breaker)
        state["triage"] = triage_profiles(
            store, state["run_id"], state["profiles"], options, log, breaker
        )
        state["ledger"] = export(
            store,
            repo_id,
            state["run_id"],
            state["profiles"],
            directory,
            options.discovery is not None,
            log,
        )
    except Exception as exc:
        state["failure"] = {"step": log.steps[-1]["step"] if log.steps else None}
        state["failure"]["error"] = safe_error(exc)
    state["duration_seconds"] = round(time.monotonic() - started, 3)
    state["steps"] = list(log.steps)
    with log.step("summary") as record:
        summary = repository_summary(state, options)
        write_summary(directory / "summary", summary)
        record.update(status_of_repo=summary["status"], candidates=summary["stats"]["candidates"])
    log.end_repo()
    return summary


def run_pipeline(store, manifest, input_root, output, options, echo=None):
    """Process CSV rows strictly one at a time; one failed repository never stops the rest."""
    header, rows = read_manifest(manifest)
    input_root = input_root.resolve(strict=True)
    with pipeline_lock(store.root):
        output.mkdir(parents=True, exist_ok=True)
        log = PipelineLog(output, echo)
        breaker = ProviderBreaker()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        started_at, started = now(), time.monotonic()
        with log.step("initialize", rows=len(rows)) as record:
            store.initialize()
            preflight(options)
            catalog = joern_profiles.catalog(store)
            profile_catalog = {
                "mode": catalog.mode,
                "registry_version": catalog.registry_version,
                "runtime_profiles": sorted(
                    {f"{b.name} ({b.source})" for b in catalog.bindings if b.source != "packaged"}
                ),
                "problems": list(catalog.problems),
                "ignored_directory_profiles": list(catalog.ignored),
            }
            record.update(
                profile_mode=catalog.mode,
                registry_version=catalog.registry_version,
                runtime_profiles=len(profile_catalog["runtime_profiles"]),
                profile_problems=len(catalog.problems),
            )
            for problem in catalog.problems:
                log.write(step="profile catalog", status="profile_skipped", **problem)
            if catalog.ignored:
                log.write(
                    step="profile catalog",
                    status="directory_ignored",
                    reason="approved mode loads only packaged and approved profiles",
                    profiles=list(catalog.ignored),
                )
        seen = {}
        results = [
            run_repository(
                store, header, number, row, input_root, output, options, log, stamp, seen, breaker
            )
            for number, row in rows
        ]
        summary = run_summary(
            results,
            options,
            started_at=started_at,
            duration_seconds=round(time.monotonic() - started, 3),
            manifest_name=manifest.name,
            provider_unavailable=breaker.tripped,
            profile_catalog=profile_catalog,
        )
        write_summary(output / "summary", summary)
        log.write(step="pipeline", status=summary["status"], repositories=len(results))
    return {
        "schema_version": "1",
        "report_kind": "pipeline_run",
        "status": summary["status"],
        "output_dir": str(output),
        "repositories": [
            {key: item[key] for key in ("repo_id", "status", "run_id", "directory", "failure")}
            | {"candidates": item["stats"]["candidates"]}
            for item in results
        ],
        "provider_unavailable": breaker.tripped,
        "security_verdict": "not_adjudicated",
        "scope": "Candidates and advisory outcomes only; zero candidates is not a clean result",
    }
