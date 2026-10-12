import csv
import json
import zipfile
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_triage import FakeAdapter, policy
from typer.testing import CliRunner

from veriflow import csv_pipeline, joern, joern_selection, pipeline
from veriflow.cli import app
from veriflow.csv_pipeline import PipelineOptions, run_pipeline
from veriflow.domain import VeriFlowError
from veriflow.joern_claims import policy_for
from veriflow.llm_discovery import DiscoveryOptions
from veriflow.models import ModelConfig
from veriflow.pipeline_summary import render_html, render_markdown, repository_summary

FIXTURES = Path(__file__).parent / "fixtures"
FLOW = json.loads((FIXTURES / "joern-spring-evidence/native-flow.json").read_text())


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    home = tmp_path / "tools"
    (home / "lib").mkdir(parents=True)
    (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()
    flows = {"doc": FLOW}

    def fake(command, root, name, timeout):
        if name == "analyze":
            (root / "flows.json").write_text(json.dumps(flows["doc"]))

    monkeypatch.setattr(joern, "stage", fake)
    # One Java profile keeps the synthetic native document matched to its decoder.
    monkeypatch.setitem(joern_selection.PROFILES, "java", (None,))

    def archive(name="source.zip", files=None):
        path = inputs / name
        if path.exists() and files is None:
            # Rewriting changes ZIP timestamps, which the resume check rightly reports.
            return path
        with zipfile.ZipFile(path, "w") as out:
            for item in (FIXTURES / "joern-java/vulnerable").glob("*.java"):
                out.writestr(item.name, item.read_text())
            for key, text in (files or {}).items():
                out.writestr(key, text)
        return path

    def manifest(rows):
        path = tmp_path / "repos.csv"
        with path.open("w", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return path

    def row(path, repo_id="example"):
        return {
            "repo_id": repo_id,
            "source_type": "pvc",
            "source_uri": str(path),
            "owner": "tests",
            "classification": "synthetic",
        }

    return SimpleNamespace(
        inputs=inputs,
        home=home,
        flows=flows,
        archive=archive,
        manifest=manifest,
        row=row,
        output=tmp_path / "out",
    )


def options(ws, adapter=None, **changes):
    return PipelineOptions(
        config=policy(), adapter=adapter or FakeAdapter(), joern_home=ws.home, **changes
    )


def run(store, ws, opts, rows=None, echo=None):
    rows = rows or [ws.row(ws.archive())]
    return run_pipeline(
        store, ws.manifest(rows), ws.inputs, ws.output, opts, echo or (lambda line: None)
    )


def read_summary(ws, folder="example"):
    return json.loads((ws.output / folder / "summary.json").read_text())


def step(summary, prefix):
    return [s for s in summary["steps"] if s["step"].startswith(prefix)]


def test_end_to_end_then_resume_without_new_calls(store, workspace):
    ws = workspace
    adapter = FakeAdapter()
    lines = []
    result = run(store, ws, options(ws, adapter), echo=lines.append)
    assert result["repositories"][0]["status"] == "completed"
    summary = read_summary(ws)
    candidates = summary["stats"]["candidates"]
    assert candidates >= 1 and adapter.calls == candidates
    assert summary["stats"]["triaged"] == candidates
    assert summary["profiles"][0]["review_policy"] == "joern-spring-review-v1"
    assert summary["verified_finding_count"] is None
    assert step(summary, "import")[0]["action"] == "imported"
    folder = ws.output / "example" / "java-default"
    for name in (*csv_pipeline.REPORT_FILES, "scan-report.md", "results.sarif"):
        assert (folder / name).is_file(), name
    for name in ("triage-ledger.json", "steps.log", "summary.md", "summary.html", "intake.csv"):
        assert (ws.output / "example" / name).is_file(), name
    for name in ("pipeline.log", "summary.json", "summary.md", "summary.html"):
        assert (ws.output / name).is_file(), name
    events = [json.loads(x) for x in (ws.output / "pipeline.log").read_text().splitlines()]
    assert {e["step"] for e in events} >= {"initialize", "import", "select", "pipeline"}
    assert any("triage java/default" in line for line in lines)

    again = run(store, ws, options(ws, adapter))
    assert again["repositories"][0]["run_id"] == result["repositories"][0]["run_id"]
    resumed = read_summary(ws)
    assert adapter.calls == candidates
    assert step(resumed, "import")[0]["action"] == "reused"
    assert step(resumed, "scan java/default")[0]["action"] == "reused"
    assert resumed["stats"]["triaged"] == candidates


def test_budget_stop_resumes_triage_when_run_unmetered(store, workspace):
    ws = workspace
    first = run(store, ws, options(ws, FakeAdapter(), unmetered=False, budget_micro_usd=0))
    halted = read_summary(ws)
    assert first["repositories"][0]["status"] == "partial"
    assert halted["stats"]["by_triage_state"] == {"budget_exhausted": 1}
    assert any("no model answer" in problem for problem in halted["problems"])
    adapter = FakeAdapter()
    run(store, ws, options(ws, adapter))
    assert adapter.calls == 1
    assert "budget_exhausted" not in read_summary(ws)["stats"]["by_triage_state"]
    with pytest.raises(VeriFlowError, match="metered run requires"):
        run(store, ws, options(ws, adapter, unmetered=False))


def test_empty_profile_rescanned_only_with_flag(store, workspace):
    ws = workspace
    ws.flows["doc"] = {**FLOW, "paths": [], "flow_count": 0}
    run(store, ws, options(ws))
    assert read_summary(ws)["stats"]["candidates"] == 0
    run(store, ws, options(ws))
    assert step(read_summary(ws), "scan java/default")[0]["action"] == "reused"
    ws.flows["doc"] = FLOW
    run(store, ws, options(ws, rescan_empty=True))
    rescanned = read_summary(ws)
    assert step(rescanned, "scan java/default")[0]["reason"] == "empty_rescan_requested"
    assert rescanned["stats"]["candidates"] >= 1


def test_changed_archive_requires_reimport(store, workspace):
    ws = workspace
    rows = [ws.row(ws.archive())]
    first = run(store, ws, options(ws), rows)
    ws.archive(files={"Extra.java": "class Extra {}\n"})
    blocked = run(store, ws, options(ws), rows)
    assert blocked["status"] == "failed"
    assert "--reimport" in blocked["repositories"][0]["failure"]["error"]
    again = run(store, ws, options(ws, reimport=True), rows)
    assert again["repositories"][0]["status"] == "completed"
    assert again["repositories"][0]["run_id"] != first["repositories"][0]["run_id"]


def test_failed_repository_does_not_stop_the_next(store, workspace):
    ws = workspace
    good = ws.archive()
    rows = [ws.row(ws.inputs / "missing.zip", "broken"), ws.row(good, "example")]
    result = run(store, ws, options(ws), rows)
    assert [r["status"] for r in result["repositories"]] == ["failed", "completed"]
    assert result["status"] == "failed"
    broken = read_summary(ws, "broken")
    assert broken["failure"]["step"] == "import" and broken["status"] == "failed"
    run_summary = json.loads((ws.output / "summary.json").read_text())
    assert run_summary["repository_statuses"] == {"failed": 1, "completed": 1}


def test_disallowed_classification_fails_that_row_only(store, workspace):
    ws = workspace
    row = ws.row(ws.archive()) | {"classification": "restricted"}
    result = run(store, ws, options(ws), [row])
    assert "allowed_classifications" in result["repositories"][0]["failure"]["error"]


def test_llm_discovery_only_with_flag(store, workspace, monkeypatch):
    ws = workspace
    calls = []

    def fake(store, attempt_id, discovery):
        calls.append((attempt_id, discovery.request_key))
        return {"state": "completed", "candidate_rows_created": 0, "live_model_calls": 0}

    monkeypatch.setattr(csv_pipeline, "run_hybrid_discovery", fake)
    run(store, ws, options(ws))
    assert calls == []
    discovery = DiscoveryOptions(policy(), None, "pipeline")
    run(store, ws, options(ws, discovery=discovery))
    summary = read_summary(ws)
    assert len(calls) == 1 and calls[0][1].startswith(f"pipeline-discovery:{calls[0][0]}:")
    assert summary["llm_discovery_passes"][0]["state"] == "completed"
    assert summary["llm_discovery"] is True


def test_preflight_rejects_live_config_without_transmission(store, workspace):
    ws = workspace
    live = ModelConfig(
        provider="openai",
        model="m",
        endpoint="https://api.openai.com/v1/responses",
        allowed_endpoint_hosts=["api.openai.com"],
        input_micro_usd_per_1k=1,
        output_micro_usd_per_1k=1,
    )
    with pytest.raises(VeriFlowError, match="disables live source transmission"):
        run(store, ws, PipelineOptions(config=live, adapter=None, joern_home=ws.home))
    with pytest.raises(VeriFlowError, match="Joern home"):
        run(store, ws, PipelineOptions(config=policy(), adapter=None, joern_home=ws.inputs / "x"))


def test_policy_for_maps_only_reviewed_profiles():
    assert policy_for("java", None) == "joern-spring-review-v1"
    assert policy_for("python", "python-flask-system-v1") == "joern-flask-review-v1"
    assert policy_for("python", "python-flask-sql-v1") is None
    assert policy_for("kotlin", None) is None


def test_selected_discovery_runs_per_language(monkeypatch):
    from veriflow import llm_discovery

    seen = []

    def fake(store, attempt_id, options):
        seen.append((attempt_id, options.request_key))
        return {"state": "completed", "provider_invocations": 1, "live_model_calls": 0}

    monkeypatch.setattr(llm_discovery, "run_hybrid_discovery", fake)
    monkeypatch.setattr(
        pipeline,
        "publish_report",
        lambda store, repo, run, attempt: {"report_id": f"r-{attempt}", "candidate_count": 3},
    )
    result = {
        "repo_id": "repo",
        "detected_languages": ["go", "java", "kotlin", "python"],
        "items": [
            {"language": "java", "attempt_id": "j0", "analysis_status": "failed"},
            {
                "language": "java",
                "attempt_id": "j1",
                "analysis_status": "partial",
                "discovery_profile": "java-spring-file-path-v1",
                "report_id": "old",
            },
            {"language": "go", "status": "scope_error", "report_id": None},
            {"language": "kotlin", "status": "unsupported_language", "report_id": None},
        ],
        "model_calls": 0,
    }
    options = DiscoveryOptions(policy(), None, "key")
    merged = pipeline._selected_discovery(None, "run", result, options)
    assert seen == [("j1", "key:java")]
    states = {p["language"]: p["state"] for p in merged["llm_discovery"]["passes"]}
    assert states == {
        "go": "skipped_deterministic_incomplete",
        "java": "completed",
        "kotlin": "unsupported_language",
    }
    assert merged["report_ids"] == ["r-j1"] and merged["model_calls"] == 1
    assert merged["hybrid_status"] == "partial"


def test_summary_escapes_report_values():
    state = {
        "repo_id": "repo",
        "row_number": 2,
        "run_id": "run",
        "snapshot_id": "snap",
        "detected_languages": ["python"],
        "profiles": [
            {
                "language": "python",
                "discovery_profile": "python-flask-sql-v1",
                "review_policy": None,
                "status": "scanned",
                "candidate_count": 1,
                "report": {
                    "report_id": "r" * 64,
                    "candidates": [
                        {
                            "latest_advisory": "needs_review",
                            "triage_history": [{"state": "completed", "evidence_degraded": []}],
                            "rule_id": "<script>alert(1)</script>",
                            "path": "a|b.py",
                            "line": 3,
                            "fingerprint": "f" * 64,
                        }
                    ],
                },
            }
        ],
        "steps": [],
    }
    opts = SimpleNamespace(
        config=policy(), unmetered=True, allow_degraded_evidence=True, discovery=None
    )
    summary = repository_summary(state, opts)
    assert summary["status"] == "completed" and summary["stats"]["ungated_candidates"] == 1
    assert any("no reviewed evidence gate" in gap for gap in summary["coverage_gaps"])
    assert "<script>" not in render_html(summary)
    assert "<script>" not in render_markdown(summary)


def test_cli_defaults(monkeypatch, tmp_path):
    received = {}

    def fake(store, manifest, input_root, output, opts, echo=None):
        received.update(output=output, options=opts)
        return {"status": "partial", "repositories": []}

    monkeypatch.setattr(csv_pipeline, "run_pipeline", fake)
    config = tmp_path / "advisory.json"
    config.write_text(json.dumps({"provider": "replay", "model": "fixture"}))
    replay = tmp_path / "replay.json"
    replay.write_text("{}")
    base = [
        "--state-dir",
        str(tmp_path / "state"),
        "run-pipeline-from-csv",
        str(tmp_path / "repos.csv"),
        "--input-root",
        str(tmp_path),
        "--advisory-config",
        str(config),
        "--joern-home",
        str(tmp_path),
        "--replay",
        str(replay),
    ]
    result = CliRunner().invoke(app, base)
    assert result.exit_code == 0, result.output
    opts = received["options"]
    assert opts.unmetered and opts.allow_degraded_evidence and opts.discovery is None
    assert not opts.rescan_empty and not opts.reimport
    assert received["output"].parent == Path("work/pipeline")
    result = CliRunner().invoke(
        app,
        base
        + [
            "--llm-discovery",
            "--llm-discovery-replay",
            str(replay),
            "--output-dir",
            str(tmp_path / "o"),
            "--no-unmetered",
        ],
    )
    assert result.exit_code == 0, result.output
    opts = received["options"]
    assert opts.discovery.config == opts.config and not opts.discovery.unmetered
    assert received["output"] == tmp_path / "o" and not opts.unmetered
    result = CliRunner().invoke(app, base + ["--budget-micro-usd", "5"])
    assert result.exit_code == 1 and "require --no-unmetered" in result.output


def test_unknown_is_retried_only_on_request(store, workspace):
    ws = workspace
    run(store, ws, options(ws, FakeAdapter(error=OSError("provider down"))))
    failed = read_summary(ws)
    assert failed["status"] == "partial"
    assert failed["stats"]["by_triage_state"] == {"unknown": 1}
    adapter = FakeAdapter()
    run(store, ws, options(ws, adapter))
    assert adapter.calls == 0
    run(store, ws, options(ws, adapter, retry_unknown=True))
    assert adapter.calls == 1
    assert "unknown" not in read_summary(ws)["stats"]["by_triage_state"]


def test_breaker_stops_provider_traffic_for_the_run(store, workspace, monkeypatch):
    ws = workspace
    monkeypatch.setattr(csv_pipeline, "BREAKER_LIMIT", 1)
    rows = [ws.row(ws.archive(), "first"), ws.row(ws.archive("b.zip", {"B.java": ""}), "second")]
    adapter = FakeAdapter(error=OSError("provider down"))
    result = run(store, ws, options(ws, adapter), rows)
    assert result["provider_unavailable"] is True and adapter.calls == 1
    second = read_summary(ws, "second")
    assert second["profiles"][0]["triage"] == {
        "status": "not_started",
        "reason": "provider_unavailable",
    }


def test_envelope_change_triages_again_without_key_conflict(store, workspace):
    from veriflow.envelope import resolve

    ws = workspace
    run(store, ws, options(ws, FakeAdapter()))
    adapter = FakeAdapter()
    run(store, ws, options(ws, adapter, envelope=resolve(None, {"max_locations": 4})))
    summary = read_summary(ws)
    assert adapter.calls == 1
    assert "operation_error" not in json.dumps(summary["profiles"])


def test_whitespace_in_csv_values_still_resumes(store, workspace):
    ws = workspace
    row = {key: f" {value} " for key, value in ws.row(ws.archive()).items()}
    first = run(store, ws, options(ws), [row])
    again = run(store, ws, options(ws), [row])
    assert again["repositories"][0]["run_id"] == first["repositories"][0]["run_id"]
    assert step(read_summary(ws), "import")[0]["action"] == "reused"


def test_reordered_columns_do_not_collide_with_a_failed_import(store, workspace):
    ws = workspace
    bad = ws.row(ws.inputs / "missing.zip", "other")
    run(store, ws, options(ws), [bad])
    reordered = {key: bad[key] for key in reversed(list(bad))}
    result = run(store, ws, options(ws), [reordered])
    error = result["repositories"][0]["failure"]["error"]
    assert "Idempotency" not in error and "snapshot" in error


def test_scan_crash_keeps_profile_rows_and_continues(store, workspace, monkeypatch):
    from veriflow import joern_pipeline

    ws = workspace

    def boom(*args, **kwargs):
        raise RuntimeError("synthetic crash with /private/source/text")

    monkeypatch.setattr(joern_pipeline, "scan_run", boom)
    result = run(store, ws, options(ws))
    summary = read_summary(ws)
    assert result["repositories"][0]["status"] == "partial"
    assert summary["profiles"][0]["status"] == "scan_error"
    assert "source/text" not in json.dumps(summary)


def test_reimport_only_changed_rows_and_force_reimport_all(store, workspace):
    ws = workspace
    rows = [ws.row(ws.archive(), "first"), ws.row(ws.archive("b.zip", {"B.java": ""}), "second")]
    before = {r["repo_id"]: r["run_id"] for r in run(store, ws, options(ws), rows)["repositories"]}
    ws.archive(files={"Extra.java": "class Extra {}\n"})
    after = run(store, ws, options(ws, reimport=True), rows)["repositories"]
    assert after[0]["run_id"] != before["first"] and after[1]["run_id"] == before["second"]
    forced = run(store, ws, options(ws, force_reimport=True), rows)["repositories"]
    assert forced[1]["run_id"] != before["second"]


def test_duplicate_repo_rows_fail_without_overwriting(store, workspace):
    ws = workspace
    row = ws.row(ws.archive())
    result = run(store, ws, options(ws), [row, dict(row)])
    assert [r["status"] for r in result["repositories"]] == ["completed", "failed"]
    assert result["repositories"][1]["directory"] == "row-000003"
    assert read_summary(ws)["status"] == "completed"
    assert "Duplicate repo_id" in read_summary(ws, "row-000003")["failure"]["error"]


def test_paged_collects_every_page():
    calls = list(range(2500))

    def fetch(offset):
        return {"total": len(calls), "calls": calls[offset : offset + 1000], "offset": offset}

    assert csv_pipeline.paged(fetch, "calls")["calls"] == calls


def test_llm_candidates_use_exploratory_gate_and_ungated_can_be_skipped(monkeypatch):
    seen = []
    engines = {"det": "joern", "llm": "llm_discovery"}
    monkeypatch.setattr(csv_pipeline, "fingerprints", lambda store, attempt: ["det", "llm"])
    monkeypatch.setattr(
        csv_pipeline,
        "build_bundle",
        lambda store, attempt, fp, envelope: {"bundle_id": fp, "engine_id": engines[fp]},
    )
    monkeypatch.setattr(csv_pipeline, "request_key", lambda *args: "k")

    def fake_triage(store, bundle_id, config, adapter, key, *, review_policy, **kwargs):
        seen.append((bundle_id, review_policy))
        return {"state": "completed"}

    monkeypatch.setattr(csv_pipeline, "triage", fake_triage)
    log = csv_pipeline.PipelineLog(Path("/nonexistent"), lambda line: None)
    log.path = None
    entry = {"attempt_id": "a", "review_policy": "joern-spring-review-v1"}
    opts = PipelineOptions(config=policy(), adapter=FakeAdapter(), joern_home=Path("."))
    states = Counter()
    adapter = csv_pipeline.CountingAdapter(FakeAdapter())
    breaker = csv_pipeline.ProviderBreaker()
    csv_pipeline.triage_candidates(None, "run", entry, opts, adapter, log, "t", states, breaker)
    assert seen == [("det", "joern-spring-review-v1"), ("llm", None)]
    seen.clear()
    ungated = {**entry, "review_policy": None}
    skip = PipelineOptions(
        config=policy(), adapter=FakeAdapter(), joern_home=Path("."), ungated_triage=False
    )
    csv_pipeline.triage_candidates(None, "run", ungated, skip, adapter, log, "t", states, breaker)
    assert seen == [("llm", None)] and states["skipped_ungated"] == 1


def test_with_retry_waits_out_lock_contention(monkeypatch):
    from sqlalchemy.exc import OperationalError

    monkeypatch.setattr(csv_pipeline, "sleep", lambda seconds: None)
    log = csv_pipeline.PipelineLog(Path("/nonexistent"), lambda line: None)
    log.path = None
    errors = [
        VeriFlowError(csv_pipeline.WORKER_BUSY),
        OperationalError("BEGIN", {}, Exception("database is locked")),
    ]

    def flaky():
        if errors:
            raise errors.pop(0)
        return "done"

    assert csv_pipeline.with_retry(log, "x", flaky) == "done"
    with pytest.raises(VeriFlowError, match="different"):
        csv_pipeline.with_retry(log, "x", lambda: (_ for _ in ()).throw(VeriFlowError("different")))


def test_summary_reports_unverified_model_verdict():
    state = {
        "repo_id": "repo",
        "row_number": 2,
        "run_id": "run",
        "snapshot_id": "snap",
        "detected_languages": ["java"],
        "profiles": [
            {
                "language": "java",
                "discovery_profile": "java-spring-file-path-v1",
                "review_policy": None,
                "status": "scanned",
                "candidate_count": 2,
                "model_verdicts": {"a": "needs_review"},
                "report": {
                    "report_id": "r",
                    "candidates": [
                        {
                            "fingerprint": fp,
                            "latest_advisory": advisory,
                            "triage_history": history,
                            "rule_id": "rule",
                        }
                        for fp, advisory, history in [
                            ("a", "abstain", [{"state": "evidence_rejected"}]),
                            ("b", "not_triaged", []),
                        ]
                    ],
                },
            }
        ],
        "steps": [],
    }
    opts = SimpleNamespace(
        config=policy(), unmetered=True, allow_degraded_evidence=True, discovery=None
    )
    summary = repository_summary(state, opts)
    assert summary["findings"][0]["model_verdict"] == "needs_review"
    assert summary["stats"]["by_model_verdict"] == {"needs_review": 1, "none": 1}
    assert summary["status"] == "partial" and summary["stats"]["without_model_answer"] == 1
    assert "Model verdict (unverified)" in render_markdown(summary)
