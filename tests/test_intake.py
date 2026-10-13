import json
import subprocess
import sys

import pytest
from conftest import row
from sqlalchemy import func, inspect, select
from typer.testing import CliRunner

from veriflow.artifacts import ArtifactStore
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.intake import import_status, process, run_status, submit
from veriflow.persistence import ImportItem, Run, Snapshot, exclusive_worker


def run_worker(store, batch):
    with exclusive_worker(store.root):
        return process(store, ArtifactStore(store.root), batch)


def test_migration_repeatable(store):
    store.initialize()
    assert set(inspect(store.engine).get_table_names()) == {
        "repositories",
        "imports",
        "snapshots",
        "runs",
        "import_items",
        "import_controls",
        "alembic_version",
        "source_indexes",
        "indexed_files",
        "codeql_attempts",
        "scan_attempts",
        "candidates",
        "evidence_bundles",
        "triage_budgets",
        "triage_calls",
        "discovery_calls",
        "published_reports",
        "operator_reviews",
        "rule_drafts",
        "rule_registries",
        "rule_approvals",
        "profile_drafts",
        "profile_tests",
        "profile_approvals",
        "benchmark_scorecards",
    }
    with store.engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"


def test_mixed_rows_and_read_only_status(store, archive, manifest):
    path = manifest([row(archive), row(archive, repo_id="second", source_type="gcs")])
    batch = submit(store, path, archive.parent, "key")
    items = import_status(store, batch)["items"]
    assert [i["state"] for i in items] == ["ready", "rejected"]
    assert run_status(store, items[0]["run_id"])["state"] == "admitted"
    assert not (store.root / "artifacts").exists()
    result = run_worker(store, batch)
    assert [i["state"] for i in result["items"]] == ["snapshotted", "rejected"]
    status = run_status(store, items[0]["run_id"])
    assert status["analysis_performed"] is False
    assert status["report_status"] == "not_available"


def test_idempotency_and_conflict(store, archive, manifest):
    path = manifest([row(archive)])
    first = submit(store, path, archive.parent, "key")
    run_worker(store, first)
    assert submit(store, path, archive.parent, "key") == first
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(Run)) == 1
    path.write_text(path.read_text() + "\n")
    with pytest.raises(VeriFlowError, match="different request"):
        submit(store, path, archive.parent, "key")


def test_snapshot_reused_but_new_request_retains_new_run(store, archive, manifest):
    path = manifest([row(archive)])
    batches = [submit(store, path, archive.parent, key) for key in ["a", "b"]]
    for batch in batches:
        run_worker(store, batch)
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(Snapshot)) == 1
        assert session.scalar(select(func.count()).select_from(Run)) == 2


def test_digest_failure_is_durable_and_not_clean(store, archive, manifest):
    path = manifest([row(archive, sha256="0" * 64)])
    batch = submit(store, path, archive.parent, "key")
    item = run_worker(store, batch)["items"][0]
    assert item["state"] == "failed"
    assert "SHA-256" in item["error"]
    assert run_status(store, item["run_id"])["state"] == "failed"
    assert list((store.root / "artifacts").iterdir()) == []


def test_other_rows_continue_after_corrupt_archive(store, archive, manifest):
    corrupt = archive.parent / "corrupt.zip"
    corrupt.write_bytes(b"not an archive")
    batch = submit(store, manifest([row(corrupt), row(archive)]), archive.parent, "key")
    assert [i["state"] for i in run_worker(store, batch)["items"]] == ["failed", "snapshotted"]


def test_scoped_input_and_symlinks_rejected(store, archive, manifest, tmp_path):
    outside = tmp_path / "elsewhere.zip"
    outside.write_bytes(archive.read_bytes())
    link = archive.parent / "link.zip"
    link.symlink_to(archive)
    batch = submit(store, manifest([row(outside), row(link)]), archive.parent, "key")
    assert [i["state"] for i in import_status(store, batch)["items"]] == ["rejected", "rejected"]


def test_metadata_cannot_be_reassigned(store, archive, manifest):
    submit(store, manifest([row(archive)]), archive.parent, "first")
    second = submit(store, manifest([row(archive, owner="other")]), archive.parent, "second")
    assert import_status(store, second)["items"][0]["state"] == "rejected"


@pytest.mark.parametrize(
    "text", ["repo_id,repo_id\na,b\n", "repo_id,source_type\na,pvc\n", "", "\xff"]
)
def test_invalid_manifest_headers(store, archive, tmp_path, text):
    path = tmp_path / "bad.csv"
    path.write_bytes(text.encode("latin1"))
    with pytest.raises(VeriFlowError):
        submit(store, path, archive.parent, "key")


def test_extra_row_values_rejected_without_echoing(store, archive, manifest):
    path = manifest([row(archive)])
    path.write_text(path.read_text().rstrip() + ",secret-value\n")
    batch = submit(store, path, archive.parent, "key")
    result = import_status(store, batch)
    assert result["items"][0]["state"] == "rejected"
    assert "secret-value" not in json.dumps(result)


def test_exclusive_local_worker(store):
    with exclusive_worker(store.root):
        with pytest.raises(VeriFlowError, match="already owns"):
            with exclusive_worker(store.root):
                pass
    with exclusive_worker(store.root):
        pass


def test_process_death_after_artifact_publication_recovers(store, archive, manifest):
    batch = submit(store, manifest([row(archive)]), archive.parent, "key")
    program = """
import os, sys
from pathlib import Path
from veriflow.persistence import Store, exclusive_worker
from veriflow.artifacts import ArtifactStore
from veriflow.intake import process
store = Store(Path(sys.argv[1]))
artifacts = ArtifactStore(store.root)
capture = artifacts.capture
def die_after_publication(*args):
    capture(*args)
    os._exit(42)
artifacts.capture = die_after_publication
with exclusive_worker(store.root):
    process(store, artifacts, sys.argv[2])
"""
    child = subprocess.run([sys.executable, "-c", program, str(store.root), batch], timeout=20)
    assert child.returncode == 42
    assert import_status(store, batch)["items"][0]["state"] == "processing"
    result = run_worker(store, batch)["items"][0]
    assert result["state"] == "snapshotted"
    assert result["attempts"] == 2
    with store.transaction() as session:
        assert session.scalar(select(func.count()).select_from(Snapshot)) == 1


def test_interruption_cap(store, archive, manifest):
    batch = submit(store, manifest([row(archive)]), archive.parent, "key")
    with store.transaction() as session:
        item = session.scalar(select(ImportItem))
        item.state, item.attempts = "processing", 3
    item = run_worker(store, batch)["items"][0]
    assert item["state"] == "failed"
    assert "three" in item["error"]


def test_cli_roundtrip(tmp_path, archive, manifest):
    runner = CliRunner()
    args = ["--state-dir", str(tmp_path / "cli-state")]
    assert runner.invoke(app, [*args, "init"]).exit_code == 0
    result = runner.invoke(
        app,
        [
            *args,
            "import-csv",
            str(manifest([row(archive)])),
            "--input-root",
            str(archive.parent),
            "--key",
            "demo",
        ],
    )
    assert result.exit_code == 0, result.output
    batch = json.loads(result.output)["import_id"]
    result = runner.invoke(app, [*args, "worker", batch])
    assert result.exit_code == 0, result.output
    run_id = json.loads(result.output)["items"][0]["run_id"]
    result = runner.invoke(app, [*args, "run-status", run_id])
    report = json.loads(result.output)
    assert report["state"] == "snapshotted"
    result = runner.invoke(app, [*args, "verify-snapshot", report["snapshot_id"]])
    assert result.exit_code == 0 and json.loads(result.output)["valid"]
    assert runner.invoke(app, [*args, "run-status", "missing"]).exit_code == 1
