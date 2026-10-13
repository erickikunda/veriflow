import json

import pytest
from conftest import row
from typer.testing import CliRunner

from veriflow import batch_scan
from veriflow.artifacts import ArtifactStore
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.import_controls import control_status, set_control
from veriflow.intake import import_status, process, submit
from veriflow.persistence import Run, exclusive_worker


def test_pause_resume_idempotency_and_cli(store, archive, manifest):
    batch = submit(store, manifest([row(archive)]), archive.parent, "controls")
    assert control_status(store, batch)["revision"] == 0
    first = set_control(store, batch, "paused", "pause", "Maintenance", 0)
    assert set_control(store, batch, "paused", "pause", "Maintenance", 0) == first
    assert process(store, ArtifactStore(store.root), batch)["items"][0]["state"] == "ready"
    with pytest.raises(VeriFlowError, match="revision"):
        set_control(store, batch, "active", "resume", "Ready", 0)
    with pytest.raises(VeriFlowError, match="different"):
        set_control(store, batch, "active", "pause", "Ready", 1)
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "import-control",
            batch,
            "active",
            "resume",
            "Ready",
            "--expected-revision",
            "1",
        ],
    )
    assert result.exit_code == 0 and json.loads(result.output)["applied_revision"] == 2
    captured = process(store, ArtifactStore(store.root), batch)
    run_id = captured["items"][0]["run_id"]
    with store.transaction() as session:
        snapshot = session.get(Run, run_id).snapshot_id
    old = set_control(store, batch, "paused", "pause", "Maintenance", 0)
    assert old["current"]["state"] == "active" and old["applied_revision"] == 1
    assert process(store, ArtifactStore(store.root), batch)["items"][0]["run_id"] == run_id
    with store.transaction() as session:
        assert session.get(Run, run_id).snapshot_id == snapshot
    assert control_status(store, batch, limit=1)["next_offset"] == 1


@pytest.mark.parametrize("state", ["paused", "cancelled"])
def test_pause_during_capture_stops_next_row(store, archive, manifest, monkeypatch, state):
    batch = submit(
        store, manifest([row(archive), row(archive, repo_id="second")]), archive.parent, "boundary"
    )
    artifacts = ArtifactStore(store.root)
    original = artifacts.capture

    def capture(*args):
        result = original(*args)
        set_control(store, batch, state, "stop", "Stop after current row", 0)
        return result

    monkeypatch.setattr(artifacts, "capture", capture)
    with exclusive_worker(store.root):
        result = process(store, artifacts, batch)
    assert [item["state"] for item in result["items"]] == ["snapshotted", "ready"]
    assert result["dispatch_control"]["state"] == state


def test_scan_pause_boundary_and_resume_offset(store, archive, manifest, tmp_path, monkeypatch):
    batch = submit(
        store,
        manifest([row(archive), row(archive, repo_id="second")]),
        archive.parent,
        "scan-boundary",
    )
    process(store, ArtifactStore(store.root), batch)
    query = tmp_path / "approved.ql"
    query.write_text("// synthetic")
    calls = []

    def scan(*args, **kwargs):
        calls.append(args[1])
        set_control(store, batch, "paused", "pause", "Pause next row", 0)
        return {"status": "ready_for_review", "report_id": "synthetic"}

    monkeypatch.setattr(batch_scan, "scan_run", scan)
    result = batch_scan.scan_import(store, batch, query, limit=2)
    assert result["dispatch_status"] == "paused" and result["next_offset"] == 1
    assert len(calls) == len(result["items"]) == 1
    assert batch_scan.scan_import(store, batch, query, offset=1)["items"] == []
    set_control(store, batch, "active", "resume", "Continue", 1)
    monkeypatch.setattr(batch_scan, "scan_run", lambda *a, **kw: {"status": "incomplete"})
    resumed = batch_scan.scan_import(store, batch, query, offset=1)
    assert resumed["dispatch_status"] == "page_complete" and resumed["next_offset"] is None
    assert resumed["items"][0]["row_number"] == 3


def test_upgrade_preserves_imports(store, archive, manifest):
    batch = submit(store, manifest([row(archive)]), archive.parent, "migration")
    before = import_status(store, batch)["items"]
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE profile_approvals")
        connection.exec_driver_sql("DROP TABLE profile_tests")
        connection.exec_driver_sql("DROP TABLE profile_drafts")
        connection.exec_driver_sql("DROP TABLE rule_approvals")
        connection.exec_driver_sql("DROP TABLE rule_registries")
        connection.exec_driver_sql("DROP TABLE rule_drafts")
        connection.exec_driver_sql("DROP TABLE discovery_calls")
        connection.exec_driver_sql("DROP TABLE import_controls")
        connection.exec_driver_sql("UPDATE alembic_version SET version_num='0008'")
    store.initialize()
    store.initialize()
    assert import_status(store, batch)["items"] == before
    assert control_status(store, batch)["state"] == "active"
