import json

import pytest
from test_evaluation import evaluation as evaluation
from test_reports import scanned as scanned
from test_triage import evidence_fixture as evidence_fixture
from typer.testing import CliRunner

from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.persistence import BenchmarkScorecard
from veriflow.scorecards import get_scorecard, publish_scorecard, scorecard_history


def test_publish_reuse_history_and_input_free_retrieval(store, evaluation, tmp_path):
    expected = evaluation[3]()
    paths = [tmp_path / (name + ".json") for name in ["manifest", "labels", "plan"]]
    first = publish_scorecard(store, *paths)
    assert first == expected == publish_scorecard(store, *paths)
    published = CliRunner().invoke(
        app, ["--state-dir", str(store.root), "benchmark-publish", *map(str, paths)]
    )
    assert published.exit_code == 0 and json.loads(published.output) == first
    assert scorecard_history(store, "test")["total"] == 1
    evaluation[2]["reports"] = []
    evaluation[3]()
    second = publish_scorecard(store, *paths)
    assert second["scorecard_id"] != first["scorecard_id"]
    assert not second["complete"]
    history = scorecard_history(store, "test", limit=1)
    assert history["total"] == 2 and history["next_offset"] == 1
    for path in paths:
        path.unlink()
    assert get_scorecard(store, "test", first["scorecard_id"]) == first
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(store.root),
            "benchmark-get",
            "test",
            first["scorecard_id"],
            "--format",
            "weaknesses-csv",
        ],
    )
    assert result.exit_code == 0 and "CWE-94" in result.output
    for format in [
        "json",
        "html",
        "markdown",
        "summary-csv",
        "repositories-csv",
        "labels-csv",
        "candidates-csv",
    ]:
        result = CliRunner().invoke(
            app,
            [
                "--state-dir",
                str(store.root),
                "benchmark-get",
                "test",
                first["scorecard_id"],
                "--format",
                format,
            ],
        )
        assert result.exit_code == 0 and result.output


def test_ownership_integrity_and_pagination(store, evaluation, tmp_path):
    evaluation[3]()
    report = publish_scorecard(
        store, *[tmp_path / (name + ".json") for name in ["manifest", "labels", "plan"]]
    )
    with pytest.raises(VeriFlowError, match="belong"):
        get_scorecard(store, "other", report["scorecard_id"])
    assert scorecard_history(store, "other")["total"] == 0
    with pytest.raises(VeriFlowError, match="pagination"):
        scorecard_history(store, "test", limit=0)
    with store.transaction() as session:
        record = session.get(BenchmarkScorecard, report["scorecard_id"])
        record.content = {**record.content, "precision": 1.0}
    with pytest.raises(VeriFlowError, match="integrity"):
        get_scorecard(store, "test", report["scorecard_id"])
    with pytest.raises(VeriFlowError, match="integrity"):
        scorecard_history(store, "test")


def test_migration_from_six_preserves_existing_reports(store, evaluation):
    report = evaluation[3]()
    # Recreate the prior schema boundary in this isolated test database.
    with store.engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE profile_approvals")
        conn.exec_driver_sql("DROP TABLE profile_tests")
        conn.exec_driver_sql("DROP TABLE profile_drafts")
        conn.exec_driver_sql("DROP TABLE rule_approvals")
        conn.exec_driver_sql("DROP TABLE rule_registries")
        conn.exec_driver_sql("DROP TABLE rule_drafts")
        conn.exec_driver_sql("DROP TABLE discovery_calls")
        conn.exec_driver_sql("DROP TABLE benchmark_scorecards")
        conn.exec_driver_sql("DROP TABLE import_controls")
        conn.exec_driver_sql("ALTER TABLE triage_budgets DROP COLUMN max_requests")
        conn.exec_driver_sql("UPDATE alembic_version SET version_num='0006'")
    store.initialize()
    store.initialize()
    assert evaluation[3]() == report
    result = CliRunner().invoke(app, ["--state-dir", str(store.root), "init"])
    assert json.loads(result.output)["schema"] == "0011"
