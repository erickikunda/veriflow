import json
import os
import re
import shutil
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from veriflow import joern, joern_profiles, joern_selection, profile_admin
from veriflow.artifacts import ArtifactStore
from veriflow.cli import app
from veriflow.domain import VeriFlowError
from veriflow.intake import process, submit
from veriflow.profile_admin import ProfileApprovalRequest

QUERY = 'val rule = 1 // "rule_id" -> "{rule}"\n'


@pytest.fixture
def tools(tmp_path, monkeypatch):
    home = tmp_path / "tools"
    (home / "lib").mkdir(parents=True)
    (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()

    def fake_stage(command, root, name, timeout, **kwargs):
        if name != "analyze":
            return
        rule = re.search(r'"rule_id" -> "([^"]+)"', (root / "query.sc").read_text()).group(1)
        files = sorted(
            p.relative_to(root / "source").as_posix() for p in (root / "source").rglob("*.go")
        )
        vulnerable = [f for f in files if "VULNERABLE" in (root / "source" / f).read_text()]
        paths = [[{"file": f, "line": 1, "code": "x"}] for f in vulnerable]
        (root / "flows.json").write_text(
            json.dumps(
                {
                    "schema_version": "2",
                    "engine_id": "joern",
                    "rule_id": rule,
                    "represented_go_files": files,
                    "source_count": 1,
                    "sink_count": 1,
                    "flow_count": len(paths),
                    "paths": paths,
                }
            )
        )

    monkeypatch.setattr(joern, "stage", fake_stage)
    return home


def profile_folder(root, name="acme-go-ssti-v1", **changes):
    folder = root / name
    (folder / "fixtures").mkdir(parents=True)
    descriptor = {
        "schema_version": "1",
        "name": name,
        "language": "go",
        "rule_id": f"acme/joern-{name}",
        "query": "query.sc",
        "message": "Go request input to template text; discovery only.",
        "limitations": ["text/template Parse only; execution unverified."],
        "selection": "auto",
        "weakness": {"cwe": ["CWE-1336"], "internal_pattern": None},
        "fixtures": [
            {"kind": "vulnerable", "file": "vulnerable.go", "expected_flows": None},
            {"kind": "fixed", "file": "fixed.go", "expected_flows": None},
            {"kind": "misleading", "file": "misleading", "expected_flows": None},
        ],
        **changes,
    }
    (folder / "profile.json").write_text(json.dumps(descriptor))
    (folder / "query.sc").write_text(QUERY.format(rule=descriptor["rule_id"]))
    (folder / "fixtures" / "vulnerable.go").write_text("// VULNERABLE\n")
    (folder / "fixtures" / "fixed.go").write_text("// fixed\n")
    (folder / "fixtures" / "misleading").mkdir()
    (folder / "fixtures" / "misleading" / "main.go").write_text("// misleading\n")
    (folder / "fixtures" / "misleading" / "go.mod").write_text("module example\n")
    return folder


def go_run(store, root, text="// VULNERABLE\n"):
    inputs = root / f"inputs-{uuid4().hex[:8]}"
    inputs.mkdir()
    archive = inputs / "source.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("main.go", text)
    manifest = inputs / "repos.csv"
    manifest.write_text(
        f"repo_id,source_type,source_uri,owner,classification\ndemo,pvc,{archive},tests,synthetic\n"
    )
    batch = submit(store, manifest, inputs, str(uuid4()))
    return process(store, ArtifactStore(store.root), batch)["items"][0]["run_id"]


def fresh(store, **settings):
    for key, value in settings.items():
        setattr(store, key, value)
    store._joern_catalog = None
    return joern_profiles.catalog(store)


def test_trusted_directory_profile_joins_auto_and_scans(store, tools, tmp_path):
    profile_folder(store.root / "profiles")
    catalog = fresh(store)
    runtime = [b for b in catalog.bindings if b.source == "trusted_directory"]
    assert [b.name for b in runtime] == ["acme-go-ssti-v1"] and not catalog.problems
    assert joern_selection.plan_for(store)["go"] == ["go-http-shell-v1", "acme-go-ssti-v1"]
    assert "acme-go-ssti-v1" not in joern_selection.PROFILES["go"]
    report = joern.discover(
        store, go_run(store, tmp_path), tools, language="go", discovery_profile="acme-go-ssti-v1"
    )
    assert report["status"] == "partial" and report["candidate_count"] == 1
    assert report["cwe_scope"] == ["CWE-1336"]
    assert report["limitations"][-1].startswith("Runtime profile (trusted_directory)")
    assert report["profile_provenance"]["source"] == "trusted_directory"
    sarif = json.loads(Path(report["raw_sarif_path"]).read_text())
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "acme/joern-acme-go-ssti-v1"
    assert result["message"]["text"] == "Go request input to template text; discovery only."


def test_explicit_selection_is_named_only(store):
    profile_folder(store.root / "profiles", selection="explicit")
    fresh(store)
    assert "acme-go-ssti-v1" not in joern_selection.plan_for(store)["go"]
    assert joern_profiles.binding("go", "acme-go-ssti-v1", store).selection == "explicit"


@pytest.mark.parametrize(
    "change,problem",
    [
        ({"name": "go-http-shell-v1"}, "reserved by a packaged"),
        ({"rule_id": "veriflow/joern-x"}, "namespace is reserved"),
        ({"weakness": {"cwe": ["CWE-TODO"], "internal_pattern": None}}, "CWE-79"),
        ({"weakness": {"cwe": [], "internal_pattern": None}}, "CWE or an internal pattern"),
        ({"rule_id": "veriflow/joern-go-http-shell-v1"}, "namespace is reserved"),
        ("symlink", "not a link"),
        ("world", "world-writable"),
        ("mismatch", "must equal the descriptor name"),
    ],
)
def test_bad_directory_entries_are_skipped_not_fatal(store, tmp_path, change, problem):
    profiles = store.root / "profiles"
    profile_folder(profiles, "acme-go-good-v1")
    if isinstance(change, dict):
        change = dict(change)
        profile_folder(profiles, change.pop("name", "acme-go-bad-v1"), **change)
    else:
        folder = profile_folder(profiles, "acme-go-bad-v1")
        if change == "symlink":
            target = tmp_path / "elsewhere.sc"
            target.write_text(QUERY.format(rule="acme/x"))
            (folder / "query.sc").unlink()
            (folder / "query.sc").symlink_to(target)
        elif change == "world":
            os.chmod(folder / "query.sc", 0o666)
        else:
            folder.rename(profiles / "acme-go-renamed-v1")
    catalog = fresh(store)
    assert [b.name for b in catalog.bindings if b.source != "packaged"] == ["acme-go-good-v1"]
    assert len(catalog.problems) == 1 and problem in catalog.problems[0]["problem"]


def test_query_changed_after_load_fails_the_attempt(store, tools, tmp_path):
    folder = profile_folder(store.root / "profiles")
    fresh(store)
    run_id = go_run(store, tmp_path)
    (folder / "query.sc").write_text(QUERY.format(rule="acme/joern-acme-go-ssti-v1") + "// x\n")
    report = joern.discover(
        store, run_id, tools, language="go", discovery_profile="acme-go-ssti-v1"
    )
    assert report["status"] == "failed" and report["failed_stage"] == "query_load"
    assert report["candidate_count"] is None


def lifecycle(store, tools, tmp_path, name="acme-go-ssti-v1", **changes):
    draft = profile_admin.add_profile(
        store, profile_folder(tmp_path / "authoring", name, **changes)
    )
    test = profile_admin.test_profile(store, draft["draft_id"], tools)
    return draft, test


def approval(draft_id, version):
    return ProfileApprovalRequest(
        draft_sha256=draft_id,
        expected_registry_version=version,
        reviewer_label="rule-owner",
        rationale="Fixture test passed",
    )


def test_add_test_approve_disable_cycle(store, tools, tmp_path):
    draft, test = lifecycle(store, tools, tmp_path)
    assert draft["origin"] == "cwe_priority" and draft["state"] == "draft"
    assert test["passed"] and [f["candidates"] for f in test["fixtures"]] == [1, 0, 0]
    assert (
        profile_admin.add_profile(store, tmp_path / "authoring" / "acme-go-ssti-v1")["draft_id"]
        == draft["draft_id"]
    )
    approved = profile_admin.approve_profile(
        store, draft["draft_id"], approval(draft["draft_id"], 0), "k1"
    )
    assert approved["registry"]["version"] == 1
    again = profile_admin.approve_profile(
        store, draft["draft_id"], approval(draft["draft_id"], 0), "k1"
    )
    assert again["approval_id"] == approved["approval_id"]
    catalog = fresh(store, profile_mode="approved")
    assert [(b.name, b.source) for b in catalog.bindings if b.source != "packaged"] == [
        ("acme-go-ssti-v1", "registry")
    ]
    assert catalog.registry_version == 1
    report = joern.discover(
        store, go_run(store, tmp_path), tools, language="go", discovery_profile="acme-go-ssti-v1"
    )
    assert report["profile_provenance"] == {
        "source": "registry",
        "mode": "approved",
        "registry_version": 1,
        "draft_id": draft["draft_id"],
        "internal_pattern": None,
    }
    disabled = profile_admin.disable_profile(store, "acme-go-ssti-v1", 1, "replaced by v2")
    assert disabled["version"] == 2 and disabled["rules"] == []
    assert all(b.source == "packaged" for b in fresh(store).bindings)
    with pytest.raises(VeriFlowError, match="Stale"):
        profile_admin.disable_profile(store, "acme-go-ssti-v1", 1, "again")


def test_approval_requires_a_passing_executed_test(store, tools, tmp_path):
    draft = profile_admin.add_profile(store, profile_folder(tmp_path / "a"))
    with pytest.raises(VeriFlowError, match="profile-test"):
        profile_admin.approve_profile(store, draft["draft_id"], approval(draft["draft_id"], 0), "k")
    folder = profile_folder(tmp_path / "b", "acme-go-weak-v1")
    (folder / "fixtures" / "fixed.go").write_text("// VULNERABLE leftover\n")
    weak = profile_admin.add_profile(store, folder)
    result = profile_admin.test_profile(store, weak["draft_id"], tools)
    assert not result["passed"] and result["fixtures"][1]["candidates"] == 1
    with pytest.raises(VeriFlowError, match="profile-test"):
        profile_admin.approve_profile(store, weak["draft_id"], approval(weak["draft_id"], 0), "k2")


def test_internal_pattern_profile_and_mode_rules(store, tools, tmp_path):
    pattern = {"cwe": [], "internal_pattern": {"id": "ACME-2026-007", "title": "Report export"}}
    draft, _ = lifecycle(store, tools, tmp_path, "acme-go-export-v1", weakness=pattern)
    assert draft["origin"] == "internal_pattern"
    profile_admin.approve_profile(store, draft["draft_id"], approval(draft["draft_id"], 0), "k")
    profile_folder(store.root / "profiles", "acme-go-export-v1")
    profile_folder(store.root / "profiles", "acme-go-local-v1")
    trusted = fresh(store, profile_mode="trusted-directory")
    runtime = [(b.name, b.source) for b in trusted.bindings if b.source != "packaged"]
    # The approved profile keeps running; only the directory copy of its name is skipped.
    assert runtime == [("acme-go-export-v1", "registry"), ("acme-go-local-v1", "trusted_directory")]
    assert [p["source"] for p in trusted.problems] == ["trusted_directory"]
    assert "stays active" in trusted.problems[0]["problem"]
    approved = fresh(store, profile_mode="approved")
    assert [b.name for b in approved.bindings if b.source != "packaged"] == ["acme-go-export-v1"]
    assert approved.ignored == ("acme-go-export-v1", "acme-go-local-v1")
    binding = joern_profiles.binding("go", "acme-go-export-v1", store)
    assert binding.cwe_scope is None and binding.internal_pattern["id"] == "ACME-2026-007"
    shutil.rmtree(store.root / "profiles" / "acme-go-export-v1")
    profile_folder(store.root / "profiles", "acme-go-broken-v1", rule_id="veriflow/x")
    fresh(store, profile_mode="trusted-directory")
    with pytest.raises(VeriFlowError, match="not active"):
        joern_profiles.binding("go", "acme-go-broken-v1", store)


def test_runtime_drafts_are_kept_out_of_llm_promotion(store, tmp_path):
    from veriflow.rule_registry import ApprovalRequest, approve_rule_draft, rule_draft_status

    draft = profile_admin.add_profile(store, profile_folder(tmp_path))
    with pytest.raises(VeriFlowError, match="profile-status"):
        rule_draft_status(store, draft["draft_id"])
    request = ApprovalRequest(
        draft_sha256=draft["draft_id"],
        expected_registry_version=0,
        expected_review_revision=1,
        reviewer_label="x",
        rationale="y",
    )
    with pytest.raises(VeriFlowError, match="profile-approve"):
        approve_rule_draft(store, draft["draft_id"], request, "k")


def test_scaffold_stays_inactive_until_edited(store, tmp_path):
    result = profile_admin.scaffold("acme-go-new-v1", "go", store.root / "profiles")
    assert "query.sc" in result["files"] and "fixtures/vulnerable.go" in result["files"]
    catalog = fresh(store)
    assert all(b.source == "packaged" for b in catalog.bindings)
    assert "CWE-79" in catalog.problems[0]["problem"]
    with pytest.raises(VeriFlowError, match="already exists"):
        profile_admin.scaffold("acme-go-new-v1", "go", store.root / "profiles")


def test_cli_modes_and_listing(store, tmp_path, monkeypatch):
    profile_folder(store.root / "profiles")
    base = ["--state-dir", str(store.root)]
    listed = CliRunner().invoke(app, [*base, "profile-list"])
    assert listed.exit_code == 0, listed.output
    data = json.loads(listed.output)
    assert data["mode"] == "trusted-directory"
    assert any(p["name"] == "acme-go-ssti-v1" for p in data["profiles"])
    monkeypatch.setenv("VERIFLOW_PROFILE_MODE", "approved")
    data = json.loads(CliRunner().invoke(app, [*base, "profile-list"]).output)
    assert data["mode"] == "approved" and data["ignored_directory_profiles"] == ["acme-go-ssti-v1"]
    bad = CliRunner().invoke(app, [*base, "--profile-mode", "loose", "profile-list"])
    assert bad.exit_code != 0


def test_reuse_requires_the_same_query_text(store, tools, tmp_path):
    from veriflow import joern_pipeline

    folder = profile_folder(store.root / "profiles")
    fresh(store)
    run_id = go_run(store, tmp_path)
    args = (store, run_id, "go", tools, None, None, 300, 600, True, "acme-go-ssti-v1")
    first = joern_pipeline.scan_run(*args)
    assert joern_pipeline.scan_run(*args)["status"] == "skipped_existing_attempt"
    (folder / "query.sc").write_text(QUERY.format(rule="acme/joern-acme-go-ssti-v1") + "// v2\n")
    fresh(store)
    rescanned = joern_pipeline.scan_run(*args)
    assert rescanned["status"] != "skipped_existing_attempt"
    assert rescanned["attempt_id"] != first["attempt_id"]


def test_csv_pipeline_picks_up_runtime_profiles_and_resumes(store, tools, tmp_path):
    from test_triage import FakeAdapter, policy

    from veriflow.csv_pipeline import PipelineOptions, run_pipeline

    inputs = tmp_path / "inputs"
    inputs.mkdir()
    archive = inputs / "go.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("main.go", "// VULNERABLE\n")
    manifest = tmp_path / "repos.csv"
    manifest.write_text(
        f"repo_id,source_type,source_uri,owner,classification\ndemo,pvc,{archive},tests,synthetic\n"
    )
    opts = PipelineOptions(config=policy(), adapter=FakeAdapter(), joern_home=tools)

    def run(name):
        output = tmp_path / name
        run_pipeline(store, manifest, inputs, output, opts, lambda line: None)
        store._joern_catalog = None
        summary = json.loads((output / "demo" / "summary.json").read_text())
        return (
            {
                p["discovery_profile"]: (p["action"], p["profile_source"])
                for p in summary["profiles"]
            },
            summary,
            json.loads((output / "summary.json").read_text()),
        )

    folder = profile_folder(store.root / "profiles")
    first, summary, overall = run("one")
    assert first == {
        "go-http-shell-v1": ("scanned", "packaged"),
        "acme-go-ssti-v1": ("scanned", "trusted_directory"),
    }
    assert overall["profile_catalog"]["runtime_profiles"] == ["acme-go-ssti-v1 (trusted_directory)"]
    assert summary["stats"]["candidates"] == 2
    assert run("two")[0]["acme-go-ssti-v1"] == ("reused", "trusted_directory")
    (folder / "query.sc").write_text(QUERY.format(rule="acme/joern-acme-go-ssti-v1") + "// v2\n")
    profile_folder(store.root / "profiles", "acme-go-second-v1")
    third, summary, _ = run("three")
    assert third == {
        "go-http-shell-v1": ("reused", "packaged"),
        "acme-go-ssti-v1": ("scanned", "trusted_directory"),
        "acme-go-second-v1": ("scanned", "trusted_directory"),
    }
    reasons = {s["step"]: s.get("reason") for s in summary["steps"] if s["step"].startswith("scan")}
    assert reasons["scan go/acme-go-ssti-v1"] == "query_changed"
    assert reasons["scan go/acme-go-second-v1"] == "not_scanned"


GATED_SOURCE = (
    'package main\nfunc handler(r Request) {\n value := r.FormValue("command")\n run(value)\n}\n'
)


@pytest.fixture
def gated_tools(tmp_path, monkeypatch):
    home = tmp_path / "gate-tools"
    (home / "lib").mkdir(parents=True)
    (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()

    def fake_stage(command, root, name, timeout, **kwargs):
        if name != "analyze":
            return
        rule = re.search(r'"rule_id" -> "([^"]+)"', (root / "query.sc").read_text()).group(1)
        path = [
            {"file": "main.go", "line": 3, "code": 'r.FormValue("command")'},
            {"file": "main.go", "line": 4, "code": "value"},
        ]
        (root / "flows.json").write_text(
            json.dumps(
                {
                    "schema_version": "2",
                    "engine_id": "joern",
                    "rule_id": rule,
                    "represented_go_files": ["main.go"],
                    "source_count": 1,
                    "sink_count": 1,
                    "flow_count": 1,
                    "paths": [path],
                }
            )
        )

    monkeypatch.setattr(joern, "stage", fake_stage)
    return home


def gated_bundle(store, tools, tmp_path, **changes):
    from veriflow.bundles import build_bundle
    from veriflow.scanning import scan_report

    profile_folder(store.root / "profiles", **changes)
    fresh(store)
    run_id = go_run(store, tmp_path, GATED_SOURCE)
    report = joern.discover(
        store, run_id, tools, language="go", discovery_profile="acme-go-ssti-v1"
    )
    fingerprint = scan_report(store, "demo", run_id, report["attempt_id"])["candidates"][0]
    return build_bundle(store, report["attempt_id"], fingerprint["fingerprint"])


def test_runtime_profiles_get_the_default_native_gate(store, gated_tools, tmp_path):
    from test_joern_advisory import adapter_for
    from test_triage import policy

    from veriflow.joern_claims import RUNTIME_GATE, policy_for, review_preflight
    from veriflow.triage import triage

    bundle = gated_bundle(store, gated_tools, tmp_path)
    gate = f"{RUNTIME_GATE}:acme-go-ssti-v1"
    assert policy_for("go", "acme-go-ssti-v1", store) == gate
    assert policy_for("go", "acme-go-ssti-v1") is None  # no store, no runtime gates
    assert bundle["joern_native_audit"]["status"] == "validated"
    preflight = review_preflight(bundle, gate, store)
    assert preflight["passed"] and preflight["endpoint_syntax_verified"] is False
    assert preflight["assurance"] == "path_citation_only"
    result = triage(
        store,
        bundle["bundle_id"],
        policy(),
        adapter_for(bundle),
        "gate",
        review_policy=gate,
        unmetered=True,
    )
    assert result["state"] == "completed" and result["disposition"] == "needs_review"
    assert result["evidence_gate"]["passed"] and not result["verified"]
    negative = triage(
        store,
        bundle["bundle_id"],
        policy(),
        adapter_for(bundle, "likely_false_positive"),
        "negative",
        review_policy=gate,
        unmetered=True,
    )
    assert negative["disposition"] == "abstain"


def test_review_gate_none_leaves_runtime_profiles_ungated(store, gated_tools, tmp_path):
    from veriflow.joern_claims import policy_for

    bundle = gated_bundle(store, gated_tools, tmp_path, review_gate="none")
    assert policy_for("go", "acme-go-ssti-v1", store) is None
    assert "joern_native_audit" not in bundle


def test_runtime_gate_rejects_a_quote_off_the_recorded_endpoint(store, gated_tools, tmp_path):
    from test_joern_claims import review_decision
    from test_triage import FakeAdapter, policy

    from veriflow.joern_claims import RUNTIME_GATE
    from veriflow.models import Reply, Usage
    from veriflow.triage import triage

    bundle = gated_bundle(store, gated_tools, tmp_path)
    decision = review_decision(bundle)
    claims = [
        claim.model_copy(update={"quote": "run(value)", "line": 4, "end_line": 4})
        if claim.obligation == "source"
        else claim
        for claim in decision.claims
    ]
    adapter = FakeAdapter(
        Reply(
            status="completed",
            decision=decision.model_copy(update={"claims": claims}),
            usage=Usage(input_tokens=10, output_tokens=5),
        )
    )
    result = triage(
        store,
        bundle["bundle_id"],
        policy(),
        adapter,
        "off-endpoint",
        review_policy=f"{RUNTIME_GATE}:acme-go-ssti-v1",
        unmetered=True,
    )
    assert result["state"] == "evidence_rejected" and result["disposition"] == "abstain"


def test_migration_0012_upgrades_a_registry_with_approved_drafts(tmp_path):
    import sqlite3
    from importlib.resources import files

    from alembic import command
    from alembic.config import Config

    from veriflow.persistence import Store

    store = Store(tmp_path / "state")
    store.root.mkdir(parents=True)
    config = Config()
    config.set_main_option("script_location", str(files("veriflow") / "migrations"))
    with store.engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0011")
    with store.engine.begin() as connection:
        run = connection.exec_driver_sql
        run("INSERT INTO repositories VALUES ('r','o','synthetic')")
        run("INSERT INTO runs VALUES ('run','r','snapshotted','standard',NULL,'t')")
        run("INSERT INTO scan_attempts VALUES ('a','run','t','{}')")
        run("INSERT INTO candidates VALUES ('c','a','f','{}')")
        run("INSERT INTO rule_drafts VALUES ('d','c','t','approved','{}')")
        run("INSERT INTO rule_registries VALUES ('g',1,'t','{\"rules\": []}')")
        run("INSERT INTO rule_approvals VALUES ('ap','d','g','k','t','{}')")
    store.initialize()
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("select version_num from alembic_version").fetchone() == ("0012",)
        assert connection.execute("select draft_id from rule_approvals").fetchall() == [("d",)]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    store.close()


def test_disabled_profile_can_be_approved_again_with_a_new_key(store, tools, tmp_path):
    draft, _ = lifecycle(store, tools, tmp_path)
    first = profile_admin.approve_profile(
        store, draft["draft_id"], approval(draft["draft_id"], 0), "k1"
    )
    profile_admin.disable_profile(store, "acme-go-ssti-v1", 1, "paused")
    with pytest.raises(VeriFlowError, match="no longer active"):
        profile_admin.approve_profile(
            store, draft["draft_id"], approval(draft["draft_id"], 2), "k1"
        )
    second = profile_admin.approve_profile(
        store, draft["draft_id"], approval(draft["draft_id"], 2), "k2"
    )
    assert second["approval_id"] != first["approval_id"]
    assert second["registry"]["version"] == 3
    retry = profile_admin.approve_profile(
        store, draft["draft_id"], approval(draft["draft_id"], 2), "k2"
    )
    assert retry["approval_id"] == second["approval_id"]
    active = fresh(store, profile_mode="approved")
    assert [b.name for b in active.bindings if b.source == "registry"] == ["acme-go-ssti-v1"]
    with pytest.raises(VeriFlowError, match="already the active"):
        profile_admin.approve_profile(
            store, draft["draft_id"], approval(draft["draft_id"], 3), "k3"
        )
    status = profile_admin.profile_status(store, draft["draft_id"])
    assert status["state"] == "approved" and len(status["approvals"]) == 2


def test_registry_entry_without_a_recorded_gate_stays_ungated(store, tools, tmp_path):
    from sqlalchemy import select

    from veriflow.joern_claims import RUNTIME_GATE, policy_for
    from veriflow.persistence import RuleRegistry

    draft, _ = lifecycle(store, tools, tmp_path)
    result = profile_admin.approve_profile(
        store, draft["draft_id"], approval(draft["draft_id"], 0), "k"
    )
    assert result["registry"]["rules"][0]["review_gate"] == RUNTIME_GATE
    fresh(store)
    assert policy_for("go", "acme-go-ssti-v1", store) == f"{RUNTIME_GATE}:acme-go-ssti-v1"
    with store.transaction() as session:
        registry = session.scalar(select(RuleRegistry).where(RuleRegistry.version == 1))
        content = json.loads(json.dumps(registry.content))
        del content["rules"][0]["descriptor"]["review_gate"]
        registry.content = content
    fresh(store)
    assert policy_for("go", "acme-go-ssti-v1", store) is None
    assert joern_profiles.binding("go", "acme-go-ssti-v1", store).review_gate is None


def test_scaffold_refuses_names_that_leave_the_output_folder(tmp_path):
    for name in ("../escape-v1", "a/b-v1", "Bad-v1", "no-version"):
        with pytest.raises(VeriFlowError, match="Profile name"):
            profile_admin.scaffold(name, "go", tmp_path / "out")
    assert not (tmp_path / "escape-v1").exists()


def test_profile_test_records_setup_errors(store, tmp_path):
    draft = profile_admin.add_profile(store, profile_folder(tmp_path))
    broken = tmp_path / "not-joern"
    broken.mkdir()
    result = profile_admin.test_profile(store, draft["draft_id"], broken)
    assert not result["passed"]
    assert {item["status"] for item in result["fixtures"]} == {"error"}
    assert "Joern version layout" in result["fixtures"][0]["error"]
    assert len(profile_admin.profile_status(store, draft["draft_id"])["tests"]) == 1


def test_runtime_gate_requires_the_complete_endpoint_line(store, gated_tools, tmp_path):
    from test_joern_claims import review_decision
    from test_triage import FakeAdapter, policy

    from veriflow.joern_claims import RUNTIME_GATE
    from veriflow.models import Reply, Usage
    from veriflow.triage import triage

    bundle = gated_bundle(store, gated_tools, tmp_path)
    decision = review_decision(bundle)
    claims = [
        claim.model_copy(update={"quote": "value"}) if claim.obligation == "sink" else claim
        for claim in decision.claims
    ]
    adapter = FakeAdapter(
        Reply(
            status="completed",
            decision=decision.model_copy(update={"claims": claims}),
            usage=Usage(input_tokens=10, output_tokens=5),
        )
    )
    result = triage(
        store,
        bundle["bundle_id"],
        policy(),
        adapter,
        "fragment",
        review_policy=f"{RUNTIME_GATE}:acme-go-ssti-v1",
        unmetered=True,
    )
    assert result["state"] == "evidence_rejected" and result["disposition"] == "abstain"


def test_failed_attempt_without_a_query_is_reported_as_failed(store, tools, tmp_path):
    from test_triage import FakeAdapter, policy

    from veriflow.csv_pipeline import PipelineOptions, run_pipeline
    from veriflow.persistence import ScanAttempt

    inputs = tmp_path / "inputs"
    inputs.mkdir()
    with zipfile.ZipFile(inputs / "go.zip", "w") as out:
        out.writestr("main.go", "// VULNERABLE\n")
    manifest = tmp_path / "repos.csv"
    manifest.write_text(
        "repo_id,source_type,source_uri,owner,classification\n"
        f"demo,pvc,{inputs / 'go.zip'},tests,synthetic\n"
    )
    opts = PipelineOptions(config=policy(), adapter=FakeAdapter(), joern_home=tools)
    run_pipeline(store, manifest, inputs, tmp_path / "one", opts, lambda line: None)
    with store.transaction() as session:
        for attempt in session.query(ScanAttempt):
            report = dict(attempt.report)
            report.pop("query_sha256")
            report["status"] = "failed"
            attempt.report = report
    run_pipeline(store, manifest, inputs, tmp_path / "two", opts, lambda line: None)
    summary = json.loads((tmp_path / "two" / "demo" / "summary.json").read_text())
    reasons = {s["step"]: s.get("reason") for s in summary["steps"] if s["step"].startswith("scan")}
    assert reasons["scan go/go-http-shell-v1"] == "previous_attempt_failed"
