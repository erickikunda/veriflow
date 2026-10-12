from types import SimpleNamespace

import pytest

from veriflow import joern_pipeline, joern_selection
from veriflow.domain import VeriFlowError


def manifest(*paths):
    return SimpleNamespace(files=[SimpleNamespace(path=p) for p in paths])


def test_inventory_selects_all_profiles_and_preserves_unsupported():
    detected, plan = joern_selection.selection(manifest("app.py", "Main.java", "x.kt", "README.md"))
    assert detected == ["java", "kotlin", "python"]
    assert len(plan) == 11
    assert ("kotlin", None) in plan
    assert len([p for lang, p in plan if lang == "python"]) == 4
    assert joern_selection.selection(manifest("app.py", "Main.java"), "java")[1] == [
        ("java", None),
        ("java", "java-spring-file-path-v1"),
        ("java", "java-spring-url-stream-v1"),
        ("java", "java-spring-object-read-v1"),
        ("java", "java-spring-xml-entities-v1"),
        ("java", "java-spring-runtime-shell-v1"),
    ]


def test_no_source_does_not_claim_clean():
    with pytest.raises(VeriFlowError, match="No recognized"):
        joern_selection.selection(manifest("README.md"))


def test_scope_failure_continues_other_languages_and_reports(monkeypatch):
    monkeypatch.setattr(
        joern_selection,
        "verified_source",
        lambda *a: (SimpleNamespace(repo_id="repo"), manifest("app.cs", "x.kt", "app.py"), None),
    )
    calls = []

    def fake(*args, advisory=None):
        calls.append((args[2], args[8], args[9]))
        if args[2] == "csharp":
            raise VeriFlowError("C# requires repair")
        return {"status": "incomplete", "report_id": args[9], "model_calls": 0}

    monkeypatch.setattr(joern_pipeline, "scan_run", fake)
    result = joern_selection.scan_selected(
        None, "run", "auto", "/joern", None, None, 300, 600, True
    )
    assert len(result["report_ids"]) == 4
    assert result["items"][0]["status"] == "scope_error"
    assert result["items"][4]["status"] == "unsupported_language"
    assert len(calls) == 8
    assert all(skip for _, skip, _ in calls)
    assert result["model_calls"] == 0
    assert result["security_completion_verified"] is False


def test_explicit_advisory_policy_requires_explicit_profile():
    explicit = SimpleNamespace(review_policy="joern-spring-review-v1")
    with pytest.raises(VeriFlowError, match="review-policy auto"):
        joern_selection.scan_selected(
            None, "run", "auto", "/joern", None, None, 300, 600, advisory=explicit
        )


def test_auto_advisory_binds_reviewed_policy_per_profile(monkeypatch):
    from veriflow.models import ModelConfig
    from veriflow.scan_advisory import AUTO_POLICY, AdvisoryOptions

    monkeypatch.setattr(
        joern_selection,
        "verified_source",
        lambda *a: (SimpleNamespace(repo_id="repo"), manifest("Main.java", "app.go"), None),
    )
    bound = {}

    def fake(*args, advisory=None):
        bound[(args[2], args[9] or "default")] = advisory.review_policy
        return {"status": "incomplete", "report_id": None, "model_calls": 1}

    monkeypatch.setattr(joern_pipeline, "scan_run", fake)
    advisory = AdvisoryOptions(
        ModelConfig(provider="replay", model="fixture"), object(), "key", AUTO_POLICY
    )
    result = joern_selection.scan_selected(
        None, "run", "auto", "/joern", None, None, 300, 600, advisory=advisory
    )
    assert bound[("java", "default")] == "joern-spring-review-v1"
    assert bound[("go", "go-http-shell-v1")] == "joern-go-http-review-v1"
    assert bound[("java", "java-spring-file-path-v1")] is None
    assert result["model_calls"] == len(bound) == 7


def test_cli_omitted_language_and_profile_dispatch_auto(monkeypatch, tmp_path):
    import json

    from typer.testing import CliRunner

    from veriflow import pipeline
    from veriflow.cli import app

    received = {}

    def fake(*args, **kwargs):
        received.update(kwargs)
        return {"status": "incomplete"}

    monkeypatch.setattr(pipeline, "scan_run", fake)
    result = CliRunner().invoke(
        app,
        [
            "--state-dir",
            str(tmp_path),
            "scan-run",
            "run",
            "--engine",
            "joern",
            "--joern-home",
            "/tools",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "incomplete"
    assert received["language"] == "auto"
    assert received["joern_profile"] == "auto"


@pytest.mark.parametrize("language,suffix", [("javascript", "js"), ("typescript", "ts")])
def test_express_selection_includes_eval_command_and_html(language, suffix):
    _, plan = joern_selection.selection(manifest(f"app.{suffix}"))
    assert plan == [
        (language, "express-request-eval-v1"),
        (language, "express-request-exec-v1"),
        (language, "express-html-send-v1"),
    ]
