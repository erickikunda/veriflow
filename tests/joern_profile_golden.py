"""Golden capture of every Joern (language, profile) binding through the real discover path."""

import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest import mock
from uuid import uuid4

from veriflow import joern
from veriflow.artifacts import ArtifactStore
from veriflow.domain import VeriFlowError
from veriflow.intake import process, submit
from veriflow.persistence import Store

GOLDEN = Path(__file__).parent / "fixtures" / "joern-profile-golden.json"
SOURCES = {
    "java": "A.java",
    "csharp": "A.cs",
    "python": "app.py",
    "javascript": "app.js",
    "typescript": "app.ts",
    "go": "main.go",
    "rust": "src/main.rs",
    "c": "main.c",
    "cpp": "main.cpp",
}
PROFILES = [
    None,
    "csharp-query-commandtext-v1",
    "csharp-query-file-read-v1",
    "csharp-query-shell-start-v1",
    "python-flask-system-v1",
    "python-flask-path-v1",
    "python-flask-ssrf-v1",
    "python-flask-sql-v1",
    "java-spring-file-path-v1",
    "java-spring-url-stream-v1",
    "java-spring-object-read-v1",
    "java-spring-xml-entities-v1",
    "java-spring-runtime-shell-v1",
    "express-html-send-v1",
    "express-request-exec-v1",
    "express-request-eval-v1",
    "go-http-shell-v1",
    "rust-env-shell-v1",
    "c-family-argv-system-v1",
    "unknown-profile-v1",
]


def _run(store, root, language):
    archive = root / f"{language}.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr(SOURCES[language], "x\n")
    manifest = root / f"{language}.csv"
    manifest.write_text(
        "repo_id,source_type,source_uri,owner,classification\n"
        f"{language},pvc,{archive},tests,synthetic\n"
    )
    batch = submit(store, manifest, root, str(uuid4()))
    return process(store, ArtifactStore(store.root), batch)["items"][0]["run_id"]


def capture():
    results = {}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp).resolve()
        store = Store(root / "state")
        store.initialize()
        home = root / "tools"
        (home / "lib").mkdir(parents=True)
        (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()
        hooks = {}

        def fake_stage(command, stage_root, name, timeout, **kwargs):
            if name != "analyze":
                return
            query = (stage_root / "query.sc").read_text()
            rule = re.search(r'"rule_id" -> "([^"]+)"', query).group(1)
            language = hooks["language"]
            path = SOURCES[language]
            (stage_root / "flows.json").write_text(
                json.dumps(
                    {
                        "schema_version": "2",
                        "engine_id": "joern",
                        "rule_id": rule,
                        f"represented_{language}_files": [path],
                        "source_count": 1,
                        "sink_count": 1,
                        "flow_count": 1,
                        "paths": [[{"file": path, "line": 1, "code": "x"}]],
                    }
                )
            )

        def fake_parse(content, **kwargs):
            hooks["flask_parse"] = sorted(kwargs)
            return {"status": "parsed", "sources": [], "sinks": []}

        def fake_map(doc, source, selected, *, require_query_source=False):
            hooks["require_query_source"] = require_query_source
            return json.dumps(doc).encode(), {"validated_paths": 1, "unsupported_paths": 0}

        patches = [
            mock.patch.object(joern, "stage", fake_stage),
            mock.patch("veriflow.joern_flask.parse_isolated", fake_parse),
            mock.patch("veriflow.joern_csharp.map_output", fake_map),
            mock.patch(
                "veriflow.joern_csharp.repaired_frontend",
                lambda store, home, repair: (["frontend"], {"id": "repair"}),
            ),
            mock.patch("veriflow.joern_rust.trusted_toolchain", lambda store, home: home),
            mock.patch("veriflow.joern_rust.cargo_manifest", lambda tree, manifest: b"[cargo]\n"),
        ]
        for patch in patches:
            patch.start()
        try:
            for language in SOURCES:
                run_id = _run(store, root, language)
                for profile in PROFILES:
                    hooks.clear()
                    hooks["language"] = language
                    key = f"{language}/{profile or 'default'}"
                    try:
                        report = joern.discover(
                            store,
                            run_id,
                            home,
                            language=language,
                            discovery_profile=profile,
                            repair_dir=root if language == "csharp" else None,
                            rust_home=root if language == "rust" else None,
                        )
                    except VeriFlowError as exc:
                        results[key] = {"error": str(exc)}
                        continue
                    sarif = json.loads(
                        (store.root / "scans" / report["attempt_id"] / "results.sarif").read_text()
                    )
                    result = sarif["runs"][0]["results"][0]
                    results[key] = {
                        "status": report["status"],
                        "rule": result["ruleId"],
                        "message": result["message"]["text"],
                        "query_sha256": report["query_sha256"],
                        "cwe_scope": report.get("cwe_scope", "<absent>"),
                        "limitations": report["limitations"],
                        "adapter_version": report["scanner"]["adapter_version"],
                        "discovery_profile": report["discovery_profile"],
                        "endpoint_audit": "endpoint_audit" in report,
                        "source_mapping": "source_mapping" in report,
                        "hooks": {k: v for k, v in hooks.items() if k != "language"},
                    }
            from veriflow.joern_selection import PROFILES as auto_plan

            results["__auto_plan__"] = {
                language: [profile or "default" for profile in plan]
                for language, plan in auto_plan.items()
            }
        finally:
            for patch in reversed(patches):
                patch.stop()
            store.close()
    return results


if __name__ == "__main__":
    data = capture()
    if "--write" in sys.argv:
        GOLDEN.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"{len(data)} bindings; {sum('error' not in v for v in data.values())} scanned")
