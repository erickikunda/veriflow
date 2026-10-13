"""Experimental durable discovery with explicit, bounded Joern profiles."""

import hashlib
import json
import os
import signal
import subprocess
from collections import Counter
from pathlib import Path
from uuid import uuid4

from veriflow import joern_profiles
from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.intake import now
from veriflow.joern_diagnostics import observe_logs
from veriflow.persistence import Candidate, ScanAttempt, exclusive_worker
from veriflow.sarif import MAX_SARIF_BYTES, normalize

VERSION = "4.0.625"
RULE = "veriflow/joern-spring-get-jdbc-sql-v1"
SUFFIXES = {
    "java": ".java",
    "csharp": ".cs",
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "rust": ".rs",
    "c": (".c", ".h"),
    "cpp": (".cpp", ".h", ".hpp"),
}
PYTHON_RULE = "veriflow/joern-python-lookup-system-v1"


def stage(command, root, name, timeout, *, rust_home=None):
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(root),
        "TMPDIR": str(root),
        "LANG": "en_US.UTF-8",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
    }
    if rust_home is not None:
        env.update(
            PATH=str(rust_home / "bin") + os.pathsep + env["PATH"],
            CARGO_HOME=str(root / "cargo-home"),
            CARGO_NET_OFFLINE="true",
        )
    if os.environ.get("JAVA_HOME"):
        env["JAVA_HOME"] = os.environ["JAVA_HOME"]
    with (root / f"{name}.log").open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise VeriFlowError(f"Joern {name} timed out") from None
    if code:
        raise VeriFlowError(f"Joern {name} failed; inspect stage log")


def decode_output(raw, language="java", rule=RULE):
    if len(raw) > MAX_SARIF_BYTES:
        raise VeriFlowError("Joern output exceeds 16 MiB")
    try:
        doc = json.loads(raw)
        if doc["schema_version"] != "2" or doc["engine_id"] != "joern" or doc["rule_id"] != rule:
            raise ValueError()
        for key in ("source_count", "sink_count", "flow_count"):
            if type(doc[key]) is not int or not 0 <= doc[key] <= 1_000_000:
                raise ValueError()
        if not isinstance(doc["paths"], list) or doc["flow_count"] != len(doc["paths"]):
            raise ValueError()
        if doc["flow_count"] and (not doc["source_count"] or not doc["sink_count"]):
            raise ValueError()
        represented = doc[f"represented_{language}_files"]
        if not isinstance(represented, list) or len(represented) > 100_000:
            raise ValueError()
        if any(not isinstance(path, str) or not path for path in represented):
            raise ValueError()
        return doc
    except (ValueError, KeyError, TypeError, RecursionError):
        raise VeriFlowError("Malformed Joern coverage/output contract") from None


def discovery_coverage(doc, source, selected, language="java"):
    expected = {record.path for record in selected}
    represented = set()
    try:
        for value in doc[f"represented_{language}_files"]:
            path = Path(value)
            if path.is_absolute():
                path = path.relative_to(source)
            if ".." in path.parts or path.as_posix() not in expected:
                raise ValueError()
            represented.add(path.as_posix())
    except ValueError:
        raise VeriFlowError("Graph inventory references unexpected source") from None
    if doc["flow_count"]:
        observation = "modeled_flows_found"
    elif not doc["source_count"] and not doc["sink_count"]:
        observation = "no_modeled_sources_or_sinks"
    elif not doc["source_count"]:
        observation = "no_modeled_sources"
    elif not doc["sink_count"]:
        observation = "no_modeled_sinks"
    else:
        observation = "no_recorded_flow_between_modeled_endpoints"
    return {
        "schema_version": "1",
        "observation": observation,
        f"selected_{language}_files": len(expected),
        f"represented_{language}_files": len(represented),
        "missing_graph_files": sorted(expected - represented),
        "modeled_source_count": doc["source_count"],
        "modeled_sink_count": doc["sink_count"],
        "recorded_flow_count": doc["flow_count"],
        "parser_diagnostics": "not_qualified",
        "parse_completeness_verified": False,
        "reachability_verified": False,
        "interpretation": "Graph representation and modeled endpoints are not complete coverage",
    }


def to_sarif(raw, source, manifest, language="java", rule=RULE, message=None):
    """Preserve recorded flow order; reject invalid references instead of inventing nodes."""
    if len(raw) > MAX_SARIF_BYTES:
        raise VeriFlowError("Joern output exceeds 16 MiB")
    try:
        doc = decode_output(raw, language, rule)
        paths = doc["paths"]
        if not isinstance(paths, list) or len(paths) > 10000 or doc["flow_count"] != len(paths):
            raise ValueError()
        records = {f.path: f for f in manifest.files if f.path.endswith(SUFFIXES[language])}
        results = []
        for flow in paths:
            if not isinstance(flow, list) or not 1 <= len(flow) <= 1000:
                raise ValueError()
            locations = []
            for node in flow:
                path = Path(node["file"])
                if path.is_absolute():
                    path = path.relative_to(source)
                if ".." in path.parts or path.as_posix() not in records:
                    raise ValueError()
                line = node["line"]
                text = (source / path).read_text()
                if type(line) is not int or not 1 <= line <= len(text.splitlines()):
                    raise ValueError()
                locations.append(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path.as_posix()},
                            "region": {"startLine": line},
                        }
                    }
                )
            results.append(
                {
                    "ruleId": rule,
                    "message": {"text": message or joern_profiles.message_for(rule, language)},
                    "locations": [locations[-1]],
                    "codeFlows": [
                        {"threadFlows": [{"locations": [{"location": loc} for loc in locations]}]}
                    ],
                }
            )
        return json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Joern", "version": VERSION}},
                        "invocations": [{"executionSuccessful": False}],
                        "results": results,
                    }
                ],
            }
        ).encode()
    except (ValueError, KeyError, TypeError, OSError, AttributeError, RecursionError):
        raise VeriFlowError("Invalid Joern output or source reference") from None


def discover(
    store,
    run_id,
    joern_home,
    timeout=180,
    *,
    repair_dir=None,
    language=None,
    rust_home=None,
    extraction_timeout=None,
    discovery_profile=None,
    profile_binding=None,
):
    """Explicit local opt-in; caller supplies trusted tools, never repository scripts.

    profile_binding runs an unapproved draft binding; only profile tests pass it.
    """
    language = language or ("csharp" if repair_dir is not None else "java")
    if language not in SUFFIXES or (language == "csharp") != (repair_dir is not None):
        raise VeriFlowError("Unsupported Joern language/repair combination")
    profile = profile_binding or joern_profiles.binding(language, discovery_profile, store)
    if profile.language != language:
        raise VeriFlowError("Unsupported Joern discovery profile/language")
    discovery_profile = profile.profile
    rust_toolchain = None
    if language == "rust":
        from veriflow.joern_rust import trusted_toolchain

        rust_toolchain = trusted_toolchain(store, rust_home)
    elif rust_home is not None:
        raise VeriFlowError("Rust toolchain only applies to Rust scans")
    stage_options = {"rust_home": rust_toolchain} if rust_toolchain else {}
    rule = profile.rule_id
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise VeriFlowError("Timeout must be between 1 and 3600 seconds")
    extraction_timeout = timeout if extraction_timeout is None else extraction_timeout
    if type(extraction_timeout) is not int or not 1 <= extraction_timeout <= 3600:
        raise VeriFlowError("Extraction timeout must be between 1 and 3600 seconds")
    home = Path(joern_home).resolve(strict=True)
    if not (home / "lib" / f"io.joern.joern-cli-{VERSION}.jar").is_file():
        raise VeriFlowError("Expected pinned Joern version layout not found")
    if home.is_relative_to(store.root / "artifacts") or home.is_relative_to(store.root / "scans"):
        raise VeriFlowError("Joern must come from operator tooling, not scan artifacts")
    frontend_name = {
        "java": "javasrc2cpg",
        "csharp": "javasrc2cpg",
        "python": "pysrc2cpg",
        "javascript": "jssrc2cpg.sh",
        "typescript": "jssrc2cpg.sh",
        "go": "gosrc2cpg",
        "rust": "rust2cpg",
        "c": "c2cpg.sh",
        "cpp": "c2cpg.sh",
    }[language]
    frontend = [str(home / frontend_name), "-J-Xmx2g"]
    repair_identity = None
    if repair_dir is not None:
        from veriflow.joern_csharp import repaired_frontend

        frontend, repair_identity = repaired_frontend(store, home, Path(repair_dir))
    store.require_initialized()
    with exclusive_worker(store.root):
        run, manifest, tree = verified_source(store, run_id)
        selected = [f for f in manifest.files if f.path.endswith(SUFFIXES[language])]
        if not selected:
            raise VeriFlowError(f"Snapshot contains no {language} source")
        cargo = None
        if language == "rust":
            from veriflow.joern_rust import cargo_manifest

            cargo = cargo_manifest(tree, manifest)
        prepared = selected + (
            [f for f in manifest.files if Path(f.path).name == "go.mod"] if language == "go" else []
        )
        attempt_id = str(uuid4())
        root = store.root / "scans" / attempt_id
        root.mkdir(parents=True, mode=0o700)
        source = root / "source"
        report = {
            "schema_version": "1",
            "report_kind": "static_candidates",
            "attempt_id": attempt_id,
            "run_id": run_id,
            "repo_id": run.repo_id,
            "snapshot_id": manifest.snapshot_id,
            "classification": manifest.classification,
            "language": language,
            "discovery_profile": discovery_profile or "default",
            "status": "running",
            "scanner": {
                "engine_id": "joern",
                "version": VERSION,
                "adapter_version": "experimental-csharp-1"
                if repair_dir
                else "experimental-python-1"
                if language == "python"
                else f"experimental-{language}-1"
                if language in {"javascript", "typescript", "go", "rust", "c", "cpp"}
                else "experimental-4",
            },
            "prepared_input": {"kind": "joern_cpg", "path": str(root / "cpg.bin")},
            "candidate_count": None,
            "verified_finding_count": None,
            "coverage_verified": False,
            "security_verdict": "not_adjudicated",
            "network_isolated": False,
            "automatic_reuse_eligible": False,
            "timeout_seconds_per_stage": timeout,
            "extraction_timeout_seconds": extraction_timeout,
            "query_timeout_seconds": timeout,
            "requested_heap_mb_per_jvm": 2048,
            "raw_sarif_path": str(root / "results.sarif"),
            "log_path": str(root / "analyze.log"),
            "limitations": list(profile.limitations),
            "omitted_file_count": len(manifest.files) - len(prepared),
        }
        if profile.cwe_scope is not None:
            report["cwe_scope"] = list(profile.cwe_scope)
        if language == "rust":
            report["cargo_manifest_sha256"] = hashlib.sha256(cargo).hexdigest()
        if repair_dir is not None:
            report["repair_identity"] = repair_identity
        current = joern_profiles.catalog(store)
        # Which catalog produced this attempt, so a candidate traces to the query that ran.
        report["profile_provenance"] = {
            "source": profile.source,
            "mode": current.mode,
            "registry_version": current.registry_version,
            "draft_id": profile.draft_id,
            "internal_pattern": profile.internal_pattern,
        }
        with store.transaction() as session:
            session.add(ScanAttempt(id=attempt_id, run_id=run_id, created_at=now(), report=report))
        candidates = []
        active_stage = "source_copy"
        try:
            for record in prepared:
                target = source / record.path
                target.parent.mkdir(parents=True, exist_ok=True)
                content = (tree / record.path).read_bytes()
                if hashlib.sha256(content).hexdigest() != record.sha256:
                    raise VeriFlowError("Source integrity changed")
                target.write_bytes(content)
            if cargo is not None:
                (source / "Cargo.toml").write_bytes(cargo)
            endpoint_args = []
            endpoint_digest = None
            endpoints = profile.hooks.get("flask_endpoints")
            if endpoints is not None:
                from veriflow.joern_flask import parse_isolated

                audit = []
                # A local module with a modeled name could stand in for the real library.
                modules = {"flask", "os", *endpoints["shadow_modules"]}
                shadowed = any(
                    Path(f.path).name in {f"{module}.py" for module in modules}
                    or any(module in Path(f.path).parts[:-1] for module in modules)
                    for f in selected
                )
                facts_option = {endpoints["facts"]: True} if endpoints["facts"] else {}
                for record in selected:
                    facts = (
                        {"status": "local_module_shadow", "sources": [], "sinks": []}
                        if shadowed
                        else parse_isolated((source / record.path).read_bytes(), **facts_option)
                    )
                    audit.append(
                        dict(
                            facts,
                            file=record.path,
                            absolute_file=str(source / record.path),
                            sha256=record.sha256,
                        )
                    )
                endpoint_path = root / "endpoints.json"
                endpoint_path.write_text(json.dumps(audit, indent=2))
                endpoint_digest = hashlib.sha256(endpoint_path.read_bytes()).hexdigest()
                report["endpoint_audit"] = {
                    "sha256": endpoint_digest,
                    "file_status_counts": dict(Counter(f["status"] for f in audit)),
                }
                endpoint_args = ["--param", f"endpointFile={endpoint_path}"]
            query = root / "query.sc"
            active_stage = "query_load"
            query.write_bytes(joern_profiles.read_query(profile))
            query_digest = hashlib.sha256(query.read_bytes()).hexdigest()
            report["query_sha256"] = query_digest
            active_stage = "prepare"
            stage(
                frontend
                + [
                    str(source),
                    "--output",
                    str(root / "cpg.bin"),
                ],
                root,
                "prepare",
                extraction_timeout,
                **stage_options,
            )
            active_stage = "analyze"
            stage(
                [
                    str(home / "joern"),
                    "-J-Xmx2g",
                    "--script",
                    str(query),
                    "--param",
                    f"cpgFile={root / 'cpg.bin'}",
                    "--param",
                    f"outFile={root / 'flows.json'}",
                ]
                + endpoint_args,
                root,
                "analyze",
                timeout,
                **stage_options,
            )
            active_stage = "normalize_and_verify"
            verified_source(store, run_id)
            for record in prepared:
                if hashlib.sha256((source / record.path).read_bytes()).hexdigest() != record.sha256:
                    raise VeriFlowError("Prepared source changed")
            if (
                endpoint_digest is not None
                and hashlib.sha256(endpoint_path.read_bytes()).hexdigest() != endpoint_digest
            ):
                raise VeriFlowError("Endpoint selection changed")
            if cargo is not None and (source / "Cargo.toml").read_bytes() != cargo:
                raise VeriFlowError("Prepared Cargo metadata changed")
            if hashlib.sha256(query.read_bytes()).hexdigest() != query_digest:
                raise VeriFlowError("Query changed")
            with (root / "flows.json").open("rb") as handle:
                raw = handle.read(MAX_SARIF_BYTES + 1)
            report["native_output_sha256"] = hashlib.sha256(raw).hexdigest()
            doc = decode_output(raw, language, rule)
            coverage = discovery_coverage(doc, source, selected, language)
            if language == "rust" and coverage["represented_rust_files"] == 0:
                report["discovery_coverage"] = coverage
                raise VeriFlowError("Rust preparation produced no selected source in graph")
            if repair_dir is not None:
                from veriflow.joern_csharp import map_output, repaired_frontend

                _, after_identity = repaired_frontend(store, home, Path(repair_dir))
                if after_identity != repair_identity:
                    raise VeriFlowError("Repair tooling changed during scan")
                raw, mapping = map_output(
                    doc,
                    source,
                    selected,
                    require_query_source=profile.hooks.get("csharp_query_source", False),
                )
                (root / "source-mapping.json").write_text(json.dumps(mapping, indent=2))
                report["source_mapping"] = {
                    "validated_paths": mapping["validated_paths"],
                    "unsupported_paths": mapping["unsupported_paths"],
                    "artifact": str(root / "source-mapping.json"),
                }
            sarif = to_sarif(raw, source, manifest, language, rule, profile.message)
            candidates, summary = normalize(sarif, manifest, tree)
            (root / "results.sarif").write_bytes(sarif)
            report.update(summary, status="partial", sarif_sha256=hashlib.sha256(sarif).hexdigest())
            report.update(
                discovery_coverage=coverage,
                diagnostic_errors=None,
                diagnostic_warnings=None,
                process_stages_completed=True,
            )
        except (VeriFlowError, OSError) as exc:
            candidates = []
            report.update(
                status="failed", failure_kind=type(exc).__name__, failed_stage=active_stage
            )
        report["joern_diagnostics"] = observe_logs(root, selected)
        with store.transaction() as session:
            for candidate in candidates:
                session.add(
                    Candidate(
                        id=str(uuid4()),
                        attempt_id=attempt_id,
                        fingerprint=candidate["fingerprint"],
                        evidence=candidate,
                    )
                )
            session.get(ScanAttempt, attempt_id).report = report
        return report
