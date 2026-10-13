"""Experimental Joern producer for the persisted Python inventory contract."""

import hashlib
import json
import time
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from veriflow.domain import VeriFlowError
from veriflow.indexing import verified_source
from veriflow.joern import VERSION as JOERN_VERSION
from veriflow.joern import stage
from veriflow.persistence import IndexedFile, SourceIndex

VERSION = f"joern-inventory-v1-python-{JOERN_VERSION}"
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def _relative(value, source, expected):
    path = Path(value)
    if path.is_absolute():
        path = path.relative_to(source)
    relative = path.as_posix()
    if ".." in path.parts or relative not in expected:
        raise VeriFlowError("Joern inventory references unexpected source")
    return relative


def _decode(path, source, expected):
    raw = path.read_bytes()
    if len(raw) > MAX_OUTPUT_BYTES:
        raise VeriFlowError("Joern inventory output exceeds 16 MiB")
    try:
        doc = json.loads(raw)
        if (
            doc["schema_version"] != "1"
            or doc["engine_id"] != "joern"
            or doc["language"] != "python"
            or not isinstance(doc["symbols"], list)
            or not isinstance(doc["calls"], list)
            or not isinstance(doc["represented_files"], list)
            or len(doc["symbols"]) > 1_000_000
            or len(doc["calls"]) > 1_000_000
        ):
            raise ValueError()
        represented = {_relative(item, source, expected) for item in doc["represented_files"]}
        by_file = {name: {"symbols": [], "calls": []} for name in expected}
        for kind in ("symbols", "calls"):
            for item in doc[kind]:
                relative = _relative(item.pop("file"), source, expected)
                if type(item.get("line")) is not int or type(item.get("end_line")) is not int:
                    raise ValueError()
                by_file[relative][kind].append(item)
        return represented, by_file
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
        raise VeriFlowError("Malformed Joern inventory output") from None


def build_index(store, run_id, joern_home, timeout=300):
    if joern_home is None:
        raise VeriFlowError("Joern indexing requires --joern-home")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise VeriFlowError("Index timeout must be between 1 and 3600 seconds")
    home = Path(joern_home).resolve(strict=True)
    if not (home / "lib" / f"io.joern.joern-cli-{JOERN_VERSION}.jar").is_file():
        raise VeriFlowError("Expected pinned Joern version layout not found")
    run, manifest, tree = verified_source(store, run_id)
    selected = [record for record in manifest.files if record.path.endswith(".py")]
    if not selected:
        raise VeriFlowError("Snapshot contains no Python source for comparable indexing")
    with store.transaction() as session:
        existing = session.scalar(
            select(SourceIndex).where(
                SourceIndex.snapshot_id == manifest.snapshot_id,
                SourceIndex.version == VERSION,
                SourceIndex.state == "published",
            )
        )
        if existing is not None:
            return {**existing.report, "run_id": run.id, "repo_id": run.repo_id}
        index = SourceIndex(
            id=str(uuid4()), snapshot_id=manifest.snapshot_id, version=VERSION, state="building"
        )
        session.add(index)
        index_id = index.id
    root = store.root / "indexes" / index_id
    root.mkdir(parents=True, mode=0o700)
    source = root / "source"
    source.mkdir(mode=0o700)
    for record in selected:
        target = source / record.path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = (tree / record.path).read_bytes()
        if hashlib.sha256(payload).hexdigest() != record.sha256:
            raise VeriFlowError("Source changed during Joern indexing")
        target.write_bytes(payload)
    cpg = root / "cpg.bin"
    started = time.monotonic()
    stage(
        [str(home / "pysrc2cpg"), "-J-Xmx2g", str(source), "--output", str(cpg)],
        root,
        "prepare",
        timeout,
    )
    extraction_seconds = time.monotonic() - started
    query = root / "inventory.sc"
    query.write_bytes(files("veriflow").joinpath("queries/joern-python-inventory.sc").read_bytes())
    output = root / "inventory.json"
    started = time.monotonic()
    stage(
        [
            str(home / "joern"),
            "-J-Xmx2g",
            "--script",
            str(query),
            "--param",
            f"cpgFile={cpg}",
            "--param",
            f"outFile={output}",
        ],
        root,
        "analyze",
        timeout,
    )
    query_seconds = time.monotonic() - started
    verified_source(store, run_id)
    expected = {record.path for record in selected}
    represented, by_file = _decode(output, source, expected)
    with store.transaction() as session:
        for record in manifest.files:
            payload = {"status": "not_supported", "symbols": [], "calls": []}
            if record.path in expected:
                payload = {
                    "status": "parsed" if record.path in represented else "graph_missing",
                    **by_file[record.path],
                }
            payload.update(path=record.path, sha256=record.sha256, size_bytes=record.size_bytes)
            session.add(
                IndexedFile(id=str(uuid4()), index_id=index_id, path=record.path, result=payload)
            )
        function_count = sum(len(item["symbols"]) for item in by_file.values())
        call_count = sum(len(item["calls"]) for item in by_file.values())
        report = {
            "schema_version": "1",
            "report_kind": "index_coverage",
            "index_id": index_id,
            "index_version": VERSION,
            "index_backend": "joern",
            "snapshot_id": manifest.snapshot_id,
            "classification": manifest.classification,
            "security_analysis_performed": False,
            "security_verdict": "not_assessed",
            "finding_count": None,
            "python_index_gate": "ready"
            if represented == expected and function_count
            else "blocked",
            "total_files": len(manifest.files),
            "python_files": len(expected),
            "parsed_python_files": len(represented),
            "python_parse_fraction": len(represented) / len(expected),
            "function_count": function_count,
            "call_count": call_count,
            "unresolved_call_count": sum(
                item.get("resolution") == "unresolved"
                for result in by_file.values()
                for item in result["calls"]
            ),
            "elapsed_seconds": extraction_seconds + query_seconds,
            "extraction_seconds": extraction_seconds,
            "query_seconds": query_seconds,
            "artifact_bytes": sum(
                path.stat().st_size for path in root.rglob("*") if path.is_file()
            ),
            "requested_heap_mb": 2048,
            "files": [
                {
                    "path": record.path,
                    "sha256": record.sha256,
                    "size_bytes": record.size_bytes,
                    "status": "parsed"
                    if record.path in represented
                    else "graph_missing"
                    if record.path in expected
                    else "not_supported",
                }
                for record in manifest.files
            ],
            "limitations": [
                "Experimental Python-only Joern inventory comparable to the current syntax index.",
                "CPG names and calls are normalized and need not equal written source syntax.",
                "No per-file extraction checkpoint; a failed CPG blocks this backend.",
                "Peak RSS requires container telemetry and is not measured by this command.",
                "No security queries, LLM analysis, or benchmark evaluation have run.",
            ],
        }
        index = session.get(SourceIndex, index_id)
        index.report = report
        index.state = "published"
    return {**report, "run_id": run.id, "repo_id": run.repo_id}
