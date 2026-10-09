"""Validate the review gates above the packaged envelope against real Joern output.

The in-tree wide fixture uses a native document written by hand. This script runs the real
toolchain over the same source and records what Joern actually emits, so the twelve-node shape
is qualified rather than assumed.
"""

import argparse
import csv
import json
import zipfile
from pathlib import Path

from veriflow.artifacts import ArtifactStore
from veriflow.bundles import build_bundle
from veriflow.envelope import Envelope
from veriflow.intake import process, submit
from veriflow.joern_claims import RUST_POLICY, assess_review_evidence, review_preflight
from veriflow.models import Decision
from veriflow.persistence import Store
from veriflow.pipeline import scan_run
from veriflow.reports import publish_report, render_report
from veriflow.scanning import scan_report

# The packaged envelope stops at eight locations; this is the operator-widened one under test.
WIDE = Envelope(max_locations=16, max_source_bytes=64 * 1024, max_bundle_bytes=256 * 1024)
MIN_WIDE_NODES = 9

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--joern-home", type=Path, required=True)
parser.add_argument("--rust-home", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=False)
fixtures = Path(__file__).resolve().parents[1] / "tests/fixtures/joern-rust-env/wide-crossfile"
store = Store(root / "state")
store.initialize()
summary = {"schema_version": "1", "state": "failed", "qualification": "fixture_feasibility_only"}
try:
    archive = root / "wide.zip"
    with zipfile.ZipFile(archive, "w") as out:
        for item in sorted(fixtures.rglob("*")):
            if item.is_file():
                out.write(item, item.relative_to(fixtures))
    row = dict(
        repo_id="wide-crossfile",
        source_type="pvc",
        source_uri=str(archive),
        owner="poc",
        classification="synthetic",
    )
    manifest = root / "wide.csv"
    with manifest.open("w") as out:
        writer = csv.DictWriter(out, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    batch = submit(store, manifest, root, "wide-crossfile")
    run = process(store, ArtifactStore(store.root), batch)["items"][0]["run_id"]
    result = scan_run(
        store,
        run,
        engine="joern",
        language="auto",
        joern_home=args.joern_home,
        rust_home=args.rust_home,
        joern_profile="rust-env-shell-v1",
    )
    attempt = result["attempt_id"]
    assert result["analysis_status"] == "partial", result
    report = scan_report(store, "wide-crossfile", run, attempt)
    assert report["candidate_count"] == 1, report

    # Record the real path length instead of asserting the hand-written one.
    native = json.loads((store.root / "scans" / attempt / "flows.json").read_text())
    nodes = len(native["paths"][0])
    summary["native_path_nodes"] = nodes
    assert nodes >= MIN_WIDE_NODES, f"path of {nodes} nodes does not exceed the packaged envelope"

    fingerprint = report["candidates"][0]["fingerprint"]
    narrow = build_bundle(store, attempt, fingerprint)
    summary["packaged_envelope"] = {
        "status": narrow["status"],
        "gaps": narrow["gaps"],
        "audit_status": narrow.get("joern_native_audit", {}).get("status"),
        "audit_reason": narrow.get("joern_native_audit", {}).get("reason"),
        "preflight_status": review_preflight(narrow, RUST_POLICY)["status"],
    }
    assert not review_preflight(narrow, RUST_POLICY)["passed"], summary["packaged_envelope"]

    wide = build_bundle(store, attempt, fingerprint, WIDE)
    audit = wide["joern_native_audit"]
    preflight = review_preflight(wide, RUST_POLICY)
    summary["widened_envelope"] = {
        "status": wide["status"],
        "gaps": wide["gaps"],
        "notes": wide["notes"],
        "locations_total": wide["locations_total"],
        "duplicate_locations_merged": wide["duplicate_locations_merged"],
        "audit_status": audit["status"],
        "audit_nodes": len(audit.get("nodes", [])),
        "preflight_status": preflight["status"],
    }
    assert audit["status"] == "validated", summary["widened_envelope"]
    assert len(audit["nodes"]) == nodes, summary["widened_envelope"]
    assert preflight["passed"], preflight

    retained = [s for s in wide["snippets"] if s.get("flow_id") is not None]
    quote = lambda s: s["text"].splitlines()[s["line"] - s["excerpt_line"]].strip()  # noqa: E731
    decision = Decision(
        verdict="needs_review",
        rationale="Native path retained above the packaged envelope",
        evidence_ids=[retained[0]["id"], retained[-1]["id"]],
        counterevidence="Guards unknown",
        claims=[
            dict(
                obligation=obligation,
                evidence_id=snippet["id"],
                line=snippet["line"],
                end_line=snippet["line"],
                assessment="unknown" if obligation == "guard" else "present",
                quote=quote(snippet),
                explanation="Acceptance claim bound to retained source",
            )
            for obligation, snippet in (
                ("source", retained[0]),
                ("sink", retained[-1]),
                ("flow", retained[0]),
                ("guard", retained[-1]),
            )
        ],
    )
    gate = assess_review_evidence(wide, decision, RUST_POLICY)
    summary["evidence_gate"] = {
        "status": gate["status"],
        "passed": gate["passed"],
        "missing": gate["missing"],
        "reachability_proven": gate["reachability_proven"],
    }
    assert gate["passed"], gate
    assert gate["reachability_proven"] is False

    published = publish_report(store, "wide-crossfile", run, attempt)
    (root / "report.html").write_text(render_report(published, "html"))
    summary["advisory_reductions"] = published["advisory_reductions"]
    summary["report_id"] = published["report_id"]
    summary["state"] = "passed"
    summary["model_calls"] = 0
finally:
    store.close()
    (root / "wide-gate.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
assert summary["state"] == "passed"
