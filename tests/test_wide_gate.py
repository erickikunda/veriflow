"""The review gates executed above the packaged envelope, which no other fixture reaches."""

from pathlib import Path

import pytest
from test_joern_claims import review_decision
from test_slice03 import captured_source as captured_source

from veriflow import joern
from veriflow.bundles import build_bundle
from veriflow.envelope import Envelope
from veriflow.joern_claims import RUST_POLICY, assess_review_evidence, review_preflight
from veriflow.scanning import scan_report

FIXTURES = Path(__file__).parent / "fixtures"
# Twelve native nodes over five files, one of them past the packaged 16 KiB context cap.
WIDE = Envelope(max_locations=16, max_source_bytes=64 * 1024, max_bundle_bytes=256 * 1024)


@pytest.fixture
def wide_attempt(store, captured_source, tmp_path, monkeypatch):
    run = captured_source(
        {
            item.name: item.read_text()
            for item in (FIXTURES / "joern-rust-env/wide-crossfile").iterdir()
            if item.is_file()
        }
    )
    monkeypatch.setattr("veriflow.joern_rust.trusted_toolchain", lambda *args: tmp_path)
    home = tmp_path / "tools"
    (home / "lib").mkdir(parents=True)
    (home / "lib" / f"io.joern.joern-cli-{joern.VERSION}.jar").touch()

    def fake(command, root, name, timeout, **kwargs):
        if name == "analyze":
            (root / "flows.json").write_bytes(
                (FIXTURES / "joern-rust-advisory/wide-crossfile-native.json").read_bytes()
            )

    monkeypatch.setattr(joern, "stage", fake)
    result = joern.discover(
        store, run, home, language="rust", rust_home=tmp_path, discovery_profile="rust-env-shell-v1"
    )
    report = scan_report(store, "example", run, result["attempt_id"])
    return result["attempt_id"], report["candidates"][0]["fingerprint"]


def test_packaged_envelope_cannot_carry_a_twelve_node_path(store, wide_attempt):
    attempt, fingerprint = wide_attempt
    narrow = build_bundle(store, attempt, fingerprint)
    # The native audit refuses the path outright, so no amount of citation makes it reviewable.
    assert narrow["joern_native_audit"]["status"] == "withheld"
    assert narrow["joern_native_audit"]["reason"] == "native_path_limit"
    # Truncation is reported first; the audit refusal is the underlying cause.
    assert any(gap.startswith("location_limit:") for gap in narrow["gaps"])
    assert review_preflight(narrow, RUST_POLICY)["status"] == "incomplete_bundle"


def test_widened_envelope_passes_preflight_and_the_evidence_gate(store, wide_attempt):
    attempt, fingerprint = wide_attempt
    bundle = build_bundle(store, attempt, fingerprint, WIDE)
    assert bundle["status"] == "ready" and bundle["gaps"] == []
    assert bundle["location_limit"] == 17 and bundle["envelope"]["max_locations"] == 16
    # Eleven distinct regions carry all twelve steps; the repeated source line merged.
    assert bundle["locations_total"] == 13 and bundle["duplicate_locations_merged"] == 2
    audit = bundle["joern_native_audit"]
    assert audit["status"] == "validated" and len(audit["nodes"]) == 12

    preflight = review_preflight(bundle, RUST_POLICY)
    assert preflight["passed"], preflight
    assert preflight["status"] == "eligible_for_advisory"
    assert not preflight["reachability_proven"]

    gate = assess_review_evidence(bundle, review_decision(bundle), RUST_POLICY)
    assert gate["passed"], gate
    assert "source_to_sink_recorded_flow" not in gate["missing"]
    assert not gate["reachability_proven"]


def test_widened_context_is_bounded_by_the_recorded_envelope(store, wide_attempt):
    attempt, fingerprint = wide_attempt
    # The oversized file is reconstructed only because the bundle recorded a wider bound.
    bundle = build_bundle(store, attempt, fingerprint, WIDE)
    oversized = [s for s in bundle["snippets"] if s["path"] == "repository.rs"]
    assert oversized and len(oversized[0]["text"].encode()) > 16 * 1024
    starved = {**bundle, "envelope": {**bundle["envelope"], "max_source_bytes": 16 * 1024}}
    # Below that bound the file cannot be rebuilt, and the refusal names the reason.
    assert review_preflight(starved, RUST_POLICY)["status"] == "incomplete_source_context"


def test_a_tampered_wide_node_is_still_refused(store, wide_attempt):
    attempt, fingerprint = wide_attempt
    bundle = build_bundle(store, attempt, fingerprint, WIDE)
    for index, change in ((5, {"line": 99}), (11, {"code": "absent_identifier"})):
        tampered = {
            **bundle,
            "joern_native_audit": {
                **bundle["joern_native_audit"],
                "nodes": [
                    {**node, **(change if position == index else {})}
                    for position, node in enumerate(bundle["joern_native_audit"]["nodes"])
                ],
            },
        }
        assert not review_preflight(tampered, RUST_POLICY)["passed"]


def test_a_tight_budget_still_funds_one_complete_excerpt_per_file(store, wide_attempt):
    """Allocation and the syntax gates want opposite things; the gates must still win."""
    attempt, fingerprint = wide_attempt
    # Enough for the oversized file once, but not enough for every excerpt to widen freely.
    tight = Envelope(max_locations=16, max_source_bytes=24 * 1024, max_bundle_bytes=128 * 1024)
    bundle = build_bundle(store, attempt, fingerprint, tight)
    rebuilt = [
        snippet
        for snippet in bundle["snippets"]
        if snippet["path"] == "repository.rs"
        and snippet["excerpt_line"] == 1
        and snippet["excerpt_end_line"] == snippet["source_line_count"]
    ]
    assert rebuilt, "the oversized file lost its one complete excerpt"
    assert review_preflight(bundle, RUST_POLICY)["passed"]
    assert assess_review_evidence(bundle, review_decision(bundle), RUST_POLICY)["passed"]
