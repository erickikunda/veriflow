# Slice 161 — Declarative Joern profile catalog (phase 0, no behaviour change)

## What was added

Every packaged Joern discovery profile is now a descriptor in
`src/veriflow/profiles/joern-packaged.json`, read through `joern_profiles.py`. The descriptor
binds a profile name, per language, to its rule ID and query file, and carries the candidate
message, `cwe_scope`, limitations and `selection` (`auto` or `explicit`). List order is the
`--joern-profile auto` order.

This removes six hard-coded places: `supported_profiles`, the rule if/elif chain, the query
file chain, the SARIF message chain and the limitations/CWE blocks in `joern.py`, and the
`PROFILES` table in `joern_selection.py`, which is now derived from the catalog.

Code that needs Python support stays in `joern.py` and is named by descriptor `hooks`:
`flask_endpoints` (endpoint audit facts and shadowed module names) and `csharp_query_source`.
Only packaged profiles may name hooks. Language-level behaviour (C# repair, Rust Cargo
metadata, adapter versions) is unchanged. Reviewed gates in `joern_claims.py` and the
benchmark rule map in `evaluation.py` are unchanged.

The catalog has 27 descriptors and 31 language bindings: 9 language defaults and 22 named
bindings (18 profiles; the three Express profiles cover JavaScript and TypeScript, and the
C-family profile covers C and C++).

## Verification

- `tests/joern_profile_golden.py` runs the real `discover()` for 9 languages × 20 profile
  values, with Joern replaced by a fake that echoes each query's rule ID. It records rule,
  SARIF message, query digest, CWE scope (or its absence), limitations, adapter version, hook
  arguments and refusals, plus the automatic plan. The golden file was written from the code
  **before** the refactor; `test_joern_profile_catalog.py` requires an identical capture after
  it (181 entries: 31 scanned, 149 refused, 1 automatic plan). Changing one word of one message
  makes the test fail.
- `uv run pytest`: 1402 passed.
- A host run with Joern 4.0.625 on the `joern-flask/vulnerable` fixture gave identical query
  digests, statuses, candidate fingerprints, CWE scopes, limitations and SARIF messages for all
  4 Python profiles, compared with a run made before the refactor.

## Non-claims

- No profile, query, message or limitation changed. No migration.
- Runtime profiles (trusted directory, approved registry) are phase 1 and not in this slice.

## Next

Phase 1: catalog resolution from a trusted profile directory (default) and the approved rule
registry (`--profile-mode approved`), the `profile-*` commands, digest-aware attempt reuse, and
wiring into `scan-run`, `scan-import`, `run-pipeline-from-csv` and `joern-*-discover`.
