# Slice 162 — Runtime Joern profiles (phase 1)

## What was added

Operators can add a Joern discovery profile at runtime: a descriptor and a `.sc` query, stored
on the state volume, with no code change or image rebuild. `joern_profiles.resolve` builds the
catalog for each command from packaged profiles, the approved rule registry, and, in the
default `trusted-directory` mode, the trusted directory (`<state-dir>/profiles`).
`--profile-mode approved` (or `VERIFLOW_PROFILE_MODE`) ignores the directory and lists what it
ignored. The catalog is resolved once per store, so a run sees one snapshot.

- **Descriptor** (`RuntimeDescriptor`): name ending `-vN`, one language, a non-`veriflow/`
  rule ID, message, limitations, `selection` (`auto` by default), a weakness with CWEs and/or an
  internal pattern, and fixtures. Runtime bindings get one more limitation naming their source.
- **Loading rules**: regular files only, no links, not world-writable, size limits, no packaged
  names or rule IDs, no hooks. A bad entry is skipped and reported; others still load. A
  directory profile with an approved profile's name is skipped (changed in Slice 163).
- **Wiring**: `discover()` resolves the binding through the store's catalog, reads the query
  with a digest check (`read_query`), passes the descriptor message to SARIF, and records
  `profile_provenance` (source, mode, registry version, draft ID, internal pattern).
  `joern_selection.selection` appends active runtime `auto` profiles after the packaged plan.
  `scan-run`, `scan-import`, `run-pipeline-from-csv` and `joern-*-discover` inherit this.
- **Digest-aware reuse**: `joern_pipeline` skip-existing and the CSV pipeline reuse an attempt
  only when its `query_sha256` equals the current query; otherwise the reason is
  `query_changed`.
- **Approved workflow** (`profile_admin.py`): `profile-scaffold`, `profile-add` (immutable draft
  without an LLM candidate; origin `cwe_priority` or `internal_pattern`), `profile-test` (runs
  the real Joern on each fixture in a disposable state and records a `ProfileTest`),
  `profile-approve` (needs a passing test with the current Joern version and query, the current
  registry version, and an idempotency key), `profile-status`, `profile-disable`, `profile-list`.
  `rule-draft-status` / `approve-rule-draft` redirect runtime drafts to these commands.
- **Migration `0012`**: adds `profile_drafts`, `profile_tests` and `profile_approvals`. (The first
  version rebuilt `rule_drafts`; Slice 163 replaced it because that failed on databases with
  approved drafts.)
- **CLI**: global `--profile-mode` and `--profiles-dir`, with `VERIFLOW_PROFILE_MODE` and
  `VERIFLOW_PROFILES_DIR`. The OCP renderer gains `--profile-mode`.
- **Pipeline summary**: profile mode, registry version, runtime and skipped profiles, and the
  source of each profile row.

## Verification

- `uv run pytest`: 1421 passed. `tests/test_joern_runtime_profiles.py` (19): directory loading
  and auto inclusion, explicit selection, eight skip cases, query change after load, the full
  add/test/approve/disable cycle with idempotency and staleness, approval refused without a
  passing executed test, internal-pattern profiles and mode rules, LLM-path redirects, scaffold
  inactivity, CLI mode and environment variable, digest-aware reuse, and the CSV pipeline
  picking up a new profile and rescanning only new or changed ones.
- The phase 0 golden test still passes: packaged behaviour is unchanged.
- Migration `0012` upgraded a copy of a real `0011` database; integrity `ok`.
- Real Joern 4.0.625 on the host: a runtime profile for `exec.CommandContext(ctx, "sh", "-c", …)`
  (not covered by `go-http-shell-v1`) passed `profile-test` (vulnerable 1, fixed 0, misleading
  0 where the misleading fixture is the packaged `exec.Command` case), was approved, and in
  `approved` mode the pipeline reported the packaged finding at `main.go:7` and the runtime
  finding at `main.go:11`.

## Non-claims

- Runtime profiles are ungated: advisory outcomes stay `abstain`; model verdicts are unverified.
- `profile-test` checks fixture agreement only, not coverage or precision.
- A Joern query is code with JVM access; the trusted directory is trusted by definition.
- No pin prevents choosing `trusted-directory` mode; this is a POC decision.
- No image was built and no Job ran on OCP.

## Next

Phase 3 (declarative review gate) is deferred. Commit, build the image, and try a runtime
profile on OCP through `oc rsh` and the toolbox pod.
