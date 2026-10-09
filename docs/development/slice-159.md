# Slice 159 — Fair evidence allocation, windowed triage and a tunable envelope

## What was added

Long dataflow paths previously lost their sink-side evidence and then abstained silently. The
sections below address that. None of them relaxes an evidence gate: each changes what is sent or
what is spent, and no path sets `verified: true`.

### Duplicate regions merge before the budget is spent

`bundles.merge_duplicates` collapses references that bind to one `(role, path, line, end_line)`
region, recording `flow_steps_covered` on the surviving snippet. A primary location never merges
into a flow step sharing its region, and unmapped references are never collapsed together. The
count is reported as `duplicate_locations_merged`.

The Joern C# fixtures show the effect: a three-node path that previously consumed three slots now
consumes two. The eight-node Rust crossfile fixture materializes 6 snippets covering all 9
locations, with `duplicate_locations_merged == 3`.

Merging changed three places that assumed one snippet per flow step:

- `source_context.covered_steps` / `covers_flow_step` are the shared predicate.
- Every `*_claims.anchors` module compares coverage instead of a single `flow_step`.
- `claims._assess_supported` links source to sink through covered steps, and the Java/C# thread
  completeness check unions them.
- `joern_claims.review_preflight` maps each native node to the snippet covering its step, and
  binds the source/sink obligations to node steps 0 and `len(nodes) - 1` rather than to list
  positions.

### Truncation keeps both flow endpoints

`bundles.select_references` retains primary locations, then splits the remaining budget between
the flow head and tail, then related locations. For a 43-location candidate with a budget of 8 it
keeps flow steps 0–3 and 39–41 instead of 0–6, so the taint source and the node adjacent to the
sink both survive. `bundles.elided_index` records `{role, path, line, flow_step}` for every
omitted location without its source text, and the gap is now `location_limit:<n>_elided`.

### Source bytes are allocated max-min fair, not greedily

`bundles.allocate_source` replaces the in-order greedy spend. Every retained location is offered a
set of excerpt widths from `bundles.excerpt_options` — the region itself, then widening context,
then the whole file where the small-file rule applies. Allocation serves each location's narrowest
excerpt before any location gets context, ordered by `(priority, minimum size, position)` where
primary and endpoint locations take priority 0, then upgrades context one step at a time across
all locations until the budget is spent.

The practical effect: a large intermediate region can no longer starve the flow's source or sink,
which is precisely what head/tail retention set out to keep. On a fixture with two 9 KiB comment
lines mid-flow, all eight selected locations are retained with trimmed context, where the previous
code dropped the oversized one entirely. Locations whose narrowest excerpt still does not fit keep
`location_<n>:source_budget`; trimmed context is reported as `source_budget_trimmed:<n>`.

### The envelope is resolved per profile, not hardcoded

`veriflow/envelope.py` resolves `max_locations`, `max_source_bytes`, `max_bundle_bytes`,
`max_elided_index`, `context_lines` and `max_region_lines`. Precedence is explicit overrides, then
`VERIFLOW_ENVELOPE_*` environment variables, then an operator-authored JSON file
(`--envelope-config` or `VERIFLOW_ENVELOPE_CONFIG`) whose `profiles` block is keyed by rule id,
then packaged defaults. The resolved bounds are recorded in the bundle as `envelope` and
`location_limit`, so the content digest distinguishes bundles built under different bounds, and
`review_preflight` derives its node ceiling from the recorded `location_limit` instead of a second
magic constant. Defaults are unchanged (8 / 16 KiB / 32 KiB), and the `+1` for
`veriflow/joern-rust-env-shell-v1` still applies on top.

CLI surface: `build-bundle`, `triage-attempt`, `triage-windows`, `scan-run` and `scan-import`
accept `--envelope-config` and the six per-field overrides.

### Size bounds outside the envelope

Three further bounds sat on the gate path and were not envelope-aware, so widening the envelope
could not work and in one case made the gate stricter:

- `joern_claims.native_audit` capped the native path at `8 if RUST_POLICY else 7` — the same magic
  bound replaced in `review_preflight`, in a second place. It refused a 12-node path before the
  bundle's envelope was ever consulted, so **no** widened envelope could pass a Joern review
  policy. It now takes `max_nodes` from the bundle's effective `location_limit`.
- `source_context.complete_context` capped reconstructed source at a hardcoded 16 KiB. Widening
  `max_source_bytes` therefore produced bundles whose files the gate could no longer rebuild,
  failing candidates that passed at the narrow envelope. It now reads the bundle's recorded
  `max_source_bytes`, defaulting to `DEFAULT_CONTEXT_BYTES` for bundles built before this slice.
- `review_preflight` reported that failure as the generic `insufficient_native_evidence`. A
  reconstruction failure is now `incomplete_source_context`.

`Decision.evidence_ids` and `Decision.claims` remain capped at `MAX_CITATIONS` (8). That is a
schema contract, not a tunable: evidence beyond eight locations is context the model may reason
over but cannot formally cite. `envelope.compatibility` records that as an explicit note on every
`triage-attempt` and `triage-windows` result when `max_locations` exceeds it, and refuses outright
when an envelope's `max_bundle_bytes` exceeds a configured Ollama context.

### Windowed triage for flows larger than the envelope

`veriflow/windows.py` walks one candidate's flow in overlapping spans. `plan_windows` produces
contiguous spans of `max_locations - 1` steps with a configurable overlap (default 1) so every
step is covered and consecutive windows share a step. `bundles.within_window` restricts the
materialized flow steps to one span while always retaining the reported and related locations, and
the span is recorded in the bundle as `window`, so each window is its own content-addressed
bundle. Out-of-window locations are reported as `window_scope:<n>_outside`, distinct from
`location_limit`.

`triage_windows` pages over candidates like `triage-attempt`. A flow that already fits takes the
ordinary single-bundle path with the ordinary gates. A longer flow is split, and **every window is
triaged with `allow_degraded_evidence`**, because no window observes the complete source-to-sink
path and the linkage check therefore cannot be satisfied by construction. Per-window request keys
are derived from the operator key, attempt, fingerprint, policy, index and span, so a repeated
command replays stored calls rather than paying twice. `--max-windows` bounds the call count
(default 8, ceiling 32) and reports `windows_truncated` with `covered_flow_steps`.

On a 42-step fixture: 7 windows at size 7 overlap 1, `covered_flow_steps == 42`, seven provider
calls, every window `advisory_unverified` with `disposition: "abstain"`, and the page
`verified: false`.

### Unmetered and degraded-evidence triage

`triage(..., unmetered=True)` skips the budget-exists check, the request cap and the cost cap.
It does **not** skip accounting: reservations and actual charges are still written to the ledger,
so `triage-report` reports `overrun_micro_usd` honestly.

`triage(..., allow_degraded_evidence=True)` sends a bundle that is `partial`, has no snippets, or
failed `review_preflight`, instead of abstaining before the call. The reasons are recorded in
`evidence_degraded`. The evidence gate still runs on the response; a non-abstain verdict over
degraded evidence becomes the new state `advisory_unverified` with `disposition: "abstain"` and
`verified: false`, while the model's rationale is retained for an operator. `advisory_unverified`
is in `CONTINUE_STATES`, so a page keeps walking.

Both flags are exposed on `triage`, `triage-attempt`, `scan-run` and `scan-import`; `--unmetered`
is also on `triage-windows`. They surface in results as `metered` and
`degraded_evidence_allowed`.

`advisory_unverified` joins `CONTINUE_STATES` in `batch_triage`, so a degraded page keeps walking
instead of halting on the first reduced answer. `AdvisoryOptions` carries `unmetered`,
`allow_degraded_evidence` and `envelope`, so the inline advisory on `scan-run` and `scan-import`
honours the same options as the standalone commands.

### Bundle identity moves

`BUILDER_VERSION` goes from `13` to `15`. The content gains `notes`, `envelope`, `location_limit`,
`duplicate_locations_merged`, `elided_locations` and `window`, and `merge_duplicates` changes
which snippets a bundle holds. A bundle id is the digest of its content, so **every bundle built
before this slice has a different id from the same candidate rebuilt after it**.

Nothing rewrites a stored bundle. Existing bundles, their triage calls and published reports stay
valid and readable. A rebuild creates a new bundle beside the old one. Bundles without an
`envelope` field fall back to the packaged bounds: `DEFAULT_CONTEXT_BYTES` in `complete_context`,
and the `8 if RUST_POLICY else 7` ceiling in `native_audit` and `review_preflight`.

`bundles.MAX_LOCATIONS` is deleted. `Envelope.max_locations` owns that default now, and a dead
constant naming the old bound would mislead the next reader. `MAX_BUNDLE_BYTES` and
`MAX_SOURCE_BYTES` remain, used only as fallbacks for bundles that predate the envelope.

### Defects found and fixed in review

An adversarial pass over the above found four more, each now covered by a test that fails without
its fix:

- `triage_report` refused to read the ledger when no `TriageBudget` row existed, so an unmetered
  run's charges were unreadable — removing the only accountability an unmetered run has. It now
  reports the ledger with null budget fields and `metered: false`.
- `claims.flask_mapping` still compared a literal `flow_step` prefix against `range(step)`, so a
  merged Flask bundle silently lost its import mapping and failed the linkage check.
- `expansion.expand_bundle` enforced the packaged `MAX_SOURCE_BYTES`/`MAX_BUNDLE_BYTES` rather
  than the envelope the parent was built under, so a widened bundle could never be expanded.
- `triage_candidate_windows` counted `covered_flow_steps` from the span it requested rather than
  the steps a window actually materialized, overstating coverage, and `planned_windows` was
  computed after truncation. Both now report what happened.

### Second review pass

A second pass over the finished work addressed seven further gaps.

**The published report hid every new caveat.** `reports.py` recorded state, disposition, gate and
cost for each advisory call. It recorded neither `metered`, nor `evidence_degraded`, nor the
window span. An unmetered windowed run over seven partial views therefore published the same
`disposition: abstain` as an ordinary gated abstention. The project exists to keep coverage gaps
visible, and this path hid them. Each advisory entry now carries `metered`, `evidence_degraded`,
`window`, `bundle_status` and `max_locations`. `advisory_reductions` names the counts at the top
of the report, and the Markdown and HTML summaries add a line whenever any count is non-zero.

**Trimmed context blocked the gate.** Fair allocation keeps every location by narrowing context.
That narrowing was recorded as a gap, so the bundle became `partial` and `review_preflight`
refused it. Fair allocation could therefore never produce a gate-passing bundle. Narrowing loses
no location, so `source_budget_trimmed:<n>` now sits in a new `notes` field rather than in
`gaps`. The reduction stays visible; the gates, not a proxy, judge sufficiency.

**Allocation starved file reconstruction.** `complete_context` rebuilds a file from its excerpts
and needs full coverage; allocation spreads bytes and trims. `allocate_source` now funds one
complete excerpt per file before it funds general context, so reconstruction survives a tight
budget. A first attempt also capped the other excerpts of that file; it broke 100 tests and was
withdrawn. The guarantee is additive and the deduplication is not worth its cost.

**Overlapping windows hid disagreement.** Adjacent windows share a step and answer about it
twice. `model_suggested_verdicts` is a set, so it collapsed contradiction into one entry.
`triage-windows` now reports `overlapping_steps`, `contradicted_steps` with the differing
verdicts, and `verdicts_disagree`.

**`select_references` ordered by `id()`.** It now carries positions through the partition.
`within_window` returns the inside and outside sets instead of making the caller recompute the
difference by identity. `covered_steps` documents that it accepts a snippet or the metadata it
was built from.

**`MAX_CITATIONS` stays at 8.** It belongs to the request schema every provider validates
against, so raising it changes the model contract rather than an operator setting. Locations past
the eighth are reading context. `envelope_notes` says so on every result that crosses it.

**The `next_offset` criticism was wrong.** A halted candidate has a recorded call, so advancing
past it is correct; the `operation_error` path already does not advance. No change was made.

## What passed

`uv run pytest` — 1366 tests, all passing (8 new in `tests/test_envelope.py`, 12 in
`tests/test_windows.py`, 4 in `tests/test_wide_gate.py`, 4 in `tests/test_window_replay.py`,
1 in `tests/test_modeled_sources.py`). `uv run ruff check .` and `uv run ruff format --check .` clean.

Five existing test modules changed because the behaviour genuinely changed, not to make failures
go away:

- `tests/test_triage.py` — `evidence_fixture` gained `distinct_flow`. Its 20 identical flow
  locations now merge to one rather than overflowing the budget, which is the precise pathology
  this slice fixes. The `location_limit` case now asks for distinct locations.
- `tests/test_evidence_gate.py` — a three-line source puts the taint source and the sink on
  different lines. A flow test should always have exercised that.
- `tests/test_reviews.py` — the partial-bundle case needs distinct locations for the same reason.
- `tests/test_joern_rust_advisory.py` — asserts covered steps instead of a snippet count, since
  the eight-node path now materializes six snippets.
- `tests/test_batch_triage.py` — a stub adapter accepts the new keyword arguments.

New: `tests/test_envelope.py`, `tests/test_windows.py`, `tests/test_wide_gate.py`,
`tests/test_window_replay.py`, and one case in `tests/test_modeled_sources.py`.

Native toolchain acceptance has **not** been run for this slice. `scripts/validate_joern_rust_wide.py`
is new and unrun.

### Coverage above the packaged envelope

`tests/fixtures/joern-rust-env/wide-crossfile/` is a five-file Rust flow of twelve native nodes,
one file padded past 16 KiB while staying inside `max_region_lines` so whole-file context applies.
`tests/test_wide_gate.py` executes the whole chain on it: at the packaged envelope the audit is
`withheld` with reason `native_path_limit` and preflight refuses; at `max_locations=16` with
64 KiB of source the bundle is `ready`, the audit validates all twelve nodes, `review_preflight`
returns `eligible_for_advisory` and `assess_review_evidence` passes. Starving the recorded
`max_source_bytes` back to 16 KiB reproduces `incomplete_source_context`, and tampering with a
node's line or code is still refused. Before this slice, every gate-executing test ran at nine
locations or fewer.

`tests/test_window_replay.py` drives windowed triage through `ReplayAdapter`, so `request_body` is
exercised rather than bypassed by a fake adapter. It pins that `window` and `window_scope` reach
the model, that every recorded bundle field is serialized, that a window prompt stays within
24 KiB, that the elided index stays below a third of the prompt with its cap actually biting at
121 locations, that seven windows produce seven distinct requests and bundles with replayed usage
accounted at 480 micro-USD each, and that reusing a key against a different stored response is
refused.

### Native acceptance

`scripts/validate_joern_rust_wide.py` runs the real toolchain over the wide fixture and is
registered as the `joern-rust-wide` suite in `scripts/validate_container.py`. It records the path
length Joern actually emits rather than asserting the hand-written one, requires only that the
path exceed the packaged envelope, and then asserts the full chain: the packaged envelope refuses
it, the widened envelope validates every node, preflight and the evidence gate pass, and
`reachability_proven` stays false. **This script has not been run.** It needs the pinned
container and a real JDK.

## Documentation

`docs/guides/advisory-triage-operations.md` is the operator guide: diagnosing a bundle's gaps,
widening the envelope, degraded-evidence triage, windowed triage and unmetered runs.

## Explicit non-claims

- Merging and head/tail retention improve which evidence is materialized. They do not make a
  truncated bundle complete, and `location_limit:<n>_elided` is still a visible coverage gap.
- `allow_degraded_evidence` never raises confidence. No path sets `verified: true`, and no
  degraded result can dismiss a candidate.
- `unmetered` removes spend limits, not spend. An operator running it against a paid provider is
  responsible for the cost; the ledger records it but nothing stops it.
- A widened envelope is an operator assertion that the larger evidence set is still reviewable. It
  is not evidence that longer flows are correctly adjudicated. `tests/test_wide_gate.py` now
  establishes that the gate chain accepts twelve nodes, but it does so against a native document
  written by hand. Real Joern output at that length stays unqualified until `joern-rust-wide`
  runs.
- `elided_locations` names omitted steps. It does not summarize them, and the model receives no
  source text for them.
- Fair allocation changes which excerpts survive a tight budget. It does not add evidence, and a
  trimmed excerpt carries less context than the profile intends.
- A windowed run is **not** an adjudication of the flow. No window sees source and sink together,
  so `model_suggested_verdicts` records what a model said about a fragment and nothing more.
  Agreement across windows is not corroboration; the windows overlap and share a prompt shape.
- Window overlap of one step links adjacent spans positionally. It does not establish that the
  data actually flows across the boundary.
- `contradicted_steps` detects that two windows answered differently about one step. It does not
  decide which answer is right, and an absence of contradiction is not agreement about the flow.
- Moving `source_budget_trimmed` from `gaps` to `notes` changes which component judges
  sufficiency. It does not mean that a trimmed excerpt carries the context the profile intends.
- One complete excerpt per file is funded before general context. A budget too small for that one
  excerpt still leaves the file unreconstructable, and the gate still refuses it.
- `advisory_reductions` counts the calls that saw reduced evidence. A count of zero means that no
  call was reduced in the ways this slice can detect, not that the run was complete.
- The window prompt budget of 24 KiB is pinned by a test. No evaluation shows that a model uses
  the elided index it pays for.

## Next step

Run `joern-rust-wide` in the container. Until it passes, the twelve-node path is a synthetic
native document and the gate's behaviour above eight locations is established only against that
document. Then measure whether the elided index changes model behaviour, using the A/B procedure
in the guide; its ~2 KiB per prompt is a reasoned default with no evidence behind it.
