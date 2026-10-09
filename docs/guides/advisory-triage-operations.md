# Advisory triage operations

How to get a long or imperfect dataflow candidate in front of a model, and what the result does
and does not mean afterwards.

Nothing here relaxes an evidence gate. Every option below changes **what is sent** or **what is
spent**. None changes what counts as verified: no path sets `verified: true`, and no model
outcome can dismiss a candidate. A candidate stays unreviewed until an operator reviews it.

---

## 1. Decide which problem you have

Run `bundle-status` on the candidate's bundle first. The `gaps` array names the problem.

```bash
veriflow --state-dir /work/.veriflow bundle-status BUNDLE_ID \
 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(
   "status:", b["status"],
   "\ngaps:", b["gaps"],
   "\nnotes:", b["notes"],
   "\nmerged:", b["duplicate_locations_merged"],
   "\nlocations:", b["locations_total"], "->", b["locations_considered"],
   "\nelided:", len(b["elided_locations"]),
   "\nwindow:", b["window"],
   "\nenvelope:", b["envelope"])'
```

| what you see | what it means | what to do |
| --- | --- | --- |
| `location_limit:<n>_elided` | more locations than the envelope holds | §2 widen, or §5 window |
| `notes: source_budget_trimmed:<n>` | excerpts kept, context narrowed to fit; not a gap | §2 raise `max_source_bytes` if the gate refuses |
| `location_<n>:source_budget` | one region alone exceeds the budget | §2 raise `max_source_bytes` |
| `location_<n>:unmapped` | SARIF path not in the snapshot | §4, a wider envelope will not help |
| `location_<n>:range_limit` | region past end of file, or over `max_region_lines` | §2 raise `max_region_lines` |
| `window_scope:<n>_outside` | this is a window bundle; the rest is in other windows | expected, see §5 |
| preflight `unsupported_profile` | the rule has no review policy | register the rule; §4 meanwhile |
| preflight `incomplete_source_context` | a file exceeds `max_source_bytes` when rebuilt | §2 raise `max_source_bytes` |
| audit `withheld` / `native_path_limit` | more native nodes than the envelope allows | §2 raise `max_locations`, or §5 |

---

## 2. Widen the envelope

A bundle is built under six bounds:

| field | default | meaning |
| --- | --- | --- |
| `max_locations` | 8 | materialized SARIF locations per bundle |
| `max_source_bytes` | 16384 | cumulative excerpt bytes |
| `max_bundle_bytes` | 32768 | serialized bundle envelope |
| `max_elided_index` | 64 | entries recorded for omitted locations |
| `context_lines` | 3 | lines retained either side of a region |
| `max_region_lines` | 40 | largest single region accepted |

Precedence, most specific first: a CLI flag, then `VERIFLOW_ENVELOPE_<FIELD>`, then an
operator-authored file, then the packaged defaults. `max_source_bytes` must stay below
`max_bundle_bytes`. `veriflow/joern-rust-env-shell-v1` still gets `max_locations + 1` on top.

### Per rule

```json
{
  "defaults": { "max_locations": 12 },
  "profiles": {
    "veriflow/custom-rust-unwrap-v1": {
      "max_locations": 48,
      "max_source_bytes": 65536,
      "max_bundle_bytes": 262144
    }
  }
}
```

```bash
veriflow --state-dir /work/.veriflow triage-attempt REPO ATTEMPT config.json KEY \
  --review-policy <policy> --envelope-config /etc/veriflow/envelope.json
```

### Per invocation

```bash
# flags, one per envelope field
--max-locations 48 --max-source-bytes 65536 --max-bundle-bytes 262144 \
--max-elided-index 128 --context-lines 5 --max-region-lines 80
# or environment, which suits a pod with no argument plumbing
export VERIFLOW_ENVELOPE_MAX_LOCATIONS=48
export VERIFLOW_ENVELOPE_MAX_REGION_LINES=80
export VERIFLOW_ENVELOPE_CONFIG=/etc/veriflow/envelope.json
```

Every field in the table above has a flag of the same name and a `VERIFLOW_ENVELOPE_<FIELD>`
variable.

Accepted by `build-bundle`, `triage-attempt`, `triage-windows`, `scan-run` and `scan-import`.

### Two bounds the envelope does not move

**Citations are capped at 8.** `Decision.evidence_ids` and `Decision.claims` are schema contracts
(`models.MAX_CITATIONS`). Widening `max_locations` past 8 sends the model more context, but it can
still formally cite only eight locations. `triage-attempt` and `triage-windows` report that in
`envelope_notes` when you cross it.

The cap stays fixed on purpose. It belongs to the request schema that every provider validates
against, so raising it changes the model contract rather than an operator setting. Treat
locations past the eighth as reading context. If you need more than eight *cited* locations, the
flow is too long for one bundle, and §5 is the route.

**Ollama needs its own knob.** An envelope whose `max_bundle_bytes` exceeds the configured
`ollama_context_tokens` is refused up front, naming both. Raise `ollama_context_tokens` in the
model configuration (ceiling 131072) alongside the envelope.

Per-file source reconstruction follows the bundle's recorded `max_source_bytes`. If a file still
cannot be rebuilt within it, preflight reports `incomplete_source_context` rather than a generic
failure.

The resolved bounds are recorded in the bundle as `envelope` and `location_limit`, and the bundle
id is the digest of its content — so a bundle built under different bounds is a **different
bundle**. Widening never rewrites an existing one, and you can compare the two.

`expand-bundle` inherits the parent's recorded envelope. A bundle built at 64 KiB of source can
therefore be expanded; before, expansion enforced the packaged 16 KiB and refused.

---

## 3. What the builder does with a long flow

Three steps, in order, before anything is sent.

**Merge.** Locations binding to the same `(role, path, line, end_line)` collapse into one snippet
carrying `flow_steps_covered`. Engines routinely emit several dataflow vertices on one source
line; without this they each cost a slot. A reported location never merges into a flow step that
shares its region. Every gate maps native flow nodes through `flow_steps_covered`, so merging
never loosens a check.

**Select.** If still over budget: the reported location, then the flow **head and tail**, then
related locations. A 43-location candidate at the default envelope keeps flow steps 0–3 and
39–41 — the taint source and the node next to the sink — rather than an arbitrary prefix.
Omitted locations are listed in `elided_locations` as `{role, path, line, flow_step}` with no
source text.

**Allocate.** Source bytes are shared max-min fair. Each location is offered a ladder of widths
(the region alone, then widening context, then the whole file where the small-file rule applies).
Every location gets its narrowest excerpt before any gets context, with the reported location and
the flow endpoints served first. One complete excerpt per file is funded next, because the syntax
gates rebuild a file from its excerpts and a file covered only in part cannot be rebuilt at all.
Leftover budget then widens context one step at a time across all locations.

A large intermediate region can no longer starve the sink. It takes its own region and everything
else trades context. That trade is recorded in `notes` as `source_budget_trimmed:<n>`, **not** in
`gaps`: no location was lost, so the bundle stays `ready` and the gates decide on sufficiency.
`gaps` keeps only the reductions that lose evidence.

---

## 4. Send a bundle the gates would refuse

```bash
veriflow --state-dir /work/.veriflow triage-attempt REPO ATTEMPT config.json KEY \
  --review-policy <policy> --allow-degraded-evidence --limit 100
```

Normally a bundle that is `partial`, has no snippets, or fails `review_preflight` abstains
**before** the call. This flag sends it anyway and records why in `evidence_degraded`.

The whole bundle — `gaps`, `elided_locations` and all — is serialized into the request, so the
model is told what it is missing.

The gate still runs on the response. A non-abstain verdict over degraded evidence is recorded as
state `advisory_unverified`, `disposition: "abstain"`, `verified: false`, with the model's
rationale retained for an operator to read. `advisory_unverified` is a continue state, so a page
keeps walking.

Use this when a wider envelope cannot help: an unmappable path, a rule with no review policy, a
region past the limit. It buys a rationale for a human, not an adjudication.

---

## 5. Walk a flow too long for any single bundle

```bash
veriflow --state-dir /work/.veriflow triage-windows REPO ATTEMPT config.json KEY \
  --review-policy <policy> --overlap 1 --max-windows 8
```

Spans are `max_locations - 1` steps wide with a one-step overlap by default, so every step is
covered and consecutive windows share a step. Each window is its own content-addressed bundle
recording its `window` span; locations outside it appear as `window_scope:<n>_outside`.

A 42-step flow at the default envelope:

```
flow_steps=42 window_size=7 overlap=1 windows=7 covered=42/42
  w0: steps  0-6   advisory_unverified  abstain
  w1: steps  6-12  advisory_unverified  abstain
  ...
  w6: steps 36-41  advisory_unverified  abstain
```

**Every window is advisory by construction.** No span observes the complete source-to-sink path,
so the linkage check cannot be satisfied and each call runs with degraded evidence. What you gain
is a model rationale for each segment of a flow that was previously unreachable.

Things to know:

- **Cost scales with window count.** Seven windows is seven provider calls *per candidate*.
  `--max-windows` caps it (default 8, ceiling 32). The result reports `windows_truncated`,
  `planned_windows` (the full plan before the cap) and `window_count` (what ran), so a partial
  walk stays visible.
- **`covered_flow_steps` counts steps that actually materialized**, not spans requested. A window
  whose steps fall outside the file, or that loses locations to its own budget, reports less than
  it asked for. Compare it against `flow_steps`.
- **Re-running is free.** Per-window request keys derive from the operator key, attempt,
  fingerprint, policy, index and span, so a repeat replays the stored calls.
- **A flow that already fits skips windowing** and takes the ordinary single-bundle path with the
  ordinary gates. Check `windowed` in the output.
- **`model_suggested_verdicts` is not a tally.** Agreement across windows is not corroboration —
  the windows overlap and share a prompt shape — and it never dismisses a candidate.
- **Disagreement is reported.** Adjacent windows share a step, so the same step is asked about
  twice. `overlapping_steps` lists every shared step. `contradicted_steps` lists the shared steps
  whose windows answered differently, with the verdicts. `verdicts_disagree` is the one-field
  summary. Read it before any single window's rationale: a flow whose windows contradict each
  other is telling you the fragments are not individually decidable.

---

## 6. Measure whether the elided index earns its place

The index of omitted steps costs about 2 KiB of every prompt. Nothing proves that a model uses
it.

Set `--max-elided-index 0` to remove it, then compare. Run the same candidates twice against the
same provider with different keys:

```bash
V="veriflow --state-dir /work/.veriflow"
$V triage-attempt REPO ATTEMPT config.json with-index --review-policy P --limit 20
$V triage-attempt REPO ATTEMPT config.json no-index  --review-policy P --limit 20 \
  --max-elided-index 0
$V triage-report RUN
```

Compare `accounted_micro_usd` for the cost. Compare the per-call `state` and `disposition` for
the effect. Both runs stay in the ledger, so the comparison is reproducible.

Until somebody runs that, the index is a reasoned default and nothing more.

## 7. Run without a budget

```bash
veriflow --state-dir /work/.veriflow triage-attempt REPO ATTEMPT config.json KEY \
  --review-policy <policy> --unmetered --limit 100
```

`--unmetered` bypasses every budget **check**: the `TriageBudget` row need not exist, the request
cap is ignored, and an exhausted cost cap no longer stops the call.

It does not bypass **accounting**. Reservations and actual charges are still written to the
ledger, so `triage-report` reports what was spent and `overrun_micro_usd` grows past any
configured limit.

`triage-report` works when no budget row exists at all. It returns `metered: false` and null
budget fields, so an unmetered run's spend stays readable. Without that, the one safeguard an
unmetered run has would be unreadable.

There is nothing between an unmetered run and a provider bill. Against a local Ollama provider
the cost is zero and the flag is simply convenient; against a paid provider with `--limit 100`,
or combined with `triage-windows`, the call count multiplies. Prefer a `replay` provider in CI.

Results carry `metered: false`.

---

## 8. Read what the report says about all this

A published report never hides a reduced run. `advisory_reductions` names the counts at the top:

```json
{
  "advisory_calls": 7, "unmetered_calls": 7, "degraded_evidence_calls": 7,
  "windowed_calls": 7, "windowed_candidates": 1,
  "widened_envelope_calls": 0, "partial_bundle_calls": 7
}
```

Each advisory entry also carries `metered`, `evidence_degraded`, `window`, `bundle_status` and
`max_locations`. The Markdown and HTML renderings add a line to the summary when any count is
non-zero, so a reduced run cannot read as a complete one at a glance.

## 9. Putting it together

```bash
SD=/work/.veriflow; V="veriflow --state-dir $SD"
CFG=/etc/veriflow/advisory.json; POLICY=joern-rust-env-review-v1; KEY=run-$(date +%s)

# 1. see what the default envelope makes of it
$V scan-report REPO --attempt-id ATTEMPT | python3 -c 'import json,sys
r=json.load(sys.stdin); print(r["language"], r["discovery_profile"], len(r["candidates"]))'

# 2. a long but complete flow: widen and triage normally
$V triage-attempt REPO ATTEMPT $CFG $KEY --review-policy $POLICY \
   --envelope-config /etc/veriflow/envelope.json --limit 50

# 3. too long for one prompt: walk it
$V triage-windows REPO ATTEMPT $CFG $KEY-win --review-policy $POLICY --max-windows 8

# 4. read the ledger and the outcomes
$V triage-report RUN | python3 -c 'import json,sys
d=json.load(sys.stdin); print(d["accounted_micro_usd"], d["overrun_micro_usd"],
  [(c["state"], c.get("disposition")) for c in d["calls"]])'

# 5. publish, since triage does not
$V publish-report REPO --attempt-id ATTEMPT
```

`triage-attempt` and `triage-windows` do **not** publish. Run `publish-report` afterwards or the
latest published report still shows the pre-triage state.

---

## 10. Choosing

- The flow is complete and merely long → **widen the envelope** (§2). Gates run normally; this is
  the only route that can still produce a gate-passing advisory result.
- The flow is longer than any prompt you want to send → **window it** (§5). Advisory only.
- The evidence is broken, not big — unmapped paths, an unregistered rule → **degraded** (§4).
  Advisory only, and fix the underlying cause.
- You are iterating locally against Ollama, or evaluating → **unmetered** (§7), alone or with any
  of the above.

A rule absent from `RULE_POLICIES` has no review policy and no native audit, so `review_preflight`
returns `unsupported_profile` at any envelope and through any window. Registering the rule is the
fix; §4 only lets you hear what a model says meanwhile.
