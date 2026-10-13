# Slice 163 — Default review gate for runtime Joern profiles

## What was added

Runtime profiles now get a review gate by default: `runtime-native-v1`, policy ID
`runtime-native-v1:<profile name>`. A descriptor can opt out with `"review_gate": "none"`;
`runtime-native-v1` is the default.

The packaged Joern gates combine generic native-evidence checks with source/sink syntax checks
written per profile. The default gate keeps all generic checks and replaces the syntax checks:

- `native_audit` and `review_preflight` run unchanged for runtime policies: native output
  digest, SARIF regeneration byte for byte, scanner version, language, profile, query digest
  (from the catalog), node code on its source line, complete source context.
- Endpoint syntax is not checked; the preflight records `gate: runtime-native-v1` and
  `endpoint_syntax_verified: false`.
- Claims use `joern_claims.runtime_anchors`: a source or sink claim must cite the first or last
  recorded node's line and quote its code. The shared flow-link check still applies.
- As for packaged Joern gates, only `needs_review` can pass; negative verdicts become `abstain`.

Runtime gate policies are registered from the active catalog (`joern_claims.register_runtime`,
called once per resolved catalog). `policy_for`, `require_policy`, `query_digest` and the new
`policy_for_rule` (used by bundles) include them. Bundle building, triage, batch triage and the
single-profile scan resolve the catalog first.

A defect found while building it: SARIF regeneration in `native_audit` has no store, so a
runtime rule fell back to the language-default message and every runtime audit was withheld.
`message_for` now uses the catalog in force when no store is given; a test fails without it.

The pipeline summary lists runtime-gated profiles as a coverage gap ("path consistency only,
endpoint syntax unchecked"), and `profile-list` shows each profile's gate.

## Adversarial review fixes

An adversarial review of the staged phase 1 and gate changes found 11 issues; all are fixed and
each has a regression test.

1. **Migration `0012` failed on databases with approved rule drafts** (`DROP TABLE rule_drafts`
   broke `rule_approvals` foreign keys during the SQLite rebuild). `0012` is now additive:
   runtime drafts, tests and approvals have their own tables (`profile_drafts`,
   `profile_tests`, `profile_approvals`) and folder (`<state>/profile-drafts`); `rule_drafts` is
   unchanged. A test upgrades a `0011` database holding an approval.
2. **A disabled profile could not be approved again**, and the same key returned a stale
   approval as success. Approvals are no longer unique per draft; a same-key retry is accepted
   only while that approval is active; a new key re-approves after a disable.
3. **The default gate applied retroactively.** Approvals record `review_gate` explicitly; a
   registry entry without it loads as `none`.
4. **Re-triage cost after a gate change** is documented in the runtime profile guide.
5. **`profile-scaffold` accepted path separators in the name.** It now requires the descriptor
   name pattern.
6. **Process-wide gate state.** The runtime gate registry and the message fallback are removed;
   gate functions take the store and read its catalog.
7. **A directory profile could switch off an approved one.** The approved profile now stays
   active and the directory copy is skipped.
8. **Misleading stage label.** A query that changed after the catalog loaded now fails in
   `query_load`, not `source_copy`.
9. **Misleading rescan reason.** A failed attempt is reported as `previous_attempt_failed` even
   when it recorded no query.
10. **`profile-test` errors left no record.** Each fixture's setup error is now recorded as a
    failed fixture.
11. **Weak citations.** Runtime anchors require the complete endpoint source line, not a
    fragment; preflight records `assurance: path_citation_only`; the pipeline summary counts
    `needs_review` results under the default runtime gate separately.

## Verification

- `uv run pytest`: 1431 passed. New tests: a runtime candidate's bundle gets a
  validated native audit; preflight passes with `endpoint_syntax_verified: false`; a cited
  decision ends `needs_review` with the gate passed and `verified: false`; a negative verdict
  ends `abstain`; a source claim quoting a line off the recorded endpoint is
  `evidence_rejected`; `"review_gate": "none"` leaves the profile ungated with no native audit.
- Packaged gates and the phase 0 golden test are unchanged.
- Real Joern 4.0.625, fresh state: the `CommandContext` runtime profile passed `profile-test`
  (1, 0, 0), was approved with `review_gate: runtime-native-v1`, ran in `approved` mode next to
  the packaged Go profile, and its candidate's native audit validated with the preflight
  `eligible_for_advisory`, `assurance: path_citation_only`.

## Non-claims

- A passed default gate means the model's citations agree with the recorded path, not that the
  query models the intended weakness or that the endpoints are the right APIs.
- C# runtime profiles: discovery remaps C# output, but the native audit only remaps for the
  packaged C# policy. When remapping changed the output, the audit is withheld and those
  candidates go to the model as degraded, unverified evidence.
