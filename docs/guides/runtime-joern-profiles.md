# Runtime Joern profiles (Slice 162)

A runtime profile adds one Joern query and its wording without a code change or a new image.
It is stored on the state volume and is picked up by every Joern command when it starts:
`scan-run`, `scan-import`, `run-pipeline-from-csv` and `joern-<lang>-discover`. With
`--joern-profile auto` it runs after the packaged profiles of its language; it can also be
named with `--joern-profile <name>`.

Runtime profiles produce **candidates only**. By default they get the generic
`runtime-native-v1` review gate (below); with `"review_gate": "none"` advisory triage always
ends `abstain`, and the pipeline summary shows the model's verdict as unverified.

## Two modes

| | `trusted-directory` (default) | `approved` |
|---|---|---|
| Packaged profiles | loaded | loaded |
| Profiles in the trusted directory | loaded, no test or approval | ignored and listed as ignored |
| Approved registry profiles | loaded | loaded |

Choose the mode before the command name, or with an environment variable:

```sh
veriflow --state-dir /state --profile-mode approved run-pipeline-from-csv ...
export VERIFLOW_PROFILE_MODE=approved
```

The trusted directory is `<state-dir>/profiles`; change it with `--profiles-dir` or
`VERIFLOW_PROFILES_DIR`. A command reads the catalog once, so one run sees one consistent set.
`veriflow profile-list` shows the effective catalog, skipped profiles and the reason for each.

## Profile folder

```text
acme-go-commandcontext-v1/
  profile.json          descriptor (below)
  query.sc              the Joern query
  fixtures/             needed only for the approved workflow
    vulnerable/ fixed/ misleading/    a source file or a small folder each (max 50 files)
```

```json
{
  "schema_version": "1",
  "name": "acme-go-commandcontext-v1",
  "language": "go",
  "rule_id": "acme/joern-go-http-commandcontext-v1",
  "query": "query.sc",
  "message": "CWE-78: Go HTTP form input to exec.CommandContext shell text; discovery only.",
  "limitations": ["net/http FormValue/PostFormValue to os/exec.CommandContext only."],
  "selection": "auto",
  "review_gate": "runtime-native-v1",
  "weakness": {"cwe": ["CWE-78"], "internal_pattern": null},
  "fixtures": [
    {"kind": "vulnerable", "file": "vulnerable", "expected_flows": 1},
    {"kind": "fixed", "file": "fixed", "expected_flows": 0},
    {"kind": "misleading", "file": "misleading", "expected_flows": 0}
  ]
}
```

Rules checked when the catalog loads:

- `name` ends in `-vN`, equals the folder name, and is not a packaged profile name.
- `rule_id` is `<namespace>/<id>`; the `veriflow/` namespace is reserved.
- `weakness` names at least one CWE, or an internal pattern such as
  `{"id": "ACME-2026-007", "title": "Unsigned report export"}`, or both.
- `selection` is `auto` (default) or `explicit` (runs only when named).
- `review_gate` is `runtime-native-v1` (default) or `none`.
- Files are regular files, not links, not world-writable; descriptor at most 32 KiB, query at
  most 1 MiB. A bad profile is skipped and reported; other profiles still load.
- A trusted-directory profile with the name of an approved profile is skipped; the approved
  profile stays active.
- Runtime profiles cannot use the Python hooks that some packaged profiles need (Flask
  endpoint audit, C# query-source mapping).

## Default review gate (`runtime-native-v1`)

Packaged gates check source and sink syntax with code written for each profile. A runtime
profile has no such code, so its default gate keeps every check that works for any query:

- the native output matches its recorded digest, and regenerating SARIF from it gives the
  stored SARIF byte for byte;
- the scanner version, language, profile and query digest match the attempt;
- every path node's code appears on its source line, with complete source context;
- the model's source and sink claims cite exactly the first and last recorded path nodes and
  quote their **complete** source lines (a fragment such as the node code alone is rejected),
  and the recorded flow links them;
- only `needs_review` can pass; a negative verdict is never accepted (it becomes `abstain`).

It does **not** check that the endpoints are the intended source or sink API
(`endpoint_syntax_verified: false`). A passed gate means the model's citation agrees with the
path the query recorded, not that the query models the weakness correctly. The policy ID is
`runtime-native-v1:<profile name>`; `--review-policy auto` and the CSV pipeline use it
automatically. Set `"review_gate": "none"` in the descriptor to opt out.

## Cost of a gate change

The review policy is part of every triage request key. When a profile's gate changes — for
example when a runtime profile first gets `runtime-native-v1`, or when `review_gate` is set to
`none` — the next pipeline run sends each of its candidates to the model again, because the
earlier answer was given under a different gate. The earlier calls stay in the ledger. Expect
one new request per candidate of each affected profile; use `--no-ungated-triage`,
`"review_gate": "none"` or `--no-unmetered` with a budget to control the spend.

## Query contract

`veriflow profile-scaffold NAME --language go --output DIR` writes a template. Its
`CWE-TODO` placeholder keeps it inactive until you edit it. The query receives `cpgFile` and
`outFile` and must write JSON with:

`schema_version: "2"`, `engine_id: "joern"`, `rule_id` equal to the descriptor,
`represented_<language>_files`, `source_count`, `sink_count`, `flow_count`, and `paths`
(each node with `code`, `file`, `line`). Output that breaks the contract fails the attempt.

A Joern query is a Scala program with full JVM access. A runtime profile is code that runs in
the scanner, at the same trust level as the packaged queries.

## Trusted-directory workflow

```sh
oc rsh -n scan veriflow-toolbox
veriflow profile-scaffold acme-go-commandcontext-v1 --language go --output /state/profiles
vi /state/profiles/acme-go-commandcontext-v1/query.sc       # sources, sinks, rule_id
vi /state/profiles/acme-go-commandcontext-v1/profile.json   # wording, weakness
veriflow --state-dir /state profile-list                    # check it is active
```

The next command picks it up. Editing `query.sc` changes its digest, so the next run scans that
profile again instead of reusing the old attempt.

## Approved workflow

```sh
veriflow --state-dir /state profile-add /work/acme-go-commandcontext-v1     # -> DRAFT_ID
veriflow --state-dir /state profile-test DRAFT_ID --joern-home /opt/joern-cli
veriflow --state-dir /state rule-registry                                  # current version
veriflow --state-dir /state profile-approve DRAFT_ID /work/approval.json approve-acme-go-cc-v1
veriflow --state-dir /state --profile-mode approved profile-list
```

- `profile-add` copies the folder into `/state/profile-drafts/DRAFT_ID` with digests. Nothing runs.
- `profile-test` runs the real Joern on each fixture in a disposable state and records the
  result. Without `expected_flows`, vulnerable must give at least one candidate and the others
  none. C# needs `--joern-repair-dir`; Rust needs `--rust-home` and a crate folder fixture.
  A setup error (for example a wrong `--joern-home`) is recorded as a failed fixture.
- `profile-approve` needs a passing test made with the current Joern version and query, and the
  current registry version in the approval document:
  `{"draft_sha256": "DRAFT_ID", "expected_registry_version": 0, "reviewer_label": "...",
  "rationale": "..."}`. The last argument is an idempotency key: a retry with the same key
  and draft returns the same approval while it is still active. The approval records the
  descriptor's `review_gate`; a registry entry without one stays ungated.
- `profile-status DRAFT_ID` shows the draft, its tests and every approval.
- `profile-disable NAME --expected-registry-version N --reason TEXT` writes a registry version
  without the profile; earlier versions stay readable. To enable the same draft again, approve
  it with a **new** key; the old key is refused because its approval is no longer active. A
  changed query needs a new draft, and usually a new name (`-v2`).

## What is recorded

Each attempt has `profile_provenance`: source (`packaged`, `trusted_directory`, `registry`),
mode, registry version, draft ID and internal pattern; `query_sha256` is the query that ran.
The pipeline summary lists the mode, the registry version, the runtime profiles and the
skipped ones, and shows the source of each profile row.

## On OCP

Runtime profiles live on the state PVC (`/state/profiles`, `/state/profile-drafts`), so they
survive pod restarts and need no image change. `scripts/render_ocp_pipeline.py
--profile-mode approved` sets `VERIFLOW_PROFILE_MODE` in the Job.
