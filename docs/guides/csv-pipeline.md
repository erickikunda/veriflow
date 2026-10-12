# CSV pipeline — `run-pipeline-from-csv` (Slice 160)

One command takes a repository CSV through intake, Joern discovery for every bounded profile of
every detected language, advisory triage of every candidate, report export and a summary. It
processes rows strictly one at a time. Its output is **candidates and advisory outcomes**: no
entry is a confirmed vulnerability, `verified_finding_count` stays `null`, and zero candidates
is not a clean result.

## Run on a host

```sh
uv run veriflow --state-dir .veriflow run-pipeline-from-csv repos.csv \
  --input-root /data/archives \
  --advisory-config advisory.json \
  --joern-home /opt/joern-cli \
  --output-dir work/pipeline/nightly
```

The CSV uses the intake columns (`repo_id, source_type, source_uri, owner, classification`, plus
optional `sha256`, `scan_profile`, `acquisition_receipt`, `acquisition_sha256`). Archives must be
under `--input-root`. Git and GCS sources must be acquired first by the networked acquisition
container; this command does not acquire.

| Option | Default | Effect |
|---|---|---|
| `--output-dir` | `work/pipeline/<UTC timestamp>` | Logs and reports; may already exist |
| `--unmetered / --no-unmetered` | on | Bypass budget checks; charges are still recorded |
| `--allow-degraded-evidence / --no-…` | on | Send incomplete and ungated bundles; results stay unverified |
| `--budget-micro-usd`, `--max-requests` | none | Required with, and only accepted with, `--no-unmetered` |
| `--rescan-empty` | off | Scan again profiles whose last attempt found zero candidates |
| `--reimport` | off | Import again rows whose archive changed or whose import failed |
| `--force-reimport` | off | Import every row again (new runs, full rescan and triage) |
| `--retry-unknown` | off | Send again calls stored as `unknown`; the provider may charge twice |
| `--ungated-triage / --no-ungated-triage` | on | Send candidates of profiles without a reviewed gate |
| `--llm-discovery` | off | Add one LLM discovery pass per detected language |
| `--llm-discovery-config` | `--advisory-config` | Separate model config for discovery |
| `--joern-repair-dir`, `--rust-home` | none | Needed for C# and Rust; missing ones become scope errors |
| `--no-check-connectivity` | check on | Skip the TCP probe of live endpoints |
| `--replay`, `--llm-discovery-replay` | none | Replay responses for replay configs |

The engine is always Joern and the language is always `auto`. State must be initialized or
upgradeable; the command runs the Alembic upgrade itself.

## What happens per row

1. **preflight** — values are stripped as intake strips them. A repeated `repo_id` fails that
   row (`row-<n>` folder) and leaves the first row's output alone. The row classification must
   be in `allowed_classifications` of every config in use.
2. **import** — the latest snapshotted run for `repo_id` is reused when its `source_uri` and
   archive SHA-256 still match. A changed archive stops that row until you pass `--reimport`,
   which imports only changed or failed rows. Otherwise the row is submitted as a one-row
   `intake.csv` with a key derived from its bytes, so an interrupted import resumes instead of
   duplicating.
3. **select** — `joern_selection.selection(manifest, "auto")` lists the detected languages and
   every (language, profile) pair.
4. **scan** — per pair: reuse the latest usable attempt (`partial` or `completed`); scan again
   when there is none, when it failed, or when it is empty and `--rescan-empty` is set.
5. **llm-discovery** (only with `--llm-discovery`) — one pass per detected language, attached to
   that language's first usable attempt. The request key includes the attempt and config digest.
6. **triage** — every candidate of every usable attempt, one at a time. Joern candidates use
   the reviewed policy of their profile where one exists (`joern_claims.policy_for`).
   LLM-discovered candidates always use the exploratory gate, never a Joern profile gate. A
   failed candidate is logged and skipped. `budget_exhausted` or `request_limit_exhausted`
   stops triage for the row. Three fresh calls in a row that end `unknown` stop provider
   traffic for the rest of the run (`provider_unavailable`).
7. **export** — publish each attempt again (so triage history is included) and write its files.
8. **summary** — the repository summary, written even when an earlier step failed.

A failure in one row never stops the next row. The command exits 1 when any row failed.

## Resume

Run the same command again. Imports, usable scans and triage calls are reused. A triage request
key is derived from the advisory config digest, adapter identity, attempt, candidate, bundle,
review policy, `--unmetered` and `--allow-degraded-evidence`. So:

- A stored call is returned with no provider call.
- A call that ran out of budget, or stopped at `unsupported_rule` / `incomplete_evidence`, is
  sent again when you rerun with the flag that removes that stop.
- A new envelope, bundle builder or model config makes a new bundle or key and triages again.
- Calls stored as `unknown` (a provider error or an interrupted call) are retried only with
  `--retry-unknown`, because the provider may already have charged for them.

A repository with any candidate that has no model answer is `partial`, and its summary names
the states.

## Ungated profiles and model verdicts

Only 9 of 24 packaged profiles have a reviewed evidence gate. For a Joern candidate without one,
`assess_evidence` returns `unsupported_engine`, so the advisory outcome is always `abstain`,
whatever the model says. The summary therefore shows the raw model verdict in a separate,
unverified column (`Model verdict (unverified)`, `by_model_verdict`). Use
`--no-ungated-triage` to skip those candidates and save the cost; they then stay `not_triaged`.

## SQLite state

- The pipeline holds `pipeline.lock` for the whole run. Each stage still takes the
  `exclusive_worker` file lock and short SQLite transactions; no transaction is open while
  Joern or a provider runs.
- When another process holds `exclusive_worker`, or SQLite reports `database is locked` /
  `busy`, the stage waits and retries up to six times (1, 2, 4, 8, 16 s). Every wrapped stage is
  idempotent or resumable. Avoid other write commands on the same state directory during a run;
  read commands are safe under WAL.
- Some other commands (reviews, rule registry, import controls) nest transactions, so the
  store keeps deferred `BEGIN`; a global `BEGIN IMMEDIATE` would deadlock them.

## Output

```text
<output-dir>/
  pipeline.log                 JSON lines for every step of every row
  summary.{json,md,html}       run summary: one row per repository, totals, legend
  <repo_id>/
    steps.log                  JSON lines for this repository
    intake.csv                 the one-row CSV submitted (only when imported)
    summary.{json,md,html}     repository summary
    triage-ledger.json         full run triage ledger, all pages (includes model results)
    discovery-report.json      only with --llm-discovery
    <language>-<profile>/
      report.{json,md,html}, scan.csv, candidates.csv, results.sarif,
      scan-report.md (scan-report-NNN.md per 1000 candidates when larger)
```

Logs never contain source text. `results.sarif` and `triage-ledger.json` can contain sensitive
detail; treat the output directory like the source archives. The progress lines also go to
stderr; the final JSON goes to stdout.

The repository summary follows the OpenAnt overview, adapted to this tool: overview (run,
snapshot, languages, provider, metering, cost from the run ledger), candidates grouped by
advisory outcome (`needs_review`, `likely_false_positive`, `abstain`, `not_triaged`), the
discovery-profile table, the step table with durations, problems, coverage gaps and the
category legend. There are no disclosure documents.

## Providers

- **Anthropic / OpenAI**: the config needs `allow_source_transmission: true`, explicit pricing,
  an allowed HTTPS endpoint and `api_key_env` set in the environment.
- **Ollama**: the config endpoint must be a numeric loopback `http://127.0.0.1:<port>/api/chat`
  with a locally installed model.

## Run on OpenShift

Build the image (C# and Rust need their own base):

```sh
uv build
docker build -f containers/Containerfile.pipeline -t veriflow:pipeline-linux-poc .
docker build -f containers/Containerfile.pipeline \
  --build-arg BASE=veriflow:joern-csharp-advisory-linux-poc@sha256:<digest> \
  -t veriflow:pipeline-csharp-linux-poc .
```

Mirror it and render a Job (the renderer never contacts a cluster):

```sh
uv run python scripts/render_ocp_pipeline.py --namespace scan --name nightly-20261012 \
  --image registry.example/veriflow-pipeline@sha256:<digest> \
  --input-pvc archives --reports-pvc reports --state-pvc veriflow-state \
  --config-secret advisory-config --provider anthropic \
  --api-key-secret anthropic-key --api-key-env TRACEPROOF_ANTHROPIC_API_KEY \
  --egress-cidr <provider CIDR> --output work/nightly.json
oc apply -f work/nightly.json
```

- `/input` holds the CSV (`--manifest`, default `repos.csv`) and the archives, read-only.
- `/config/advisory.json` comes from the config Secret; the API key Secret uses the key `api-key`.
- Reports go to `/reports/<job name>`.
- `/state` holds SQLite and scan artifacts and **must persist** for resume. Use a block-backed
  PVC with `ReadWriteOncePod` (or RWO, and never two Jobs on one PVC at a time); never RWX or
  NFS storage.
- `/work` and `/tmp` are emptyDir scratch; the Joern base image uses `/work` as HOME.
- Hosted providers: the NetworkPolicy allows DNS and TCP 443 to the given CIDRs only.
  NetworkPolicy cannot filter by host name; use an EgressFirewall for that.
- Ollama: `--provider ollama --ollama-image <digest> --ollama-models-pvc <pvc>` adds a native
  sidecar (`initContainers` with `restartPolicy: Always`, OpenShift 4.16 or later) on
  `127.0.0.1:11434`, and no egress. Its startup probe runs `ollama list` inside the pod,
  because kubelet TCP probes come from the node and cannot reach the pod loopback. Models must already be on the models PVC, and the image must
  run as an arbitrary non-root UID.
- `--toolchain csharp|rust` adds the repair directory or Rust home of the matching image.
- `--rescan-empty`, `--reimport`, `--force-reimport`, `--retry-unknown` and
  `--llm-discovery` pass through.

The image and Job are rendered and unit-tested only. They are not OCP-qualified.
