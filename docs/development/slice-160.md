# Slice 160 — CSV pipeline command and advisory under automatic selection

## What was added

### `run-pipeline-from-csv`

`csv_pipeline.run_pipeline` takes each CSV row, one at a time, through preflight, import,
selection, every Joern profile of every detected language, optional LLM discovery, triage of
every candidate, publication, export and a summary. Defaults: engine Joern, language `auto`,
`--unmetered` and `--allow-degraded-evidence` on. A separate `pipeline.lock` stops two runs on
one state directory; scanner stages still take `exclusive_worker` themselves, because that lock
is not reentrant.

Resume rules:

- Import is reused when the latest snapshotted run has the same `source_uri` and archive
  SHA-256. A changed archive needs `--reimport`.
- A (language, profile) attempt is reused when it is `partial` or `completed`. A failed one is
  scanned again. An empty one is scanned again only with `--rescan-empty`.
- Triage request keys come from the advisory config digest, attempt, candidate and policy, so
  stored calls are returned with no provider call.

Each step writes JSON lines to `pipeline.log` and the repository `steps.log`, with a progress
line on stderr. `pipeline_summary` renders repository and run summaries (JSON, Markdown, HTML)
from the published reports. They follow the OpenAnt overview, but keep candidate language and
show coverage gaps and ungated profiles.

### Advisory with automatic selection

`--review-policy auto` (`scan_advisory.AUTO_POLICY`) binds each (language, profile) to its
reviewed policy through `joern_claims.policy_for`, or to none. `scan_selected` now accepts it
and reports summed model calls. Before this, automatic selection refused all advisory. Nine of
the 24 packaged profiles have a reviewed gate; the other 15 send ungated requests, which stop at
`unsupported_rule` unless degraded evidence is allowed, and stay unverified.

### LLM discovery with automatic selection

`pipeline.scan_run` read `attempt_id` from the result, which automatic selection never sets, so
`--llm-discovery` with `--joern-profile auto` was always `skipped_deterministic_incomplete`. It
now runs one pass per detected language on that language's first usable attempt. Live discovery
also accepts `unmetered`, and records `metered` on the call.

### Markdown escaping

`reports.markdown_cell` escaped characters one after another, so `#` was escaped again inside
earlier entities (`(` became `&&#35;40;`). It now escapes in one pass. Existing Markdown reports
are affected for any value with `_`, `(`, `[`, `{` or similar.

### OpenShift

`containers/Containerfile.pipeline` adds the current wheel to a qualified Joern base, with the
`veriflow` console script as entrypoint. `scripts/render_ocp_pipeline.py` renders a
ServiceAccount, NetworkPolicy and Job: persistent state PVC, config Secret, hosted-provider
egress limited to DNS and TCP 443 for given CIDRs, or an Ollama native sidecar on loopback with
no egress.

### Adversarial review fixes

An adversarial review found 16 defects in the first version; all are fixed and each has a test.

- Triage runs per candidate. LLM-discovered candidates use the exploratory gate; before, they
  inherited the anchor profile's Joern gate and always ended `abstain`.
- Ungated Joern candidates always end `abstain` (`assess_evidence` returns
  `unsupported_engine`). The summary now shows the raw model verdict as unverified, and
  `--no-ungated-triage` skips them.
- Request keys include the config digest, adapter identity, bundle, policy and both run flags.
  Budget and gate stops are sent again when a later run removes the stop; envelope or builder
  changes triage again instead of failing with a key conflict. `unknown` is retried only with
  `--retry-unknown`. Three fresh `unknown` results in a row stop provider traffic for the run.
- A repository is `partial` while any candidate has no model answer.
- CSV values are stripped as intake strips them; the import key comes from the one-row CSV
  bytes, so reordered columns do not collide; repeated `repo_id` rows fail on their own.
- `--reimport` imports only changed or failed rows; `--force-reimport` imports all.
- A crash in one profile keeps earlier profile rows and continues; errors that are not
  `VeriFlowError` are logged by type only.
- The triage ledger, discovery history and scan reports are written in full, page by page.
- Budget options without `--no-unmetered` are refused.
- Selected-language LLM discovery reports only the languages it scanned.
- OCP: the Ollama startup probe is an exec probe (a TCP probe from the kubelet cannot reach the
  pod loopback), and `/work` is mounted because the Joern base image uses it as HOME.

### SQLite review

- No pipeline stage keeps a transaction open while Joern or a provider runs.
- Stages retry `exclusive_worker` contention and SQLite `locked`/`busy` errors with backoff.
  Before, contention from another process failed the stage at once.
- A global `BEGIN IMMEDIATE` was tested and rejected: reviews, rule registry, import controls
  and one LLM discovery review path nest transactions and would deadlock. Deferred `BEGIN`
  stays; the pipeline's own paths do not nest.

## Verification

- `uv run pytest`: 1399 passed.
- `tests/test_csv_pipeline.py` (24): the first 12 cases plus one regression test per review
  finding and the lock retry.
- `tests/test_render_ocp_pipeline.py` (7) and two new `tests/test_joern_selection.py` cases.
- A host run with Joern 4.0.625 on the `joern-flask/vulnerable` fixture: 4 Python profiles,
  1 candidate, triaged under `joern-flask-review-v1` with a replay provider. A second run reused
  the import, all 4 attempts and the triage call (0 provider calls). Repeated after the review
  fixes with the same result.

## Non-claims

- No live provider was called. No container image was built and no Job ran on OCP.
- Advisory outcomes are not verdicts. Ungated outcomes are unverified even when they complete.
- Calls stored as `unknown` are retried only with `--retry-unknown`.
- The state PVC must be RWO block storage; SQLite on shared network storage is unsupported.
- No migration.

## Next

Build `Containerfile.pipeline` for the general, C# and Rust bases and run the rendered Job on
OCP with Ollama and one hosted provider.
