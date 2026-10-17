# Validate LLM discovery contracts with replay

Slice 143 provides an offline contract harness for the hybrid scan mode. It validates a bounded
source packet and structured model response against an exact completed deterministic scan, then
stores provenance in the discovery ledger. Slice 145 promotes valid proposals into explicitly
unreviewed exploratory candidates. Replay never calls a model.

Initialize or upgrade the local schema:

```sh
uv run veriflow --state-dir STATE init
```

Prepare a packet JSON containing the exact `run_id`, deterministic `attempt_id`, snapshot,
language, classification, selection reasons and one to twelve source excerpts. Each excerpt needs
an evidence ID, snapshot-relative path, file SHA-256, a range of at most 80 lines and the exact
UTF-8 text for that range.

Prepare a replay response JSON with schema version `1`, zero to twenty proposals and coverage
notes. Each proposal supplies a CWE (or `CWE-Other`), weakness description, primary and optional
related packet citations, attacker-control and impact hypotheses, explicit unknowns and a
low/medium/high ranking confidence.

Run the offline validation:

```sh
uv run veriflow --state-dir STATE discovery-replay ATTEMPT_ID \
  PACKET_JSON RESPONSE_JSON --request-key UNIQUE_KEY
```

The command rejects packets that do not match the immutable scan snapshot and proposals that cite
paths or lines outside their packet evidence. The request key is idempotent: repeating the same
request returns its durable result; reusing the key with a different packet fails.

Retrieve the ledger without reading source or invoking a provider:

```sh
uv run veriflow --state-dir STATE discovery-report RUN_ID
uv run veriflow --state-dir STATE discovery-report RUN_ID --attempt-id ATTEMPT_ID
```

The replay output labels proposals and candidate rows `origin=llm_discovery` and
`not_adjudicated`. Exact repeated proposal locations/CWEs within an attempt are idempotent. A
cross-origin candidate is not merged merely because its location resembles a deterministic alert;
weakness equivalence must be established explicitly. Replay proves schema, integrity and
orchestration behavior only; it provides no security-quality evidence.

Build the retained source evidence for an exploratory candidate and use the existing bounded
triage and operator-review commands:

```sh
uv run veriflow --state-dir STATE build-bundle ATTEMPT_ID CANDIDATE_FINGERPRINT
uv run veriflow --state-dir STATE triage-budget RUN_ID 100000
uv run veriflow --state-dir STATE triage BUNDLE_ID MODEL_CONFIG REQUEST_KEY \
  --replay TRIAGE_RESPONSE_JSON
uv run veriflow --state-dir STATE record-review REPO_ID ATTEMPT_ID \
  CANDIDATE_FINGERPRINT REVIEW_JSON REVIEW_KEY
```

Exploratory triage validates cited evidence, quotes and line ranges. Its successful gate status is
`exploratory_supported_for_review`; `reachability_proven` and `verified` remain false. Only an
explicit operator review can set the candidate’s review state to `confirmed`. Rule drafting and
approval remain later work.

## Run the hybrid scan path

Slice 144 can build the packet automatically after a deterministic `scan-run` succeeds. Add the
explicit discovery flag, replay response and a unique key to an otherwise normal CodeQL or Joern
command:

```sh
uv run veriflow --state-dir STATE scan-run RUN_ID QUERIES \
  --engine codeql \
  --llm-discovery \
  --llm-discovery-replay RESPONSE_JSON \
  --llm-discovery-key RUN_ID-discovery-1 \
  --llm-discovery-max-excerpts 8
```

For Joern, omit `QUERIES` and provide the normal `--joern-home` and profile/toolchain options.
Without `--llm-discovery`, all discovery-specific options are rejected and the scan performs zero
discovery calls. Replay records one simulated provider invocation and zero live calls.

## Run live discovery

Create a model configuration using the same strict `ModelConfig` contract as triage. It supports
`openai`, `anthropic` and local `ollama`. Hosted endpoints require HTTPS, an exact hostname in
`allowed_endpoint_hosts`, explicit nonzero input/output prices, an API-key environment-variable
name, and `allow_source_transmission=true`. Ollama requires an allowlisted numeric loopback
`/api/chat` endpoint. The source classification must appear in `allowed_classifications`.

Configure the immutable shared run budget before the scan:

```sh
uv run veriflow --state-dir STATE triage-budget RUN_ID 100000 --max-requests 20
```

Then replace the replay option with the live configuration:

```sh
uv run veriflow --state-dir STATE scan-run RUN_ID QUERIES \
  --llm-discovery \
  --llm-discovery-config MODEL_CONFIG_JSON \
  --llm-discovery-key RUN_ID-live-discovery-1 \
  --llm-discovery-max-excerpts 8
```

OpenAI and Anthropic API keys are read only from the environment variable named in the model
configuration. VeriFlow sends the request from an isolated subprocess, disables proxy inheritance
and redirects, performs no retry, applies the configured CA file and total timeout, and caps the
response. A timeout or transport failure retains the reservation because the provider charge may
be unknown. Local Ollama uses the same subprocess and structured schema without an API key.

### Unmetered discovery

With `--unmetered`, discovery skips the run budget and request cap; every charge is still
recorded. Unmetered discovery also changes two more limits:

- `--llm-discovery-max-output-tokens N` (128–128000) replaces the config's
  `max_output_tokens` for discovery requests only, so a discovery answer can exceed the config
  ceiling of 8192. Without `--unmetered` the option is refused. The config file is unchanged and
  still validated; triage keeps using the config value. The provider-response read limit grows
  with N (16 bytes per token, at least 128 KiB, at most 8 MiB).
- `--llm-discovery-timeout-seconds N` (1–600) replaces the config's `timeout_seconds` (at
  most 120) for discovery requests only. It applies to the HTTP request in the isolated child
  and to the child's wall-clock limit (N + 3 seconds). The child still validates the config as
  written and accepts only 1–600 for the override.
- A call whose actual cost exceeds its reservation keeps its proposals. The overrun is recorded
  as `reservation_exceeded_micro_usd`; metered runs still stop with `reservation_exceeded`.

```sh
uv run veriflow --state-dir STATE scan-run RUN_ID --engine joern --joern-home JOERN \
  --llm-discovery --llm-discovery-config MODEL_CONFIG_JSON --llm-discovery-key KEY \
  --unmetered --llm-discovery-max-output-tokens 32000 --llm-discovery-timeout-seconds 600 \
  --advisory-config ADVISORY_JSON --review-policy auto --advisory-key ADVICE_KEY
```

Each call records `max_output_tokens`, `output_limit_source`, `timeout_seconds` and
`timeout_source` (`config` or `unmetered_override`). Limits that still apply: at most 600
seconds per request (a longer answer is stored as `unknown`), the provider's own model maximum
and gateway timeouts, at most 20 proposals per answer, and for Ollama `ollama_context_tokens`,
which must hold the request plus the requested output.

Discovery and triage share the run’s monetary and request caps. `triage-report` now shows triage
calls, discovery calls, total requests and combined accounted cost. Published reports include
discovery-call count and combine discovery charges into simulated/live/unknown cost fields.

The selector considers UTF-8 source files for the scan language up to 1 MiB, ranks files by a
versioned set of security-sensitive API markers and retains one deterministic lower-ranked sample
when capacity permits. It includes at most twelve excerpts and forty lines per excerpt. The result
reports eligible, examined and deferred file counts. These are selection-coverage metrics, not a
claim that every function in an examined file reached the model.

If deterministic scanning fails before producing an attempt, exploration is skipped. If packet
selection or provider/response validation fails, the command retains the deterministic report and returns
`hybrid_status=partial` with an explicit discovery failure. It never relabels deterministic output
as failed or clean.
