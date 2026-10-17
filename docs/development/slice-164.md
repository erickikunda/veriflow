# Slice 164 — Unmetered LLM discovery without the output-token and timeout ceilings

## What was added

Triage and discovery already skipped budget and request caps under `--unmetered`. Discovery
still had three limits that a large answer could hit; unmetered discovery now relaxes them:

- `--llm-discovery-max-output-tokens N` (128–128000) on `scan-run` and `run-pipeline-from-csv`
  replaces `max_output_tokens` for discovery requests. It requires `--unmetered`. The model
  config file keeps its 8192 validation ceiling and is still validated, in the parent and in the
  isolated child; the larger value is only in the request body (`effective_config`).
- The provider-response read limit follows the requested output: 16 bytes per token, at least
  128 KiB and at most 8 MiB (`response_limit`). Triage keeps 128 KiB.
- `--llm-discovery-timeout-seconds N` (1–600), also only with `--unmetered`, replaces the
  config's `timeout_seconds` (at most 120) for discovery. The parent passes it to the isolated
  child, which validates the config as written, accepts only 1–600 for the override, and uses
  it for the HTTP request; the parent's wall-clock limit is N + 3 seconds.
- A charge above the reservation keeps the proposals under `--unmetered` and records
  `reservation_exceeded_micro_usd`; metered runs still end `reservation_exceeded`.

The override is part of the request identity: the recorded config, the reservation, and the CSV
pipeline's discovery request key include it, so changing it is a new request, not a key
conflict. The same holds for the timeout. Each call records `max_output_tokens`,
`output_limit_source`, `timeout_seconds` and `timeout_source`.

## Verification

- `uv run pytest`: 1442 passed. New tests: the override is refused without `--unmetered` and
  outside 128–128000; unmetered discovery sends `max_tokens` 64000, reads up to 64000 × 16
  bytes, keeps the child config at 1024, and keeps the proposals despite a large overrun; the
  metered path sends the config value, reads 128 KiB and stops at `reservation_exceeded`; the
  response limit is clamped; `scan-run` passes the option through and refuses it without
  `--unmetered`.
  The timeout override is refused without `--unmetered` and outside 1–600, reaches the request
  (600) while the child's config stays at 60, is passed to the child with a 603-second
  wall-clock limit, and the real child process refuses 0, 601 and a string before any network
  access.

## Non-claims

- At most 600 seconds per request, the provider's model maximum and gateway timeouts, the
  20-proposal response schema and Ollama's context size still apply. An answer slower than the
  timeout is stored as `unknown`.
- Triage is unchanged: its output ceiling and reservation check stay as they were.
- No live provider was called.
