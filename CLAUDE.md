# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

VeriFlow is a local, single-operator CLI (Typer + SQLAlchemy/SQLite + local artifact store)
that turns source archives into **evidence-backed vulnerability *candidates*** — never verdicts.
Everything in the codebase is organized around that distinction: discovery emits candidates,
deterministic gates decide what an LLM may even see, and reports are immutable and must keep
coverage gaps visible. Zero findings never means "clean"; absence never means "fixed".

## Commands

```bash
uv sync --locked
uv run pytest                       # full suite, ~1060 tests, ~60s, no external tools needed
uv run pytest tests/test_joern_selection.py -k selects_all_profiles   # single test
uv run ruff check .
uv run ruff format --check .
uv build                            # wheel into dist/, required before container builds
```

CLI is `uv run veriflow <command>` (entry point `veriflow.cli:app`). `--state-dir` is a
**global** option and goes before the subcommand. `veriflow init` creates/upgrades the SQLite
schema via Alembic (currently `0012`); run it after adding a migration.

`veriflow doctor` reports local prerequisites without running any tool.

### Native / container validation

Unit tests never invoke Joern, CodeQL, or a JDK. Real toolchain acceptance runs inside pinned
restricted Linux containers, one `scripts/validate_*.py` per profile, driven by:

```bash
uv build
docker build --network=none -f containers/Containerfile.joern-csharp -t veriflow:joern-csharp-linux-poc .
uv run python scripts/validate_container.py work/<new-output-dir> --suite joern-csharp --image veriflow:joern-csharp-linux-poc
```

Output directories must not already exist. `scripts/validate_*.py` run *inside* the container
(they hardcode `/work` and `/repo` or `/opt/veriflow` paths) — don't run them on the host.
See `docs/guides/container-operator-guide.md` for the full suite/image matrix.

`work/` is gitignored scratch for logs, acceptance output and downloaded toolchains.

## Architecture

Pipeline stages, each durable and independently retrievable by ID:

1. **Intake** (`intake.py`, `artifacts.py`, `git_acquisition.py`, `gcs_acquisition.py`) — CSV
   manifests of local TAR/ZIP (`source_type=pvc`) or acquired Git/GCS archives become verified,
   immutable snapshots with manifests. Archives are never recursively unpacked or executed.
   Git/GCS acquisition is a *separate networked container*; scanning runs offline.
2. **Indexing** (`indexing.py`, `*_parser.py`, `java_index.py`) — tree-sitter syntax inventory
   and conservative call candidates. `static_candidate` is never proven reachability.
3. **Scanning** — two backends behind `scanner_backends.py`:
   - **Joern** (`joern.py`, `joern_pipeline.py`, `joern_selection.py`, `queries/*.sc`) — the
     current strategy. Bounded per-language *profiles*.
   - **CodeQL** (`codeql*.py`, `scanning.py`, `pipeline.py`) — retained reference route,
     still the default in some CLI paths; select Joern explicitly.
   `pipeline.scan_run` orchestrates the CodeQL route; `joern_pipeline.scan_run` the Joern one;
   `joern_selection.scan_selected` fans out `--language auto` into one attempt+report per
   (language, profile) pair — discovery-only, never advisory.
4. **Evidence + triage** (`bundles.py`, `evidence.py`, `claims.py`, `joern_claims.py`,
   `expansion.py`, `triage.py`) — bundles are capped (8 locations / 16 KiB source / 32 KiB
   envelope). Claim gates re-verify quoted source, sink syntax and flow against the snapshot
   *before* any model call. Failed claims **abstain**; they never dismiss a candidate.
   Providers (OpenAI / Anthropic / Ollama) are opt-in per operator-authored config with an
   explicit budget in micro-USD and a request cap.
5. **Reports** (`reports.py`, `comparison.py`, `sarif_export.py`, `scorecard*.py`,
   `evaluation.py`, `benchmark*.py`) — immutable, content-addressed; identical state reuses a
   report. Retrieval enforces repository ownership and refuses to hide newer attempts behind
   an older report. Formats: JSON / Markdown / HTML / scan-csv / candidates-csv / SARIF.

`persistence.py` holds every ORM model and the Alembic runner; `domain.py` defines
`VeriFlowError`, the only exception the CLI renders as a clean `{"error": ...}` exit 1.
`exclusive_worker` is an OS file lock — deliberately *not* a distributed lease.

### Adding a Joern discovery profile

The repeatable shape (see commit "Add bounded C# file-path discovery" for a worked example):

- `src/veriflow/queries/joern-<lang>-<pattern>.sc` — the bounded CPG query.
- `src/veriflow/profiles/joern-packaged.json` — add a descriptor: per-language `rule_id` and
  query file, candidate `message`, `cwe_scope` (or `null`), `limitations`, and `selection`
  (`auto` joins `--joern-profile auto`; list order is the automatic order). `joern.py` and
  `joern_selection.py` read this catalog through `joern_profiles.py`; do not hard-code profiles.
- Behaviour that needs Python support (Flask endpoint audit, C# query-source mapping) is a
  named `hooks` entry implemented in `joern.py`; only packaged profiles may use hooks.
- Regenerate `tests/fixtures/joern-profile-golden.json` with
  `uv run python tests/joern_profile_golden.py --write` and review its diff.
- `tests/fixtures/joern-<lang>-<pattern>/<case>/` — vulnerable, fixed, crossfile, disconnected,
  shadowed, unbound-source, guard-unknown … each case asserts an exact candidate count.
- `scripts/validate_joern_<lang>_<pattern>.py` — native acceptance over those fixtures.
- `tests/test_joern_selection.py` + focused unit tests (pure Python, monkeypatched).
- `docs/guides/<lang>-<pattern>-discovery.md` and a new `docs/development/slice-NNN.md`.

New profiles are **advisory-unsupported** until a reviewed evidence gate exists for them.

Operators can also add **runtime** Joern profiles without a code change: a descriptor and query
in the trusted directory (`<state-dir>/profiles`, default `--profile-mode trusted-directory`),
or approved through `profile-add` / `profile-test` / `profile-approve` (`--profile-mode
approved`). See `docs/guides/runtime-joern-profiles.md`. Runtime profiles never use hooks.
They get the generic `runtime-native-v1` gate by default (native/path consistency, endpoint
syntax unchecked), not a reviewed profile-specific gate.

## Conventions

- **Delivery is slice-based.** Each unit of work gets `docs/development/slice-NNN.md` (what was
  added, exact fixture counts, what passed, explicit non-claims, next step), a one-paragraph
  entry prepended to `docs/development/progress.md`, and updates to
  `docs/architecture/system-design.md` / `docs/plans/*` where scope changed. Commit subjects are
  single-line imperative with no body ("Add bounded C# file-path discovery").
- **Language discipline is load-bearing.** Docstrings, report text, guides and slice notes state
  what is *not* established ("candidate", "unverified", "discovery-only", "incomplete") as
  carefully as what is. Don't upgrade hedged wording when editing nearby text.
- Module docstrings are a single sentence naming the module's boundary, not a summary.
- Ruff: line length 100, `E,F,I,UP,B`, target py312.
- Errors must never echo source contents.
- `docs/plans/cwe-coverage-roadmap.md` holds the current coverage queue; check it before picking
  up new detection work.
