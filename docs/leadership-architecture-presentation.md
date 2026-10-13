# VeriFlow: Evidence-Driven, AI-Assisted Vulnerability Discovery
## Executive & Leadership Presentation

---

## Slide 1: Title & Executive Summary

### VeriFlow: Enterprise Vulnerability Discovery with Verifiable Evidence
*Transforming Code Security from Noisy Alerts to Cryptographically Grounded Intelligence*

#### High-Level Value Proposition
* **The Problem:** Traditional static application security testing (SAST) floods engineering teams with false positives, while naive LLM scanners hallucinate vulnerabilities and leak code context.
* **The VeriFlow Solution:** An enterprise-grade, evidence-driven scanning platform combining deterministic code-property graph analysis (Joern / CodeQL) with strictly bounded, audited AI reasoning (OpenAI, Anthropic, local Ollama).
* **Core Philosophy:** *An AI model can never declare a vulnerability on its own.* Every finding must have verifiable source-code provenance, exact taint-flow facts, and cryptographic auditability.

> **Key Takeaway for Leadership:** VeriFlow bridges the gap between mechanical static analysis and AI reasoning—reducing manual triaging costs while ensuring zero hallucinations reach developers.

#### Implementation Proof & Code References
* System Architecture & Downstream Adaptation: [`docs/architecture/system-design.md:L1-L150`](file:///Users/eric/PycharmProjects/veriflow/docs/architecture/system-design.md#L1-L150)
* Core Platform CLI Entrypoints & Commands: [`src/veriflow/cli.py:L1-L120`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/cli.py#L1-L120)
* Domain Contract & Custom Exception Types: [`src/veriflow/domain.py:L10-L35`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/domain.py#L10-L35)

---

## Slide 2: Strategic Drivers & Business Outcomes

### Why VeriFlow? Balancing Security Recall, Precision, and Cost

| Strategic Goal | Conventional SAST / LLM Wrappers | VeriFlow Approach | Code Enforcement & Line References | Business Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Alert Fatigue & Noise** | 40%–70% false positive rates overwhelm AppSec teams. | **Deterministic Evidence Gates** require concrete source, sink, and data-flow proof before elevating findings. | [`src/veriflow/claims.py:L10-L70`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/claims.py#L10-L70)<br>Gate versioning & required obligations (`source`, `sink`, `flow`, `guard`). | **Cuts triage backlogs** and focuses senior security engineers on genuine exploit risks. |
| **AI Hallucinations** | Generative models invent non-existent functions, libraries, or bypasses. | **Cryptographic Snapshot Binding:** Models only inspect bounded slices and must cite exact line ranges and SHA-256 digests. | [`src/veriflow/claims.py:L305-L331`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/claims.py#L305-L331)<br>Deterministic verification rejecting quote mismatches or unrecorded flows. | **100% auditable decisions;** models are forced to abstain when proof is missing. |
| **Cost & Token Economics** | Unbounded prompt expansion burns millions of tokens on irrelevant code. | **Budget Ledgers & Strict Caps:** Micro-dollar token accounting, bounded context windows (16 KiB source / 32 KiB envelope). | [`src/veriflow/triage.py:L19-L55`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/triage.py#L19-L55)<br>Immutable run budgets and micro-USD reservations. | **Predictable ROI:** Enforces pre-allocated financial caps per repository scan. |
| **Enterprise Governance** | SaaS tools ingest entire proprietary codebases into external cloud LLMs. | **Zero-Transmission Defaults & Air-Gapped Modes:** Local Ollama support, containerized offline scanners, redacted tokens. | [`src/veriflow/models.py:L60-L109`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/models.py#L60-L109)<br>`allow_source_transmission` flag & loopback HTTP Ollama check. | **Preserves intellectual property** and satisfies strict banking/enterprise regulatory boundaries. |

---

## Slide 3: End-to-End System Architecture (The Big Picture)

### Modular, Multi-Tiered Architecture Built for Enterprise Scale

```
+----------------------------------------------------------------------------------------------------+
|                                      OPERATOR & INGESTION LAYER                                    |
|   - CSV Manifest Intake (repositories.csv / archives.csv)                                          |
|   - Networked Acquisition (Isolated Git clone / HTTPS / GCS Tarball extraction)                    |
|   [Code Ref: src/veriflow/git_acquisition.py:L29-L65 | src/veriflow/intake.py:L28-L62]         |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ [Immutable Tarball / Manifest SHA-256]
+----------------------------------------------------------------------------------------------------+
|                                  SNAPSHOT & IMMUTABLE STORAGE TIER                                 |
|   - Local Artifact Store / Enterprise PVC: Read-only source snapshots & Normalized Trees          |
|   - Database (SQLite for Dev/POC -> PostgreSQL for Production Fleet)                               |
|   [Code Ref: src/veriflow/artifacts.py:L100-L150 | src/veriflow/persistence.py:L186-L228]      |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ [Zero-Network Execution Sandbox]
+----------------------------------------------------------------------------------------------------+
|                                    STATIC ANALYSIS ENGINE (SAST)                                   |
|   - Primary Engine: Joern Code Property Graph (CPG) (Multi-language taint & flow analysis)        |
|   - Reference Engine: GitHub CodeQL (Security queries & database compilation)                      |
|   - Language Coverage: Python, Java/Spring, C#/ASP.NET, JS/TS/Node, Go, Rust, C/C++                |
|   [Code Ref: src/veriflow/joern.py:L36-L73 | src/veriflow/codeql.py:L50-L110]                  |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ [Raw Candidates & Flow Traces]
+----------------------------------------------------------------------------------------------------+
|                                    EVIDENCE COMPILATION & GATES                                    |
|   - Candidate Extraction & Deduplication (Structural Fingerprinting)                               |
|   - Context Builder: Assembles bounded Evidence Bundles (Source, Sinks, Sanitizers, Call Paths)    |
|   - Strict Size Enforcement: Max 8 locations, ≤16 KiB code, ≤32 KiB total payload                  |
|   [Code Ref: src/veriflow/bundles.py:L18-L45 | src/veriflow/sarif.py:L60-L66]                  |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ [Bounded Evidence Bundle + Policy Requirements]
+----------------------------------------------------------------------------------------------------+
|                               AI-ASSISTED TRIAGE GATEWAY (OPT-IN & BUDGETED)                       |
|   - Model Adapters: Enterprise OpenAI / Anthropic (HTTPS) / Local Ollama (Air-Gapped)              |
|   - Run Budget Ledger: Pre-allocated financial cap (micro-USD) & request count limits              |
|   - Deterministic Verification Gate: Validates LLM quotes against exact snapshot lines             |
|   [Code Ref: src/veriflow/triage.py:L102-L180 | src/veriflow/models.py:L125-L205]              |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ [Validated Verdicts + Gap Disclosures]
+----------------------------------------------------------------------------------------------------+
|                                    REPORTING & DECISION PROJECTION                                 |
|   - Immutable Versioned Reports (JSON, HTML, Markdown, CSV, SARIF, CycloneDX SBOM)                |
|   - Dual-Track Separation: Machine Findings vs. Operator Review History vs. Model Advice           |
|   - Portfolio Governance Dashboards & Offline Benchmark Scorecards (Ground-truth recall)           |
|   [Code Ref: src/veriflow/reports.py:L190-L287 | src/veriflow/sbom_export.py:L50-L100]         |
+----------------------------------------------------------------------------------------------------+
```

---

## Slide 4: Data Flow Pipeline: From Source Code to Verifiable Report

### A 7-Stage Deterministic Pipeline with Code Proof

VeriFlow processes software repositories through strict, unidirectional state transitions:

```
[1. ADMIT] ────► [2. SNAPSHOT] ────► [3. INDEX & PARSE] ────► [4. STATIC SCAN]
                                                                     │
[7. PUBLISH] ◄─── [6. GATE VERIFY] ◄─── [5. EVIDENCE BUNDLE] ◄───────┘
```

#### Detailed Stage Breakdown & Code Lines

1. **Intake & Admission (`ADMIT`):**
   * Validates CSV headers (`repo_id`, `source_type`, `source_uri`, `owner`, `classification`).
   * Enforces security sanitization: directory descriptor checks prevent directory traversal or symlink escapes.
   * *Code Reference:* [`src/veriflow/intake.py:L28-L100`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/intake.py#L28-L100) (CSV validation and duplicate key handling); [`src/veriflow/artifacts.py:L56-L82`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/artifacts.py#L56-L82) (`open_scoped_source` using `O_NOFOLLOW | O_DIRECTORY`).
2. **Snapshot Creation (`SNAPSHOT`):**
   * Extracts TAR/ZIP archives under strict resource quotas (max members, depth, compression ratio).
   * Generates immutable source tree manifest and cryptographic root digest (`snapshot_id`).
   * *Code Reference:* [`src/veriflow/intake.py:L260-L290`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/intake.py#L260-L290) (`artifacts.capture()` & `verify_snapshot()`); [`src/veriflow/artifacts.py:L100-L140`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/artifacts.py#L100-L140) (`Extractor.member()` boundary validation).
3. **Semantic Indexing (`INDEX`):**
   * Parses files in isolated subprocesses; inventories functions, classes, and top-level calls.
   * If parsing fails or files exceed size limits, logs an explicit **Coverage Gap** rather than pretending the code is clean.
   * *Code Reference:* [`src/veriflow/indexing.py:L40-L95`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/indexing.py#L40-L95) (`parse_isolated()` and `build_index()`); [`src/veriflow/readiness.py:L15-L55`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/readiness.py#L15-L55) (`static_readiness()` gate).
4. **Static Code Analysis (`STATIC SCAN`):**
   * Executes Joern or CodeQL in an isolated process tree with network access revoked (`CARGO_NET_OFFLINE="true"`, `GOPROXY="off"`).
   * Generates normalized candidate alerts containing complete taint-propagation paths from source to sink.
   * *Code Reference:* [`src/veriflow/joern.py:L36-L73`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/joern.py#L36-L73) (`stage()` runner and timeout enforcement); [`src/veriflow/joern.py:L74-L96`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/joern.py#L74-L96) (`decode_output()` schema validation).
5. **Evidence Packaging (`BUNDLE`):**
   * Filters and normalizes SARIF alerts into deterministic **Evidence Bundles**.
   * Caps payloads at $\le$8 locations, $\le$16 KiB source code, and $\le$32 KiB total JSON size.
   * *Code Reference:* [`src/veriflow/bundles.py:L18-L36`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/bundles.py#L18-L36) (Constants & `get_bundle()` digest check); [`src/veriflow/bundles.py:L44-L105`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/bundles.py#L44-L105) (`_build_bundle()` SARIF flow extraction).
6. **AI Advisory & Deterministic Gate (`TRIAGE` & `GATE`):**
   * Dispatches bundle to configured model under strict structured output schema.
   * Independent Python engine checks that quotes exist verbatim in source and match syntax AST rules.
   * *Code Reference:* [`src/veriflow/triage.py:L102-L170`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/triage.py#L102-L170) (`triage()` execution & budget check); [`src/veriflow/claims.py:L300-L360`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/claims.py#L300-L360) (`assess_evidence()` verification gate).
7. **Publication (`REPORT`):**
   * Materializes an immutable published report record with atomic version incrementing.
   * Dual-track reporting guarantees raw SAST candidates, human reviews, and AI advice are never conflated.
   * *Code Reference:* [`src/veriflow/reports.py:L182-L250`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L182-L250) (`projection()` summary assembly); [`src/veriflow/reports.py:L252-L287`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L252-L287) (`publish_report()` atomic persistence).

---

## Slide 5: The Guardrail System: Why Our AI Does Not Hallucinate

### How VeriFlow Keeps Generative AI Accountable

```
                      Raw CodeQL / Joern Candidate
                                   │
                                   ▼
                      [ Evidence Bundle Builder ]
                [Code Ref: src/veriflow/bundles.py:L44]
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
     Bounded Context Slice                    Model Instructions
  - Max 8 source locations                 - "Untrusted Data: Do not execute"
  - Max 16 KiB code context                - "Cite exact line numbers & quotes"
  - Stripped of prompt injections          - "Must identify Sanitizers & Guards"
  [Ref: bundles.py:L18-L22]                [Ref: models.py:L22-L34]
              └────────────────────┬────────────────────┘
                                   │
                                   ▼
                    [ LLM Reasoning / Evaluation ]
                 [Code Ref: src/veriflow/models.py:L125]
                                   │
                                   ▼
                 Proposed Decision (Strict JSON Schema)
                 - Verdict: needs_review | likely_false_positive | abstain
                 - Quoted source, sink, flow, guard claims
                 [Code Ref: src/veriflow/models.py:L41-L47]
                                   │
                                   ▼
            ================================================
            THE TRACEPROOF DETERMINISTIC EVIDENCE GATE
            [Code Ref: src/veriflow/claims.py:L300-L360]
            ================================================
             [?] Do quoted strings match snapshot bytes?  (L313)
             [?] Are cited lines within boundaries?      (L300)
             [?] Are guard claims verified by AST rules?  (L316)
             [?] Is ledger budget available?              (triage.py:L175)
            ================================================
                                   │
                  ┌────────────────┴────────────────┐
                 PASS                              FAIL
                  │                                 │
                  ▼                                 ▼
         Advisory Decision Recorded          Forced ABSTAIN
         (Attached to Report)             (Marked as Unreviewed Candidate)
         [Ref: triage.py:L210-L240]       [Ref: claims.py:L314-L327]
```

#### Key Leadership Guarantees in Code:
* **The "Untrusted Source" Barrier:** Prompt instructions explicitly declare all source code, comments, and identifiers as untrusted data ([`src/veriflow/models.py:L22-L34`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/models.py#L22-L34)), neutralizing indirect prompt injection attacks.
* **Algorithmic Veto Power:** If an AI model claims a sanitizer exists but quotes text that does not match the file bytes, the gate forces `reason = "quote_mismatch"` and reverts the verdict to `abstain` ([`src/veriflow/claims.py:L313-L315`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/claims.py#L313-L315)).
* **Advisory Status:** System schemas restrict LLM output to advisory classifications (`needs_review`, `likely_false_positive`, `abstain`). An AI model cannot close, confirm, or delete a finding ([`src/veriflow/models.py:L41-L47`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/models.py#L41-L47)).

---

## Slide 6: Data Models & Schema Architecture

### Grounded in Relational Integrity, Immutability & Auditability

VeriFlow’s persistence model separates operational workflow state from static evidence:

```
┌─────────────────────────┐         ┌─────────────────────────┐
│       Repository        │1       *│       ImportBatch       │
│  (id, owner,            │─────────│  (id, idempotency_key,  │
│   classification)       │         │   request_sha256, root) │
│ [persistence.py:L21-25] │         │ [persistence.py:L28-35] │
└─────────────────────────┘         └─────────────────────────┘
             │                                   │ 1
             │ 1                                 │
             │                                   │ *
             │ *                    ┌─────────────────────────┐
┌─────────────────────────┐         │       ImportItem        │
│        Snapshot         │1       *│  (id, import_id, row,   │
│  (id, repo_id,          │─────────│   state, spec, error)   │
│   manifest JSON)        │         │ [persistence.py:L65-76] │
│ [persistence.py:L48-53] │         └─────────────────────────┘
└─────────────────────────┘                      │
             │ 1                                 │ 1
             │                                   │
             │ *                                 │ 1
┌─────────────────────────────────────────────────────────────┐
│                             Run                             │
│       (id, repo_id, state, profile, snapshot_id)            │
│                 [persistence.py:L55-63]                     │
└─────────────────────────────────────────────────────────────┘
             │ 1                                 │ 1
             │                                   │
             │ *                                 │ 1
┌─────────────────────────┐         ┌─────────────────────────┐
│       ScanAttempt       │         │      TriageBudget       │
│  (id, run_id, report,   │         │  (run_id, max_requests, │
│   created_at)           │         │   limit_micro_usd)      │
│ [persistence.py:L104-110│         │ [persistence.py:L128-133│
└─────────────────────────┘         └─────────────────────────┘
             │ 1                                 │ 1
             │                                   │
             │ *                                 │ *
┌─────────────────────────┐         ┌─────────────────────────┐
│        Candidate        │1       *│       TriageCall        │
│  (id, attempt_id,       │─────────│  (id, run_id, bundle_id,│
│   fingerprint, evidence)│         │   charged_usd, result)  │
│ [persistence.py:L112-119│         │ [persistence.py:L135-147│
└─────────────────────────┘         └─────────────────────────┘
             │ 1                                 │
             │                                   │
             │ *                                 │ *
┌─────────────────────────┐         ┌─────────────────────────┐
│     EvidenceBundle      │1       *│     PublishedReport     │
│  (id, candidate_id,     │─────────│  (id, run_id, version,  │
│   content JSON)         │         │   input_digest, content)│
│ [persistence.py:L121-126│         │ [persistence.py:L149-161│
└─────────────────────────┘         └─────────────────────────┘
```

---

## Slide 7: Deep Dive: Core Entities & Structures

### Transparent Data Structures Designed for Enterprise Audit

#### 1. The Repository & Snapshot (The Foundation)
* **`Repository`** ([`src/veriflow/persistence.py:L21-L26`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L21-L26)): Establishes tenancy, owner, and data classification (`internal`, `restricted`, `public`).
* **`Snapshot`** ([`src/veriflow/persistence.py:L48-L53`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L48-L53)): Cryptographic anchor. Stores the parsed manifest containing every relative file path, file size, and file SHA-256 ([`src/veriflow/domain.py:L80-L88`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/domain.py#L80-L88)). Once committed, it cannot be modified.

#### 2. Scan Execution & Candidate Entities (The Findings)
* **`Run` & `ScanAttempt`** ([`src/veriflow/persistence.py:L55-L63`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L55-L63), [`L104-L110`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L104-L110)): Records the scan lifecycle (`admitted` $\rightarrow$ `snapshotted` $\rightarrow$ `failed`), scanner tool versions, and diagnostic outputs.
* **`Candidate`** ([`src/veriflow/persistence.py:L112-L119`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L112-L119)): Represents a potential vulnerability.
  * **Key Field: `fingerprint`** ([`src/veriflow/sarif.py:L60-L66`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/sarif.py#L60-L66)): A 64-character SHA-256 hash formed by hashing `[snapshot_id, driver_name, rule_id, result_structure]`. This prevents trivial line edits from re-alerting or duplicating findings.

#### 3. Evidence Bundles & AI Audit Trails (The Proof)
* **`EvidenceBundle`** ([`src/veriflow/persistence.py:L121-L126`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L121-L126)): Complete self-contained JSON artifact containing primary locations, flow steps, and bounded code context ([`src/veriflow/bundles.py:L80-L105`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/bundles.py#L80-L105)). Capped strictly at 16 KiB total source text.
* **`TriageBudget` & `TriageCall`** ([`src/veriflow/persistence.py:L128-L147`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L128-L147)): Financial audit ledger tracking `limit_micro_usd`, `max_requests`, and `charged_micro_usd` per LLM invocation ([`src/veriflow/triage.py:L19-L26`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/triage.py#L19-L26)).

#### 4. The Published Report (The Deliverable)
* **`PublishedReport`** ([`src/veriflow/persistence.py:L149-L161`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L149-L161)): Immutable versioned record of results at a specific point in time (`report_id = sha256(canonical(report))`). If subsequent operator reviews occur, a new version is created (`version = 2`), preserving complete revision history ([`src/veriflow/reports.py:L264-L287`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L264-L287)).

---

## Slide 8: Multi-Language & Weakness Coverage Matrix

### Supported Languages & Detection Profiles with Code Backings

VeriFlow enforces explicit, tested profiles across enterprise application stacks:

| Language | Primary Framework | Weakness Family (CWE) | Code Implementation & Handlers | Example Flow Detected |
| :--- | :--- | :--- | :--- | :--- |
| **Java** | Spring Boot | **CWE-89** (SQL Injection)<br>**CWE-78** (OS Command) | [`src/veriflow/java_claims.py:L1-L40`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/java_claims.py#L1-L40)<br>Joern profile `joern-spring-get-jdbc-sql-v1` | HTTP `@RequestParam` string concatenated into JDBC query or inline `Runtime.exec()` shell array. |
| **Python** | Flask / Django | **CWE-78** (Command Injection)<br>**CWE-22** (Path Traversal)<br>**CWE-918** (SSRF) | [`src/veriflow/joern_flask.py:L1-L60`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/joern_flask.py#L1-L60)<br>Joern profile `python-flask-system-v1` | `request.args` flow into `os.system()`, unsanitized file path opening, or uncontrolled `urllib` calls. |
| **C# / .NET** | ASP.NET Core | **CWE-89** (SQL Injection)<br>**CWE-78** (Process Injection)<br>**CWE-22** (File Access) | [`src/veriflow/joern_csharp.py:L1-L50`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/joern_csharp.py#L1-L50)<br>Profiles `csharp-query-commandtext-v1`, `csharp-query-file-read-v1` | Controller query bindings flowing into ADO.NET `CommandText`, `Process.Start`, or `File.ReadAllText`. |
| **JS / TS** | Express / Node | **CWE-94** (Code Injection)<br>**CWE-78** (Command Injection) | [`src/veriflow/express_parser.py:L1-L60`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/express_parser.py#L1-L60)<br>Joern profile `express-request-eval-v1` | `req.query` / `req.body` values reaching `eval()`, `Function()`, or `child_process.exec()`. |
| **Go** | net/http | **CWE-78** (Command Injection)<br>**CWE-22** (Path Traversal) | [`src/veriflow/go_http_parser.py:L1-L50`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/go_http_parser.py#L1-L50)<br>Joern profile `go-http-shell-v1` | HTTP form values directly passed into `exec.Command` shell wrappers or file readers. |
| **C / C++** | Native / Posix | **CWE-78** (Command Injection) | [`src/veriflow/c_family_parser.py:L1-L50`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/c_family_parser.py#L1-L50)<br>Joern profile `c-family-argv-system-v1` | Untrusted CLI arguments (`argv`) propagating to `system()` or `popen()` without argument validation. |
| **Rust** | Actix / Standard | **CWE-78** (Command Injection) | [`src/veriflow/rust_env_parser.py:L1-L50`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/rust_env_parser.py#L1-L50)<br>Joern profile `rust-env-shell-v1` | Untrusted environment variables or network payloads flowing into `std::process::Command`. |

> **Honest Engineering Standard:** VeriFlow explicitly flags what was **not** checked ([`src/veriflow/reports.py:L243-L248`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L243-L248)). If an application uses an unmodeled framework or dependency, the report flags an **explicit coverage gap** rather than issuing a false "clean" bill of health.

---

## Slide 9: Cost Governance & Operational Controls

### Predictable Budgets, Multi-Tenancy & Failsafes

```
              ┌────────────────────────────────────────────────────────┐
              │             Enterprise Run Budget Config               │
              │  - Max Financial Spend: $0.25 (250,000 micro-USD)      │
              │  - Max Request Count: 50 AI Triage Requests            │
              │   [Code Ref: src/veriflow/triage.py:L28-L55]         │
              └────────────────────────────────────────────────────────┘
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    ▼                                             ▼
       [ High-Severity Candidate ]                   [ Lower-Ranked Candidate ]
                    │                                             │
      Deduct $0.005 & 1 request                     Deduct $0.005 & 1 request
   [Code Ref: triage.py:L150-L151]               [Code Ref: triage.py:L150-L151]
                    │                                             │
                    ▼                                             ▼
       (Active Triage Execution)                     (Budget Threshold Reached?)
                                                 [Code Ref: triage.py:L175-L180]
                                                                  │
                                                                 YES
                                                                  │
                                                                  ▼
                                                   [ GRACEFUL DEGRADATION ]
                                                   - Halt LLM Calls
                                                   - Preserve Raw Candidate
                                                   - Flag "Deferred for Budget"
                                                   - Publish Partial Scan Status
                                                 [Code Ref: triage.py:L176]
```

#### Operational Governance Capabilities in Code:
1. **Pre-Scan Financial Reservations:** Runs cannot run away with cloud costs. Each scan has an immutable budget ceiling set before analysis begins ([`src/veriflow/triage.py:L28-L55`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/triage.py#L28-L55)).
2. **Deterministic Run Controls:** Operations teams can issue `pause`, `resume`, and `cancel` commands at the batch level ([`src/veriflow/import_controls.py:L1-L60`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/import_controls.py#L1-L60)).
3. **Multi-Format Exportability:**
   * **Executive Level:** Interactive HTML reports and trend summaries ([`src/veriflow/reports.py:L350-L400`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L350-L400)).
   * **Engineering Level:** GitHub-flavored Markdown and SARIF v2.1.0 for IDE / pull-request integration ([`src/veriflow/sarif_export.py:L1-L50`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/sarif_export.py#L1-L50)).
   * **Data & Analytics:** Flat CSV tables (`scan.csv` joined with `candidates.csv`) optimized for corporate BI tools (Tableau, PowerBI, Splunk) ([`src/veriflow/reports.py:L410-L460`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L410-L460)).
   * **Supply Chain:** CycloneDX Software Bill of Materials (SBOM) tracking third-party components alongside code findings ([`src/veriflow/sbom_export.py:L50-L100`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/sbom_export.py#L50-L100)).

---

## Slide 10: Comparison: VeriFlow vs. Industry Alternatives

### Why VeriFlow Wins in Regulated Enterprise Environments

| Evaluation Dimension | Legacy SAST (e.g., Checkmarx, Fortify) | Naive LLM Wrappers (e.g., ChatGPT Plugins) | VeriFlow Enterprise Platform | Supporting Code Architecture |
| :--- | :--- | :--- | :--- | :--- |
| **Precision & False Positives** | **Poor.** High volume of raw syntactic warnings without reachability context. | **Unpredictable.** Hallucinates nonexistent vulnerabilities and sanitizers. | **High.** Deterministic data-flow analysis filtered by strict LLM verification gates. | [`src/veriflow/claims.py:L300-L360`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/claims.py#L300-L360)<br>Verification gates require valid AST sinks & sources. |
| **Evidence & Verifiability** | Static line pointers; opaque vendor heuristics. | Unverified natural language prose. | **Cryptographic proof:** Exact snapshot SHA-256, AST syntax facts, and quoted line anchors. | [`src/veriflow/sarif.py:L60-L66`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/sarif.py#L60-L66)<br>Snapshot-anchored candidate fingerprints. |
| **Cost Predictability** | Expensive per-seat/per-IP licenses; heavy infrastructure. | Uncontrolled token consumption; unpredictable vendor billing spikes. | **Granular Ledger:** Micro-dollar token accounting with hard pre-scan limits. | [`src/veriflow/triage.py:L19-L55`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/triage.py#L19-L55)<br>`TriageBudget` and `cost_micro_usd`. |
| **Data Privacy & Air-Gap** | Requires heavy on-prem appliances or vendor cloud upload. | Exposes proprietary source code to external multi-tenant cloud APIs. | **Air-gap capable:** Local Ollama model support, zero-network scanning containers, strict token redaction. | [`src/veriflow/models.py:L77-L95`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/models.py#L77-L95)<br>Enforces loopback-only Ollama endpoints. |
| **Auditability & Integrity** | State often lost between periodic scans. | Ephemeral chat sessions with zero provenance. | **Immutable Data Model:** Versioned reports, append-only review history, reproducible scorecards. | [`src/veriflow/persistence.py:L149-L185`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/persistence.py#L149-L185)<br>`PublishedReport` & `BenchmarkScorecard`. |

---

## Slide 11: Enterprise Roadmap & Implementation Horizons

### Strategic Milestones: From Laptop POC to Enterprise OpenShift Fleet

```
  HORIZON 1: PROVEN POC (Current State)
  ├── 140+ functional implementation slices completed (Slice 1 to Slice 141)
  ├── 9-language Joern-first static analysis & CodeQL reference pipeline
  │   [Code Ref: src/veriflow/joern.py | src/veriflow/languages.py]
  ├── Local SQLite engine, CLI operator tooling, & deterministic Evidence Gates
  │   [Code Ref: src/veriflow/persistence.py | src/veriflow/claims.py]
  └── Multi-format reporting (HTML, SARIF, CSV, SBOM) & Local Ollama AI validation
      [Code Ref: src/veriflow/reports.py | src/veriflow/models.py:L77-L95]
        │
        ▼
  HORIZON 2: OPENSHIFT PILOT (Target Enterprise Architecture)
  ├── Migration from SQLite to PostgreSQL with row-level transaction fencing
  │   [Architecture Ref: docs/architecture/system-design.md:L476-L525]
  ├── Kubernetes / OpenShift Job isolation for untrusted code execution
  │   [Container Ref: containers/Containerfile.joern | containers/Containerfile.ocp-smoke]
  ├── Network-isolated acquisition containers (Git & GCS Tarball ingest)
  │   [Code Ref: src/veriflow/git_acquisition.py | src/veriflow/gcs_acquisition.py]
  └── Integration with Enterprise LLM Gateways (Azure OpenAI / Anthropic Bedrock)
      [Code Ref: src/veriflow/models.py:L60-L109]
        │
        ▼
  HORIZON 3: FLEET SCALE & AUTOMATION (Full Enterprise Integration)
  ├── 1,000+ repositories/day automated fleet processing
  │   [Architecture Ref: docs/architecture/system-design.md:L397-L405]
  ├── Centralized AppSec dashboard ingestion (Splunk / Tableau / Jira integration)
  │   [Format Ref: src/veriflow/reports.py:L410-L460 (scan-csv / candidates-csv)]
  ├── Automated benchmark scoring against 50-repo curated ground truth
  │   [Code Ref: src/veriflow/benchmark.py | src/veriflow/evaluation.py]
  └── Independent containerized testbed reproduction of confirmed exploits
      [Architecture Ref: docs/architecture/system-design.md:L323-L347]
```

---

## Slide 12: Conclusion & Leadership Discussion

### Strategic Summary
* VeriFlow delivers a **verifiable, audit-ready approach** to code security that embraces the power of Modern AI while eliminating hallucination risks through deterministic AST gates ([`src/veriflow/claims.py`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/claims.py)).
* The architecture provides **unconditional visibility into coverage gaps**, ensuring that leadership never mistakes an incomplete scan for secure code ([`src/veriflow/readiness.py`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/readiness.py)).
* The platform gives our enterprise **total control over cost, deployment boundaries, and data sovereignty** ([`src/veriflow/triage.py:L19-L55`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/triage.py#L19-L55)).

### Key Discussion Questions for Leadership
1. **Model Deployment Preference:** Should our initial enterprise deployment leverage bank-hosted cloud endpoints (Azure OpenAI / AWS Anthropic via [`src/veriflow/models.py:L163-L205`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/models.py#L163-L205)) or completely air-gapped on-premise models (Ollama / vLLM via [`src/veriflow/models.py:L77-L95`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/models.py#L77-L95))?
2. **Pilot Application Portfolio:** Which business-critical applications (Java/Spring, Python, or C#/.NET via profiles in [`src/veriflow/joern.py:L20-L35`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/joern.py#L20-L35)) should form the initial cohort for the OpenShift pilot?
3. **Integration Targets:** Which enterprise vulnerability management systems (e.g., Jira, ServiceNow, ThreadFix via CSV/SARIF projections in [`src/veriflow/reports.py:L410-L460`](file:///Users/eric/PycharmProjects/veriflow/src/veriflow/reports.py#L410-L460)) should receive prioritized automated export feeds?
