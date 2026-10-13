# VeriFlow Scan & Advisory Sequence

This document provides a detailed visual and architectural sequence diagram for the **Scan and Advisory Pipeline** in **VeriFlow**.

It details how an admitted source run transitions through snapshot integrity verification, isolated static taint scanning (Joern), candidate fingerprinting, evidence bundling, pre-execution budget reservations, and deterministic evidence-gate triage using generative AI models.

---

## Complete Scan and Advisory Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Operator / CI Runner
    participant CLI as VeriFlow CLI (scan-run)
    participant Store as Local Store / DB (veriflow.db)
    participant Art as Artifact Store (Source Tree)
    participant SAST as Static Scanner Engine (Joern)
    participant Bundle as Evidence Bundle Builder
    participant Triage as Triage Engine & Ledger
    participant Gate as Deterministic Evidence Gate
    participant LLM as Model Gateway (Ollama / Cloud LLM)
    participant Pub as Report Publisher

    %% PHASE 1: PRE-FLIGHT CHECKS & SNAPSHOT VERIFICATION
    rect rgb(240, 245, 255)
        Note over Operator,Art: Phase 1: Pre-Flight & Snapshot Integrity Verification
        Operator->>CLI: scan-run RUN_ID --engine joern --advisory-config config.json
        CLI->>Store: Query Run and Snapshot details (RunID)
        Store-->>CLI: Return Run & SnapshotManifest (file digests, repo_id, classification)
        CLI->>Art: Verify physical source tree matches SnapshotManifest SHA-256
        Art-->>CLI: Integrity verified (no files tampered)
        opt Advisory Config Provided
            CLI->>Store: Query TriageBudget (RunID)
            alt Budget Missing or Limit Exhausted
                Store-->>CLI: No budget / max requests reached
                CLI-->>Operator: Abort: Configure triage-budget before advisory scanning
            else Budget Active
                Store-->>CLI: Budget confirmed (remaining micro-USD & requests)
            end
        end
    end

    %% PHASE 2: STATIC TAINT ANALYSIS & CANDIDATE NORMALIZATION
    rect rgb(245, 250, 245)
        Note over CLI,SAST: Phase 2: Static Analysis Execution (Zero-Network Sandbox)
        CLI->>SAST: Execute Joern CPG Discovery (env: GOPROXY=off, CARGO_NET_OFFLINE=true)
        SAST->>Art: Read immutable source files & build Code Property Graph
        SAST->>SAST: Trace taint flows from untrusted inputs to sensitive sinks
        SAST-->>CLI: Raw JSON / SARIF results (flow paths, line numbers, rules)
        CLI->>Store: Create ScanAttempt record (attempt_id, diagnostics, exit code)
        loop For each raw alert in SARIF
            CLI->>CLI: Calculate structural fingerprint = SHA-256(snapshot_id, driver, rule, sink)
            CLI->>Store: Upsert Candidate (attempt_id, fingerprint, evidence JSON)
        end
    end

    %% PHASE 3: ADVISORY BUNDLING & TRIAGE LOOP
    rect rgb(255, 250, 240)
        Note over CLI,LLM: Phase 3: Bounded Evidence Packaging & AI Triage
        CLI->>CLI: Initiate batch triage (bounded page: offset, limit)
        loop For each Candidate (up to advisory limit)
            CLI->>Bundle: build_bundle(attempt_id, candidate_fingerprint)
            Bundle->>Art: Read bounded source context (primary, steps, sink)
            Note over Bundle: Enforce hard limits: <= 8 locations, <= 16 KiB code, <= 32 KiB total
            Bundle->>Store: Persist EvidenceBundle (bundle_id = SHA-256(bundle_content))
            Bundle-->>CLI: Return Bundle (includes classification, code snippets, rule_id)

            CLI->>Triage: triage(bundle_id, model_config, key)
            
            %% Security Policy Check
            Triage->>Triage: Verify bundle["classification"] in config.allowed_classifications
            alt Classification Disallowed
                Triage-->>CLI: Error: Bundle classification not permitted by model policy
            else Classification Allowed
                %% Budget Reservation
                Triage->>Store: Calculate conservative cost & reserve micro-USD on Run budget
                alt Run Budget Exceeded
                    Store-->>Triage: Reject: Budget limit reached
                    Triage-->>CLI: Halt triage: Budget exhausted (candidate marked deferred)
                else Budget Reserved
                    %% Model Request
                    Triage->>LLM: POST prompt + bounded evidence + JSON schema
                    Note over LLM: Evaluates claims using only supplied code excerpts
                    LLM-->>Triage: Return Decision JSON (verdict, quoted source/sink, guard claims)

                    %% Deterministic Verification Gate
                    Triage->>Gate: assess_evidence(bundle, decision)
                    Gate->>Gate: Check 1: Do quoted snippets match snapshot bytes verbatim?
                    Gate->>Gate: Check 2: Are cited lines within recorded boundary?
                    Gate->>Gate: Check 3: Are source/sink AST syntax anchors valid?
                    
                    alt Gate Check Fails (Quote mismatch or invalid anchor)
                        Gate-->>Triage: Gate REJECTED: Reason logged (e.g. quote_mismatch)
                        Triage->>Triage: Force verdict = "abstain" (Never dismiss candidate)
                    else Gate Check Passes
                        Gate-->>Triage: Gate PASSED (Verifiable syntax match)
                        Triage->>Triage: Accept model disposition (needs_review / likely_false_positive)
                    end

                    Triage->>Store: Record TriageCall (actual charged micro-USD, tokens, verdict, gate status)
                end
            end
        end
    end

    %% PHASE 4: REPORT PUBLICATION
    rect rgb(250, 245, 255)
        Note over CLI,Pub: Phase 4: Atomic Report Materialization
        CLI->>Pub: publish_report(repo_id, run_id, attempt_id)
        Pub->>Store: Compile projection (scan metrics, candidates, triage history, coverage gaps)
        Pub->>Pub: Calculate canonical report digest: report_id = SHA-256(report_json)
        Pub->>Store: Persist PublishedReport (report_id, version = max + 1)
        Pub-->>CLI: Return report publication summary (report_id, version, candidate counts)
        CLI-->>Operator: Output JSON / Markdown scan summary with advisory findings
    end
```

---

## Detailed Sequence Phases & Code Reference Anchors

### Phase 1: Pre-Flight & Snapshot Integrity Verification
* **CLI Trigger:** [`src/veriflow/cli.py:L497-L557`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/cli.py#L497-L557) (`scan_run_command`)
* **Integrity Validation:** [`src/veriflow/indexing.py:L31-L38`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/indexing.py#L31-L38) (`verified_source()`).
* **Budget Pre-Check:** [`src/veriflow/scan_advisory.py:L39-L43`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/scan_advisory.py#L39-L43) (`AdvisoryOptions.validate_budget()`).
* **Guarantee:** Guarantees that neither scanner nor model operates on unverified or tampered source code, and halts early if no triage budget has been allocated.

### Phase 2: Static Analysis Execution (Zero-Network Sandbox)
* **Execution Runner:** [`src/veriflow/joern.py:L36-L73`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/joern.py#L36-L73) (`stage()`).
* **Network Revocation:** Environment variables `GOPROXY="off"`, `GOSUMDB="off"`, and `CARGO_NET_OFFLINE="true"` ensure no dependencies are downloaded during scan execution.
* **Candidate Fingerprinting:** [`src/veriflow/sarif.py:L60-L66`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/sarif.py#L60-L66) (`fingerprint()`).
* **Guarantee:** Alerts are persisted as unreviewed candidates with content-addressed fingerprints, preventing line number shifts from creating duplicate alerts.

### Phase 3: Bounded Evidence Packaging & AI Triage
* **Evidence Bundling:** [`src/veriflow/bundles.py:L44-L105`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/bundles.py#L44-L105) (`_build_bundle()`).
  * Hard limits enforced: Maximum 8 locations, $\le$16 KiB total source text, and $\le$32 KiB total payload.
* **Classification Gating:** [`src/veriflow/triage.py:L110-L111`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/triage.py#L110-L111).
  * Verifies `bundle["classification"] in config.allowed_classifications`.
* **Budget Ledger Reservation:** [`src/veriflow/triage.py:L149-L185`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/triage.py#L149-L185).
* **Deterministic Verification Gate:** [`src/veriflow/claims.py:L300-L360`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/claims.py#L300-L360) (`assess_evidence()`).
  * Validates quoted strings verbatim against snapshot bytes; forces `verdict = "abstain"` if quotes do not match.
* **Guarantee:** LLMs never receive full codebases, cannot run away with cloud costs, and cannot hallucinate sanitizers or code that does not exist.

### Phase 4: Atomic Report Materialization
* **Summary Assembly:** [`src/veriflow/reports.py:L52-L250`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/reports.py#L52-L250) (`projection()`).
* **Immutable Persistence:** [`src/veriflow/reports.py:L252-L287`](file:///Users/eric/PycharmProjects/traceproof/src/veriflow/reports.py#L252-L287) (`publish_report()`).
* **Guarantee:** Reports are immutable and versioned (`version = 1 + max(version)`). Machine findings, human operator reviews, and AI model advice remain strictly separated.
