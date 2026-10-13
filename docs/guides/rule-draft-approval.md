# Rule draft and approval operator guide

This workflow promotes a tested scanner query only after an LLM-origin candidate has passed
downstream triage and an operator has recorded its latest review as `confirmed`. Approval does
not rewrite the original scan and does not execute generated code.

## 1. Prepare and create a draft

Prepare one Joern `.sc` query or CodeQL `.ql`/`.qls` query outside captured repository source.
Also prepare exactly three bounded fixtures: `vulnerable`, `fixed`, and `misleading`. Record each
file's SHA-256 in a strict JSON request:

```json
{
  "engine": "joern",
  "language": "python",
  "target_profile": "python-core",
  "query_path": "/work/new-rule.sc",
  "query_sha256": "64-lowercase-hex-characters",
  "fixtures": [
    {"kind": "vulnerable", "path": "/work/vulnerable.py", "sha256": "64-lowercase-hex-characters"},
    {"kind": "fixed", "path": "/work/fixed.py", "sha256": "64-lowercase-hex-characters"},
    {"kind": "misleading", "path": "/work/misleading.py", "sha256": "64-lowercase-hex-characters"}
  ],
  "test_status": "passed",
  "test_evidence": "Fixture test command and result",
  "benchmark_status": "not_run",
  "benchmark_evidence": ""
}
```

Create and retrieve the immutable draft:

```sh
veriflow --state-dir /state create-rule-draft REPO_ID ATTEMPT_ID FINGERPRINT /work/draft.json
veriflow --state-dir /state rule-draft-status DRAFT_ID
```

The first command copies the query and fixtures into `/state/rule-drafts/DRAFT_ID`, verifies
their digests, and binds them to the exact candidate and confirmed review revision.

## 2. Approve one draft

Retrieve the latest registry with `veriflow --state-dir /state rule-registry`. Put its `version`,
the draft ID, and the bound review revision in an approval document:

```json
{
  "draft_sha256": "DRAFT_ID",
  "expected_registry_version": 0,
  "expected_review_revision": 1,
  "reviewer_label": "security-rule-owner",
  "rationale": "Reviewed evidence, fixtures, and deterministic test results."
}
```

```sh
veriflow --state-dir /state approve-rule-draft DRAFT_ID /work/approval.json UNIQUE_REQUEST_KEY
```

Reusing the same request key for the same draft is idempotent. A stale registry version, changed
review, altered artifact, reused key for another draft, or previously approved draft is rejected.

## 3. Approve a batch

Use an RFC 4180 CSV with this exact header. Relative approval paths resolve from the CSV folder.

```csv
draft_id,approval_path,request_key
abc123...,approvals/abc123.json,approve-abc123
def456...,approvals/def456.json,approve-def456
```

```sh
veriflow --state-dir /state approve-rule-drafts /mnt/pvc/rule-approvals.csv
```

Each row succeeds or fails independently and appears in the machine-readable result. Because
each successful row creates the next registry version, its approval JSON must state the version
expected at that point in CSV order.

## 4. Use the registry

```sh
veriflow --state-dir /state rule-registry
veriflow --state-dir /state rule-registry --version 1
```

The POC registry returns every approved rule's engine, language, CWE, target profile, digest, and
`approved_query_path`. CodeQL scans can explicitly supply a compatible approved `.qls` path as
the `QUERIES` argument. Joern registry entries are governed artifacts for profile integration;
automatic loading of arbitrary approved Joern scripts is intentionally not part of this slice.
The 50-repository benchmark remains a separate evaluation slice.
