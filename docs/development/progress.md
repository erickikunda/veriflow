# Implementation progress through Slice 160

## Slice 160 — CSV pipeline command and advisory under automatic selection

`run-pipeline-from-csv` takes each CSV row, one at a time, from intake through every Joern
profile of every detected language, advisory triage of every candidate, report export and an
OpenAnt-style summary, with JSON-lines step logs. It resumes: matching snapshots, usable attempts
and stored triage calls are reused, `--rescan-empty` and `--reimport` are explicit. `--review-policy
auto` lets automatic selection run advisory by binding each profile to its reviewed gate or to
none, and `--llm-discovery` with automatic selection now actually runs, once per language. A
double-escaping bug in Markdown report cells is fixed. A pipeline image recipe and an OCP Job
renderer (hosted provider or Ollama sidecar) are added but not yet qualified. See
[Slice 160](slice-160.md). Next build the image and run the Job on OCP.

## Slice 159 — Fair evidence allocation, windowed triage and a tunable envelope

Duplicate flow regions merge before the location budget is spent, truncation retains the flow head
and tail instead of an arbitrary prefix, source bytes are allocated max-min fair so a large
intermediate region cannot starve the endpoints, and the envelope is resolved per profile from CLI
flags, environment variables or an operator-authored file rather than hardcoded. `triage-windows`
walks a flow longer than the envelope in overlapping spans, advisory-only by construction, and
reports where those spans contradict each other. `--unmetered` bypasses every budget check while
still accounting, and `--allow-degraded-evidence` sends incomplete bundles to the model without
ever marking the result verified. Published reports now name every reduction through
`advisory_reductions`, so an unmetered windowed run cannot read as an ordinary gated one. Nine
size bounds outside the envelope were tracking it incorrectly or not at all, including a native
audit cap that made every widened envelope inert for Joern policies. `BUILDER_VERSION` moves to
15, so rebuilt bundles take new identities while stored ones stay valid. See
[Slice 159](slice-159.md). Next run the new `joern-rust-wide` container suite; until it passes,
the twelve-node gate coverage rests on a hand-written native document.

## Slice 158 — Second review pass on the SBOM/OSV chain

Nested advisory validation, bounded accumulation and honest evaluation accounting close four
further review findings. See [Slice 158](slice-158.md). Next native amd64 and OCP acceptance;
an incomplete database now reports zero fully evaluated components.

## Slice 157 — Review findings across the SBOM/OSV chain

Nine reviewed defects fixed, three of which let a component be reported cleanly when it had not
been evaluated. See [Slice 157](slice-157.md). Next native amd64 and OCP acceptance; some
previously clean results now correctly report gaps.

## Slice 156 — Maven range-only advisories end to end

Live range-only Maven advisories exercised the ComparableVersion path end to end, including two
cases a lexical comparison gets wrong. See [Slice 156](slice-156.md). Next native amd64 and OCP
acceptance; a range match is not exploitability.

## Slice 155 — End-to-end scan against the live database

A real scan over a synthetic repository exercised the whole chain and found two defects the unit
suite could not reach. See [Slice 155](slice-155.md). Next native amd64 and OCP acceptance; no
scanner backend ran and nothing establishes exploitability.

## Slice 154 — Full OSV export on linux/amd64

The npm-inclusive export qualified on amd64, with the inventory digest difference traced to
upstream drift rather than architecture. See [Slice 154](slice-154.md). Next native amd64 and
OCP acceptance; emulated timings are not native figures.

## Slice 153 — OSV acquisition image on linux/amd64

The acquisition image builds and qualifies on amd64 under emulation, with a byte-identical
pinned inventory across architectures. See [Slice 153](slice-153.md). Next native amd64 and OCP
acceptance; emulation is not native execution.

## Slice 152 — Opt-in OSV index caching

A derived index cuts a three-ecosystem match from 52.8 to 10.5 seconds by skipping record
re-verification, which is stated per document and opt-in. See [Slice 152](slice-152.md). Next
OCP and registry acceptance; caching changes performance, never candidates.

## Slice 151 — OSV acquisition container qualification

The acquisition image was built and run against the live export, exposing three limits set an
order of magnitude too low. See [Slice 151](slice-151.md). Next index caching to remove the
per-run load cost; no OCP or registry acceptance.

## Slice 150 — Go package and symbol evidence

Go advisories carrying symbol data are classified against first-party references, giving a finer
priority signal that still clears nothing. See [Slice 150](slice-150.md). Next OSV container
qualification; no call graph is resolved.

## Slice 149 — Bounded go.mod dependency discovery

Go modules join the dependency stage with replaced requirements made unmatchable and exact
import evidence. See [Slice 149](slice-149.md). Next OSV container qualification; go.sum is
unread and no symbol matching exists.

## Slice 148 — Import evidence for declared dependencies

A bounded lexical import scan prioritizes dependency candidates without ever clearing one; this
is import evidence, not reachability. See [Slice 148](slice-148.md). Next OSV container
qualification; no call graph and no vulnerable-symbol matching.

## Slice 147 — Networked OSV export acquisition

A separate networked container fetches and pins an OSV export that the offline matcher already
verifies; real container qualification is outstanding. See [Slice 147](slice-147.md). Next
container acceptance against the live export; no reachability.

## Slice 146 — Maven version ordering for OSV ranges

A faithful ComparableVersion port evaluates Maven ECOSYSTEM ranges, validated against Maven's
own ordering vectors. See [Slice 146](slice-146.md). Next networked database acquisition;
inheritance is still unresolved and no reachability is established.

## Slice 145 — OSV matching against a pinned export

Declared components match a pinned offline OSV export on exact versions and semantic-version
ranges, with every unevaluated range recorded as a gap. See [Slice 145](slice-145.md). Next
networked database acquisition; no reachability and no confirmed vulnerability.

## Slice 144 — Bounded Maven pom.xml dependency discovery

Maven declarations join the ecosystem-generalized dependency stage with entity declarations
refused and inheritance recorded as unresolved. See [Slice 144](slice-144.md). Next tier 3
OSV matching; no transitive resolution and no vulnerability position.

## Slice 143 — Bounded npm dependency discovery

Declared npm packages become snapshot-scoped candidate components with pinned/unpinned
provenance and explicit coverage gaps. See [Slice 143](slice-143.md). Next a second
ecosystem; no transitive resolution and no vulnerability position.

## Slice 142 — Snapshot file inventory export

Deterministic CycloneDX export of a snapshot manifest adds a file inventory with no package,
license or vulnerability claim. See [Slice 142](slice-142.md). Next bounded dependency
discovery; package SBOM and OSV matching remain unimplemented.


## Slice 141 — C# explicit shell-start discovery

Added `csharp-query-shell-start-v1` (CWE-78): mapped query input to fully qualified
Process.Start argument syntax with literal sh/bash and -c prefix. Runtime binding
and argument splitting remain unverified. Separate automatic-selection reports;
no new advisory, migration or image promotion. See
[guide](../guides/csharp-shell-discovery.md). Next broaden Go HTTP file-path discovery
to improve language/API breadth beyond the existing shell profile.

## Slice 131 — Python SQL breadth

Bounded sqlite3 query-text flow adds CWE-89 candidates with parameter-binding negatives.
See [Slice 131](slice-131.md). Next automatic language/profile selection.

## Slice 130 — Python SSRF breadth

Explicit Flask-to-requests.get discovery adds bounded CWE-918 candidates. See
[Slice 130](slice-130.md). Next SQL breadth; no qualified SSRF advisory.

## Slice 129 — Java filesystem CWE-22

Explicit Spring GET-to-Files.readAllBytes discovery adds Java path coverage without
changing default SQL behavior. See [Slice 129](slice-129.md). Next bounded SSRF.

## Slice 128 — First CWE breadth addition

Python/Flask CWE-22 profile passes six native fixture cases with discovery-only reporting.
See [Slice 128](slice-128.md). Next Java/Spring path coverage. No new advisory claims.

## Slice 127 — CWE scope and breadth roadmap

Current profiles cover bounded CWE-78/89/94 patterns. Next Python/Flask CWE-22 discovery,
then Java path coverage, SSRF and SQL breadth. See [Slice 127](slice-127.md) and the
[CWE roadmap](../plans/cwe-coverage-roadmap.md). No new coverage is claimed by this assessment.

## Current priority override — approved after Slice 126

Functional completeness and useful detection breadth take precedence over optimization/refinement.
Next Slice 127 inventories/prioritizes language/framework/CWE coverage; Slice 128 onward implements
selected additions. PostgreSQL and distributed-worker qualification are deferred together to
pilot. Recovery refinement stays behind detection breadth unless a demonstrated blocker requires it.
See the standing delivery priority in the implementation plan. Historical next-step notes below
are retained as history, not the current queue.

## Slice 126 — Local acceptance entrypoint

Retained 18-case audit and three negative tests pass; fresh native/test modes are explicit.
See [Slice 126](slice-126.md). Next local PostgreSQL compatibility work.

## Slice 125 — General GCS image matrix

Seven general-language fixture pairs join retained C#/Rust results in the 18-case local
matrix. See [Slice 125](slice-125.md). No cloud/model calls or broader coverage claims.

## Slice 124 — Specialized GCS image acceptance

C#/Rust refreshed image pairs retain projection 14 cloud provenance with 1/0 fixture results.
See [Slice 124](slice-124.md). Next general image matrix acceptance.

## Slice 123 — Consolidated intake/readiness

Operator guidance and current plan now distinguish supported intake, image compatibility
and remaining gates. See [Slice 123](slice-123.md). Next specialized image refresh.

## Slice 122 — Packaged GCS handoff

Dedicated SDK image and refreshed general scanner pass synthetic GCS-to-real-C-scan handoff,
with snapshot-bound projection 14, zero cloud/model calls. See [Slice 122](slice-122.md).

## Slice 121 — Durable cloud provenance

Typed GCS receipts bind repository/archive identity and survive into projection 14 reports.
See [Slice 121](slice-121.md). Next image refresh and packaged GCS handoff validation.

## Slice 120 — Live GCS adapter and CLI

Optional SDK and explicit ADC acquisition command pass local mocked boundary tests.
No real bucket access; next durable cloud provenance and packaging. See [Slice 120](slice-120.md).

## Slice 119 — GCS archive contract

Generation/digest/size-checked internal archive handoff passes five local adapter tests.
Live GCS transport and CLI remain next; see [Slice 119](slice-119.md).

## Slice 118 — Packaged private acquisition

Refreshed acquisition image passes local HTTPS smart-HTTP/CA/auth/HTTP-proxy tests and
public-to-offline-scanner handoff. See [Slice 118](slice-118.md). Next GCS archive intake;
actual bank and OCP acceptance remain pending.

## Slice 117 — Private HTTPS credential input

Exact-repository credentials are supplied only to Git fetch; local HTTPS positive/negative
authentication and CA tests cover the transport boundary. See [Slice 117](slice-117.md).
Next acquisition image refresh and packaged validation.

## Slice 116 — Explicit Git transport configuration

Operator CA/proxy options preserve TLS verification and environment isolation. Private
authentication, native proxy integration and image refresh remain next. See [Slice 116](slice-116.md).

## Slice 115 — Acquisition container and offline handoff

A separate Git/CA acquisition image hands receipt-pinned archives to the qualified offline
scanner. Public-repository mixed acquisition and one C scan pass, with zero model calls.
See [Slice 115](slice-115.md). Next enterprise acquisition configuration; no migration or OCP apply.


## Slice 114 — repositories.csv acquisition

Explicit bounded Git CSV acquisition emits successful archives.csv rows and a complete
per-row acquisition summary, reusing source/receipt safeguards. See [Slice 114](slice-114.md).
No migration, model or scan execution. Next dedicated networked acquisition-stage packaging.


## Slice 113 — Refreshed application in smoke images

All three toolchain variants now install the current built application and locked Python
dependencies. Plain/receipt-enabled mounted batch checks verify projection 13 and explicit
invalid-row outcomes. See [Slice 113](slice-113.md). Next bounded repositories.csv acquisition.
No migration or bank deployment; immutable earlier image versions remain unchanged.


## Slice 112 — Durable Git provenance

Optional pinned receipt columns persist validated provenance in existing intake JSON and
bind it to captured file hashes. Projection 13 exposes commit/archive identity and binding
status across report formats. See [Slice 112](slice-112.md). No migration. Next container
application refresh/requalification before provenance-enabled PVC input is used there.


## Slice 111 — Mounted multi-row archive batches

Separate batch entrypoint reuses intake and sequential scanning, with up to ten rows,
per-row exact reports, progress summaries and explicit incomplete/failed exits. See
[Slice 111](slice-111.md). No migration or OCP operation. Next durable Git provenance.


## Slice 110 — PVC archive manifest naming

Mounted smoke entrypoints accept archives.csv with input.csv compatibility and reject
ambiguous/Git/linked/non-file input before scan state. See [Slice 110](slice-110.md).
One-row smoke semantics remain; next bounded mounted multi-row handoff. No migration.


## Slice 109 — Public HTTPS Git acquisition

Explicit acquire-git prepares commit-pinned raw-blob source ZIP, hashed CSV and provenance
sidecar for existing archive intake. Host allowlist, bounded execution and unsupported-content
rejection are enforced. See [Slice 109](slice-109.md). No migration or automatic scan.
Next durable intake/report binding of acquisition provenance; private Git/GCS remain open.


## Slice 108 — Specialized C# and Rust smoke images

The shared mounted archive-to-report workflow now has separate C# repair and Rust toolchain
layers, with per-image selection and the existing tool identity gates. See [Slice 108](slice-108.md).
No migration or bank deployment. Next bounded repository-URL acquisition intake.


## Slice 107 — Seven-language mounted smoke workflow

Explicit language/profile selection now connects the namespace Job to the shared offline
scan/report workflow for Java, Python, JavaScript, TypeScript, Go, C and C++. C#/Rust remain
outside this image pending their separate toolchain layers. See [Slice 107](slice-107.md).
No migration or cluster operation. Next C#/Rust deployment handoff, not further CLI polish.


## Slice 106 — Offline OCP smoke deployment preparation

Namespace manifest renderer, digest-pinned ARM64 image and one-archive C-profile entrypoint
are implemented. Restricted Docker archive-to-report vulnerable/fixed runs pass 1/0 with
zero model calls. No cluster operation or migration. See [Slice 106](slice-106.md).
Next representative mounted-input integration across profiles; OCP acceptance stays deferred.


## Slice 105 — POC readiness checkpoint

The bounded language/advisory pass is complete for its documented profiles. The remaining
immediate local priority is an OCP-2 offline smoke deployment bundle and Docker rehearsal.
Git/GCS acquisition, hosted HTTP API, PostgreSQL/distributed qualification, real benchmark,
live gateway and actual OCP acceptance remain open. See [checkpoint](slice-105.md).
This documentation checkpoint adds no runtime behavior; 947 tests is the Slice 104 baseline.


## Slice 104 — C/C++ argv-to-system advisory

Two explicit policies reuse budgeted scan/triage/report integration with isolated syntax
and complete native/source evidence checks. 59 new tests and 16 restricted Linux fixture
cases pass; six replay calls and zero live calls. See [Slice 104](slice-104.md).
Next: POC readiness/integration-gap checkpoint across the language/profile matrix.


## Slice 103 — Rust environment-to-shell advisory

Explicit joern-rust-env-review-v1 adds bounded syntax/native/context checks and the existing
budgeted scan/triage/report workflow. Rust's eight-node cross-file path is retained in full.
888 tests and nine restricted Linux cases pass; three replay calls, zero live calls.
See [Slice 103](slice-103.md). Next bounded C/C++ argv-to-system advisory.

## Slice 102 — Go HTTP-to-shell advisory

Explicit joern-go-http-review-v1 adds isolated request/shell syntax checks and bounded
native/source eligibility to the existing scan/advisory/report workflow. 844 tests and nine
restricted Linux cases pass; three replay calls, zero live calls. See [Slice 102](slice-102.md).
Next bounded Rust environment-to-shell advisory, then C-family portability.

## Slice 101 — Repaired C#/ASP.NET advisory

Explicit joern-csharp-review-v1 replays source mapping, checks repair provenance and binds
endpoint claims to mapped syntax facts. Budgeted workflow/report integration is available;
unsupported source candidates abstain without calls. 805 tests and ten restricted Linux
cases pass; four replay advisories, zero live calls. See [Slice 101](slice-101.md).
Next bounded Go HTTP-to-shell advisory; broader C# discovery stays a separate enhancement.

## Slice 100 — JavaScript/TypeScript Express advisory

Explicit language-specific Express policies now support bounded native/source/syntax checks
and budgeted scan/triage/report workflows. 760 tests and 16 restricted Linux cases pass;
six replay advisories, zero live calls. See [Slice 100](slice-100.md). Next bounded C# advisory
using the existing repaired Joern and source-location evidence.

## Slice 99 — Bounded Flask advisory

Explicit Flask evidence/triage policy now uses the main advisory workflow, with native
provenance, isolated endpoint binding and generated intermediates retained as observations.
Eight restricted Linux cases and 696 tests pass; three replay advisories, zero live calls.
See [Slice 99](slice-99.md). Next bounded JavaScript/TypeScript Express advisory portability.

## Slice 98 — Main scan/advisory workflow

Explicit bounded Java/Spring advisory now runs from scan-run/scan-import with existing
budgets, stop/skip reporting, invocation counts and exact-attempt publication. Seven Linux
cases and 678 tests pass; zero live calls. See [Slice 98](slice-98.md). Next bounded Python
Flask evidence/advisory portability, reusing the workflow rather than refining CLI mechanics.


## Slice 97 — Budgeted Joern Spring advisory

Explicit triage/triage-attempt policy now supports native/context preflight, durable
budgets, policy-aware idempotency and post-response checks. Seven Linux cases with two
replay advisories and 667 tests pass. Default Joern scans remain discovery-only. See
[Slice 97](slice-97.md). Next explicit advisory integration into the main scan workflow.


## Slice 96 — Explicit Joern Spring evidence review

Fresh native output is bound to query/SARIF/source evidence; an explicitly selected policy
can assess needs_review claims without invoking a model. Seven restricted Linux cases and
654 tests pass. Automatic Joern triage remains disabled. See [Slice 96](slice-96.md).
Next opt-in budgeted advisory orchestration with replay acceptance and preflight gates.


## Slice 95 — Rust environment discovery and POC checkpoint

Opt-in environment-to-shell profile passes nine restricted Linux cases; 635 tests pass.
The useful-input expansion pass ends here. Next bounded Java/Spring Joern evidence/triage
portability: the current main Joern path still makes no model calls and qualified policies
remain CodeQL-only. See [Slice 95](slice-95.md). Bank benchmark, fleet throughput and OCP
execution remain separate open gates.


## Slice 94 — C/C++ command-line discovery

Opt-in main argument-vector reads to system now run through the main workflow. Eight
restricted Linux cases per language pass; 629 tests pass. Native probes resolved array
and C++ graph-name differences without changing acceptance fixtures. See
[Slice 94](slice-94.md). Next useful Rust input-source modeling within bounded Cargo scope.


## Slice 93 — Go HTTP form-to-shell discovery

Opt-in FormValue/PostFormValue to literal shell -c command text now runs through the
main workflow. Nine restricted Linux cases and 621 tests pass. Command construction
remains separate from proven execution/reachable routes. See [Slice 93](slice-93.md).
Next bounded C/C++ command-line source modeling, preserving breadth-first scope.


## Slice 92 — Express HTTP-input discovery

Opt-in JS/TS request query/body/params field-to-eval profile now runs through the main
workflow. Eight restricted Linux cases per language and 615 tests pass. The observed
factory import-alias gap remains explicit; no triage/recall promotion. See
[Slice 92](slice-92.md). Next bounded Go HTTP-input modeling, preserving breadth.


## Slice 91 — Flask request-to-shell discovery

Opt-in import-aware syntax endpoints remove fixture-name dependence for this bounded
Python profile. Eight Linux cases and 607 tests pass. See [Slice 91](slice-91.md).
Next useful JS/TS HTTP-input profile, preserving breadth-first priorities.

## Slice 90 — Joern benchmark coverage audit

Schema-2 audit plans accept bounded Joern profiles; gaps remain explicit and recall
unknown. Real retained-report publication/retrieval and 596 tests pass.
See [Slice 90](slice-90.md). Next useful detection-profile expansion and scoped evaluation.

## Slice 89 — Joern main scan workflow

scan-run/scan-import route explicit Joern profiles with auto selection and engine-aware
retry skipping. Shared restricted Linux acceptance and 584 tests pass. See [Slice 89](slice-89.md).
Next benchmark/evaluation compatibility and visible coverage gaps.

## Slice 88 — C/C++ durable Joern integration

Five restricted Linux cases per language pass; 566 tests pass. See [Slice 88](slice-88.md).
The bounded opt-in language sequence is complete; next shared backend/pipeline integration.

## Slice 87 — Rust durable Joern integration

Five cases pass on macOS and restricted UBI 10 Linux; 562 tests pass.
Cargo admission remains dependency-free and single-binary. See [Slice 87](slice-87.md).
Next planned C/C++ durable integration.

## Slice 86 — Go durable Joern integration

Five restricted Linux cases pass, including three-package flow; 548 tests pass.
See [Slice 86](slice-86.md). Next Rust integration and Linux acceptance.

## Slice 85 — JavaScript/TypeScript durable Joern integration

Both profiles pass five restricted Linux cases each; 546 regression tests pass.
See [Slice 85](slice-85.md). Next Go integration, then Rust.

## Slice 84 — Python durable Joern integration

Five restricted Linux cases pass (1/0 single-file, 1/0 cross-file, disconnected 0);
542 tests pass. See [Slice 84](slice-84.md). Next JavaScript/TypeScript integration.
Further C# refinement is deferred under the approved breadth-first priority.

## Slice 83 — Durable C# Linux acceptance

All 22 cases pass under restricted Linux, including durable 1/0 discovery and reports.
537 tests pass. See [Slice 83](slice-83.md). Next bounded ASP.NET source-profile qualification.

## Slice 82 — Experimental C# durable discovery

Opt-in command publishes validated paths through normal scan/report storage; real
intake-to-report pair yields 1/0 and stays incomplete. See [Slice 82](slice-82.md).
537 tests pass. Durable Linux integration acceptance is next.

## Slice 81 — Repaired C# restricted Linux acceptance

All 20 flow/binding cases, 18 spans and expected syntax facts pass with arbitrary UID,
read-only root, no network and bounded resources. See [Slice 81](slice-81.md).
Experimental discovery integration is next; actual bank OCP remains deferred.

## Slice 80 — C# framework syntax facts

Optional framework facts attach through validated byte spans and hashes; attributed
parameter subspans are supported. Eighteen baseline nodes validate; 533 tests pass.
See [Slice 80](slice-80.md). Restricted Linux validation is next; triage remains unchanged.

## Slice 79 — C# source-span validation

All 16 retained binding-fixture nodes map to unique syntax spans with raw coordinates
preserved. Repeated/multiline and invalid-input regression tests pass. See [Slice 79](slice-79.md).
Framework facts and runtime qualification remain next; no triage gate is promoted.

## Slice 78 — C# adversarial binding checks

Ten additional cases pass exact callee and flow assertions, including namespace,
instance/overload and disconnected/duplicate-name cases. See [Slice 78](slice-78.md).
Per-node source mapping is next; broader dispatch and runtime qualification remain open.

## Slice 77 — Experimental C# global-namespace repair

A one-line frontend change recovers the original cross-file flow and all ten existing
cases pass. Joern installation and fixtures remain unchanged. See [Slice 77](slice-77.md).
Adversarial binding, source mapping and runtime qualification remain open.

## Slice 76 — Opengrep C# comparison

Stable and interfile alpha pass single-file pairs but miss cross-file and combined-file
call-chain positives. Sample returned coordinates are consistent. See [Slice 76](slice-76.md).
Neither replaces CodeQL evidence yet; bounded Joern repair remains next.

## Slice 75 — C# recovery investigation

Explicit namespaces recover the synthetic cross-file pair (1/0); original global-namespace
failure remains. Mixed raw coordinate errors rule out blanket offsets. See [Slice 75](slice-75.md)
for the bounded repair recommendation. C# remains unqualified.

## Slice 74 — Early C/C++ feasibility

Ten common-subset .c/.cpp cases passed, including shared-header cross-file flows and
disconnected negatives. Sample coordinates matched. See [Slice 74](slice-74.md).
Initial language assessments are complete; C# investigation is next. C++ features,
memory safety and restricted runtime qualification remain open.

## Slice 73 — Go initial feasibility

Five Go module cases passed, including a three-package flow and disconnected negative.
All returned sample source lines matched. See [Slice 73](slice-73.md). Early C/C++ is
next, followed by the deferred C# review; broad Go and Linux qualification remain open.

## Slice 72 — JavaScript/TypeScript initial feasibility

Ten real source-only cases passed across both languages, including ES-module cross-file
flows and disconnected negatives. Sample source lines matched; framework and runtime
qualification remain open. See [Slice 72](slice-72.md). Go is next, followed by early
C/C++ and the deferred C# review.

## Slice 71 — Python initial feasibility

Five source-only Python cases passed: single-file and cross-file pairs 1/0 plus a
disconnected negative. Sample source lines matched; framework and runtime qualification
remain open. See [Slice 71](slice-71.md). JavaScript/TypeScript is next, before Go, early
C/C++ and the deferred C# review.

## Slice 70 — Rust initial feasibility

Four real Cargo-based Rust flow cases passed, including a six-node cross-file path.
Preparation requires a Cargo project/toolchain in this profile; runtime/build-policy
qualification remains open. See [Slice 70](slice-70.md). C# remediation is deferred until
Python, JS/TS, Go and early C/C++ assessments finish.

## Slice 69 — C# gate not passed

The real C# probe missed the vulnerable cross-file chain and exposed framework metadata
and source-line gaps. Single-file Core/MVC/Web API pairs retained expected 1/0 flows;
that does not qualify the backend. See [Slice 69](slice-69.md). Existing 521 tests pass.
C# registration remains gated; no external access blocker requires user action.

## Slice 68 — parser diagnostic observations

Bounded log observations now retain parser-problem files and event counts, with explicit
unknown/truncated states. Nine-case Linux acceptance includes malformed and partially
parsed inputs. See [Slice 68](slice-68.md). Next: Joern C#/ASP.NET feasibility, then Rust.

## Slice 67 — restricted Linux Joern

A separate UBI/JDK21/Joern image and durable seven-case acceptance suite exercise arbitrary
UID, read-only root, network denial and resource limits. See [Slice 67](slice-67.md) for
runtime evidence and the remaining bank OCP boundary. No migration is required.

## Slice 66 — Joern coverage and unknown diagnostics

Joern now reports modeled source/sink/flow counts and missing graph files. Process success
is separate from complete analysis; unqualified parser diagnostics remain null. Shared
reports retain the new coverage block. See [Slice 66](slice-66.md).

## Slice 65 — bounded Spring/JDBC model

Joern now uses fully qualified graph annotations and the JDBC signature rather than
fixture names. Seven real cases cover renamed sources, safe/disconnected flows and
annotation/sink lookalikes. Discovery remains partial and unqualified for triage.
See [Slice 65](slice-65.md).

## Slice 64 — durable experimental Joern

Explicit Joern discovery now stores attempts, candidates and reports. Real durable tests
passed 1/0/0; all reports remain incomplete and Joern triage remains unsupported. The query
is still fixture-scoped. See [Slice 64](slice-64.md). No migration required.

## Slice 63 — real Joern feasibility

Pinned Joern 4.0.625 produced 1/0/0 flows for the vulnerable, parameterized and disconnected
three-file Java fixtures. Source references and hashes are retained. This is fixture-level
macOS feasibility, not Spring qualification or a selectable production adapter. See
[Slice 63](slice-63.md). Existing 499 tests pass.

## Slice 62 — preparation routing and recorded identity

Creation and lookup now route through the selected backend. Static attempts record
version-aware configuration identity; automatic reuse remains disabled until transitive
rule packs and prepared artifacts are pinned. Next: Joern Java feasibility/adapter with
explicit preparation/output contracts. See [Slice 62](slice-62.md).

## Slice 61 — evidence isolation

Backend-owned prepared-input lookup and engine-scoped evidence policies are delivered.
Builder 6, gate 8 and prompt 3 prevent another engine from qualifying via CodeQL rule
names. Legacy CodeQL bundles remain supported. See [Slice 61](slice-61.md).

## Slice 60 — engine provenance

New attempts record engine/capability, prepared-input and rule-entry metadata. Explicitly
different engines cannot satisfy the CodeQL existing-attempt guard. Historical reports
remain readable; CodeQL is the only runnable backend. S2 is partial: prepared-input
routing, evidence-policy isolation and full engine/rule-pack reuse remain open.
See [Slice 60](slice-60.md).

## Current priority — scanner portability

Slice 59 separates CodeQL process execution from integrity checks and publication.
All 484 tests pass. Joern is the preferred qualification candidate; it is not installed
or runnable through VeriFlow yet. Plan §18 supersedes the earlier queue: complete
engine-neutral contracts, qualify Java/Spring then C#/Rust early, compare Opengrep,
and resume language expansion. C and C++ follow the existing language work plan.
See [Slice 59](slice-59.md) for scope and remaining boundaries.

The language-priority notes below describe the earlier planning baseline.

## Priority reset — 10 September 2026

The [implementation plan v0.2](../plans/implementation-plan.md) now prioritizes Java/Spring,
C#/ASP.NET, JavaScript/TypeScript, Rust and Go over further CLI refinement. Slice 37 delivers shared language selection/coverage and a dependency-free Java static
scan-to-report fixture. L0/L1 remain partial: Java semantic indexing, evidence qualification
and Spring/Maven/Gradle profiles come next, followed by the sequence in plan §2.

The estimates and 64-package table below are a **historical baseline for the former scope**.
M3.1 has expanded into seven substantial subpackages; no current expanded-scope completion
percentage is asserted until these are re-estimated. Existing implementation evidence remains
valid, but added scope does not earn completion credit. Defer discretionary CLI/report/storage
enhancements; retain necessary correctness/security fixes and language-workflow documentation.

Slice 38 adds bounded, resumable Java syntax indexing and pre-extraction parse gates.
Java semantic resolution, evidence policies and Spring remain unqualified.

Slice 39 adds snapshot-bound Spring annotation syntax observations; runtime binding,
Java LLM evidence and framework extraction qualification remain open.

Slice 40 adds real source-only Spring-style SQL path acceptance with vulnerable,
fixed, foreign-annotation and malformed-source cases. Built Spring and Java LLM
evidence qualification remain open; L1 is still partial.

Slice 41 adds a narrow Java SQL advisory gate for retained RequestParam-to-executeQuery
flows. Broader Java evidence and built Spring qualification remain pending.

Slice 42 lets Java advisory gates use complete context assembled from bounded
evidence expansions. Build qualification and broader language coverage remain open.

Slice 43 adds explicit Java-only copied-source extraction for Maven/Gradle layouts.
This does not qualify builds; isolated build execution and approved dependencies remain
prerequisites. L1 remains partial.

Slice 44 adds opt-in automatic selection for one detected supported source language.
Mixed-language execution and query routing remain pending.

Slice 45 starts L2 with opt-in C# source-only extraction/reporting. SDK/NuGet behavior
requires explicit download consent. Classic ASP.NET detection qualification has a known
miss; C# evidence and both ASP.NET framework lanes remain unqualified.

Slice 46 resolves the specific classic ASP.NET fixture miss with pinned framework
references and SDK. The classic vulnerable/fixed pair now passes under externally
enforced macOS network denial (1/0 candidates). Slice 47 adds application-managed macOS extraction network isolation. Linux container
qualification and broader C# evidence/framework qualification remain open.

## Historical delivery assessment

Slice 36 extends conservative Flask source mapping to request aliases in evidence gate 3.
M3.2 remains partial; no corpus recall measurement or additional package credit is claimed.

Slice 35 adds a bounded storage/reference inventory. M1.4 remains partial: automated
orphan cleanup and retention are still open. No additional package credit is claimed.

Slice 34 adds extraction-attempt history and timestamps for new extraction records.
This improves recovery visibility without additional work-package credit.

Slice 33 adds paginated import discovery with dispatch state and intake counts. It extends
local operational visibility without additional package credit.

Slice 32 adds terminal import dispatch cancellation. M1.6 remains partial because full
run/process and distributed cancellation are not implemented; package credit is unchanged.

Slice 31 adds durable import dispatch pause/resume and audit history. M1.6 is now partial:
running processes are not interrupted, and cancellation/distributed controls remain open.

Slice 30 adds bounded exact-attempt triage orchestration using existing model/evidence
and budget gates. No new detection-quality or milestone credit is claimed.

Slice 29 adds a self-contained HTML benchmark scorecard. M4.7 remains partial at the full
acceptance level; no bank benchmark or additional package credit is claimed.

Slice 28 adds configurable, recorded CodeQL resource requests. This prepares local
tuning but does not qualify capacity or container enforcement; package credit is unchanged.

Slice 27 adds integrity-checked original SARIF retrieval for exact repository/attempt
identities. M2.8 remains partial because the full finding/coverage contract is still open;
package credit is unchanged.

Slice 26 adds read-only import report inventory and CSV export, scoped to admitted runs
with explicit missing-report states. Local reporting improves; package credit is unchanged.

Slice 25 adds bounded sequential import scanning. This is local orchestration, not
distributed scheduling or throughput qualification; package credit is unchanged.

Slice 24 adds durable request limits alongside monetary budgets, including zero-priced
local inference. This strengthens the existing local controls without new package credit.

Slice 23 adds local Ollama inference for POC testing; no additional detection-quality
or enterprise-qualification credit is claimed.

Slice 22 adds local prerequisite diagnostics. M0 environment qualification remains partial;
no additional work-package credit is claimed.

Slice 21 combines the existing source-only stages behind `scan-run` with prerequisite
gates and exact-attempt publication. It adds no new detection coverage or package credit.

Slices 15–16 add the verified CLI guide, an API documentation delivery gate and repository
run/query-attempt histories. These extend existing partial packages; work-package credit
below remains unchanged.

Slice 17 adds benchmark CSV projections at four explicit grains. M4.6 remains partial:
persisted scorecards and full adjudicated quality measures remain open. Slice 18 adds
per-CWE proxy metrics with explicit no-label/incomplete states; package credit remains partial.

Slice 19 adds durable scorecard publication/history/retrieval. Persisted proxy reports now
exist; full adjudicated quality measures and benchmark qualification still remain open.
No additional work-package credit is claimed.

**Historical planning estimate for the former scope: approximately 31% overall and 64%
of M0–M2.** These are feature-delivery estimates,
not percentages of elapsed effort, calendar duration, production readiness or quality.

The plan contains 64 work packages. The simple rubric below assigns implemented work
1 point, partial work 0.5 and unimplemented work 0. It deliberately gives no credit for
architecture prose alone. Work packages differ greatly in effort, so the result is a
rough progress indicator, not an earned-value forecast or release acceptance decision.

| Milestone | Packages | Implemented | Partial | Unimplemented | Credit |
| --- | ---: | ---: | ---: | ---: | ---: |
| M0: contracts and prerequisites | 8 | 2 | 6 | 0 | 5 / 8 |
| M1: intake and durable execution | 7 | 3 | 2 | 2 | 4 / 7 |
| M2: scan-to-report POC | 10 | 4 | 6 | 0 | 7 / 10 |
| M3: quality and reuse | 9 | 0 | 3 | 6 | 1.5 / 9 |
| M4: benchmark reporting | 8 | 0 | 5 | 3 | 2.5 / 8 |
| M5: multiworker and portfolio exports | 8 | 0 | 0 | 8 | 0 / 8 |
| M6: OpenShift pilot | 7 | 0 | 0 | 7 | 0 / 7 |
| M7: production qualification | 7 | 0 | 0 | 7 | 0 / 7 |
| **Total** | **64** | **9** | **22** | **33** | **20 / 64 ≈ 31%** |

M0–M2 receive 16 / 25 points, or 64%. The source-only CLI path is usable, but the full
milestones include work beyond that narrow demonstration. No entire milestone is
declared accepted merely because its central demonstration works.

## Work-package assessment

| Packages | Status and evidence/remaining scope |
| --- | --- |
| M0.1–M0.5, M0.8 | Partial: pinned Python/local CodeQL, typed runtime contracts and synthetic tests exist; broader environment qualification, static type checking, complete schemas/adapter contracts and a full requirement-to-test register remain |
| M0.6 | Implemented local Python scope: reproducible vulnerable/fixed/incomplete fixtures exercised with real CodeQL and report assertions |
| M0.7 | Implemented initial local scope: separate manifest/label schemas, strict validation, pinned identities and optional stored-metadata alignment; no dataset registration or evaluation |
| M1.1, M1.2, M1.5 | Implemented local scope: CSV admission, safe archive snapshots, SQLite single-worker persistence/checkpoints/recovery |
| M1.4 | Partial: immutable artifacts exist; automated orphan cleanup does not |
| M1.6 | Partial: durable import dispatch pause/resume with audit history; run cancellation and distributed execution controls remain |
| M1.3, M1.7 | Unimplemented: Git acquisition and PostgreSQL contract qualification |
| M2.1, M2.2 | Implemented local Python scope: inventory/conservative resolution, CodeQL extraction/query execution and candidate ingestion |
| M2.3, M2.4 | Partial: index gates/bundles exist; full coverage obligations and security-map semantics remain |
| M2.5 | Partial: replay and opt-in OpenAI/Anthropic transports exist; live gateway compatibility has not been validated |
| M2.6 | Partial: bounded advisory triage and two class policies exist; broader evidence/accepted-verdict semantics remain |
| M2.7 | Partial: exact occurrence references and advisory history exist; stable reviewed finding-family records across edits remain |
| M2.8 | Partial: immutable reports, formats and explicit latest-completed selection with freshness disclosure exist; full finding/coverage report contract remains |
| M2.9, M2.10 | Implemented local scope: scan/candidate CSV exports and single-worker reservations/stop rules |
| M3.2, M3.7 | Partial: narrow Flask source mapping and conservative observation comparison; broader models and coverage-qualified resolution remain |
| M3.8 | Partial: append-only local operator review assertions, evidence ownership, revision checks and report history; authenticated reviewers, suppression expiry and rule-gap records remain |
| Other M3 packages | Unimplemented at the stated acceptance level: Java/Spring, independent exploration/review, dependency/secret adapters, layered cache invalidation and measured cost/quality ablations. Anthropic transport exists, but selective independent review in M3.4 does not; no additional package credit is claimed |
| M4.3, M4.5–M4.7 | Partial: pinned offline report selection, conservative location matching and JSON/Markdown recall-proxy scorecards; full scan configuration, structural/adjudicated matching, per-class metrics and persisted multi-format scorecards remain |
| M4.8 | Partial: compatible saved scorecard comparison and provisional label transitions; cost/latency, model attribution and adjudicated regression gates remain |
| M4.1, M4.2, M4.4 | Unimplemented operationally: durable corpus registration/applicability review and evaluator-only scan dispatch |
| M5–M7 | Unimplemented operationally: distributed orchestration, GCS, enterprise authorization, OpenShift and production load/recovery/quality qualification |

## What the percentages do not establish

There has been no benchmark run against the 50-repository ground truth, no live bank
gateway validation and no demonstrated 1,000-repositories/day throughput. SQLite tests
and local locking are not substitutes for PostgreSQL reservations, Redis coordination
or OpenShift isolation. The largest enterprise and operational risks are still ahead.

The next priorities are complete evidence/coverage and finding-state contracts,
benchmark evaluation
and enterprise-compatible model integration. Update this assessment as acceptance
evidence accumulates; do not increment the percentage simply because another slice
has been numbered or committed.

Slice 48 begins OCP-1 locally: UBI/Linux ARM64 image and restricted Docker Python
acceptance. Actual bank OCP validation is deferred to functional POC completion by
request, and remains required. Other language toolchains and deployment manifests
remain unqualified in Linux.

Slice 49 extends Linux qualification to basic source-only Java using a pinned full
Java 21 JDK. Offline Spring is NOT qualified: the vulnerable case produces zero
candidates with blocked inferred Maven downloads and unresolved annotations. Historical
macOS Spring runs fetched dependencies despite source-only input. Next: pinned Java
profiles and offline Spring requalification. Full builds and Linux C# remain open.
Container suite selection and package inventories use VeriFlow's virtual environment.

Slice 50 supplies pinned local Maven-layout JAR profiles for Java, records profile
identity in reuse/reports and rechecks integrity after extraction. Six pinned Spring
JARs restore the offline flat Spring fixture. Other inferred fetch attempts remain
blocked by the container; the profile itself does not enforce network isolation.

Slice 51 brings the pinned .NET SDK/net48 profile to Linux ARM64 containers and
validates basic C#/classic ASP.NET fixtures with networking denied. This does not
qualify ASP.NET Core, broad classic MVC/Web API coverage, C# LLM evidence or OCP.

Slice 52 qualifies the ASP.NET Core MVC FromQuery/DbCommand SQL fixture pair in
restricted Linux containers with a separate pinned Core reference profile. Minimal
APIs, broad classic MVC/Web API and C# LLM evidence remain open.

Slice 53 adds a distinct Core minimal API MapGet/FromQuery SQL pair under restricted
Linux execution. The vulnerable/fixed pair passes with 1/0 candidates. This advances
L2 fixture coverage; it does not complete C# evidence or broad framework qualification.

Slice 54 qualifies the classic Web API ApiController/FromUri SQL fixture pair with
separate pinned net48/Web API references under Linux network denial. The pair produces
1/0 candidates; C# evidence and classic MVC remain open. No schema migration.

Slice 55 adds the classic MVC Controller/action-parameter SQL fixture pair with a
separate pinned MVC profile. The pair passes with 1/0 candidates under restricted
Linux execution. Core MVC, minimal API, classic Web API and classic MVC now have
individual SQL fixture pairs; broader C# evidence remains the next L2 obligation.

Slice 56 adds narrow C# SQL advisory evidence for explicit Core FromQuery parameters
and CommandText assignments on complete retained CodeQL paths. Syntax parsing is
bounded and isolated; guard effectiveness and runtime reachability remain unproven.
Classic C# source evidence and broader framework qualification remain open.

Slice 57 extends the SQL advisory gate to the qualified classic MVC/Web API public
HttpGet string-action shapes. Guard and reachability claims remain unproven. The next
priority is JavaScript/TypeScript; broader C# semantics/builds remain tracked gaps.

Approved planning addition: T1–T4 configurable triage policy packs, with discovery-only,
explicit exploratory and qualified advisory modes. Current behavior is unchanged.
JavaScript/TypeScript remains next; registry work is reconsidered after initial L3
qualification without indefinitely blocking the remaining language priorities.

Slice 58 starts JavaScript/TypeScript extraction-to-report support with separate
source-only selections, a shared CodeQL extractor and distinct Express/eval fixture
pairs. Semantic resolution and JS/TS triage remain unsupported; readiness stays incomplete.


## Slice 132 — automatic selection delivered

Main CLI scan commands now default to automatic language selection. Joern selects
all bounded profiles per recognized language, with sequential mixed-language
attempts and separate report IDs. Unsupported/missing-tool scopes remain explicit;
no model calls are used for selection. See [automatic selection guide](../guides/automatic-scan-selection.md)
for overrides, advisory requirements, retry semantics and extraction limitations.
No migration or container entrypoint change. Next prioritize useful detection
breadth from the CWE roadmap over CLI/extraction optimization.


## Slice 133 — Java/Spring SSRF discovery

Added bounded request-to-URL.openStream receiver discovery (CWE-918), separate
profile/report identity and automatic Java selection. Destination policy and
exploitability remain unverified; advisory is unsupported for this rule. See
[operator guide](../guides/java-ssrf-discovery.md). No migration, model calls or
published-image promotion. Next: useful JS/TS process-execution breadth, then
reflected XSS; continue prioritizing functional coverage over refinement.


## Slice 134 — Express command-execution discovery

Added `express-request-exec-v1` for JavaScript and TypeScript request-property flow
into child_process.exec command text (CWE-78). Automatic selection includes eval
and exec as separate attempts/reports. Advisory remains unsupported for the new
rules. See [operator guide](../guides/express-command-discovery.md). No migration
or published-image promotion. Next prioritize bounded reflected XSS discovery.


## Slice 135 — explicit HTML response discovery

Added `express-html-send-v1` for JavaScript/TypeScript request fields flowing into
chained response.type("html").send(...) output (CWE-79). Automatic selection retains
separate eval, exec and HTML attempts/reports. This adds a sixth bounded CWE family;
encoding and browser execution remain unverified and advisory is unsupported.
See [guide](../guides/express-html-discovery.md). No migration or published-image
promotion. Next assess bounded Java deserialization candidates (CWE-502), keeping
useful breadth ahead of local refinement.


## Slice 136 — Java object deserialization discovery

Added `java-spring-object-read-v1`: bounded Spring String RequestParam flow through
Base64/byte-stream construction to ObjectInputStream.readObject (CWE-502). Automatic
selection retains a separate attempt/report. This adds a seventh bounded CWE family;
object filters and runtime exploitability remain unverified, advisory unsupported.
See [guide](../guides/java-deserialization-discovery.md). No migration or image
promotion. Next assess bounded Java XML external-entity discovery (CWE-611), with
parser-configuration evidence and explicit uncertainty.


## Slice 137 — explicitly enabled Java XML entity discovery

Added `java-spring-xml-entities-v1` (CWE-611), requiring request input into DOM parsing
and a linked factory binding with explicit external-general-entities=true. Unknown
defaults are omitted, not safe; configuration overrides and actual resolution remain
unverified. Eight bounded CWE families have discovery profiles. See
[guide](../guides/java-xml-discovery.md). Automatic selection includes the profile,
with separate report identity and no qualified advisory. No migration/image promotion.
Next prioritize Java process-execution breadth, then reassess remaining language/API
gaps against the roadmap rather than refining these profiles indefinitely.


## Slice 138 — Java shell command-text discovery

Added `java-spring-runtime-shell-v1` (CWE-78): Spring String RequestParam flow to
the command-text element of an inline Runtime.exec shell array. Automatic selection
retains separate attempt/report identity. Ordinary arguments and extra-element arrays
are excluded; no general process/argument-injection claim. See
[guide](../guides/java-shell-discovery.md). No migration, advisory qualification or
image promotion. Next assess practical C#/ASP.NET request-source breadth, where
legacy Lookup-based discovery remains a significant functional limitation.


## Slice 139 — C# query-binding discovery

Added `csharp-query-commandtext-v1` (CWE-89): parameter-to-CommandText flows require
a mapped query-binding syntax fact at their source, removing Lookup(name) naming
restrictions. Native coverage uses renamed Core FromQuery actions and a cross-file
helper. Automatic selection preserves legacy and new profiles separately. Runtime
route/database identity remains unverified; new-rule advisory unsupported. See
[guide](../guides/csharp-query-discovery.md). No migration/image promotion. Next assess
C# sink breadth with these source facts, prioritizing useful file/process patterns.


## Slice 140 — C# query-to-file discovery

Added `csharp-query-file-read-v1` (CWE-22) using fully qualified ReadAllText receiver
syntax, mapped query-source facts and a conservative local-type-lookalike exclusion.
The frontend does not resolve the API signature; runtime identity and directory
escape remain unverified. Automatic selection retains separate reports. See
[guide](../guides/csharp-file-discovery.md). No migration, new advisory or image
promotion. Next assess bounded C# process execution with argument/option evidence.


## Slice 142 — selectable Python index backend evaluation

Kept the existing syntax inventory as the default and added an experimental, separately
versioned Joern Python inventory. Operators can select either backend, compare both on the
same immutable snapshot, and query either exact index record. The comparison reports parsed
files, inventory counts, normalized overlap, elapsed Joern stages and CPG artifact size; it
does not infer scanner quality or a security verdict. Native validation under the restricted
Linux container profile showed equal file/function coverage on the synthetic fixture and
different call normalization, which is the behavior the experiment is intended to expose.
See the [architecture note](../architecture/index-backend-evaluation.md) and
[operator guide](../guides/index-backend-comparison.md). Python is the only evaluation
language in this slice; language-specific evidence gates and vulnerability profiles remain
unchanged. No migration or image promotion.


## Slice 143 — replay-first hybrid discovery contracts

Added migration `0010` and a separate discovery-call ledger, strict bounded packet/proposal
schemas, immutable snapshot/path/hash/line validation, idempotent replay recording and paginated
retrieval. `discovery-replay` never invokes a provider or creates candidate rows; proposals retain
`llm_discovery` provenance and `not_adjudicated` state for the later integration slice. A failed
packet or proposal cannot alter the completed deterministic attempt. See the
[operator guide](../guides/llm-discovery-replay.md) and
[hybrid architecture](../architecture/hybrid-llm-discovery.md). Next: deterministic packet
selection and opt-in scan orchestration with the shared run budget.


## Slice 144 — deterministic packet selection and hybrid scan mode

Added opt-in `scan-run --llm-discovery` orchestration for both CodeQL and Joern results. The
deterministic scan always runs first. A versioned selector then builds one bounded packet from
verified UTF-8 source using risk markers plus a deterministic lower-ranked audit sample and
reports eligible/examined/deferred files. The current path requires an explicit replay response,
records one simulated invocation and makes zero live calls. Selection or response failure retains
the deterministic report and marks only hybrid exploration partial. Default scans reject stray
discovery options and remain zero-call. See the
[replay and hybrid operator guide](../guides/llm-discovery-replay.md). Next: live provider policy
and shared budget accounting, followed by exploratory candidate persistence and adjudication.


## Slice 145 — exploratory candidates through evidence and review

Valid replay/hybrid proposals now create idempotent `llm_discovery` candidates on the exact
deterministic attempt, with CWE, snapshot-bound primary/related locations, proposal digest and
model-proposal provenance. Attempt counts reconcile deterministic and exploratory rows and hybrid
publication creates a new immutable report version. The bundle builder reads these locations
directly from the verified snapshot instead of pretending they came from SARIF. Existing bounded
triage supports a separate exploratory quote/range gate that never claims semantic reachability or
verification, and explicit operator review can confirm or reject the candidate. Reports expose
origin/CWE and separate deterministic/LLM counts. Cross-origin semantic deduplication remains
conservative. Next: live provider policy/shared accounting, then confirmed rule-gap packages and
exact/batch approval.


## Slice 145 extension — live discovery and shared accounting

Added structured OpenAI Responses, Anthropic Messages and local Ollama discovery bodies/parsers
using the existing strict model policy and an isolated no-retry transport subprocess. Live mode
requires explicit source transmission, classification/endpoint allowlists, configured pricing and
an existing run budget. Discovery and triage now share both monetary and request caps; missing
usage retains the reservation and ambiguous transport outcomes remain unknown. Replay remains
available and unchanged. `triage-report` and immutable repository reports include discovery usage
without exposing source or model prose. No live endpoint was called during implementation.


## Slice 146 — confirmed rule drafts and governed approval

Added migration `0011`, immutable draft packages for confirmed `llm_discovery` candidates, and
exact or CSV-batch approval into a content-addressed registry. Drafts bind query and fixture
digests, candidate/review revision, engine, language, CWE, profile, and operator-attested test
evidence. Approval rechecks artifacts and optimistic registry/review versions; request keys make
exact retries idempotent. Operators can retrieve and integrity-check drafts and exact registry
versions. See the [operator guide](../guides/rule-draft-approval.md). The POC exposes approved
CodeQL paths for explicit use; automatic Joern registry activation and the 50-repository
benchmark remain later work.
