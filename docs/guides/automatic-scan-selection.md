# Automatic scan selection

`scan-run` and `scan-import` now default `--language` to `auto`. With
`--engine joern`, omitting `--joern-profile` selects all packaged bounded
profiles for each recognized source language. No model is used for selection.

```sh
veriflow scan-run RUN_ID --engine joern --joern-home /opt/joern-cli
veriflow scan-import IMPORT_ID --engine joern --joern-home /opt/joern-cli --limit 10
```

Python selects Flask command, file-path, SSRF and SQLite query-text profiles.
Java selects the existing Spring/JDBC SQL, Spring file-path, URL.openStream SSRF and ObjectInputStream.readObject explicit XML-entity and Runtime.exec shell profiles.
JavaScript/TypeScript select Express eval, child_process.exec and explicit-HTML response, Go HTTP shell, Rust environment shell,
and C/C++ argv/system. C# runs the repaired legacy SQL, query-binding SQL, file-path and shell-start profiles and requires
`--joern-repair-dir`; Rust requires `--rust-home`. These profiles retain their
individual documented limitations. Framework use is not required for selection:
running all bounded profiles avoids excluding checks based on an uncertain guess.

Mixed-language repositories run sequentially, one attempt/report per language and
profile. The response has `items` and `report_ids`; its top-level `report_id` is
null. Use each ID with `get-report REPO_ID --report-id REPORT_ID --format html`
(or JSON/scan-csv/candidates-csv). This is not an aggregated vulnerability report.
Reports and attempts retain their individual profile identity. Import retry
suppression applies separately to each language/profile; `--rescan` reruns them.

Missing C#/Rust tooling and expected scope errors remain visible in `items` while
other selected scopes continue. Recognized unsupported languages such as Kotlin
are reported explicitly. Unknown extensions are not detected. Header-only C needs
an explicit language; `.h` is ambiguous. Recognition does not expand extractor
support: for example JSX/TSX and `.cc`/`.cxx` remain outside the current copied
source suffixes. Cross-language flow is not implemented. An incomplete or empty
result never means the repository is clean.

To narrow discovery, pass `--language python --joern-profile python-flask-sql-v1`.
Use `--joern-profile default` to select the previous default rule, including when
requesting an existing default-rule advisory. Since Slice 160, automatic
multi-profile discovery accepts advisory only with `--review-policy auto`: each
(language, profile) attempt is bound to its reviewed policy when one exists, and is
otherwise sent without a policy. Ungated requests stop at `unsupported_rule` unless
`--allow-degraded-evidence` is set; when sent, the generic gate returns `unsupported_engine`
for Joern, so their advisory outcome is always `abstain`. An explicit
policy still needs an explicit profile, and an explicit profile with `--language auto`
retains the single-language requirement. With `--llm-discovery`, one additive LLM pass
runs per detected language, attached to that language's first usable attempt.

The default scanner engine remains CodeQL. Its automatic language selection keeps
its existing ambiguity checks and requires a compatible query/suite. Direct Python
API defaults and dedicated/container scanner commands have not changed; API callers
opt into this feature with `language="auto", joern_profile="auto"`.

Selection currently repeats extraction for each profile. Sharing extraction is a
future efficiency improvement; the POC prioritizes useful detection breadth. Stage
timeouts apply to each attempt, not the combined command. No throughput claim is
made from fixture validation.
