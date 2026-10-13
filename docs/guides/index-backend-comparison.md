# Compare syntax and Joern indexing

The syntax backend remains the default:

```sh
veriflow --state-dir STATE index-run RUN_ID
veriflow --state-dir STATE index-run RUN_ID --backend syntax
```

Run the experimental Python Joern inventory with the pinned local tool installation:

```sh
veriflow --state-dir STATE index-run RUN_ID \
  --backend joern --joern-home /path/to/joern-cli --timeout 300
```

Run both against the exact same captured snapshot and return a neutral comparison:

```sh
veriflow --state-dir STATE compare-indexes RUN_ID \
  --joern-home /path/to/joern-cli --timeout 300 \
  > index-comparison.json
```

The result includes both complete index reports and a `comparison` object containing parsed-file,
function and call deltas plus normalized exact symbol/call overlap. Count differences are not a
quality or security verdict. Inspect each backend's limitations and per-file status.

Each backend has a distinct immutable `index_id`. Query either output explicitly:

```sh
veriflow --state-dir STATE query-index RUN_ID \
  --index-id INDEX_ID --kind symbols
```

The Joern backend currently matches the Python inventory boundary only. It requires Python source,
the pinned Joern layout and up to two bounded stages: CPG extraction and inventory query. It does
not execute repository code. It records elapsed stage times and artifact bytes. Capture peak memory
and pod-level CPU through Docker/OpenShift telemetry during portfolio evaluation.

Run comparisons with fixed source snapshots and versions. Keep raw JSON reports, repeat cold and
warm trials, and include failures rather than dropping them. Do not use this command to infer
vulnerabilities, precision, recall or a clean security result.
