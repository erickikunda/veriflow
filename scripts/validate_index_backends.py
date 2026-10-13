"""Run the syntax/Joern inventory comparison on one synthetic immutable snapshot."""

import csv
import json
import shutil
import zipfile
from pathlib import Path

from veriflow.artifacts import ArtifactStore
from veriflow.indexing import compare_indexes
from veriflow.intake import process, submit
from veriflow.persistence import Store, exclusive_worker

root = Path("/work/index-backend-validation")
root.mkdir(parents=True, exist_ok=True)
archive = root / "source.zip"
with zipfile.ZipFile(archive, "w") as target:
    target.writestr(
        "app.py",
        "def greet(name):\n    print(name)\n    return name.strip()\n",
    )
manifest = root / "repositories.csv"
with manifest.open("w", newline="") as target:
    writer = csv.DictWriter(
        target,
        fieldnames=["repo_id", "source_type", "source_uri", "owner", "classification"],
    )
    writer.writeheader()
    writer.writerow(
        {
            "repo_id": "index-comparison",
            "source_type": "pvc",
            "source_uri": str(archive),
            "owner": "poc",
            "classification": "synthetic",
        }
    )
store = Store(root / "state")
try:
    store.initialize()
    imported = submit(store, manifest, root, "index-comparison")
    with exclusive_worker(store.root):
        run_id = process(store, ArtifactStore(store.root), imported)["items"][0]["run_id"]
    with exclusive_worker(store.root):
        result = compare_indexes(store, run_id, Path("/opt/joern-cli"), 300)
    assert result["baseline"]["index_backend"] == "syntax"
    assert result["candidate"]["index_backend"] == "joern"
    assert result["baseline"]["snapshot_id"] == result["candidate"]["snapshot_id"]
    assert result["baseline"]["python_index_gate"] == "ready"
    assert result["candidate"]["python_index_gate"] == "ready"
    assert result["baseline"]["parsed_python_files"] == 1
    assert result["candidate"]["parsed_python_files"] == 1
    assert result["baseline"]["security_verdict"] == "not_assessed"
    assert result["candidate"]["security_verdict"] == "not_assessed"
    Path("/reports/index-comparison.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
finally:
    for log in (root / "state/indexes").glob("*/analyze.log"):
        shutil.copyfile(log, Path("/reports") / f"{log.parent.name}-analyze.log")
    store.close()
