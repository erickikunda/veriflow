import json

import pytest
from joern_profile_golden import GOLDEN, capture

from veriflow import joern_profiles
from veriflow.domain import VeriFlowError


def test_catalog_reproduces_every_binding_byte_for_byte():
    assert capture() == json.loads(GOLDEN.read_text())


def test_catalog_is_consistent():
    bindings = joern_profiles.packaged()
    assert len(bindings) == 31
    assert len({b.rule_id for b in bindings}) == len(bindings)
    for b in bindings:
        assert (joern_profiles.files("veriflow") / "queries" / b.query).is_file()
    with pytest.raises(VeriFlowError, match="Unsupported"):
        joern_profiles.binding("go", "default")
    with pytest.raises(VeriFlowError, match="Unsupported"):
        joern_profiles.binding("go", "python-flask-sql-v1")
    assert joern_profiles.binding("go").rule_id == "veriflow/joern-go-lookup-command-v1"


def test_hooks_are_refused_outside_packaged_profiles():
    document = json.loads(
        (joern_profiles.files("veriflow") / "profiles/joern-packaged.json").read_text()
    )
    flask = next(p for p in document["profiles"] if p["name"] == "python-flask-sql-v1")
    with pytest.raises(VeriFlowError, match="hooks"):
        list(joern_profiles._bindings({**document, "profiles": [flask]}, "runtime"))
