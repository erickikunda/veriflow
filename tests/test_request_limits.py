import pytest
from test_triage import FakeAdapter, policy
from test_triage import evidence_fixture as evidence_fixture

from veriflow.bundles import build_bundle
from veriflow.domain import VeriFlowError
from veriflow.triage import set_budget, triage, triage_report


def test_zero_cost_calls_are_bounded_and_replays_still_retrieve(store, evidence_fixture):
    run, attempt, fingerprint, _ = evidence_fixture()
    bundle = build_bundle(store, attempt, fingerprint)["bundle_id"]
    config = policy().model_copy(update={"input_micro_usd_per_1k": 0, "output_micro_usd_per_1k": 0})
    adapter = FakeAdapter()
    set_budget(store, run, 0, max_requests=1)
    first = triage(store, bundle, config, adapter, "first")
    assert triage(store, bundle, config, adapter, "first") == first
    with pytest.raises(VeriFlowError, match="request limit exhausted"):
        triage(store, bundle, config, adapter, "second")
    assert adapter.calls == 1
    report = triage_report(store, run)
    assert report["remaining_requests"] == 0 and report["total"] == 1
    assert report["accounted_micro_usd"] == 0
    with pytest.raises(VeriFlowError, match="already fixed"):
        set_budget(store, run, 0, max_requests=2)
    assert set_budget(store, run, 0)["max_requests"] == 1


def test_skipped_requests_count_and_zero_disables_new_work(store, evidence_fixture):
    run, attempt, fingerprint, _ = evidence_fixture()
    bundle = build_bundle(store, attempt, fingerprint)["bundle_id"]
    adapter = FakeAdapter()
    set_budget(store, run, 0, max_requests=1)
    assert triage(store, bundle, policy(), adapter, "skipped")["state"] == "budget_exhausted"
    with pytest.raises(VeriFlowError, match="request limit exhausted"):
        triage(store, bundle, policy(), adapter, "skipped-again")
    assert adapter.calls == 0


def test_migration_defaults_existing_budget_and_preserves_history(store, evidence_fixture):
    run, attempt, fingerprint, _ = evidence_fixture()
    bundle = build_bundle(store, attempt, fingerprint)["bundle_id"]
    set_budget(store, run, 100000)
    adapter = FakeAdapter()
    first = triage(store, bundle, policy(), adapter, "before-upgrade")
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE profile_approvals")
        connection.exec_driver_sql("DROP TABLE profile_tests")
        connection.exec_driver_sql("DROP TABLE profile_drafts")
        connection.exec_driver_sql("DROP TABLE rule_approvals")
        connection.exec_driver_sql("DROP TABLE rule_registries")
        connection.exec_driver_sql("DROP TABLE rule_drafts")
        connection.exec_driver_sql("DROP TABLE discovery_calls")
        connection.exec_driver_sql("DROP TABLE import_controls")
        connection.exec_driver_sql("ALTER TABLE triage_budgets DROP COLUMN max_requests")
        connection.exec_driver_sql("UPDATE alembic_version SET version_num='0007'")
    store.initialize()
    store.initialize()
    assert triage_report(store, run)["max_requests"] == 100
    assert triage_report(store, run)["remaining_requests"] == 99
    assert triage(store, bundle, policy(), adapter, "before-upgrade") == first
    assert adapter.calls == 1


def test_zero_limit_disables_new_requests(store, evidence_fixture):
    run, attempt, fingerprint, _ = evidence_fixture()
    bundle = build_bundle(store, attempt, fingerprint)["bundle_id"]
    set_budget(store, run, 100000, max_requests=0)
    adapter = FakeAdapter()
    with pytest.raises(VeriFlowError, match="request limit exhausted"):
        triage(store, bundle, policy(), adapter, "disabled")
    assert triage_report(store, run)["total"] == 0 and adapter.calls == 0


@pytest.mark.parametrize("value", [-1, True, 10001])
def test_invalid_limits(store, value):
    with pytest.raises(VeriFlowError, match="Request limit"):
        set_budget(store, "unused", 0, max_requests=value)
