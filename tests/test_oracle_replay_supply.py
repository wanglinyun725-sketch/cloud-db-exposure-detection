import json
from pathlib import Path

from src.oracle_gold.replay_supply import (
    build_replay_supply_inventory,
)


ROOT = Path(__file__).resolve().parents[1]
EXECUTION = ROOT / "data" / "real_sources" / "oracle" / "execution"
COMMITTED = EXECUTION / "oracle_replay_supply_inventory_v1.json"


def _build():
    return build_replay_supply_inventory(
        ROOT,
        acquisition_manifest_path=(
            ROOT / "data" / "real_sources" / "acquisition_manifest.json"
        ),
        oracle_registry_path=(
            ROOT / "data" / "real_sources" / "oracle"
            / "executable_oracle_registry_v1.json"
        ),
        probe_contracts_path=(
            EXECUTION / "oracle_probe_contracts_v1.json"
        ),
        replay_safety_audit_path=(
            EXECUTION / "cross_cloud_replay_safety_audit_v1.json"
        ),
    )


def test_committed_supply_inventory_is_reproducible_and_fail_closed():
    built = _build()

    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == built
    assert built["summary"]["lineage_count"] == 40
    assert built["summary"]["source_supply_count"] == 9
    assert built["summary"]["safe_probe_contract_count"] == 7
    assert built["summary"]["execution_eligible_count"] == 0
    assert len({
        row["independence_group"] for row in built["lineages"]
    }) == 40
    assert all(
        row["eligible_for_execution"] is False
        and row["authorization_granted"] is False
        for row in built["lineages"]
    )


def test_supply_inventory_separates_replay_tiers_and_blockers():
    built = _build()
    statuses = built["summary"]["lineage_counts_by_supply_status"]
    tiers = built["summary"]["lineage_counts_by_replay_tier"]

    assert tiers == {
        "pinned_iac_lab": 11,
        "published_telemetry_only": 8,
        "upstream_native_cli": 21,
    }
    assert statuses[
        "blocked_upstream_archive_requires_sanitized_adapter"
    ] == 10
    assert statuses[
        "published_telemetry_only_no_authorized_replay_adapter"
    ] == 8
    assert statuses[
        "safe_adapter_contract_registered_execution_disabled"
    ] == 7
    assert statuses[
        "pinned_supply_available_source_specific_audit_pending"
    ] == 15
    cross_supply = next(
        item
        for item in built["source_supplies"]
        if item["source_id"] == "cross_cloud_observability_2026"
    )
    assert cross_supply["safety_audit"]["blocking_finding_count"] == 298
    assert cross_supply["eligible_for_direct_execution"] is False


def test_supply_inventory_contains_no_answers_or_generated_evidence():
    built = _build()
    serialized = json.dumps(built, sort_keys=True)

    assert '"truth_state"' not in serialized
    assert '"expected_truth_state"' not in serialized
    assert built["policy"]["generated_events"] == 0
    assert built["policy"]["generated_labels"] == 0
    assert built["policy"]["source_supply_implies_reachability"] is False
