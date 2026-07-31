import json
from pathlib import Path

from src.oracle_gold.scope_candidates import (
    build_scope_candidate_inventory,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_scope_candidates_v1.json"
)


def _build():
    return build_scope_candidate_inventory(
        ROOT,
        registry_path=REGISTRY,
    )


def test_committed_scope_inventory_is_reproducible_and_label_free():
    built = _build()

    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == built
    assert built["status"] == "not_frozen_not_gold"
    assert built["policy"] == {
        "scope_candidates_are_frozen_scope": False,
        "scope_candidates_are_truth_labels": False,
        "empty_observation_is_negative_evidence": False,
        "generated_events": 0,
        "generated_labels": 0,
    }
    assert all(
        item["scope_candidate_status"] != "frozen"
        and "truth_state" not in item
        for item in built["candidates"]
    )


def test_scope_inventory_exposes_evidence_supply_without_padding():
    inventory = _build()

    assert inventory["summary"] == {
        "independence_groups": 40,
        "runtime_groups": 30,
        "runtime_groups_with_observations": 22,
        "runtime_groups_without_observations": 8,
        "configuration_groups": 10,
        "candidates_with_all_scope_fields_observed": 7,
        "single_claim_scope_candidates": 2,
        "platform_counts": {"AWS": 28, "AZURE": 5, "GCP": 7},
    }
    empty_runtime = [
        item
        for item in inventory["candidates"]
        if item["category"] == "runtime_telemetry"
        and item["observation_count"] == 0
    ]
    assert len(empty_runtime) == 8
    assert all(
        item["unresolved_fields"]
        == [
            "actions",
            "network_origins",
            "principals",
            "resources",
            "time_window",
        ]
        for item in empty_runtime
    )


def test_filter_parameter_names_are_not_promoted_to_resources():
    inventory = _build()
    row = next(
        item
        for item in inventory["candidates"]
        if item["independence_group"].endswith(
            "secretsmanager-batch-retrieve-secrets"
        )
    )

    assert row["scope_fields"]["resources"] == []
    assert "resources" in row["unresolved_fields"]
    assert row["all_scope_fields_observed"] is False
