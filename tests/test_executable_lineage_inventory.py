from pathlib import Path

from src.data.executable_lineage_inventory import (
    build_executable_lineage_inventory,
)


ROOT = Path(__file__).resolve().parents[1]


def test_combined_candidate_gate_passes_without_faking_human_gold():
    inventory = build_executable_lineage_inventory(ROOT)

    assert inventory["summary"]["runtime_independence_groups"] == 32
    assert inventory["summary"]["configuration_independence_groups"] == 10
    assert inventory["summary"]["combined_independence_groups"] == 42
    assert inventory["summary"]["near_duplicate_review_pending_groups"] == 2
    assert inventory["summary"]["conservative_independence_groups"] == 40
    assert inventory["summary"]["source_count"] == 9
    assert inventory["summary"]["platforms"] == ["AWS", "AZURE", "GCP"]
    assert inventory["minimum_candidate_gate"]["passes"] is True
    assert inventory["summary"]["human_gold_independence_groups"] == 0
    assert inventory["human_gold_gate"] == {
        "minimum_double_blind_labeled_groups": 30,
        "current": 0,
        "remaining": 30,
        "passes": False,
    }


def test_each_lineage_occurs_once_and_stays_unlabeled():
    inventory = build_executable_lineage_inventory(ROOT)
    groups = inventory["groups"]
    identifiers = [item["independence_group"] for item in groups]

    assert len(identifiers) == len(set(identifiers)) == 42
    assert {item["category"] for item in groups} == {
        "runtime",
        "configuration",
    }
    assert all(item["gold_status"] == "unlabeled" for item in groups)
    assert all(item["case_ids"] for item in groups)
    assert all(item["source_ids"] for item in groups)
    assert all(item["platforms"] for item in groups)
    flagged = {
        item["independence_group"]
        for item in groups
        if item["near_duplicate_review_required"]
    }
    assert flagged == {
        "crosscloud-family:data_manipulation",
        "crosscloud-family:data_staged",
    }
    assert (
        inventory["policy"][
            "near_duplicate_groups_counted_toward_minimum"
        ]
        is False
    )
