from pathlib import Path

from src.data.configuration_oracle_queue import (
    build_configuration_oracle_queue,
)


ROOT = Path(__file__).resolve().parents[1]


def test_queue_verifies_real_iac_facts_without_creating_gold():
    queue = build_configuration_oracle_queue(ROOT)

    assert queue["summary"] == {
        "cases": 5,
        "independence_groups": 5,
        "sources": 3,
        "platforms": ["AWS", "Azure", "GCP"],
        "verified_literal_assertions": 9,
        "configuration_gold_cases": 0,
        "runtime_gold_cases": 0,
        "path_gold_cases": 0,
        "needs_execution_cases": 5,
    }
    assert queue["policy"]["literal_iac_fact_is_path_gold"] is False
    assert queue["policy"]["generated_labels"] == 0
    assert all(case["gold_label"] is None for case in queue["cases"])
    assert all(case["path_state"] is None for case in queue["cases"])
    assert all(case["label_origin"] is None for case in queue["cases"])
    assert all(
        case["upstream_expected_outcome_exposed"] is False
        for case in queue["cases"]
    )


def test_every_literal_fact_has_immutable_member_and_line_provenance():
    queue = build_configuration_oracle_queue(ROOT)

    for case in queue["cases"]:
        assert [layer["status"] for layer in case["evidence_layers"]] == [
            "verified_literal_facts_only",
            "pending",
            "pending",
        ]
        for assertion in case["configuration_assertions"]:
            raw_ref = assertion["raw_ref"]
            assert len(raw_ref["archive_sha256"]) == 64
            assert len(raw_ref["archive_member_sha256"]) == 64
            assert raw_ref["archive_member_bytes"] > 0
            assert assertion["does_not_prove"]
            for fragment in assertion["fragment_matches"]:
                assert len(fragment["fragment_sha256"]) == 64
                assert fragment["occurrence_count"] >= 1
                assert all(
                    occurrence["line_start"] >= 1
                    and occurrence["line_end"] >= occurrence["line_start"]
                    for occurrence in fragment["occurrences"]
                )
