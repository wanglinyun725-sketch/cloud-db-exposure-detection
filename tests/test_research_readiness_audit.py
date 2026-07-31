from scripts.experiments.audit_research_readiness import build_audit


def test_legacy_entry_point_returns_objective_goal_v2_audit():
    audit = build_audit()

    assert audit["audit_version"] == "2.0"
    assert audit["assessment"].startswith("repository evidence only")
    assert "weighted_current_score_out_of_10" not in audit


def test_zero_executable_oracle_gold_cannot_complete_the_goal():
    audit = build_audit()

    assert audit["objective_complete"] is False
    assert (
        audit["gates"]["thirty_lineage_executable_oracle_gold"]
        is False
    )
    assert (
        audit["evidence"]["executable_oracle_gold"][
            "qualifying_independence_groups"
        ]
        == 0
    )


def test_current_real_benchmark_and_method_gates_are_evidence_backed():
    audit = build_audit()

    assert audit["gates"]["real_cross_cloud_benchmark"] is True
    assert audit["evidence"]["dataset"] == {
        "conservative_independence_groups": 40,
        "source_count": 9,
        "platforms": ["AWS", "AZURE", "GCP"],
    }
    assert audit["gates"]["ec_react_and_baselines_implemented"] is True
    assert audit["evidence"]["method"]["schedule_errors"] == []
