from pathlib import Path

import yaml

from src.experiments.confirmatory_decision import (
    evaluate_confirmatory_decision,
)
from src.experiments.statistics import analyze_frozen_runs


def _config():
    path = (
        Path(__file__).resolve().parents[1]
        / "configs"
        / "ec_react_main_v2_draft.yaml"
    )
    return yaml.safe_load(
        path.read_text(encoding="utf-8")
    )


def _analysis(
    *,
    qwen_f1=0.65,
    strong_f1=0.70,
    qwen_gain=0.11,
    strong_gain=0.05,
    qwen_p=0.20,
    strong_p=0.01,
    qwen_unsafe=0.0,
    strong_unsafe=-0.1,
):
    summaries = []
    comparisons = []
    safety = []
    values = {
        "qwen2_5_7b_local": (
            qwen_f1, qwen_gain, qwen_p, qwen_unsafe
        ),
        "gpt_5_4_snapshot": (
            strong_f1, strong_gain, strong_p, strong_unsafe
        ),
    }
    for model, (f1, gain, p_holm, unsafe) in values.items():
        summaries.append({
            "method_id": "ec_react_full",
            "model_id": model,
            "budget": 20,
            "split": "test",
            "metric": "certified_fine_edge_f1_at_5",
            "independence_groups": 20,
            "mean": f1,
            "ci_low": f1 - 0.05,
            "ci_high": f1 + 0.05,
            "confidence_level": 0.95,
        })
        comparisons.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": model,
            "baseline_method_id": "vanilla_react",
            "baseline_model_id": model,
            "budget": 20,
            "split": "test",
            "metric": "certified_fine_edge_f1_at_5",
            "paired_independence_groups": 20,
            "favorable_effect": gain,
            "favorable_effect_ci_low": gain - 0.05,
            "favorable_effect_ci_high": gain + 0.05,
            "confidence_level": 0.95,
            "paired_standardized_effect": 0.5,
            "minimum_detectable_paired_dz": 0.65,
            "p_holm": p_holm,
        })
        safety.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": model,
            "baseline_method_id": "vanilla_react",
            "budget": 20,
            "split": "external_negative_control",
            "rate_difference_primary_minus_baseline": unsafe,
            "rate_difference_ci_low": unsafe - 0.05,
            "rate_difference_ci_high": min(0.0, unsafe + 0.05),
            "confidence_level": 0.95,
            "unsafe_false_reachable_must_not_increase_pass": unsafe <= 0,
        })
    return {
        "summaries": summaries,
        "paired_comparisons": comparisons,
        "safety_gate_evaluations": {"evaluations": safety},
    }


def test_material_or_statistical_gain_passes_for_both_models():
    decision = evaluate_confirmatory_decision(_analysis(), _config())

    assert decision["claim_allowed"] is True
    assert decision["overall_status"] == "pass"
    by_model = {
        item["model_id"]: item
        for item in decision["model_decisions"]
    }
    assert by_model["qwen2_5_7b_local"]["material_gain_pass"] is True
    assert by_model["qwen2_5_7b_local"]["statistical_pass"] is False
    assert by_model["gpt_5_4_snapshot"]["material_gain_pass"] is False
    assert by_model["gpt_5_4_snapshot"]["statistical_pass"] is True
    assert by_model["qwen2_5_7b_local"]["absolute_f1_ci_low"] == 0.60
    assert by_model["qwen2_5_7b_local"][
        "minimum_detectable_paired_dz"
    ] == 0.65


def test_absolute_f1_or_safety_failure_blocks_claim():
    low_f1 = evaluate_confirmatory_decision(
        _analysis(qwen_f1=0.59),
        _config(),
    )
    unsafe = evaluate_confirmatory_decision(
        _analysis(strong_unsafe=0.1),
        _config(),
    )

    assert low_f1["claim_allowed"] is False
    assert low_f1["overall_status"] == "fail"
    assert unsafe["claim_allowed"] is False
    assert unsafe["overall_status"] == "fail"


def test_missing_model_result_is_insufficient_not_success():
    analysis = _analysis()
    analysis["summaries"] = [
        item for item in analysis["summaries"]
        if item["model_id"] != "gpt_5_4_snapshot"
    ]

    decision = evaluate_confirmatory_decision(analysis, _config())

    assert decision["claim_allowed"] is False
    assert decision["overall_status"] == "insufficient_evidence"
    assert decision["posthoc_metric_substitution_allowed"] is False


def test_missing_confidence_interval_blocks_claim():
    analysis = _analysis()
    del analysis["paired_comparisons"][0]["favorable_effect_ci_low"]

    decision = evaluate_confirmatory_decision(analysis, _config())

    assert decision["claim_allowed"] is False
    qwen = next(
        item for item in decision["model_decisions"]
        if item["model_id"] == "qwen2_5_7b_local"
    )
    assert qwen["status"] == "insufficient_evidence"
    assert "paired_effect_inference" in qwen["missing"]


def test_analyzer_output_satisfies_the_full_claim_contract():
    config = {
        "methods": [
            {"method_id": "ec_react_full", "family": "llm"},
            {"method_id": "vanilla_react", "family": "llm"},
        ],
        "schedule_arms": [{
            "role": "confirmatory_primary",
            "model_ids": [
                "qwen2_5_7b_local",
                "gpt_5_4_snapshot",
            ],
        }],
        "statistics": {
            "cluster_bootstrap_resamples": 300,
            "paired_permutation_resamples": 1000,
            "confidence_level": 0.95,
            "confirmatory_alpha": 0.05,
            "power_sensitivity": {
                "target_power": 0.80,
                "alpha": 0.05,
                "sided": 2,
            },
        },
        "reporting": {
            "primary_metrics": ["certified_fine_edge_f1_at_5"],
            "secondary_metrics": ["unsafe_false_reachable"],
            "confirmatory_primary_metric": (
                "certified_fine_edge_f1_at_5"
            ),
            "confirmatory_budget": 20,
            "success_gates": {
                "two_sided_p_below": 0.05,
                "minimum_mean_f1_gain": 0.10,
                "minimum_absolute_f1": 0.60,
                "relative_improvement_rule": (
                    "material_or_holm_significant"
                ),
                "unsafe_false_reachable_must_not_increase": True,
            },
        },
    }
    records = []
    for split in ("test", "external_negative_control"):
        for model in ("qwen2_5_7b_local", "gpt_5_4_snapshot"):
            for group_index in range(8):
                group = f"{split}-g{group_index}"
                for method in ("ec_react_full", "vanilla_react"):
                    f1 = (
                        0.80
                        if split == "test" and method == "ec_react_full"
                        else 0.60
                        if split == "test"
                        else 0.0
                    )
                    run_id = f"{split}-{model}-{group}-{method}"
                    records.append({
                        "run_id": run_id,
                        "schedule_id": "schedule-" + run_id,
                        "research_effectiveness_result": True,
                        "human_gold_used_for_scoring_only": True,
                        "config_sha256": "d" * 64,
                        "method_id": method,
                        "model_id": model,
                        "budget": 20,
                        "split": split,
                        "independence_group": group,
                        "case_id": "case-" + group,
                        "instance_id": "instance-" + group,
                        "score": {
                            "certified_fine_edge_f1_at_k": f1,
                            "unsafe_false_reachable": False,
                        },
                    })

    analysis = analyze_frozen_runs(records, config)
    decision = evaluate_confirmatory_decision(analysis, config)

    assert analysis["analysis_version"] == "0.5"
    assert decision["claim_allowed"] is True
    assert all(
        item["absolute_f1_ci_low"] >= 0.60
        and item["mean_f1_gain_ci_low"] >= 0.0
        and item["unsafe_rate_difference_ci_high"] <= 0.0
        and item["minimum_detectable_paired_dz"] is not None
        for item in decision["model_decisions"]
    )
