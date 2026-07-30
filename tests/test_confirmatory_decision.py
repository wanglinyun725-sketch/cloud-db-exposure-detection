from pathlib import Path

import yaml

from src.experiments.confirmatory_decision import (
    evaluate_confirmatory_decision,
)


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
            "p_holm": p_holm,
        })
        safety.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": model,
            "baseline_method_id": "vanilla_react",
            "budget": 20,
            "split": "external_negative_control",
            "rate_difference_primary_minus_baseline": unsafe,
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
