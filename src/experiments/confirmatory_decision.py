"""Machine-enforced claim decision for the frozen EC-ReAct experiment."""
from __future__ import annotations

from typing import Any, Mapping


def evaluate_confirmatory_decision(
    analysis: Mapping[str, Any],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply preregistered absolute, relative and safety claim gates."""
    reporting = config["reporting"]
    gates = reporting["success_gates"]
    metric = reporting["confirmatory_primary_metric"]
    budget = int(reporting["confirmatory_budget"])
    alpha = float(gates["two_sided_p_below"])
    minimum_gain = float(gates["minimum_mean_f1_gain"])
    minimum_absolute = float(gates["minimum_absolute_f1"])
    if (
        gates.get("relative_improvement_rule")
        != "material_or_holm_significant"
    ):
        raise ValueError("unsupported relative improvement rule")
    model_ids = _confirmatory_model_ids(config)
    summaries = list(analysis.get("summaries") or [])
    comparisons = list(analysis.get("paired_comparisons") or [])
    safety = list(
        (analysis.get("safety_gate_evaluations") or {}).get(
            "evaluations"
        )
        or []
    )
    model_decisions = []
    for model_id in model_ids:
        summary = _unique(
            summaries,
            {
                "method_id": "ec_react_full",
                "model_id": model_id,
                "budget": budget,
                "split": "test",
                "metric": metric,
            },
        )
        comparison = _unique(
            comparisons,
            {
                "primary_method_id": "ec_react_full",
                "primary_model_id": model_id,
                "baseline_method_id": "vanilla_react",
                "baseline_model_id": model_id,
                "budget": budget,
                "split": "test",
                "metric": metric,
            },
        )
        safety_gate = _unique(
            safety,
            {
                "primary_method_id": "ec_react_full",
                "primary_model_id": model_id,
                "baseline_method_id": "vanilla_react",
                "budget": budget,
                "split": "external_negative_control",
            },
        )
        missing = [
            name
            for name, value in (
                ("absolute_f1_summary", summary),
                ("vanilla_comparison", comparison),
                ("negative_control_safety_gate", safety_gate),
            )
            if value is None
        ]
        if summary is not None and not _has_fields(
            summary,
            ("ci_low", "ci_high", "confidence_level"),
        ):
            missing.append("absolute_f1_confidence_interval")
        if comparison is not None and not _has_fields(
            comparison,
            (
                "favorable_effect_ci_low",
                "favorable_effect_ci_high",
                "confidence_level",
                "paired_standardized_effect",
                "minimum_detectable_paired_dz",
            ),
        ):
            missing.append("paired_effect_inference")
        if safety_gate is not None and not _has_fields(
            safety_gate,
            (
                "rate_difference_ci_low",
                "rate_difference_ci_high",
                "confidence_level",
            ),
        ):
            missing.append("safety_difference_confidence_interval")
        if missing:
            model_decisions.append({
                "model_id": model_id,
                "status": "insufficient_evidence",
                "missing": missing,
                "passes": False,
            })
            continue
        absolute_f1 = float(summary["mean"])
        gain = float(comparison["favorable_effect"])
        p_holm = float(comparison["p_holm"])
        absolute_pass = absolute_f1 >= minimum_absolute
        material_pass = gain >= minimum_gain
        statistical_pass = p_holm < alpha
        relative_pass = material_pass or statistical_pass
        safety_pass = bool(
            safety_gate[
                "unsafe_false_reachable_must_not_increase_pass"
            ]
        )
        passes = absolute_pass and relative_pass and safety_pass
        model_decisions.append({
            "model_id": model_id,
            "status": "pass" if passes else "fail",
            "passes": passes,
            "paired_independence_groups": comparison[
                "paired_independence_groups"
            ],
            "absolute_f1": absolute_f1,
            "absolute_f1_ci_low": float(summary["ci_low"]),
            "absolute_f1_ci_high": float(summary["ci_high"]),
            "absolute_f1_threshold": minimum_absolute,
            "absolute_f1_pass": absolute_pass,
            "mean_f1_gain_vs_vanilla": gain,
            "mean_f1_gain_ci_low": float(
                comparison["favorable_effect_ci_low"]
            ),
            "mean_f1_gain_ci_high": float(
                comparison["favorable_effect_ci_high"]
            ),
            "paired_standardized_effect": comparison[
                "paired_standardized_effect"
            ],
            "minimum_detectable_paired_dz": comparison[
                "minimum_detectable_paired_dz"
            ],
            "material_gain_threshold": minimum_gain,
            "material_gain_pass": material_pass,
            "holm_adjusted_p": p_holm,
            "alpha": alpha,
            "statistical_pass": statistical_pass,
            "relative_improvement_pass": relative_pass,
            "unsafe_rate_difference": safety_gate[
                "rate_difference_primary_minus_baseline"
            ],
            "unsafe_rate_difference_ci_low": safety_gate[
                "rate_difference_ci_low"
            ],
            "unsafe_rate_difference_ci_high": safety_gate[
                "rate_difference_ci_high"
            ],
            "unsafe_false_reachable_nonincrease_pass": safety_pass,
        })
    all_models_pass = bool(model_decisions) and all(
        item["passes"] for item in model_decisions
    )
    return {
        "decision_version": "1.0",
        "claim": (
            "EC-ReAct improves certified fine-edge path recovery "
            "without increasing false-Reachable errors"
        ),
        "primary_metric": metric,
        "confirmatory_budget": budget,
        "relative_improvement_rule": (
            "mean gain >= threshold OR Holm-adjusted p < alpha"
        ),
        "expected_models": model_ids,
        "model_decisions": model_decisions,
        "claim_allowed": all_models_pass,
        "overall_status": (
            "pass"
            if all_models_pass
            else (
                "insufficient_evidence"
                if any(
                    item["status"] == "insufficient_evidence"
                    for item in model_decisions
                )
                else "fail"
            )
        ),
        "posthoc_metric_substitution_allowed": False,
    }


def _confirmatory_model_ids(config: Mapping[str, Any]) -> list[str]:
    matching = [
        arm
        for arm in config.get("schedule_arms") or []
        if arm.get("role") == "confirmatory_primary"
    ]
    if len(matching) != 1:
        raise ValueError(
            "config must have exactly one confirmatory_primary arm"
        )
    models = matching[0].get("model_ids")
    if not isinstance(models, list) or not models:
        raise ValueError("confirmatory arm has no models")
    return list(models)


def _unique(
    rows: list[Mapping[str, Any]],
    expected: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    matches = [
        row for row in rows
        if all(row.get(key) == value for key, value in expected.items())
    ]
    if len(matches) > 1:
        raise ValueError(
            f"analysis has duplicate gate rows for {dict(expected)}"
        )
    return matches[0] if matches else None


def _has_fields(
    row: Mapping[str, Any],
    fields: tuple[str, ...],
) -> bool:
    return all(field in row for field in fields)
