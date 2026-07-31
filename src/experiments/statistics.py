"""Cluster-aware summaries and paired tests for frozen experiment runs."""
from __future__ import annotations

from hashlib import sha256
from itertools import combinations
import json
from math import sqrt
import random
from statistics import mean
from typing import Any, Iterable, Mapping

from src.experiments.power_analysis import (
    minimum_detectable_normal_effect,
)


METRIC_KEYS = {
    "valid_path_recall_at_5": "valid_path_recall_at_k",
    "exact_path_match": "exact_path_match",
    "correct_rejection": "correct_rejection",
    "correct_abstention": "correct_abstention",
    "hallucinated_path_rate": "hallucinated_path_rate",
    "mean_query_cost": "query_cost",
    "literal_exact_path_match": "literal_exact_path_match",
    "coarse_exact_path_match": "coarse_exact_path_match",
    "certified_fine_edge_precision_at_5": (
        "certified_fine_edge_precision_at_k"
    ),
    "certified_fine_edge_recall_at_5": (
        "certified_fine_edge_recall_at_k"
    ),
    "certified_fine_edge_f1_at_5": "certified_fine_edge_f1_at_k",
    "raw_fine_edge_precision_at_5": "raw_fine_edge_precision_at_k",
    "raw_fine_edge_recall_at_5": "raw_fine_edge_recall_at_k",
    "raw_fine_edge_f1_at_5": "raw_fine_edge_f1_at_k",
    "mean_best_fine_edge_f1": "mean_best_edge_f1",
    "mean_best_coarse_edge_f1": "mean_best_coarse_edge_f1",
    "ontology_invalid_predicted_path_rate": (
        "ontology_invalid_predicted_path_rate"
    ),
    "unsafe_false_reachable": "unsafe_false_reachable",
    "unsupported_path_rate": "unsupported_evidence_rate",
}
LOWER_IS_BETTER = {
    "hallucinated_path_rate",
    "mean_query_cost",
    "ontology_invalid_predicted_path_rate",
    "unsafe_false_reachable",
    "unsupported_path_rate",
}


def analyze_frozen_runs(
    records: list[dict[str, Any]],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Analyze repeats without treating runs or episodes as independent."""
    if not records:
        raise ValueError("at least one run record is required")
    primary_metrics = list(config["reporting"]["primary_metrics"])
    secondary_metrics = list(
        config["reporting"].get("secondary_metrics") or []
    )
    requested = list(dict.fromkeys([
        *primary_metrics,
        *secondary_metrics,
    ]))
    unknown = sorted(set(requested) - set(METRIC_KEYS))
    if unknown:
        raise ValueError(f"unsupported reporting metrics: {unknown}")
    required_slices = list(
        config["reporting"].get("required_slices") or []
    )
    supported_slices = {
        "scenario_source_id",
        "runtime_evidence_source_id",
        "platform",
        "split",
    }
    unsupported_slices = sorted(set(required_slices) - supported_slices)
    if unsupported_slices:
        raise ValueError(
            f"unsupported reporting slices: {unsupported_slices}"
        )
    _validate_records(records, required_slices)
    stats = config["statistics"]
    bootstrap_resamples = int(stats["cluster_bootstrap_resamples"])
    permutation_resamples = int(stats["paired_permutation_resamples"])
    confidence = float(stats["confidence_level"])
    if bootstrap_resamples <= 0 or permutation_resamples <= 0:
        raise ValueError("resample counts must be positive")
    if not 0 < confidence < 1:
        raise ValueError("confidence_level must be between zero and one")
    power_spec = stats.get("power_sensitivity") or {}
    target_power = float(power_spec.get("target_power", 0.80))
    power_alpha = float(
        power_spec.get(
            "alpha",
            stats.get("confirmatory_alpha", 0.05),
        )
    )
    power_sided = int(power_spec.get("sided", 2))
    if not 0 < target_power < 1:
        raise ValueError("power target must be between zero and one")
    if not 0 < power_alpha < 1 or power_sided not in {1, 2}:
        raise ValueError("power sensitivity alpha/sided is invalid")

    collapsed = _collapse_repeats_then_groups(records, requested)
    summaries = []
    for condition, metrics in sorted(collapsed.items(), key=str):
        for metric_name in requested:
            values = metrics.get(metric_name, {})
            if not values:
                continue
            point = mean(values.values())
            seed = _seed_for(("bootstrap", condition, metric_name))
            low, high = _cluster_bootstrap_ci(
                list(values.values()),
                bootstrap_resamples,
                confidence,
                seed,
            )
            summaries.append({
                **_condition_payload(condition),
                "metric": metric_name,
                "independence_groups": len(values),
                "mean": point,
                "ci_low": low,
                "ci_high": high,
                "confidence_level": confidence,
            })

    methods = {item["method_id"]: item for item in config["methods"]}
    primary_id = "ec_react_full"
    if primary_id not in methods:
        raise ValueError("config lacks ec_react_full")
    conditions = set(collapsed)
    primary_conditions = sorted(
        (
            condition for condition in conditions
            if condition[0] == primary_id
        ),
        key=str,
    )
    comparisons = []
    for primary in primary_conditions:
        _, primary_model, budget, split = primary
        for baseline_id, baseline_method in sorted(methods.items()):
            if baseline_id == primary_id:
                continue
            baseline_model = (
                primary_model
                if baseline_method["family"] == "llm"
                else None
            )
            baseline = (
                baseline_id,
                baseline_model,
                budget,
                split,
            )
            if baseline not in collapsed:
                continue
            for metric_name in primary_metrics:
                left = collapsed[primary].get(metric_name, {})
                right = collapsed[baseline].get(metric_name, {})
                common = sorted(set(left) & set(right))
                if not common:
                    continue
                differences = [
                    left[group] - right[group] for group in common
                ]
                raw_effect = mean(differences)
                favorable_effect = (
                    -raw_effect
                    if metric_name in LOWER_IS_BETTER
                    else raw_effect
                )
                raw_ci = _cluster_bootstrap_ci(
                    differences,
                    bootstrap_resamples,
                    confidence,
                    _seed_for((
                        "paired-difference-bootstrap",
                        primary,
                        baseline,
                        metric_name,
                    )),
                )
                favorable_ci = (
                    (-raw_ci[1], -raw_ci[0])
                    if metric_name in LOWER_IS_BETTER
                    else raw_ci
                )
                p_value = _paired_sign_permutation(
                    differences,
                    permutation_resamples,
                    _seed_for((
                        "permutation",
                        primary,
                        baseline,
                        metric_name,
                    )),
                )
                comparisons.append({
                    "primary_method_id": primary_id,
                    "primary_model_id": primary_model,
                    "baseline_method_id": baseline_id,
                    "baseline_model_id": baseline_model,
                    "budget": budget,
                    "split": split,
                    "metric": metric_name,
                    "paired_independence_groups": len(common),
                    "raw_mean_difference_primary_minus_baseline": raw_effect,
                    "raw_difference_ci_low": raw_ci[0],
                    "raw_difference_ci_high": raw_ci[1],
                    "favorable_effect": favorable_effect,
                    "favorable_effect_ci_low": favorable_ci[0],
                    "favorable_effect_ci_high": favorable_ci[1],
                    "confidence_level": confidence,
                    "paired_standardized_effect": (
                        _paired_standardized_effect(differences)
                    ),
                    "minimum_detectable_paired_dz": (
                        minimum_detectable_normal_effect(
                            len(common),
                            target_power=target_power,
                            alpha=power_alpha,
                            sided=power_sided,
                        )
                    ),
                    "p_value": p_value,
                })
    adjusted = _holm_adjust(
        [item["p_value"] for item in comparisons]
    )
    for item, p_holm in zip(comparisons, adjusted):
        item["p_holm"] = p_holm

    sliced = _collapse_slices(records, requested, required_slices)
    slice_summaries = _build_slice_summaries(
        sliced,
        requested,
        bootstrap_resamples,
        confidence,
    )
    heterogeneity = _source_heterogeneity(
        sliced,
        config,
        primary_metrics,
        confidence,
    )
    efficiency_gates = _efficiency_gate_evaluations(
        collapsed,
        config,
        bootstrap_resamples,
        confidence,
    )
    safety_summaries = _safety_error_summaries(
        collapsed,
        confidence,
    )
    safety_gates = _safety_gate_evaluations(
        collapsed,
        config,
        bootstrap_resamples,
        confidence,
    )

    return {
        "analysis_version": "0.5",
        "statistical_unit": "independence_group",
        "repeat_handling": (
            "mean within runtime instance, then mean runtime instances "
            "within independence group"
        ),
        "cluster_bootstrap_resamples": bootstrap_resamples,
        "paired_permutation_resamples": permutation_resamples,
        "multiple_comparison_correction": "holm",
        "power_sensitivity": {
            "kind": "prospective_minimum_detectable_paired_effect",
            "target_power": target_power,
            "alpha": power_alpha,
            "sided": power_sided,
            "normal_approximation": True,
            "holm_family_not_incorporated": True,
            "observed_posthoc_power_reported": False,
            "interpretation": (
                "minimum detectable dz is a sensitivity diagnostic based "
                "only on paired lineage N; it is not achieved power and "
                "does not override the preregistered effect/CI/p-value"
            ),
        },
        "primary_metrics": primary_metrics,
        "secondary_metrics": secondary_metrics,
        "secondary_metrics_used_for_hypothesis_tests": False,
        "run_records": len(records),
        "unique_runtime_instances": len({
            (item["case_id"], item["instance_id"]) for item in records
        }),
        "unique_independence_groups": len({
            item["independence_group"] for item in records
        }),
        "summaries": summaries,
        "paired_comparisons": comparisons,
        "required_slices": required_slices,
        "slice_summaries": slice_summaries,
        "source_heterogeneity": heterogeneity,
        "efficiency_gate_evaluations": efficiency_gates,
        "safety_error_summaries": safety_summaries,
        "safety_gate_evaluations": safety_gates,
        "pseudo_replication_guard": True,
    }


def _efficiency_gate_evaluations(
    collapsed: Mapping[
        tuple[str, str | None, int, str],
        dict[str, dict[str, float]],
    ],
    config: Mapping[str, Any],
    bootstrap_resamples: int,
    confidence: float,
) -> dict[str, Any]:
    spec = config["reporting"].get("efficiency_gates") or {}
    if not spec:
        return {"configured": False, "evaluations": []}
    baseline_id = str(
        spec.get("accuracy_baseline_method_id") or "full_query"
    )
    accuracy_metric = str(
        spec.get("accuracy_metric")
        or "certified_fine_edge_f1_at_5"
    )
    cost_metric = str(spec.get("cost_metric") or "mean_query_cost")
    margin = float(spec.get("noninferiority_margin", -0.05))
    minimum_reduction = float(
        spec.get("minimum_mean_cost_reduction_fraction", 0.20)
    )
    if accuracy_metric not in METRIC_KEYS or cost_metric not in METRIC_KEYS:
        raise ValueError("efficiency gate uses unsupported metrics")
    if not -1 < margin <= 0:
        raise ValueError("noninferiority_margin must be in (-1, 0]")
    if not 0 <= minimum_reduction < 1:
        raise ValueError(
            "minimum_mean_cost_reduction_fraction must be in [0, 1)"
        )

    evaluations = []
    for primary in sorted(collapsed, key=str):
        if primary[0] != "ec_react_full":
            continue
        baseline = (baseline_id, None, primary[2], primary[3])
        if baseline not in collapsed:
            continue
        primary_metrics = collapsed[primary]
        baseline_metrics = collapsed[baseline]
        left_accuracy = primary_metrics.get(accuracy_metric, {})
        right_accuracy = baseline_metrics.get(accuracy_metric, {})
        accuracy_groups = sorted(set(left_accuracy) & set(right_accuracy))
        left_cost = primary_metrics.get(cost_metric, {})
        right_cost = baseline_metrics.get(cost_metric, {})
        cost_groups = sorted(set(left_cost) & set(right_cost))
        if not accuracy_groups or not cost_groups:
            continue
        accuracy_differences = [
            left_accuracy[group] - right_accuracy[group]
            for group in accuracy_groups
        ]
        cost_reductions = [
            (right_cost[group] - left_cost[group]) / right_cost[group]
            for group in cost_groups
            if right_cost[group] > 0
        ]
        if not cost_reductions:
            continue
        accuracy_ci = _cluster_bootstrap_ci(
            accuracy_differences,
            bootstrap_resamples,
            confidence,
            _seed_for(("efficiency-accuracy", primary, baseline)),
        )
        cost_ci = _cluster_bootstrap_ci(
            cost_reductions,
            bootstrap_resamples,
            confidence,
            _seed_for(("efficiency-cost", primary, baseline)),
        )
        mean_accuracy_difference = mean(accuracy_differences)
        mean_cost_reduction = mean(cost_reductions)
        accuracy_pass = (
            mean_accuracy_difference >= margin
            and accuracy_ci[0] >= margin
        )
        cost_pass = (
            mean_cost_reduction >= minimum_reduction
            and cost_ci[0] > 0
        )
        evaluations.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": primary[1],
            "baseline_method_id": baseline_id,
            "budget": primary[2],
            "split": primary[3],
            "accuracy_metric": accuracy_metric,
            "paired_accuracy_groups": len(accuracy_groups),
            "mean_accuracy_difference": mean_accuracy_difference,
            "accuracy_difference_ci_low": accuracy_ci[0],
            "accuracy_difference_ci_high": accuracy_ci[1],
            "noninferiority_margin": margin,
            "accuracy_noninferiority_pass": accuracy_pass,
            "cost_metric": cost_metric,
            "paired_cost_groups": len(cost_reductions),
            "mean_cost_reduction_fraction": mean_cost_reduction,
            "cost_reduction_ci_low": cost_ci[0],
            "cost_reduction_ci_high": cost_ci[1],
            "minimum_mean_cost_reduction_fraction": minimum_reduction,
            "cost_reduction_pass": cost_pass,
            "efficiency_claim_pass": accuracy_pass and cost_pass,
            "confidence_level": confidence,
        })
    return {
        "configured": True,
        "accuracy_baseline_method_id": baseline_id,
        "accuracy_metric": accuracy_metric,
        "cost_metric": cost_metric,
        "evaluations": evaluations,
    }


def _safety_error_summaries(
    collapsed: Mapping[
        tuple[str, str | None, int, str],
        dict[str, dict[str, float]],
    ],
    confidence: float,
) -> list[dict[str, Any]]:
    output = []
    for condition, metrics in sorted(collapsed.items(), key=str):
        values = metrics.get("unsafe_false_reachable", {})
        if not values:
            continue
        lineage_events = {
            group: value > 0 for group, value in values.items()
        }
        event_count = sum(lineage_events.values())
        total = len(lineage_events)
        output.append({
            **_condition_payload(condition),
            "metric": "unsafe_false_reachable",
            "independence_groups": total,
            "lineages_with_at_least_one_event": event_count,
            "event_rate": event_count / total,
            "zero_event_exact_one_sided_upper": (
                _zero_event_exact_upper_bound(total, confidence)
                if event_count == 0
                else None
            ),
            "confidence_level": confidence,
            "aggregation": (
                "a lineage is unsafe if any collapsed runtime instance or "
                "repeat has a false-Reachable event"
            ),
        })
    return output


def _safety_gate_evaluations(
    collapsed: Mapping[
        tuple[str, str | None, int, str],
        dict[str, dict[str, float]],
    ],
    config: Mapping[str, Any],
    bootstrap_resamples: int,
    confidence: float,
) -> dict[str, Any]:
    success_gates = config["reporting"].get("success_gates") or {}
    required = (
        success_gates.get("unsafe_false_reachable_must_not_increase")
        is True
    )
    if not required:
        return {"configured": False, "evaluations": []}
    baseline_id = str(
        success_gates.get("unsafe_baseline_method_id")
        or "vanilla_react"
    )
    evaluations = []
    for primary in sorted(collapsed, key=str):
        if primary[0] != "ec_react_full":
            continue
        baseline = (baseline_id, primary[1], primary[2], primary[3])
        if baseline not in collapsed:
            continue
        left = collapsed[primary].get("unsafe_false_reachable", {})
        right = collapsed[baseline].get("unsafe_false_reachable", {})
        common = sorted(set(left) & set(right))
        if not common:
            continue
        primary_events = [left[group] > 0 for group in common]
        baseline_events = [right[group] > 0 for group in common]
        primary_rate = sum(primary_events) / len(common)
        baseline_rate = sum(baseline_events) / len(common)
        difference = primary_rate - baseline_rate
        paired_differences = [
            float(primary_event) - float(baseline_event)
            for primary_event, baseline_event in zip(
                primary_events,
                baseline_events,
            )
        ]
        difference_ci = _cluster_bootstrap_ci(
            paired_differences,
            bootstrap_resamples,
            confidence,
            _seed_for(("safety-difference", primary, baseline)),
        )
        evaluations.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": primary[1],
            "baseline_method_id": baseline_id,
            "budget": primary[2],
            "split": primary[3],
            "paired_independence_groups": len(common),
            "primary_unsafe_event_rate": primary_rate,
            "baseline_unsafe_event_rate": baseline_rate,
            "rate_difference_primary_minus_baseline": difference,
            "rate_difference_ci_low": difference_ci[0],
            "rate_difference_ci_high": difference_ci[1],
            "confidence_level": confidence,
            "nonincrease_margin": 0.0,
            "unsafe_false_reachable_must_not_increase_pass": (
                difference <= 0 and difference_ci[1] <= 0
            ),
        })
    return {
        "configured": True,
        "baseline_method_id": baseline_id,
        "evaluations": evaluations,
    }


def _zero_event_exact_upper_bound(
    trials: int,
    confidence: float,
) -> float:
    """One-sided Clopper-Pearson upper bound when zero events occur."""
    if trials <= 0:
        raise ValueError("zero-event bound requires at least one trial")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between zero and one")
    return 1.0 - (1.0 - confidence) ** (1.0 / trials)


def _collapse_repeats_then_groups(
    records: list[dict[str, Any]],
    metrics: list[str],
) -> dict[
    tuple[str, str | None, int, str],
    dict[str, dict[str, float]],
]:
    instance_values: dict[
        tuple[
            tuple[str, str | None, int, str],
            str,
            str,
            str,
        ],
        dict[str, list[float]],
    ] = {}
    for record in records:
        condition = (
            record["method_id"],
            record.get("model_id"),
            int(record["budget"]),
            record.get("split", "unspecified"),
        )
        key = (
            condition,
            record["independence_group"],
            record["case_id"],
            record["instance_id"],
        )
        bucket = instance_values.setdefault(key, {})
        for metric_name in metrics:
            value = record["score"].get(METRIC_KEYS[metric_name])
            if value is None:
                continue
            bucket.setdefault(metric_name, []).append(float(value))

    group_values: dict[
        tuple[
            tuple[str, str | None, int, str],
            str,
        ],
        dict[str, list[float]],
    ] = {}
    for (condition, group, _case, _instance), values in instance_values.items():
        bucket = group_values.setdefault((condition, group), {})
        for metric_name, repeats in values.items():
            bucket.setdefault(metric_name, []).append(mean(repeats))

    collapsed: dict[
        tuple[str, str | None, int, str],
        dict[str, dict[str, float]],
    ] = {}
    for (condition, group), values in group_values.items():
        bucket = collapsed.setdefault(condition, {})
        for metric_name, instances in values.items():
            bucket.setdefault(metric_name, {})[group] = mean(instances)
    return collapsed


def _collapse_slices(
    records: list[dict[str, Any]],
    metrics: list[str],
    dimensions: list[str],
) -> dict[
    tuple[
        str,
        str,
        tuple[str, str | None, int, str],
    ],
    dict[str, dict[str, float]],
]:
    instance_values: dict[
        tuple[
            str,
            str,
            tuple[str, str | None, int, str],
            str,
            str,
            str,
        ],
        dict[str, list[float]],
    ] = {}
    for record in records:
        condition = (
            record["method_id"],
            record.get("model_id"),
            int(record["budget"]),
            record.get("split", "unspecified"),
        )
        for dimension in dimensions:
            raw_value = record.get(dimension)
            if not isinstance(raw_value, str) or not raw_value:
                raise ValueError(
                    f"record lacks required slice {dimension}"
                )
            key = (
                dimension,
                raw_value,
                condition,
                record["independence_group"],
                record["case_id"],
                record["instance_id"],
            )
            bucket = instance_values.setdefault(key, {})
            for metric_name in metrics:
                value = record["score"].get(METRIC_KEYS[metric_name])
                if value is None:
                    continue
                bucket.setdefault(metric_name, []).append(float(value))

    group_values: dict[
        tuple[
            str,
            str,
            tuple[str, str | None, int, str],
            str,
        ],
        dict[str, list[float]],
    ] = {}
    for (
        dimension,
        slice_value,
        condition,
        group,
        _case,
        _instance,
    ), values in instance_values.items():
        bucket = group_values.setdefault(
            (dimension, slice_value, condition, group), {}
        )
        for metric_name, repeats in values.items():
            bucket.setdefault(metric_name, []).append(mean(repeats))

    collapsed: dict[
        tuple[
            str,
            str,
            tuple[str, str | None, int, str],
        ],
        dict[str, dict[str, float]],
    ] = {}
    for (
        dimension,
        slice_value,
        condition,
        group,
    ), values in group_values.items():
        bucket = collapsed.setdefault(
            (dimension, slice_value, condition), {}
        )
        for metric_name, instances in values.items():
            bucket.setdefault(metric_name, {})[group] = mean(instances)
    return collapsed


def _build_slice_summaries(
    sliced: Mapping[
        tuple[
            str,
            str,
            tuple[str, str | None, int, str],
        ],
        dict[str, dict[str, float]],
    ],
    metrics: list[str],
    bootstrap_resamples: int,
    confidence: float,
) -> list[dict[str, Any]]:
    output = []
    for (
        dimension,
        slice_value,
        condition,
    ), metric_values in sorted(sliced.items(), key=str):
        for metric_name in metrics:
            groups = metric_values.get(metric_name, {})
            if not groups:
                continue
            values = list(groups.values())
            low, high = _cluster_bootstrap_ci(
                values,
                bootstrap_resamples,
                confidence,
                _seed_for((
                    "slice-bootstrap",
                    dimension,
                    slice_value,
                    condition,
                    metric_name,
                )),
            )
            output.append({
                "slice_dimension": dimension,
                "slice_value": slice_value,
                **_condition_payload(condition),
                "metric": metric_name,
                "independence_groups": len(groups),
                "mean": mean(values),
                "ci_low": low,
                "ci_high": high,
                "confidence_level": confidence,
            })
    return output


def _source_heterogeneity(
    sliced: Mapping[
        tuple[
            str,
            str,
            tuple[str, str | None, int, str],
        ],
        dict[str, dict[str, float]],
    ],
    config: Mapping[str, Any],
    primary_metrics: list[str],
    confidence: float,
) -> dict[str, Any]:
    spec = (config["statistics"].get("source_heterogeneity") or {})
    dimensions = list(spec.get("dimensions") or [])
    if not dimensions:
        return {
            "configured": False,
            "source_gain_summaries": [],
            "heterogeneity_tests": [],
        }
    minimum_groups = int(
        spec.get("minimum_independence_groups_per_source", 5)
    )
    resamples = int(spec.get("permutation_resamples", 0))
    baseline_id = str(spec.get("baseline_method_id") or "")
    if (
        minimum_groups < 2
        or resamples <= 0
        or not baseline_id
    ):
        raise ValueError("invalid source heterogeneity configuration")
    if any(dimension not in {
        "scenario_source_id",
        "runtime_evidence_source_id",
    } for dimension in dimensions):
        raise ValueError("heterogeneity dimensions must be source IDs")

    gains: dict[
        tuple[str, str | None, int, str, str, str],
        dict[str, float],
    ] = {}
    for (dimension, source, condition), metrics in sliced.items():
        if dimension not in dimensions or condition[0] != "ec_react_full":
            continue
        primary_model = condition[1]
        baseline_condition = (
            baseline_id,
            primary_model,
            condition[2],
            condition[3],
        )
        baseline = sliced.get(
            (dimension, source, baseline_condition)
        )
        if baseline is None:
            continue
        for metric_name in primary_metrics:
            left = metrics.get(metric_name, {})
            right = baseline.get(metric_name, {})
            common = sorted(set(left) & set(right))
            if not common:
                continue
            raw = {
                group: left[group] - right[group] for group in common
            }
            gains[(
                dimension,
                primary_model,
                condition[2],
                condition[3],
                metric_name,
                source,
            )] = (
                {
                    group: -value for group, value in raw.items()
                }
                if metric_name in LOWER_IS_BETTER
                else raw
            )

    summaries = []
    for key, values_by_group in sorted(gains.items(), key=str):
        (
            dimension,
            model_id,
            budget,
            split,
            metric_name,
            source,
        ) = key
        values = list(values_by_group.values())
        low, high = _cluster_bootstrap_ci(
            values,
            int(config["statistics"]["cluster_bootstrap_resamples"]),
            confidence,
            _seed_for(("source-gain", key)),
        )
        summaries.append({
            "source_dimension": dimension,
            "source": source,
            "primary_method_id": "ec_react_full",
            "baseline_method_id": baseline_id,
            "model_id": model_id,
            "budget": budget,
            "split": split,
            "metric": metric_name,
            "independence_groups": len(values),
            "mean_favorable_gain": mean(values),
            "ci_low": low,
            "ci_high": high,
            "eligible_for_heterogeneity_test": (
                len(values) >= minimum_groups
            ),
        })

    by_condition: dict[
        tuple[str, str | None, int, str, str],
        dict[str, dict[str, float]],
    ] = {}
    for key, values in gains.items():
        dimension, model, budget, split, metric, source = key
        by_condition.setdefault(
            (dimension, model, budget, split, metric), {}
        )[source] = values

    tests = []
    for condition, source_values in sorted(by_condition.items(), key=str):
        eligible = {
            source: values
            for source, values in source_values.items()
            if len(values) >= minimum_groups
        }
        for first, second in combinations(sorted(eligible), 2):
            overlap = set(eligible[first]) & set(eligible[second])
            if overlap:
                raise ValueError(
                    "source heterogeneity slices share independence groups: "
                    + ", ".join(sorted(overlap))
                )
            first_values = list(eligible[first].values())
            second_values = list(eligible[second].values())
            observed, p_value = _two_sample_permutation_difference(
                first_values,
                second_values,
                resamples,
                _seed_for((
                    "source-heterogeneity",
                    condition,
                    first,
                    second,
                )),
            )
            dimension, model, budget, split, metric = condition
            tests.append({
                "source_dimension": dimension,
                "first_source": first,
                "second_source": second,
                "model_id": model,
                "budget": budget,
                "split": split,
                "metric": metric,
                "first_independence_groups": len(first_values),
                "second_independence_groups": len(second_values),
                "difference_in_mean_gain": observed,
                "p_value": p_value,
                "permutation_resamples": resamples,
            })
    adjusted = _holm_adjust([item["p_value"] for item in tests])
    for item, value in zip(tests, adjusted):
        item["p_holm"] = value
    return {
        "configured": True,
        "dimensions": dimensions,
        "baseline_method_id": baseline_id,
        "gain_definition": (
            "positive means EC-ReAct is better; raw primary-minus-baseline "
            "for higher-is-better metrics and its negation for "
            "lower-is-better metrics"
        ),
        "minimum_independence_groups_per_source": minimum_groups,
        "permutation_resamples": resamples,
        "source_gain_summaries": summaries,
        "heterogeneity_tests": tests,
        "multiple_comparison_correction": "holm",
    }


def _two_sample_permutation_difference(
    first: list[float],
    second: list[float],
    resamples: int,
    seed: int,
) -> tuple[float, float]:
    if not first or not second:
        raise ValueError("two-sample permutation requires both sources")
    observed_signed = mean(first) - mean(second)
    observed = abs(observed_signed)
    combined = [*first, *second]
    first_size = len(first)
    indices = list(range(len(combined)))
    rng = random.Random(seed)
    extreme = 0
    for _ in range(resamples):
        rng.shuffle(indices)
        left = [combined[index] for index in indices[:first_size]]
        right = [combined[index] for index in indices[first_size:]]
        if abs(mean(left) - mean(right)) >= observed - 1e-15:
            extreme += 1
    return observed_signed, (extreme + 1) / (resamples + 1)


def _cluster_bootstrap_ci(
    values: list[float],
    resamples: int,
    confidence: float,
    seed: int,
) -> tuple[float, float]:
    if len(values) == 1:
        return values[0], values[0]
    rng = random.Random(seed)
    estimates = sorted(
        mean(rng.choice(values) for _ in values)
        for _ in range(resamples)
    )
    alpha = 1.0 - confidence
    return (
        _quantile(estimates, alpha / 2),
        _quantile(estimates, 1 - alpha / 2),
    )


def _paired_sign_permutation(
    differences: list[float],
    resamples: int,
    seed: int,
) -> float:
    observed = abs(mean(differences))
    if not differences:
        raise ValueError("paired permutation requires differences")
    rng = random.Random(seed)
    extreme = 0
    for _ in range(resamples):
        permuted = mean(
            value if rng.random() < 0.5 else -value
            for value in differences
        )
        if abs(permuted) >= observed - 1e-15:
            extreme += 1
    return (extreme + 1) / (resamples + 1)


def _paired_standardized_effect(differences: list[float]) -> float | None:
    if len(differences) < 2:
        return None
    center = mean(differences)
    variance = sum(
        (value - center) ** 2 for value in differences
    ) / (len(differences) - 1)
    standard_deviation = sqrt(variance)
    if standard_deviation == 0:
        return None
    return center / standard_deviation


def _holm_adjust(p_values: list[float]) -> list[float]:
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [0.0] * len(p_values)
    running = 0.0
    total = len(p_values)
    for rank, (index, value) in enumerate(indexed):
        current = min(1.0, (total - rank) * value)
        running = max(running, current)
        adjusted[index] = running
    return adjusted


def _quantile(values: list[float], probability: float) -> float:
    if not values:
        raise ValueError("quantile requires values")
    position = probability * (len(values) - 1)
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def _condition_payload(
    condition: tuple[str, str | None, int, str],
) -> dict[str, Any]:
    return {
        "method_id": condition[0],
        "model_id": condition[1],
        "budget": condition[2],
        "split": condition[3],
    }


def _seed_for(value: Any) -> int:
    digest = sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    return int(digest[:16], 16)


def _validate_records(
    records: Iterable[dict[str, Any]],
    required_slices: Iterable[str] = (),
) -> None:
    run_ids: set[str] = set()
    schedule_ids: set[str] = set()
    config_hashes: set[str] = set()
    for record in records:
        if record.get("research_effectiveness_result") is not True:
            raise ValueError("all rows must be human-gold effectiveness runs")
        if record.get("human_gold_used_for_scoring_only") is not True:
            raise ValueError("row lacks gold-separation attestation")
        run_id = record.get("run_id")
        if not isinstance(run_id, str) or run_id in run_ids:
            raise ValueError("duplicate or missing run_id")
        run_ids.add(run_id)
        schedule_id = record.get("schedule_id")
        if schedule_id is not None:
            if schedule_id in schedule_ids:
                raise ValueError("duplicate schedule_id")
            schedule_ids.add(schedule_id)
        config_hash = record.get("config_sha256")
        if isinstance(config_hash, str):
            config_hashes.add(config_hash)
        for dimension in required_slices:
            value = record.get(dimension)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"row lacks required slice dimension: {dimension}"
                )
    if len(config_hashes) > 1:
        raise ValueError("records mix multiple frozen configs")
