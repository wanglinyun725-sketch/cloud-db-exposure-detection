#!/usr/bin/env python3
"""Sample-level statistical tests for C2 path-retrieval experiments.

The analysis uses paired observations from the held-out ``test`` and
``hard_test`` splits. It never manufactures observations from aggregate
metrics. Confidence intervals use non-parametric bootstrap resampling and
method comparisons use a paired sign-flip permutation test.
"""
from __future__ import annotations

import json
import math
import random
import statistics
from pathlib import Path


ROOT = Path(__file__).parent.parent.parent
RESULTS_FILE = ROOT / "output" / "dataset_v1" / "semantic_experiments_by_split.json"
OUT_FILE = ROOT / "output" / "semantic_corpus" / "statistical_tests_results.json"
REPORT_SPLITS = ("test", "hard_test")
METRICS = ("recall@1", "recall@3", "recall@5", "mrr", "precision@3")
METHODS = (
    "plain_dfs_gatescore",
    "type_dfs_gatescore",
    "full_constrained_gatescore",
    "refute_aware_beam",
)
TREATMENT = "refute_aware_beam"
PRIMARY_BASELINE = "full_constrained_gatescore"


def load_results() -> dict:
    with open(RESULTS_FILE, encoding="utf-8") as f:
        return json.load(f)


def collect_sample_metrics(results: dict, method_name: str) -> dict[str, dict]:
    """Collect held-out sample metrics keyed by sample_id."""
    rows = {}
    for split in REPORT_SPLITS:
        method = results.get("splits", {}).get(split, {}).get("methods", {}).get(method_name, {})
        for row in method.get("sample_metrics", []):
            item = dict(row)
            item["split"] = split
            rows[item["sample_id"]] = item
    if not rows:
        raise RuntimeError(
            f"{RESULTS_FILE} does not contain sample_metrics for {method_name}. "
            "Run scripts/experiments/run_semantic_experiments_by_split.py first."
        )
    return rows


def bootstrap_confidence_interval(
    values: list[float],
    n_bootstrap: int = 10_000,
    confidence: float = 0.95,
    seed: int = 42,
) -> dict:
    """Percentile bootstrap confidence interval over real sample values."""
    if not values:
        raise ValueError("bootstrap requires at least one observation")
    rng = random.Random(seed)
    n = len(values)
    means = [
        statistics.fmean(values[rng.randrange(n)] for _ in range(n))
        for _ in range(n_bootstrap)
    ]
    means.sort()
    alpha = 1.0 - confidence
    return {
        "n": n,
        "mean": statistics.fmean(values),
        "ci_lower": _percentile(means, alpha / 2),
        "ci_upper": _percentile(means, 1 - alpha / 2),
        "confidence": confidence,
        "n_bootstrap": n_bootstrap,
    }


def paired_sign_flip_test(
    baseline: list[float],
    treatment: list[float],
    n_permutations: int = 50_000,
    seed: int = 42,
) -> dict:
    """Two-sided paired randomization test plus paired Cohen's dz."""
    if len(baseline) != len(treatment) or not baseline:
        raise ValueError("paired test requires equally sized non-empty samples")

    differences = [t - b for b, t in zip(baseline, treatment)]
    observed = abs(statistics.fmean(differences))
    rng = random.Random(seed)
    extreme = 0
    for _ in range(n_permutations):
        permuted_mean = statistics.fmean(
            value if rng.random() < 0.5 else -value
            for value in differences
        )
        if abs(permuted_mean) >= observed - 1e-15:
            extreme += 1
    p_value = (extreme + 1) / (n_permutations + 1)

    mean_diff = statistics.fmean(differences)
    sd_diff = statistics.stdev(differences) if len(differences) > 1 else 0.0
    effect_size = mean_diff / sd_diff if sd_diff > 0 else None
    return {
        "n_pairs": len(differences),
        "baseline_mean": statistics.fmean(baseline),
        "treatment_mean": statistics.fmean(treatment),
        "mean_difference": mean_diff,
        "p_value": p_value,
        "effect_size_dz": effect_size,
        "effect_magnitude": classify_effect_size(effect_size),
        "n_permutations": n_permutations,
    }


def classify_effect_size(value: float | None) -> str:
    if value is None or not math.isfinite(value):
        return "undefined_zero_variance"
    magnitude = abs(value)
    if magnitude < 0.2:
        return "negligible"
    if magnitude < 0.5:
        return "small"
    if magnitude < 0.8:
        return "medium"
    return "large"


def paired_metric_values(
    baseline_rows: dict[str, dict],
    treatment_rows: dict[str, dict],
    metric: str,
) -> tuple[list[float], list[float], list[str]]:
    sample_ids = sorted(set(baseline_rows) & set(treatment_rows))
    baseline = [float(baseline_rows[sid][metric]) for sid in sample_ids]
    treatment = [float(treatment_rows[sid][metric]) for sid in sample_ids]
    return baseline, treatment, sample_ids


def apply_holm_correction(results: dict[str, dict], alpha: float = 0.05) -> None:
    """Add Holm-Bonferroni adjusted p-values in place."""
    ordered = sorted(results.items(), key=lambda item: item[1]["p_value"])
    running_max = 0.0
    m = len(ordered)
    for rank, (_, result) in enumerate(ordered):
        adjusted = min(1.0, (m - rank) * result["p_value"])
        running_max = max(running_max, adjusted)
        result["p_value_adjusted"] = running_max
        result["significant_adjusted"] = running_max < alpha


def compare_methods(
    baseline_rows: dict[str, dict],
    treatment_rows: dict[str, dict],
) -> dict[str, dict]:
    comparisons = {}
    for metric in METRICS:
        baseline, treatment, sample_ids = paired_metric_values(
            baseline_rows, treatment_rows, metric
        )
        result = paired_sign_flip_test(baseline, treatment)
        result["sample_ids"] = sample_ids
        comparisons[metric] = result
    apply_holm_correction(comparisons)
    return comparisons


def run_statistical_tests() -> dict:
    results = load_results()
    sample_metrics = {
        method: collect_sample_metrics(results, method)
        for method in METHODS
    }

    treatment_rows = sample_metrics[TREATMENT]
    confidence_intervals = {
        metric: bootstrap_confidence_interval(
            [float(row[metric]) for row in treatment_rows.values()]
        )
        for metric in METRICS
    }
    all_comparisons = {
        baseline: compare_methods(sample_metrics[baseline], treatment_rows)
        for baseline in METHODS
        if baseline != TREATMENT
    }
    primary = all_comparisons[PRIMARY_BASELINE]
    significant = sum(
        result["significant_adjusted"] for result in primary.values()
    )
    all_positive = all(
        result["mean_difference"] > 0 for result in primary.values()
    )

    output = {
        "methodology": {
            "source": RESULTS_FILE.relative_to(ROOT).as_posix(),
            "splits": list(REPORT_SPLITS),
            "unit": "retrieval sample",
            "confidence_interval": "non-parametric percentile bootstrap",
            "paired_test": "two-sided paired sign-flip permutation test",
            "multiple_testing": "Holm-Bonferroni correction within each baseline comparison",
            "seed": 42,
        },
        "confidence_intervals": confidence_intervals,
        "paired_permutation_vs_full_constrained": primary,
        "all_comparisons": all_comparisons,
        "summary": {
            "significant_improvements_adjusted": significant,
            "total_metrics_tested": len(METRICS),
            "all_mean_differences_positive": all_positive,
            "n_paired_samples": len(treatment_rows),
        },
    }
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"paired held-out samples: {len(treatment_rows)}")
    for metric in METRICS:
        ci = confidence_intervals[metric]
        test = primary[metric]
        print(
            f"{metric}: mean={ci['mean']:.4f} "
            f"95%CI=[{ci['ci_lower']:.4f}, {ci['ci_upper']:.4f}] "
            f"diff={test['mean_difference']:+.4f} "
            f"p_holm={test['p_value_adjusted']:.4f}"
        )
    print(f"wrote {OUT_FILE}")
    return output


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        raise ValueError("percentile requires values")
    position = (len(sorted_values) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1 - fraction) + sorted_values[upper] * fraction


if __name__ == "__main__":
    run_statistical_tests()
