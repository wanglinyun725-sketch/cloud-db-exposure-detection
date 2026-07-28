#!/usr/bin/env python3
"""Test whether RefuteAware gains are stable across held-out data sources."""
from __future__ import annotations

import json
import random
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.experiments.run_statistical_tests import (
    METRICS,
    PRIMARY_BASELINE,
    TREATMENT,
    apply_holm_correction,
    bootstrap_confidence_interval,
    collect_sample_metrics,
    load_results,
)

OUT = ROOT / "output" / "semantic_corpus" / "source_robustness_results.json"
REPORT = ROOT / "output" / "source_robustness_report.md"
SOURCES = {
    "pathbench_60": "data:pathbench_60:",
    "samples_v2": "data:verification_set:samples_v2:",
}


def source_of(sample_id: str) -> str:
    for source, prefix in SOURCES.items():
        if sample_id.startswith(prefix):
            return source
    return "unknown"


def heterogeneity_permutation_test(
    first: list[float],
    second: list[float],
    n_permutations: int = 50_000,
    seed: int = 20260725,
) -> dict:
    if not first or not second:
        raise ValueError("heterogeneity test requires two non-empty groups")
    observed_signed = statistics.fmean(first) - statistics.fmean(second)
    observed = abs(observed_signed)
    values = [*first, *second]
    first_n = len(first)
    rng = random.Random(seed)
    extreme = 0
    indices = list(range(len(values)))
    for _ in range(n_permutations):
        rng.shuffle(indices)
        left = [values[index] for index in indices[:first_n]]
        right = [values[index] for index in indices[first_n:]]
        statistic = abs(statistics.fmean(left) - statistics.fmean(right))
        if statistic >= observed - 1e-15:
            extreme += 1
    return {
        "source_difference_in_gain": observed_signed,
        "p_value": (extreme + 1) / (n_permutations + 1),
        "n_permutations": n_permutations,
    }


def main() -> None:
    results = load_results()
    baseline = collect_sample_metrics(results, PRIMARY_BASELINE)
    treatment = collect_sample_metrics(results, TREATMENT)
    sample_ids = sorted(set(baseline) & set(treatment))

    output = {
        "methodology": {
            "splits": ["test", "hard_test"],
            "baseline": PRIMARY_BASELINE,
            "treatment": TREATMENT,
            "unit": "retrieval sample",
            "gain": "treatment metric minus baseline metric on the same sample",
            "source_gain_ci": "10,000-repeat percentile bootstrap",
            "heterogeneity_test": "50,000-label permutation test",
            "multiple_testing": "Holm-Bonferroni over five heterogeneity tests",
        },
        "sources": {},
        "heterogeneity": {},
    }
    differences: dict[str, dict[str, list[float]]] = {
        source: {metric: [] for metric in METRICS}
        for source in SOURCES
    }
    for sample_id in sample_ids:
        source = source_of(sample_id)
        if source not in differences:
            continue
        for metric in METRICS:
            differences[source][metric].append(
                float(treatment[sample_id][metric])
                - float(baseline[sample_id][metric])
            )

    for source, metrics in differences.items():
        output["sources"][source] = {
            metric: bootstrap_confidence_interval(
                values,
                seed=42 + metric_index,
            )
            for metric_index, (metric, values) in enumerate(metrics.items())
        }

    first_name, second_name = SOURCES
    for metric in METRICS:
        output["heterogeneity"][metric] = heterogeneity_permutation_test(
            differences[first_name][metric],
            differences[second_name][metric],
        )
    apply_holm_correction(output["heterogeneity"])

    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT.write_text(_markdown(output), encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False, indent=2))
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"wrote {REPORT.relative_to(ROOT)}")


def _markdown(output: dict) -> str:
    lines = [
        "# 来源稳健性与增益异质性报告",
        "",
        "`test + hard_test` 共 23 个配对检索样本。本报告比较 RefuteAwareBeamSearch",
        "相对 Full-constrained 基线的样本级增益是否在两个数据来源之间一致。",
        "",
        "| 指标 | pathbench_60 增益（95% CI） | samples_v2 增益（95% CI） | 来源增益差 | Holm p |",
        "|---|---:|---:|---:|---:|",
    ]
    for metric in METRICS:
        first = output["sources"]["pathbench_60"][metric]
        second = output["sources"]["samples_v2"][metric]
        heterogeneity = output["heterogeneity"][metric]
        lines.append(
            f"| {metric} | {first['mean']:+.4f} "
            f"[{first['ci_lower']:+.4f}, {first['ci_upper']:+.4f}] | "
            f"{second['mean']:+.4f} "
            f"[{second['ci_lower']:+.4f}, {second['ci_upper']:+.4f}] | "
            f"{heterogeneity['source_difference_in_gain']:+.4f} | "
            f"{heterogeneity['p_value_adjusted']:.4f} |"
        )
    lines.extend([
        "",
        "## 解释",
        "",
        "- 正增益表示 RefuteAware 优于基线；负增益表示弱于基线。",
        "- Holm p 检验的是两个来源的“方法增益”是否不同，不是单个来源内部的显著性。",
        "- 样本量只有 14 与 9；即使异质性未显著，也不能据此证明跨来源等效。",
        "",
        "机器可读结果：`output/semantic_corpus/source_robustness_results.json`",
        "",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    main()
