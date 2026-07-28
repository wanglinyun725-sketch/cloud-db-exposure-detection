#!/usr/bin/env python3
"""Analyze protocol-v8 results without treating repeats as samples."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import statistics
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "output" / "provider_oracle_protocol_v8_results.json"
DEFAULT_JSON = (
    ROOT / "output" / "provider_oracle_protocol_v8_analysis.json"
)
DEFAULT_REPORT = ROOT / "docs" / "provider_oracle_protocol_v8_results.md"
PRIMARY_METHOD = "provider_aware_cp_cert"


def _mean(values) -> float:
    materialized = list(values)
    return statistics.fmean(materialized) if materialized else 0.0


def _wilson(outcomes: list[bool]) -> list[float]:
    if not outcomes:
        return [0.0, 0.0]
    z = 1.959963984540054
    n = len(outcomes)
    proportion = sum(outcomes) / n
    z2 = z * z
    denominator = 1 + z2 / n
    center = (proportion + z2 / (2 * n)) / denominator
    half_width = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / n
            + z2 / (4 * n * n)
        )
        / denominator
    )
    return [center - half_width, center + half_width]


def _exact_mcnemar(wins: int, losses: int) -> float:
    """Two-sided exact McNemar/sign-test p-value for discordant pairs."""
    discordant = wins + losses
    if discordant == 0:
        return 1.0
    tail = sum(
        math.comb(discordant, index)
        for index in range(min(wins, losses) + 1)
    ) / (2 ** discordant)
    return min(1.0, 2 * tail)


def _holm(p_values: list[float]) -> list[float]:
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [1.0] * len(p_values)
    running = 0.0
    total = len(p_values)
    for rank, (original_index, p_value) in enumerate(indexed):
        candidate = min(1.0, (total - rank) * p_value)
        running = max(running, candidate)
        adjusted[original_index] = running
    return adjusted


def _collapse_groups(
    rows: list[dict[str, Any]],
) -> dict[tuple[str, int], dict[str, dict[str, Any]]]:
    buckets: dict[
        tuple[str, int, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for row in rows:
        buckets[(
            row["method_id"],
            int(row["budget"]),
            row["independence_group"],
        )].append(row)

    collapsed: dict[
        tuple[str, int], dict[str, dict[str, Any]]
    ] = defaultdict(dict)
    for (method_id, budget, group), group_rows in buckets.items():
        correctness = []
        for row in group_rows:
            score = row["score"]
            correctness.append(
                bool(score["semantically_correct_state"])
                if score["provider_oracle_gold"]
                else bool(score["correct_abstention"])
            )
        collapsed[(method_id, budget)][group] = {
            "protocol_correct": all(correctness),
            "unsafe_false_reachable": any(
                row["score"]["false_reachable"] for row in group_rows
            ),
            "mean_query_cost": _mean(
                row["score"]["query_cost"] for row in group_rows
            ),
            "case_count": len({
                row["case_id"] for row in group_rows
            }),
            "run_count": len(group_rows),
        }
    return dict(collapsed)


def analyze(report: dict[str, Any]) -> dict[str, Any]:
    if report["protocol_version"] != "8.0-pilot":
        raise ValueError("analysis requires protocol v8")
    collapsed = _collapse_groups(report["rows"])
    summaries = []
    for (method_id, budget), groups in sorted(collapsed.items()):
        correctness = [
            item["protocol_correct"] for item in groups.values()
        ]
        unsafe = [
            item["unsafe_false_reachable"] for item in groups.values()
        ]
        summaries.append({
            "method_id": method_id,
            "budget": budget,
            "independence_groups": len(groups),
            "protocol_correct_group_rate": _mean(correctness),
            "protocol_correct_group_rate_ci95": _wilson(correctness),
            "unsafe_false_reachable_group_rate": _mean(unsafe),
            "unsafe_false_reachable_group_rate_ci95": _wilson(unsafe),
            "mean_group_query_cost": _mean(
                item["mean_query_cost"] for item in groups.values()
            ),
        })

    comparisons = []
    primary_conditions = sorted(
        condition for condition in collapsed
        if condition[0] == PRIMARY_METHOD
    )
    for _, budget in primary_conditions:
        primary = collapsed[(PRIMARY_METHOD, budget)]
        for method_id in sorted({
            condition[0] for condition in collapsed
            if condition[0] != PRIMARY_METHOD
        }):
            baseline = collapsed[(method_id, budget)]
            common = sorted(set(primary) & set(baseline))
            wins = sum(
                primary[group]["protocol_correct"]
                and not baseline[group]["protocol_correct"]
                for group in common
            )
            losses = sum(
                baseline[group]["protocol_correct"]
                and not primary[group]["protocol_correct"]
                for group in common
            )
            ties = len(common) - wins - losses
            comparisons.append({
                "primary_method_id": PRIMARY_METHOD,
                "baseline_method_id": method_id,
                "budget": budget,
                "paired_independence_groups": len(common),
                "primary_wins": wins,
                "baseline_wins": losses,
                "ties": ties,
                "paired_accuracy_difference": _mean(
                    float(primary[group]["protocol_correct"])
                    - float(baseline[group]["protocol_correct"])
                    for group in common
                ),
                "p_exact_mcnemar": _exact_mcnemar(wins, losses),
            })
    adjusted = _holm([
        item["p_exact_mcnemar"] for item in comparisons
    ])
    for item, p_holm in zip(comparisons, adjusted):
        item["p_holm_all_budget_baseline_comparisons"] = p_holm

    new_case_rows = [
        row for row in report["rows"]
        if row["case_id"].startswith("oracle-v8:")
    ]
    new_case_buckets: dict[
        tuple[str, int, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for row in new_case_rows:
        new_case_buckets[(
            row["method_id"],
            int(row["budget"]),
            row["case_id"],
        )].append(row)
    new_case_diagnostics = []
    for (method_id, budget, case_id), rows in sorted(
        new_case_buckets.items()
    ):
        scores = [row["score"] for row in rows]
        new_case_diagnostics.append({
            "method_id": method_id,
            "budget": budget,
            "case_id": case_id,
            "runs": len(rows),
            "strict_state_correct": all(
                item["state_correct"] for item in scores
            ),
            "strict_semantic_or_abstention_correct": all(
                item["semantically_correct_state"]
                if item["provider_oracle_gold"]
                else item["correct_abstention"]
                for item in scores
            ),
            "false_reachable_runs": sum(
                item["false_reachable"] for item in scores
            ),
        })

    return {
        "analysis_version": "provider-oracle-v8-group-analysis-v1",
        "protocol_version": report["protocol_version"],
        "research_effectiveness_result": False,
        "statistical_unit": "independence_group",
        "pseudo_replication_guard": True,
        "repeat_handling": (
            "all cases and randomized repeats in one lineage must pass before "
            "the independence group counts as correct"
        ),
        "run_records": len(report["rows"]),
        "independence_groups": report["independence_groups"],
        "summaries": summaries,
        "paired_comparisons": comparisons,
        "new_case_diagnostics": new_case_diagnostics,
        "limitations": [
            "provider-oracle protocol pilot, not independent human gold",
            "only sixteen independence groups",
            "Holm correction spans all three budgets and three baselines",
            "perfect deterministic-reference accuracy is a contract sanity "
            "check and not evidence of population-level generalization",
        ],
    }


def render_markdown(analysis: dict[str, Any]) -> str:
    lines = [
        "# Provider-oracle protocol v8 results",
        "",
        "## Scope",
        "",
        (
            f"The pilot contains {analysis['run_records']} run records but "
            f"only **{analysis['independence_groups']} independent groups**. "
            "Events, cases from the same lineage, and repeated random seeds "
            "are not treated as independent samples."
        ),
        "",
        "## Group-level results",
        "",
        (
            "| Method | Budget | Correct groups | 95% CI | Unsafe "
            "false-Reachable | Mean query cost |"
        ),
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in analysis["summaries"]:
        low, high = item["protocol_correct_group_rate_ci95"]
        lines.append(
            f"| `{item['method_id']}` | {item['budget']} | "
            f"{item['protocol_correct_group_rate']:.3f} | "
            f"[{low:.3f}, {high:.3f}] | "
            f"{item['unsafe_false_reachable_group_rate']:.3f} | "
            f"{item['mean_group_query_cost']:.3f} |"
        )
    lines.extend([
        "",
        "A group is correct only when every provider-gold case is "
        "semantically correct and every epistemic control correctly abstains.",
        "",
        "## Paired exact comparisons",
        "",
        (
            "| Budget | Baseline | Primary wins | Baseline wins | Ties | "
            "Difference | Exact p | Holm p |"
        ),
        "|---:|---|---:|---:|---:|---:|---:|---:|",
    ])
    for item in analysis["paired_comparisons"]:
        lines.append(
            f"| {item['budget']} | `{item['baseline_method_id']}` | "
            f"{item['primary_wins']} | {item['baseline_wins']} | "
            f"{item['ties']} | "
            f"{item['paired_accuracy_difference']:.3f} | "
            f"{item['p_exact_mcnemar']:.4f} | "
            f"{item['p_holm_all_budget_baseline_comparisons']:.4f} |"
        )
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        (
            "The deterministic provider-aware method is expected to satisfy "
            "the frozen contract and therefore functions as a protocol sanity "
            "check. Its result is not an LLM effectiveness claim. The exact "
            "tests expose the limited number of independent groups, and the "
            "Holm correction prevents selecting a favorable budget after the "
            "fact."
        ),
        "",
        "The thesis main effectiveness claim still requires independent "
        "human-finalized gold and source-disjoint evaluation.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    analysis = analyze(report)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_markdown(analysis), encoding="utf-8")
    print(json.dumps({
        "run_records": analysis["run_records"],
        "independence_groups": analysis["independence_groups"],
        "paired_comparisons": len(analysis["paired_comparisons"]),
        "research_effectiveness_result": False,
        "report": str(args.report),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
