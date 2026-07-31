#!/usr/bin/env python3
"""Compare the frozen v8 local-LLM pilot with its scope-guard replication."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import statistics
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BEFORE = (
    ROOT / "output" / "provider_oracle_llm_pilot_v8_new_cases"
    / "results_finalized_full_grid.json"
)
DEFAULT_AFTER = (
    ROOT / "output" / "provider_oracle_llm_pilot_v8_1_scope_guard"
    / "results_finalized_full_grid.json"
)
DEFAULT_JSON = (
    ROOT / "output" / "provider_oracle_llm_pilot_v8_scope_analysis.json"
)
DEFAULT_REPORT = ROOT / "docs" / "local_llm_pilot_v8_results.md"
FULL_LINEAR = "ec_react_full_linear"
FULL_LANGGRAPH = "ec_react_full_langgraph"
VANILLA = "vanilla_react_linear"


def _mean(values) -> float:
    materialized = list(values)
    return statistics.fmean(materialized) if materialized else 0.0


def _exact_mcnemar(wins: int, losses: int) -> float:
    discordant = wins + losses
    if discordant == 0:
        return 1.0
    tail = sum(
        math.comb(discordant, index)
        for index in range(min(wins, losses) + 1)
    ) / (2 ** discordant)
    return min(1.0, 2 * tail)


def _protocol_correct(score: dict[str, Any]) -> bool:
    if score["provider_oracle_gold"]:
        return bool(score["semantically_correct_state"])
    return bool(score["correct_abstention"])


def _collapse_groups(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[(row["method_id"], row["independence_group"])].append(row)
    collapsed: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for (method_id, group), group_rows in buckets.items():
        collapsed[method_id][group] = {
            "protocol_correct": all(
                _protocol_correct(row["score"]) for row in group_rows
            ),
            "false_reachable": any(
                row["score"]["false_reachable"] for row in group_rows
            ),
            "run_count": len(group_rows),
        }
    return dict(collapsed)


def _coordinate(row: dict[str, Any]) -> tuple[str, str, int, int]:
    return (
        row["case_id"],
        row["method_id"],
        int(row["repeat"]),
        int(row["seed"]),
    )


def _validate_pair(
    before: dict[str, Any],
    after: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    for label, report in (("before", before), ("after", after)):
        if report.get("protocol_version") != "8.0-pilot":
            raise ValueError(f"{label} report is not protocol v8")
        if not report.get("schedule_complete"):
            raise ValueError(f"{label} schedule is incomplete")
        conflicts = report.get("duplicate_semantic_conflicts")
        conflict_count = (
            len(conflicts) if isinstance(conflicts, list)
            else int(conflicts or 0)
        )
        if conflict_count:
            raise ValueError(f"{label} contains semantic duplicate conflicts")
    before_rows = before["rows"]
    after_rows = after["rows"]
    before_coordinates = {_coordinate(row) for row in before_rows}
    after_coordinates = {_coordinate(row) for row in after_rows}
    if before_coordinates != after_coordinates:
        raise ValueError("pre/post reports do not have the same run grid")
    if (
        set(before.get("model_digest_values") or [])
        != set(after.get("model_digest_values") or [])
    ):
        raise ValueError("pre/post reports use different model digests")
    return before_rows, after_rows


def _paired_counts(
    primary: dict[str, dict[str, Any]],
    comparator: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    common = sorted(set(primary) & set(comparator))
    wins = sum(
        primary[group]["protocol_correct"]
        and not comparator[group]["protocol_correct"]
        for group in common
    )
    losses = sum(
        comparator[group]["protocol_correct"]
        and not primary[group]["protocol_correct"]
        for group in common
    )
    return {
        "paired_independence_groups": len(common),
        "primary_wins": wins,
        "comparator_wins": losses,
        "ties": len(common) - wins - losses,
        "p_exact_mcnemar": _exact_mcnemar(wins, losses),
    }


def analyze(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    before_rows, after_rows = _validate_pair(before, after)
    before_groups = _collapse_groups(before_rows)
    after_groups = _collapse_groups(after_rows)

    method_summaries = []
    pre_post_comparisons = []
    for method_id in sorted(after_groups):
        groups_after = after_groups[method_id]
        groups_before = before_groups[method_id]
        method_summaries.append({
            "method_id": method_id,
            "independence_groups": len(groups_after),
            "before_correct_group_rate": _mean(
                item["protocol_correct"] for item in groups_before.values()
            ),
            "after_correct_group_rate": _mean(
                item["protocol_correct"] for item in groups_after.values()
            ),
            "before_false_reachable_group_rate": _mean(
                item["false_reachable"] for item in groups_before.values()
            ),
            "after_false_reachable_group_rate": _mean(
                item["false_reachable"] for item in groups_after.values()
            ),
            "before_mean_latency_seconds": _mean(
                row["latency_seconds"]
                for row in before_rows if row["method_id"] == method_id
            ),
            "after_mean_latency_seconds": _mean(
                row["latency_seconds"]
                for row in after_rows if row["method_id"] == method_id
            ),
        })
        comparison = _paired_counts(groups_after, groups_before)
        comparison["method_id"] = method_id
        pre_post_comparisons.append(comparison)

    case_buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for phase, rows in (("before", before_rows), ("after", after_rows)):
        for row in rows:
            case_buckets[(phase, row["method_id"], row["case_id"])].append(
                row
            )
    case_diagnostics = []
    for phase, method_id, case_id in sorted(case_buckets):
        rows = case_buckets[(phase, method_id, case_id)]
        case_diagnostics.append({
            "phase": phase,
            "method_id": method_id,
            "case_id": case_id,
            "runs": len(rows),
            "prediction_counts": dict(sorted(Counter(
                row["score"]["predicted_state"] for row in rows
            ).items())),
            "protocol_correct_runs": sum(
                _protocol_correct(row["score"]) for row in rows
            ),
            "false_reachable_runs": sum(
                row["score"]["false_reachable"] for row in rows
            ),
            "invalid_actions": sum(
                row["result"]["invalid_actions"] for row in rows
            ),
        })

    after_by_method_coordinate = {
        (
            row["method_id"],
            row["case_id"],
            int(row["repeat"]),
            int(row["seed"]),
        ): row
        for row in after_rows
    }
    backend_pairs = []
    for key, linear in sorted(after_by_method_coordinate.items()):
        method_id, case_id, repeat, seed = key
        if method_id != FULL_LINEAR:
            continue
        graph = after_by_method_coordinate[
            (FULL_LANGGRAPH, case_id, repeat, seed)
        ]
        backend_pairs.append({
            "case_id": case_id,
            "repeat": repeat,
            "seed": seed,
            "predicted_state_match": (
                linear["score"]["predicted_state"]
                == graph["score"]["predicted_state"]
            ),
            "semantic_score_match": (
                linear["score"]["semantically_correct_state"]
                == graph["score"]["semantically_correct_state"]
            ),
            "decision_match": (
                linear["result"]["decision"] == graph["result"]["decision"]
            ),
        })

    full_vs_vanilla = _paired_counts(
        after_groups[FULL_LINEAR],
        after_groups[VANILLA],
    )
    return {
        "analysis_version": "local-llm-v8-scope-replication-v1",
        "protocol_version": "8.0-pilot",
        "research_effectiveness_result": False,
        "diagnostic_replication": True,
        "statistical_unit": "independence_group",
        "pseudo_replication_guard": True,
        "same_run_grid": True,
        "same_model_digest": True,
        "before_raw_records": before["raw_jsonl_records"],
        "before_unique_runs": before["unique_completed_runs"],
        "before_duplicates_ignored": before["duplicate_records_ignored"],
        "after_raw_records": after["raw_jsonl_records"],
        "after_unique_runs": after["unique_completed_runs"],
        "after_duplicates_ignored": after["duplicate_records_ignored"],
        "independence_groups": after["independence_groups"],
        "method_summaries": method_summaries,
        "pre_post_group_comparisons": pre_post_comparisons,
        "case_diagnostics": case_diagnostics,
        "backend_equivalence": {
            "paired_runs": len(backend_pairs),
            "predicted_state_mismatches": sum(
                not item["predicted_state_match"] for item in backend_pairs
            ),
            "semantic_score_mismatches": sum(
                not item["semantic_score_match"] for item in backend_pairs
            ),
            "decision_mismatches": sum(
                not item["decision_match"] for item in backend_pairs
            ),
        },
        "full_vs_vanilla_group_comparison": full_vs_vanilla,
        "limitations": [
            "post-hoc diagnostic replication, not a preregistered main result",
            "only three independent lineages in this four-case subset",
            "three seeds test stability but are not independent samples",
            "provider-oracle labels and epistemic controls are not human gold",
            "the local seven-billion-parameter model is a reproducible systems "
            "probe, not evidence about all LLMs",
        ],
    }


def _diagnostic_lookup(
    analysis: dict[str, Any],
    phase: str,
    method_id: str,
    case_suffix: str,
) -> dict[str, Any]:
    return next(
        item for item in analysis["case_diagnostics"]
        if item["phase"] == phase
        and item["method_id"] == method_id
        and item["case_id"].endswith(case_suffix)
    )


def render_markdown(analysis: dict[str, Any]) -> str:
    lines = [
        "# Local Qwen2.5-7B protocol-v8 diagnostic",
        "",
        "## What this experiment is",
        "",
        (
            "The frozen v8 pilot exposed a method defect: compact tool results "
            "hid `scope_completeness`, while the dynamic policy schema treated "
            "every provider `allow` as end-to-end reachability. The v8.1 run "
            "keeps the same model digest, cases, seeds, budget, and methods, "
            "but exposes public oracle scope and rejects incomplete provider "
            "outcomes as path certificates. The v8 result is retained rather "
            "than overwritten."
        ),
        "",
        "This is a **post-hoc diagnostic replication**, not a frozen thesis "
        "effectiveness result.",
        "",
        "## Independence-aware result",
        "",
        (
            "| Method | Groups | Correct before | Correct after | "
            "False-Reachable before | False-Reachable after | "
            "Latency before (s) | Latency after (s) |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in analysis["method_summaries"]:
        lines.append(
            f"| `{item['method_id']}` | {item['independence_groups']} | "
            f"{item['before_correct_group_rate']:.3f} | "
            f"{item['after_correct_group_rate']:.3f} | "
            f"{item['before_false_reachable_group_rate']:.3f} | "
            f"{item['after_false_reachable_group_rate']:.3f} | "
            f"{item['before_mean_latency_seconds']:.2f} | "
            f"{item['after_mean_latency_seconds']:.2f} |"
        )
    lines.extend([
        "",
        "Group correctness is deliberately strict:",
        "",
        (
            r"$$C_{m,g}=\bigwedge_{r\in g}\left["
            r"\mathbb{1}_{gold}(r)S_r + "
            r"\mathbb{1}_{control}(r)A_r\right],$$"
        ),
        "",
        "where $S_r$ is semantic state correctness and $A_r$ is correct "
        "Unknown abstention. Repeated seeds and related cases never increase "
        "the sample size.",
        "",
        "## Pre/post paired diagnostic",
        "",
        "| Method | Corrected groups | Regressed groups | Ties | Exact p |",
        "|---|---:|---:|---:|---:|",
    ])
    for item in analysis["pre_post_group_comparisons"]:
        lines.append(
            f"| `{item['method_id']}` | {item['primary_wins']} | "
            f"{item['comparator_wins']} | {item['ties']} | "
            f"{item['p_exact_mcnemar']:.4f} |"
        )
    lines.extend([
        "",
        (
            "The two-sided exact paired value uses "
            r"$p=2\sum_{k=0}^{\min(b,c)}\binom{b+c}{k}2^{-(b+c)}$."
        ),
        "With only three lineages it is descriptive; a non-significant value "
        "does not negate the directly reproduced software defect.",
        "",
        "## Unknown-control behavior",
        "",
        "| Method | Case | Before | After |",
        "|---|---|---:|---:|",
    ])
    for method_id in (FULL_LINEAR, FULL_LANGGRAPH, VANILLA):
        for suffix, label in (
            ("rds-password-reset-without-query", "RDS password reset"),
            (
                "s3-acl-without-effective-access-control",
                "S3 ACL change",
            ),
        ):
            before = _diagnostic_lookup(
                analysis, "before", method_id, suffix
            )
            after = _diagnostic_lookup(
                analysis, "after", method_id, suffix
            )
            lines.append(
                f"| `{method_id}` | {label} | "
                f"`{before['prediction_counts']}` | "
                f"`{after['prediction_counts']}` |"
            )
    backend = analysis["backend_equivalence"]
    comparison = analysis["full_vs_vanilla_group_comparison"]
    lines.extend([
        "",
        "## LangGraph result",
        "",
        (
            f"Across {backend['paired_runs']} matched case-seed runs, linear "
            f"and LangGraph had {backend['predicted_state_mismatches']} state, "
            f"{backend['semantic_score_mismatches']} semantic-score, and "
            f"{backend['decision_mismatches']} runner-decision mismatches."
        ),
        "",
        "Therefore LangGraph is an implementation/orchestration choice here, "
        "not an accuracy innovation. Any latency difference is descriptive.",
        "",
        "## Full method versus vanilla ReAct",
        "",
        (
            f"At the independence-group level the full method wins "
            f"{comparison['primary_wins']}, vanilla wins "
            f"{comparison['comparator_wins']}, and "
            f"{comparison['ties']} groups tie "
            f"(exact p={comparison['p_exact_mcnemar']:.4f})."
        ),
        "",
        "## Audit boundary",
        "",
        (
            f"The original JSONL had {analysis['before_raw_records']} records "
            f"for {analysis['before_unique_runs']} unique coordinates; "
            f"{analysis['before_duplicates_ignored']} duplicate resume records "
            "were ignored after semantic-conflict checking. The replication "
            f"had {analysis['after_raw_records']} records for "
            f"{analysis['after_unique_runs']} unique coordinates and "
            f"{analysis['after_duplicates_ignored']} ignored duplicates."
        ),
        "",
        "Limitations:",
        "",
    ])
    lines.extend(f"- {item}" for item in analysis["limitations"])
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", type=Path, default=DEFAULT_BEFORE)
    parser.add_argument("--after", type=Path, default=DEFAULT_AFTER)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    before = json.loads(args.before.read_text(encoding="utf-8"))
    after = json.loads(args.after.read_text(encoding="utf-8"))
    result = analyze(before, after)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps({
        "analysis": str(args.json_output),
        "report": str(args.report),
        "independence_groups": result["independence_groups"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
