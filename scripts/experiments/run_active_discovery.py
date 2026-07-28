#!/usr/bin/env python3
"""Evaluate active evidence acquisition without exposing truth attributes."""
from __future__ import annotations

import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.agent.active_investigator import (  # noqa: E402
    estimate_block_priors,
    investigate,
    total_candidate_query_cost,
    truth_has_valid_path,
)
from src.graph.constrained_search import constrained_dfs  # noqa: E402
from src.graph.gate_score import load_config  # noqa: E402
from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes  # noqa: E402


DATA = ROOT / "output" / "dataset_v1" / "dataset_v1_corpus.json"
OUT = ROOT / "output" / "active_discovery_results.json"
REPORT = ROOT / "output" / "active_discovery_report.md"
POLICIES = ["full_scan", "fixed_order", "impact_per_cost", "voi_per_cost", "random"]
BUDGET_RATIOS = [0.25, 0.50, 0.75, 1.00]


def main():
    samples = json.loads(DATA.read_text(encoding="utf-8"))
    config = load_config()
    validation_graphs = [
        build_graph(sample) for sample in samples if sample.get("split") == "validation"
    ]
    block_priors = estimate_block_priors(validation_graphs)

    heldout = [
        sample for sample in samples if sample.get("split") in {"test", "hard_test"}
    ]
    prepared, excluded = _prepare(heldout, config)
    full_budget_rows = _run_full_budget(prepared, block_priors)
    budget_sweep = _run_budget_sweep(prepared, block_priors)

    main_summary = {
        policy: _summarize([row["policies"][policy] for row in full_budget_rows])
        for policy in POLICIES
    }
    by_source = {}
    for source in sorted({row["source_dataset"] for row in full_budget_rows}):
        source_rows = [row for row in full_budget_rows if row["source_dataset"] == source]
        by_source[source] = {
            policy: _summarize([row["policies"][policy] for row in source_rows])
            for policy in POLICIES
        }

    statistical_tests = {
        "voi_vs_full_scan_cost": _group_permutation(
            full_budget_rows, "voi_per_cost", "full_scan", "spent"
        ),
        "voi_vs_fixed_order_cost": _group_permutation(
            full_budget_rows, "voi_per_cost", "fixed_order", "spent"
        ),
        "impact_vs_fixed_order_cost": _group_permutation(
            full_budget_rows, "impact_per_cost", "fixed_order", "spent"
        ),
    }

    output = {
        "protocol": {
            "data": str(DATA.relative_to(ROOT)).replace("\\", "/"),
            "prior_fit_split": "validation",
            "evaluation_splits": ["test", "hard_test"],
            "partial_observation": (
                "topology, node metadata, edge type and query cost visible; "
                "status, strength, confidence, timestamp and raw evidence hidden until query"
            ),
            "task_scope": (
                "sequential evidence verification conditioned on candidates generated "
                "by constrained DFS; not external real-world detection accuracy"
            ),
            "truth_definition": (
                "whether at least one generated candidate is Valid under the existing "
                "deterministic verifier on the fully observed graph"
            ),
            "budget_ratios": BUDGET_RATIOS,
            "random_seed": 17,
        },
        "sample_counts": {
            "heldout_samples": len(heldout),
            "evaluated_samples": len(prepared),
            "excluded_no_candidates": excluded,
            "independent_groups": len({item["sample"]["group_id"] for item in prepared}),
            "positive_candidate_pools": sum(item["truth_has_valid"] for item in prepared),
            "negative_candidate_pools": sum(not item["truth_has_valid"] for item in prepared),
        },
        "validation_block_priors": block_priors,
        "full_budget_summary": main_summary,
        "budget_sweep": budget_sweep,
        "by_source": by_source,
        "group_aware_statistical_tests": statistical_tests,
        "sample_results": full_budget_rows,
    }
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT.write_text(_render_report(output), encoding="utf-8")
    print(json.dumps({k: v for k, v in output.items() if k != "sample_results"}, ensure_ascii=False, indent=2))
    print(f"wrote {OUT}")
    print(f"wrote {REPORT}")


def _prepare(samples, config):
    prepared = []
    excluded = 0
    min_depth = config["search"]["min_depth"]
    max_depth = config["search"]["max_depth"]
    for sample in samples:
        graph = build_graph(sample)
        paths = constrained_dfs(
            graph,
            get_entry_nodes(graph),
            get_target_nodes(graph),
            min_depth,
            max_depth,
        )
        if not paths:
            excluded += 1
            continue
        prepared.append(
            {
                "sample": sample,
                "graph": graph,
                "paths": paths,
                "truth_has_valid": truth_has_valid_path(graph, paths),
                "full_cost": total_candidate_query_cost(graph, paths),
            }
        )
    return prepared, excluded


def _run_full_budget(prepared, priors):
    rows = []
    for item in prepared:
        row = {
            "sample_id": item["sample"]["sample_id"],
            "group_id": item["sample"]["group_id"],
            "split": item["sample"]["split"],
            "source_dataset": item["sample"]["source_dataset"],
            "variant_type": item["sample"].get("variant_type", "base"),
            "candidate_paths": len(item["paths"]),
            "truth_has_valid": item["truth_has_valid"],
            "available_query_cost": item["full_cost"],
            "policies": {},
        }
        for policy in POLICIES:
            result = investigate(
                item["graph"],
                item["paths"],
                policy=policy,
                budget=item["full_cost"],
                seed=17,
                block_priors=priors,
            )
            packed = result.to_dict()
            packed["correct"] = result.predicted_has_valid == item["truth_has_valid"]
            row["policies"][policy] = packed
        rows.append(row)
    return rows


def _run_budget_sweep(prepared, priors):
    sweep = {}
    for ratio in BUDGET_RATIOS:
        policy_rows = defaultdict(list)
        for item in prepared:
            budget = max(1, math.floor(item["full_cost"] * ratio))
            for policy in POLICIES:
                result = investigate(
                    item["graph"],
                    item["paths"],
                    policy=policy,
                    budget=budget,
                    seed=17,
                    block_priors=priors,
                )
                policy_rows[policy].append(
                    {
                        **result.to_dict(),
                        "correct": result.predicted_has_valid == item["truth_has_valid"],
                        "truth_has_valid": item["truth_has_valid"],
                    }
                )
        sweep[f"{ratio:.2f}"] = {
            policy: _summarize(rows) for policy, rows in policy_rows.items()
        }
    return sweep


def _summarize(rows):
    n = len(rows)
    positives = [row for row in rows if row.get("truth_has_valid", False)]
    negatives = [row for row in rows if not row.get("truth_has_valid", False)]
    # Full-budget sample rows do not repeat truth inside the policy dict.
    if rows and "truth_has_valid" not in rows[0]:
        positives = []
        negatives = []
    return {
        "n": n,
        "decision_accuracy": _mean(row["correct"] for row in rows),
        "abstention_rate": _mean(
            row["decision"] in {"budget_exhausted", "insufficient_evidence"}
            for row in rows
        ),
        "avg_query_cost": _mean(row["spent"] for row in rows),
        "avg_tool_calls": _mean(row["tool_calls"] for row in rows),
        "positive_accuracy": _mean(row["correct"] for row in positives) if positives else None,
        "negative_accuracy": _mean(row["correct"] for row in negatives) if negatives else None,
        "avg_certificate_size": _mean(len(row["certificate_edge_ids"]) for row in rows),
    }


def _group_permutation(rows, treatment, baseline, metric, repetitions=50000):
    grouped = defaultdict(list)
    for row in rows:
        difference = (
            row["policies"][treatment][metric] - row["policies"][baseline][metric]
        )
        grouped[row["group_id"]].append(difference)
    group_differences = [sum(values) / len(values) for values in grouped.values()]
    observed = sum(group_differences) / len(group_differences)
    rng = random.Random(20260726)
    extreme = 0
    for _ in range(repetitions):
        permuted = sum(
            difference if rng.random() < 0.5 else -difference
            for difference in group_differences
        ) / len(group_differences)
        extreme += abs(permuted) >= abs(observed) - 1e-12
    return {
        "treatment_minus_baseline": round(observed, 4),
        "independent_groups": len(group_differences),
        "paired_group_sign_flip_p": round((extreme + 1) / (repetitions + 1), 6),
        "repetitions": repetitions,
    }


def _mean(values):
    values = list(values)
    return round(sum(values) / max(len(values), 1), 4)


def _render_report(result):
    counts = result["sample_counts"]
    summary = result["full_budget_summary"]
    tests = result["group_aware_statistical_tests"]
    sweep = result["budget_sweep"]

    def pct(value):
        return f"{100 * value:.1f}%"

    lines = [
        "# 主动证据发现第一轮实验报告",
        "",
        "## 结论先行",
        "",
        "本轮已经把“Agent 主动发现证据链路”从完整图上的一次性打分，改成了",
        "真实的部分可观测序贯取证：证据状态、强度、时间与原始证据在查询前不可见，",
        "Agent 每次只能选择一条边调用工具，消耗预算，并在找到有效路径、形成否定",
        "证书或预算耗尽时停止。",
        "",
        "闭环已经成立，但实验不支持夸大算法优势。验证集拟合的 VOI/cost 策略在满预算",
        "下相对全量查询显著节省开销；相对固定顺序只略有节省，优势很小。单纯的",
        "coverage/cost 启发式反而更贵。因此当前可以把“主动取证机制”作为已实现贡献，",
        "但不能把现有策略写成已经全面优于强基线的新算法。",
        "",
        "## 实验口径",
        "",
        f"- 评估样本：test + hard_test 共 {counts['heldout_samples']} 个；"
        f"{counts['evaluated_samples']} 个存在结构候选路径，来自 "
        f"{counts['independent_groups']} 个独立样本组。",
        f"- 正/负候选池：{counts['positive_candidate_pools']} / "
        f"{counts['negative_candidate_pools']}。",
        "- blocker 概率只在 validation split 估计，test/hard_test 不参与策略拟合。",
        "- 这里评价的是“给定结构候选后的取证效率与停止正确性”，不是外部真实云环境",
        "  的攻击检测准确率。",
        "",
        "## 满预算结果",
        "",
        "| 策略 | 决策正确率 | 平均查询成本 | 平均工具调用 | 平均证书边数 |",
        "|---|---:|---:|---:|---:|",
    ]
    names = {
        "full_scan": "全量查询",
        "fixed_order": "固定顺序",
        "impact_per_cost": "Coverage/Cost",
        "voi_per_cost": "验证集 VOI/Cost",
        "random": "随机顺序",
    }
    for policy in POLICIES:
        row = summary[policy]
        lines.append(
            f"| {names[policy]} | {pct(row['decision_accuracy'])} | "
            f"{row['avg_query_cost']:.3f} | {row['avg_tool_calls']:.3f} | "
            f"{row['avg_certificate_size']:.3f} |"
        )
    full = summary["full_scan"]["avg_query_cost"]
    voi = summary["voi_per_cost"]["avg_query_cost"]
    fixed = summary["fixed_order"]["avg_query_cost"]
    lines.extend(
        [
            "",
            f"VOI/Cost 相对全量查询减少 {pct((full - voi) / full)} 的平均查询成本；"
            f"相对固定顺序只减少 {pct((fixed - voi) / fixed)}。",
            "",
            "## 预算—正确性曲线",
            "",
            "| 可用预算 | 固定顺序 | Coverage/Cost | VOI/Cost | 随机 |",
            "|---:|---:|---:|---:|---:|",
        ]
    )
    for ratio in BUDGET_RATIOS:
        row = sweep[f"{ratio:.2f}"]
        lines.append(
            f"| {pct(ratio)} | {pct(row['fixed_order']['decision_accuracy'])} | "
            f"{pct(row['impact_per_cost']['decision_accuracy'])} | "
            f"{pct(row['voi_per_cost']['decision_accuracy'])} | "
            f"{pct(row['random']['decision_accuracy'])} |"
        )
    lines.extend(
        [
            "",
            "低预算下的正确率主要来自快速排除负样本；25% 预算时，各策略对正样本",
            "均无法完成一条有效路径证书。因此不能只报告总体正确率，论文中必须同时",
            "报告 valid discovery recall、correct rejection 和 abstention。",
            "",
            "## 核心公式",
            "",
            "对当前仍可行的候选集合 $\\mathcal{F}_t$，定义查询边 $e$ 的估计价值为：",
            "",
            "$$",
            "\\operatorname{VOI}_t(e)=",
            "\\frac{\\hat p_{\\mathrm{block}}(\\tau_e)N_{\\mathrm{prune}}(e)",
            "+[1-\\hat p_{\\mathrm{block}}(\\tau_e)]N_{\\mathrm{complete}}(e)}{c(e)}.",
            "$$",
            "",
            "其中 blocker 先验按边类型在 validation 上做 Beta(1,1) 平滑估计；",
            "$N_{\\mathrm{prune}}$ 是查询后可能被一次排除的候选数，",
            "$N_{\\mathrm{complete}}$ 是只差该证据即可完成证书的候选数。",
            "该策略不读取查询前隐藏的真实状态。",
            "",
            "## 组级统计检验",
            "",
            "| 对比（查询成本，前者−后者） | 组级均值差 | p 值 |",
            "|---|---:|---:|",
            f"| VOI/Cost − 全量查询 | "
            f"{tests['voi_vs_full_scan_cost']['treatment_minus_baseline']:.4f} | "
            f"{tests['voi_vs_full_scan_cost']['paired_group_sign_flip_p']:.6f} |",
            f"| VOI/Cost − 固定顺序 | "
            f"{tests['voi_vs_fixed_order_cost']['treatment_minus_baseline']:.4f} | "
            f"{tests['voi_vs_fixed_order_cost']['paired_group_sign_flip_p']:.6f} |",
            f"| Coverage/Cost − 固定顺序 | "
            f"{tests['impact_vs_fixed_order_cost']['treatment_minus_baseline']:.4f} | "
            f"{tests['impact_vs_fixed_order_cost']['paired_group_sign_flip_p']:.6f} |",
            "",
            "置换以 group 为独立单元，避免把同一基础样本的 missing/refuted/temporal",
            "变体当成独立观测。",
            "",
            "## 客观判断与下一轮",
            "",
            "1. PPT 中“局部信号—动态取证—更新证据状态—停止/剪枝”的机制现在有了",
            "   对应代码、动作轨迹、预算和停止证书，不再只是流程图。",
            "2. 当前最好结果更多证明“有必要做主动查询”，还没有证明一个强的新策略。",
            "3. 下一轮应把单一标量策略升级成召回—成本 Pareto 策略，并在独立人工标注",
            "   外部案例上评估；不要再用同图衍生变体强化结论。",
            "4. Gate·Score 应只负责已验证路径的风险严重度排序，不再承担路径真伪证明。",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
