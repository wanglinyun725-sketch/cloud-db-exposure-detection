#!/usr/bin/env python3
"""Generate the pre-freeze statistical-power sensitivity report."""
from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.power_analysis import (  # noqa: E402
    exact_sign_power,
    minimum_groups_for_normal_power,
    minimum_groups_for_sign_power,
    normal_paired_power,
)


OUTPUT_JSON = ROOT / "output" / "research_design" / "power_analysis_v1.json"
OUTPUT_MD = ROOT / "docs" / "power_analysis_v1.md"
SAMPLE_SIZES = (30, 40, 50, 60, 67, 80)
EFFECTS_DZ = (0.35, 0.45, 0.50, 0.65)
SIGN_SCENARIOS = (
    {
        "name": "optimistic_pilot_like",
        "discordance_rate": 0.625,
        "treatment_win_share": 0.90,
    },
    {
        "name": "moderate",
        "discordance_rate": 0.50,
        "treatment_win_share": 0.75,
    },
    {
        "name": "conservative",
        "discordance_rate": 0.40,
        "treatment_win_share": 0.70,
    },
)


def build_report() -> dict:
    normal_rows = []
    for effect_dz in EFFECTS_DZ:
        row = {
            "effect_dz": effect_dz,
            "minimum_n_for_80pct_power": minimum_groups_for_normal_power(
                effect_dz
            ),
        }
        row["power_by_n"] = {
            str(n): normal_paired_power(n, effect_dz)
            for n in SAMPLE_SIZES
        }
        normal_rows.append(row)

    sign_rows = []
    for scenario in SIGN_SCENARIOS:
        discordance = scenario["discordance_rate"]
        win_share = scenario["treatment_win_share"]
        row = dict(scenario)
        row["minimum_n_for_80pct_power"] = minimum_groups_for_sign_power(
            discordance,
            win_share,
        )
        row["power_by_n"] = {
            str(n): exact_sign_power(n, discordance, win_share)
            for n in SAMPLE_SIZES
        }
        sign_rows.append(row)

    return {
        "status": "pre_freeze_sensitivity_analysis",
        "independent_unit": "attack_or_configuration_lineage",
        "alpha": 0.05,
        "sided": 2,
        "target_power": 0.80,
        "primary_endpoint_candidate": (
            "group-level fine-grained exact edge F1 difference: "
            "EC-ReAct minus vanilla ReAct at budget B=20"
        ),
        "normal_approximation": normal_rows,
        "exact_sign_sensitivity": sign_rows,
        "interpretation": {
            "pilot_limitation": (
                "The existing LLM pilot has three independent lineages and "
                "zero exact edge F1, so it cannot estimate a trustworthy "
                "paired variance for the thesis main study."
            ),
            "minimum_rule": (
                "Forty lineages is a data-governance floor, not automatic "
                "statistical adequacy. Final N is selected before freezing "
                "from the dev-only variance and this sensitivity table."
            ),
            "recommended_target": (
                "Aim for at least 80 accepted double-reviewed independent "
                "lineages, with at least 67 reserved for the confirmatory "
                "paired evaluation."
            ),
        },
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# 主实验统计功效敏感性分析 v1",
        "",
        "状态：冻结前规划，不是实验结果。",
        "",
        "独立统计单位是攻击/配置谱系。事件数、路径数、case 数和重复种子均不增加 N。",
        "",
        "现有 LLM pilot 只有 3 个独立谱系且 exact edge F1 为 0，无法可靠估计主实验的配对方差。因此本报告采用多情景敏感性分析，不把早期 pilot 包装成精确功效估计。",
        "",
        "## 连续路径指标：配对标准化效应",
        "",
        "候选主指标为预算 B=20 时，EC-ReAct 相对 vanilla ReAct 的 group-level fine-grained exact edge F1 配对差。表中为双侧 α=0.05 的正态近似功效；正式检验仍使用配对随机化检验和 group-cluster bootstrap。",
        "",
        "| 配对效应 dz | N=30 | N=40 | N=50 | N=60 | N=67 | N=80 | 80% 功效所需最小 N |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["normal_approximation"]:
        power = row["power_by_n"]
        lines.append(
            f"| {row['effect_dz']:.2f} | "
            f"{power['30']:.3f} | {power['40']:.3f} | "
            f"{power['50']:.3f} | {power['60']:.3f} | "
            f"{power['67']:.3f} | {power['80']:.3f} | "
            f"{row['minimum_n_for_80pct_power']} |"
        )

    lines.extend([
        "",
        "## 二元组级胜负：包含 ties 的精确 sign-test 情景",
        "",
        "discordance rate 表示两个方法在多少谱系上出现胜负而非打平；win share 是出现胜负时 EC-ReAct 获胜的比例。功效计算把 ties 保留在总样本量中。",
        "",
        "| 情景 | 非平局率 | EC 胜率（条件于非平局） | N=30 | N=40 | N=50 | N=60 | N=67 | N=80 | 80% 功效所需最小 N |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in report["exact_sign_sensitivity"]:
        power = row["power_by_n"]
        lines.append(
            f"| `{row['name']}` | {row['discordance_rate']:.3f} | "
            f"{row['treatment_win_share']:.3f} | "
            f"{power['30']:.3f} | {power['40']:.3f} | "
            f"{power['50']:.3f} | {power['60']:.3f} | "
            f"{power['67']:.3f} | {power['80']:.3f} | "
            f"{row['minimum_n_for_80pct_power']} |"
        )

    lines.extend([
        "",
        "## 决策",
        "",
        "- Goal 中的 40 个谱系只是数据治理最低线，不能自动解释为统计充分。",
        "- 操作目标提高为至少 80 个通过准入且完成双人复核的独立谱系，其中不少于 67 个保留给确认性配对评估。",
        "- 在冻结前只使用 dev/pilot 谱系估计配对差标准差；测试 gold 保持不可见。",
        "- 若只能获得 30 个确认性谱系，则对中等效应的功效可能不足，论文必须明确标注为限制。",
        "- 只设置一个确认性主指标，避免在多个预算和指标中挑选最有利结果；其他比较进入 Holm 校正的次要分析族。",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    report = build_report()
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    OUTPUT_MD.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(
        {
            "json": str(OUTPUT_JSON),
            "markdown": str(OUTPUT_MD),
            "recommended_lineages": 80,
            "confirmatory_lineages": 67,
        },
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
