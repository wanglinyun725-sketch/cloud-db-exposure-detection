#!/usr/bin/env python3
"""Audit the real-source lineage pool without reading or generating gold."""
from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.lineage_admission_audit import audit_candidate_packet  # noqa: E402


PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)
OUTPUT = (
    ROOT
    / "output"
    / "research_design"
    / "lineage_admission_audit_v1.json"
)
REPORT = ROOT / "docs" / "lineage_admission_audit_v1.md"


def render_report(audit: dict) -> str:
    counts = audit["group_class_counts"]
    gap = audit["target_gap"]
    integrity = audit["integrity"]
    lines = [
        "# 真实谱系准入审计 v1",
        "",
        "状态：冻结前、label-blind 元数据审计。该报告没有生成或读取任何 gold 标签。",
        "",
        "## 结论",
        "",
        f"- 候选案例：{audit['case_count']}；独立谱系：{audit['independence_group_count']}。",
        f"- 可立即进入人工语义标注的运行时谱系：{audit['runtime_annotation_ready_groups']}。",
        f"- 静态材料、仍需运行时证据或 provider oracle：{counts.get('static_needs_runtime_or_provider_oracle', 0)}。",
        f"- 元数据或制品完整性阻断谱系：{counts.get('blocked_metadata_or_integrity', 0)}。",
        f"- 距 80 个操作目标仍缺 {gap['runtime_ready_gap_to_operational_target']} 个运行时/确定性 oracle 谱系；距 67 个确认性目标仍缺 {gap['runtime_ready_gap_to_confirmatory_target']} 个。",
        "",
        "候选数不能冒充 gold 数；同一谱系的多个 case、平台副本和重复运行均不增加统计 N。",
        "",
        "## 完整性",
        "",
        f"- 已核验唯一文件或压缩包成员引用：{integrity['verified_unique_refs']}。",
        f"- 含阻断项的案例：{integrity['case_blocker_count']}。",
        f"- 含阻断项的谱系：{integrity['group_blocker_count']}。",
        f"- 与其他谱系运行序列指纹碰撞、需人工近重复复核的谱系：{integrity['runtime_fingerprint_collision_group_count']}。",
        "",
        "## 可立即标注谱系分布",
        "",
        "### 平台",
        "",
        "| 平台 | 独立谱系数 |",
        "|---|---:|",
    ]
    for platform, count in audit[
        "runtime_ready_platform_group_counts"
    ].items():
        lines.append(f"| {platform} | {count} |")
    lines.extend([
        "",
        "一个跨云谱系可同时计入多个平台覆盖，但统计 N 仍只计一个谱系。",
        "",
        "### 来源",
        "",
        "| 来源 | 独立谱系数 |",
        "|---|---:|",
    ])
    for source_id, count in audit[
        "runtime_ready_source_group_counts"
    ].items():
        lines.append(f"| `{source_id}` | {count} |")
    lines.extend([
        "",
        "## 下一步准入规则",
        "",
        "1. 运行时 ready 谱系进入双人盲标队列，但仍需人工判断是否存在云数据目标、多步路径和关键边。",
        "2. 静态 C 级材料不得直接进入确认性测试；只有补齐供应商确定性配置结果、授权探针或公开运行时遥测后才能晋级。",
        "3. 跨组运行序列碰撞必须人工判断是否近重复；不得通过改 case ID 重复计数。",
        "4. 需要新增真实来源或执行隔离靶场，以补足确认性谱系，而不是用重复种子、平台副本或脚本生成样本填数。",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    audit = audit_candidate_packet(ROOT, packet)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT.write_text(render_report(audit), encoding="utf-8")
    print(json.dumps(
        {
            "groups": audit["independence_group_count"],
            "runtime_ready": audit["runtime_annotation_ready_groups"],
            "static_needs_evidence": audit["group_class_counts"].get(
                "static_needs_runtime_or_provider_oracle",
                0,
            ),
            "blocked": audit["integrity"]["group_blocker_count"],
            "report": str(REPORT.relative_to(ROOT)),
        },
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
