#!/usr/bin/env python3
"""Audit the provenance-qualified 500-lineage development catalogue."""
from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = (
    Path(".")
    if Path("data/real_sources").is_dir() and Path("src/data").is_dir()
    else Path(__file__).resolve().parents[2]
)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.candidate_lineage_catalog import audit_candidate_catalog  # noqa: E402


CATALOG = ROOT / "data" / "real_sources" / "candidate_lineage_catalog_v1.json"
OUTPUT = ROOT / "output" / "research_design" / "candidate_lineage_500_status_v1.json"
REPORT = ROOT / "docs" / "candidate_lineage_500_status_v1.md"


def render(audit: dict) -> str:
    summary = audit["summary"]
    distributions = audit["accepted_distributions"]
    lines = [
        "# 500 个真实谱系扩充状态 v1",
        "",
        "本报告是来源与独立性硬门禁结果，不是攻击路径 Gold 评测结果。",
        "",
        "## 当前硬结果",
        "",
        f"- 已声明候选：{summary['declared_lineages']}。",
        f"- 通过全部机器门禁的独立候选谱系：{summary['accepted_independent_lineages']}。",
        f"- 距 500 个还差：{summary['gap_to_target']}。",
        f"- 已核验精确证据定位：{summary['verified_evidence_locators']}。",
        f"- Runtime/Oracle Gold：{summary['runtime_or_oracle_gold']}（候选绝不计作 Gold）。",
        "",
        "## 分层",
        "",
        "| 层级 | 通过数 |",
        "|---|---:|",
    ]
    for key, count in distributions["tiers"].items():
        lines.append(f"| `{key}` | {count} |")
    lines.extend(["", "## 云平台覆盖", "", "| 平台 | 通过数 |", "|---|---:|"])
    for key, count in distributions["platforms"].items():
        lines.append(f"| {key} | {count} |")
    lines.extend(["", "## 来源", "", "| 来源 | 通过数 |", "|---|---:|"])
    for key, count in distributions["sources"].items():
        lines.append(f"| `{key}` | {count} |")
    lines.extend([
        "",
        "## 尚未完成",
        "",
        "当前开发目录仅纳入 MITRE ATT&CK 和 Atomic Red Team 两个来源。其余已有固定来源与外部新来源必须逐一转换为同一证据合同，并完成跨来源近重复复核；达到 500 前，`target_passed` 必须保持 false。",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    audit = audit_candidate_catalog(ROOT, catalog)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT.write_text(render(audit), encoding="utf-8")
    print(json.dumps(audit["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
