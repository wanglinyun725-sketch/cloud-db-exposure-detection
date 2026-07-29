#!/usr/bin/env python3
"""Freeze all integrity-passing runtime lineages into a label-empty queue."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.lineage_admission_audit import audit_candidate_packet  # noqa: E402


BASE_PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)
OUTPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_ready_queue_v1_unlabeled.json"
)
REPORT = ROOT / "docs" / "runtime_annotation_queue_v1.md"
LABEL_FIELDS = (
    "nodes",
    "edges",
    "path_labels",
    "tool_tasks",
    "instance_labels",
)


def _file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _group(case: dict[str, Any]) -> str:
    value = (case.get("candidate_metadata") or {}).get(
        "independence_group"
    )
    if not isinstance(value, str) or not value:
        raise ValueError(f"{case.get('case_id')} lacks independence_group")
    return value


def _assert_unlabeled(case: dict[str, Any]) -> None:
    annotation = case.get("annotation") or {}
    if (
        annotation.get("status") != "pending"
        or annotation.get("label_origin") is not None
    ):
        raise ValueError(f"{case.get('case_id')} is not label-empty")
    if any(case.get(field) for field in LABEL_FIELDS):
        raise ValueError(f"{case.get('case_id')} contains graph labels")
    screen = case.get("admission_screen") or {}
    if any(value is not None for value in screen.values()):
        raise ValueError(
            f"{case.get('case_id')} contains admission labels"
        )


def build_queue(
    root: Path = ROOT,
    base_packet_path: Path = BASE_PACKET,
) -> dict[str, Any]:
    base_packet_path = base_packet_path.resolve()
    packet = json.loads(base_packet_path.read_text(encoding="utf-8"))
    audit = audit_candidate_packet(root, packet)
    ready_rows = [
        row for row in audit["groups"]
        if row["admission_class"] == "runtime_annotation_ready"
    ]
    ready_groups = {
        row["independence_group"] for row in ready_rows
    }
    selected = [
        deepcopy(case)
        for case in packet["cases"]
        if _group(case) in ready_groups
    ]
    selected_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    base_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in packet["cases"]:
        base_by_group[_group(case)].append(case)
    for case in selected:
        _assert_unlabeled(case)
        selected_by_group[_group(case)].append(case)
    if set(selected_by_group) != ready_groups:
        raise ValueError("runtime-ready group selection is incomplete")
    for group_id in ready_groups:
        base_ids = {
            case["case_id"] for case in base_by_group[group_id]
        }
        selected_ids = {
            case["case_id"] for case in selected_by_group[group_id]
        }
        if selected_ids != base_ids:
            raise ValueError(
                f"partial independence group selected: {group_id}"
            )

    selected.sort(key=lambda case: case["case_id"])
    instances = [
        instance
        for case in selected
        for instance in case["runtime_instances"]
    ]
    source_case_counts = Counter(
        case["source"]["source_id"] for case in selected
    )
    source_group_counts: Counter[str] = Counter()
    for group_cases in selected_by_group.values():
        for source_id in {
            case["source"]["source_id"] for case in group_cases
        }:
            source_group_counts[source_id] += 1
    platform_instance_counts = Counter(
        str(instance.get("platform") or "").upper()
        for instance in instances
    )
    observation_count = sum(
        int(instance.get("observation_count") or 0)
        for instance in instances
    )
    collision_groups = sorted(
        row["independence_group"]
        for row in ready_rows
        if (
            "runtime_sequence_collides_with_another_independence_group"
            in row["warnings"]
        )
    )
    selected_case_ids = [
        case["case_id"] for case in selected
    ]
    selected_group_ids = sorted(ready_groups)
    return {
        "packet_version": "1.0",
        "packet_kind": "runtime_ready_annotation_queue_unlabeled",
        "protocol_status": "frozen_before_human_labels",
        "policy": {
            "generated_labels": 0,
            "selection_before_human_labels": True,
            "selection_uses_gold": False,
            "complete_independence_groups_only": True,
            "two_independent_humans_required": True,
            "third_human_adjudication_for_disputes": True,
            "collision_groups_require_near_duplicate_review": True,
        },
        "base_packet": {
            "path": str(base_packet_path.relative_to(root)).replace(
                "\\", "/"
            ),
            "sha256": _file_sha256(base_packet_path),
        },
        "selection": {
            "rule": (
                "all groups classified runtime_annotation_ready by "
                "label-blind lineage admission audit v1"
            ),
            "audit_version": audit["audit_version"],
            "selected_case_ids": selected_case_ids,
            "selected_case_ids_sha256": _stable_hash(
                selected_case_ids
            ),
            "selected_independence_groups": selected_group_ids,
            "selected_independence_groups_sha256": _stable_hash(
                selected_group_ids
            ),
            "near_duplicate_review_required_groups": collision_groups,
        },
        "summary": {
            "case_count": len(selected),
            "independence_group_count": len(selected_by_group),
            "runtime_instance_count": len(instances),
            "observation_count": observation_count,
            "source_count": len(source_group_counts),
            "source_case_counts": dict(sorted(
                source_case_counts.items()
            )),
            "source_group_counts": dict(sorted(
                source_group_counts.items()
            )),
            "platform_instance_counts": dict(sorted(
                platform_instance_counts.items()
            )),
            "human_gold_cases": 0,
            "human_gold_independence_groups": 0,
        },
        "schema_ref": packet["schema_ref"],
        "cases": selected,
    }


def render_report(queue: dict[str, Any]) -> str:
    summary = queue["summary"]
    collision_groups = queue["selection"][
        "near_duplicate_review_required_groups"
    ]
    lines = [
        "# 运行时谱系双人标注队列 v1",
        "",
        "该队列在任何人工标签产生前冻结，选择过程只读取来源、哈希、运行时实例和独立谱系元数据，不读取或生成 gold。",
        "",
        "## 规模",
        "",
        f"- 案例：{summary['case_count']}",
        f"- 独立谱系：{summary['independence_group_count']}",
        f"- 运行时实例：{summary['runtime_instance_count']}",
        f"- 原始观测：{summary['observation_count']}",
        f"- 独立运行时来源：{summary['source_count']}",
        f"- human gold：{summary['human_gold_independence_groups']}",
        "",
        "## 来源分布",
        "",
        "| 来源 | 案例 | 独立谱系 |",
        "|---|---:|---:|",
    ]
    for source_id, group_count in summary[
        "source_group_counts"
    ].items():
        lines.append(
            f"| `{source_id}` | "
            f"{summary['source_case_counts'][source_id]} | "
            f"{group_count} |"
        )
    lines.extend([
        "",
        "## 平台实例分布",
        "",
        "| 平台 | 运行时实例 |",
        "|---|---:|",
    ])
    for platform, count in summary[
        "platform_instance_counts"
    ].items():
        lines.append(f"| {platform} | {count} |")
    lines.extend([
        "",
        "## 人工流程",
        "",
        "1. 两位真实标注者必须从同一无标签队列分别创建 assignment，彼此不可见。",
        "2. 每位标注者独立回答五项准入问题，并为接受案例标注 canonical 节点、边、路径和证据。",
        "3. 系统计算原始一致率、Cohen's kappa/其他适用一致性指标。",
        "4. 只对分歧案例创建第三人仲裁任务。",
        "5. 标注提交必须包含 human attestation；LLM、AI assistant 或模型身份不能登记为标注者。",
        "",
        "## 必须人工复核的近重复风险",
        "",
    ])
    if collision_groups:
        lines.extend(f"- `{group_id}`" for group_id in collision_groups)
    else:
        lines.append("- 无")
    lines.extend([
        "",
        "运行序列指纹碰撞只触发复核，不自动判为重复，也不自动赋予任何标签。",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    queue = build_queue()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(queue, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT.write_text(render_report(queue), encoding="utf-8")
    print(json.dumps(queue["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
