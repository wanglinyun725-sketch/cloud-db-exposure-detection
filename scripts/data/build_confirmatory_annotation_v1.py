#!/usr/bin/env python3
"""Freeze the conservative 30-lineage double-human annotation packet."""
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


INPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_ready_queue_v1_unlabeled.json"
)
OUTPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_confirmatory_30_unlabeled.json"
)
REPORT = ROOT / "docs" / "confirmatory_annotation_v1.md"
LABEL_ARRAYS = (
    "nodes",
    "edges",
    "path_labels",
    "tool_tasks",
    "instance_labels",
)


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _group(case: dict[str, Any]) -> str:
    return case["candidate_metadata"]["independence_group"]


def _assert_unlabeled(case: dict[str, Any]) -> None:
    annotation = case.get("annotation") or {}
    screen = case.get("admission_screen") or {}
    if (
        annotation.get("status") != "pending"
        or annotation.get("label_origin") is not None
        or any(case.get(field) for field in LABEL_ARRAYS)
        or any(value is not None for value in screen.values())
    ):
        raise ValueError(f"{case.get('case_id')} is not label-empty")


def build_packet(
    root: str | Path = ROOT,
    input_path: str | Path = INPUT,
) -> dict[str, Any]:
    root = Path(root).resolve()
    input_path = Path(input_path).resolve()
    source = json.loads(input_path.read_text(encoding="utf-8"))
    collision_groups = set(
        source["selection"]["near_duplicate_review_required_groups"]
    )
    all_groups = set(source["selection"]["selected_independence_groups"])
    selected_groups = all_groups - collision_groups
    if len(all_groups) != 32 or len(collision_groups) != 2:
        raise ValueError(
            "runtime queue no longer matches the preregistered 32-minus-2 "
            "selection rule"
        )
    if len(selected_groups) != 30:
        raise ValueError("confirmatory packet must contain 30 lineages")

    base_by_group: dict[str, list[str]] = defaultdict(list)
    selected = []
    for case in source["cases"]:
        base_by_group[_group(case)].append(case["case_id"])
        if _group(case) in selected_groups:
            _assert_unlabeled(case)
            selected.append(deepcopy(case))
    selected.sort(key=lambda case: case["case_id"])
    selected_by_group: dict[str, list[str]] = defaultdict(list)
    for case in selected:
        selected_by_group[_group(case)].append(case["case_id"])
    if set(selected_by_group) != selected_groups:
        raise ValueError("one or more selected groups have no cases")
    for group_id in selected_groups:
        if sorted(selected_by_group[group_id]) != sorted(
            base_by_group[group_id]
        ):
            raise ValueError(f"partial group selected: {group_id}")

    instances = [
        instance
        for case in selected
        for instance in case["runtime_instances"]
    ]
    source_groups: dict[str, set[str]] = defaultdict(set)
    for case in selected:
        source_groups[case["source"]["source_id"]].add(_group(case))
    selected_case_ids = [case["case_id"] for case in selected]
    selected_group_ids = sorted(selected_groups)
    excluded_group_ids = sorted(collision_groups)
    return {
        "packet_version": "1.0",
        "packet_kind": "runtime_confirmatory_30_unlabeled",
        "protocol_id": "confirmatory_double_human_v1",
        "protocol_status": "frozen_before_human_labels",
        "policy": {
            "generated_labels": 0,
            "selection_before_human_labels": True,
            "selection_uses_gold": False,
            "complete_independence_groups_only": True,
            "near_duplicate_warning_groups_excluded": True,
            "two_independent_humans_required": True,
            "third_human_adjudication_for_disputes": True,
            "llm_annotation_prohibited": True,
        },
        "base_queue": {
            "path": str(input_path.relative_to(root)).replace("\\", "/"),
            "sha256": _file_hash(input_path),
        },
        "selection": {
            "rule": (
                "all runtime-ready groups except every group carrying the "
                "pre-label runtime-sequence collision warning"
            ),
            "selected_case_ids": selected_case_ids,
            "selected_case_ids_sha256": _stable_hash(selected_case_ids),
            "selected_independence_groups": selected_group_ids,
            "selected_independence_groups_sha256": _stable_hash(
                selected_group_ids
            ),
            "excluded_collision_groups": excluded_group_ids,
            "excluded_collision_groups_sha256": _stable_hash(
                excluded_group_ids
            ),
        },
        "summary": {
            "case_count": len(selected),
            "independence_group_count": len(selected_groups),
            "excluded_collision_group_count": len(collision_groups),
            "runtime_instance_count": len(instances),
            "observation_count": sum(
                int(instance.get("observation_count") or 0)
                for instance in instances
            ),
            "source_count": len(source_groups),
            "source_case_counts": dict(sorted(Counter(
                case["source"]["source_id"] for case in selected
            ).items())),
            "source_group_counts": {
                source_id: len(groups)
                for source_id, groups in sorted(source_groups.items())
            },
            "platform_instance_counts": dict(sorted(Counter(
                str(instance["platform"]).upper()
                for instance in instances
            ).items())),
            "human_gold_cases": 0,
            "human_gold_independence_groups": 0,
        },
        "schema_ref": source["schema_ref"],
        "cases": selected,
    }


def render_report(packet: dict[str, Any]) -> str:
    summary = packet["summary"]
    excluded = packet["selection"]["excluded_collision_groups"]
    return "\n".join([
        "# 30 谱系双人盲标确认集 v1",
        "",
        "该确认集在任何人工标签产生前冻结。它从运行时就绪队列的 32 个谱系中，"
        "排除全部 2 个带有序列指纹冲突警告的谱系，并完整保留其余 30 个谱系"
        "的所有案例。",
        "",
        f"- 案例数：{summary['case_count']}",
        f"- 独立谱系数：{summary['independence_group_count']}",
        f"- 运行时实例数：{summary['runtime_instance_count']}",
        f"- 原始观测数：{summary['observation_count']}",
        f"- 上游来源数：{summary['source_count']}",
        "- 当前 human gold：0",
        "",
        "排除的近重复待复核组：",
        "",
        *[f"- `{group_id}`" for group_id in excluded],
        "",
        "## 人工判定原则",
        "",
        "- `accept`：五项准入问题都能由当前冻结证据肯定回答，并完整标出节点、"
        "边、路径和工具任务。",
        "- `needs_execution`：存在合理路径假设，但关键权限、网络或数据面边需要"
        "额外 provider-native oracle 或隔离主动探针。",
        "- `reject`：入口、多步性、云数据目标、原始证据或独立性中的必要条件"
        "明确不成立。",
        "- 不确定时不得猜测；选择 `needs_execution` 并说明缺少哪条决定性证据。",
        "- 主标人与复核人必须独立作答，互不可见；分歧只交给第三位真人仲裁。",
        "",
        "52 个案例是 30 个完整谱系的组内展开，统计单位始终是谱系，不能把同一"
        "谱系下的多云案例当作多个独立样本。",
        "",
    ])


def main() -> int:
    packet = build_packet()
    OUTPUT.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT.write_text(render_report(packet), encoding="utf-8")
    print(json.dumps(packet["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
