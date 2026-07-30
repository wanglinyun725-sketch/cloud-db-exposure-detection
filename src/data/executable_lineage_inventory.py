"""Audit executable runtime/configuration candidates without calling them gold."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


def build_executable_lineage_inventory(
    root: str | Path,
    *,
    runtime_queue_path: str | Path = (
        "data/real_sources/annotation/"
        "runtime_ready_queue_v1_unlabeled.json"
    ),
    configuration_queue_path: str | Path = (
        "data/real_sources/annotation/"
        "configuration_oracle_queue_v1_unlabeled.json"
    ),
    admission_audit_path: str | Path = (
        "output/research_design/lineage_admission_audit_v1.json"
    ),
) -> dict[str, Any]:
    root = Path(root).resolve()
    runtime_path = _resolve(root, runtime_queue_path)
    configuration_path = _resolve(root, configuration_queue_path)
    admission_audit_path = _resolve(root, admission_audit_path)
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    configuration = json.loads(
        configuration_path.read_text(encoding="utf-8")
    )
    admission_audit = json.loads(
        admission_audit_path.read_text(encoding="utf-8")
    )
    collision_warning = (
        "runtime_sequence_collides_with_another_independence_group"
    )
    flagged_runtime_groups = {
        group["independence_group"]
        for group in admission_audit["groups"]
        if collision_warning in group.get("warnings", [])
    }

    groups: dict[tuple[str, str], dict[str, set[str]]] = {}
    for case in runtime["cases"]:
        group_id = case["candidate_metadata"]["independence_group"]
        bucket = groups.setdefault(
            ("runtime", group_id),
            {"case_ids": set(), "source_ids": set(), "platforms": set()},
        )
        bucket["case_ids"].add(case["case_id"])
        bucket["source_ids"].add(case["source"]["source_id"])
        bucket["platforms"].update(
            instance["platform"] for instance in case["runtime_instances"]
        )

    for case in configuration["cases"]:
        group_id = case["independence_group"]
        bucket = groups.setdefault(
            ("configuration", group_id),
            {"case_ids": set(), "source_ids": set(), "platforms": set()},
        )
        bucket["case_ids"].add(case["case_id"])
        bucket["source_ids"].add(case["source_id"])
        bucket["platforms"].add(_canonical_platform(case["platform"]))

    raw_group_ids: dict[str, set[str]] = {}
    for category, group_id in groups:
        raw_group_ids.setdefault(group_id, set()).add(category)
    category_collisions = sorted(
        group_id for group_id, categories in raw_group_ids.items()
        if len(categories) > 1
    )
    if category_collisions:
        raise ValueError(
            "independence groups collide across queue categories: "
            + ", ".join(category_collisions)
        )

    group_rows = []
    for (category, group_id), values in sorted(groups.items()):
        near_duplicate_review_required = (
            category == "runtime" and group_id in flagged_runtime_groups
        )
        group_rows.append({
            "category": category,
            "independence_group": group_id,
            "case_ids": sorted(values["case_ids"]),
            "source_ids": sorted(values["source_ids"]),
            "platforms": sorted(values["platforms"]),
            "gold_status": "unlabeled",
            "near_duplicate_review_required": (
                near_duplicate_review_required
            ),
        })

    runtime_groups = [
        row for row in group_rows if row["category"] == "runtime"
    ]
    configuration_groups = [
        row for row in group_rows if row["category"] == "configuration"
    ]
    sources = sorted({
        source_id
        for row in group_rows
        for source_id in row["source_ids"]
    })
    platforms = sorted({
        platform
        for row in group_rows
        for platform in row["platforms"]
    })
    matched_flagged_runtime_groups = {
        row["independence_group"]
        for row in runtime_groups
        if row["near_duplicate_review_required"]
    }
    unmatched_flagged_runtime_groups = sorted(
        flagged_runtime_groups - matched_flagged_runtime_groups
    )
    if unmatched_flagged_runtime_groups:
        raise ValueError(
            "admission audit collision groups are absent from runtime queue: "
            + ", ".join(unmatched_flagged_runtime_groups)
        )
    conservative_independence_groups = (
        len(group_rows) - len(matched_flagged_runtime_groups)
    )
    minimum_candidate_gate = {
        "minimum_independence_groups": 40,
        "minimum_sources": 6,
        "required_platforms": ["AWS", "AZURE", "GCP"],
        "groups_pass": conservative_independence_groups >= 40,
        "sources_pass": len(sources) >= 6,
        "platforms_pass": set(platforms) >= {"AWS", "AZURE", "GCP"},
    }
    minimum_candidate_gate["passes"] = all([
        minimum_candidate_gate["groups_pass"],
        minimum_candidate_gate["sources_pass"],
        minimum_candidate_gate["platforms_pass"],
    ])
    return {
        "inventory_version": "1.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "executable_candidates_not_gold",
        "inputs": {
            "runtime_queue": str(runtime_path.relative_to(root)).replace(
                "\\", "/"
            ),
            "configuration_queue": str(
                configuration_path.relative_to(root)
            ).replace("\\", "/"),
            "lineage_admission_audit": str(
                admission_audit_path.relative_to(root)
            ).replace("\\", "/"),
        },
        "summary": {
            "runtime_independence_groups": len(runtime_groups),
            "configuration_independence_groups": len(configuration_groups),
            "combined_independence_groups": len(group_rows),
            "near_duplicate_review_pending_groups": len(
                matched_flagged_runtime_groups
            ),
            "conservative_independence_groups": (
                conservative_independence_groups
            ),
            "source_count": len(sources),
            "sources": sources,
            "platforms": platforms,
            "human_gold_independence_groups": 0,
            "double_blind_labeled_independence_groups": 0,
            "adjudicated_independence_groups": 0,
        },
        "minimum_candidate_gate": minimum_candidate_gate,
        "human_gold_gate": {
            "minimum_double_blind_labeled_groups": 30,
            "current": 0,
            "remaining": 30,
            "passes": False,
        },
        "policy": {
            "candidate_count_is_gold_count": False,
            "configuration_literal_is_path_verdict": False,
            "runtime_ready_is_human_accepted": False,
            "final_independence_requires_blind_review_and_deduplication": True,
            "near_duplicate_groups_counted_toward_minimum": False,
        },
        "groups": group_rows,
    }


def _canonical_platform(value: str) -> str:
    normalized = value.strip().upper()
    if normalized == "AZURE":
        return "AZURE"
    if normalized in {"AWS", "GCP"}:
        return normalized
    raise ValueError(f"unsupported platform: {value}")


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()
