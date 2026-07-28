"""Freeze the label-independent, runtime-backed human annotation pilot."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "configs" / "runtime_annotation_pilot_v1.json"
OUTPUT_PATH = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_pilot_round1_unlabeled.json"
)
CONFIG_V2_PATH = ROOT / "configs" / "runtime_annotation_pilot_v2.json"
OUTPUT_V2_PATH = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_pilot_round2_unlabeled.json"
)
LABEL_LIST_FIELDS = (
    "nodes",
    "edges",
    "path_labels",
    "tool_tasks",
    "instance_labels",
)
PLATFORMS = {"AWS", "AZURE", "GCP"}


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
    value = case.get("candidate_metadata", {}).get("independence_group")
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
    if any(case.get(field) for field in LABEL_LIST_FIELDS):
        raise ValueError(f"{case.get('case_id')} contains graph labels")
    screen = case.get("admission_screen") or {}
    if any(value is not None for value in screen.values()):
        raise ValueError(f"{case.get('case_id')} contains admission labels")


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def build_runtime_pilot(
    config_path: Path = CONFIG_PATH,
) -> dict[str, Any]:
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    config = json.loads(config_path.read_text(encoding="utf-8"))
    base_path = ROOT / config["base_packet"]
    actual_base_sha = _file_sha256(base_path)
    if actual_base_sha != config["base_packet_sha256"]:
        raise ValueError(
            "base packet SHA-256 changed: "
            f"{actual_base_sha} != {config['base_packet_sha256']}"
        )
    base = json.loads(base_path.read_text(encoding="utf-8"))
    groups = set(config["selection_rule"]["independence_groups"])
    selected = [
        deepcopy(case) for case in base["cases"] if _group(case) in groups
    ]
    if {_group(case) for case in selected} != groups:
        missing = sorted(groups - {_group(case) for case in selected})
        raise ValueError(f"configured independence groups are missing: {missing}")

    base_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    selected_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in base["cases"]:
        base_by_group[_group(case)].append(case)
    for case in selected:
        _assert_unlabeled(case)
        selected_by_group[_group(case)].append(case)
        if not case.get("runtime_instances"):
            raise ValueError(f"{case['case_id']} has no runtime instance")
    for group in groups:
        base_ids = {case["case_id"] for case in base_by_group[group]}
        selected_ids = {case["case_id"] for case in selected_by_group[group]}
        if selected_ids != base_ids:
            raise ValueError(f"partial independence group selected: {group}")

    instances = [
        instance
        for case in selected
        for instance in case["runtime_instances"]
    ]
    if any(instance.get("platform") not in PLATFORMS for instance in instances):
        raise ValueError("every runtime instance must have a supported platform")
    runtime_blob = json.dumps(instances, ensure_ascii=False)
    for forbidden in ("source_condition", "payload_present", "payload_absent"):
        if forbidden in runtime_blob:
            raise ValueError(
                f"runtime instances expose evaluator-only field: {forbidden}"
            )

    cross_groups = {
        group: cases
        for group, cases in selected_by_group.items()
        if group.startswith("crosscloud-family:")
    }
    expected = config["expected"]
    for group, cases in cross_groups.items():
        platforms = {
            case["candidate_metadata"]["platform"] for case in cases
        }
        instance_count = sum(
            len(case["runtime_instances"]) for case in cases
        )
        if (
            len(cases) != expected["crosscloud_cases_per_group"]
            or platforms != PLATFORMS
            or instance_count != expected["crosscloud_instances_per_group"]
        ):
            raise ValueError(f"incomplete cross-cloud family group: {group}")

    source_counts = Counter(
        case["source"]["source_id"] for case in selected
    )
    platform_counts = Counter(
        instance["platform"] for instance in instances
    )
    observation_count = sum(
        int(instance["observation_count"]) for instance in instances
    )
    actual = {
        "case_count": len(selected),
        "runtime_instance_count": len(instances),
        "independence_group_count": len(selected_by_group),
        "observation_count": observation_count,
        "source_case_counts": _counter_dict(source_counts),
        "platform_instance_counts": _counter_dict(platform_counts),
    }
    for key, value in actual.items():
        if value != expected[key]:
            raise ValueError(
                f"pilot {key} changed: {value!r} != {expected[key]!r}"
            )

    selected = sorted(selected, key=lambda case: case["case_id"])
    config_sha = _file_sha256(config_path)
    selected_case_ids = [case["case_id"] for case in selected]
    return {
        "packet_version": config.get("packet_version", "0.1"),
        "packet_kind": "runtime_annotation_pilot_unlabeled",
        "protocol_id": config["protocol_id"],
        "protocol_status": config["protocol_status"],
        **(
            {"supersedes": deepcopy(config["supersedes"])}
            if config.get("supersedes")
            else {}
        ),
        "policy": {
            "generated_labels": 0,
            "selection_before_human_labels": True,
            "complete_independence_groups_only": True,
            "runtime_source_condition_visible_to_humans": False,
            "two_independent_humans_required": True,
            "third_human_adjudication_for_disputes": True
        },
        "schema_ref": base["schema_ref"],
        "base_packet": {
            "path": config["base_packet"],
            "sha256": actual_base_sha
        },
        "selection": {
            "config_path": str(config_path.relative_to(ROOT)).replace(
                "\\", "/"
            ),
            "config_sha256": config_sha,
            "rule": deepcopy(config["selection_rule"]),
            "selected_case_ids": selected_case_ids,
            "selected_case_ids_sha256": _stable_hash(selected_case_ids)
        },
        "summary": {
            **actual,
            "human_gold_cases": 0,
            "human_gold_runtime_instances": 0
        },
        "cases": selected
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    packet = build_runtime_pilot(args.config)
    output_path = (
        args.output if args.output.is_absolute() else ROOT / args.output
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(packet["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
