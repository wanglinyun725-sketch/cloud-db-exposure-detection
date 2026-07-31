"""Extract label-free scope candidates from frozen upstream evidence."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from src.oracle_gold.protocol import validate_oracle_registry


RESOURCE_KEYS = {
    "arn",
    "bucket",
    "bucketname",
    "container",
    "containername",
    "database",
    "databaseid",
    "dbinstanceidentifier",
    "datasetid",
    "imageid",
    "instanceid",
    "parametername",
    "parameternames",
    "project",
    "projectid",
    "repositoryname",
    "resource",
    "resourceid",
    "resourcename",
    "secretid",
    "snapshotid",
    "storageaccountname",
    "tablename",
    "workspace",
    "workspacename",
}


def build_scope_candidate_inventory(
    root: str | Path,
    *,
    registry_path: str | Path,
) -> dict[str, Any]:
    """Build conservative scope hints without freezing scope or labels."""
    root = Path(root).resolve()
    registry_path = _resolve_file(root, registry_path)
    registry = _read_object(registry_path)
    validate_oracle_registry(root, registry)
    runtime_packet = _packet(root, registry, "runtime_packet")
    configuration_packet = _packet(
        root,
        registry,
        "configuration_packet",
    )
    packet_cases = {
        "runtime_telemetry": {
            str(item["case_id"]): item
            for item in runtime_packet.get("cases") or []
        },
        "configuration": {
            str(item["case_id"]): item
            for item in configuration_packet.get("cases") or []
        },
    }
    rows = []
    for candidate in registry["candidates"]:
        unit = candidate["selected_oracle_unit"]
        case = packet_cases[candidate["category"]][unit["case_id"]]
        if candidate["category"] == "runtime_telemetry":
            row = _runtime_scope_candidate(candidate, case)
        else:
            row = _configuration_scope_candidate(candidate, case)
        rows.append(row)
    rows.sort(key=lambda item: item["independence_group"])
    return {
        "inventory_version": "1.0.0",
        "inventory_kind": "label_free_oracle_scope_candidates",
        "status": "not_frozen_not_gold",
        "bindings": {
            "oracle_registry": _binding(root, registry_path),
            "runtime_packet": registry["inputs"]["runtime_packet"],
            "configuration_packet": (
                registry["inputs"]["configuration_packet"]
            ),
        },
        "policy": {
            "scope_candidates_are_frozen_scope": False,
            "scope_candidates_are_truth_labels": False,
            "empty_observation_is_negative_evidence": False,
            "generated_events": 0,
            "generated_labels": 0,
        },
        "summary": {
            "independence_groups": len(rows),
            "runtime_groups": sum(
                item["category"] == "runtime_telemetry"
                for item in rows
            ),
            "runtime_groups_with_observations": sum(
                item["category"] == "runtime_telemetry"
                and item["observation_count"] > 0
                for item in rows
            ),
            "runtime_groups_without_observations": sum(
                item["category"] == "runtime_telemetry"
                and item["observation_count"] == 0
                for item in rows
            ),
            "configuration_groups": sum(
                item["category"] == "configuration"
                for item in rows
            ),
            "candidates_with_all_scope_fields_observed": sum(
                item["all_scope_fields_observed"] is True
                for item in rows
            ),
            "single_claim_scope_candidates": sum(
                _is_single_claim_candidate(item) for item in rows
            ),
            "platform_counts": {
                platform: sum(
                    item["platform"] == platform for item in rows
                )
                for platform in ("AWS", "AZURE", "GCP")
            },
        },
        "candidates": rows,
    }


def _runtime_scope_candidate(
    candidate: Mapping[str, Any],
    case: Mapping[str, Any],
) -> dict[str, Any]:
    unit = candidate["selected_oracle_unit"]
    matches = [
        item
        for item in case.get("runtime_instances") or []
        if item.get("instance_id") == unit["runtime_instance_id"]
    ]
    if len(matches) != 1:
        raise ValueError(
            "selected runtime instance is missing or duplicated: "
            + unit["unit_id"]
        )
    observations = matches[0].get("observations") or []
    principals = _strings(observations, "actor_id")
    actions = sorted({
        f"{item.get('service')}:{item.get('operation')}"
        for item in observations
        if item.get("service") and item.get("operation")
    })
    resources = sorted({
        value
        for item in observations
        for value in _resource_values(item.get("request"))
    })
    network_origins = _strings(observations, "source_ip")
    timestamps = _strings(observations, "timestamp")
    time_window = (
        [min(timestamps), max(timestamps)] if timestamps else []
    )
    fields = {
        "principals": principals,
        "actions": actions,
        "resources": resources,
        "network_origins": network_origins,
        "time_window": time_window,
    }
    return {
        "independence_group": candidate["independence_group"],
        "category": candidate["category"],
        "platform": unit["platform"],
        "selected_oracle_unit": unit,
        "scope_candidate_status": "observed_not_frozen",
        "scope_fields": fields,
        "observation_count": len(observations),
        "all_scope_fields_observed": all(fields.values()),
        "unresolved_fields": sorted(
            key for key, value in fields.items() if not value
        ),
        "selection_semantics": (
            "all normalized values observed in the frozen selected runtime "
            "instance; no terminal edge or truth outcome selected"
        ),
    }


def _configuration_scope_candidate(
    candidate: Mapping[str, Any],
    case: Mapping[str, Any],
) -> dict[str, Any]:
    unit = candidate["selected_oracle_unit"]
    target = case.get("data_target") or {}
    service = str(target.get("service") or "")
    actions = sorted({
        str(value)
        for value in target.get("operation_scope") or []
        if str(value)
    })
    fields = {
        "principals": [],
        "actions": actions,
        "resources": ([f"service_hint:{service}"] if service else []),
        "network_origins": [],
        "time_window": [],
    }
    return {
        "independence_group": candidate["independence_group"],
        "category": candidate["category"],
        "platform": unit["platform"],
        "selected_oracle_unit": unit,
        "scope_candidate_status": "deployment_resolution_required",
        "scope_fields": fields,
        "observation_count": 0,
        "all_scope_fields_observed": False,
        "unresolved_fields": [
            "principals",
            "network_origins",
            "time_window",
            "exact_resource_identifiers",
        ],
        "selection_semantics": (
            "operation and service hints copied from byte-verified upstream "
            "configuration; deployment must resolve exact live scope"
        ),
    }


def _is_single_claim_candidate(item: Mapping[str, Any]) -> bool:
    fields = item["scope_fields"]
    return (
        item["all_scope_fields_observed"] is True
        and len(fields["principals"]) == 1
        and len(fields["actions"]) == 1
        and len(fields["resources"]) == 1
        and len(fields["network_origins"]) == 1
        and len(fields["time_window"]) == 2
    )


def _strings(
    observations: list[Mapping[str, Any]],
    field: str,
) -> list[str]:
    return sorted({
        str(item[field])
        for item in observations
        if item.get(field) not in (None, "")
    })


def _resource_values(value: Any, prefix: str = "request") -> set[str]:
    output: set[str] = set()
    if isinstance(value, Mapping):
        normalized_keys = {
            str(key).casefold(): key for key in value
        }
        if (
            {"bucket", "bucketname"} & set(normalized_keys)
            and "key" in normalized_keys
        ):
            key = normalized_keys["key"]
            output.update(
                _flatten_resource_value(f"{prefix}.{key}", value[key])
            )
        for key, item in value.items():
            child = f"{prefix}.{key}"
            if str(key).casefold() in RESOURCE_KEYS:
                output.update(_flatten_resource_value(child, item))
            elif isinstance(item, (Mapping, list)):
                output.update(_resource_values(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            output.update(_resource_values(item, f"{prefix}[{index}]"))
    return output


def _flatten_resource_value(prefix: str, value: Any) -> set[str]:
    if isinstance(value, (str, int, float, bool)):
        text = str(value)
        return {f"{prefix}={text}"} if text else set()
    if isinstance(value, list):
        return {
            item
            for index, child in enumerate(value)
            for item in _flatten_resource_value(f"{prefix}[{index}]", child)
        }
    if isinstance(value, Mapping):
        return {
            item
            for key, child in value.items()
            for item in _flatten_resource_value(f"{prefix}.{key}", child)
        }
    return set()


def _packet(
    root: Path,
    registry: Mapping[str, Any],
    name: str,
) -> dict[str, Any]:
    binding = registry["inputs"][name]
    path = _resolve_file(root, binding["path"])
    if _binding(root, path) != binding:
        raise ValueError(f"Oracle packet binding mismatch: {name}")
    return _read_object(path)


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _resolve_file(root: Path, value: str | Path) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {value}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _binding(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }
