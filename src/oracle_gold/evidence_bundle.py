"""Label-blind evidence bundles for executable Oracle runs.

The bundle contains raw-artifact bindings and execution attestations, but no
declared truth label.  A truth state is derived only after all four channel
outcomes have been validated against one frozen scope.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from src.oracle_gold.protocol import (
    refresh_registry_derived_fields,
    validate_oracle_registry,
)


CHANNELS = (
    "configuration",
    "provider_native_analysis",
    "authorized_active_probe",
    "audit_telemetry",
)
SCOPE_FIELDS = (
    "principals",
    "actions",
    "resources",
    "network_origins",
    "time_window",
)
REACHABLE_OUTCOMES = {
    "configuration": "verified_facts",
    "provider_native_analysis": "allows",
    "authorized_active_probe": "allowed",
    "audit_telemetry": "allowed_observed",
}
NOT_REACHABLE_OUTCOMES = {
    "configuration": "verified_facts",
    "provider_native_analysis": "denies",
    "authorized_active_probe": "denied",
    "audit_telemetry": "denied_observed",
}


def build_evidence_bundle_templates(
    root: str | Path,
    *,
    queue_path: str | Path,
    policy_path: str | Path,
) -> dict[str, Any]:
    """Build deterministic, outcome-empty forms for every queued lineage."""
    root = Path(root).resolve()
    queue_path = _resolve_file(root, queue_path)
    policy_path = _resolve_file(root, policy_path)
    queue = _read_object(queue_path)
    policy = _read_yaml_object(policy_path)
    templates = []
    for task in queue.get("tasks") or []:
        platform = task["selected_oracle_unit"]["platform"]
        templates.append({
            "bundle_version": "1.0.0",
            "bundle_kind": "privileged_oracle_evidence",
            "status": "pending",
            "task_binding": {
                "queue": _binding(root, queue_path),
                "policy": _binding(root, policy_path),
                "task_id": task["task_id"],
                "independence_group": task["independence_group"],
                "selected_oracle_unit": task["selected_oracle_unit"],
            },
            "run": {
                "status": "pending",
                "run_id": None,
                "platform": platform,
                "started_at": None,
                "finished_at": None,
                "estimated_cost_usd": None,
                "credential_values_recorded": False,
                "authorization": {
                    "dedicated_scope_verified": False,
                    "production_scope": None,
                    "sentinel_verified": False,
                    "no_sensitive_data_attested": False,
                    "run_owned_resources_only": False,
                },
                "teardown": {
                    "status": "pending",
                    "inventory_artifact": None,
                },
            },
            "scope": {
                "status": "pending",
                **{field: [] for field in SCOPE_FIELDS},
            },
            "channels": {
                channel: {
                    "status": "pending",
                    "outcome": None,
                    "evidence": [],
                }
                for channel in CHANNELS
            },
            "critical_edges": [],
            "leakage_control": {
                "agent_view_artifact": None,
                "evaluator_only_artifacts": [],
                "oracle_outputs_withheld_until_scoring": True,
            },
        })
    templates.sort(
        key=lambda item: item["task_binding"]["independence_group"]
    )
    return {
        "collection_version": "1.0.0",
        "collection_kind": "oracle_evidence_bundle_templates",
        "status": "pending_no_execution",
        "bindings": {
            "queue": _binding(root, queue_path),
            "policy": _binding(root, policy_path),
        },
        "policy": {
            "contains_truth_labels": False,
            "contains_expected_outcomes": False,
            "generated_events": 0,
            "generated_labels": 0,
            "completed_bundle_count": 0,
        },
        "summary": {
            "template_count": len(templates),
            "platform_counts": {
                platform: sum(
                    item["run"]["platform"] == platform
                    for item in templates
                )
                for platform in ("AWS", "AZURE", "GCP")
            },
        },
        "templates": templates,
    }


def derive_truth_state(bundle: Mapping[str, Any]) -> str:
    """Derive the four-value state without accepting a supplied label."""
    channels = bundle.get("channels")
    if not isinstance(channels, Mapping):
        return "Unknown"
    entries = [channels.get(channel) for channel in CHANNELS]
    if any(not isinstance(entry, Mapping) for entry in entries):
        return "Unknown"
    if any(entry.get("status") == "conflict" for entry in entries):
        return "Conflict"
    if any(entry.get("status") != "verified" for entry in entries):
        return "Unknown"
    outcomes = {
        channel: channels[channel].get("outcome")
        for channel in CHANNELS
    }
    if outcomes == REACHABLE_OUTCOMES:
        return "Reachable"
    if outcomes == NOT_REACHABLE_OUTCOMES:
        return "NotReachableWithinScope"
    return "Conflict"


def validate_evidence_bundle(
    root: str | Path,
    bundle: Mapping[str, Any],
    *,
    queue_path: str | Path,
    policy_path: str | Path,
    require_completed: bool = True,
) -> dict[str, Any]:
    """Validate a bundle and return its deterministically derived state."""
    root = Path(root).resolve()
    queue_path = _resolve_file(root, queue_path)
    policy_path = _resolve_file(root, policy_path)
    schema_path = _resolve_file(
        root,
        "data/real_sources/oracle/evidence/"
        "executable_oracle_evidence_bundle_v1.schema.json",
    )
    schema = _read_object(schema_path)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(bundle),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(item) for item in first.absolute_path)
        raise ValueError(
            f"Oracle evidence schema violation at {location}: "
            f"{first.message}"
        )

    queue = _read_object(queue_path)
    policy = _read_yaml_object(policy_path)
    binding = bundle["task_binding"]
    if binding["queue"] != _binding(root, queue_path):
        raise ValueError("Oracle evidence queue binding mismatch")
    if binding["policy"] != _binding(root, policy_path):
        raise ValueError("Oracle evidence policy binding mismatch")
    tasks = {
        item["task_id"]: item for item in queue.get("tasks") or []
    }
    task = tasks.get(binding["task_id"])
    if task is None:
        raise ValueError("Oracle evidence task is absent from queue")
    for field in ("independence_group", "selected_oracle_unit"):
        if binding[field] != task[field]:
            raise ValueError(f"Oracle evidence task {field} mismatch")
    if bundle["run"]["platform"] != (
        task["selected_oracle_unit"]["platform"]
    ):
        raise ValueError("Oracle evidence platform differs from frozen unit")

    state = derive_truth_state(bundle)
    if not require_completed:
        return {
            "valid": True,
            "completed": bundle.get("status") == "completed",
            "derived_truth_state": state,
        }
    _validate_completed_run(root, bundle, policy)
    _validate_evidence(root, bundle)
    return {
        "valid": True,
        "completed": True,
        "task_id": binding["task_id"],
        "independence_group": binding["independence_group"],
        "derived_truth_state": state,
        "qualifies_by_state": state in {
            "Reachable",
            "NotReachableWithinScope",
        },
    }


def apply_completed_evidence_bundles(
    root: str | Path,
    registry: Mapping[str, Any],
    bundles: list[Mapping[str, Any]],
    *,
    queue_path: str | Path,
    policy_path: str | Path,
) -> dict[str, Any]:
    """Apply validated bundles and recompute Gold fields from evidence."""
    from copy import deepcopy

    root = Path(root).resolve()
    output = deepcopy(dict(registry))
    validate_oracle_registry(root, output)
    candidates = {
        item["independence_group"]: item
        for item in output["candidates"]
    }
    seen: set[str] = set()
    for bundle in bundles:
        report = validate_evidence_bundle(
            root,
            bundle,
            queue_path=queue_path,
            policy_path=policy_path,
            require_completed=True,
        )
        group = report["independence_group"]
        if group in seen:
            raise ValueError(f"duplicate Oracle evidence bundle: {group}")
        seen.add(group)
        candidate = candidates.get(group)
        if candidate is None:
            raise ValueError(f"Oracle bundle group absent from registry: {group}")
        if candidate["selected_oracle_unit"] != (
            bundle["task_binding"]["selected_oracle_unit"]
        ):
            raise ValueError(f"Oracle bundle selected unit mismatch: {group}")
        candidate["scope"] = deepcopy(bundle["scope"])
        candidate["evidence_channels"] = deepcopy(bundle["channels"])
        candidate["critical_edges"] = deepcopy(bundle["critical_edges"])
        leakage = deepcopy(bundle["leakage_control"])
        leakage["views_are_hash_distinct"] = True
        candidate["leakage_control"] = leakage
        candidate["truth_state"] = report["derived_truth_state"]

    refresh_registry_derived_fields(root, output)
    validate_oracle_registry(root, output)
    return output


def _validate_completed_run(
    root: Path,
    bundle: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    if bundle.get("status") != "completed":
        raise ValueError("Oracle evidence bundle is not completed")
    run = bundle["run"]
    if run.get("status") != "completed":
        raise ValueError("Oracle execution run is not completed")
    if run.get("credential_values_recorded") is not False:
        raise ValueError("credential values must not enter Oracle artifacts")
    authorization = run["authorization"]
    required_true = (
        "dedicated_scope_verified",
        "sentinel_verified",
        "no_sensitive_data_attested",
        "run_owned_resources_only",
    )
    if any(authorization.get(field) is not True for field in required_true):
        raise ValueError("Oracle execution authorization is incomplete")
    if authorization.get("production_scope") is not False:
        raise ValueError("production scope is forbidden")
    maximum = float(
        policy["safety"]["maximum_estimated_cost_usd_per_lineage"]
    )
    cost = run.get("estimated_cost_usd")
    if not isinstance(cost, (int, float)) or cost < 0 or cost > maximum:
        raise ValueError("Oracle execution cost exceeds frozen policy")
    started = _parse_time(run.get("started_at"), "started_at")
    finished = _parse_time(run.get("finished_at"), "finished_at")
    if finished < started:
        raise ValueError("Oracle execution time window is reversed")
    teardown = run["teardown"]
    if teardown.get("status") != "verified_clean":
        raise ValueError("Oracle teardown is not verified clean")
    _validate_binding(root, teardown.get("inventory_artifact"))

    scope = bundle["scope"]
    if scope.get("status") != "frozen":
        raise ValueError("Oracle scope is not frozen")
    for field in SCOPE_FIELDS:
        values = scope.get(field)
        if not isinstance(values, list) or not values:
            raise ValueError(f"Oracle scope field is empty: {field}")


def _validate_evidence(
    root: Path,
    bundle: Mapping[str, Any],
) -> None:
    scope_digest = _stable_hash(bundle["scope"])
    evidence_ids: dict[str, str] = {}
    evidence_paths: list[Path] = []
    for channel in CHANNELS:
        entry = bundle["channels"][channel]
        if entry["status"] not in {"verified", "conflict"}:
            raise ValueError(f"Oracle channel is incomplete: {channel}")
        if not entry["evidence"]:
            raise ValueError(f"Oracle channel has no evidence: {channel}")
        for item in entry["evidence"]:
            evidence_id = item["evidence_id"]
            if evidence_id in evidence_ids:
                raise ValueError(
                    f"duplicate Oracle evidence ID: {evidence_id}"
                )
            evidence_ids[evidence_id] = channel
            if item["scope_binding_sha256"] != scope_digest:
                raise ValueError(
                    f"Oracle evidence scope mismatch: {evidence_id}"
                )
            adapter = item["adapter"]
            if adapter.get("deterministic") is not True:
                raise ValueError(
                    f"non-deterministic Oracle adapter: {evidence_id}"
                )
            _parse_time(item["observed_at"], "observed_at")
            evidence_paths.append(
                _validate_binding(root, item["artifact"])
            )

    edges = bundle["critical_edges"]
    if not edges:
        raise ValueError("Oracle evidence has no critical edges")
    for index, edge in enumerate(edges):
        refs = edge["evidence_refs"]
        if any(ref not in evidence_ids for ref in refs):
            raise ValueError(
                f"Oracle edge references unknown evidence: {index}"
            )
        if len({evidence_ids[ref] for ref in refs}) < 2:
            raise ValueError(
                f"Oracle edge lacks independent channels: {index}"
            )

    leakage = bundle["leakage_control"]
    if leakage.get("oracle_outputs_withheld_until_scoring") is not True:
        raise ValueError("Oracle outputs are not withheld until scoring")
    agent_path = _validate_binding(
        root,
        leakage.get("agent_view_artifact"),
    )
    evaluator_paths = [
        _validate_binding(root, item)
        for item in leakage.get("evaluator_only_artifacts") or []
    ]
    if not evaluator_paths:
        raise ValueError("evaluator-only Oracle artifacts are missing")
    if agent_path in evaluator_paths:
        raise ValueError("agent view equals evaluator-only artifact")
    agent_hash = leakage["agent_view_artifact"]["sha256"]
    evaluator_hashes = {
        item["sha256"]
        for item in leakage["evaluator_only_artifacts"]
    }
    if agent_hash in evaluator_hashes:
        raise ValueError("agent and evaluator artifacts are byte-identical")
    if not set(evidence_paths).issubset(set(evaluator_paths)):
        raise ValueError(
            "channel evidence is not bound as evaluator-only"
        )


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid Oracle time: {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid Oracle time: {field}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Oracle time lacks timezone: {field}")
    return parsed


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _read_yaml_object(path: Path) -> dict[str, Any]:
    import yaml

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be object: {path}")
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


def _validate_binding(root: Path, value: Any) -> Path:
    if not isinstance(value, Mapping):
        raise ValueError("artifact binding must be an object")
    path = _resolve_file(root, str(value.get("path") or ""))
    data = path.read_bytes()
    expected = {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }
    if dict(value) != expected:
        raise ValueError(f"artifact binding mismatch: {expected['path']}")
    return path


def _binding(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()
