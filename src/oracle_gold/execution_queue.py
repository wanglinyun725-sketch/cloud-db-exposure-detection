"""Build a label-blind execution queue for the four Oracle channels."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.oracle_gold.protocol import validate_oracle_registry


def build_execution_queue(
    root: str | Path,
    *,
    registry_path: str | Path,
    policy_path: str | Path,
) -> dict[str, Any]:
    root = Path(root).resolve()
    registry_path = _resolve(root, registry_path)
    policy_path = _resolve(root, policy_path)
    registry = _read_json(registry_path)
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(policy, Mapping):
        raise ValueError("Oracle execution policy must be an object")
    validate_oracle_registry(root, registry)
    _validate_policy(policy)

    contracts = policy["provider_contracts"]
    tasks = []
    for candidate in registry["candidates"]:
        if candidate.get("counts_toward_oracle_gold") is True:
            continue
        platform_tasks = []
        selected_platform = candidate["selected_oracle_unit"]["platform"]
        for platform in [selected_platform]:
            contract = contracts.get(platform)
            if not isinstance(contract, Mapping):
                raise ValueError(
                    f"missing execution contract for {platform}"
                )
            channel_rows = []
            for channel, contract_field in (
                ("configuration", "configuration_oracles"),
                (
                    "provider_native_analysis",
                    "provider_native_oracles",
                ),
                ("authorized_active_probe", "active_probe_transport"),
                ("audit_telemetry", "audit_sources"),
            ):
                existing = candidate["evidence_channels"][channel]
                channel_rows.append({
                    "channel": channel,
                    "status": existing["status"],
                    "accepted_oracles": list(contract[contract_field]),
                    "artifact_bindings": [
                        item["artifact"]
                        for item in existing.get("evidence") or []
                    ],
                    "existing_evidence_ids": [
                        item["evidence_id"]
                        for item in existing.get("evidence") or []
                    ],
                })
            platform_tasks.append({
                "platform": platform,
                "required_tools": list(contract["required_tools"]),
                "channels": channel_rows,
            })
        task_id = "oracle-task-" + sha256(
            candidate["independence_group"].encode("utf-8")
        ).hexdigest()[:20]
        tasks.append({
            "task_id": task_id,
            "independence_group": candidate["independence_group"],
            "category": candidate["category"],
            "source_ids": candidate["source_ids"],
            "case_ids": candidate["case_ids"],
            "selected_oracle_unit": candidate["selected_oracle_unit"],
            "truth_state_before_execution": candidate["truth_state"],
            "expected_truth_state": None,
            "status": "pending",
            "scope_freeze_status": "pending",
            "platform_tasks": platform_tasks,
            "safety": {
                "execution_authorized": False,
                "isolated_environment_verified": False,
                "no_sensitive_data_attested": False,
                "cost_estimate_approved": False,
                "teardown_plan_verified": False,
            },
            "promotion_rule": (
                "all protocol channels and critical-edge bindings must pass "
                "src.oracle_gold.protocol.validate_oracle_registry"
            ),
        })
    tasks.sort(key=lambda item: item["independence_group"])
    platform_counts: dict[str, int] = {}
    required_tools: set[str] = set()
    verified_configuration_groups: set[str] = set()
    verified_telemetry_artifact_groups: set[str] = set()
    for task in tasks:
        for platform_task in task["platform_tasks"]:
            platform = platform_task["platform"]
            platform_counts[platform] = (
                platform_counts.get(platform, 0) + 1
            )
            required_tools.update(platform_task["required_tools"])
            if any(
                channel["channel"] == "configuration"
                and channel["status"] == "verified"
                for channel in platform_task["channels"]
            ):
                verified_configuration_groups.add(
                    task["independence_group"]
                )
            if any(
                channel["channel"] == "audit_telemetry"
                and channel["status"] == "artifact_verified"
                for channel in platform_task["channels"]
            ):
                verified_telemetry_artifact_groups.add(
                    task["independence_group"]
                )
    return {
        "queue_version": "1.0.0",
        "queue_kind": "executable_oracle_evidence_collection",
        "status": "execution_disabled_pending_isolated_credentials",
        "bindings": {
            "oracle_registry": _binding(root, registry_path),
            "execution_policy": _binding(root, policy_path),
        },
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "expected_outcomes_exposed": False,
            "execution_default": policy["execution_default"],
            "authorization_sentinel": dict(
                policy["authorization_sentinel"]
            ),
            "production_accounts_forbidden": True,
            "configuration_only_cannot_promote": True,
        },
        "summary": {
            "pending_independence_groups": len(tasks),
            "platform_task_counts": dict(sorted(platform_counts.items())),
            "required_tools": sorted(required_tools),
            "authorized_tasks": 0,
            "executed_tasks": 0,
            "new_oracle_gold_groups": 0,
            "configuration_verified_groups": len(
                verified_configuration_groups
            ),
            "telemetry_artifact_verified_groups": len(
                verified_telemetry_artifact_groups
            ),
        },
        "tasks": tasks,
    }


def _validate_policy(policy: Mapping[str, Any]) -> None:
    if policy.get("policy_kind") != "isolated_cloud_oracle_execution":
        raise ValueError("wrong Oracle execution policy kind")
    if policy.get("execution_default") != "disabled":
        raise ValueError("Oracle execution must default to disabled")
    safety = policy.get("safety")
    if not isinstance(safety, Mapping):
        raise ValueError("Oracle execution policy lacks safety section")
    for field in (
        "production_accounts_forbidden",
        "require_dedicated_account_subscription_or_project",
        "require_no_sensitive_data",
        "teardown_required",
        "credentials_must_not_enter_artifacts",
    ):
        if safety.get(field) is not True:
            raise ValueError(f"mandatory safety control disabled: {field}")
    evidence_contract = policy.get("evidence_contract")
    if not isinstance(evidence_contract, Mapping):
        raise ValueError("Oracle execution policy lacks evidence contract")
    for field in (
        "raw_stdout_stderr_preserved_when_non_sensitive",
        "value_bearing_raw_responses_must_not_be_persisted",
        "sensitive_fields_removed_before_persistence",
        "sanitized_stdout_stderr_preserved",
        "sha256_required",
        "expected_outcome_hidden_from_agent",
    ):
        if evidence_contract.get(field) is not True:
            raise ValueError(
                f"mandatory evidence control disabled: {field}"
            )
    if set(policy.get("provider_contracts") or {}) != {
        "AWS",
        "AZURE",
        "GCP",
    }:
        raise ValueError("execution policy must define all three clouds")


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {value}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _binding(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }
