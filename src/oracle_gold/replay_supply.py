"""Build a label-free, fail-closed replay-supply inventory."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping


SOURCE_PLANS = {
    "splunk_attack_data": {
        "replay_tier": "published_telemetry_only",
        "artifact_names": ("repository-tree.json",),
        "default_status": (
            "published_telemetry_only_no_authorized_replay_adapter"
        ),
        "required_next_action": (
            "retain as published evidence; build a separate pinned "
            "provider adapter before any new replay"
        ),
    },
    "cross_cloud_observability_2026": {
        "replay_tier": "upstream_native_cli",
        "artifact_names": (
            "README.md",
            "attack_scripts.zip",
            "aws_logs_redacted.zip",
            "azure_logs_redacted.zip",
            "gcp_logs_redacted.zip",
        ),
        "default_status": (
            "blocked_upstream_archive_requires_sanitized_adapter"
        ),
        "required_next_action": (
            "replace upstream scripts with least-privilege argv-only "
            "adapters and repeat static safety audit"
        ),
    },
    "stratus_red_team": {
        "replay_tier": "upstream_native_cli",
        "artifact_names": ("snapshot.zip",),
        "default_status": (
            "pinned_supply_available_source_specific_audit_pending"
        ),
        "required_next_action": (
            "audit the exact technique implementation and wrap only "
            "run-owned resources"
        ),
    },
    "cloudgoat": {
        "replay_tier": "pinned_iac_lab",
        "artifact_names": ("snapshot.zip",),
    },
    "awsgoat": {
        "replay_tier": "pinned_iac_lab",
        "artifact_names": ("snapshot.zip",),
    },
    "azuregoat": {
        "replay_tier": "pinned_iac_lab",
        "artifact_names": ("snapshot.zip",),
    },
    "gcpgoat": {
        "replay_tier": "pinned_iac_lab",
        "artifact_names": ("snapshot.zip",),
    },
    "terragoat": {
        "replay_tier": "pinned_iac_lab",
        "artifact_names": ("snapshot.zip",),
    },
    "cloudfoxable": {
        "replay_tier": "pinned_iac_lab",
        "artifact_names": ("snapshot.zip",),
    },
}
DEFAULT_IAC_STATUS = (
    "pinned_supply_available_source_specific_audit_pending"
)
DEFAULT_IAC_NEXT_ACTION = (
    "audit deploy/destroy modules, constrain costs and resource ownership, "
    "then register a source-specific adapter"
)


def build_replay_supply_inventory(
    root: str | Path,
    *,
    acquisition_manifest_path: str | Path,
    oracle_registry_path: str | Path,
    probe_contracts_path: str | Path,
    replay_safety_audit_path: str | Path,
) -> dict[str, Any]:
    """Map every frozen lineage to real source supply without authorizing it."""
    root = Path(root).resolve()
    acquisition_path = _resolve_file(root, acquisition_manifest_path)
    registry_path = _resolve_file(root, oracle_registry_path)
    probes_path = _resolve_file(root, probe_contracts_path)
    safety_path = _resolve_file(root, replay_safety_audit_path)
    acquisition = _read_object(acquisition_path)
    registry = _read_object(registry_path)
    probes = _read_object(probes_path)
    safety = _read_object(safety_path)
    _validate_inputs(registry, probes, safety)

    source_index = {
        item["source_id"]: item
        for item in acquisition.get("sources") or []
    }
    candidate_source_ids = {
        source_id
        for candidate in registry.get("candidates") or []
        for source_id in candidate.get("source_ids") or []
    }
    unknown = sorted(candidate_source_ids - set(SOURCE_PLANS))
    if unknown:
        raise ValueError(f"no replay-supply policy for sources: {unknown}")

    source_supplies = {
        source_id: _source_supply(
            root,
            source_id=source_id,
            source=source_index.get(source_id),
            safety=safety,
        )
        for source_id in sorted(candidate_source_ids)
    }
    contract_index = {
        item["independence_group"]: item
        for item in probes.get("contracts") or []
    }
    lineages = []
    for candidate in registry.get("candidates") or []:
        source_ids = candidate.get("source_ids") or []
        if len(source_ids) != 1:
            raise ValueError(
                "each frozen lineage must have exactly one source: "
                f"{candidate.get('independence_group')}"
            )
        selected = candidate.get("selected_oracle_unit")
        if not isinstance(selected, dict):
            raise ValueError("selected Oracle unit is missing")
        source_id = source_ids[0]
        supply = source_supplies[source_id]
        group = candidate["independence_group"]
        contract = contract_index.get(group)
        status = supply["default_lineage_status"]
        next_action = supply["required_next_action"]
        contract_binding = None
        if contract is not None:
            status = (
                "safe_adapter_contract_registered_execution_disabled"
            )
            next_action = (
                "resolve current-run placeholders, pass every authorization "
                "gate, then execute through the evaluator"
            )
            contract_binding = {
                "contract_id": contract["contract_id"],
                "contract_registry_path": (
                    probes_path.relative_to(root).as_posix()
                ),
                "contract_registry_sha256": _binding(
                    root, probes_path
                )["sha256"],
            }
        lineages.append({
            "independence_group": group,
            "category": candidate["category"],
            "source_id": source_id,
            "platform": selected["platform"],
            "selected_oracle_unit_id": selected["unit_id"],
            "selected_oracle_unit_digest": selected[
                "selection_digest"
            ],
            "replay_tier": supply["replay_tier"],
            "supply_status": status,
            "eligible_for_execution": False,
            "authorization_granted": False,
            "source_supply_id": supply["source_supply_id"],
            "safe_probe_contract": contract_binding,
            "required_next_action": next_action,
        })
    lineages.sort(key=lambda item: item["independence_group"])
    _require_exact_contract_coverage(contract_index, lineages)

    by_tier = Counter(item["replay_tier"] for item in lineages)
    by_status = Counter(item["supply_status"] for item in lineages)
    by_platform = Counter(item["platform"] for item in lineages)
    return {
        "inventory_version": "1.0.0",
        "inventory_kind": "label_free_replay_supply_inventory",
        "status": "execution_disabled_fail_closed",
        "bindings": {
            "acquisition_manifest": _binding(root, acquisition_path),
            "oracle_registry": _binding(root, registry_path),
            "probe_contracts": _binding(root, probes_path),
            "cross_cloud_replay_safety_audit": _binding(
                root, safety_path
            ),
        },
        "policy": {
            "contains_truth_labels": False,
            "contains_expected_outcomes": False,
            "source_supply_implies_reachability": False,
            "static_scan_authorizes_execution": False,
            "safe_contract_authorizes_execution": False,
            "authorization_default": False,
            "selected_unit_frozen_before_gold": True,
            "upstream_code_executed_while_building_inventory": False,
            "generated_events": 0,
            "generated_labels": 0,
        },
        "summary": {
            "lineage_count": len(lineages),
            "source_supply_count": len(source_supplies),
            "safe_probe_contract_count": sum(
                item["safe_probe_contract"] is not None
                for item in lineages
            ),
            "execution_eligible_count": sum(
                item["eligible_for_execution"] for item in lineages
            ),
            "lineage_counts_by_replay_tier": dict(
                sorted(by_tier.items())
            ),
            "lineage_counts_by_supply_status": dict(
                sorted(by_status.items())
            ),
            "lineage_counts_by_platform": dict(
                sorted(by_platform.items())
            ),
        },
        "source_supplies": [
            source_supplies[source_id]
            for source_id in sorted(source_supplies)
        ],
        "lineages": lineages,
    }


def _source_supply(
    root: Path,
    *,
    source_id: str,
    source: Mapping[str, Any] | None,
    safety: Mapping[str, Any],
) -> dict[str, Any]:
    if source is None:
        raise ValueError(f"source absent from acquisition manifest: {source_id}")
    plan = SOURCE_PLANS[source_id]
    artifacts = {
        item["name"]: item
        for item in source.get("artifacts") or []
    }
    selected_artifacts = []
    for name in plan["artifact_names"]:
        artifact = artifacts.get(name)
        if artifact is None:
            raise ValueError(f"{source_id} is missing artifact {name}")
        path = _resolve_file(root, artifact["relative_path"])
        binding = _binding(root, path)
        if artifact.get("status") != "verified":
            raise ValueError(f"artifact not verified: {source_id}/{name}")
        for field in ("bytes", "sha256"):
            if artifact.get(field) != binding[field]:
                raise ValueError(
                    f"artifact {field} mismatch: {source_id}/{name}"
                )
        selected_artifacts.append({
            "name": name,
            **binding,
            "url": artifact.get("url"),
        })
    status = plan.get("default_status", DEFAULT_IAC_STATUS)
    next_action = plan.get(
        "required_next_action",
        DEFAULT_IAC_NEXT_ACTION,
    )
    safety_binding = None
    if source_id == "cross_cloud_observability_2026":
        if safety.get("source_id") != source_id:
            raise ValueError("cross-cloud safety audit source mismatch")
        if safety.get("summary", {}).get(
            "direct_execution_eligible"
        ) is not False:
            raise ValueError(
                "cross-cloud source must remain blocked by current audit"
            )
        safety_binding = {
            "audit_status": safety["status"],
            "blocking_finding_count": safety["summary"][
                "blocking_finding_count"
            ],
        }
    supply_id = "source-supply-" + sha256(
        (
            source_id
            + "\0"
            + str(source.get("commit"))
            + "\0"
            + "\0".join(
                item["sha256"] for item in selected_artifacts
            )
        ).encode("utf-8")
    ).hexdigest()[:20]
    return {
        "source_supply_id": supply_id,
        "source_id": source_id,
        "repository": source.get("repository"),
        "commit": source.get("commit"),
        "replay_tier": plan["replay_tier"],
        "default_lineage_status": status,
        "eligible_for_direct_execution": False,
        "authorization_granted": False,
        "artifacts": selected_artifacts,
        "safety_audit": safety_binding,
        "required_next_action": next_action,
    }


def _validate_inputs(
    registry: Mapping[str, Any],
    probes: Mapping[str, Any],
    safety: Mapping[str, Any],
) -> None:
    if registry.get("registry_kind") != "executable_oracle_gold":
        raise ValueError("wrong Oracle registry kind")
    if probes.get("registry_kind") != (
        "outcome_free_oracle_probe_contracts"
    ):
        raise ValueError("wrong probe-contract registry kind")
    if safety.get("audit_kind") != (
        "static_replay_supply_safety_audit"
    ):
        raise ValueError("wrong replay-safety audit kind")


def _require_exact_contract_coverage(
    contracts: Mapping[str, Any],
    lineages: list[Mapping[str, Any]],
) -> None:
    groups = {item["independence_group"] for item in lineages}
    unknown = sorted(set(contracts) - groups)
    if unknown:
        raise ValueError(f"probe contracts reference unknown lineages: {unknown}")


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
