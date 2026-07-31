"""Build evaluator-only, outcome-free active-probe contracts."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping


SUPPORTED_AWS_PROBES = {
    (
        "ec2.amazonaws.com:ModifySnapshotAttribute",
        "request.snapshotId",
    ): {
        "provider_action": "ec2:ModifySnapshotAttribute",
        "resource_kind": "ebs_snapshot",
        "resource_id_placeholder": "{{RUN_OWNED_SNAPSHOT_ID}}",
        "resource_arn_template": (
            "arn:{{AWS_PARTITION}}:ec2:{{AWS_REGION}}::"
            "snapshot/{{RUN_OWNED_SNAPSHOT_ID}}"
        ),
        "precheck": [
            "aws",
            "ec2",
            "modify-snapshot-attribute",
            "--snapshot-id",
            "{{RUN_OWNED_SNAPSHOT_ID}}",
            "--attribute",
            "createVolumePermission",
            "--operation-type",
            "add",
            "--user-ids",
            "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}",
            "--dry-run",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ],
        "probe": [
            "aws",
            "ec2",
            "modify-snapshot-attribute",
            "--snapshot-id",
            "{{RUN_OWNED_SNAPSHOT_ID}}",
            "--attribute",
            "createVolumePermission",
            "--operation-type",
            "add",
            "--user-ids",
            "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ],
        "postcondition": [
            "aws",
            "ec2",
            "describe-snapshot-attribute",
            "--snapshot-id",
            "{{RUN_OWNED_SNAPSHOT_ID}}",
            "--attribute",
            "createVolumePermission",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cleanup": [
            "aws",
            "ec2",
            "modify-snapshot-attribute",
            "--snapshot-id",
            "{{RUN_OWNED_SNAPSHOT_ID}}",
            "--attribute",
            "createVolumePermission",
            "--operation-type",
            "remove",
            "--user-ids",
            "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ],
        "cloudtrail_event_name": "ModifySnapshotAttribute",
        "official_cli_reference": (
            "https://docs.aws.amazon.com/cli/latest/reference/ec2/"
            "modify-snapshot-attribute.html"
        ),
        "official_resource_reference": (
            "https://docs.aws.amazon.com/service-authorization/latest/"
            "reference/list_amazonec2.html"
        ),
    },
    (
        "ec2.amazonaws.com:ModifyImageAttribute",
        "request.imageId",
    ): {
        "provider_action": "ec2:ModifyImageAttribute",
        "resource_kind": "ec2_ami",
        "resource_id_placeholder": "{{RUN_OWNED_AMI_ID}}",
        "resource_arn_template": (
            "arn:{{AWS_PARTITION}}:ec2:{{AWS_REGION}}::"
            "image/{{RUN_OWNED_AMI_ID}}"
        ),
        "precheck": [
            "aws",
            "ec2",
            "modify-image-attribute",
            "--image-id",
            "{{RUN_OWNED_AMI_ID}}",
            "--launch-permission",
            "Add=[{UserId={{ISOLATED_COUNTERPART_ACCOUNT_ID}}}]",
            "--dry-run",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ],
        "probe": [
            "aws",
            "ec2",
            "modify-image-attribute",
            "--image-id",
            "{{RUN_OWNED_AMI_ID}}",
            "--launch-permission",
            "Add=[{UserId={{ISOLATED_COUNTERPART_ACCOUNT_ID}}}]",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ],
        "postcondition": [
            "aws",
            "ec2",
            "describe-image-attribute",
            "--image-id",
            "{{RUN_OWNED_AMI_ID}}",
            "--attribute",
            "launchPermission",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cleanup": [
            "aws",
            "ec2",
            "modify-image-attribute",
            "--image-id",
            "{{RUN_OWNED_AMI_ID}}",
            "--launch-permission",
            "Remove=[{UserId={{ISOLATED_COUNTERPART_ACCOUNT_ID}}}]",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ],
        "cloudtrail_event_name": "ModifyImageAttribute",
        "official_cli_reference": (
            "https://docs.aws.amazon.com/cli/latest/reference/ec2/"
            "modify-image-attribute.html"
        ),
        "official_resource_reference": (
            "https://docs.aws.amazon.com/service-authorization/latest/"
            "reference/list_amazonec2.html"
        ),
    },
}


def build_probe_contract_registry(
    root: str | Path,
    *,
    scope_inventory_path: str | Path,
) -> dict[str, Any]:
    """Convert only unambiguous, supported observations into templates."""
    root = Path(root).resolve()
    inventory_path = _resolve_file(root, scope_inventory_path)
    inventory = _read_object(inventory_path)
    if inventory.get("inventory_kind") != (
        "label_free_oracle_scope_candidates"
    ):
        raise ValueError("wrong Oracle scope inventory kind")
    contracts = []
    rejected = []
    for row in inventory.get("candidates") or []:
        match = _supported_match(row)
        if match is None:
            rejected.append({
                "independence_group": row["independence_group"],
                "reason": _rejection_reason(row),
            })
            continue
        resource_prefix, plan = match
        contracts.append(_build_contract(row, resource_prefix, plan))
    contracts.sort(key=lambda item: item["independence_group"])
    rejected.sort(key=lambda item: item["independence_group"])
    return {
        "registry_version": "1.0.0",
        "registry_kind": "outcome_free_oracle_probe_contracts",
        "status": "execution_disabled_requires_runtime_resolution",
        "bindings": {
            "scope_inventory": _binding(root, inventory_path),
        },
        "policy": {
            "evaluator_only": True,
            "contains_truth_labels": False,
            "contains_expected_outcomes": False,
            "historical_resource_ids_reused": False,
            "public_sharing_forbidden": True,
            "shell_interpolation_forbidden": True,
            "argv_execution_only": True,
            "generated_events": 0,
            "generated_labels": 0,
        },
        "summary": {
            "candidate_groups": len(inventory.get("candidates") or []),
            "supported_contracts": len(contracts),
            "unsupported_or_unresolved_groups": len(rejected),
            "platform_counts": {
                platform: sum(
                    item["platform"] == platform for item in contracts
                )
                for platform in ("AWS", "AZURE", "GCP")
            },
        },
        "contracts": contracts,
        "rejected_or_unresolved": rejected,
    }


def _supported_match(
    row: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any]] | None:
    fields = row["scope_fields"]
    if not (
        row.get("all_scope_fields_observed") is True
        and len(fields["actions"]) == 1
        and len(fields["resources"]) == 1
        and len(fields["principals"]) == 1
        and len(fields["network_origins"]) == 1
    ):
        return None
    action = fields["actions"][0]
    resource = fields["resources"][0]
    prefix = resource.split("=", 1)[0]
    plan = SUPPORTED_AWS_PROBES.get((action, prefix))
    return (prefix, plan) if plan is not None else None


def _rejection_reason(row: Mapping[str, Any]) -> str:
    fields = row["scope_fields"]
    if row.get("observation_count") == 0:
        return "no_selected_runtime_observation_or_deployment_required"
    if not row.get("all_scope_fields_observed"):
        return "one_or_more_scope_fields_unresolved"
    if any(
        len(fields[field]) != 1
        for field in (
            "principals",
            "actions",
            "resources",
            "network_origins",
        )
    ):
        return "multi_value_scope_requires_prelabel_terminal_selection"
    return "no_deterministic_safe_probe_adapter"


def _build_contract(
    row: Mapping[str, Any],
    resource_prefix: str,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    group = row["independence_group"]
    contract_id = "probe-contract-" + sha256(
        group.encode("utf-8")
    ).hexdigest()[:20]
    action = plan["provider_action"]
    event_name = plan["cloudtrail_event_name"]
    return {
        "contract_id": contract_id,
        "independence_group": group,
        "platform": row["platform"],
        "selected_oracle_unit": row["selected_oracle_unit"],
        "visibility": "evaluator_only",
        "status": "requires_runtime_resolution",
        "derivation": {
            "observed_action": row["scope_fields"]["actions"][0],
            "observed_resource_field": resource_prefix,
            "selection_rule": (
                "exactly one observed principal/action/resource/network "
                "and an allow-listed deterministic safe adapter"
            ),
            "historical_values_copied_into_runtime_scope": False,
        },
        "runtime_scope_template": {
            "principals": ["{{DEDICATED_PROBE_PRINCIPAL_ARN}}"],
            "actions": [action],
            "resources": [plan["resource_arn_template"]],
            "network_origins": ["{{RUNNER_EGRESS_CIDR}}"],
            "time_window": [
                "{{RUN_STARTED_AT}}",
                "{{RUN_FINISHED_AT}}",
            ],
        },
        "provider_native_analysis": {
            "adapter_id": "aws_iam_simulate_principal_policy_v1",
            "command_argv_template": [
                "aws",
                "iam",
                "simulate-principal-policy",
                "--policy-source-arn",
                "{{DEDICATED_PROBE_PRINCIPAL_ARN}}",
                "--action-names",
                action,
                "--resource-arns",
                plan["resource_arn_template"],
                "--no-paginate",
                "--output",
                "json",
                "--no-cli-pager",
            ],
        },
        "authorized_active_probe": {
            "permission_precheck_argv_template": plan["precheck"],
            "probe_argv_template": plan["probe"],
            "postcondition_argv_template": plan["postcondition"],
            "cleanup_argv_template": plan["cleanup"],
            "dry_run_is_qualifying_runtime_evidence": False,
            "actual_mutation_requires_all_safety_gates": True,
        },
        "audit_telemetry": {
            "adapter_id": "aws_cloudtrail_exact_event_v1",
            "command_argv_template": [
                "aws",
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                f"AttributeKey=EventName,AttributeValue={event_name}",
                "--start-time",
                "{{RUN_STARTED_AT}}",
                "--end-time",
                "{{RUN_FINISHED_AT}}",
                "--region",
                "{{AWS_REGION}}",
                "--output",
                "json",
                "--no-cli-pager",
            ],
            "required_event_predicates": {
                "eventSource": "ec2.amazonaws.com",
                "eventName": event_name,
                "userIdentity.arn": (
                    "{{DEDICATED_PROBE_PRINCIPAL_ARN}}"
                ),
                "sourceIPAddress": "{{RUNNER_EGRESS_IP}}",
                "request_resource_id": (
                    plan["resource_id_placeholder"]
                ),
            },
            "official_reference": (
                "https://docs.aws.amazon.com/awscloudtrail/latest/"
                "userguide/view-cloudtrail-events-cli.html"
            ),
        },
        "safety": {
            "owner_account_must_be_dedicated": True,
            "counterpart_account_must_be_dedicated": True,
            "owner_and_counterpart_accounts_must_differ": True,
            "resource_must_be_created_by_current_run": True,
            "public_group_all_forbidden": True,
            "historical_account_resource_and_ip_values_forbidden": True,
            "cleanup_mandatory": True,
            "post_cleanup_inventory_mandatory": True,
        },
        "controlled_counterfactual_template": {
            "same_runtime_scope_required": True,
            "only_mutation": (
                "attach exact explicit deny for action/resource to "
                "dedicated probe principal"
            ),
            "pair_assignment_frozen_before_execution": True,
            "expected_truth_state": None,
        },
        "official_cli_reference": plan["official_cli_reference"],
        "official_resource_reference": plan[
            "official_resource_reference"
        ],
    }


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
