"""Build evaluator-only, outcome-free active-probe contracts."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping
from zipfile import ZipFile


STRATUS_COMMIT = "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0"
STRATUS_ARCHIVE_RELATIVE = (
    "data/real_sources/raw/stratus_red_team/"
    f"{STRATUS_COMMIT}/snapshot.zip"
)
STRATUS_ARCHIVE_SHA256 = (
    "fa2ad67871887a55f226f875a9c339b7e12987b83aa5a951631ce9f5036d0480"
)
STRATUS_PREFIX = f"stratus-red-team-{STRATUS_COMMIT}"


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


def _stratus_members(
    technique: str,
    source_directory: str | None = None,
) -> tuple[str, ...]:
    directory = source_directory or technique.rsplit(".", 1)[-1]
    tactic = technique.split(".")[1]
    return (
        f"{STRATUS_PREFIX}/docs/attack-techniques/AWS/{technique}.md",
        f"{STRATUS_PREFIX}/docs/detonation-logs/{technique}.json",
        (
            f"{STRATUS_PREFIX}/v2/internal/attacktechniques/aws/"
            f"{tactic}/{directory}/main.go"
        ),
        (
            f"{STRATUS_PREFIX}/v2/internal/attacktechniques/aws/"
            f"{tactic}/{directory}/main.tf"
        ),
    )


STRATUS_IMPLEMENTATION_MEMBERS = {
    "stratus-technique:T1578.001": _stratus_members(
        "aws.exfiltration.ec2-share-ebs-snapshot"
    ),
    (
        "stratus_red_team:stratus:"
        "aws.exfiltration.ec2-share-ami"
    ): _stratus_members("aws.exfiltration.ec2-share-ami"),
}


STRATUS_BOUNDED_READ_PROBES = {
    (
        "stratus_red_team:stratus:"
        "aws.credential-access.secretsmanager-retrieve-secrets"
    ): {
        "technique": (
            "aws.credential-access.secretsmanager-retrieve-secrets"
        ),
        "provider_actions": ["secretsmanager:GetSecretValue"],
        "resource_arn_templates": [
            "{{RUN_OWNED_SECRET_ARN}}",
        ],
        "setup_argv_templates": [[
            "aws",
            "secretsmanager",
            "create-secret",
            "--cli-input-json",
            "file://{{EVALUATOR_PRIVATE_CREATE_SECRET_JSON}}",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ]],
        "probe_argv_template": [
            "aws",
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            "{{RUN_OWNED_SECRET_ARN}}",
            "--query",
            (
                "{ARN:ARN,Name:Name,VersionId:VersionId,"
                "VersionStages:VersionStages}"
            ),
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "postcondition_argv_template": [
            "aws",
            "secretsmanager",
            "describe-secret",
            "--secret-id",
            "{{RUN_OWNED_SECRET_ARN}}",
            "--query",
            "{ARN:ARN,Name:Name,Tags:Tags,DeletedDate:DeletedDate}",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cleanup_argv_templates": [[
            "aws",
            "secretsmanager",
            "delete-secret",
            "--secret-id",
            "{{RUN_OWNED_SECRET_ARN}}",
            "--force-delete-without-recovery",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ]],
        "post_cleanup_inventory_argv_template": [
            "aws",
            "secretsmanager",
            "describe-secret",
            "--secret-id",
            "{{RUN_OWNED_SECRET_ARN}}",
            "--query",
            "{ARN:ARN,Name:Name,DeletedDate:DeletedDate}",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cloudtrail_event_name": "GetSecretValue",
        "request_resource_predicate": {
            "requestParameters.secretId": "{{RUN_OWNED_SECRET_ARN}}",
        },
        "sensitive_json_pointers": [
            "/SecretString",
            "/SecretBinary",
        ],
        "official_references": [
            (
                "https://docs.aws.amazon.com/secretsmanager/latest/"
                "userguide/retrieving-secrets_cli.html"
            ),
            (
                "https://docs.aws.amazon.com/secretsmanager/latest/"
                "userguide/monitoring-cloudtrail.html"
            ),
        ],
    },
    (
        "stratus_red_team:stratus:"
        "aws.credential-access.secretsmanager-batch-retrieve-secrets"
    ): {
        "technique": (
            "aws.credential-access.secretsmanager-batch-retrieve-secrets"
        ),
        "provider_actions": [
            "secretsmanager:BatchGetSecretValue",
            "secretsmanager:GetSecretValue",
        ],
        "resource_arn_templates": [
            "{{RUN_OWNED_SECRET_1_ARN}}",
            "{{RUN_OWNED_SECRET_2_ARN}}",
        ],
        "setup_argv_templates": [
            [
                "aws",
                "secretsmanager",
                "create-secret",
                "--cli-input-json",
                "file://{{EVALUATOR_PRIVATE_CREATE_SECRET_1_JSON}}",
                "--region",
                "{{AWS_REGION}}",
                "--no-cli-pager",
            ],
            [
                "aws",
                "secretsmanager",
                "create-secret",
                "--cli-input-json",
                "file://{{EVALUATOR_PRIVATE_CREATE_SECRET_2_JSON}}",
                "--region",
                "{{AWS_REGION}}",
                "--no-cli-pager",
            ],
        ],
        "probe_argv_template": [
            "aws",
            "secretsmanager",
            "batch-get-secret-value",
            "--secret-id-list",
            "{{RUN_OWNED_SECRET_1_ARN}}",
            "{{RUN_OWNED_SECRET_2_ARN}}",
            "--query",
            (
                "{SecretValues:SecretValues[].{ARN:ARN,Name:Name,"
                "VersionId:VersionId},Errors:Errors[].{"
                "SecretId:SecretId,ErrorCode:ErrorCode}}"
            ),
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "postcondition_argv_template": [
            "aws",
            "secretsmanager",
            "list-secrets",
            "--filters",
            "Key=tag-key,Values=pathbench-run",
            "Key=tag-value,Values={{RUN_ID}}",
            "--query",
            "SecretList[].{ARN:ARN,Name:Name,Tags:Tags}",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cleanup_argv_templates": [
            [
                "aws",
                "secretsmanager",
                "delete-secret",
                "--secret-id",
                "{{RUN_OWNED_SECRET_1_ARN}}",
                "--force-delete-without-recovery",
                "--region",
                "{{AWS_REGION}}",
                "--no-cli-pager",
            ],
            [
                "aws",
                "secretsmanager",
                "delete-secret",
                "--secret-id",
                "{{RUN_OWNED_SECRET_2_ARN}}",
                "--force-delete-without-recovery",
                "--region",
                "{{AWS_REGION}}",
                "--no-cli-pager",
            ],
        ],
        "post_cleanup_inventory_argv_template": [
            "aws",
            "secretsmanager",
            "list-secrets",
            "--include-planned-deletion",
            "--filters",
            "Key=tag-key,Values=pathbench-run",
            "Key=tag-value,Values={{RUN_ID}}",
            "--query",
            "SecretList[].{ARN:ARN,Name:Name,DeletedDate:DeletedDate}",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cloudtrail_event_name": "BatchGetSecretValue",
        "request_resource_predicate": {
            "requestParameters.secretIdList": [
                "{{RUN_OWNED_SECRET_1_ARN}}",
                "{{RUN_OWNED_SECRET_2_ARN}}",
            ],
        },
        "sensitive_json_pointers": [
            "/SecretValues/*/SecretString",
            "/SecretValues/*/SecretBinary",
        ],
        "official_references": [
            (
                "https://docs.aws.amazon.com/cli/latest/reference/"
                "secretsmanager/batch-get-secret-value.html"
            ),
            (
                "https://docs.aws.amazon.com/secretsmanager/latest/"
                "userguide/monitoring-cloudtrail.html"
            ),
        ],
    },
    (
        "stratus_red_team:stratus:"
        "aws.credential-access.ssm-retrieve-securestring-parameters"
    ): {
        "technique": (
            "aws.credential-access.ssm-retrieve-securestring-parameters"
        ),
        "provider_actions": ["ssm:GetParameters"],
        "resource_arn_templates": [
            (
                "arn:{{AWS_PARTITION}}:ssm:{{AWS_REGION}}:"
                "{{DEDICATED_OWNER_ACCOUNT_ID}}:parameter/"
                "pathbench/{{RUN_ID}}/canary"
            ),
        ],
        "setup_argv_templates": [[
            "aws",
            "ssm",
            "put-parameter",
            "--cli-input-json",
            "file://{{EVALUATOR_PRIVATE_PUT_PARAMETER_JSON}}",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ]],
        "probe_argv_template": [
            "aws",
            "ssm",
            "get-parameters",
            "--names",
            "/pathbench/{{RUN_ID}}/canary",
            "--with-decryption",
            "--query",
            (
                "{Parameters:Parameters[].{Name:Name,Type:Type,"
                "Version:Version,ARN:ARN,DataType:DataType},"
                "InvalidParameters:InvalidParameters}"
            ),
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "postcondition_argv_template": [
            "aws",
            "ssm",
            "describe-parameters",
            "--parameter-filters",
            (
                "Key=Name,Option=Equals,"
                "Values=/pathbench/{{RUN_ID}}/canary"
            ),
            "--query",
            (
                "Parameters[].{Name:Name,Type:Type,Version:Version,"
                "DataType:DataType}"
            ),
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cleanup_argv_templates": [[
            "aws",
            "ssm",
            "delete-parameter",
            "--name",
            "/pathbench/{{RUN_ID}}/canary",
            "--region",
            "{{AWS_REGION}}",
            "--no-cli-pager",
        ]],
        "post_cleanup_inventory_argv_template": [
            "aws",
            "ssm",
            "describe-parameters",
            "--parameter-filters",
            (
                "Key=Name,Option=Equals,"
                "Values=/pathbench/{{RUN_ID}}/canary"
            ),
            "--query",
            "Parameters[].{Name:Name,Type:Type}",
            "--region",
            "{{AWS_REGION}}",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        "cloudtrail_event_name": "GetParameters",
        "request_resource_predicate": {
            "requestParameters.names": [
                "/pathbench/{{RUN_ID}}/canary",
            ],
            "requestParameters.withDecryption": True,
        },
        "sensitive_json_pointers": [
            "/Parameters/*/Value",
        ],
        "official_references": [
            (
                "https://docs.aws.amazon.com/cli/latest/reference/"
                "ssm/get-parameters.html"
            ),
            (
                "https://docs.aws.amazon.com/cli/latest/reference/"
                "ssm/put-parameter.html"
            ),
        ],
    },
}

for _group, _plan in STRATUS_BOUNDED_READ_PROBES.items():
    STRATUS_IMPLEMENTATION_MEMBERS[_group] = _stratus_members(
        _plan["technique"]
    )


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
    stratus_archive = _resolve_file(root, STRATUS_ARCHIVE_RELATIVE)
    stratus_archive_binding = _binding(root, stratus_archive)
    if stratus_archive_binding["sha256"] != STRATUS_ARCHIVE_SHA256:
        raise ValueError("pinned Stratus archive SHA-256 mismatch")
    implementation_bindings = _load_implementation_bindings(
        stratus_archive
    )
    contracts = []
    rejected = []
    for row in inventory.get("candidates") or []:
        bounded_read_plan = STRATUS_BOUNDED_READ_PROBES.get(
            row["independence_group"]
        )
        if bounded_read_plan is not None:
            contracts.append(_build_bounded_read_contract(
                row,
                bounded_read_plan,
                implementation_bindings[row["independence_group"]],
            ))
            continue
        match = _supported_match(row)
        if match is None:
            rejected.append({
                "independence_group": row["independence_group"],
                "reason": _rejection_reason(row),
            })
            continue
        resource_prefix, plan = match
        contract = _build_contract(row, resource_prefix, plan)
        contract["upstream_implementation"] = (
            implementation_bindings[row["independence_group"]]
        )
        contracts.append(contract)
    contracts.sort(key=lambda item: item["independence_group"])
    rejected.sort(key=lambda item: item["independence_group"])
    return {
        "registry_version": "1.0.0",
        "registry_kind": "outcome_free_oracle_probe_contracts",
        "status": "execution_disabled_requires_runtime_resolution",
        "bindings": {
            "scope_inventory": _binding(root, inventory_path),
            "stratus_archive": stratus_archive_binding,
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


def _build_bounded_read_contract(
    row: Mapping[str, Any],
    plan: Mapping[str, Any],
    implementation_binding: Mapping[str, Any],
) -> dict[str, Any]:
    group = row["independence_group"]
    contract_id = "probe-contract-" + sha256(
        group.encode("utf-8")
    ).hexdigest()[:20]
    actions = plan["provider_actions"]
    resources = plan["resource_arn_templates"]
    native_commands = []
    for action in actions:
        native_commands.append([
            "aws",
            "iam",
            "simulate-principal-policy",
            "--policy-source-arn",
            "{{DEDICATED_PROBE_PRINCIPAL_ARN}}",
            "--action-names",
            action,
            "--resource-arns",
            *resources,
            "--no-paginate",
            "--output",
            "json",
            "--no-cli-pager",
        ])
    predicates = {
        "eventSource": (
            "ssm.amazonaws.com"
            if actions[0].startswith("ssm:")
            else "secretsmanager.amazonaws.com"
        ),
        "eventName": plan["cloudtrail_event_name"],
        "userIdentity.arn": "{{DEDICATED_PROBE_PRINCIPAL_ARN}}",
        "sourceIPAddress": "{{RUNNER_EGRESS_IP}}",
        **plan["request_resource_predicate"],
    }
    return {
        "contract_id": contract_id,
        "independence_group": group,
        "platform": row["platform"],
        "selected_oracle_unit": row["selected_oracle_unit"],
        "visibility": "evaluator_only",
        "status": "requires_runtime_resolution",
        "derivation": {
            "upstream_technique": plan["technique"],
            "observed_actions": row["scope_fields"]["actions"],
            "terminal_actions_selected": actions,
            "selection_rule": (
                "pinned Stratus terminal read narrowed to explicit "
                "current-run resources with a value-redacting CLI query"
            ),
            "upstream_behavior_narrowed": True,
            "narrowing_does_not_reproduce": (
                "account-wide enumeration or high-volume collection"
            ),
            "historical_values_copied_into_runtime_scope": False,
        },
        "upstream_implementation": implementation_binding,
        "runtime_scope_template": {
            "principals": ["{{DEDICATED_PROBE_PRINCIPAL_ARN}}"],
            "actions": actions,
            "resources": resources,
            "network_origins": ["{{RUNNER_EGRESS_CIDR}}"],
            "time_window": [
                "{{RUN_STARTED_AT}}",
                "{{RUN_FINISHED_AT}}",
            ],
        },
        "provider_native_analysis": {
            "adapter_id": "aws_iam_simulate_principal_policy_v1",
            "command_argv_templates": native_commands,
            "all_terminal_actions_must_be_evaluated": True,
        },
        "evaluator_setup": {
            "command_argv_templates": plan["setup_argv_templates"],
            "private_cli_input_files_must_be_mode_0600": True,
            "private_cli_input_files_deleted_after_setup": True,
            "canary_contains_no_real_credentials_or_personal_data": True,
            "resource_tags_required": {
                "pathbench-run": "{{RUN_ID}}",
            },
        },
        "authorized_active_probe": {
            "probe_argv_template": plan["probe_argv_template"],
            "postcondition_argv_template": plan[
                "postcondition_argv_template"
            ],
            "cleanup_argv_templates": plan["cleanup_argv_templates"],
            "post_cleanup_inventory_argv_template": plan[
                "post_cleanup_inventory_argv_template"
            ],
            "dry_run_available": False,
            "dry_run_is_qualifying_runtime_evidence": False,
            "actual_call_requires_all_safety_gates": True,
        },
        "sensitive_response_handling": {
            "upstream_stdout_behavior_reused": False,
            "secret_values_may_be_logged": False,
            "cli_query_excludes_sensitive_values": True,
            "defense_in_depth_json_pointers_to_drop": plan[
                "sensitive_json_pointers"
            ],
            "raw_stdout_persistence_forbidden": True,
            "agent_visibility": "none",
            "retained_fields": (
                "resource identifiers, versions, API status and "
                "error codes only"
            ),
        },
        "audit_telemetry": {
            "adapter_id": "aws_cloudtrail_exact_event_v1",
            "command_argv_template": [
                "aws",
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                (
                    "AttributeKey=EventName,AttributeValue="
                    + plan["cloudtrail_event_name"]
                ),
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
            "required_event_predicates": predicates,
            "official_reference": (
                "https://docs.aws.amazon.com/awscloudtrail/latest/"
                "userguide/view-cloudtrail-events-cli.html"
            ),
        },
        "safety": {
            "owner_account_must_be_dedicated": True,
            "resource_must_be_created_by_current_run": True,
            "explicit_resource_identifiers_only": True,
            "public_group_all_forbidden": True,
            "account_wide_enumeration_forbidden": True,
            "upstream_high_volume_behavior_forbidden": True,
            "historical_account_resource_and_ip_values_forbidden": True,
            "real_secret_material_forbidden": True,
            "cleanup_mandatory": True,
            "post_cleanup_inventory_mandatory": True,
        },
        "controlled_counterfactual_template": {
            "same_runtime_scope_required": True,
            "only_mutation": (
                "attach exact explicit deny for every terminal "
                "action/resource to the dedicated probe principal"
            ),
            "pair_assignment_frozen_before_execution": True,
            "expected_truth_state": None,
        },
        "official_references": plan["official_references"],
    }


def _load_implementation_bindings(
    archive_path: Path,
) -> dict[str, Any]:
    with ZipFile(archive_path) as archive:
        available = set(archive.namelist())
        result = {}
        for group, member_paths in (
            STRATUS_IMPLEMENTATION_MEMBERS.items()
        ):
            bindings = []
            for member_path in member_paths:
                if member_path not in available:
                    raise ValueError(
                        f"missing Stratus implementation: {member_path}"
                    )
                data = archive.read(member_path)
                bindings.append({
                    "member_path": member_path,
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                })
            result[group] = {
                "source_id": "stratus_red_team",
                "repository": "DataDog/stratus-red-team",
                "commit": STRATUS_COMMIT,
                "archive_sha256": STRATUS_ARCHIVE_SHA256,
                "members": bindings,
                "source_code_executed_by_contract_builder": False,
            }
    return result


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
