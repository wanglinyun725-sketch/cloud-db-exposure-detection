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
CONFIGURATION_PACKET_RELATIVE = (
    "data/real_sources/annotation/"
    "configuration_supplemental_10_unlabeled.json"
)
GCPGOAT_POLICY_TRANSITION_GROUP = (
    "configuration-lineage:gcpgoat:"
    "gcpgoat_anonymous_bucket_policy_transition"
)
AZUREGOAT_BLOB_CONTROL_PAIR_GROUP = (
    "configuration-lineage:azuregoat:"
    "azuregoat_prod_dev_blob_control_pair"
)


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
        "post_cleanup_inventory": [
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
        "post_cleanup_inventory": [
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
        "setup_output_bindings": [{
            "placeholder": "RUN_OWNED_SECRET_ARN",
            "source_template_path": (
                "evaluator_setup.command_argv_templates[0]"
            ),
            "json_pointer": "/ARN",
            "validator_id": "aws_secretsmanager_secret_arn_v1",
            "run_owned": True,
            "sensitive": False,
        }],
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
        "setup_output_bindings": [
            {
                "placeholder": "RUN_OWNED_SECRET_1_ARN",
                "source_template_path": (
                    "evaluator_setup.command_argv_templates[0]"
                ),
                "json_pointer": "/ARN",
                "validator_id": "aws_secretsmanager_secret_arn_v1",
                "run_owned": True,
                "sensitive": False,
            },
            {
                "placeholder": "RUN_OWNED_SECRET_2_ARN",
                "source_template_path": (
                    "evaluator_setup.command_argv_templates[1]"
                ),
                "json_pointer": "/ARN",
                "validator_id": "aws_secretsmanager_secret_arn_v1",
                "run_owned": True,
                "sensitive": False,
            },
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
                "{{DEDICATED_OWNER_ACCOUNT_ID}}:parameter"
                "{{RUN_OWNED_PARAMETER_NAME}}"
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
            "{{RUN_OWNED_PARAMETER_NAME}}",
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
                "Values={{RUN_OWNED_PARAMETER_NAME}}"
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
            "{{RUN_OWNED_PARAMETER_NAME}}",
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
                "Values={{RUN_OWNED_PARAMETER_NAME}}"
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
                "{{RUN_OWNED_PARAMETER_NAME}}",
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
    configuration_packet_path = _resolve_file(
        root, CONFIGURATION_PACKET_RELATIVE
    )
    configuration_packet = _read_object(configuration_packet_path)
    configuration_bindings = _load_configuration_bindings(
        root, configuration_packet
    )
    contracts = []
    rejected = []
    for row in inventory.get("candidates") or []:
        if row["independence_group"] == AZUREGOAT_BLOB_CONTROL_PAIR_GROUP:
            contracts.append(_build_azure_blob_control_pair_contract(
                row,
                configuration_bindings[
                    row["selected_oracle_unit"]["case_id"]
                ],
            ))
            continue
        if row["independence_group"] == GCPGOAT_POLICY_TRANSITION_GROUP:
            contracts.append(_build_gcp_policy_transition_contract(
                row,
                configuration_bindings[
                    row["selected_oracle_unit"]["case_id"]
                ],
            ))
            continue
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
            "configuration_packet": _binding(
                root, configuration_packet_path
            ),
        },
        "policy": {
            "evaluator_only": True,
            "contains_truth_labels": False,
            "contains_expected_outcomes": False,
            "historical_resource_ids_reused": False,
            "unbounded_public_sharing_forbidden": True,
            "public_sharing_requires_explicit_bounded_adapter": True,
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
            "post_cleanup_inventory_argv_template": plan[
                "post_cleanup_inventory"
            ],
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
    return _finish_bounded_read_contract(
        row=row,
        plan=plan,
        implementation_binding=implementation_binding,
        group=group,
        contract_id=contract_id,
        actions=actions,
        resources=resources,
        native_commands=native_commands,
        predicates=predicates,
    )


def _build_azure_blob_control_pair_contract(
    row: Mapping[str, Any],
    implementation_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a minimal, audit-visible AzureGoat Blob control pair.

    The pinned lab deploys many unrelated and costly resources.  This
    contract reproduces only its literal ``blob`` versus ``container``
    access-level pair in a fresh storage account.  It never executes the
    upstream Terraform and never copies upstream payload data.
    """
    group = row["independence_group"]
    contract_id = "probe-contract-" + sha256(
        group.encode("utf-8")
    ).hexdigest()[:20]
    account = "{{RUN_OWNED_AZURE_STORAGE_ACCOUNT}}"
    resource_group = "{{RUN_OWNED_AZURE_RESOURCE_GROUP}}"
    prod = "{{RUN_OWNED_AZURE_PROD_CONTAINER}}"
    dev = "{{RUN_OWNED_AZURE_DEV_CONTAINER}}"
    blob = "{{RUN_OWNED_AZURE_CANARY_BLOB}}"
    subscription = "{{AZURE_SUBSCRIPTION_ID}}"
    account_id = (
        "/subscriptions/{{AZURE_SUBSCRIPTION_ID}}/resourceGroups/"
        "{{RUN_OWNED_AZURE_RESOURCE_GROUP}}/providers/Microsoft.Storage/"
        "storageAccounts/{{RUN_OWNED_AZURE_STORAGE_ACCOUNT}}"
    )
    blob_service_id = account_id + "/blobServices/default"
    prod_url = f"https://{account}.blob.core.windows.net/{prod}"
    dev_url = f"https://{account}.blob.core.windows.net/{dev}"
    prod_blob_url = prod_url + f"/{blob}"
    dev_blob_url = dev_url + f"/{blob}"
    az_common = [
        "--subscription", subscription,
        "--output", "json",
        "--only-show-errors",
    ]
    storage_common = [
        "--account-name", account,
        "--auth-mode", "key",
        *az_common,
    ]
    diagnostic_logs = json.dumps([
        {"category": "StorageRead", "enabled": True},
        {"category": "StorageWrite", "enabled": True},
        {"category": "StorageDelete", "enabled": True},
    ], separators=(",", ":"))

    def anonymous_get(
        url: str,
        request_id: str,
        *,
        one_byte: bool = False,
    ) -> list[str]:
        argv = [
            "curl", "--disable", "--silent", "--show-error",
            "--noproxy", "*", "--proto", "=https",
            "--tlsv1.2", "--connect-timeout", "10",
            "--max-time", "30", "--max-redirs", "0",
            "--request", "GET",
            "--header", "x-ms-version: 2023-11-03",
            "--header", f"x-ms-client-request-id: {request_id}",
            "--user-agent", "CloudDB-PathBench-Oracle/1.0",
        ]
        if one_byte:
            argv.extend(["--range", "0-0"])
        argv.extend([
            "--output", "{{ORACLE_NULL_SINK}}",
            "--write-out",
            (
                '{"http_code":"%{http_code}",'
                '"remote_ip":"%{remote_ip}",'
                '"num_redirects":%{num_redirects},'
                '"size_download":%{size_download},'
                '"time_total":%{time_total}}\\n'
            ),
            "--url", url,
        ])
        return argv

    prod_list_url = prod_url + "?restype=container&comp=list&maxresults=1"
    dev_list_url = dev_url + "?restype=container&comp=list&maxresults=1"
    kql = (
        "StorageBlobLogs "
        "| where TimeGenerated between "
        "(datetime({{RUN_STARTED_AT}}) .. datetime({{RUN_FINISHED_AT}})) "
        f'| where AccountName == "{account}" '
        '| where AuthenticationType == "Anonymous" '
        f'| where CallerIpAddress startswith "{{{{RUNNER_EGRESS_IP}}}}" '
        "| where ClientRequestId in "
        "(\"{{AZURE_PROD_GET_CLIENT_REQUEST_ID}}\","
        "\"{{AZURE_DEV_LIST_CLIENT_REQUEST_ID}}\","
        "\"{{AZURE_DEV_GET_CLIENT_REQUEST_ID}}\") "
        "| project TimeGenerated, AccountName, AuthenticationType, "
        "CallerIpAddress, ClientRequestId, OperationName, StatusCode, "
        "StatusText, Uri, CorrelationId, TlsVersion "
        "| order by TimeGenerated asc"
    )
    return {
        "contract_id": contract_id,
        "independence_group": group,
        "platform": "AZURE",
        "selected_oracle_unit": row["selected_oracle_unit"],
        "visibility": "evaluator_only",
        "status": "requires_runtime_resolution",
        "derivation": {
            "upstream_configuration_case": (
                row["selected_oracle_unit"]["case_id"]
            ),
            "terminal_actions_selected": [
                "BlobService.ListBlobs",
                "BlobService.GetBlob",
            ],
            "selection_rule": (
                "pinned AzureGoat production blob-only versus development "
                "container-public pair, minimally reproduced with one "
                "random current-run account and non-sensitive canary"
            ),
            "upstream_behavior_narrowed": True,
            "full_azuregoat_deployment_executed": False,
            "upstream_payloads_copied": False,
            "historical_values_copied_into_runtime_scope": False,
        },
        "upstream_implementation": implementation_binding,
        "runtime_scope_template": {
            "tenant_boundary": "{{AZURE_TENANT_ID}}",
            "principals": [
                "anonymous HTTPS client with no Authorization header"
            ],
            "actions": [
                "BlobService.ListBlobs",
                "BlobService.GetBlob",
            ],
            "resources": [
                prod_url,
                prod_blob_url,
                dev_url,
                dev_blob_url,
            ],
            "network_origins": ["{{RUNNER_EGRESS_CIDR}}"],
            "time_window": [
                "{{RUN_STARTED_AT}}",
                "{{RUN_FINISHED_AT}}",
            ],
        },
        "evaluator_setup": {
            "command_argv_templates": [
                [
                    "az", "group", "create",
                    "--name", resource_group,
                    "--location", "{{AZURE_LOCATION}}",
                    "--tags",
                    "managed-by=cloud-db-pathbench",
                    "purpose=executable-oracle",
                    "pathbench-run={{RUN_ID}}",
                    *az_common,
                ],
                [
                    "az", "storage", "account", "create",
                    "--name", account,
                    "--resource-group", resource_group,
                    "--location", "{{AZURE_LOCATION}}",
                    "--sku", "Standard_LRS",
                    "--kind", "StorageV2",
                    "--https-only", "true",
                    "--min-tls-version", "TLS1_2",
                    "--allow-blob-public-access", "true",
                    "--public-network-access", "Enabled",
                    "--default-action", "Allow",
                    "--tags",
                    "managed-by=cloud-db-pathbench",
                    "purpose=executable-oracle",
                    "pathbench-run={{RUN_ID}}",
                    *az_common,
                ],
                [
                    "az", "monitor", "diagnostic-settings", "create",
                    "--name", "{{RUN_OWNED_AZURE_DIAGNOSTIC_SETTING}}",
                    "--resource", blob_service_id,
                    "--workspace",
                    "{{DEDICATED_AZURE_LOG_ANALYTICS_WORKSPACE_RESOURCE_ID}}",
                    "--export-to-resource-specific", "true",
                    "--logs", diagnostic_logs,
                    *az_common,
                ],
                [
                    "az", "storage", "container", "create",
                    "--name", prod,
                    "--public-access", "blob",
                    *storage_common,
                ],
                [
                    "az", "storage", "container", "create",
                    "--name", dev,
                    "--public-access", "container",
                    *storage_common,
                ],
                [
                    "az", "storage", "blob", "upload",
                    "--container-name", prod,
                    "--name", blob,
                    "--file", "{{EVALUATOR_PRIVATE_AZURE_CANARY_FILE}}",
                    "--overwrite", "true",
                    "--content-type", "application/json",
                    *storage_common,
                ],
                [
                    "az", "storage", "blob", "upload",
                    "--container-name", dev,
                    "--name", blob,
                    "--file", "{{EVALUATOR_PRIVATE_AZURE_CANARY_FILE}}",
                    "--overwrite", "true",
                    "--content-type", "application/json",
                    *storage_common,
                ],
            ],
            "source_semantics_reproduced": {
                "production_container_access": "blob",
                "development_container_access": "container",
            },
            "resource_tags_required": {
                "managed-by": "cloud-db-pathbench",
                "purpose": "executable-oracle",
                "pathbench-run": "{{RUN_ID}}",
            },
            "private_canary_file_must_be_mode_0600": True,
            "private_canary_contains_no_real_credentials_or_personal_data": (
                True
            ),
            "diagnostic_setting_must_precede_active_probe": True,
        },
        "provider_native_analysis": {
            "adapter_id": "azure_blob_effective_public_configuration_v1",
            "command_argv_templates": [
                [
                    "az", "storage", "account", "show",
                    "--ids", account_id,
                    "--query",
                    (
                        "{id:id,allowBlobPublicAccess:allowBlobPublicAccess,"
                        "publicNetworkAccess:publicNetworkAccess,"
                        "defaultAction:networkRuleSet.defaultAction,"
                        "minimumTlsVersion:minimumTlsVersion}"
                    ),
                    *az_common,
                ],
                [
                    "az", "storage", "container", "show-permission",
                    "--name", prod,
                    *storage_common,
                ],
                [
                    "az", "storage", "container", "show-permission",
                    "--name", dev,
                    *storage_common,
                ],
                [
                    "az", "monitor", "diagnostic-settings", "show",
                    "--name", "{{RUN_OWNED_AZURE_DIAGNOSTIC_SETTING}}",
                    "--resource", blob_service_id,
                    *az_common,
                ],
            ],
            "all_commands_must_agree": True,
            "configuration_is_not_runtime_reachability": True,
        },
        "authorized_active_probe": {
            "probe_argv_templates": [
                anonymous_get(
                    prod_list_url,
                    "{{AZURE_PROD_LIST_CLIENT_REQUEST_ID}}",
                ),
                anonymous_get(
                    prod_blob_url,
                    "{{AZURE_PROD_GET_CLIENT_REQUEST_ID}}",
                    one_byte=True,
                ),
                anonymous_get(
                    dev_list_url,
                    "{{AZURE_DEV_LIST_CLIENT_REQUEST_ID}}",
                ),
                anonymous_get(
                    dev_blob_url,
                    "{{AZURE_DEV_GET_CLIENT_REQUEST_ID}}",
                    one_byte=True,
                ),
            ],
            "postcondition_argv_templates": [
                [
                    "az", "storage", "blob", "show",
                    "--container-name", prod,
                    "--name", blob,
                    "--query", "{name:name,size:properties.contentLength,"
                    "etag:properties.etag,contentType:properties.contentSettings."
                    "contentType}",
                    *storage_common,
                ],
                [
                    "az", "storage", "blob", "show",
                    "--container-name", dev,
                    "--name", blob,
                    "--query", "{name:name,size:properties.contentLength,"
                    "etag:properties.etag,contentType:properties.contentSettings."
                    "contentType}",
                    *storage_common,
                ],
            ],
            "cleanup_argv_templates": [[
                "az", "group", "delete",
                "--name", resource_group,
                "--yes",
                "--subscription", subscription,
                "--only-show-errors",
            ]],
            "post_cleanup_inventory_argv_templates": [[
                "az", "group", "exists",
                "--name", resource_group,
                *az_common,
            ]],
            "expected_cleanup_inventory_state": (
                "resource group existence is false"
            ),
            "curl_config_loading_disabled": True,
            "authorization_header_forbidden": True,
            "proxy_use_disabled": True,
            "response_body_discarded": True,
            "actual_probe_requires_all_safety_gates": True,
        },
        "audit_telemetry": {
            "adapter_id": "azure_storage_blob_logs_exact_requests_v1",
            "command_argv_template": [
                "az", "monitor", "log-analytics", "query",
                "--workspace",
                "{{DEDICATED_AZURE_LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID}}",
                "--analytics-query", kql,
                "--timespan",
                "{{RUN_STARTED_AT}}/{{RUN_FINISHED_AT}}",
                *az_common,
            ],
            "required_event_predicates": [
                {
                    "ClientRequestId": (
                        "{{AZURE_PROD_GET_CLIENT_REQUEST_ID}}"
                    ),
                    "AuthenticationType": "Anonymous",
                    "OperationName": "GetBlob",
                    "StatusCode": ["200", "206"],
                    "Uri": prod_blob_url,
                    "CallerIpAddress": "{{RUNNER_EGRESS_IP}}:*",
                },
                {
                    "ClientRequestId": (
                        "{{AZURE_DEV_LIST_CLIENT_REQUEST_ID}}"
                    ),
                    "AuthenticationType": "Anonymous",
                    "OperationName": "ListBlobs",
                    "StatusCode": ["200"],
                    "Uri_prefix": dev_list_url,
                    "CallerIpAddress": "{{RUNNER_EGRESS_IP}}:*",
                },
                {
                    "ClientRequestId": (
                        "{{AZURE_DEV_GET_CLIENT_REQUEST_ID}}"
                    ),
                    "AuthenticationType": "Anonymous",
                    "OperationName": "GetBlob",
                    "StatusCode": ["200", "206"],
                    "Uri": dev_blob_url,
                    "CallerIpAddress": "{{RUNNER_EGRESS_IP}}:*",
                },
            ],
            "all_required_events_must_be_present": True,
            "poll_until_complete": {
                "maximum_wait_seconds": 1200,
                "poll_interval_seconds": 30,
                "timeout_truth_state": "Unknown",
            },
            "failed_anonymous_requests_expected_in_resource_logs": False,
            "production_list_denial_is_supporting_only": True,
            "absence_of_failed_anonymous_log_is_not_denial_evidence": True,
            "official_reference": (
                "https://learn.microsoft.com/en-us/azure/storage/blobs/"
                "monitor-blob-storage"
            ),
        },
        "safety": {
            "owner_subscription_must_be_dedicated": True,
            "resource_group_must_be_created_by_current_run": True,
            "storage_account_must_be_created_by_current_run": True,
            "random_storage_account_minimum_entropy_bits": 88,
            "public_access_limited_to_two_random_run_owned_containers": True,
            "public_access_is_read_only": True,
            "real_data_forbidden": True,
            "authorization_headers_and_tokens_forbidden_in_probe": True,
            "dedicated_external_log_workspace_required": True,
            "blob_resource_logs_must_be_pre_enabled": True,
            "cleanup_mandatory": True,
            "post_cleanup_inventory_mandatory": True,
        },
        "controlled_counterfactual_template": {
            "same_runtime_scope_required": True,
            "only_mutation": (
                "set storage-account allowBlobPublicAccess=false, wait for "
                "documented propagation, then repeat the same four probes"
            ),
            "pair_assignment_frozen_before_execution": True,
            "failed_anonymous_requests_not_logged_by_platform": True,
            "not_independently_qualifying_without_required_channels": True,
            "expected_truth_state": None,
        },
        "official_references": [
            (
                "https://learn.microsoft.com/en-us/azure/storage/blobs/"
                "anonymous-read-access-configure"
            ),
            (
                "https://learn.microsoft.com/en-us/azure/storage/blobs/"
                "monitor-blob-storage"
            ),
            (
                "https://learn.microsoft.com/en-us/azure/azure-monitor/"
                "reference/tables/storagebloblogs"
            ),
            (
                "https://learn.microsoft.com/en-us/rest/api/"
                "storageservices/authorize-requests-to-azure-storage"
            ),
        ],
    }


def _build_gcp_policy_transition_contract(
    row: Mapping[str, Any],
    implementation_binding: Mapping[str, Any],
) -> dict[str, Any]:
    group = row["independence_group"]
    contract_id = "probe-contract-" + sha256(
        group.encode("utf-8")
    ).hexdigest()[:20]
    bucket_url = "gs://{{RUN_OWNED_GCS_BUCKET}}"
    bucket_resource = (
        "//storage.googleapis.com/projects/_/buckets/"
        "{{RUN_OWNED_GCS_BUCKET}}"
    )
    object_url = (
        "gs://{{RUN_OWNED_GCS_BUCKET}}/{{RUN_OWNED_GCS_OBJECT}}"
    )
    object_resource = (
        bucket_resource + "/objects/{{RUN_OWNED_GCS_OBJECT}}"
    )
    role_name = (
        "projects/{{GCP_OWNER_PROJECT_ID}}/roles/"
        "{{RUN_OWNED_GCP_ROLE_ID}}"
    )
    probe_member = (
        "serviceAccount:{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}"
    )
    gcloud_common = ["--project", "{{GCP_OWNER_PROJECT_ID}}", "--quiet"]
    return {
        "contract_id": contract_id,
        "independence_group": group,
        "platform": "GCP",
        "selected_oracle_unit": row["selected_oracle_unit"],
        "visibility": "evaluator_only",
        "status": "requires_runtime_resolution",
        "derivation": {
            "upstream_configuration_case": (
                row["selected_oracle_unit"]["case_id"]
            ),
            "terminal_actions_selected": [
                "storage.buckets.setIamPolicy",
                "storage.objects.get",
            ],
            "selection_rule": (
                "pinned GCPGoat allUsers custom-role policy transition "
                "narrowed to one random current-run bucket"
            ),
            "upstream_behavior_narrowed": True,
            "historical_values_copied_into_runtime_scope": False,
        },
        "upstream_implementation": implementation_binding,
        "runtime_scope_template": {
            "principals": [
                "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}"
            ],
            "actions": [
                "storage.buckets.setIamPolicy",
                "storage.objects.get",
            ],
            "resources": [bucket_resource, object_resource],
            "network_origins": ["{{RUNNER_EGRESS_CIDR}}"],
            "time_window": [
                "{{RUN_STARTED_AT}}",
                "{{RUN_FINISHED_AT}}",
            ],
        },
        "evaluator_setup": {
            "command_argv_templates": [
                [
                    "gcloud", "storage", "buckets", "create",
                    bucket_url,
                    "--location", "{{GCP_LOCATION}}",
                    "--uniform-bucket-level-access",
                    "--no-public-access-prevention",
                    "--soft-delete-duration", "0",
                    *gcloud_common,
                ],
                [
                    "gcloud", "iam", "roles", "create",
                    "{{RUN_OWNED_GCP_ROLE_ID}}",
                    "--title", "PathBench bounded policy mutator",
                    "--description", (
                        "Ephemeral role for an isolated PathBench "
                        "executable Oracle run"
                    ),
                    "--permissions", (
                        "storage.buckets.get,"
                        "storage.buckets.getIamPolicy,"
                        "storage.buckets.setIamPolicy"
                    ),
                    "--stage", "GA",
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "buckets", "update",
                    bucket_url,
                    "--update-labels",
                    (
                        "managed-by=cloud-db-pathbench,"
                        "purpose=executable-oracle,"
                        "pathbench-run={{RUN_ID}}"
                    ),
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "cp",
                    "{{EVALUATOR_PRIVATE_GCS_CANARY_FILE}}",
                    object_url,
                    "--content-type", "application/json",
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "buckets",
                    "add-iam-policy-binding", bucket_url,
                    "--member", "allUsers",
                    "--role", role_name,
                    *gcloud_common,
                ],
            ],
            "public_binding_is_exactly_one_random_run_owned_bucket": True,
            "public_binding_contains_no_data_read_or_delete_permission": True,
            "resource_tags_required": {
                "managed-by": "cloud-db-pathbench",
                "purpose": "executable-oracle",
                "pathbench-run": "{{RUN_ID}}",
            },
            "private_canary_file_must_be_mode_0600": True,
            "private_canary_contains_no_real_credentials_or_personal_data": (
                True
            ),
        },
        "provider_native_analysis": {
            "adapter_id": "gcp_policy_troubleshooter_exact_tuple_v1",
            "command_argv_templates": [
                [
                    "gcloud", "storage", "buckets", "get-iam-policy",
                    bucket_url,
                    "--format", "json",
                    *gcloud_common,
                ],
                [
                    "gcloud", "policy-intelligence",
                    "troubleshoot-policy", "iam", bucket_resource,
                    "--principal-email",
                    "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}",
                    "--permission", "storage.buckets.setIamPolicy",
                    "--resource-name", bucket_resource,
                    "--resource-service", "storage.googleapis.com",
                    "--resource-type", "storage.googleapis.com/Bucket",
                    "--request-time", "{{RUN_STARTED_AT}}",
                    "--format", "json",
                    *gcloud_common,
                ],
            ],
            "all_commands_must_agree": True,
        },
        "authorized_active_probe": {
            "probe_argv_templates": [
                [
                    "gcloud", "storage", "buckets",
                    "add-iam-policy-binding", bucket_url,
                    "--member", probe_member,
                    "--role", "roles/storage.objectViewer",
                    "--impersonate-service-account",
                    "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}",
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "objects", "describe",
                    object_url,
                    "--format", "json(name,bucket,generation,size)",
                    "--impersonate-service-account",
                    "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}",
                    *gcloud_common,
                ],
            ],
            "postcondition_argv_templates": [
                [
                    "gcloud", "storage", "buckets", "get-iam-policy",
                    bucket_url,
                    "--format", "json",
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "objects", "describe",
                    object_url,
                    "--format", "json(name,bucket,generation,size)",
                    *gcloud_common,
                ],
            ],
            "cleanup_argv_templates": [
                [
                    "gcloud", "storage", "buckets",
                    "remove-iam-policy-binding", bucket_url,
                    "--member", probe_member,
                    "--role", "roles/storage.objectViewer",
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "rm", object_url,
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "buckets",
                    "remove-iam-policy-binding", bucket_url,
                    "--member", "allUsers",
                    "--role", role_name,
                    *gcloud_common,
                ],
                [
                    "gcloud", "storage", "buckets", "delete",
                    bucket_url,
                    *gcloud_common,
                ],
                [
                    "gcloud", "iam", "roles", "delete",
                    "{{RUN_OWNED_GCP_ROLE_ID}}",
                    *gcloud_common,
                ],
            ],
            "post_cleanup_inventory_argv_templates": [
                [
                    "gcloud", "storage", "buckets", "describe",
                    bucket_url,
                    "--format", "json",
                    *gcloud_common,
                ],
                [
                    "gcloud", "iam", "roles", "describe",
                    "{{RUN_OWNED_GCP_ROLE_ID}}",
                    "--format", "json",
                    *gcloud_common,
                ],
            ],
            "expected_cleanup_inventory_state": (
                "bucket absent and custom role deleted"
            ),
            "actual_mutation_requires_all_safety_gates": True,
        },
        "audit_telemetry": {
            "adapter_id": "gcp_admin_activity_exact_event_v1",
            "command_argv_template": [
                "gcloud", "logging", "read",
                (
                    'protoPayload.serviceName="storage.googleapis.com" '
                    'AND (protoPayload.methodName="storage.buckets.'
                    'setIamPolicy" OR protoPayload.methodName="storage.'
                    'objects.get") AND '
                    'protoPayload.authenticationInfo.principalEmail="'
                    "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}" + '" AND '
                    'resource.labels.bucket_name="'
                    "{{RUN_OWNED_GCS_BUCKET}}" + '" AND '
                    'protoPayload.requestMetadata.callerIp="'
                    "{{RUNNER_EGRESS_IP}}" + '" AND '
                    'timestamp>="{{RUN_STARTED_AT}}" AND '
                    'timestamp<="{{RUN_FINISHED_AT}}"'
                ),
                "--limit", "20",
                "--format", "json",
                *gcloud_common,
            ],
            "required_event_predicates": [
                {
                    "protoPayload.serviceName": "storage.googleapis.com",
                    "protoPayload.methodName": (
                        "storage.buckets.setIamPolicy"
                    ),
                    "protoPayload.authenticationInfo.principalEmail": (
                        "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}"
                    ),
                    "resource.labels.bucket_name": (
                        "{{RUN_OWNED_GCS_BUCKET}}"
                    ),
                    "protoPayload.requestMetadata.callerIp": (
                        "{{RUNNER_EGRESS_IP}}"
                    ),
                    "audit_log_type": "Admin Activity",
                },
                {
                    "protoPayload.serviceName": "storage.googleapis.com",
                    "protoPayload.methodName": "storage.objects.get",
                    "protoPayload.authenticationInfo.principalEmail": (
                        "{{DEDICATED_GCP_PROBE_SERVICE_ACCOUNT}}"
                    ),
                    "resource.labels.bucket_name": (
                        "{{RUN_OWNED_GCS_BUCKET}}"
                    ),
                    "protoPayload.requestMetadata.callerIp": (
                        "{{RUNNER_EGRESS_IP}}"
                    ),
                    "resource_name_suffix": (
                        "/objects/{{RUN_OWNED_GCS_OBJECT}}"
                    ),
                    "audit_log_type": "Data Access",
                },
            ],
            "all_required_events_must_be_present": True,
            "data_access_logging_must_be_pre_enabled": True,
            "public_object_access_used_as_telemetry": False,
            "official_reference": (
                "https://cloud.google.com/storage/docs/audit-logging"
            ),
        },
        "safety": {
            "owner_project_must_be_dedicated": True,
            "probe_project_must_be_dedicated_and_distinct": True,
            "resource_must_be_created_by_current_run": True,
            "random_bucket_name_minimum_entropy_bits": 128,
            "real_data_forbidden": True,
            "data_access_logging_must_be_pre_enabled": True,
            "public_binding_limited_to_exact_custom_role_and_bucket": True,
            "custom_role_permissions": [
                "storage.buckets.get",
                "storage.buckets.getIamPolicy",
                "storage.buckets.setIamPolicy",
            ],
            "custom_role_has_no_data_read_write_or_delete": True,
            "cleanup_mandatory": True,
            "post_cleanup_inventory_mandatory": True,
        },
        "controlled_counterfactual_template": {
            "same_runtime_scope_required": True,
            "only_mutation": (
                "remove the allUsers custom-role binding before the "
                "same policy mutation probe"
            ),
            "pair_assignment_frozen_before_execution": True,
            "expected_truth_state": None,
        },
        "official_references": [
            (
                "https://cloud.google.com/sdk/gcloud/reference/"
                "policy-intelligence/troubleshoot-policy/iam"
            ),
            (
                "https://cloud.google.com/sdk/gcloud/reference/storage/"
                "buckets/add-iam-policy-binding"
            ),
            "https://cloud.google.com/storage/docs/audit-logging",
            "https://cloud.google.com/iam/docs/full-resource-names",
        ],
    }


def _load_configuration_bindings(
    root: Path,
    packet: Mapping[str, Any],
) -> dict[str, Any]:
    cases = packet.get("cases")
    if not isinstance(cases, list):
        raise ValueError("configuration packet cases missing")
    result = {}
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str):
            continue
        evidence = case.get("configuration_evidence") or []
        members = {}
        archive_binding = None
        source = case.get("source") or {}
        for assertion in evidence:
            raw = assertion.get("raw_ref") or {}
            archive_path = _resolve_file(root, raw["archive_relative_path"])
            binding = _binding(root, archive_path)
            if binding["sha256"] != raw["archive_sha256"]:
                raise ValueError(
                    f"configuration archive SHA-256 mismatch: {case_id}"
                )
            if archive_binding is not None and archive_binding != binding:
                raise ValueError(
                    f"multiple configuration archives for {case_id}"
                )
            archive_binding = binding
            with ZipFile(archive_path) as archive:
                data = archive.read(raw["archive_member"])
            member = {
                "member_path": raw["archive_member"],
                "sha256": sha256(data).hexdigest(),
                "bytes": len(data),
            }
            if (
                member["sha256"] != raw["archive_member_sha256"]
                or member["bytes"] != raw["archive_member_bytes"]
            ):
                raise ValueError(
                    f"configuration member binding mismatch: {case_id}"
                )
            members[member["member_path"]] = member
        if archive_binding is None:
            continue
        result[case_id] = {
            "source_id": source.get("source_id"),
            "repository": source.get("upstream_url"),
            "commit": source.get("version_or_commit"),
            "archive": archive_binding,
            "members": [members[key] for key in sorted(members)],
            "source_code_executed_by_contract_builder": False,
        }
    return result


def _finish_bounded_read_contract(
    *,
    row: Mapping[str, Any],
    plan: Mapping[str, Any],
    implementation_binding: Mapping[str, Any],
    group: str,
    contract_id: str,
    actions: list[str],
    resources: list[str],
    native_commands: list[list[str]],
    predicates: Mapping[str, Any],
) -> dict[str, Any]:
    contract = {
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
    setup_output_bindings = plan.get("setup_output_bindings")
    if setup_output_bindings:
        contract["runtime_binding_plan"] = {
            "plan_version": "1.0.0",
            "outputs": setup_output_bindings,
            "raw_setup_stdout_persistence_forbidden": True,
            "agent_visibility": "none",
            "post_setup_full_repreflight_required": True,
        }
    return contract


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
