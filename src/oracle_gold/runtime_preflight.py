"""Resolve Oracle probe contracts in memory after fail-closed validation."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


PLACEHOLDER = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")
RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,31}")
SSM_PARAMETER_NAME = re.compile(
    r"/pathbench/(?P<run_id>[a-z0-9][a-z0-9-]{7,31})/canary"
)
AWS_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-\d")
ACCOUNT_ID = re.compile(r"\d{12}")
GCP_PROJECT_ID = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
GCP_LOCATION = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,29}")
GCP_SERVICE_ACCOUNT = re.compile(
    r"[a-z][a-z0-9-]{4,28}[a-z0-9]@"
    r"(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])\."
    r"iam\.gserviceaccount\.com"
)
GCS_RUN_BUCKET = re.compile(r"pathbench-oracle-[0-9a-f]{32}")
GCS_RUN_OBJECT = re.compile(
    r"canary-(?P<run_id>[a-z0-9][a-z0-9-]{7,31})\.json"
)
GCP_RUN_ROLE = re.compile(r"pathbenchOracle[0-9a-f]{16}")
UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
AZURE_LOCATION = re.compile(r"[a-z][a-z0-9]{1,31}")
AZURE_RUN_RESOURCE_GROUP = re.compile(r"pathbench-oracle-[0-9a-f]{32}")
AZURE_RUN_STORAGE_ACCOUNT = re.compile(r"pb[0-9a-f]{22}")
AZURE_RUN_CONTAINER = re.compile(r"(?:prod|dev)-[0-9a-f]{32}")
AZURE_RUN_BLOB = re.compile(
    r"canary-(?P<run_id>[a-z0-9][a-z0-9-]{7,31})\.json"
)
AZURE_RUN_DIAGNOSTIC = re.compile(r"pathbench-oracle-[0-9a-f]{32}")
AZURE_LOG_WORKSPACE_RESOURCE_ID = re.compile(
    r"/subscriptions/(?P<subscription>[0-9a-f-]{36})/"
    r"resourceGroups/(?P<resource_group>[A-Za-z0-9._()\-]{1,90})/"
    r"providers/Microsoft\.OperationalInsights/workspaces/"
    r"(?P<workspace>[A-Za-z0-9][A-Za-z0-9-]{2,62})",
    re.IGNORECASE,
)
SHA256 = re.compile(r"[0-9a-f]{64}")
SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|secret_value|access_key|private_key|session_token|"
    r"credential_value)"
)
FORBIDDEN_AWS_FLAGS = {
    "--debug",
    "--endpoint-url",
    "--no-sign-request",
    "--no-verify-ssl",
}
FORBIDDEN_GCLOUD_FLAGS = {
    "--access-token-file",
    "--account",
    "--configuration",
    "--log-http",
    "--trace-token",
    "--verbosity",
}
FORBIDDEN_AZ_FLAGS = {
    "--account-key",
    "--connection-string",
    "--debug",
    "--sas-token",
    "--verbose",
}
FORBIDDEN_CURL_FLAGS = {
    "--anyauth",
    "--basic",
    "--config",
    "--digest",
    "--header-file",
    "--location",
    "--netrc",
    "--netrc-file",
    "--negotiate",
    "--oauth2-bearer",
    "--proxy",
    "--proxy-header",
    "--user",
}
AWS_COMMAND_ALLOWLIST = {
    "setup": {
        ("secretsmanager", "create-secret"),
        ("ssm", "put-parameter"),
    },
    "provider_native_analysis": {
        ("iam", "simulate-principal-policy"),
    },
    "permission_precheck": {
        ("ec2", "modify-image-attribute"),
        ("ec2", "modify-snapshot-attribute"),
    },
    "active_probe": {
        ("ec2", "modify-image-attribute"),
        ("ec2", "modify-snapshot-attribute"),
        ("secretsmanager", "batch-get-secret-value"),
        ("secretsmanager", "get-secret-value"),
        ("ssm", "get-parameters"),
    },
    "postcondition": {
        ("ec2", "describe-image-attribute"),
        ("ec2", "describe-snapshot-attribute"),
        ("secretsmanager", "describe-secret"),
        ("secretsmanager", "list-secrets"),
        ("ssm", "describe-parameters"),
    },
    "audit_telemetry": {("cloudtrail", "lookup-events")},
    "cleanup": {
        ("ec2", "modify-image-attribute"),
        ("ec2", "modify-snapshot-attribute"),
        ("secretsmanager", "delete-secret"),
        ("ssm", "delete-parameter"),
    },
    "post_cleanup_inventory": {
        ("ec2", "describe-image-attribute"),
        ("ec2", "describe-snapshot-attribute"),
        ("secretsmanager", "describe-secret"),
        ("secretsmanager", "list-secrets"),
        ("ssm", "describe-parameters"),
    },
}
GCLOUD_COMMAND_ALLOWLIST = {
    "setup": {
        ("storage", "buckets", "create"),
        ("storage", "buckets", "update"),
        ("storage", "buckets", "add-iam-policy-binding"),
        ("iam", "roles", "create"),
        ("storage", "cp"),
    },
    "provider_native_analysis": {
        ("storage", "buckets", "get-iam-policy"),
        ("policy-intelligence", "troubleshoot-policy", "iam"),
    },
    "active_probe": {
        ("storage", "buckets", "add-iam-policy-binding"),
        ("storage", "objects", "describe"),
    },
    "postcondition": {
        ("storage", "buckets", "get-iam-policy"),
        ("storage", "objects", "describe"),
    },
    "audit_telemetry": {("logging", "read")},
    "cleanup": {
        ("storage", "buckets", "remove-iam-policy-binding"),
        ("storage", "buckets", "delete"),
        ("iam", "roles", "delete"),
        ("storage", "rm"),
    },
    "post_cleanup_inventory": {
        ("storage", "buckets", "describe"),
        ("iam", "roles", "describe"),
    },
}
AZ_COMMAND_ALLOWLIST = {
    "setup": {
        ("group", "create"),
        ("storage", "account", "create"),
        ("storage", "container", "create"),
        ("storage", "blob", "upload"),
        ("monitor", "diagnostic-settings", "create"),
    },
    "provider_native_analysis": {
        ("storage", "account", "show"),
        ("storage", "container", "show-permission"),
        ("monitor", "diagnostic-settings", "show"),
    },
    "postcondition": {
        ("storage", "blob", "show"),
    },
    "audit_telemetry": {
        ("monitor", "log-analytics", "query"),
    },
    "cleanup": {
        ("group", "delete"),
    },
    "post_cleanup_inventory": {
        ("group", "exists"),
    },
}
PHASE_ORDER = (
    "setup",
    "provider_native_analysis",
    "permission_precheck",
    "active_probe",
    "postcondition",
    "audit_telemetry",
    "cleanup",
    "post_cleanup_inventory",
)


@dataclass(frozen=True)
class ResolvedStep:
    phase: str
    template_path: str
    argv: tuple[str, ...]
    argv_sha256: str


@dataclass(frozen=True)
class ExecutionPreflight:
    """The resolved argv is memory-only; persist only ``audit_report``."""

    audit_report: Mapping[str, Any]
    resolved_steps: tuple[ResolvedStep, ...]


def preflight_probe_contract(
    contract: Mapping[str, Any],
    *,
    runtime_values: Mapping[str, str],
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> ExecutionPreflight:
    """Validate and resolve a contract but never execute a command."""
    blockers: list[str] = []
    platform = str(contract.get("platform") or "")
    _reject_sensitive_input_keys(runtime_values, "runtime_values", blockers)
    _reject_sensitive_input_keys(authorization, "authorization", blockers)
    _validate_policy(policy, blockers)
    _validate_authorization(
        authorization, policy, platform=platform, blockers=blockers
    )

    required = sorted(_find_placeholders(contract))
    supplied = set(runtime_values)
    missing = sorted(set(required) - supplied)
    unexpected = sorted(supplied - set(required))
    blockers.extend(f"missing_runtime_value:{name}" for name in missing)
    blockers.extend(
        f"unexpected_runtime_value:{name}" for name in unexpected
    )
    _validate_runtime_values(
        required,
        runtime_values,
        authorization,
        platform,
        blockers,
    )

    templates = _collect_command_templates(contract, blockers)
    resolved_steps: list[ResolvedStep] = []
    if not blockers:
        for phase, template_path, argv in templates:
            resolved = tuple(
                _replace_placeholders(token, runtime_values)
                for token in argv
            )
            _validate_resolved_argv(
                resolved,
                phase=phase,
                platform=platform,
                runtime_values=runtime_values,
                template_path=template_path,
                blockers=blockers,
            )
            resolved_steps.append(ResolvedStep(
                phase=phase,
                template_path=template_path,
                argv=resolved,
                argv_sha256=_argv_digest(resolved),
            ))
    _validate_step_coverage(contract, resolved_steps, blockers)

    blockers = sorted(set(blockers))
    ready = not blockers
    if not ready:
        resolved_steps = []
    phase_counts = Counter(step.phase for step in resolved_steps)
    audit_report = {
        "report_version": "1.0.0",
        "report_kind": "oracle_contract_runtime_preflight",
        "contract_id": contract.get("contract_id"),
        "independence_group": contract.get("independence_group"),
        "platform": platform,
        "ready_for_execution": ready,
        "commands_executed": 0,
        "truth_labels_present": False,
        "expected_outcomes_present": False,
        "credential_values_recorded": False,
        "runtime_values_recorded": False,
        "resolved_argv_recorded": False,
        "authorization_sentinel_valid": _sentinel_valid(
            authorization, policy
        ),
        "required_placeholder_count": len(required),
        "supplied_runtime_value_count": len(runtime_values),
        "private_input_count": _safe_collection_length(
            authorization.get("private_inputs")
        ),
        "run_owned_resource_count": _safe_collection_length(
            authorization.get("run_owned_resource_identifiers")
        ),
        "resolved_step_count": len(resolved_steps),
        "resolved_step_counts_by_phase": {
            phase: phase_counts[phase]
            for phase in PHASE_ORDER
            if phase_counts[phase]
        },
        "runtime_binding_sha256": (
            _runtime_binding_digest(runtime_values)
            if (
                not missing
                and not unexpected
                and all(
                    isinstance(value, str)
                    for value in runtime_values.values()
                )
            )
            else None
        ),
        "resolved_step_digests": [
            {
                "phase": step.phase,
                "template_path": step.template_path,
                "program": step.argv[0],
                "service": step.argv[1] if len(step.argv) > 1 else None,
                "operation": step.argv[2] if len(step.argv) > 2 else None,
                "argv_sha256": step.argv_sha256,
            }
            for step in resolved_steps
        ],
        "blockers": blockers,
    }
    return ExecutionPreflight(
        audit_report=audit_report,
        resolved_steps=tuple(resolved_steps),
    )


def _validate_policy(
    policy: Mapping[str, Any],
    blockers: list[str],
) -> None:
    if policy.get("policy_kind") != "isolated_cloud_oracle_execution":
        blockers.append("wrong_execution_policy_kind")
    if policy.get("execution_default") != "disabled":
        blockers.append("execution_default_not_disabled")
    safety = policy.get("safety")
    evidence = policy.get("evidence_contract")
    if not isinstance(safety, Mapping):
        blockers.append("policy_safety_missing")
        return
    if not isinstance(evidence, Mapping):
        blockers.append("policy_evidence_contract_missing")
        return
    for field in (
        "production_accounts_forbidden",
        "require_dedicated_account_subscription_or_project",
        "require_no_sensitive_data",
        "destructive_actions_only_on_run_owned_resources",
        "teardown_required",
        "post_teardown_inventory_required",
        "credentials_must_not_enter_artifacts",
    ):
        if safety.get(field) is not True:
            blockers.append(f"policy_control_disabled:{field}")
    for field in (
        "value_bearing_raw_responses_must_not_be_persisted",
        "sensitive_fields_removed_before_persistence",
        "sanitized_stdout_stderr_preserved",
        "expected_outcome_hidden_from_agent",
    ):
        if evidence.get(field) is not True:
            blockers.append(f"evidence_control_disabled:{field}")


def _validate_authorization(
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    platform: str,
    blockers: list[str],
) -> None:
    safety = policy.get("safety") or {}
    if not _sentinel_valid(authorization, policy):
        blockers.append("authorization_sentinel_invalid")
    truthy_fields = (
        "dedicated_scope_attested",
        "no_sensitive_data_attested",
        "teardown_plan_verified",
        "post_teardown_inventory_plan_verified",
        "cost_estimate_approved",
    )
    for field in truthy_fields:
        if authorization.get(field) is not True:
            blockers.append(f"authorization_attestation_missing:{field}")
    if authorization.get("production_scope") is not False:
        blockers.append("production_scope_not_explicitly_false")

    if platform == "AWS":
        owner = str(authorization.get("owner_account_id") or "")
        if not ACCOUNT_ID.fullmatch(owner):
            blockers.append("owner_account_id_invalid")
        counterpart = authorization.get("counterpart_account_id")
        if counterpart is not None:
            counterpart = str(counterpart)
            if not ACCOUNT_ID.fullmatch(counterpart):
                blockers.append("counterpart_account_id_invalid")
            elif counterpart == owner:
                blockers.append(
                    "owner_and_counterpart_accounts_not_distinct"
                )
    elif platform == "GCP":
        owner = str(authorization.get("owner_project_id") or "")
        probe = str(authorization.get("probe_project_id") or "")
        probe_identity = str(
            authorization.get("probe_service_account_email") or ""
        )
        if not GCP_PROJECT_ID.fullmatch(owner):
            blockers.append("owner_project_id_invalid")
        if not GCP_PROJECT_ID.fullmatch(probe):
            blockers.append("probe_project_id_invalid")
        elif probe == owner:
            blockers.append("owner_and_probe_projects_not_distinct")
        identity_match = GCP_SERVICE_ACCOUNT.fullmatch(probe_identity)
        if identity_match is None:
            blockers.append("probe_service_account_email_invalid")
        elif identity_match.group("project") != probe:
            blockers.append("probe_service_account_project_mismatch")
        if authorization.get(
            "resource_names_cryptographically_random_attested"
        ) is not True:
            blockers.append(
                "authorization_attestation_missing:"
                "resource_names_cryptographically_random_attested"
            )
        if authorization.get(
            "gcp_storage_data_access_logs_enabled_attested"
        ) is not True:
            blockers.append(
                "authorization_attestation_missing:"
                "gcp_storage_data_access_logs_enabled_attested"
            )
        if authorization.get(
            "probe_impersonation_authorized_attested"
        ) is not True:
            blockers.append(
                "authorization_attestation_missing:"
                "probe_impersonation_authorized_attested"
            )
    elif platform == "AZURE":
        subscription = str(
            authorization.get("owner_subscription_id") or ""
        ).casefold()
        tenant = str(authorization.get("owner_tenant_id") or "").casefold()
        customer_id = str(
            authorization.get(
                "log_analytics_workspace_customer_id"
            ) or ""
        ).casefold()
        workspace_resource = str(
            authorization.get(
                "log_analytics_workspace_resource_id"
            ) or ""
        )
        if not UUID.fullmatch(subscription):
            blockers.append("owner_subscription_id_invalid")
        if not UUID.fullmatch(tenant):
            blockers.append("owner_tenant_id_invalid")
        if not UUID.fullmatch(customer_id):
            blockers.append(
                "log_analytics_workspace_customer_id_invalid"
            )
        workspace_match = AZURE_LOG_WORKSPACE_RESOURCE_ID.fullmatch(
            workspace_resource
        )
        if workspace_match is None:
            blockers.append(
                "log_analytics_workspace_resource_id_invalid"
            )
        elif workspace_match.group("subscription").casefold() != subscription:
            blockers.append(
                "log_analytics_workspace_subscription_mismatch"
            )
        for field in (
            "azure_cli_identity_subscription_bound_attested",
            "azure_blob_resource_log_sink_ready_attested",
            "anonymous_probe_has_no_authorization_material_attested",
            "resource_names_cryptographically_random_attested",
        ):
            if authorization.get(field) is not True:
                blockers.append(
                    f"authorization_attestation_missing:{field}"
                )
    else:
        blockers.append("unsupported_contract_platform")

    estimated = authorization.get("estimated_cost_usd")
    maximum_cost = safety.get(
        "maximum_estimated_cost_usd_per_lineage"
    )
    if not isinstance(estimated, (int, float)) or estimated < 0:
        blockers.append("estimated_cost_invalid")
    elif (
        not isinstance(maximum_cost, (int, float))
        or estimated > maximum_cost
    ):
        blockers.append("estimated_cost_exceeds_policy")
    ttl = authorization.get("ttl_hours")
    maximum_ttl = safety.get("maximum_ttl_hours")
    if not isinstance(ttl, (int, float)) or ttl <= 0:
        blockers.append("ttl_invalid")
    elif not isinstance(maximum_ttl, (int, float)) or ttl > maximum_ttl:
        blockers.append("ttl_exceeds_policy")

    mandatory = safety.get("mandatory_tags") or {}
    tags = authorization.get("resource_tags")
    if not isinstance(tags, Mapping):
        blockers.append("resource_tags_missing")
    else:
        for key, value in mandatory.items():
            if tags.get(key) != value:
                blockers.append(f"mandatory_tag_missing:{key}")


def _validate_runtime_values(
    required: Sequence[str],
    values: Mapping[str, str],
    authorization: Mapping[str, Any],
    platform: str,
    blockers: list[str],
) -> None:
    valid_strings: dict[str, str] = {}
    for name in required:
        value = values.get(name)
        if not isinstance(value, str) or not value:
            blockers.append(f"runtime_value_not_nonempty_string:{name}")
            continue
        if "\x00" in value or "\r" in value or "\n" in value:
            blockers.append(f"runtime_value_contains_control_character:{name}")
            continue
        valid_strings[name] = value

    if "RUN_ID" in valid_strings and not RUN_ID.fullmatch(
        valid_strings["RUN_ID"]
    ):
        blockers.append("run_id_invalid")
    if (
        "AWS_PARTITION" in valid_strings
        and valid_strings["AWS_PARTITION"] not in {
            "aws",
            "aws-cn",
            "aws-us-gov",
        }
    ):
        blockers.append("aws_partition_invalid")
    if (
        "AWS_REGION" in valid_strings
        and not AWS_REGION.fullmatch(valid_strings["AWS_REGION"])
    ):
        blockers.append("aws_region_invalid")

    owner = str(authorization.get("owner_account_id") or "")
    if (
        "DEDICATED_OWNER_ACCOUNT_ID" in valid_strings
        and valid_strings["DEDICATED_OWNER_ACCOUNT_ID"] != owner
    ):
        blockers.append("runtime_owner_account_mismatch")
    if "ISOLATED_COUNTERPART_ACCOUNT_ID" in valid_strings:
        if valid_strings["ISOLATED_COUNTERPART_ACCOUNT_ID"] != str(
            authorization.get("counterpart_account_id") or ""
        ):
            blockers.append("runtime_counterpart_account_mismatch")
    principal = valid_strings.get("DEDICATED_PROBE_PRINCIPAL_ARN")
    if principal is not None and not re.fullmatch(
        rf"arn:(?:aws|aws-cn|aws-us-gov):iam::{re.escape(owner)}:"
        r"(?:role|user)/[A-Za-z0-9+=,.@_/-]+",
        principal,
    ):
        blockers.append("probe_principal_not_in_owner_account")
    elif (
        principal is not None
        and "AWS_PARTITION" in valid_strings
        and not principal.startswith(
            f"arn:{valid_strings['AWS_PARTITION']}:"
        )
    ):
        blockers.append("probe_principal_partition_mismatch")

    for key, pattern in (
        ("RUN_OWNED_SNAPSHOT_ID", r"snap-[0-9a-f]{17}"),
        ("RUN_OWNED_AMI_ID", r"ami-[0-9a-f]{17}"),
    ):
        if key in valid_strings and not re.fullmatch(
            pattern, valid_strings[key]
        ):
            blockers.append(f"runtime_resource_identifier_invalid:{key}")

    parameter_name = valid_strings.get("RUN_OWNED_PARAMETER_NAME")
    if parameter_name is not None:
        match = SSM_PARAMETER_NAME.fullmatch(parameter_name)
        if match is None:
            blockers.append(
                "runtime_resource_identifier_invalid:"
                "RUN_OWNED_PARAMETER_NAME"
            )
        elif (
            "RUN_ID" in valid_strings
            and match.group("run_id") != valid_strings["RUN_ID"]
        ):
            blockers.append("run_owned_parameter_run_id_mismatch")

    if platform == "GCP":
        _validate_gcp_runtime_values(
            valid_strings, authorization, blockers
        )
    elif platform == "AZURE":
        _validate_azure_runtime_values(
            valid_strings, authorization, blockers
        )

    _validate_network(valid_strings, blockers)
    _validate_time_window(valid_strings, authorization, blockers)
    _validate_run_owned_resources(
        valid_strings, authorization, owner, blockers
    )
    _validate_private_inputs(valid_strings, authorization, blockers)


def _validate_gcp_runtime_values(
    values: Mapping[str, str],
    authorization: Mapping[str, Any],
    blockers: list[str],
) -> None:
    owner = values.get("GCP_OWNER_PROJECT_ID")
    if owner is not None:
        if not GCP_PROJECT_ID.fullmatch(owner):
            blockers.append("gcp_owner_project_id_invalid")
        elif owner != str(authorization.get("owner_project_id") or ""):
            blockers.append("runtime_owner_project_mismatch")
    location = values.get("GCP_LOCATION")
    if location is not None and not GCP_LOCATION.fullmatch(location):
        blockers.append("gcp_location_invalid")
    service_account = values.get("DEDICATED_GCP_PROBE_SERVICE_ACCOUNT")
    if service_account is not None:
        match = GCP_SERVICE_ACCOUNT.fullmatch(service_account)
        if match is None:
            blockers.append("gcp_probe_service_account_invalid")
        else:
            probe_project = str(
                authorization.get("probe_project_id") or ""
            )
            if match.group("project") != probe_project:
                blockers.append("gcp_probe_service_account_project_mismatch")
        if service_account != str(
            authorization.get("probe_service_account_email") or ""
        ):
            blockers.append("runtime_probe_service_account_mismatch")
    bucket = values.get("RUN_OWNED_GCS_BUCKET")
    if bucket is not None and not GCS_RUN_BUCKET.fullmatch(bucket):
        blockers.append(
            "runtime_resource_identifier_invalid:RUN_OWNED_GCS_BUCKET"
        )
    object_name = values.get("RUN_OWNED_GCS_OBJECT")
    if object_name is not None:
        match = GCS_RUN_OBJECT.fullmatch(object_name)
        if match is None:
            blockers.append(
                "runtime_resource_identifier_invalid:RUN_OWNED_GCS_OBJECT"
            )
        elif (
            "RUN_ID" in values
            and match.group("run_id") != values["RUN_ID"]
        ):
            blockers.append("run_owned_gcs_object_run_id_mismatch")
    role_id = values.get("RUN_OWNED_GCP_ROLE_ID")
    if role_id is not None and not GCP_RUN_ROLE.fullmatch(role_id):
        blockers.append(
            "runtime_resource_identifier_invalid:RUN_OWNED_GCP_ROLE_ID"
        )


def _validate_azure_runtime_values(
    values: Mapping[str, str],
    authorization: Mapping[str, Any],
    blockers: list[str],
) -> None:
    subscription = values.get("AZURE_SUBSCRIPTION_ID")
    expected_subscription = str(
        authorization.get("owner_subscription_id") or ""
    ).casefold()
    if subscription is not None:
        if not UUID.fullmatch(subscription.casefold()):
            blockers.append("azure_subscription_id_invalid")
        elif subscription.casefold() != expected_subscription:
            blockers.append("runtime_owner_subscription_mismatch")
    tenant = values.get("AZURE_TENANT_ID")
    if tenant is not None:
        if not UUID.fullmatch(tenant.casefold()):
            blockers.append("azure_tenant_id_invalid")
        elif tenant.casefold() != str(
            authorization.get("owner_tenant_id") or ""
        ).casefold():
            blockers.append("runtime_owner_tenant_mismatch")
    location = values.get("AZURE_LOCATION")
    if location is not None and not AZURE_LOCATION.fullmatch(location):
        blockers.append("azure_location_invalid")

    workspace_resource = values.get(
        "DEDICATED_AZURE_LOG_ANALYTICS_WORKSPACE_RESOURCE_ID"
    )
    if workspace_resource is not None:
        match = AZURE_LOG_WORKSPACE_RESOURCE_ID.fullmatch(
            workspace_resource
        )
        if match is None:
            blockers.append("azure_log_workspace_resource_id_invalid")
        else:
            if (
                subscription is not None
                and match.group("subscription").casefold()
                != subscription.casefold()
            ):
                blockers.append(
                    "azure_log_workspace_subscription_mismatch"
                )
            run_group = values.get("RUN_OWNED_AZURE_RESOURCE_GROUP")
            if (
                run_group is not None
                and match.group("resource_group").casefold()
                == run_group.casefold()
            ):
                blockers.append("azure_log_workspace_inside_run_group")
        if workspace_resource != str(
            authorization.get(
                "log_analytics_workspace_resource_id"
            ) or ""
        ):
            blockers.append("runtime_log_workspace_resource_mismatch")
    customer_id = values.get(
        "DEDICATED_AZURE_LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID"
    )
    if customer_id is not None:
        if not UUID.fullmatch(customer_id.casefold()):
            blockers.append("azure_log_workspace_customer_id_invalid")
        elif customer_id.casefold() != str(
            authorization.get(
                "log_analytics_workspace_customer_id"
            ) or ""
        ).casefold():
            blockers.append("runtime_log_workspace_customer_mismatch")

    patterns = (
        (
            "RUN_OWNED_AZURE_RESOURCE_GROUP",
            AZURE_RUN_RESOURCE_GROUP,
        ),
        (
            "RUN_OWNED_AZURE_STORAGE_ACCOUNT",
            AZURE_RUN_STORAGE_ACCOUNT,
        ),
        (
            "RUN_OWNED_AZURE_PROD_CONTAINER",
            AZURE_RUN_CONTAINER,
        ),
        (
            "RUN_OWNED_AZURE_DEV_CONTAINER",
            AZURE_RUN_CONTAINER,
        ),
        (
            "RUN_OWNED_AZURE_DIAGNOSTIC_SETTING",
            AZURE_RUN_DIAGNOSTIC,
        ),
    )
    for key, pattern in patterns:
        value = values.get(key)
        if value is not None and not pattern.fullmatch(value):
            blockers.append(f"runtime_resource_identifier_invalid:{key}")
    prod = values.get("RUN_OWNED_AZURE_PROD_CONTAINER")
    dev = values.get("RUN_OWNED_AZURE_DEV_CONTAINER")
    if prod is not None and not prod.startswith("prod-"):
        blockers.append("azure_prod_container_prefix_invalid")
    if dev is not None and not dev.startswith("dev-"):
        blockers.append("azure_dev_container_prefix_invalid")
    if prod is not None and dev is not None and prod == dev:
        blockers.append("azure_control_containers_not_distinct")
    blob = values.get("RUN_OWNED_AZURE_CANARY_BLOB")
    if blob is not None:
        match = AZURE_RUN_BLOB.fullmatch(blob)
        if match is None:
            blockers.append(
                "runtime_resource_identifier_invalid:"
                "RUN_OWNED_AZURE_CANARY_BLOB"
            )
        elif (
            "RUN_ID" in values
            and match.group("run_id") != values["RUN_ID"]
        ):
            blockers.append("run_owned_azure_blob_run_id_mismatch")

    request_id_names = (
        "AZURE_PROD_LIST_CLIENT_REQUEST_ID",
        "AZURE_PROD_GET_CLIENT_REQUEST_ID",
        "AZURE_DEV_LIST_CLIENT_REQUEST_ID",
        "AZURE_DEV_GET_CLIENT_REQUEST_ID",
    )
    request_ids = []
    for name in request_id_names:
        value = values.get(name)
        if value is None:
            continue
        if not UUID.fullmatch(value.casefold()) or value[14] != "4":
            blockers.append(f"azure_client_request_id_invalid:{name}")
        request_ids.append(value.casefold())
    if len(request_ids) != len(set(request_ids)):
        blockers.append("azure_client_request_ids_not_distinct")
    null_sink = values.get("ORACLE_NULL_SINK")
    if null_sink is not None and null_sink not in {"NUL", "/dev/null"}:
        blockers.append("oracle_null_sink_invalid")


def _validate_network(
    values: Mapping[str, str],
    blockers: list[str],
) -> None:
    if "RUNNER_EGRESS_IP" not in values:
        return
    try:
        address = ipaddress.ip_address(values["RUNNER_EGRESS_IP"])
    except ValueError:
        blockers.append("runner_egress_ip_invalid")
        return
    try:
        network = ipaddress.ip_network(
            values.get("RUNNER_EGRESS_CIDR", ""),
            strict=True,
        )
    except ValueError:
        blockers.append("runner_egress_cidr_invalid")
        return
    expected_prefix = 32 if address.version == 4 else 128
    if address not in network or network.prefixlen != expected_prefix:
        blockers.append("runner_egress_cidr_must_be_exact_host")


def _validate_time_window(
    values: Mapping[str, str],
    authorization: Mapping[str, Any],
    blockers: list[str],
) -> None:
    if not {
        "RUN_STARTED_AT",
        "RUN_FINISHED_AT",
    }.issubset(values):
        return
    try:
        started = _parse_utc(values["RUN_STARTED_AT"])
        finished = _parse_utc(values["RUN_FINISHED_AT"])
    except ValueError:
        blockers.append("run_time_window_invalid")
        return
    duration_hours = (finished - started).total_seconds() / 3600
    if duration_hours <= 0:
        blockers.append("run_time_window_not_increasing")
    ttl = authorization.get("ttl_hours")
    if isinstance(ttl, (int, float)) and duration_hours > ttl:
        blockers.append("run_time_window_exceeds_authorized_ttl")


def _validate_run_owned_resources(
    values: Mapping[str, str],
    authorization: Mapping[str, Any],
    owner: str,
    blockers: list[str],
) -> None:
    declared = authorization.get("run_owned_resource_identifiers")
    if not isinstance(declared, Sequence) or isinstance(
        declared, (str, bytes)
    ):
        blockers.append("run_owned_resource_inventory_missing")
        return
    declared_set = {str(value) for value in declared}
    run_owned = {
        value
        for key, value in values.items()
        if key.startswith("RUN_OWNED_")
    }
    missing = run_owned - declared_set
    if missing:
        blockers.append("runtime_resource_not_in_run_owned_inventory")
    for key, value in values.items():
        if not key.startswith("RUN_OWNED_") or "_ARN" not in key:
            continue
        parts = value.split(":")
        if len(parts) < 6 or not value.startswith("arn:"):
            blockers.append(f"run_owned_arn_invalid:{key}")
        elif parts[4] != owner:
            blockers.append(f"run_owned_arn_owner_mismatch:{key}")
        else:
            partition = values.get("AWS_PARTITION")
            region = values.get("AWS_REGION")
            if partition is not None and parts[1] != partition:
                blockers.append(
                    f"run_owned_arn_partition_mismatch:{key}"
                )
            if region is not None and parts[3] != region:
                blockers.append(f"run_owned_arn_region_mismatch:{key}")


def _validate_private_inputs(
    values: Mapping[str, str],
    authorization: Mapping[str, Any],
    blockers: list[str],
) -> None:
    names = {
        key
        for key in values
        if key.startswith("EVALUATOR_PRIVATE_")
    }
    metadata = authorization.get("private_inputs")
    if not isinstance(metadata, Mapping):
        if names:
            blockers.append("private_input_metadata_missing")
        return
    if set(metadata) != names:
        blockers.append("private_input_metadata_key_mismatch")
        return
    if not names:
        return
    private_root_value = authorization.get("evaluator_private_root")
    if not isinstance(private_root_value, str):
        blockers.append("evaluator_private_root_missing")
        return
    try:
        private_root = Path(private_root_value).resolve(strict=True)
    except (OSError, ValueError):
        blockers.append("evaluator_private_root_invalid")
        return
    if not private_root.is_dir():
        blockers.append("evaluator_private_root_not_directory")
        return
    for name in sorted(names):
        item = metadata.get(name)
        if not isinstance(item, Mapping):
            blockers.append(f"private_input_metadata_invalid:{name}")
            continue
        path = Path(values[name])
        if not path.is_absolute():
            blockers.append(f"private_input_path_not_absolute:{name}")
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(private_root)
        except (OSError, ValueError):
            blockers.append(f"private_input_outside_verified_root:{name}")
            continue
        if item.get("path") != str(resolved):
            blockers.append(f"private_input_path_mismatch:{name}")
        if item.get("access_control_verified") is not True:
            blockers.append(f"private_input_access_control_unverified:{name}")
        if item.get("contains_real_secret") is not False:
            blockers.append(f"private_input_may_contain_real_secret:{name}")
        if not resolved.is_file():
            blockers.append(f"private_input_not_regular_file:{name}")
            continue
        try:
            data = resolved.read_bytes()
        except OSError:
            blockers.append(f"private_input_unreadable:{name}")
            continue
        digest = sha256(data).hexdigest()
        if (
            item.get("sha256") != digest
            or not SHA256.fullmatch(str(item.get("sha256") or ""))
        ):
            blockers.append(f"private_input_sha256_mismatch:{name}")
        if item.get("bytes") != len(data) or not data:
            blockers.append(f"private_input_size_mismatch:{name}")


def _collect_command_templates(
    contract: Mapping[str, Any],
    blockers: list[str],
) -> list[tuple[str, str, list[str]]]:
    rows: list[tuple[str, str, list[str]]] = []
    locations = (
        ("setup", "evaluator_setup", "command_argv_templates"),
        (
            "provider_native_analysis",
            "provider_native_analysis",
            "command_argv_template",
        ),
        (
            "provider_native_analysis",
            "provider_native_analysis",
            "command_argv_templates",
        ),
        (
            "permission_precheck",
            "authorized_active_probe",
            "permission_precheck_argv_template",
        ),
        (
            "active_probe",
            "authorized_active_probe",
            "probe_argv_template",
        ),
        (
            "active_probe",
            "authorized_active_probe",
            "probe_argv_templates",
        ),
        (
            "postcondition",
            "authorized_active_probe",
            "postcondition_argv_template",
        ),
        (
            "postcondition",
            "authorized_active_probe",
            "postcondition_argv_templates",
        ),
        (
            "audit_telemetry",
            "audit_telemetry",
            "command_argv_template",
        ),
        (
            "cleanup",
            "authorized_active_probe",
            "cleanup_argv_template",
        ),
        (
            "cleanup",
            "authorized_active_probe",
            "cleanup_argv_templates",
        ),
        (
            "post_cleanup_inventory",
            "authorized_active_probe",
            "post_cleanup_inventory_argv_template",
        ),
        (
            "post_cleanup_inventory",
            "authorized_active_probe",
            "post_cleanup_inventory_argv_templates",
        ),
    )
    for phase, section_name, field_name in locations:
        section = contract.get(section_name)
        if not isinstance(section, Mapping) or field_name not in section:
            continue
        value = section[field_name]
        path = f"{section_name}.{field_name}"
        if field_name.endswith("_templates"):
            if not isinstance(value, list):
                blockers.append(f"argv_templates_not_list:{path}")
                continue
            for index, argv in enumerate(value):
                if not _is_argv(argv):
                    blockers.append(f"invalid_argv_template:{path}[{index}]")
                    continue
                rows.append((phase, f"{path}[{index}]", argv))
        else:
            if not _is_argv(value):
                blockers.append(f"invalid_argv_template:{path}")
                continue
            rows.append((phase, path, value))
    return rows


def _validate_resolved_argv(
    argv: Sequence[str],
    *,
    phase: str,
    platform: str,
    runtime_values: Mapping[str, str],
    template_path: str,
    blockers: list[str],
) -> None:
    if not argv:
        blockers.append(f"program_not_allowlisted:{template_path}")
        return
    if platform == "AWS":
        _validate_aws_argv(argv, phase, template_path, blockers)
    elif platform == "GCP":
        _validate_gcloud_argv(
            argv,
            phase,
            runtime_values,
            template_path,
            blockers,
        )
    elif platform == "AZURE":
        if argv[0] == "az":
            _validate_az_argv(
                argv,
                phase,
                runtime_values,
                template_path,
                blockers,
            )
        elif argv[0] == "curl":
            _validate_azure_curl_argv(
                argv,
                phase,
                runtime_values,
                template_path,
                blockers,
            )
        else:
            blockers.append(f"program_not_allowlisted:{template_path}")
    else:
        blockers.append(f"program_not_allowlisted:{template_path}")
    if any(PLACEHOLDER.search(token) for token in argv):
        blockers.append(f"unresolved_placeholder:{template_path}")


def _validate_aws_argv(
    argv: Sequence[str],
    phase: str,
    template_path: str,
    blockers: list[str],
) -> None:
    if argv[0] != "aws" or len(argv) < 3:
        blockers.append(f"program_not_allowlisted:{template_path}")
        return
    if (argv[1], argv[2]) not in AWS_COMMAND_ALLOWLIST.get(phase, set()):
        blockers.append(f"aws_operation_not_allowlisted:{template_path}")
    if any(_flag_matches(token, FORBIDDEN_AWS_FLAGS) for token in argv):
        blockers.append(f"forbidden_aws_flag:{template_path}")


def _validate_gcloud_argv(
    argv: Sequence[str],
    phase: str,
    runtime_values: Mapping[str, str],
    template_path: str,
    blockers: list[str],
) -> None:
    if argv[0] != "gcloud" or len(argv) < 3:
        blockers.append(f"program_not_allowlisted:{template_path}")
        return
    command = _gcloud_command_prefix(argv)
    if command not in GCLOUD_COMMAND_ALLOWLIST.get(phase, set()):
        blockers.append(f"gcloud_operation_not_allowlisted:{template_path}")
    if any(_flag_matches(token, FORBIDDEN_GCLOUD_FLAGS) for token in argv):
        blockers.append(f"forbidden_gcloud_flag:{template_path}")
    project_values = _flag_values(argv, "--project")
    expected_project = runtime_values.get("GCP_OWNER_PROJECT_ID")
    if project_values != [expected_project]:
        blockers.append(f"gcloud_project_scope_mismatch:{template_path}")
    impersonated = _flag_values(argv, "--impersonate-service-account")
    expected_probe = runtime_values.get(
        "DEDICATED_GCP_PROBE_SERVICE_ACCOUNT"
    )
    if phase == "active_probe":
        if impersonated != [expected_probe]:
            blockers.append(
                f"gcloud_probe_identity_mismatch:{template_path}"
            )
    elif impersonated:
        blockers.append(
            f"gcloud_impersonation_outside_probe:{template_path}"
        )


def _validate_az_argv(
    argv: Sequence[str],
    phase: str,
    runtime_values: Mapping[str, str],
    template_path: str,
    blockers: list[str],
) -> None:
    if argv[0] != "az" or len(argv) < 3:
        blockers.append(f"program_not_allowlisted:{template_path}")
        return
    command = _az_command_prefix(argv)
    if command not in AZ_COMMAND_ALLOWLIST.get(phase, set()):
        blockers.append(f"az_operation_not_allowlisted:{template_path}")
    if any(_flag_matches(token, FORBIDDEN_AZ_FLAGS) for token in argv):
        blockers.append(f"forbidden_az_flag:{template_path}")
    subscription_values = _flag_values(argv, "--subscription")
    if subscription_values != [
        runtime_values.get("AZURE_SUBSCRIPTION_ID")
    ]:
        blockers.append(f"az_subscription_scope_mismatch:{template_path}")
    if "--only-show-errors" not in argv:
        blockers.append(f"az_only_show_errors_missing:{template_path}")

    run_group = runtime_values.get("RUN_OWNED_AZURE_RESOURCE_GROUP")
    account = runtime_values.get("RUN_OWNED_AZURE_STORAGE_ACCOUNT")
    subscription = runtime_values.get("AZURE_SUBSCRIPTION_ID")
    account_id = (
        f"/subscriptions/{subscription}/resourceGroups/{run_group}/"
        f"providers/Microsoft.Storage/storageAccounts/{account}"
    )
    blob_service_id = account_id + "/blobServices/default"

    if command == ("storage", "account", "create"):
        if _flag_values(argv, "--name") != [account]:
            blockers.append(f"az_storage_account_mismatch:{template_path}")
        if _flag_values(argv, "--resource-group") != [run_group]:
            blockers.append(f"az_resource_group_mismatch:{template_path}")
        for flag, value in (
            ("--allow-blob-public-access", "true"),
            ("--https-only", "true"),
            ("--min-tls-version", "TLS1_2"),
            ("--public-network-access", "Enabled"),
            ("--default-action", "Allow"),
        ):
            if _flag_values(argv, flag) != [value]:
                blockers.append(
                    f"az_storage_safety_setting_mismatch:{template_path}:"
                    f"{flag}"
                )
    elif command == ("storage", "account", "show"):
        if _flag_values(argv, "--ids") != [account_id]:
            blockers.append(f"az_storage_account_mismatch:{template_path}")

    if command[:2] == ("storage", "container") or command[:2] == (
        "storage", "blob"
    ):
        if _flag_values(argv, "--account-name") != [
            runtime_values.get("RUN_OWNED_AZURE_STORAGE_ACCOUNT")
        ]:
            blockers.append(f"az_storage_account_mismatch:{template_path}")
        if _flag_values(argv, "--auth-mode") != ["key"]:
            blockers.append(f"az_storage_auth_mode_mismatch:{template_path}")

    prod = runtime_values.get("RUN_OWNED_AZURE_PROD_CONTAINER")
    dev = runtime_values.get("RUN_OWNED_AZURE_DEV_CONTAINER")
    if command in {
        ("storage", "container", "create"),
        ("storage", "container", "show-permission"),
    }:
        names = _flag_values(argv, "--name")
        if len(names) != 1 or names[0] not in {prod, dev}:
            blockers.append(f"az_container_scope_mismatch:{template_path}")
        if command == ("storage", "container", "create"):
            expected_access = "blob" if names == [prod] else "container"
            if _flag_values(argv, "--public-access") != [expected_access]:
                blockers.append(
                    f"az_container_access_mismatch:{template_path}"
                )
    if command in {
        ("storage", "blob", "upload"),
        ("storage", "blob", "show"),
    }:
        containers = _flag_values(argv, "--container-name")
        if len(containers) != 1 or containers[0] not in {prod, dev}:
            blockers.append(f"az_blob_container_mismatch:{template_path}")
        if _flag_values(argv, "--name") != [
            runtime_values.get("RUN_OWNED_AZURE_CANARY_BLOB")
        ]:
            blockers.append(f"az_blob_name_mismatch:{template_path}")
    if command == ("storage", "blob", "upload"):
        if _flag_values(argv, "--file") != [
            runtime_values.get("EVALUATOR_PRIVATE_AZURE_CANARY_FILE")
        ]:
            blockers.append(f"az_blob_input_mismatch:{template_path}")
        if _flag_values(argv, "--overwrite") != ["true"]:
            blockers.append(f"az_blob_overwrite_mismatch:{template_path}")

    if command in {
        ("group", "create"),
        ("group", "delete"),
        ("group", "exists"),
    } and _flag_values(argv, "--name") != [run_group]:
        blockers.append(f"az_resource_group_mismatch:{template_path}")
    if command == ("group", "delete") and "--no-wait" in argv:
        blockers.append(f"az_async_cleanup_forbidden:{template_path}")

    if command == ("monitor", "log-analytics", "query"):
        if _flag_values(argv, "--workspace") != [
            runtime_values.get(
                "DEDICATED_AZURE_LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID"
            )
        ]:
            blockers.append(f"az_log_workspace_mismatch:{template_path}")
        if _flag_values(argv, "--timespan") != [
            runtime_values.get("RUN_STARTED_AT")
            + "/"
            + runtime_values.get("RUN_FINISHED_AT")
        ]:
            blockers.append(f"az_log_timespan_mismatch:{template_path}")
        queries = _flag_values(argv, "--analytics-query")
        required_query_values = {
            account,
            runtime_values.get("RUNNER_EGRESS_IP"),
            runtime_values.get("AZURE_PROD_GET_CLIENT_REQUEST_ID"),
            runtime_values.get("AZURE_DEV_LIST_CLIENT_REQUEST_ID"),
            runtime_values.get("AZURE_DEV_GET_CLIENT_REQUEST_ID"),
        }
        if (
            len(queries) != 1
            or 'AuthenticationType == "Anonymous"' not in queries[0]
            or not all(value in queries[0] for value in required_query_values)
        ):
            blockers.append(f"az_log_query_scope_mismatch:{template_path}")
    if command in {
        ("monitor", "diagnostic-settings", "create"),
        ("monitor", "diagnostic-settings", "show"),
    }:
        resource_values = _flag_values(argv, "--resource")
        if resource_values != [blob_service_id]:
            blockers.append(
                f"az_diagnostic_resource_mismatch:{template_path}"
            )
        if _flag_values(argv, "--name") != [
            runtime_values.get("RUN_OWNED_AZURE_DIAGNOSTIC_SETTING")
        ]:
            blockers.append(
                f"az_diagnostic_name_mismatch:{template_path}"
            )
    if command == ("monitor", "diagnostic-settings", "create"):
        if _flag_values(argv, "--workspace") != [
            runtime_values.get(
                "DEDICATED_AZURE_LOG_ANALYTICS_WORKSPACE_RESOURCE_ID"
            )
        ]:
            blockers.append(
                f"az_diagnostic_workspace_mismatch:{template_path}"
            )


def _validate_azure_curl_argv(
    argv: Sequence[str],
    phase: str,
    runtime_values: Mapping[str, str],
    template_path: str,
    blockers: list[str],
) -> None:
    if phase != "active_probe" or tuple(argv[:2]) != (
        "curl", "--disable"
    ):
        blockers.append(f"curl_probe_not_allowlisted:{template_path}")
        return
    if any(_flag_matches(token, FORBIDDEN_CURL_FLAGS) for token in argv):
        blockers.append(f"forbidden_curl_flag:{template_path}")
    if _flag_values(argv, "--noproxy") != ["*"]:
        blockers.append(f"curl_proxy_not_disabled:{template_path}")
    if _flag_values(argv, "--proto") != ["=https"]:
        blockers.append(f"curl_https_only_missing:{template_path}")
    if _flag_values(argv, "--request") != ["GET"]:
        blockers.append(f"curl_method_not_bounded_get:{template_path}")
    if _flag_values(argv, "--max-redirs") != ["0"]:
        blockers.append(f"curl_redirects_not_disabled:{template_path}")
    if _flag_values(argv, "--output") != [
        runtime_values.get("ORACLE_NULL_SINK")
    ]:
        blockers.append(f"curl_response_not_discarded:{template_path}")

    headers = _flag_values(argv, "--header")
    if len(headers) != 2:
        blockers.append(f"curl_header_set_invalid:{template_path}")
    if any(header.casefold().startswith("authorization:") for header in headers):
        blockers.append(f"curl_authorization_header_forbidden:{template_path}")
    request_headers = [
        header.split(":", 1)[1].strip()
        for header in headers
        if header.casefold().startswith("x-ms-client-request-id:")
    ]
    expected_request_ids = {
        runtime_values.get(name)
        for name in (
            "AZURE_PROD_LIST_CLIENT_REQUEST_ID",
            "AZURE_PROD_GET_CLIENT_REQUEST_ID",
            "AZURE_DEV_LIST_CLIENT_REQUEST_ID",
            "AZURE_DEV_GET_CLIENT_REQUEST_ID",
        )
    }
    if len(request_headers) != 1 or request_headers[0] not in (
        expected_request_ids
    ):
        blockers.append(f"curl_client_request_id_invalid:{template_path}")
    if not any(
        header == "x-ms-version: 2023-11-03" for header in headers
    ):
        blockers.append(f"curl_storage_version_missing:{template_path}")

    urls = _flag_values(argv, "--url")
    account = runtime_values.get("RUN_OWNED_AZURE_STORAGE_ACCOUNT")
    prod = runtime_values.get("RUN_OWNED_AZURE_PROD_CONTAINER")
    dev = runtime_values.get("RUN_OWNED_AZURE_DEV_CONTAINER")
    blob = runtime_values.get("RUN_OWNED_AZURE_CANARY_BLOB")
    allowed_prefixes = {
        f"https://{account}.blob.core.windows.net/{prod}",
        f"https://{account}.blob.core.windows.net/{dev}",
    }
    if len(urls) != 1 or not any(
        urls[0] == prefix + f"/{blob}"
        or urls[0] == prefix + "?restype=container&comp=list&maxresults=1"
        for prefix in allowed_prefixes
    ):
        blockers.append(f"curl_probe_url_out_of_scope:{template_path}")


def _az_command_prefix(argv: Sequence[str]) -> tuple[str, ...]:
    if len(argv) >= 4 and tuple(argv[1:3]) in {
        ("storage", "account"),
        ("storage", "container"),
        ("storage", "blob"),
        ("monitor", "diagnostic-settings"),
        ("monitor", "log-analytics"),
    }:
        return tuple(argv[1:4])
    return tuple(argv[1:3])


def _gcloud_command_prefix(argv: Sequence[str]) -> tuple[str, ...]:
    if tuple(argv[1:3]) == ("logging", "read"):
        return ("logging", "read")
    if len(argv) >= 4 and tuple(argv[1:3]) == ("iam", "roles"):
        return tuple(argv[1:4])
    if len(argv) >= 4 and tuple(argv[1:3]) == ("storage", "buckets"):
        return tuple(argv[1:4])
    if len(argv) >= 4 and tuple(argv[1:3]) == ("storage", "objects"):
        return tuple(argv[1:4])
    if len(argv) >= 4 and tuple(argv[1:3]) == (
        "policy-intelligence", "troubleshoot-policy"
    ):
        return tuple(argv[1:4])
    return tuple(argv[1:3])


def _flag_values(argv: Sequence[str], flag: str) -> list[str]:
    values = []
    for index, token in enumerate(argv):
        if token == flag and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith(flag + "="):
            values.append(token.split("=", 1)[1])
    return values


def _flag_matches(token: str, flags: set[str]) -> bool:
    return token in flags or any(token.startswith(flag + "=") for flag in flags)


def _validate_step_coverage(
    contract: Mapping[str, Any],
    steps: Sequence[ResolvedStep],
    blockers: list[str],
) -> None:
    if blockers:
        return
    phases = Counter(step.phase for step in steps)
    for phase in (
        "provider_native_analysis",
        "active_probe",
        "postcondition",
        "audit_telemetry",
        "cleanup",
        "post_cleanup_inventory",
    ):
        if not phases[phase]:
            blockers.append(f"required_execution_phase_missing:{phase}")
    if contract.get("visibility") != "evaluator_only":
        blockers.append("contract_not_evaluator_only")
    if contract.get("status") != "requires_runtime_resolution":
        blockers.append("contract_status_not_runtime_resolution")


def _find_placeholders(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(PLACEHOLDER.findall(value))
    elif isinstance(value, Mapping):
        for child in value.values():
            found.update(_find_placeholders(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_find_placeholders(child))
    return found


def _replace_placeholders(
    value: str,
    runtime_values: Mapping[str, str],
) -> str:
    return PLACEHOLDER.sub(
        lambda match: runtime_values[match.group(1)],
        value,
    )


def _is_argv(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(token, str) and token for token in value)
    )


def _sentinel_valid(
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> bool:
    sentinel = policy.get("authorization_sentinel")
    return (
        isinstance(sentinel, Mapping)
        and authorization.get("authorization_sentinel")
        == sentinel.get("required_value")
    )


def _reject_sensitive_input_keys(
    value: Mapping[str, Any],
    location: str,
    blockers: list[str],
) -> None:
    for key in value:
        if SENSITIVE_KEY.search(str(key)):
            blockers.append(f"sensitive_input_key_forbidden:{location}.{key}")


def _runtime_binding_digest(values: Mapping[str, str]) -> str:
    hashes = {
        key: sha256(value.encode("utf-8")).hexdigest()
        for key, value in sorted(values.items())
    }
    payload = json.dumps(
        hashes,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _safe_collection_length(value: Any) -> int:
    if isinstance(value, Mapping):
        return len(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return len(value)
    return 0


def _argv_digest(argv: Sequence[str]) -> str:
    payload = json.dumps(
        list(argv),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must be UTC Z")
    return datetime.fromisoformat(value[:-1] + "+00:00")
