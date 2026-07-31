#!/usr/bin/env python3
"""Build a leakage-separated provider-oracle protocol-v3 pilot.

All public observations are deterministic projections of pinned upstream
artifacts.  The script creates no synthetic cloud events.  Provider-oracle
labels are written to a separate evaluator file; the configuration-only
control is explicitly labelled epistemic Unknown and is not provider gold.
"""
from __future__ import annotations

from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.cross_cloud_environment import (  # noqa: E402
    CrossCloudTelemetryEnvironment,
)


REAL_ROOT = ROOT / "data" / "real_sources"
DEFAULT_PUBLIC = REAL_ROOT / "provider_oracle_protocol_v3_public.json"
DEFAULT_GOLD = REAL_ROOT / "provider_oracle_protocol_v3_gold.json"
DEFAULT_SPLITS = REAL_ROOT / "provider_oracle_protocol_v3_splits.json"
OTRF_INDEX = REAL_ROOT / "otrf_cloud_breach_s3_runtime_index.json"
CROSS_CLOUD_INDEX = REAL_ROOT / "cross_cloud_full_episode_index.json"
NEGATIVE_CANDIDATE = (
    REAL_ROOT / "gcp_scheduled_transfer_negative_candidate_v1.json"
)
CONFIG_CANDIDATES = (
    REAL_ROOT / "deterministic_config_candidates_v1.json"
)
MANIFEST = REAL_ROOT / "acquisition_manifest.json"
GCP_EPISODE = "crosscloud:gcp:scheduled_transfer:additional:run-0:y"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_observation_id(case_id: str, raw_ref: dict[str, Any]) -> str:
    payload = json.dumps(
        {"case_id": case_id, "raw_ref": raw_ref},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "obs-v3-" + _sha256(payload.encode("utf-8"))[:24]


def _manifest_artifact(source_id: str, name: str) -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source = next(
        item for item in manifest["sources"] if item["source_id"] == source_id
    )
    return deepcopy(
        next(item for item in source["artifacts"] if item["name"] == name)
    )


def _public_case(
    *,
    case_id: str,
    source_id: str,
    platform: str,
    description: str,
    environment: str,
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "candidate_id": case_id,
        "source_id": source_id,
        "upstream_dataset_id": "source-pinned; evaluator lineage withheld",
        "author": "upstream publisher",
        "published_date": "source registry",
        "description": description,
        "environment": environment,
        "platform": platform,
        "evidence_layers": sorted({
            item["evidence_layer"] for item in observations
        }),
        "observation_ids": [
            item["observation_id"] for item in observations
        ],
        "path_label": None,
        "evidence_state": None,
    }


def _decorate_runtime(
    event: dict[str, Any],
    *,
    case_id: str,
    provider_decision: str,
    target_resource: str,
    oracle_kind: str,
    scope_completeness: str = "complete",
) -> dict[str, Any]:
    item = deepcopy(event)
    item["candidate_id"] = case_id
    item["observation_id"] = _stable_observation_id(
        case_id, item["raw_ref"]
    )
    item["evidence_layer"] = "runtime"
    item["oracle_kind"] = oracle_kind
    item["scope_completeness"] = scope_completeness
    item["provider_decision"] = provider_decision
    item["target_resource"] = target_resource
    item["path_label"] = None
    item["evidence_state"] = None
    return item


def _cross_cloud_episode_events(
    platform: str,
    attack: str,
) -> list[dict[str, Any]]:
    episode_id = (
        f"crosscloud:{platform.casefold()}:{attack}:"
        "additional:run-0:y"
    )
    environment = CrossCloudTelemetryEnvironment.from_file(
        ROOT,
        CROSS_CLOUD_INDEX,
        episode_id,
        budget=None,
    )
    return list(environment._environment._events)


def _request_resource(event: dict[str, Any]) -> str:
    request = event.get("request")
    if isinstance(request, str) and "\nresource=" in request:
        return request.rsplit("\nresource=", 1)[1]
    return str(event.get("target_resource") or "")


def _build_otrf_positive() -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v3:otrf:s3-assumed-role-read"
    index = json.loads(OTRF_INDEX.read_text(encoding="utf-8"))
    actor_fragment = "assumed-role/MordorNginxStack-BankingWAFRole"
    selected = {}
    for event in index["observations"]:
        if actor_fragment not in str(event.get("actor_id")):
            continue
        if event.get("event_status") != "Success":
            continue
        operation = event.get("operation")
        if operation in {"ListObjects", "GetObject"} and operation not in selected:
            selected[operation] = event
    if set(selected) != {"ListObjects", "GetObject"}:
        raise ValueError("OTRF positive case lacks exact ListObjects/GetObject")
    list_target = selected["ListObjects"]["request"]["bucketName"]
    get_target = selected["GetObject"]["request"]["bucketName"]
    if list_target != get_target:
        raise ValueError("OTRF positive operations target different buckets")
    if selected["ListObjects"]["actor_id"] != selected["GetObject"]["actor_id"]:
        raise ValueError("OTRF positive operations use different principals")

    observations = [
        _decorate_runtime(
            selected["ListObjects"],
            case_id=case_id,
            provider_decision="allow",
            target_resource=list_target,
            oracle_kind="AWS CloudTrail",
        ),
        _decorate_runtime(
            selected["GetObject"],
            case_id=case_id,
            provider_decision="allow",
            target_resource=(
                f"{get_target}/{selected['GetObject']['request']['key']}"
            ),
            oracle_kind="AWS CloudTrail",
        ),
    ]
    by_operation = {item["operation"]: item for item in observations}
    case = _public_case(
        case_id=case_id,
        source_id="otrf_security_datasets",
        platform="AWS",
        description=(
            "Determine whether the observed assumed-role principal reaches "
            "an S3 data object through the evidenced operations."
        ),
        environment="published CloudGoat-linked AWS lab telemetry",
        observations=observations,
    )
    gold = {
        "case_id": case_id,
        "independence_group": "cloudgoat-scenario:cloud_breach_s3",
        "source_id": "otrf_security_datasets",
        "platform": "AWS",
        "gold_state": "Reachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": "otrf-s3-read-path",
            "nodes": [
                {
                    "node_id": "n-role",
                    "type": "identity",
                    "label": "observed assumed-role session",
                },
                {
                    "node_id": "n-bucket",
                    "type": "object_storage",
                    "label": "observed S3 bucket",
                },
                {
                    "node_id": "n-object",
                    "type": "data_object",
                    "label": "observed S3 object",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-list",
                    "source": "n-role",
                    "target": "n-bucket",
                    "type": "enumerate",
                },
                {
                    "edge_id": "e-read",
                    "source": "n-bucket",
                    "target": "n-object",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [
            by_operation["ListObjects"]["observation_id"],
            by_operation["GetObject"]["observation_id"],
        ],
        "refute_observation_ids": [],
        "control_observation_ids": [],
        "semantic_scope": (
            "Reachability starts at the already observed assumed-role "
            "principal; the upstream proxy exploitation is not re-labelled "
            "as provider runtime gold."
        ),
    }
    return {"case": case, "observations": observations}, gold


def _build_gcp_negative() -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v3:gcp:scheduled-function-bucket-list"
    candidate = json.loads(NEGATIVE_CANDIDATE.read_text(encoding="utf-8"))
    instance = candidate["replication"]["instances"][0]
    expected_indices = {
        "function": 152,
        "scheduler": 142,
        "deny": 60,
        "target_control": 4,
    }
    environment = CrossCloudTelemetryEnvironment.from_file(
        ROOT,
        CROSS_CLOUD_INDEX,
        GCP_EPISODE,
        budget=None,
    )
    events_by_index = {
        item["raw_ref"]["record_index"]: item
        for item in environment._environment._events
    }
    if set(expected_indices.values()) - set(events_by_index):
        raise ValueError("GCP negative case raw records changed")
    raw_events = {
        key: events_by_index[index]
        for key, index in expected_indices.items()
    }
    denied = raw_events["deny"]
    control = raw_events["target_control"]
    if (
        denied["actor_id"] != instance["principal"]
        or instance["target"] not in denied["request"]
        or denied["event_status"] != "Code:7"
    ):
        raise ValueError("GCP denial no longer matches frozen certificate")
    if (
        control["actor_id"] == denied["actor_id"]
        or instance["target"] not in control["request"]
        or control["event_status"] != "SuccessOrUnspecified"
    ):
        raise ValueError("GCP same-target success control is invalid")

    observations = [
        _decorate_runtime(
            raw_events["function"],
            case_id=case_id,
            provider_decision="allow",
            target_resource="check-bucket-changes function",
            oracle_kind="GCP Cloud Audit Logs",
        ),
        _decorate_runtime(
            raw_events["scheduler"],
            case_id=case_id,
            provider_decision="allow",
            target_resource="check-bucket-changes scheduler job",
            oracle_kind="GCP Cloud Audit Logs",
        ),
        _decorate_runtime(
            denied,
            case_id=case_id,
            provider_decision="deny",
            target_resource=instance["target"],
            oracle_kind="GCP Cloud Audit Logs",
        ),
        _decorate_runtime(
            control,
            case_id=case_id,
            provider_decision="allow_control_different_principal",
            target_resource=instance["target"],
            oracle_kind="GCP Cloud Audit Logs",
        ),
    ]
    by_index = {
        item["raw_ref"]["record_index"]: item for item in observations
    }
    case = _public_case(
        case_id=case_id,
        source_id="cross_cloud_observability_2026",
        platform="GCP",
        description=(
            "Determine whether the scheduled function's service account can "
            "enumerate the exact Cloud Storage bucket."
        ),
        environment="DOI-published controlled GCP subscription telemetry",
        observations=observations,
    )
    gold = {
        "case_id": case_id,
        "independence_group": "crosscloud-family:scheduled_transfer",
        "source_id": "cross_cloud_observability_2026",
        "platform": "GCP",
        "gold_state": "NotReachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": "gcp-scheduled-list-path",
            "nodes": [
                {
                    "node_id": "n-function",
                    "type": "compute",
                    "label": "scheduled Cloud Function",
                },
                {
                    "node_id": "n-service-account",
                    "type": "workload_identity",
                    "label": "function service account",
                },
                {
                    "node_id": "n-bucket",
                    "type": "object_storage",
                    "label": "run Cloud Storage bucket",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-function-identity",
                    "source": "n-function",
                    "target": "n-service-account",
                    "type": "impersonate",
                },
                {
                    "edge_id": "e-list-bucket",
                    "source": "n-service-account",
                    "target": "n-bucket",
                    "type": "enumerate",
                },
            ],
        },
        "support_observation_ids": [by_index[152]["observation_id"]],
        "refute_observation_ids": [by_index[60]["observation_id"]],
        "control_observation_ids": [
            by_index[142]["observation_id"],
            by_index[4]["observation_id"],
        ],
        "replication": {
            "independent_runs": candidate["replication"]["independent_runs"],
            "total_denied_attempts": candidate["replication"][
                "total_denied_attempts"
            ],
            "replicates_are_one_independence_group": True,
        },
        "semantic_scope": (
            "The provider-native code-7 denial refutes the exact "
            "service-account, operation, and bucket edge. A different "
            "principal's success proves the target was live; it is not "
            "support for the denied principal."
        ),
    }
    return {"case": case, "observations": observations}, gold


def _build_crosscloud_secret_positive(
    *,
    platform: str,
    operation: str,
    case_id: str,
    attack: str,
    principal_preference: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    events = _cross_cloud_episode_events(platform, attack)
    candidates = [
        event
        for event in events
        if event.get("operation") == operation
        and event.get("event_status") == "SuccessOrUnspecified"
        and (
            principal_preference is None
            or principal_preference in str(event.get("actor_id"))
        )
    ]
    if not candidates:
        raise ValueError(f"{case_id} lacks a successful secret access")
    selected = candidates[0]
    target = _request_resource(selected)
    if not target and operation == "GetSecretValue":
        request = selected.get("request") or ""
        if '"secretId":' not in request:
            raise ValueError("AWS secret access lacks exact secretId")
        target = request.split('"secretId":', 1)[1].split('"', 2)[1]
    if not target:
        raise ValueError(f"{case_id} lacks an exact secret target")
    if any(
        event.get("operation") == operation
        and event.get("actor_id") == selected.get("actor_id")
        and _request_resource(event) == _request_resource(selected)
        and event.get("event_status") not in {
            "Success",
            "SuccessOrUnspecified",
        }
        for event in events
    ):
        raise ValueError(f"{case_id} has a contrary provider outcome")

    oracle = (
        "AWS CloudTrail" if platform == "AWS" else "GCP Cloud Audit Logs"
    )
    observation = _decorate_runtime(
        selected,
        case_id=case_id,
        provider_decision="allow",
        target_resource=target,
        oracle_kind=oracle,
    )
    source_node_type = (
        "workload_identity"
        if platform == "GCP"
        else "identity"
    )
    case = _public_case(
        case_id=case_id,
        source_id="cross_cloud_observability_2026",
        platform=platform,
        description=(
            "Determine whether the observed low-privilege principal reaches "
            "the exact managed-secret target through the evidenced API call."
        ),
        environment=(
            f"DOI-published controlled {platform} subscription telemetry"
        ),
        observations=[observation],
    )
    gold = {
        "case_id": case_id,
        "independence_group": f"crosscloud-family:{attack}",
        "source_id": "cross_cloud_observability_2026",
        "platform": platform,
        "gold_state": "Reachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": f"{platform.casefold()}-secret-read-path",
            "nodes": [
                {
                    "node_id": "n-principal",
                    "type": source_node_type,
                    "label": "observed low-privilege principal",
                },
                {
                    "node_id": "n-secret-service",
                    "type": "cloud_service",
                    "label": "managed secret API",
                },
                {
                    "node_id": "n-secret",
                    "type": "secret_store",
                    "label": "exact secret target",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-invoke-secret-api",
                    "source": "n-principal",
                    "target": "n-secret-service",
                    "type": "invoke",
                },
                {
                    "edge_id": "e-read-secret",
                    "source": "n-secret-service",
                    "target": "n-secret",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [observation["observation_id"]],
        "refute_observation_ids": [],
        "control_observation_ids": [],
        "semantic_scope": (
            "Gold starts at the exact observed principal and ends at the "
            "managed secret. It does not promote the upstream walkthrough "
            "or any unobserved credential-acquisition predecessor to gold."
        ),
    }
    return {"case": case, "observations": [observation]}, gold


def _build_gcp_archive_positive() -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v3:gcp:archive-object-read"
    events = _cross_cloud_episode_events("gcp", "archive_collected_data")
    successful = [
        event
        for event in events
        if event.get("operation") in {
            "storage.objects.list",
            "storage.objects.get",
        }
        and event.get("event_status") == "SuccessOrUnspecified"
    ]
    list_event = next(
        event
        for event in successful
        if event["operation"] == "storage.objects.list"
    )
    get_event = next(
        event
        for event in successful
        if event["operation"] == "storage.objects.get"
    )
    if list_event["actor_id"] != get_event["actor_id"]:
        raise ValueError("GCP archive operations use different principals")
    list_target = _request_resource(list_event)
    get_target = _request_resource(get_event)
    if not get_target.startswith(list_target + "/objects/"):
        raise ValueError("GCP archive list/get targets do not align")
    observations = [
        _decorate_runtime(
            list_event,
            case_id=case_id,
            provider_decision="allow",
            target_resource=list_target,
            oracle_kind="GCP Cloud Audit Logs",
        ),
        _decorate_runtime(
            get_event,
            case_id=case_id,
            provider_decision="allow",
            target_resource=get_target,
            oracle_kind="GCP Cloud Audit Logs",
        ),
    ]
    by_operation = {item["operation"]: item for item in observations}
    case = _public_case(
        case_id=case_id,
        source_id="cross_cloud_observability_2026",
        platform="GCP",
        description=(
            "Determine whether the observed service account enumerates the "
            "bucket and reads an exact object."
        ),
        environment="DOI-published controlled GCP subscription telemetry",
        observations=observations,
    )
    gold = {
        "case_id": case_id,
        "independence_group": (
            "crosscloud-family:archive_collected_data"
        ),
        "source_id": "cross_cloud_observability_2026",
        "platform": "GCP",
        "gold_state": "Reachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": "gcp-archive-object-read-path",
            "nodes": [
                {
                    "node_id": "n-principal",
                    "type": "workload_identity",
                    "label": "observed service account",
                },
                {
                    "node_id": "n-bucket",
                    "type": "object_storage",
                    "label": "archive bucket",
                },
                {
                    "node_id": "n-object",
                    "type": "data_object",
                    "label": "archive object",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-list",
                    "source": "n-principal",
                    "target": "n-bucket",
                    "type": "enumerate",
                },
                {
                    "edge_id": "e-read",
                    "source": "n-bucket",
                    "target": "n-object",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [
            by_operation["storage.objects.list"]["observation_id"],
            by_operation["storage.objects.get"]["observation_id"],
        ],
        "refute_observation_ids": [],
        "control_observation_ids": [],
        "semantic_scope": (
            "Reachability starts at the observed service account. The exact "
            "list and object-read audit records support both mandatory edges."
        ),
    }
    return {"case": case, "observations": observations}, gold


def _build_config_unknown() -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v3:awsgoat:dynamodb-config-only"
    candidates = json.loads(CONFIG_CANDIDATES.read_text(encoding="utf-8"))
    candidate = next(
        item
        for item in candidates["cases"]
        if item["case_id"] == "awsgoat_m1_ssrf_dynamodb"
    )
    assertion = candidate["configuration_assertions"][0]
    artifact = _manifest_artifact("awsgoat", "snapshot.zip")
    archive_path = ROOT / artifact["relative_path"]
    member_suffix = "/" + assertion["member_ref"]
    with ZipFile(archive_path) as archive:
        matches = [
            name for name in archive.namelist() if name.endswith(member_suffix)
        ]
        if len(matches) != 1:
            raise ValueError("AWSGoat Terraform member is ambiguous or missing")
        member = matches[0]
        raw = archive.read(member)
    text = raw.decode("utf-8")
    missing = [
        fragment
        for fragment in assertion["expected_fragments"]
        if fragment not in text
    ]
    if missing:
        raise ValueError(f"AWSGoat frozen fragments changed: {missing}")
    raw_ref = {
        "relative_path": artifact["relative_path"],
        "archive_sha256": artifact["sha256"],
        "member_path": member,
        "member_sha256": _sha256(raw),
        "line_scope": "literal fragments; exact line numbers not normalized",
    }
    observation = {
        "observation_id": _stable_observation_id(case_id, raw_ref),
        "candidate_id": case_id,
        "schema": "terraform_hcl",
        "timestamp": None,
        "evidence_layer": "configuration",
        "oracle_kind": "frozen Terraform syntax validation",
        "scope_completeness": "unknown",
        "provider_decision": "not_run",
        "service": "dynamodb.amazonaws.com",
        "operation": "FrozenTerraformConfiguration",
        "actor_type": "configuration",
        "actor_id": None,
        "account_id": None,
        "region": None,
        "event_status": "ConfigurationObserved",
        "target_resource": "blog-users DynamoDB table",
        "source_ip": None,
        "request": {
            "expected_fragments": assertion["expected_fragments"],
            "literal_interpretation": assertion["literal_interpretation"],
        },
        "response": {
            "provider_native_analysis": "not_run",
            "authorized_runtime_probe": "not_run",
        },
        "raw_ref": raw_ref,
        "path_label": None,
        "evidence_state": None,
    }
    observations = [observation]
    case = _public_case(
        case_id=case_id,
        source_id="awsgoat",
        platform="AWS",
        description=(
            "Determine whether the stated low-privilege application entry "
            "can reach the declared DynamoDB data target. Only frozen "
            "configuration is available in this episode."
        ),
        environment="pinned executable-lab Terraform; deployment not run",
        observations=observations,
    )
    gold = {
        "case_id": case_id,
        "independence_group": "awsgoat:module-1",
        "source_id": "awsgoat",
        "platform": "AWS",
        "gold_state": "Unknown",
        "gold_tier": None,
        "label_origin": "protocol_coverage_control",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": "awsgoat-dynamodb-hypothesis",
            "nodes": [
                {
                    "node_id": "n-user",
                    "type": "external_actor",
                    "label": "registered application user",
                },
                {
                    "node_id": "n-lambda",
                    "type": "compute",
                    "label": "application Lambda",
                },
                {
                    "node_id": "n-role",
                    "type": "role",
                    "label": "Lambda execution role",
                },
                {
                    "node_id": "n-db",
                    "type": "database",
                    "label": "blog-users DynamoDB table",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-entry",
                    "source": "n-user",
                    "target": "n-lambda",
                    "type": "exploit",
                },
                {
                    "edge_id": "e-credentials",
                    "source": "n-lambda",
                    "target": "n-role",
                    "type": "use_credential",
                },
                {
                    "edge_id": "e-data",
                    "source": "n-role",
                    "target": "n-db",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [],
        "refute_observation_ids": [],
        "control_observation_ids": [observation["observation_id"]],
        "semantic_scope": (
            "Unknown is an epistemic protocol control, not a claim that the "
            "upstream lab is safe or vulnerable. Frozen Terraform syntax "
            "does not replace complete-scope IAM analysis or a runtime probe."
        ),
    }
    return {"case": case, "observations": observations}, gold


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    pairs = [
        _build_otrf_positive(),
        _build_gcp_negative(),
        _build_crosscloud_secret_positive(
            platform="AWS",
            operation="GetSecretValue",
            case_id="oracle-v3:aws:iam-user-secret-read",
            attack="credentials_from_password_stores",
            principal_preference="user/myusername",
        ),
        _build_crosscloud_secret_positive(
            platform="GCP",
            operation=(
                "google.cloud.secretmanager.v1."
                "SecretManagerService.AccessSecretVersion"
            ),
            case_id="oracle-v3:gcp:low-priority-secret-read",
            attack="credentials_from_password_stores",
            principal_preference="low-priority-account",
        ),
        _build_gcp_archive_positive(),
        _build_config_unknown(),
    ]
    public = {
        "protocol_version": "3.0-pilot",
        "dataset_role": "agent_visible",
        "research_effectiveness_result": False,
        "warning": (
            "Protocol construction and method validation only: five "
            "provider-oracle cases plus one epistemic Unknown control are "
            "insufficient for population-level effectiveness claims."
        ),
        "policy": {
            "generated_cloud_events": 0,
            "gold_file_loaded_by_agent": False,
            "same_tool_schema_for_all_cases": True,
            "unknown_is_not_denial": True,
        },
        "cases": [pair[0]["case"] for pair in pairs],
        "observations": [
            observation
            for pair in pairs
            for observation in pair[0]["observations"]
        ],
    }
    gold = {
        "protocol_version": "3.0-pilot",
        "dataset_role": "evaluator_only",
        "provider_oracle_contract_path": (
            "configs/provider_oracle_gold_contract_v1.json"
        ),
        "human_gold_cases": 0,
        "provider_oracle_gold_cases": 5,
        "epistemic_control_cases": 1,
        "cases": [pair[1] for pair in pairs],
    }
    splits = {
        "protocol_version": "3.0-pilot",
        "frozen": True,
        "statistical_unit": "independence_group",
        "assignments": [
            {
                "case_id": item["case_id"],
                "independence_group": item["independence_group"],
                "split": "protocol_validation",
            }
            for item in gold["cases"]
        ],
    }
    return public, gold, splits


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-output", type=Path, default=DEFAULT_PUBLIC)
    parser.add_argument("--gold-output", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--split-output", type=Path, default=DEFAULT_SPLITS)
    args = parser.parse_args()
    public, gold, splits = build()
    _write(args.public_output, public)
    _write(args.gold_output, gold)
    _write(args.split_output, splits)
    print(json.dumps(
        {
            "protocol_version": public["protocol_version"],
            "public_cases": len(public["cases"]),
            "public_observations": len(public["observations"]),
            "provider_oracle_gold_cases": gold[
                "provider_oracle_gold_cases"
            ],
            "epistemic_control_cases": gold["epistemic_control_cases"],
            "research_effectiveness_result": False,
        },
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
