#!/usr/bin/env python3
"""Build provider-oracle protocol v4 from independent pinned real sources.

V4 retains the leakage-separated v3 cases, adds two exact successful
data-access cases from Stratus Red Team and Splunk Attack Data, and expands
the epistemic Unknown controls to all five frozen executable-lab
configuration hypotheses.  Configuration-only controls are not provider
gold and do not inherit upstream walkthrough outcomes.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import sys
from typing import Any
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.build_provider_oracle_protocol_v3 import (  # noqa: E402
    CONFIG_CANDIDATES,
    _decorate_runtime,
    _manifest_artifact,
    _public_case,
    _sha256,
    _stable_observation_id,
    build as build_v3,
)


REAL_ROOT = ROOT / "data" / "real_sources"
DEFAULT_PUBLIC = REAL_ROOT / "provider_oracle_protocol_v4_public.json"
DEFAULT_GOLD = REAL_ROOT / "provider_oracle_protocol_v4_gold.json"
DEFAULT_SPLITS = REAL_ROOT / "provider_oracle_protocol_v4_splits.json"
STRATUS_INDEX = REAL_ROOT / "stratus_detonation_log_index.json"
SPLUNK_INDEX = REAL_ROOT / "splunk_full_observation_index.json"
STRATUS_CASE_ID = (
    "stratus:aws.credential-access.secretsmanager-retrieve-secrets"
)
SPLUNK_CASE_ID = (
    "splunk:datasets/attack_techniques/T1530/"
    "aws_exfil_high_no_getobject"
)
V3_CONFIG_CASE_ID = "awsgoat_m1_ssrf_dynamodb"
CONFIG_INDEPENDENCE_GROUPS = {
    "awsgoat_m1_ssrf_dynamodb": "awsgoat:module-1",
    "awsgoat_m2_ecs_secret_rds_credentials": "awsgoat:module-2",
    "azuregoat_ssrf_cosmos_storage": "azuregoat:module-1",
    "azuregoat_prod_dev_blob_control_pair": "azuregoat:module-1",
    (
        "gcpgoat_anonymous_bucket_policy_transition"
    ): "gcpgoat:module-1",
}
V4_CONFIG_CASE_IDS = frozenset(CONFIG_INDEPENDENCE_GROUPS)


def _build_stratus_secret_positive(
) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v4:stratus:iam-user-secret-read"
    index = json.loads(STRATUS_INDEX.read_text(encoding="utf-8"))
    source_case = next(
        item for item in index["cases"]
        if item["candidate_id"] == STRATUS_CASE_ID
    )
    successful = [
        item for item in source_case["observations"]
        if item.get("event_status") == "Success"
    ]
    list_event = next(
        item for item in successful
        if item.get("operation") == "ListSecrets"
    )
    reads = sorted(
        (
            item for item in successful
            if item.get("operation") == "GetSecretValue"
            and (item.get("request") or {}).get("secretId")
            and item.get("actor_id") == list_event.get("actor_id")
            and str(item.get("timestamp") or "")
            >= str(list_event.get("timestamp") or "")
        ),
        key=lambda item: (
            item.get("timestamp") or "",
            (item.get("raw_ref") or {}).get("record_index", 0),
        ),
    )
    if not reads:
        raise ValueError(
            "Stratus case lacks a same-principal exact secret read"
        )
    read_event = reads[0]
    secret_id = read_event["request"]["secretId"]
    observations = [
        _decorate_runtime(
            list_event,
            case_id=case_id,
            provider_decision="allow",
            target_resource="AWS Secrets Manager catalog",
            oracle_kind="AWS CloudTrail",
        ),
        _decorate_runtime(
            read_event,
            case_id=case_id,
            provider_decision="allow",
            target_resource=secret_id,
            oracle_kind="AWS CloudTrail",
        ),
    ]
    case = _public_case(
        case_id=case_id,
        source_id="stratus_red_team",
        platform="AWS",
        description=(
            "Determine whether the observed IAM user reaches an exact "
            "managed secret through the evidenced list and read operations."
        ),
        environment="published Stratus Red Team AWS detonation log",
        observations=observations,
    )
    by_operation = {
        item["operation"]: item for item in observations
    }
    gold = {
        "case_id": case_id,
        "independence_group": (
            "stratus-technique:"
            "aws.credential-access.secretsmanager-retrieve-secrets"
        ),
        "source_id": "stratus_red_team",
        "platform": "AWS",
        "gold_state": "Reachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": "stratus-secret-read-path",
            "nodes": [
                {
                    "node_id": "n-user",
                    "type": "identity",
                    "label": "observed IAM user",
                },
                {
                    "node_id": "n-catalog",
                    "type": "cloud_service",
                    "label": "Secrets Manager catalog",
                },
                {
                    "node_id": "n-secret",
                    "type": "secret_store",
                    "label": "exact observed secret",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-list",
                    "source": "n-user",
                    "target": "n-catalog",
                    "type": "enumerate",
                },
                {
                    "edge_id": "e-read",
                    "source": "n-user",
                    "target": "n-secret",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [
            by_operation["ListSecrets"]["observation_id"],
            by_operation["GetSecretValue"]["observation_id"],
        ],
        "refute_observation_ids": [],
        "control_observation_ids": [],
        "semantic_scope": (
            "Gold begins at the observed IAM user and ends at the exact "
            "secret ARN. It does not infer how the IAM credentials were "
            "acquired."
        ),
    }
    return {"case": case, "observations": observations}, gold


def _build_splunk_object_positive(
) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v4:splunk:iam-user-s3-object-read"
    index = json.loads(SPLUNK_INDEX.read_text(encoding="utf-8"))
    candidates = sorted(
        (
            item for item in index["observations"]
            if item["candidate_id"] == SPLUNK_CASE_ID
            and item.get("operation") == "GetObject"
            and item.get("event_status") == "Success"
            and (item.get("request") or {}).get("bucketName")
            and (item.get("request") or {}).get("key")
            and item.get("actor_id")
        ),
        key=lambda item: (
            item.get("timestamp") or "",
            (item.get("raw_ref") or {}).get("record_index", 0),
        ),
    )
    if not candidates:
        raise ValueError("Splunk case lacks an exact successful GetObject")
    event = candidates[0]
    request = event["request"]
    target = f"{request['bucketName']}/{request['key']}"
    observation = _decorate_runtime(
        event,
        case_id=case_id,
        provider_decision="allow",
        target_resource=target,
        oracle_kind="AWS CloudTrail",
    )
    observations = [observation]
    case = _public_case(
        case_id=case_id,
        source_id="splunk_attack_data",
        platform="AWS",
        description=(
            "Determine whether the observed IAM user reaches the exact "
            "S3 object named in the successful provider audit record."
        ),
        environment="published Splunk Attack Data AWS telemetry",
        observations=observations,
    )
    gold = {
        "case_id": case_id,
        "independence_group": (
            "splunk-dataset:T1530/aws_exfil_high_no_getobject"
        ),
        "source_id": "splunk_attack_data",
        "platform": "AWS",
        "gold_state": "Reachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": "splunk-s3-object-read-path",
            "nodes": [
                {
                    "node_id": "n-user",
                    "type": "identity",
                    "label": "observed IAM user",
                },
                {
                    "node_id": "n-bucket",
                    "type": "object_storage",
                    "label": "exact observed bucket",
                },
                {
                    "node_id": "n-object",
                    "type": "data_object",
                    "label": "exact observed object",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-invoke",
                    "source": "n-user",
                    "target": "n-bucket",
                    "type": "invoke",
                },
                {
                    "edge_id": "e-read",
                    "source": "n-bucket",
                    "target": "n-object",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [observation["observation_id"]],
        "refute_observation_ids": [],
        "control_observation_ids": [],
        "semantic_scope": (
            "Gold is limited to the exact observed IAM user, bucket, key, "
            "and successful GetObject. It does not infer an upstream entry."
        ),
    }
    return {"case": case, "observations": observations}, gold


def _service_slug(service: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", service.casefold()).strip("-")


def _config_case_id(candidate: dict[str, Any]) -> str:
    return "oracle-v4:config-only:" + candidate["case_id"]


def _build_config_unknown(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = _config_case_id(candidate)
    source_id = candidate["source_id"]
    artifact = _manifest_artifact(source_id, "snapshot.zip")
    archive_path = ROOT / artifact["relative_path"]
    observations = []
    with ZipFile(archive_path) as archive:
        for assertion in candidate["configuration_assertions"]:
            member_suffix = "/" + assertion["member_ref"]
            matches = [
                name for name in archive.namelist()
                if name.endswith(member_suffix)
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"{candidate['case_id']} member is ambiguous or missing"
                )
            member = matches[0]
            raw = archive.read(member)
            text = raw.decode("utf-8")
            missing = [
                fragment
                for fragment in assertion["expected_fragments"]
                if fragment not in text
            ]
            if missing:
                raise ValueError(
                    f"{candidate['case_id']} fragments changed: {missing}"
                )
            raw_ref = {
                "relative_path": artifact["relative_path"],
                "archive_sha256": artifact["sha256"],
                "member_path": member,
                "member_sha256": _sha256(raw),
                "assertion_id": assertion["assertion_id"],
                "line_scope": (
                    "literal fragments; exact line numbers not normalized"
                ),
            }
            service = candidate["data_target"]["service"]
            observations.append({
                "observation_id": _stable_observation_id(
                    case_id, raw_ref
                ),
                "candidate_id": case_id,
                "schema": "terraform_hcl",
                "timestamp": None,
                "evidence_layer": "configuration",
                "oracle_kind": "frozen Terraform syntax validation",
                "scope_completeness": "unknown",
                "provider_decision": "not_run",
                "service": _service_slug(service),
                "operation": "FrozenTerraformConfiguration",
                "actor_type": "configuration",
                "actor_id": None,
                "account_id": None,
                "region": None,
                "event_status": "ConfigurationObserved",
                "target_resource": service,
                "source_ip": None,
                "request": {
                    "expected_fragments": assertion[
                        "expected_fragments"
                    ],
                    "literal_interpretation": assertion[
                        "literal_interpretation"
                    ],
                },
                "response": {
                    "provider_native_analysis": "not_run",
                    "authorized_runtime_probe": "not_run",
                },
                "raw_ref": raw_ref,
                "path_label": None,
                "evidence_state": None,
            })

    case = _public_case(
        case_id=case_id,
        source_id=source_id,
        platform=candidate["platform"],
        description=(
            "Determine whether the stated entry reaches the stated cloud "
            "data target. Only hash-frozen configuration assertions are "
            "available; no native analyzer or runtime outcome is present."
        ),
        environment=(
            "pinned executable-lab Terraform; deployment and native "
            "permission oracle not run"
        ),
        observations=observations,
    )
    service = candidate["data_target"]["service"]
    gold = {
        "case_id": case_id,
        "independence_group": CONFIG_INDEPENDENCE_GROUPS[
            candidate["case_id"]
        ],
        "source_id": source_id,
        "platform": candidate["platform"],
        "gold_state": "Unknown",
        "gold_tier": None,
        "label_origin": "protocol_coverage_control",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "path": {
            "path_id": candidate["case_id"] + "-hypothesis",
            "nodes": [
                {
                    "node_id": "n-entry",
                    "type": "external_actor",
                    "label": candidate["entry"],
                },
                {
                    "node_id": "n-workload",
                    "type": "compute",
                    "label": "configured cloud workload",
                },
                {
                    "node_id": "n-data",
                    "type": "database",
                    "label": service,
                },
            ],
            "edges": [
                {
                    "edge_id": "e-entry",
                    "source": "n-entry",
                    "target": "n-workload",
                    "type": "exploit",
                },
                {
                    "edge_id": "e-data",
                    "source": "n-workload",
                    "target": "n-data",
                    "type": "read_data",
                },
            ],
        },
        "support_observation_ids": [],
        "refute_observation_ids": [],
        "control_observation_ids": [
            item["observation_id"] for item in observations
        ],
        "semantic_scope": (
            "Unknown is an epistemic control, not a safety or vulnerability "
            "claim. Frozen syntax cannot replace complete-scope native "
            "permission analysis or a matching runtime probe."
        ),
    }
    return {"case": case, "observations": observations}, gold


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    public_v3, gold_v3, _ = build_v3()
    all_config_candidates = json.loads(
        CONFIG_CANDIDATES.read_text(encoding="utf-8")
    )["cases"]
    config_candidates = [
        candidate
        for candidate in all_config_candidates
        if candidate["case_id"] in V4_CONFIG_CASE_IDS
    ]
    selected_ids = {
        candidate["case_id"] for candidate in config_candidates
    }
    if selected_ids != V4_CONFIG_CASE_IDS:
        missing = sorted(V4_CONFIG_CASE_IDS - selected_ids)
        raise ValueError(
            "protocol v4 frozen configuration controls are missing: "
            + ", ".join(missing)
        )
    additions = [
        _build_stratus_secret_positive(),
        _build_splunk_object_positive(),
        *[
            _build_config_unknown(candidate)
            for candidate in config_candidates
            if candidate["case_id"] != V3_CONFIG_CASE_ID
        ],
    ]
    public = deepcopy(public_v3)
    public["protocol_version"] = "4.0-pilot"
    public["warning"] = (
        "Protocol-scale pilot only: seven provider-runtime cases and five "
        "epistemic controls improve source diversity but remain too small "
        "and negative-class imbalanced for population-level claims."
    )
    public["policy"]["configuration_controls_are_provider_gold"] = False
    public["cases"].extend(pair[0]["case"] for pair in additions)
    public["observations"].extend(
        observation
        for pair in additions
        for observation in pair[0]["observations"]
    )
    public["cases"] = sorted(
        public["cases"], key=lambda item: item["candidate_id"]
    )
    public["observations"] = sorted(
        public["observations"],
        key=lambda item: (
            item["candidate_id"],
            item["observation_id"],
        ),
    )

    gold = deepcopy(gold_v3)
    gold["protocol_version"] = "4.0-pilot"
    gold["provider_oracle_gold_cases"] = 7
    gold["epistemic_control_cases"] = 5
    gold["cases"].extend(pair[1] for pair in additions)
    gold["cases"] = sorted(
        gold["cases"], key=lambda item: item["case_id"]
    )
    if len(gold["cases"]) != 12:
        raise ValueError("protocol v4 must contain exactly 12 cases")
    if len({
        item["case_id"] for item in gold["cases"]
    }) != len(gold["cases"]):
        raise ValueError("protocol v4 case IDs are not unique")

    splits = {
        "protocol_version": "4.0-pilot",
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
    print(json.dumps({
        "protocol_version": public["protocol_version"],
        "public_cases": len(public["cases"]),
        "public_observations": len(public["observations"]),
        "provider_oracle_gold_cases": gold[
            "provider_oracle_gold_cases"
        ],
        "epistemic_control_cases": gold["epistemic_control_cases"],
        "independence_groups": len({
            item["independence_group"] for item in gold["cases"]
        }),
        "research_effectiveness_result": False,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
