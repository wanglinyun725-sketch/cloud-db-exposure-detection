#!/usr/bin/env python3
"""Build provider-oracle protocol v8 with outcome-aware exposure controls.

V8 preserves v7 and adds four cases from three pinned Splunk Attack Data
artifacts:

* one effective external EBS-snapshot share (Reachable);
* one rejected share to an invalid grantee (NotReachable);
* one successful RDS password reset without a data-plane query (Unknown);
* one batch of successful S3 ACL changes without Block Public Access state or
  an anonymous read probe (Unknown).

The two snapshot cases share one independence group. Repeated events and
resources from the same upstream artifact are therefore never counted as
independent research samples.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.build_provider_oracle_protocol_v3 import (  # noqa: E402
    _decorate_runtime,
    _public_case,
)
from scripts.data.build_provider_oracle_protocol_v7 import (  # noqa: E402
    HELD_OUT_SOURCES,
    build as build_v7,
)


REAL_ROOT = ROOT / "data" / "real_sources"
EXPANSION_INDEX = REAL_ROOT / "splunk_exposure_expansion_v1.json"
DEFAULT_PUBLIC = REAL_ROOT / "provider_oracle_protocol_v8_public.json"
DEFAULT_GOLD = REAL_ROOT / "provider_oracle_protocol_v8_gold.json"
DEFAULT_SPLITS = REAL_ROOT / "provider_oracle_protocol_v8_splits.json"
SOURCE_ID = "splunk_attack_data_2026_expansion"
RDS_CANDIDATE = "splunk:T1110.002/aws_rds_password_reset"
S3_CANDIDATE = "splunk:T1530/aws_s3_public_bucket"
SNAPSHOT_CANDIDATE = "splunk:T1537/aws_snapshot_exfil"
SNAPSHOT_GROUP = "splunk-dataset:T1537/aws_snapshot_exfil"


def _load_source_case(candidate_id: str) -> dict[str, Any]:
    index = json.loads(EXPANSION_INDEX.read_text(encoding="utf-8"))
    matches = [
        item for item in index["cases"]
        if item["candidate_id"] == candidate_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one expansion case for {candidate_id}"
        )
    return matches[0]


def _select_one(
    observations: list[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
    description: str,
) -> dict[str, Any]:
    matches = [item for item in observations if predicate(item)]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {description}; found {len(matches)}"
        )
    return matches[0]


def _share_grantees(event: dict[str, Any]) -> list[dict[str, Any]]:
    request = event.get("request") or {}
    permission = request.get("createVolumePermission") or {}
    add = permission.get("add") or {}
    items = add.get("items") or []
    if isinstance(items, dict):
        return [items]
    return [item for item in items if isinstance(item, dict)]


def _build_snapshot_positive() -> tuple[dict[str, Any], dict[str, Any]]:
    source = _load_source_case(SNAPSHOT_CANDIDATE)
    raw_events = source["observations"]
    create = _select_one(
        raw_events,
        lambda item: (
            item.get("operation") == "CreateSnapshot"
            and item.get("event_status") == "Success"
            and (item.get("response") or {}).get("encrypted") is False
        ),
        "successful unencrypted CreateSnapshot event",
    )
    snapshot_id = create["response"]["snapshotId"]
    share = _select_one(
        raw_events,
        lambda item: (
            item.get("operation") == "ModifySnapshotAttribute"
            and item.get("event_status") == "Success"
            and (item.get("request") or {}).get("snapshotId") == snapshot_id
            and (item.get("response") or {}).get("_return") is True
            and any(
                grantee.get("userId")
                and str(grantee["userId"]) != str(item.get("account_id"))
                for grantee in _share_grantees(item)
            )
        ),
        "successful external snapshot-share event",
    )
    external_account = next(
        str(item["userId"])
        for item in _share_grantees(share)
        if item.get("userId")
        and str(item["userId"]) != str(share.get("account_id"))
    )
    if create["actor_id"] != share["actor_id"]:
        raise ValueError("snapshot creation and share use different actors")

    case_id = "oracle-v8:splunk:snapshot-external-share"
    create_observation = _decorate_runtime(
        create,
        case_id=case_id,
        provider_decision="allow",
        target_resource=snapshot_id,
        oracle_kind="AWS CloudTrail control-plane outcome",
        scope_completeness="complete_for_snapshot_encryption_state",
    )
    share_target = f"{snapshot_id}/external-account:{external_account}"
    share_observation = _decorate_runtime(
        share,
        case_id=case_id,
        provider_decision="allow",
        target_resource=share_target,
        oracle_kind="AWS CloudTrail permission-change outcome",
        scope_completeness="complete_for_exact_snapshot_share",
    )
    observations = [create_observation, share_observation]
    public_case = _public_case(
        case_id=case_id,
        source_id=SOURCE_ID,
        platform="AWS",
        description=(
            "Determine whether the observed principal made the exact EBS "
            "snapshot available to the named external account. Distinguish "
            "permission exposure from an unobserved downstream data copy."
        ),
        environment=(
            "pinned Splunk Attack Data AWS attack-range CloudTrail; the same "
            "capture records snapshot encryption state and the share result"
        ),
        observations=observations,
    )
    share_id = share_observation["observation_id"]
    create_id = create_observation["observation_id"]
    gold = {
        "case_id": case_id,
        "independence_group": SNAPSHOT_GROUP,
        "source_id": SOURCE_ID,
        "platform": "AWS",
        "gold_state": "Reachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v2",
        "time_scope": share_observation["timestamp"],
        "path": {
            "path_id": "snapshot-external-share-path",
            "nodes": [
                {
                    "node_id": "n-actor",
                    "type": "identity",
                    "label": "observed snapshot-sharing principal",
                },
                {
                    "node_id": "n-share",
                    "type": "data_object",
                    "label": share_target,
                },
            ],
            "edges": [
                {
                    "edge_id": "e-share",
                    "source": "n-actor",
                    "target": "n-share",
                    "type": "grant_permission",
                }
            ],
        },
        "support_observation_ids": [share_id],
        "refute_observation_ids": [],
        "control_observation_ids": [create_id],
        "edge_evidence": {
            "e-share": {
                "support": [share_id],
                "refute": [],
                "controls": [create_id],
            }
        },
        "positive_certificate": {
            "certificate_type": "effective_permission_exposure",
            "exact_principal": share_observation["actor_id"],
            "exact_data_resource": snapshot_id,
            "external_principal": external_account,
            "successful_provider_permission_change": True,
            "mandatory_conditions": {
                "snapshot_encrypted": False,
                "share_response_return": True,
            },
            "contrary_provider_outcome_in_selected_state": False,
        },
        "semantic_scope": (
            f"Reachable means only that unencrypted snapshot {snapshot_id} "
            f"was successfully shared with external account "
            f"{external_account} at {share_observation['timestamp']}. It "
            "does not claim that the external account copied, mounted, or "
            "queried the snapshot data."
        ),
    }
    return {"case": public_case, "observations": observations}, gold


def _build_snapshot_negative() -> tuple[dict[str, Any], dict[str, Any]]:
    source = _load_source_case(SNAPSHOT_CANDIDATE)
    raw_events = source["observations"]
    denial = _select_one(
        raw_events,
        lambda item: (
            item.get("operation") == "ModifySnapshotAttribute"
            and item.get("error_code")
            == "Client.InvalidAMIAttributeItemValue"
        ),
        "invalid snapshot-grantee event",
    )
    snapshot_id = denial["request"]["snapshotId"]
    invalid_grantees = _share_grantees(denial)
    if len(invalid_grantees) != 1 or not invalid_grantees[0].get("userId"):
        raise ValueError("invalid share must identify one exact grantee")
    invalid_account = str(invalid_grantees[0]["userId"])
    control = _select_one(
        raw_events,
        lambda item: (
            item.get("operation") == "ModifySnapshotAttribute"
            and item.get("event_status") == "Success"
            and (item.get("request") or {}).get("snapshotId") == snapshot_id
            and item.get("actor_id") == denial.get("actor_id")
            and (item.get("response") or {}).get("_return") is True
            and any(
                grantee.get("group") == "all"
                for grantee in _share_grantees(item)
            )
        ),
        "same-snapshot successful permission control",
    )

    case_id = "oracle-v8:splunk:snapshot-invalid-grantee"
    target = f"{snapshot_id}/external-account:{invalid_account}"
    control_observation = _decorate_runtime(
        control,
        case_id=case_id,
        provider_decision="allow",
        target_resource=snapshot_id,
        oracle_kind="AWS CloudTrail target-existence control",
        scope_completeness="control_only",
    )
    denial_observation = _decorate_runtime(
        denial,
        case_id=case_id,
        provider_decision="deny",
        target_resource=target,
        oracle_kind="AWS CloudTrail request-validation outcome",
        scope_completeness="complete_for_exact_snapshot_and_grantee",
    )
    observations = [control_observation, denial_observation]
    public_case = _public_case(
        case_id=case_id,
        source_id=SOURCE_ID,
        platform="AWS",
        description=(
            "Determine whether the exact snapshot was shared with the named "
            "invalid external account at the recorded event time. Do not "
            "generalize the result to another grantee or later state."
        ),
        environment=(
            "pinned Splunk Attack Data AWS attack-range CloudTrail with a "
            "same-actor, same-snapshot successful permission control"
        ),
        observations=observations,
    )
    denial_id = denial_observation["observation_id"]
    control_id = control_observation["observation_id"]
    gold = {
        "case_id": case_id,
        "independence_group": SNAPSHOT_GROUP,
        "source_id": SOURCE_ID,
        "platform": "AWS",
        "gold_state": "NotReachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v2",
        "time_scope": denial_observation["timestamp"],
        "path": {
            "path_id": "snapshot-invalid-grantee-path",
            "nodes": [
                {
                    "node_id": "n-actor",
                    "type": "identity",
                    "label": "observed snapshot-sharing principal",
                },
                {
                    "node_id": "n-share",
                    "type": "data_object",
                    "label": target,
                },
            ],
            "edges": [
                {
                    "edge_id": "e-share",
                    "source": "n-actor",
                    "target": "n-share",
                    "type": "grant_permission",
                }
            ],
        },
        "support_observation_ids": [],
        "refute_observation_ids": [denial_id],
        "control_observation_ids": [control_id],
        "edge_evidence": {
            "e-share": {
                "support": [],
                "refute": [denial_id],
                "controls": [control_id],
            }
        },
        "negative_certificate": {
            "certificate_type": "exact_target_denial",
            "exact_principal": denial_observation["actor_id"],
            "exact_operation": denial_observation["operation"],
            "exact_resource": target,
            "provider_native_decision": denial_observation["error_code"],
            "scope_completeness": (
                "complete_for_exact_snapshot_and_grantee"
            ),
            "target_existence_control": (
                "same principal successfully changed permission on the same "
                "snapshot in the same capture"
            ),
            "contrary_success_for_invalid_grantee_in_same_state": False,
        },
        "semantic_scope": (
            f"NotReachable means only that the request to share "
            f"{snapshot_id} with invalid account {invalid_account} failed at "
            f"{denial_observation['timestamp']}. The successful control "
            "proves the snapshot and permission API existed; it does not "
            "turn this request-validation failure into a general IAM denial."
        ),
    }
    return {"case": public_case, "observations": observations}, gold


def _build_rds_unknown() -> tuple[dict[str, Any], dict[str, Any]]:
    source = _load_source_case(RDS_CANDIDATE)
    case_id = "oracle-v8:splunk:rds-password-reset-without-query"
    observations = []
    for raw in source["observations"]:
        if (
            raw.get("operation") != "ModifyDBInstance"
            or raw.get("event_status") != "Success"
        ):
            raise ValueError("RDS control must contain successful resets only")
        target = raw["request"]["dBInstanceIdentifier"]
        observations.append(_decorate_runtime(
            raw,
            case_id=case_id,
            provider_decision="allow",
            target_resource=target,
            oracle_kind="AWS CloudTrail control-plane outcome",
            scope_completeness="incomplete_for_database_data_plane",
        ))
    if len(observations) != 2:
        raise ValueError("RDS control must preserve exactly two observations")
    public_case = _public_case(
        case_id=case_id,
        source_id=SOURCE_ID,
        platform="AWS",
        description=(
            "Determine whether the successful master-password reset proves "
            "that the observed principal reached database records. Separate "
            "credential control from network and SQL data-plane evidence."
        ),
        environment=(
            "pinned Splunk Attack Data AWS attack-range CloudTrail; no "
            "database connection or query record is present"
        ),
        observations=observations,
    )
    control_ids = [item["observation_id"] for item in observations]
    gold = {
        "case_id": case_id,
        "independence_group": (
            "splunk-dataset:T1110.002/aws_rds_password_reset"
        ),
        "source_id": SOURCE_ID,
        "platform": "AWS",
        "gold_state": "Unknown",
        "gold_tier": None,
        "label_origin": "protocol_coverage_control",
        "provider_oracle_contract": "provider_oracle_gold_v2",
        "path": {
            "path_id": "rds-password-to-data-hypothesis",
            "nodes": [
                {
                    "node_id": "n-actor",
                    "type": "identity",
                    "label": "observed password-reset principal",
                },
                {
                    "node_id": "n-db",
                    "type": "database",
                    "label": "database-1 records",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-read",
                    "source": "n-actor",
                    "target": "n-db",
                    "type": "read_data",
                }
            ],
        },
        "support_observation_ids": [],
        "refute_observation_ids": [],
        "control_observation_ids": control_ids,
        "unknown_certificate": {
            "observed": [
                "successful RDS master-password reset",
                "database endpoint returned by the control-plane response",
            ],
            "missing": [
                "network reachability from the principal",
                "successful database authentication",
                "successful SQL query or record read",
            ],
        },
        "semantic_scope": (
            "Unknown is required because a password reset and endpoint "
            "disclosure do not prove that any database record was queried. "
            "The response also reports publiclyAccessible=false, but that "
            "alone does not prove all network paths are blocked."
        ),
    }
    return {"case": public_case, "observations": observations}, gold


def _build_s3_acl_unknown() -> tuple[dict[str, Any], dict[str, Any]]:
    source = _load_source_case(S3_CANDIDATE)
    case_id = "oracle-v8:splunk:s3-acl-without-effective-access-control"
    observations = []
    for raw in source["observations"]:
        if (
            raw.get("operation") != "PutBucketAcl"
            or raw.get("event_status") != "Success"
        ):
            raise ValueError("S3 control must contain successful ACL calls")
        observations.append(_decorate_runtime(
            raw,
            case_id=case_id,
            provider_decision="allow",
            target_resource=raw["request"]["bucketName"],
            oracle_kind="AWS CloudTrail ACL-change outcome",
            scope_completeness="incomplete_for_effective_external_access",
        ))
    if len(observations) != 9:
        raise ValueError("S3 ACL control must preserve nine observations")
    public_case = _public_case(
        case_id=case_id,
        source_id=SOURCE_ID,
        platform="AWS",
        description=(
            "Determine whether the successful ACL changes made any named S3 "
            "bucket effectively readable by an external or anonymous "
            "principal. Require blocker state or an active read observation."
        ),
        environment=(
            "pinned Splunk Attack Data AWS attack-range CloudTrail; Block "
            "Public Access state and anonymous GetObject probes are absent"
        ),
        observations=observations,
    )
    control_ids = [item["observation_id"] for item in observations]
    gold = {
        "case_id": case_id,
        "independence_group": (
            "splunk-dataset:T1530/aws_s3_public_bucket"
        ),
        "source_id": SOURCE_ID,
        "platform": "AWS",
        "gold_state": "Unknown",
        "gold_tier": None,
        "label_origin": "protocol_coverage_control",
        "provider_oracle_contract": "provider_oracle_gold_v2",
        "path": {
            "path_id": "s3-acl-to-effective-read-hypothesis",
            "nodes": [
                {
                    "node_id": "n-actor",
                    "type": "identity",
                    "label": "observed ACL-changing principal",
                },
                {
                    "node_id": "n-buckets",
                    "type": "object_storage",
                    "label": "three named S3 buckets",
                },
            ],
            "edges": [
                {
                    "edge_id": "e-grant",
                    "source": "n-actor",
                    "target": "n-buckets",
                    "type": "grant_permission",
                }
            ],
        },
        "support_observation_ids": [],
        "refute_observation_ids": [],
        "control_observation_ids": control_ids,
        "unknown_certificate": {
            "observed": [
                "successful PutBucketAcl calls",
                "AllUsers or AuthenticatedUsers grantee syntax",
            ],
            "missing": [
                "account-level and bucket-level Block Public Access state",
                "effective GetBucketAcl state after each transition",
                "successful anonymous or external GetObject observation",
            ],
        },
        "semantic_scope": (
            "Unknown prevents a successful ACL API call from being promoted "
            "to effective data exposure. The batch is one upstream lineage, "
            "so nine events and three buckets are not independent samples."
        ),
    }
    return {"case": public_case, "observations": observations}, gold


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    public, gold, _ = build_v7()
    additions = [
        _build_snapshot_positive(),
        _build_snapshot_negative(),
        _build_rds_unknown(),
        _build_s3_acl_unknown(),
    ]

    public = deepcopy(public)
    public["protocol_version"] = "8.0-pilot"
    public["warning"] = (
        "Protocol-scale pilot only: eighteen provider-runtime cases and "
        "seven epistemic controls across sixteen independence groups. V8 "
        "adds outcome-aware permission exposure and two successful-control-"
        "plane Unknown cases; it remains underpowered for population-level "
        "effectiveness claims."
    )
    public["policy"]["provider_oracle_contract_v2_cases"] = 4
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

    gold = deepcopy(gold)
    gold["protocol_version"] = "8.0-pilot"
    gold["provider_oracle_contract_paths"] = [
        "configs/provider_oracle_gold_contract_v1.json",
        "configs/provider_oracle_gold_contract_v2.json",
    ]
    gold["provider_oracle_gold_cases"] = 18
    gold["epistemic_control_cases"] = 7
    gold["cases"].extend(pair[1] for pair in additions)
    gold["cases"] = sorted(gold["cases"], key=lambda item: item["case_id"])
    if len(gold["cases"]) != 25:
        raise ValueError("protocol v8 must contain exactly 25 cases")
    if len({
        item["independence_group"] for item in gold["cases"]
    }) != 16:
        raise ValueError("protocol v8 must contain 16 independence groups")

    splits = {
        "protocol_version": "8.0-pilot",
        "frozen": True,
        "statistical_unit": "independence_group",
        "split_strategy": "source_held_out",
        "warning": (
            "Pilot split only. Every source is assigned wholly to one split; "
            "repeated events and resources from one artifact retain the same "
            "independence group."
        ),
        "held_out_sources": sorted(HELD_OUT_SOURCES),
        "assignments": [
            {
                "case_id": item["case_id"],
                "independence_group": item["independence_group"],
                "source_id": item["source_id"],
                "split": (
                    "source_held_out_test"
                    if item["source_id"] in HELD_OUT_SOURCES
                    else "development"
                ),
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
        "provider_oracle_gold_cases": gold["provider_oracle_gold_cases"],
        "epistemic_control_cases": gold["epistemic_control_cases"],
        "independence_groups": len({
            item["independence_group"] for item in gold["cases"]
        }),
        "negative_independence_groups": len({
            item["independence_group"] for item in gold["cases"]
            if item["gold_state"] == "NotReachable"
        }),
        "research_effectiveness_result": False,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
