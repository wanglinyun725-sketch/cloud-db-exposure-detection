#!/usr/bin/env python3
"""Build provider-oracle protocol v5 with an exact S3/KMS negative control.

V5 preserves every v4 case and adds one author-published AWS CloudTrail
episode in which the same IAM user makes the same CopyObject request against
the same bucket, source object, destination object, and KMS key.  The first
request is rejected because the KMS key is pending deletion; the later
request succeeds.  The verdict is explicitly time-scoped to the rejected
request so the later success is an existence/matching-request control, not a
contradictory label.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.build_provider_oracle_protocol_v3 import (  # noqa: E402
    _decorate_runtime,
    _public_case,
)
from scripts.data.build_provider_oracle_protocol_v4 import (  # noqa: E402
    build as build_v4,
)


REAL_ROOT = ROOT / "data" / "real_sources"
SPLUNK_INDEX = REAL_ROOT / "splunk_full_observation_index.json"
DEFAULT_PUBLIC = REAL_ROOT / "provider_oracle_protocol_v5_public.json"
DEFAULT_GOLD = REAL_ROOT / "provider_oracle_protocol_v5_gold.json"
DEFAULT_SPLITS = REAL_ROOT / "provider_oracle_protocol_v5_splits.json"
SOURCE_CASE_ID = (
    "splunk:datasets/attack_techniques/T1486/s3_file_encryption"
)
EXPECTED_RAW_SHA256 = (
    "29c65aedfdb0a8b8ef56cb77af24842ec7ac5a9ad0497a186a3bda8acc411647"
)
ERROR_CODE = "KMS.KMSInvalidStateException"
ERROR_FRAGMENT = "is pending deletion."


def _read_json_stream(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    values: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            break
        value, cursor = decoder.raw_decode(text, cursor)
        if not isinstance(value, dict):
            raise ValueError("expected concatenated CloudTrail objects")
        values.append(value)
    return values


def _matching_request_key(event: dict[str, Any]) -> tuple[str, ...]:
    request = event.get("request") or {}
    return (
        str(event.get("actor_id") or ""),
        str(event.get("operation") or ""),
        str(event.get("account_id") or ""),
        str(event.get("region") or ""),
        str(request.get("bucketName") or ""),
        str(request.get("x-amz-copy-source") or ""),
        str(request.get("key") or ""),
        str(
            request.get(
                "x-amz-server-side-encryption-aws-kms-key-id"
            )
            or ""
        ),
    )


def _build_s3_kms_negative(
) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v5:splunk:s3-kms-pending-deletion"
    index = json.loads(SPLUNK_INDEX.read_text(encoding="utf-8"))
    events = [
        deepcopy(item)
        for item in index["observations"]
        if item["candidate_id"] == SOURCE_CASE_ID
        and item.get("operation") == "CopyObject"
    ]
    if len(events) != 2:
        raise ValueError("S3/KMS source must contain exactly two CopyObject events")
    denied = next(
        item for item in events if item.get("event_status") == "Error"
    )
    control = next(
        item for item in events if item.get("event_status") == "Success"
    )
    if denied["raw_ref"].get("sha256") != EXPECTED_RAW_SHA256:
        raise ValueError("S3/KMS raw telemetry hash changed")
    if control["raw_ref"].get("sha256") != EXPECTED_RAW_SHA256:
        raise ValueError("S3/KMS control raw telemetry hash changed")
    if _matching_request_key(denied) != _matching_request_key(control):
        raise ValueError("denial and success do not use the exact same request")
    if str(denied.get("timestamp")) >= str(control.get("timestamp")):
        raise ValueError("expected the denied request before the success control")

    raw_path = ROOT / denied["raw_ref"]["relative_path"]
    raw_records = _read_json_stream(raw_path)
    denied_raw = raw_records[denied["raw_ref"]["record_index"]]
    if denied_raw.get("errorCode") != ERROR_CODE:
        raise ValueError("expected provider-native KMS invalid-state code")
    if ERROR_FRAGMENT not in str(denied_raw.get("errorMessage") or ""):
        raise ValueError("expected pending-deletion error message")

    request = denied["request"]
    target = f"{request['bucketName']}/{request['key']}"
    kms_key = request[
        "x-amz-server-side-encryption-aws-kms-key-id"
    ]
    denied["event_status"] = ERROR_CODE
    denied["response"] = {
        "errorCode": denied_raw["errorCode"],
        "errorMessage": denied_raw["errorMessage"],
        "state_interpretation": "KMS key pending deletion at event time",
    }
    denied_observation = _decorate_runtime(
        denied,
        case_id=case_id,
        provider_decision="deny",
        target_resource=target,
        oracle_kind="AWS CloudTrail service outcome",
    )
    control_observation = _decorate_runtime(
        control,
        case_id=case_id,
        provider_decision="allow_control_later_state",
        target_resource=target,
        oracle_kind="AWS CloudTrail same-request success control",
    )
    observations = [denied_observation, control_observation]
    case = _public_case(
        case_id=case_id,
        source_id="splunk_attack_data",
        platform="AWS",
        description=(
            "At 2021-01-11T12:40:10Z, determine whether the observed IAM "
            "user could complete the exact KMS-encrypted S3 CopyObject "
            "request under the provider state recorded at that instant."
        ),
        environment=(
            "author-published Splunk Attack Data AWS CloudTrail; exact "
            "matching request later succeeds as a target-existence control"
        ),
        observations=observations,
    )
    gold = {
        "case_id": case_id,
        "independence_group": (
            "splunk-dataset:T1486/s3_file_encryption"
        ),
        "source_id": "splunk_attack_data",
        "platform": "AWS",
        "gold_state": "NotReachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "time_scope": denied["timestamp"],
        "path": {
            "path_id": "splunk-s3-kms-copy-denied-path",
            "nodes": [
                {
                    "node_id": "n-user",
                    "type": "identity",
                    "label": "observed IAM user",
                },
                {
                    "node_id": "n-kms-key",
                    "type": "permission_policy",
                    "label": kms_key,
                },
                {
                    "node_id": "n-object",
                    "type": "data_object",
                    "label": target,
                },
            ],
            "edges": [
                {
                    "edge_id": "e-key-dependency",
                    "source": "n-user",
                    "target": "n-kms-key",
                    "type": "invoke",
                },
                {
                    "edge_id": "e-encrypted-copy",
                    "source": "n-user",
                    "target": "n-object",
                    "type": "write_data",
                },
            ],
        },
        "support_observation_ids": [],
        "refute_observation_ids": [
            denied_observation["observation_id"]
        ],
        "control_observation_ids": [
            control_observation["observation_id"]
        ],
        "negative_certificate": {
            "exact_principal": denied["actor_id"],
            "exact_operation": denied["operation"],
            "exact_resource": target,
            "dependency_resource": kms_key,
            "provider_native_decision": ERROR_CODE,
            "scope_completeness": "complete",
            "target_existence_control": (
                "same principal and byte-for-byte matching request fields "
                "succeeded 37 seconds later"
            ),
            "contrary_success_in_same_state": False,
        },
        "semantic_scope": (
            "NotReachable applies only to completion of this exact encrypted "
            "copy at 12:40:10Z while the named KMS key was pending deletion. "
            "It is not a claim that the bucket or object remained unreachable."
        ),
    }
    return {"case": case, "observations": observations}, gold


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    public, gold, _ = build_v4()
    public = deepcopy(public)
    gold = deepcopy(gold)
    addition, metadata = _build_s3_kms_negative()

    public["protocol_version"] = "5.0-pilot"
    public["warning"] = (
        "Protocol-scale pilot only: eight provider-runtime cases and five "
        "epistemic controls remain too small and class-imbalanced for "
        "population-level effectiveness claims."
    )
    public["cases"].append(addition["case"])
    public["observations"].extend(addition["observations"])
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

    gold["protocol_version"] = "5.0-pilot"
    gold["provider_oracle_gold_cases"] = 8
    gold["epistemic_control_cases"] = 5
    gold["cases"].append(metadata)
    gold["cases"] = sorted(gold["cases"], key=lambda item: item["case_id"])
    if len(gold["cases"]) != 13:
        raise ValueError("protocol v5 must contain exactly 13 cases")

    splits = {
        "protocol_version": "5.0-pilot",
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
