#!/usr/bin/env python3
"""Build a label-free index of AWS data-service discovery denials.

The input is a pinned Splunk Attack Data CloudTrail artifact containing an
attack-range discovery sweep.  The script performs deterministic selection and
normalization only.  It does not generate events or infer path labels.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST = REAL_ROOT / "acquisition_manifest.json"
DEFAULT_OUTPUT = REAL_ROOT / "splunk_accessdenied_discovery_v1.json"
SOURCE_ID = "splunk_attack_data_2026_expansion"
RAW_NAME = "aws_iam_accessdenied_discovery_events.json"
EXPECTED_COMMIT = "67fe973a954cc35688ad9b4906ed6e85af5892e9"
EXPECTED_SHA256 = (
    "4f52389f17745abf5fa1cf30c055d4f9d34022fcfb8e5c2544c70177da228433"
)
DENIED_PRINCIPAL = "arn:aws:iam::731544447609:user/cloudsploit"
ACCOUNT_ID = "731544447609"
REGION = "us-east-1"
INDEPENDENCE_GROUP = (
    "splunk-dataset:T1580/aws_iam_accessdenied_discovery_events"
)
SPECS = (
    {
        "case_id": "splunk-accessdenied:ssm-describe-parameters:us-east-1",
        "service": "ssm.amazonaws.com",
        "operation": "DescribeParameters",
        "target_scope": (
            "arn:aws:ssm:us-east-1:731544447609:parameter-catalog/*"
        ),
        "target_type": "secret_store",
    },
    {
        "case_id": "splunk-accessdenied:secrets-list:us-east-1",
        "service": "secretsmanager.amazonaws.com",
        "operation": "ListSecrets",
        "target_scope": (
            "arn:aws:secretsmanager:us-east-1:"
            "731544447609:secret-catalog/*"
        ),
        "target_type": "secret_store",
    },
    {
        "case_id": "splunk-accessdenied:redshift-describe:us-east-1",
        "service": "redshift.amazonaws.com",
        "operation": "DescribeClusters",
        "target_scope": (
            "arn:aws:redshift:us-east-1:731544447609:cluster-catalog/*"
        ),
        "target_type": "database",
    },
    {
        "case_id": "splunk-accessdenied:rds-describe:us-east-1",
        "service": "rds.amazonaws.com",
        "operation": "DescribeDBInstances",
        "target_scope": (
            "arn:aws:rds:us-east-1:731544447609:db-catalog/*"
        ),
        "target_type": "database",
    },
    {
        "case_id": "splunk-accessdenied:dynamodb-list:us-east-1",
        "service": "dynamodb.amazonaws.com",
        "operation": "ListTables",
        "target_scope": (
            "arn:aws:dynamodb:us-east-1:731544447609:table-catalog/*"
        ),
        "target_type": "database",
    },
)


def _artifact() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source = next(
        item for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    if source["commit"] != EXPECTED_COMMIT:
        raise ValueError("Splunk expansion commit changed")
    artifact = next(
        item for item in source["artifacts"]
        if item["name"] == RAW_NAME
    )
    if artifact["sha256"] != EXPECTED_SHA256:
        raise ValueError("Splunk AccessDenied raw hash changed")
    return source, artifact


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


def _principal(record: dict[str, Any]) -> str:
    identity = record.get("userIdentity") or {}
    return str(
        identity.get("arn")
        or identity.get("principalId")
        or identity.get("accountId")
        or ""
    )


def _normalize(
    record: dict[str, Any],
    *,
    record_index: int,
    artifact: dict[str, Any],
    spec: dict[str, str],
) -> dict[str, Any]:
    identity = record.get("userIdentity") or {}
    raw_ref = {
        "relative_path": artifact["relative_path"],
        "sha256": artifact["sha256"],
        "record_index": record_index,
        "upstream_url": artifact["url"],
    }
    token = json.dumps(
        {
            "case_id": spec["case_id"],
            "raw_ref": raw_ref,
            "role": "denied_principal",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    observation_id = "obs-" + hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()[:24]
    return {
        "observation_id": observation_id,
        "candidate_id": spec["case_id"],
        "schema": "aws_cloudtrail",
        "timestamp": record.get("eventTime"),
        "service": record.get("eventSource"),
        "operation": record.get("eventName"),
        "actor_type": identity.get("type"),
        "actor_id": _principal(record),
        "account_id": (
            record.get("recipientAccountId")
            or identity.get("accountId")
        ),
        "region": record.get("awsRegion"),
        "event_status": record.get("errorCode"),
        "target_resource": spec["target_scope"],
        "target_type": spec["target_type"],
        "source_ip": record.get("sourceIPAddress"),
        "request": record.get("requestParameters"),
        "response": {
            "responseElements": record.get("responseElements"),
            "errorCode": record.get("errorCode"),
            "errorMessage": record.get("errorMessage"),
        },
        "pair_role": "denied_principal",
        "raw_ref": raw_ref,
        "path_label": None,
        "evidence_state": None,
    }


def build() -> dict[str, Any]:
    source, artifact = _artifact()
    records = _read_json_stream(ROOT / artifact["relative_path"])
    cases: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for spec in SPECS:
        matches = sorted(
            (
                (index, record)
                for index, record in enumerate(records)
                if record.get("eventSource") == spec["service"]
                and record.get("eventName") == spec["operation"]
                and record.get("awsRegion") == REGION
                and str(
                    record.get("recipientAccountId")
                    or (record.get("userIdentity") or {}).get("accountId")
                    or ""
                )
                == ACCOUNT_ID
                and _principal(record) == DENIED_PRINCIPAL
                and record.get("errorCode") == "AccessDenied"
            ),
            key=lambda item: (
                item[1].get("eventTime") or "",
                item[0],
            ),
        )
        if not matches:
            raise ValueError(f"{spec['case_id']} lacks an explicit denial")
        selected = _normalize(
            matches[0][1],
            record_index=matches[0][0],
            artifact=artifact,
            spec=spec,
        )
        observations.append(selected)
        cases.append({
            **spec,
            "region": REGION,
            "source_id": SOURCE_ID,
            "independence_group": INDEPENDENCE_GROUP,
            "denied_principal": DENIED_PRINCIPAL,
            "observation_ids": [selected["observation_id"]],
            "annotation_status": "provider_certificate_candidate",
            "path_label": None,
            "evidence_state": None,
        })

    return {
        "index_version": "1.0.0",
        "source": {
            "source_id": SOURCE_ID,
            "repository": source["repository"],
            "commit": source["commit"],
            "raw_relative_path": artifact["relative_path"],
            "raw_sha256": artifact["sha256"],
            "raw_bytes": artifact["bytes"],
        },
        "policy": {
            "source": "recorded upstream AWS CloudTrail attack-range events",
            "generated_samples": 0,
            "generated_labels": 0,
            "normalization_only": True,
            "same_scope_definition": (
                "principal + account + region + provider service + operation"
            ),
            "scope_warning": (
                "Each denial proves only that the named principal could not "
                "perform the exact catalogue operation at that event time. "
                "It does not prove that every data object was inaccessible."
            ),
            "success_control_available": False,
        },
        "summary": {
            "raw_records": len(records),
            "candidate_cases": len(cases),
            "observations": len(observations),
            "independence_groups": len({
                item["independence_group"] for item in cases
            }),
            "service_counts": dict(Counter(
                item["service"] for item in observations
            )),
        },
        "cases": cases,
        "observations": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
