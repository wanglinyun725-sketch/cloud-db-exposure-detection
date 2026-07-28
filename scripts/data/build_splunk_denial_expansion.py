#!/usr/bin/env python3
"""Build a label-free index of paired AWS catalogue denials and controls.

The input is a pinned Splunk Attack Data CloudTrail artifact.  This script
selects provider-recorded operations only; it does not generate events or
assign path labels.  Each selected denial is paired with a successful call
against the same account/region/service/operation scope by a different IAM
user from the same upstream attack-range episode.
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
DEFAULT_OUTPUT = REAL_ROOT / "splunk_denial_expansion_v1.json"
SOURCE_ID = "splunk_attack_data_2026_expansion"
RAW_NAME = "aws_iam_excessive_list_command_usage.json"
EXPECTED_COMMIT = "67fe973a954cc35688ad9b4906ed6e85af5892e9"
EXPECTED_SHA256 = (
    "d0e597bf34919e87ff53d757766a71431847d8788ca80ffe78d8ac23bb498f35"
)
DENIED_PRINCIPAL = "arn:aws:iam::760111141337:user/cloudsploit"
CONTROL_PRINCIPAL = "arn:aws:iam::760111141337:user/cloudmapper"
ACCOUNT_ID = "760111141337"
SPECS = (
    {
        "case_id": "splunk-denial:s3-list-buckets:us-east-1",
        "service": "s3.amazonaws.com",
        "operation": "ListBuckets",
        "region": "us-east-1",
        "target_scope": "aws://760111141337/s3/bucket-catalog",
        "target_type": "object_storage",
    },
    {
        "case_id": "splunk-denial:secrets-list:us-east-1",
        "service": "secretsmanager.amazonaws.com",
        "operation": "ListSecrets",
        "region": "us-east-1",
        "target_scope": (
            "arn:aws:secretsmanager:us-east-1:760111141337:secret-catalog/*"
        ),
        "target_type": "secret_store",
    },
    {
        "case_id": "splunk-denial:es-list-domains:us-east-1",
        "service": "es.amazonaws.com",
        "operation": "ListDomainNames",
        "region": "us-east-1",
        "target_scope": "arn:aws:es:us-east-1:760111141337:domain/*",
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
        raise ValueError("Splunk expansion raw hash changed")
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


def _is_error(record: dict[str, Any]) -> bool:
    return bool(record.get("errorCode") or record.get("errorMessage"))


def _normalize(
    record: dict[str, Any],
    *,
    record_index: int,
    artifact: dict[str, Any],
    spec: dict[str, str],
    role: str,
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
            "role": role,
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
        "event_status": (
            record.get("errorCode") if _is_error(record) else "Success"
        ),
        "target_resource": spec["target_scope"],
        "target_type": spec["target_type"],
        "source_ip": record.get("sourceIPAddress"),
        "request": record.get("requestParameters"),
        "response": {
            "responseElements": record.get("responseElements"),
            "errorCode": record.get("errorCode"),
            "errorMessage": record.get("errorMessage"),
        },
        "pair_role": role,
        "raw_ref": raw_ref,
        "path_label": None,
        "evidence_state": None,
    }


def build() -> dict[str, Any]:
    source, artifact = _artifact()
    raw_path = ROOT / artifact["relative_path"]
    records = _read_json_stream(raw_path)
    cases = []
    observations = []
    for spec in SPECS:
        matches = [
            (index, record)
            for index, record in enumerate(records)
            if record.get("eventSource") == spec["service"]
            and record.get("eventName") == spec["operation"]
            and record.get("awsRegion") == spec["region"]
            and str(
                record.get("recipientAccountId")
                or (record.get("userIdentity") or {}).get("accountId")
                or ""
            )
            == ACCOUNT_ID
        ]
        denied = sorted(
            (
                (index, record)
                for index, record in matches
                if _principal(record) == DENIED_PRINCIPAL
                and record.get("errorCode") == "AccessDenied"
            ),
            key=lambda item: (
                item[1].get("eventTime") or "",
                item[0],
            ),
        )
        controls = sorted(
            (
                (index, record)
                for index, record in matches
                if _principal(record) == CONTROL_PRINCIPAL
                and not _is_error(record)
            ),
            key=lambda item: (
                item[1].get("eventTime") or "",
                item[0],
            ),
        )
        if not denied or not controls:
            raise ValueError(
                f"{spec['case_id']} lacks a denial/control pair"
            )
        selected = [
            _normalize(
                denied[0][1],
                record_index=denied[0][0],
                artifact=artifact,
                spec=spec,
                role="denied_principal",
            ),
            _normalize(
                controls[0][1],
                record_index=controls[0][0],
                artifact=artifact,
                spec=spec,
                role="same_scope_success_control",
            ),
        ]
        if selected[0]["timestamp"] >= selected[1]["timestamp"]:
            raise ValueError(
                f"{spec['case_id']} control must follow the denial"
            )
        observations.extend(selected)
        cases.append({
            **spec,
            "source_id": SOURCE_ID,
            "independence_group": (
                "splunk-dataset:T1580/"
                "aws_iam_excessive_list_command_usage"
            ),
            "denied_principal": DENIED_PRINCIPAL,
            "control_principal": CONTROL_PRINCIPAL,
            "observation_ids": [
                item["observation_id"] for item in selected
            ],
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
                "account + region + provider service + operation"
            ),
            "scope_warning": (
                "A catalogue denial proves only that the denied principal "
                "could not perform that exact enumeration operation. It does "
                "not prove that no individual object could be read."
            ),
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
