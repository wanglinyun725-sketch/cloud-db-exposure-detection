#!/usr/bin/env python3
"""Index pinned Splunk CloudTrail exposure-path candidates without labels.

The selected upstream artifacts are recorded Attack Range telemetry.  This
script verifies their acquisition-manifest hashes and normalizes the original
CloudTrail rows.  It does not invent events, infer reachability, or turn the
upstream ATT&CK description into benchmark gold.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST = REAL_ROOT / "acquisition_manifest.json"
OUTPUT = REAL_ROOT / "splunk_exposure_expansion_v1.json"
SOURCE_ID = "splunk_attack_data"
COMMIT = "3821bdb77c66c95b4e529f62a9d00b168446d1a8"

DATASETS = (
    {
        "candidate_id": "splunk:T1110.002/aws_rds_password_reset",
        "metadata_artifact": "aws_rds_password_reset.yml",
        "telemetry_artifact": "aws_rds_password_reset.json",
        "upstream_dataset": (
            "datasets/attack_techniques/T1110.002/"
            "aws_rds_password_reset"
        ),
        "mitre_technique": "T1110.002",
    },
    {
        "candidate_id": "splunk:T1530/aws_s3_public_bucket",
        "metadata_artifact": "aws_s3_public_bucket.yml",
        "telemetry_artifact": "aws_s3_public_bucket.json",
        "upstream_dataset": (
            "datasets/attack_techniques/T1530/aws_s3_public_bucket"
        ),
        "mitre_technique": "T1530",
    },
    {
        "candidate_id": "splunk:T1537/aws_snapshot_exfil",
        "metadata_artifact": "aws_snapshot_exfil.yml",
        "telemetry_artifact": "aws_snapshot_exfil.json",
        "upstream_dataset": (
            "datasets/attack_techniques/T1537/aws_snapshot_exfil"
        ),
        "mitre_technique": "T1537",
    },
)


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_index() -> dict[str, dict[str, Any]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source = next(
        item for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    if source["commit"] != COMMIT:
        raise ValueError("pinned Splunk commit changed")
    return {item["name"]: item for item in source["artifacts"]}


def _read_ndjson(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    path = ROOT / artifact["relative_path"]
    if _sha256_file(path) != artifact["sha256"]:
        raise ValueError(f"artifact SHA-256 mismatch: {path}")
    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_number} is not an object")
        if not record.get("eventName") or not record.get("eventSource"):
            raise ValueError(f"{path}:{line_number} is not CloudTrail")
        record["_source_line_number"] = line_number
        rows.append(record)
    if not rows:
        raise ValueError(f"{path} contains no CloudTrail records")
    return rows


def _normalize(
    candidate_id: str,
    artifact: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    identity = record.get("userIdentity") or {}
    line_number = int(record.pop("_source_line_number"))
    raw_ref = {
        "relative_path": artifact["relative_path"],
        "artifact_sha256": artifact["sha256"],
        "line_number": line_number,
        "event_id": record.get("eventID"),
    }
    digest = sha256(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "raw_ref": raw_ref,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:24]
    error_code = record.get("errorCode")
    return {
        "observation_id": "obs-splunk-exp-" + digest,
        "candidate_id": candidate_id,
        "schema": "aws_cloudtrail",
        "timestamp": record.get("eventTime"),
        "service": record.get("eventSource"),
        "operation": record.get("eventName"),
        "actor_type": identity.get("type"),
        "actor_id": (
            identity.get("arn")
            or identity.get("principalId")
            or identity.get("accountId")
        ),
        "source_ip": record.get("sourceIPAddress"),
        "account_id": (
            record.get("recipientAccountId")
            or identity.get("accountId")
        ),
        "region": record.get("awsRegion"),
        "event_status": str(error_code) if error_code else "Success",
        "error_code": error_code,
        "error_message": record.get("errorMessage"),
        "request": record.get("requestParameters"),
        "response": record.get("responseElements"),
        "resources": record.get("resources"),
        "raw_ref": raw_ref,
        "path_label": None,
        "evidence_state": None,
    }


def build_index() -> dict[str, Any]:
    artifacts = _artifact_index()
    cases = []
    for spec in DATASETS:
        metadata = artifacts[spec["metadata_artifact"]]
        telemetry = artifacts[spec["telemetry_artifact"]]
        metadata_path = ROOT / metadata["relative_path"]
        if _sha256_file(metadata_path) != metadata["sha256"]:
            raise ValueError(
                f"metadata SHA-256 mismatch: {metadata_path}"
            )
        observations = [
            _normalize(spec["candidate_id"], telemetry, record)
            for record in _read_ndjson(telemetry)
        ]
        cases.append(
            {
                **spec,
                "source_id": SOURCE_ID,
                "source_commit": COMMIT,
                "environment": "Splunk Attack Range",
                "metadata_ref": {
                    "relative_path": metadata["relative_path"],
                    "sha256": metadata["sha256"],
                },
                "telemetry_ref": {
                    "relative_path": telemetry["relative_path"],
                    "sha256": telemetry["sha256"],
                },
                "observation_count": len(observations),
                "operation_counts": dict(
                    sorted(
                        Counter(
                            item["operation"] for item in observations
                        ).items()
                    )
                ),
                "status_counts": dict(
                    sorted(
                        Counter(
                            item["event_status"] for item in observations
                        ).items()
                    )
                ),
                "observations": observations,
            }
        )
    return {
        "index_version": "1.0",
        "source_id": SOURCE_ID,
        "source_commit": COMMIT,
        "policy": {
            "generated_cloud_events": 0,
            "generated_labels": 0,
            "upstream_descriptions_are_gold": False,
            "candidate_routing_is_gold": False,
            "all_rows_keep_immutable_raw_references": True,
        },
        "summary": {
            "datasets": len(cases),
            "cloudtrail_events": sum(
                item["observation_count"] for item in cases
            ),
            "successful_events": sum(
                sum(
                    1 for observation in item["observations"]
                    if observation["event_status"] == "Success"
                )
                for item in cases
            ),
            "error_events": sum(
                sum(
                    1 for observation in item["observations"]
                    if observation["event_status"] != "Success"
                )
                for item in cases
            ),
        },
        "cases": cases,
    }


def main() -> None:
    value = build_index()
    OUTPUT.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(value["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
