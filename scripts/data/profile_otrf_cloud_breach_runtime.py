"""Index the pinned OTRF CloudGoat-derived S3 exfiltration telemetry.

The upstream metadata links this capture to CloudGoat cloud_breach_s3.
Accordingly, this profile treats OTRF as an independent telemetry publisher,
not as an independent attack-scenario group.  It creates no events or labels.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import yaml


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
OUTPUT_PATH = REAL_ROOT / "otrf_cloud_breach_s3_runtime_index.json"
SOURCE_ID = "otrf_security_datasets"
COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
METADATA_NAME = "SDAWS-200914011940.yaml"
ARCHIVE_NAME = "ec2_proxy_s3_exfiltration.zip"
EXPECTED_MEMBER = "ec2_proxy_s3_exfiltration_2020-09-14011940.json"
CANDIDATE_ID = "cloudgoat:aws:cloud_breach_s3"
INDEPENDENCE_GROUP = "cloudgoat-scenario:cloud_breach_s3"


def _source() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    source = next(
        item for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    if source["commit"] != COMMIT:
        raise ValueError("pinned OTRF commit changed")
    return source


def _artifact(source: dict[str, Any], name: str) -> dict[str, Any]:
    artifact = next(
        item for item in source["artifacts"] if item["name"] == name
    )
    path = ROOT / artifact["relative_path"]
    if sha256(path.read_bytes()).hexdigest() != artifact["sha256"]:
        raise ValueError(f"OTRF artifact SHA-256 mismatch: {name}")
    return artifact


def _normalise(
    archive: dict[str, Any],
    member_sha: str,
    index: int,
    record: dict[str, Any],
) -> dict[str, Any]:
    identity = record.get("userIdentity") or {}
    digest = sha256(
        f"{CANDIDATE_ID}|{member_sha}|{index}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "observation_id": "obs-" + digest,
        "candidate_id": CANDIDATE_ID,
        "schema": "aws_cloudtrail",
        "timestamp": record.get("eventTime") or record.get("@timestamp"),
        "service": str(record.get("eventSource") or ""),
        "operation": str(record.get("eventName") or ""),
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
        "event_status": (
            "Error"
            if record.get("errorCode") or record.get("errorMessage")
            else "Success"
        ),
        "request": record.get("requestParameters"),
        "response": record.get("responseElements"),
        "raw_ref": {
            "archive_relative_path": archive["relative_path"],
            "archive_sha256": archive["sha256"],
            "member_path": EXPECTED_MEMBER,
            "member_sha256": member_sha,
            "record_index": index,
            "event_id": record.get("eventID"),
        },
        "path_label": None,
        "evidence_state": None,
    }


def build_index() -> dict[str, Any]:
    source = _source()
    metadata_artifact = _artifact(source, METADATA_NAME)
    archive_artifact = _artifact(source, ARCHIVE_NAME)
    metadata = yaml.safe_load(
        (ROOT / metadata_artifact["relative_path"]).read_text(
            encoding="utf-8-sig"
        )
    )
    if (
        metadata.get("id") != "SDAWS-200914011940"
        or metadata.get("platform") != ["AWS"]
        or "exfiltrate files from an S3 bucket"
        not in str(metadata.get("description"))
        or "cloud-breach-s3"
        not in str((metadata.get("simulation") or {}).get("environment"))
    ):
        raise ValueError("OTRF metadata no longer supports the frozen mapping")

    archive_path = ROOT / archive_artifact["relative_path"]
    with ZipFile(archive_path) as archive:
        if archive.namelist() != [EXPECTED_MEMBER]:
            raise ValueError("OTRF archive member set changed")
        raw = archive.read(EXPECTED_MEMBER)
    member_sha = sha256(raw).hexdigest()
    records = [
        json.loads(line)
        for line in raw.decode("utf-8-sig").splitlines()
        if line.strip()
    ]
    if (
        not records
        or any(
            not isinstance(record, dict)
            or not record.get("eventName")
            or not record.get("eventSource")
            for record in records
        )
    ):
        raise ValueError("OTRF CloudTrail member is empty or malformed")
    observations = [
        _normalise(
            archive_artifact,
            member_sha,
            index,
            record,
        )
        for index, record in enumerate(records)
    ]
    return {
        "index_version": "0.1",
        "source_id": SOURCE_ID,
        "source_commit": COMMIT,
        "source_archive": archive_artifact,
        "source_metadata": {
            "artifact": metadata_artifact,
            "metadata_id": metadata["id"],
            "title": metadata["title"],
            "description": metadata["description"],
            "simulation_environment": metadata["simulation"]["environment"],
            "attack_mappings": metadata.get("attack_mappings") or [],
        },
        "candidate_association": {
            "candidate_id": CANDIDATE_ID,
            "independence_group": INDEPENDENCE_GROUP,
            "runtime_evidence_source": SOURCE_ID,
            "scenario_origin": "cloudgoat",
            "association_basis": (
                "upstream OTRF metadata explicitly links the simulation "
                "environment to CloudGoat cloud-breach-s3"
            ),
        },
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "path_labels": "human_pending",
            "evidence_states": "human_pending",
            "independent_telemetry_publisher": True,
            "independent_attack_scenario": False,
            "current_packet_status": (
                "qualified_for_next_expanded_packet_revision"
            ),
        },
        "summary": {
            "cloudtrail_events": len(observations),
            "unique_operations": len({
                item["operation"] for item in observations
            }),
            "unique_services": len({
                item["service"] for item in observations
            }),
            "operation_counts": dict(sorted(Counter(
                item["operation"] for item in observations
            ).items())),
            "service_counts": dict(sorted(Counter(
                item["service"] for item in observations
            ).items())),
        },
        "log_member": {
            "path": EXPECTED_MEMBER,
            "sha256": member_sha,
            "bytes": len(raw),
        },
        "observations": observations,
    }


def main() -> None:
    index = build_index()
    OUTPUT_PATH.write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(index["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
