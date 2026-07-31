"""Index real, anonymized Stratus Red Team CloudTrail detonation logs.

The pinned upstream archive contains logs captured by Grimoire from real
detonations in a test AWS environment and anonymized by LogLicker.  This
script only normalizes and hashes those upstream records; it creates no path,
admission, evidence-state or attack-effectiveness label.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
AUDIT_PATH = REAL_ROOT / "source_audit.json"
OUTPUT_PATH = REAL_ROOT / "stratus_detonation_log_index.json"
SOURCE_ID = "stratus_red_team"
ARCHIVE_NAME = "snapshot.zip"
COMMIT = "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0"
ARCHIVE_PREFIX = f"stratus-red-team-{COMMIT}/"
LOG_PREFIX = ARCHIVE_PREFIX + "docs/detonation-logs/"
DOC_PREFIX = ARCHIVE_PREFIX + "docs/attack-techniques/AWS/"
UPSTREAM_ATTESTATION = (
    "These logs have been gathered from a real detonation of this "
    "technique in a test environment using"
)


def _source_artifact() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    source = next(
        item for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    if source["commit"] != COMMIT:
        raise ValueError("pinned Stratus commit changed")
    return next(
        item for item in source["artifacts"]
        if item["name"] == ARCHIVE_NAME
    )


def _normalise_event(
    technique: str,
    member_path: str,
    member_sha256: str,
    archive: dict[str, Any],
    record_index: int,
    record: dict[str, Any],
) -> dict[str, Any]:
    identity = record.get("userIdentity") or {}
    observation_digest = sha256(
        (
            technique
            + "|"
            + member_sha256
            + "|"
            + str(record_index)
        ).encode("utf-8")
    ).hexdigest()[:24]
    return {
        "observation_id": "obs-" + observation_digest,
        "candidate_id": "stratus:" + technique,
        "schema": "aws_cloudtrail",
        "timestamp": record.get("eventTime"),
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
        "error_code": record.get("errorCode"),
        "error_message": record.get("errorMessage"),
        "request": record.get("requestParameters"),
        "response": record.get("responseElements"),
        "raw_ref": {
            "archive_relative_path": archive["relative_path"],
            "archive_sha256": archive["sha256"],
            "member_path": member_path,
            "member_sha256": member_sha256,
            "record_index": record_index,
            "event_id": record.get("eventID"),
        },
        "path_label": None,
        "evidence_state": None,
    }


def build_index() -> dict[str, Any]:
    artifact = _source_artifact()
    archive_path = ROOT / artifact["relative_path"]
    if sha256(archive_path.read_bytes()).hexdigest() != artifact["sha256"]:
        raise ValueError("Stratus archive SHA-256 mismatch")
    audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    candidates_by_technique = {
        item["technique"]: item
        for item in audit["catalogues"][SOURCE_ID]
    }
    cases = []
    with ZipFile(archive_path) as archive:
        log_members = sorted(
            name for name in archive.namelist()
            if name.startswith(LOG_PREFIX) and name.endswith(".json")
        )
        for member_path in log_members:
            technique = Path(member_path).stem
            raw = archive.read(member_path)
            member_sha = sha256(raw).hexdigest()
            records = json.loads(raw)
            if not isinstance(records, list) or not records:
                raise ValueError(f"{member_path} is not a non-empty event list")
            if any(
                not isinstance(record, dict)
                or not record.get("eventName")
                or not record.get("eventSource")
                for record in records
            ):
                raise ValueError(f"{member_path} has malformed CloudTrail rows")
            documentation_path = DOC_PREFIX + technique + ".md"
            if documentation_path not in archive.namelist():
                raise ValueError(
                    f"{technique} lacks pinned upstream documentation"
                )
            documentation_raw = archive.read(documentation_path)
            documentation = documentation_raw.decode(
                "utf-8", errors="strict"
            )
            if UPSTREAM_ATTESTATION not in documentation:
                raise ValueError(
                    f"{technique} lacks real-detonation attestation"
                )
            observations = [
                _normalise_event(
                    technique,
                    member_path,
                    member_sha,
                    artifact,
                    index,
                    record,
                )
                for index, record in enumerate(records)
            ]
            candidate = candidates_by_technique.get(technique)
            cases.append({
                "technique": technique,
                "candidate_id": (
                    candidate["candidate_id"] if candidate else None
                ),
                "routed_as_cloud_data_candidate": candidate is not None,
                "platform": "AWS",
                "environment": "real_isolated_test_cloud_detonation",
                "collection_tool": "DataDog Grimoire",
                "anonymization_tool": "LogLicker",
                "documentation_path": documentation_path,
                "documentation_member_sha256": sha256(
                    documentation_raw
                ).hexdigest(),
                "log_member_path": member_path,
                "log_member_sha256": member_sha,
                "observation_count": len(observations),
                "operation_counts": dict(sorted(Counter(
                    item["operation"] for item in observations
                ).items())),
                "service_counts": dict(sorted(Counter(
                    item["service"] for item in observations
                ).items())),
                "observations": observations,
            })
    selected = [
        case for case in cases
        if case["routed_as_cloud_data_candidate"]
    ]
    return {
        "index_version": "0.1",
        "source_id": SOURCE_ID,
        "source_commit": COMMIT,
        "source_archive": artifact,
        "upstream_evidence_statement": (
            "Pinned technique documentation states that the logs were "
            "gathered from a real detonation in a test environment using "
            "Grimoire and anonymized using LogLicker."
        ),
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "path_labels": "human_pending",
            "evidence_states": "human_pending",
            "all_archive_log_members_indexed": True,
            "cloud_data_candidate_routing_is_not_gold": True,
        },
        "summary": {
            "detonation_log_files": len(cases),
            "cloudtrail_events": sum(
                case["observation_count"] for case in cases
            ),
            "routed_cloud_data_cases": len(selected),
            "routed_cloud_data_events": sum(
                case["observation_count"] for case in selected
            ),
            "unrouted_technique_logs": len(cases) - len(selected),
            "unique_operations": len({
                item["operation"]
                for case in cases
                for item in case["observations"]
            }),
            "unique_services": len({
                item["service"]
                for case in cases
                for item in case["observations"]
            }),
        },
        "cases": cases,
    }


def main() -> None:
    index = build_index()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(index["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
