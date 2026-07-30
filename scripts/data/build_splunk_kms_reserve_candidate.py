#!/usr/bin/env python3
"""Extract one unlabeled multi-step KMS/S3 reserve candidate.

The script copies only provider-recorded facts from a pinned Splunk Attack
Data CloudTrail artifact. It neither assigns an attack label nor admits the
candidate into human gold.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "data" / "real_sources" / "acquisition_manifest.json"
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources"
    / "splunk_kms_s3_reserve_candidate_v1.json"
)
SOURCE_ID = "splunk_attack_data"
EXPECTED_COMMIT = "3821bdb77c66c95b4e529f62a9d00b168446d1a8"
RAW_NAME = "aws_kms_key.json"
EXPECTED_SHA256 = (
    "8c6869476565588356d30a0c20d3767b"
    "2d64de8f871af2e97b2b0d57c4cc64b7"
)
REQUIRED_OPERATIONS = {
    "CreateKey",
    "CreateAlias",
    "PutKeyPolicy",
    "DisableKey",
    "ScheduleKeyDeletion",
    "CancelKeyDeletion",
    "EnableKey",
    "GenerateDataKey",
}
CASE_ID = "splunk:datasets/attack_techniques/T1486/aws_kms_key"
INDEPENDENCE_GROUP = "splunk-dataset:T1486/aws_kms_key"


def build(root: str | Path = ROOT) -> dict[str, Any]:
    """Return a hash-bound, label-empty reserve candidate."""
    root = Path(root).resolve()
    source, artifact = _artifact(root)
    raw_path = root / artifact["relative_path"]
    records = _read_json_stream(raw_path)
    creates = [
        (index, record)
        for index, record in enumerate(records)
        if record.get("eventName") == "CreateKey"
        and not _is_error(record)
    ]
    if len(creates) != 1:
        raise ValueError("expected exactly one successful CreateKey event")
    create_index, create = creates[0]
    key_id = str(
        ((create.get("responseElements") or {}).get("keyMetadata") or {}).get(
            "keyId"
        )
        or ""
    )
    if not key_id:
        raise ValueError("CreateKey response does not expose keyId")

    selected = [
        (index, record)
        for index, record in enumerate(records)
        if _references_key(record, key_id)
    ]
    selected.sort(key=lambda item: (
        str(item[1].get("eventTime") or ""),
        item[0],
    ))
    operations = {record.get("eventName") for _, record in selected}
    missing = REQUIRED_OPERATIONS - operations
    if missing:
        raise ValueError(
            "KMS reserve sequence lacks required operations: "
            + repr(sorted(missing))
        )
    if create_index not in {index for index, _ in selected}:
        raise AssertionError("internal error: CreateKey was not selected")

    data_key_events = [
        record
        for _, record in selected
        if record.get("eventName") == "GenerateDataKey"
    ]
    s3_targets = {
        str(
            (
                (record.get("requestParameters") or {}).get(
                    "encryptionContext"
                )
                or {}
            ).get("aws:s3:arn")
            or ""
        )
        for record in data_key_events
    } - {""}
    if len(s3_targets) != 1:
        raise ValueError(
            "GenerateDataKey events do not bind one exact S3 target"
        )
    statuses = {
        "error" if _is_error(record) else "success"
        for record in data_key_events
    }
    if statuses != {"error", "success"}:
        raise ValueError(
            "expected both failed and successful S3 data-key calls"
        )

    observations = [
        _normalize(
            record,
            record_index=index,
            artifact=artifact,
            key_id=key_id,
        )
        for index, record in selected
    ]
    operation_counts = Counter(
        item["operation"] for item in observations
    )
    return {
        "candidate_version": "1.0",
        "candidate_kind": "unlabeled_runtime_reserve",
        "case_id": CASE_ID,
        "independence_group": INDEPENDENCE_GROUP,
        "source": {
            "source_id": SOURCE_ID,
            "repository": source["repository"],
            "commit": source["commit"],
            "metadata_artifact": _artifact_binding(
                source,
                "aws_kms_key.yml",
            ),
            "raw_artifact": {
                "path": artifact["relative_path"],
                "sha256": artifact["sha256"],
                "bytes": artifact["bytes"],
                "upstream_url": artifact["url"],
            },
            "provenance_level": "B",
            "environment": "Splunk Attack Range",
        },
        "candidate_metadata": {
            "platforms": ["AWS"],
            "services": ["AWS KMS", "Amazon S3"],
            "key_id": key_id,
            "cloud_data_target": sorted(s3_targets)[0],
            "observed_operation_count": len(observations),
            "unique_operations": sorted(operation_counts),
            "operation_counts": dict(sorted(operation_counts.items())),
            "structural_multistep_observed": True,
            "successful_data_key_call_observed": True,
            "failed_data_key_call_observed": True,
            "external_or_low_privilege_entry": "unknown",
            "human_admission_required": True,
        },
        "policy": {
            "raw_events_generated": 0,
            "labels_generated": 0,
            "admission_decisions_generated": 0,
            "normalization_only": True,
            "candidate_is_not_gold": True,
            "single_upstream_dataset_is_one_independence_group": True,
            "observed_operation_does_not_prove_attack_intent": True,
            "publication_use_before_double_human_review": False,
        },
        "annotation": {
            "status": "pending",
            "label_origin": None,
        },
        "admission_screen": {
            "external_or_low_privilege_entry_defined": None,
            "multi_step_path_present": None,
            "cloud_data_target_present": None,
            "critical_edges_have_raw_evidence": None,
            "not_a_near_duplicate": None,
            "decision": None,
            "rationale": None,
        },
        "nodes": [],
        "edges": [],
        "path_labels": [],
        "tool_tasks": [],
        "instance_labels": [],
        "observations": observations,
        "observation_sequence_sha256": _stable_hash([
            item["observation_id"] for item in observations
        ]),
    }


def _artifact(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = json.loads(
        (root / MANIFEST.relative_to(ROOT)).read_text(encoding="utf-8")
    )
    source = next(
        (
            item
            for item in manifest.get("sources") or []
            if item.get("source_id") == SOURCE_ID
        ),
        None,
    )
    if not isinstance(source, dict):
        raise ValueError("Splunk source is missing from acquisition manifest")
    if source.get("commit") != EXPECTED_COMMIT:
        raise ValueError("Splunk source commit changed")
    artifact = next(
        (
            item
            for item in source.get("artifacts") or []
            if item.get("name") == RAW_NAME
        ),
        None,
    )
    if not isinstance(artifact, dict):
        raise ValueError("KMS raw artifact is missing from manifest")
    if artifact.get("sha256") != EXPECTED_SHA256:
        raise ValueError("KMS raw artifact hash changed")
    path = root / str(artifact.get("relative_path") or "")
    if (
        not path.is_file()
        or sha256(path.read_bytes()).hexdigest() != EXPECTED_SHA256
    ):
        raise ValueError("KMS raw artifact bytes changed")
    return source, artifact


def _artifact_binding(
    source: Mapping[str, Any],
    name: str,
) -> dict[str, Any]:
    artifact = next(
        (
            item
            for item in source.get("artifacts") or []
            if isinstance(item, Mapping) and item.get("name") == name
        ),
        None,
    )
    if not isinstance(artifact, Mapping):
        raise ValueError(f"source metadata artifact is missing: {name}")
    return {
        "path": artifact["relative_path"],
        "sha256": artifact["sha256"],
        "bytes": artifact["bytes"],
        "upstream_url": artifact["url"],
    }


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
        if isinstance(value, list):
            batch = value
        elif isinstance(value, dict) and isinstance(
            value.get("Records"),
            list,
        ):
            batch = value["Records"]
        else:
            batch = [value]
        if any(not isinstance(item, dict) for item in batch):
            raise ValueError("KMS artifact contains a non-object record")
        values.extend(batch)
    if not values:
        raise ValueError("KMS artifact contains no records")
    return values


def _references_key(record: Mapping[str, Any], key_id: str) -> bool:
    if record.get("eventName") == "CreateKey":
        observed = (
            ((record.get("responseElements") or {}).get("keyMetadata") or {})
            .get("keyId")
        )
        return observed == key_id
    request = record.get("requestParameters") or {}
    if not isinstance(request, Mapping):
        return False
    for field in ("keyId", "targetKeyId"):
        value = str(request.get(field) or "")
        if value == key_id or value.endswith("/" + key_id):
            return True
    return False


def _normalize(
    record: Mapping[str, Any],
    *,
    record_index: int,
    artifact: Mapping[str, Any],
    key_id: str,
) -> dict[str, Any]:
    identity = record.get("userIdentity") or {}
    if not isinstance(identity, Mapping):
        identity = {}
    raw_ref = {
        "relative_path": artifact["relative_path"],
        "sha256": artifact["sha256"],
        "record_index": record_index,
        "upstream_url": artifact["url"],
    }
    observation_id = "obs-" + sha256(json.dumps(
        {
            "case_id": CASE_ID,
            "key_id": key_id,
            "raw_ref": raw_ref,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:24]
    return {
        "observation_id": observation_id,
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
        "account_id": (
            record.get("recipientAccountId")
            or identity.get("accountId")
        ),
        "region": record.get("awsRegion"),
        "event_status": (
            str(record.get("errorCode"))
            if _is_error(record)
            else "Success"
        ),
        "request": record.get("requestParameters"),
        "response": {
            "responseElements": record.get("responseElements"),
            "errorCode": record.get("errorCode"),
            "errorMessage": record.get("errorMessage"),
        },
        "raw_ref": raw_ref,
        "path_label": None,
        "evidence_state": None,
    }


def _is_error(record: Mapping[str, Any]) -> bool:
    return bool(record.get("errorCode") or record.get("errorMessage"))


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


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
    print(json.dumps({
        "case_id": payload["case_id"],
        "independence_group": payload["independence_group"],
        "observations": len(payload["observations"]),
        "human_admission_required": True,
        "human_gold": 0,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
