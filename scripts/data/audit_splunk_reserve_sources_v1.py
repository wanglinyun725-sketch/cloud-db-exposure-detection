#!/usr/bin/env python3
"""Audit newly acquired Splunk artifacts without inflating path counts."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.build_splunk_kms_reserve_candidate import (  # noqa: E402
    build as build_kms_candidate,
)


MANIFEST = ROOT / "data" / "real_sources" / "acquisition_manifest.json"
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "splunk_reserve_source_audit_v1.json"
)
SOURCE_ID = "splunk_attack_data"
EXPECTED_COMMIT = "3821bdb77c66c95b4e529f62a9d00b168446d1a8"
SPECS = (
    {
        "dataset_id": "T1486/aws_kms_key",
        "metadata": "aws_kms_key.yml",
        "raw": "aws_kms_key.json",
        "format": "cloudtrail",
    },
    {
        "dataset_id": "T1537/aws_ami_shared_public",
        "metadata": "aws_ami_shared_public.yml",
        "raw": "aws_ami_shared_public.json",
        "format": "cloudtrail",
    },
    {
        "dataset_id": "T1562.008/put_bucketlifecycle",
        "metadata": "put_bucketlifecycle.yml",
        "raw": "put_bucketlifecycle.json",
        "format": "cloudtrail",
    },
    {
        "dataset_id": "T1485/aws_delete_knowledge_base",
        "metadata": "aws_delete_knowledge_base_old.yml",
        "raw": "aws_delete_knowledge_base.json",
        "format": "cloudtrail",
    },
    {
        "dataset_id": "T1485/decommissioned_buckets",
        "metadata": "decommissioned_buckets.yml",
        "raw": "decommissioned_buckets.log",
        "format": "cloudfront_access",
    },
    {
        "dataset_id": "T1078/gcploit_exploitation_framework",
        "metadata": "gcploit_exploitation_framework_old.yml",
        "raw": "gcploit_exploitation_framework.json",
        "format": "gcp_export",
        "exclusion_reason": (
            "the pinned GCP export contains one function-creation result "
            "and no linked cloud-data access or exposure transition"
        ),
    },
    {
        "dataset_id": "T1526/aws_security_scanner",
        "metadata": "aws_security_scanner.yml",
        "raw": "aws_security_scanner.json",
        "format": "cloudtrail",
        "exclusion_reason": (
            "the 1,071-event artifact is a read-only discovery sweep; "
            "it contains no mutation, data access, or exposure transition"
        ),
    },
    {
        "dataset_id": "T1204.003/aws_ecr_container_upload",
        "metadata": "aws_ecr_container_upload.yml",
        "raw": "aws_ecr_container_upload.json",
        "format": "cloudtrail",
        "exclusion_reason": (
            "the artifact contains two PutImage events only and does not "
            "itself prove a linked multi-step cloud-data path"
        ),
    },
)


def build_audit(root: str | Path = ROOT) -> dict[str, Any]:
    """Return label-blind structural triage for the pinned raw artifacts."""
    root = Path(root).resolve()
    manifest = json.loads(
        (root / MANIFEST.relative_to(ROOT)).read_text(encoding="utf-8")
    )
    source = next(
        (
            item for item in manifest.get("sources") or []
            if item.get("source_id") == SOURCE_ID
        ),
        None,
    )
    if (
        not isinstance(source, Mapping)
        or source.get("commit") != EXPECTED_COMMIT
    ):
        raise ValueError("pinned Splunk source is missing or changed")
    by_name = {
        item.get("name"): item
        for item in source.get("artifacts") or []
        if isinstance(item, Mapping)
    }
    kms = build_kms_candidate(root)
    rows = []
    for spec in SPECS:
        metadata = _verified_artifact(root, by_name, spec["metadata"])
        raw = _verified_artifact(root, by_name, spec["raw"])
        if spec["format"] == "cloudtrail":
            records = _read_json_stream(root / raw["relative_path"])
            operations = Counter(
                str(record.get("eventName") or "")
                for record in records
            )
            operations.pop("", None)
            record_count = len(records)
        elif spec["format"] == "gcp_export":
            records = _read_json_stream(root / raw["relative_path"])
            operations = Counter(
                str(
                    (record.get("result") or {}).get(
                        "data.protoPayload.authorizationInfo{}.permission"
                    )
                    or ""
                )
                for record in records
            )
            operations.pop("", None)
            record_count = len(records)
        else:
            lines = [
                line
                for line in (
                    root / raw["relative_path"]
                ).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            operations = Counter({"CloudFrontHttpRequest": len(lines)})
            record_count = len(lines)
        exact_linked_multistep = (
            spec["dataset_id"] == "T1486/aws_kms_key"
            and len(kms["observations"]) >= 2
        )
        rows.append({
            "dataset_id": spec["dataset_id"],
            "metadata": _binding(metadata),
            "raw": _binding(raw),
            "record_format": spec["format"],
            "record_count": record_count,
            "unique_operations": sorted(operations),
            "operation_counts": dict(sorted(operations.items())),
            "exact_linked_multistep_observed": exact_linked_multistep,
            "reserve_human_path_screening_eligible": exact_linked_multistep,
            "exclusion_reason": (
                None
                if exact_linked_multistep
                else spec.get("exclusion_reason") or (
                    "the pinned raw artifact contains only one observed "
                    "operation type and does not itself prove a multi-step "
                    "path"
                )
            ),
            "human_gold": False,
        })
    eligible = [
        item["dataset_id"]
        for item in rows
        if item["reserve_human_path_screening_eligible"]
    ]
    return {
        "audit_version": "1.0",
        "source_id": SOURCE_ID,
        "repository": source["repository"],
        "commit": source["commit"],
        "policy": {
            "real_upstream_artifacts_only": True,
            "generated_events": 0,
            "generated_labels": 0,
            "structural_triage_is_not_human_admission": True,
            "repeated_same_operation_is_not_a_multistep_path": True,
            "excluded_artifacts_do_not_increase_lineage_count": True,
        },
        "summary": {
            "audited_artifacts": len(rows),
            "reserve_screening_eligible": len(eligible),
            "structurally_excluded": len(rows) - len(eligible),
            "new_human_gold": 0,
        },
        "eligible_dataset_ids": eligible,
        "artifacts": rows,
    }


def _verified_artifact(
    root: Path,
    by_name: Mapping[str, Mapping[str, Any]],
    name: str,
) -> Mapping[str, Any]:
    artifact = by_name.get(name)
    if not isinstance(artifact, Mapping):
        raise ValueError(f"manifest lacks reserve artifact: {name}")
    path = root / str(artifact.get("relative_path") or "")
    if (
        not path.is_file()
        or artifact.get("sha256")
        != sha256(path.read_bytes()).hexdigest()
    ):
        raise ValueError(f"reserve artifact hash mismatch: {name}")
    return artifact


def _binding(artifact: Mapping[str, Any]) -> dict[str, Any]:
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
            raise ValueError(f"non-object record in {path.name}")
        values.extend(batch)
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    audit = build_audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(audit["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
