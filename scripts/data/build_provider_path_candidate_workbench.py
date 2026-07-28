#!/usr/bin/env python3
"""Build a conservative semantic-review workbench from real provider logs.

This builder does not create gold labels.  It joins exact successful
data-plane events into reviewable micro-path candidates, preserves immutable
raw references, collapses benign ``-with-webapp`` execution variants into the
same attack lineage, and records any exact-tuple provider errors as conflicts.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.profile_explicit_denial_candidates import (  # noqa: E402
    ARCHIVES,
    _events,
    _identity,
    _is_background_telemetry,
    _operation,
    _scenario_family,
    _sha256,
    _source_artifacts,
)
from scripts.data.profile_provider_success_candidates import (  # noqa: E402
    PAYLOAD_MEMBER,
    SUCCESS_OPERATIONS,
    _exact_resource,
    _lineage_family,
    _principal_class,
    _provider_operation_succeeded,
)


DEFAULT_OUTPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "provider_path_candidate_workbench_v1.json"
)
LIST_OPERATIONS = {
    "s3.amazonaws.com::ListObjects",
    "s3.amazonaws.com::ListObjectsV2",
    "storage.googleapis.com::storage.objects.list",
}
OBJECT_READ_OPERATIONS = {
    "s3.amazonaws.com::GetObject",
    "storage.googleapis.com::storage.objects.get",
}
SECRET_READ_OPERATIONS = {
    "secretsmanager.amazonaws.com::BatchGetSecretValue",
    "secretsmanager.amazonaws.com::GetSecretValue",
    (
        "secretmanager.googleapis.com::google.cloud.secretmanager.v1."
        "SecretManagerService.AccessSecretVersion"
    ),
}
DATABASE_READ_OPERATIONS = {
    "dynamodb.amazonaws.com::BatchGetItem",
    "dynamodb.amazonaws.com::ExecuteStatement",
    "dynamodb.amazonaws.com::GetItem",
    "dynamodb.amazonaws.com::Query",
    "dynamodb.amazonaws.com::Scan",
}


def _stable_id(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()[:20]


def _timestamp(provider: str, event: dict[str, Any]) -> str | None:
    value = (
        event.get("eventTime")
        if provider == "AWS"
        else event.get("timestamp") or event.get("receiveTimestamp")
    )
    return str(value) if value else None


def _target_root(
    provider: str,
    event: dict[str, Any],
    exact_resource: str,
) -> str:
    if provider == "AWS":
        request = event.get("requestParameters") or {}
        bucket = request.get("bucketName") or request.get("bucket")
        if bucket:
            return f"s3:{bucket}"
        if request.get("secretId"):
            return f"secret:{request['secretId']}"
        if request.get("tableName"):
            return f"table:{request['tableName']}"
        if "arn:aws:s3:::" in exact_resource:
            bucket = (
                exact_resource.split("|", 1)[0]
                .split("arn:aws:s3:::", 1)[1]
                .split("/", 1)[0]
            )
            return f"s3:{bucket}"
        return exact_resource

    resource_name = str(
        (event.get("protoPayload") or {}).get("resourceName")
        or exact_resource
    )
    bucket = re.search(r"(projects/_/buckets/[^/]+)", resource_name)
    if bucket:
        return f"gcs:{bucket.group(1)}"
    secret = re.search(
        r"(projects/[^/]+/secrets/[^/]+)",
        resource_name,
    )
    if secret:
        return f"secret:{secret.group(1)}"
    return resource_name


def _path_shape(operations: set[str]) -> str | None:
    if operations & LIST_OPERATIONS and operations & OBJECT_READ_OPERATIONS:
        return "list_then_object_read"
    if operations & SECRET_READ_OPERATIONS:
        return "secret_read"
    if operations & OBJECT_READ_OPERATIONS:
        return "object_read"
    if operations & DATABASE_READ_OPERATIONS:
        return "database_read"
    return None


def _event_projection(
    *,
    provider: str,
    operation: str,
    identity: str,
    target_root: str,
    exact_resource: str,
    event: dict[str, Any],
    raw_ref: dict[str, Any],
    provider_success: bool,
) -> dict[str, Any]:
    return {
        "timestamp": _timestamp(provider, event),
        "operation": operation,
        "identity": identity,
        "target_root": target_root,
        "exact_resource": exact_resource,
        "provider_outcome": (
            "success" if provider_success else "error_or_denial"
        ),
        "raw_ref": deepcopy(raw_ref),
    }


def _representative_events(
    shape: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ordered = sorted(
        events,
        key=lambda item: (
            item["timestamp"] or "",
            item["operation"],
            item["raw_ref"]["json_pointer"],
        ),
    )
    wanted: list[set[str]]
    if shape == "list_then_object_read":
        wanted = [LIST_OPERATIONS, OBJECT_READ_OPERATIONS]
    elif shape == "secret_read":
        wanted = [SECRET_READ_OPERATIONS]
    elif shape == "object_read":
        wanted = [OBJECT_READ_OPERATIONS]
    else:
        wanted = [DATABASE_READ_OPERATIONS]
    selected = []
    for operation_set in wanted:
        match = next(
            item for item in ordered
            if item["operation"] in operation_set
        )
        selected.append(match)
    return selected


def build() -> dict[str, Any]:
    artifacts = _source_artifacts()
    candidate_instances: list[dict[str, Any]] = []
    provider_events = Counter()
    allowlisted_events = Counter()
    provider_error_events = Counter()

    for provider, artifact_name in ARCHIVES.items():
        if provider not in SUCCESS_OPERATIONS:
            continue
        artifact = artifacts[artifact_name]
        archive_path = ROOT / artifact["relative_path"]
        with ZipFile(archive_path) as archive:
            for member in archive.namelist():
                filename = Path(member).name
                if (
                    not member.casefold().endswith(".json")
                    or "-clean-" in filename.casefold()
                    or not PAYLOAD_MEMBER.search(filename)
                ):
                    continue
                raw = archive.read(member)
                try:
                    payload = json.loads(raw.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue

                member_hash = _sha256(raw)
                rows: list[dict[str, Any]] = []
                for detected_provider, event, pointer in _events(payload):
                    if detected_provider != provider:
                        continue
                    provider_events[provider] += 1
                    operation = _operation(provider, event)
                    if operation not in SUCCESS_OPERATIONS[provider]:
                        continue
                    allowlisted_events[provider] += 1
                    exact_resource = _exact_resource(provider, event)
                    identity = _identity(provider, event)
                    if (
                        not exact_resource
                        or not identity
                        or _is_background_telemetry(
                            provider,
                            operation,
                            exact_resource,
                            event,
                        )
                    ):
                        continue
                    succeeded = _provider_operation_succeeded(
                        provider, event
                    )
                    if not succeeded:
                        provider_error_events[provider] += 1
                    raw_ref = {
                        "archive_relative_path": artifact["relative_path"],
                        "archive_sha256": artifact["sha256"],
                        "member": member,
                        "member_sha256": member_hash,
                        "json_pointer": pointer,
                    }
                    rows.append(
                        _event_projection(
                            provider=provider,
                            operation=operation,
                            identity=identity,
                            target_root=_target_root(
                                provider, event, exact_resource
                            ),
                            exact_resource=exact_resource,
                            event=event,
                            raw_ref=raw_ref,
                            provider_success=succeeded,
                        )
                    )

                by_principal_target: dict[
                    tuple[str, str], list[dict[str, Any]]
                ] = defaultdict(list)
                for row in rows:
                    by_principal_target[
                        (row["identity"], row["target_root"])
                    ].append(row)
                for (identity, target_root), grouped in sorted(
                    by_principal_target.items()
                ):
                    support = [
                        item for item in grouped
                        if item["provider_outcome"] == "success"
                    ]
                    shape = _path_shape({
                        item["operation"] for item in support
                    })
                    if shape is None:
                        continue
                    support_tuples = {
                        (
                            item["identity"],
                            item["target_root"],
                            item["operation"],
                        )
                        for item in support
                    }
                    exact_conflicts = [
                        item for item in grouped
                        if (
                            item["identity"],
                            item["target_root"],
                            item["operation"],
                        )
                        in support_tuples
                        and item["provider_outcome"] != "success"
                    ]
                    scenario = _scenario_family(member)
                    family = _lineage_family(scenario)
                    candidate_instances.append({
                        "provider": provider,
                        "scenario_variant": scenario,
                        "lineage_family": family,
                        "lineage_group": f"crosscloud-family:{family}",
                        "path_shape": shape,
                        "member": member,
                        "member_sha256": member_hash,
                        "identity": identity,
                        "principal_class": _principal_class(
                            provider, identity
                        ),
                        "target_root": target_root,
                        "support_events": support,
                        "exact_tuple_conflicts": exact_conflicts,
                    })

    grouped_candidates: dict[
        tuple[str, str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for item in candidate_instances:
        grouped_candidates[
            (
                item["lineage_family"],
                item["provider"],
                item["path_shape"],
            )
        ].append(item)

    candidates = []
    for (family, provider, shape), instances in sorted(
        grouped_candidates.items()
    ):
        instances = sorted(
            instances,
            key=lambda item: (
                item["principal_class"] == "root_high_privilege",
                item["member"],
                item["identity"],
                item["target_root"],
            ),
        )
        representative = instances[0]
        support_events = _representative_events(
            shape, representative["support_events"]
        )
        conflict_events = representative["exact_tuple_conflicts"]
        key = {
            "source_id": "cross_cloud_observability_2026",
            "lineage_group": representative["lineage_group"],
            "provider": provider,
            "path_shape": shape,
        }
        principal_classes = Counter(
            item["principal_class"] for item in instances
        )
        candidates.append({
            "candidate_id": "provider-path-" + _stable_id(key),
            **key,
            "scenario_variants": sorted({
                item["scenario_variant"] for item in instances
            }),
            "replicate_member_count": len({
                item["member"] for item in instances
            }),
            "candidate_instance_count": len(instances),
            "unique_principal_count": len({
                item["identity"] for item in instances
            }),
            "unique_target_count": len({
                item["target_root"] for item in instances
            }),
            "principal_class_counts": dict(sorted(
                principal_classes.items()
            )),
            "operation_set": sorted({
                event["operation"]
                for item in instances
                for event in item["support_events"]
            }),
            "support_event_count": sum(
                len(item["support_events"]) for item in instances
            ),
            "exact_tuple_conflict_count": sum(
                len(item["exact_tuple_conflicts"])
                for item in instances
            ),
            "audit_priority": (
                "P1_multi_event_runtime"
                if shape == "list_then_object_read"
                else "P2_direct_runtime_edge"
            ),
            "representative": {
                "member": representative["member"],
                "member_sha256": representative["member_sha256"],
                "identity": representative["identity"],
                "principal_class": representative["principal_class"],
                "target_root": representative["target_root"],
                "support_events": support_events,
                "exact_tuple_conflicts": conflict_events,
            },
            "oracle_precheck": {
                "provider_success_records_present": True,
                "exact_principal_present": bool(
                    representative["identity"]
                ),
                "exact_target_present": bool(
                    representative["target_root"]
                ),
                "same_tuple_error_or_denial_present": bool(
                    conflict_events
                ),
                "multi_provider_operation_chain": (
                    shape == "list_then_object_read"
                ),
                "mandatory_predecessors_complete": (
                    True
                    if shape == "list_then_object_read"
                    else "semantic_review_required"
                ),
            },
            "review_questions": [
                "Does the exact principal qualify as the path entry?",
                "Is the target a cloud data asset under the frozen ontology?",
                (
                    "Do the selected operations form a causal/reachability "
                    "path rather than unrelated actions?"
                ),
                "Are any mandatory predecessors absent from the raw evidence?",
                "Is this candidate independent after lineage-family deduplication?",
            ],
            "path_label": None,
            "evidence_state": None,
            "review_status": "semantic_review_required",
        })

    lineage_groups = {
        item["lineage_group"] for item in candidates
    }
    return {
        "workbench_version": "1.0.0",
        "dataset_stage": "provider_runtime_candidates_not_gold",
        "source_id": "cross_cloud_observability_2026",
        "policy": {
            "generated_cloud_events": 0,
            "generated_gold_labels": 0,
            "provider_success_record_required": True,
            "provider_error_is_not_success": True,
            "exact_tuple_conflicts_preserved": True,
            "with_webapp_variants_share_lineage": True,
            "retries_are_not_independent_cases": True,
            "semantic_human_or_oracle_review_required": True,
        },
        "source_scan": {
            "provider_events": dict(sorted(provider_events.items())),
            "allowlisted_operation_events": dict(sorted(
                allowlisted_events.items()
            )),
            "provider_error_events_excluded_from_support": dict(sorted(
                provider_error_events.items()
            )),
        },
        "summary": {
            "path_candidate_groups": len(candidates),
            "conservative_lineage_groups": len(lineage_groups),
            "multi_event_path_groups": sum(
                item["audit_priority"] == "P1_multi_event_runtime"
                for item in candidates
            ),
            "direct_runtime_edge_groups": sum(
                item["audit_priority"] == "P2_direct_runtime_edge"
                for item in candidates
            ),
            "groups_with_exact_tuple_conflict": sum(
                bool(item["exact_tuple_conflict_count"])
                for item in candidates
            ),
            "provider_groups": dict(sorted(Counter(
                item["provider"] for item in candidates
            ).items())),
            "non_root_representative_groups": sum(
                item["representative"]["principal_class"]
                != "root_high_privilege"
                for item in candidates
            ),
        },
        "candidates": candidates,
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
