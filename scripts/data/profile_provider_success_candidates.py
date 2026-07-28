#!/usr/bin/env python3
"""Profile exact successful cloud-data operations in pinned telemetry.

The output is a candidate inventory, not a gold-label generator. It includes
only provider audit records without an error/denial for a frozen allowlist of
data-read operations, excludes cleanup/background members, and collapses
repeated runs under a conservative scenario-family lineage group.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(ROOT))

from scripts.data.profile_explicit_denial_candidates import (  # noqa: E402
    ARCHIVES,
    _classify,
    _events,
    _identity,
    _is_background_telemetry,
    _operation,
    _resource,
    _scenario_family,
    _sha256,
    _source_artifacts,
)


DEFAULT_OUTPUT = (
    ROOT / "output" / "provider_success_candidate_inventory.json"
)
SUCCESS_OPERATIONS = {
    "AWS": {
        "s3.amazonaws.com::GetObject",
        "s3.amazonaws.com::ListObjects",
        "s3.amazonaws.com::ListObjectsV2",
        "dynamodb.amazonaws.com::BatchGetItem",
        "dynamodb.amazonaws.com::ExecuteStatement",
        "dynamodb.amazonaws.com::GetItem",
        "dynamodb.amazonaws.com::Query",
        "dynamodb.amazonaws.com::Scan",
        "secretsmanager.amazonaws.com::BatchGetSecretValue",
        "secretsmanager.amazonaws.com::GetSecretValue",
    },
    "GCP": {
        (
            "secretmanager.googleapis.com::google.cloud.secretmanager.v1."
            "SecretManagerService.AccessSecretVersion"
        ),
        "storage.googleapis.com::storage.objects.get",
        "storage.googleapis.com::storage.objects.list",
    },
}
PAYLOAD_MEMBER = re.compile(r"-\d+-y(?:-|_)", re.IGNORECASE)


def _lineage_family(scenario: str) -> str:
    """Collapse execution-context variants of the same attack family.

    The upstream ``-with-webapp`` suffix denotes concurrent benign web
    application traffic, not a new attack design.  Treating it as an
    independent lineage would inflate the effective sample size.
    """
    return scenario.removesuffix("-with-webapp")


def _exact_resource(
    provider: str,
    event: dict[str, Any],
) -> str:
    resource = _resource(provider, event)
    if resource:
        return resource
    if provider == "AWS":
        request = event.get("requestParameters") or {}
        return str(
            request.get("secretId")
            or request.get("tableName")
            or request.get("resourceArn")
            or ""
        )
    return ""


def _principal_class(provider: str, identity: str) -> str:
    folded = identity.casefold()
    if provider == "AWS":
        if folded.endswith(":root"):
            return "root_high_privilege"
        if ":user/" in folded:
            return "iam_user"
        if ":assumed-role/" in folded:
            return "assumed_role"
        return "service_or_other"
    if "low-priority" in folded:
        return "named_low_priority_workload"
    if "high-priority" in folded:
        return "named_high_priority_workload"
    if "serviceaccount" in folded or "gserviceaccount.com" in folded:
        return "workload_identity"
    return "other"


def _provider_operation_succeeded(
    provider: str,
    event: dict[str, Any],
) -> bool:
    """Require an actual successful provider record, not merely no denial.

    In particular, GCP status code 5 (NotFound) is not an authorization
    denial, but it is also not proof that an object was reached.  The earlier
    ``no_explicit_denial`` predicate admitted those events and therefore
    overstated the positive candidate pool.
    """
    if provider == "AWS":
        return not event.get("errorCode") and not event.get("errorMessage")
    if provider == "GCP":
        proto = event.get("protoPayload") or {}
        status = proto.get("status") or {}
        code = status.get("code")
        if code not in {None, 0, "0"}:
            return False
        return not any(
            item.get("granted") is False
            for item in proto.get("authorizationInfo") or []
            if isinstance(item, dict)
        )
    return False


def build_inventory() -> dict[str, Any]:
    artifacts = _source_artifacts()
    groups: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}
    provider_event_counts = Counter()
    candidate_operation_counts = Counter()
    provider_error_exclusions = Counter()
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
                for detected_provider, event, pointer in _events(payload):
                    if detected_provider != provider:
                        continue
                    provider_event_counts[provider] += 1
                    operation = _operation(provider, event)
                    if operation not in SUCCESS_OPERATIONS[provider]:
                        continue
                    candidate_operation_counts[provider] += 1
                    if not _provider_operation_succeeded(provider, event):
                        provider_error_exclusions[provider] += 1
                        continue
                    resource = _exact_resource(provider, event)
                    identity = _identity(provider, event)
                    if (
                        not resource
                        or not identity
                        or _is_background_telemetry(
                            provider,
                            operation,
                            resource,
                            event,
                        )
                    ):
                        continue
                    scenario = _scenario_family(member)
                    lineage_family = _lineage_family(scenario)
                    key = (provider, scenario, operation)
                    group = groups.setdefault(
                        key,
                        {
                            "provider": provider,
                            "scenario_family": scenario,
                            "lineage_group": (
                                f"crosscloud-family:{lineage_family}"
                            ),
                            "operation": operation,
                            "members": set(),
                            "identities": set(),
                            "resources": set(),
                            "principal_classes": Counter(),
                            "occurrence_count": 0,
                            "raw_refs": [],
                        },
                    )
                    group["members"].add(member)
                    group["identities"].add(identity)
                    group["resources"].add(resource)
                    group["principal_classes"][
                        _principal_class(provider, identity)
                    ] += 1
                    group["occurrence_count"] += 1
                    if len(group["raw_refs"]) < 20:
                        group["raw_refs"].append(
                            {
                                "archive_sha256": artifact["sha256"],
                                "member": member,
                                "member_sha256": member_hash,
                                "json_pointer": pointer,
                                "identity": identity,
                                "resource": resource,
                            }
                        )

    candidates = []
    for key in sorted(groups):
        group = groups[key]
        classes = dict(sorted(group["principal_classes"].items()))
        non_root = sum(
            count
            for name, count in classes.items()
            if name != "root_high_privilege"
        )
        candidates.append(
            {
                "provider": group["provider"],
                "scenario_family": group["scenario_family"],
                "lineage_group": group["lineage_group"],
                "operation": group["operation"],
                "payload_member_count": len(group["members"]),
                "occurrence_count": group["occurrence_count"],
                "unique_identity_count": len(group["identities"]),
                "unique_resource_count": len(group["resources"]),
                "principal_class_counts": classes,
                "non_root_occurrence_count": non_root,
                "priority_for_path_audit": (
                    "high" if non_root else "low_root_only"
                ),
                "sample_raw_refs": group["raw_refs"],
                "path_label": None,
                "evidence_state": None,
                "review_status": "candidate_only",
            }
        )
    return {
        "inventory_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_id": "cross_cloud_observability_2026",
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "payload_present_members_only": True,
            "explicit_operation_allowlist": True,
            "provider_success_record_required": True,
            "no_provider_error_or_denial_required": True,
            "success_is_edge_evidence_not_full_path_gold": True,
            "manual_or_script_claims_are_not_gold": True,
        },
        "summary": {
            "provider_events_scanned_in_payload_members": dict(sorted(
                provider_event_counts.items()
            )),
            "allowlisted_operation_events_scanned": dict(sorted(
                candidate_operation_counts.items()
            )),
            "provider_error_events_excluded": dict(sorted(
                provider_error_exclusions.items()
            )),
            "candidate_operation_groups": len(candidates),
            "conservative_lineage_groups": len({
                item["lineage_group"] for item in candidates
            }),
            "scenario_variant_groups": len({
                item["scenario_family"] for item in candidates
            }),
            "high_priority_non_root_groups": sum(
                item["priority_for_path_audit"] == "high"
                for item in candidates
            ),
            "providers": dict(sorted(Counter(
                item["provider"] for item in candidates
            ).items())),
        },
        "candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = build_inventory()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(inventory["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
