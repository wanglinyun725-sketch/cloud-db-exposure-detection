#!/usr/bin/env python3
"""Index explicit authorization denials in pinned cross-cloud telemetry.

This is a deterministic inventory, not a label generator.  Only provider
records with an explicit authorization-denial signal are selected.  A nearby
or matching success is recorded as a review lead, never promoted to a path or
gold label automatically.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
DEFAULT_OUTPUT = (
    ROOT / "output" / "explicit_denial_candidate_inventory.json"
)
SOURCE_ID = "cross_cloud_observability_2026"
ARCHIVES = {
    "AWS": "aws_logs_redacted.zip",
    "Azure": "azure_logs_redacted.zip",
    "GCP": "gcp_logs_redacted.zip",
}
DATA_TERMS = {
    "s3",
    "dynamodb",
    "rds",
    "database",
    "storage",
    "blob",
    "cosmos",
    "bigquery",
    "cloudsql",
    "sql",
    "secret",
    "snapshot",
    "bucket",
    "object",
    "vault",
}
DENIAL_TERMS = (
    "accessdenied",
    "access denied",
    "unauthorized",
    "authorizationfailed",
    "permission_denied",
    "permission denied",
    "forbidden",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_artifacts() -> dict[str, dict]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    source = next(
        item
        for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    return {
        artifact["name"]: artifact for artifact in source["artifacts"]
    }


def _provider_record(value: dict[str, Any]) -> str | None:
    if value.get("eventName") and value.get("eventSource"):
        return "AWS"
    proto = value.get("protoPayload")
    if isinstance(proto, dict) and proto.get("methodName"):
        return "GCP"
    if (
        value.get("operationName")
        or value.get("OperationName")
        or value.get("operationNameValue")
    ):
        return "Azure"
    return None


def _events(value: Any, pointer: str = "$") -> Iterable[tuple[str, dict, str]]:
    if isinstance(value, dict):
        provider = _provider_record(value)
        if provider:
            yield provider, value, pointer
            return
        for key, child in value.items():
            yield from _events(child, f"{pointer}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _events(child, f"{pointer}[{index}]")


def _text_has_denial(value: Any) -> bool:
    text = json.dumps(value, ensure_ascii=False).casefold()
    return any(term in text for term in DENIAL_TERMS)


def _classify(provider: str, event: dict[str, Any]) -> tuple[str, str]:
    if provider == "AWS":
        error_code = str(event.get("errorCode") or "")
        error_message = str(event.get("errorMessage") or "")
        if _text_has_denial((error_code, error_message)):
            return "explicit_denial", f"{error_code}: {error_message}".strip(": ")
        return "no_explicit_denial", ""

    if provider == "GCP":
        proto = event.get("protoPayload") or {}
        status = proto.get("status") or {}
        authorization = proto.get("authorizationInfo") or []
        denied_permissions = [
            item.get("permission")
            for item in authorization
            if item.get("granted") is False
        ]
        code = status.get("code")
        message = status.get("message") or ""
        if (
            code in {7, 16}
            or _text_has_denial(status)
            or _text_has_denial(message)
        ):
            reason = {
                "status_code": code,
                "status_message": message,
                "denied_permissions": denied_permissions,
            }
            return "explicit_denial", json.dumps(
                reason,
                ensure_ascii=False,
                sort_keys=True,
            )
        return "no_explicit_denial", ""

    status_fields = {
        key: event.get(key)
        for key in (
            "status",
            "statusValue",
            "resultType",
            "resultDescription",
            "subStatus",
        )
        if event.get(key) is not None
    }
    if _text_has_denial(status_fields):
        return "explicit_denial", json.dumps(
            status_fields,
            ensure_ascii=False,
            sort_keys=True,
        )
    return "no_explicit_denial", ""


def _identity(provider: str, event: dict[str, Any]) -> str:
    if provider == "AWS":
        identity = event.get("userIdentity") or {}
        return str(
            identity.get("arn")
            or identity.get("principalId")
            or identity.get("invokedBy")
            or identity.get("type")
            or ""
        )
    if provider == "GCP":
        auth = (event.get("protoPayload") or {}).get(
            "authenticationInfo"
        ) or {}
        return str(
            auth.get("principalSubject")
            or auth.get("principalEmail")
            or ""
        )
    claims = event.get("claims") or {}
    return str(
        event.get("caller")
        or event.get("Caller")
        or claims.get("name")
        or claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
        or ""
    )


def _operation(provider: str, event: dict[str, Any]) -> str:
    if provider == "AWS":
        return f"{event.get('eventSource')}::{event.get('eventName')}"
    if provider == "GCP":
        proto = event.get("protoPayload") or {}
        return f"{proto.get('serviceName')}::{proto.get('methodName')}"
    operation = (
        event.get("operationNameValue")
        or event.get("OperationName")
        or event.get("operationName")
        or ""
    )
    if isinstance(operation, dict):
        operation = operation.get("value") or operation.get("localizedValue")
    return str(operation)


def _resource(provider: str, event: dict[str, Any]) -> str:
    if provider == "AWS":
        resources = event.get("resources") or []
        arns = [
            str(item.get("ARN"))
            for item in resources
            if isinstance(item, dict) and item.get("ARN")
        ]
        if arns:
            return "|".join(sorted(arns))
        request = event.get("requestParameters") or {}
        bucket = request.get("bucketName") or request.get("bucket")
        key = request.get("key")
        if bucket:
            return f"{bucket}/{key or ''}".rstrip("/")
        return str(
            request.get("resource")
            or request.get("resourceArn")
            or ""
        )
    if provider == "GCP":
        proto = event.get("protoPayload") or {}
        if proto.get("resourceName"):
            return str(proto["resourceName"])
        for info in proto.get("authorizationInfo") or []:
            if info.get("resource"):
                return str(info["resource"])
        return str((event.get("resource") or {}).get("labels") or "")
    return str(
        event.get("resourceId")
        or event.get("ResourceId")
        or event.get("_ResourceId")
        or ""
    )


def _is_data_relevant(operation: str, resource: str) -> bool:
    text = f"{operation} {resource}".casefold()
    return any(term in text for term in DATA_TERMS)


def _scenario_family(member: str) -> str:
    filename = Path(member).name
    match = re.match(
        r"(?:aws|azure|gcp)-(.+?)-\d+-[ny](?:-|_)",
        filename,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group(1)
    return Path(filename).stem


def _event_uid(provider: str, event: dict[str, Any]) -> str:
    if provider == "AWS":
        candidate = str(event.get("eventID") or "")
    elif provider == "GCP":
        candidate = str(event.get("insertId") or "")
    else:
        candidate = str(
            event.get("correlationId")
            or event.get("CorrelationId")
            or ""
        )
    if candidate and "redacted" not in candidate.casefold():
        return candidate
    canonical = json.dumps(
        event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(canonical)


def _is_background_telemetry(
    provider: str,
    operation: str,
    resource: str,
    event: dict[str, Any],
) -> bool:
    if provider != "AWS":
        return False
    identity = event.get("userIdentity") or {}
    resource_text = resource.casefold()
    if (
        identity.get("type") == "AWSService"
        and operation == "s3.amazonaws.com::PutObject"
        and "benchmark-events" in resource_text
    ):
        return True
    return "aws-cloudtrail-logs" in resource_text


def build_inventory() -> dict:
    artifacts = _source_artifacts()
    all_records: list[dict] = []
    archive_summaries = {}
    for expected_provider, artifact_name in ARCHIVES.items():
        artifact = artifacts[artifact_name]
        archive_path = ROOT / artifact["relative_path"]
        member_count = 0
        parsed_events = 0
        with ZipFile(archive_path) as archive:
            for member in archive.namelist():
                if not member.casefold().endswith(".json"):
                    continue
                member_count += 1
                raw = archive.read(member)
                try:
                    payload = json.loads(raw.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                member_hash = _sha256(raw)
                for provider, event, pointer in _events(payload):
                    if provider != expected_provider:
                        continue
                    parsed_events += 1
                    classification, reason = _classify(provider, event)
                    operation = _operation(provider, event)
                    resource = _resource(provider, event)
                    control_or_cleanup = "-clean-" in Path(
                        member
                    ).name.casefold()
                    all_records.append(
                        {
                            "provider": provider,
                            "scenario_family": _scenario_family(member),
                            "event_uid": _event_uid(provider, event),
                            "classification": classification,
                            "operation": operation,
                            "identity": _identity(provider, event),
                            "resource": resource,
                            "data_relevant": _is_data_relevant(
                                operation,
                                resource,
                            ),
                            "background_telemetry": _is_background_telemetry(
                                provider,
                                operation,
                                resource,
                                event,
                            ),
                            "control_or_cleanup": control_or_cleanup,
                            "reason": reason,
                            "raw_ref": {
                                "archive_sha256": artifact["sha256"],
                                "member": member,
                                "member_sha256": member_hash,
                                "json_pointer": pointer,
                            },
                        }
                    )
        archive_summaries[expected_provider] = {
            "artifact": artifact_name,
            "archive_sha256": artifact["sha256"],
            "json_members": member_count,
            "provider_events": parsed_events,
        }

    successes: dict[
        tuple[str, str, str, str, str],
        dict[str, dict],
    ] = defaultdict(dict)
    for record in all_records:
        if record["classification"] == "no_explicit_denial":
            key = (
                record["provider"],
                record["scenario_family"],
                record["operation"],
                record["identity"],
                record["resource"],
            )
            if record["resource"]:
                successes[key][record["event_uid"]] = record["raw_ref"]

    denial_claims_by_key: dict[
        tuple[str, str, str, str, str, str],
        dict,
    ] = {}
    for record in all_records:
        if record["classification"] != "explicit_denial":
            continue
        key = (
            record["provider"],
            record["scenario_family"],
            record["operation"],
            record["identity"],
            record["resource"],
        )
        matching = list(successes.get(key, {}).values())
        claim_key = (
            record["provider"],
            record["raw_ref"]["member"],
            record["operation"],
            record["identity"],
            record["resource"],
            record["reason"],
        )
        claim = denial_claims_by_key.setdefault(
            claim_key,
            {
                **record,
                "event_uid": None,
                "raw_ref": record["raw_ref"],
                "occurrence_count": 0,
                "occurrence_refs": [],
                "same_scenario_exact_key_success_refs": matching[:20],
                "same_scenario_exact_key_success_count": len(matching),
                "path_label": None,
                "evidence_state": None,
                "review_status": "candidate_only",
            },
        )
        claim["occurrence_count"] += 1
        if len(claim["occurrence_refs"]) < 20:
            claim["occurrence_refs"].append(record["raw_ref"])
    denial_claims = list(denial_claims_by_key.values())

    data_candidates = [
        record
        for record in denial_claims
        if record["data_relevant"]
        and not record["background_telemetry"]
        and not record["control_or_cleanup"]
    ]
    return {
        "inventory_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_id": SOURCE_ID,
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "explicit_denial_required": True,
            "absence_of_event_means_denial": False,
            "matched_success_is_gold": False,
            "human_or_oracle_review_required": True,
        },
        "summary": {
            "provider_events": len(all_records),
            "explicit_denial_events": sum(
                record["occurrence_count"] for record in denial_claims
            ),
            "explicit_denial_claims": len(denial_claims),
            "reviewable_data_denial_claims": len(data_candidates),
            "data_denials_with_exact_key_success": sum(
                bool(record["same_scenario_exact_key_success_count"])
                for record in data_candidates
            ),
            "providers": dict(
                Counter(
                    record["provider"] for record in denial_claims
                )
            ),
            "data_relevant_providers": dict(
                Counter(record["provider"] for record in data_candidates)
            ),
        },
        "archives": archive_summaries,
        "data_relevant_denial_candidates": data_candidates,
        "all_explicit_denial_claims": denial_claims,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = build_inventory()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
