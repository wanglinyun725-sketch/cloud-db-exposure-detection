#!/usr/bin/env python3
"""Create a traceable observation index from downloaded pilot telemetry.

Every normalized observation points to a raw file hash and record index. No
attack-path state or gold label is inferred here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST = REAL_ROOT / "pilot_telemetry_manifest.json"
OUT = REAL_ROOT / "pilot_observation_index.json"
REPORT = ROOT / "docs" / "pilot_telemetry_profile.md"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    cases = []
    all_observations = []
    for candidate in manifest["candidates"]:
        metadata = {}
        observations = []
        for artifact in candidate["artifacts"]:
            path = ROOT / artifact["relative_path"]
            if path.suffix.lower() in {".yml", ".yaml"}:
                metadata = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                continue
            for record_index, record in enumerate(read_json_stream(path)):
                observation = normalize_observation(
                    record,
                    artifact,
                    record_index,
                    candidate["candidate_id"],
                )
                observations.append(observation)
                all_observations.append(observation)
        cases.append(
            {
                "candidate_id": candidate["candidate_id"],
                "source_id": candidate["source_id"],
                "upstream_dataset_id": metadata.get("id"),
                "author": metadata.get("author"),
                "published_date": metadata.get("date"),
                "description": metadata.get("description"),
                "environment": metadata.get("environment"),
                "mitre_techniques": metadata.get("mitre_technique", []),
                "observation_count": len(observations),
                "operations": dict(
                    Counter(item["operation"] for item in observations).most_common()
                ),
                "services": dict(
                    Counter(item["service"] for item in observations).most_common()
                ),
                "observation_ids": [item["observation_id"] for item in observations],
                "annotation_status": "pending_human_review",
            }
        )
    output = {
        "index_version": "0.1",
        "policy": {
            "source": "published upstream telemetry",
            "generated_samples": 0,
            "generated_labels": 0,
            "normalization_only": True,
        },
        "summary": {
            "cases": len(cases),
            "observations": len(all_observations),
            "unique_operations": len({item["operation"] for item in all_observations}),
            "unique_services": len({item["service"] for item in all_observations}),
        },
        "cases": cases,
        "observations": all_observations,
    }
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.report.write_text(render_report(output), encoding="utf-8")
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2))
    print(f"wrote {args.output}")
    print(f"wrote {args.report}")


def read_json_stream(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="strict")
    if text.lstrip() and text.lstrip()[0] not in "[{":
        return [
            parse_splunk_kv_line(line)
            for line in text.splitlines()
            if line.strip()
        ]
    decoder = json.JSONDecoder()
    values = []
    cursor = 0
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            break
        value, cursor = decoder.raw_decode(text, cursor)
        if isinstance(value, list):
            values.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            values.append(value)
    return values


def parse_splunk_kv_line(line: str) -> dict:
    """Preserve a Splunk key-value event without treating it as JSON."""
    first, _, _ = line.partition(",")
    fields = {
        name: _quoted_kv(line, name)
        for name in (
            "search_name",
            "orig_time",
            "aws_account_id",
            "bucketName",
            "count",
            "risk_message",
            "risk_object",
            "risk_object_type",
            "risk_score",
            "src_ip",
            "user_arn",
            "user_type",
        )
    }
    return {
        "_schema": "splunk_key_value_event",
        "time": first.strip(),
        "fields": {
            key: value for key, value in fields.items()
            if value is not None
        },
        "raw_event": line,
    }


def _quoted_kv(line: str, name: str) -> str | None:
    match = re.search(
        rf'(?:^|,\s){re.escape(name)}="((?:\\.|[^"])*)"',
        line,
    )
    return match.group(1) if match else None


def normalize_observation(
    record: dict,
    artifact: dict,
    record_index: int,
    candidate_id: str,
) -> dict:
    if record.get("_schema") == "splunk_key_value_event":
        schema = "splunk_key_value_event"
        fields = record["fields"]
        operation = fields.get("search_name", "")
        service = "splunk_enterprise_security"
        timestamp = record.get("time")
        actor_type = fields.get("user_type")
        actor_id = fields.get("user_arn")
        source_ip = fields.get("src_ip")
        account_id = fields.get("aws_account_id")
        region = None
        request = {
            key: fields.get(key)
            for key in (
                "bucketName",
                "count",
                "risk_object",
                "risk_object_type",
            )
            if fields.get(key) is not None
        }
        response = {
            key: fields.get(key)
            for key in ("risk_message", "risk_score")
            if fields.get(key) is not None
        }
        event_status = "DerivedRiskEvent"
    elif (
        "operationName" in record
        and "resourceId" in record
        and "properties" in record
    ):
        schema = "azure_ad_audit"
        properties = record.get("properties") or {}
        initiated = properties.get("initiatedBy") or {}
        user = initiated.get("user") or {}
        service_principal = initiated.get("app") or {}
        operation = str(record.get("operationName", ""))
        service = "Microsoft.aadiam"
        timestamp = (
            record.get("time")
            or properties.get("activityDateTime")
        )
        actor_type = "user" if user else "service_principal"
        actor_id = (
            user.get("userPrincipalName")
            or user.get("id")
            or service_principal.get("servicePrincipalId")
            or service_principal.get("appId")
        )
        source_ip = (
            record.get("callerIpAddress")
            or user.get("ipAddress")
            or service_principal.get("ipAddress")
        )
        account_id = record.get("tenantId")
        region = None
        request = {
            "category": properties.get("category"),
            "targetResources": properties.get("targetResources"),
            "additionalDetails": properties.get("additionalDetails"),
        }
        response = {
            "result": properties.get("result"),
            "resultReason": properties.get("resultReason"),
        }
        event_status = (
            properties.get("result")
            or record.get("resultDescription")
        )
    elif "eventName" in record or "eventSource" in record:
        schema = "aws_cloudtrail"
        operation = str(record.get("eventName", ""))
        service = str(record.get("eventSource", ""))
        timestamp = record.get("eventTime")
        identity = record.get("userIdentity") or {}
        actor_type = identity.get("type")
        actor_id = (
            identity.get("arn")
            or identity.get("principalId")
            or identity.get("accountId")
        )
        source_ip = record.get("sourceIPAddress")
        account_id = record.get("recipientAccountId")
        region = record.get("awsRegion")
        request = record.get("requestParameters")
        response = record.get("responseElements")
        event_status = "Error" if record.get("errorCode") else "Success"
    else:
        schema = "ocsf_api_activity"
        api = record.get("api") or {}
        operation = str(api.get("operation", ""))
        service = str((api.get("service") or {}).get("name", ""))
        timestamp = record.get("time") or record.get("time_dt")
        actor = record.get("actor") or {}
        identity = actor.get("user") or {}
        actor_type = identity.get("type")
        actor_id = identity.get("uid") or identity.get("uid_alt")
        source_ip = (record.get("src_endpoint") or {}).get("ip")
        account_id = (identity.get("account") or {}).get("uid")
        cloud = record.get("cloud") or {}
        region = cloud.get("region")
        request = (api.get("request") or {}).get("data")
        response = (api.get("response") or {}).get("data")
        event_status = record.get("status")

    raw_sha = artifact["sha256"]
    observation_id = hashlib.sha256(
        f"{candidate_id}|{raw_sha}|{record_index}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "observation_id": f"obs-{observation_id}",
        "candidate_id": candidate_id,
        "schema": schema,
        "timestamp": timestamp,
        "service": service,
        "operation": operation,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "source_ip": source_ip,
        "account_id": account_id,
        "region": region,
        "event_status": event_status,
        "request": request,
        "response": response,
        "raw_ref": {
            "relative_path": artifact["relative_path"],
            "sha256": raw_sha,
            "record_index": record_index,
            "upstream_path": artifact["upstream_path"],
            "git_blob_sha": artifact["git_blob_sha"],
            "lfs_oid_sha256": artifact.get("lfs_oid_sha256"),
        },
        "path_label": None,
        "evidence_state": None,
    }


def render_report(index: dict) -> str:
    summary = index["summary"]
    lines = [
        "# Splunk Pilot 原始遥测画像",
        "",
        "本文件由公开原始日志机械归一化得到；未生成攻击路径或证据标签。",
        "",
        f"- 案例组：{summary['cases']}",
        f"- 原始事件：{summary['observations']}",
        f"- 唯一操作：{summary['unique_operations']}",
        f"- 唯一服务：{summary['unique_services']}",
        "",
        "| 候选 | 发布日期 | 环境 | MITRE | 事件数 | 操作 |",
        "|---|---|---|---|---:|---|",
    ]
    for case in index["cases"]:
        operations = ", ".join(
            f"{name}×{count}" for name, count in case["operations"].items()
        )
        lines.append(
            f"| `{case['candidate_id']}` | {case['published_date']} | "
            f"{case['environment']} | {', '.join(case['mitre_techniques'])} | "
            f"{case['observation_count']} | {operations} |"
        )
    lines.extend(
        [
            "",
            "所有 observation 均保存原始文件 SHA-256、Git blob SHA、LFS OID（如适用）",
            "和 record index。`path_label` 与 `evidence_state` 保持 null，等待人工标注。",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
