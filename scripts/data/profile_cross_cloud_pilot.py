"""Index source-published paired cross-cloud telemetry episodes.

Episode boundaries and payload/no-payload conditions are copied from the
authors' immutable archive filenames.  This script does not generate attack
scenarios, path labels, evidence labels or synthetic observations.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
RAW_ROOT = (
    REAL_ROOT
    / "raw"
    / "cross_cloud_observability_2026"
    / "record-19933893-v2"
)
AUDIT_PATH = REAL_ROOT / "source_audit.json"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
OUT_PATH = REAL_ROOT / "cross_cloud_pilot_episode_index.json"
REPORT_PATH = ROOT / "docs" / "cross_cloud_pilot_profile.md"
FULL_OUT_PATH = REAL_ROOT / "cross_cloud_full_episode_index.json"
FULL_REPORT_PATH = ROOT / "docs" / "cross_cloud_full_pool_profile.md"

FULL_DATA_ATTACKS = {
    "archive_collected_data",
    "automated_collection",
    "automated_exfiltration",
    "credentials_from_password_stores",
    "data_destruction",
    "data_encrypted_for_impact",
    "data_manipulation",
    "data_staged",
    "inhibit_system_recovery",
    "scheduled_transfer",
    "steal_application_access_token",
    "unsecured_credentials",
}

ARCHIVES = {
    "AWS": "aws_logs_redacted.zip",
    "AZURE": "azure_logs_redacted.zip",
    "GCP": "gcp_logs_redacted.zip",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scope",
        choices=("pilot", "full"),
        default="pilot",
        help="pilot keeps the two-family round-1 subset; full indexes all "
        "paired cloud-data attack families",
    )
    args = parser.parse_args()
    output_path = OUT_PATH if args.scope == "pilot" else FULL_OUT_PATH
    report_path = REPORT_PATH if args.scope == "pilot" else FULL_REPORT_PATH
    index = build_index(scope=args.scope)
    output_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    report_path.write_text(render_report(index), encoding="utf-8")
    print(json.dumps(index["summary"], ensure_ascii=False, indent=2))
    print(f"wrote {output_path}")
    print(f"wrote {report_path}")


def build_index(scope: str = "pilot") -> dict[str, Any]:
    if scope not in {"pilot", "full"}:
        raise ValueError("scope must be pilot or full")
    audit = _load_json(AUDIT_PATH)
    manifest = _load_json(MANIFEST_PATH)
    source_manifest = next(
        source
        for source in manifest["sources"]
        if source["source_id"] == "cross_cloud_observability_2026"
    )
    artifact_by_name = {
        artifact["name"]: artifact
        for artifact in source_manifest["artifacts"]
    }
    if scope == "pilot":
        candidates = [
            item
            for item in audit["pilot_annotation_candidates"]
            if item["source_id"] == "cross_cloud_observability_2026"
        ]
        selected = {
            (
                item["candidate_id"].split(":")[1].upper(),
                item["candidate_id"].split(":")[2],
            ): item["independence_group"]
            for item in candidates
        }
    else:
        candidates = [
            item
            for item in audit["catalogues"][
                "cross_cloud_observability_2026"
            ]
            if item["attack"] in FULL_DATA_ATTACKS
            and item["has_payload_control_pair"]
        ]
        selected = {
            (item["platform"], item["attack"]): (
                f"crosscloud-family:{item['attack']}"
            )
            for item in candidates
        }

    episodes = []
    for platform, archive_name in ARCHIVES.items():
        archive_artifact = artifact_by_name[archive_name]
        archive_path = ROOT / archive_artifact["relative_path"]
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                matched = _parse_member(platform, member.filename)
                if matched is None:
                    continue
                attack, run_id, condition, log_profile = matched
                if (platform, attack) not in selected:
                    continue
                raw_bytes = archive.read(member)
                records = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(records, list):
                    raise ValueError(
                        f"expected JSON array in {archive_name}#{member.filename}"
                    )
                operations = Counter()
                services = Counter()
                statuses = Counter()
                for record in records:
                    normalized = _event_facets(platform, record)
                    operations[normalized["operation"]] += 1
                    services[normalized["service"]] += 1
                    statuses[normalized["status"]] += 1
                episode_id = (
                    f"crosscloud:{platform.lower()}:{attack}:"
                    f"{log_profile}:run-{run_id}:{condition}"
                )
                episodes.append(
                    {
                        "episode_id": episode_id,
                        "candidate_id": (
                            f"crosscloud:{platform.lower()}:{attack}"
                        ),
                        "independence_group": selected[(platform, attack)],
                        "platform": platform,
                        "attack": attack,
                        "log_profile": log_profile,
                        "run_id": run_id,
                        "source_condition": (
                            "payload_present"
                            if condition == "y"
                            else "payload_absent"
                        ),
                        "condition_origin": (
                            "upstream experiment filename and attack design"
                        ),
                        "observation_count": len(records),
                        "operation_counts": dict(operations),
                        "service_counts": dict(services),
                        "status_counts": dict(statuses),
                        "raw_ref": {
                            "archive_relative_path": archive_artifact[
                                "relative_path"
                            ],
                            "archive_sha256": archive_artifact["sha256"],
                            "member_path": member.filename,
                            "member_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                            "member_crc32": f"{member.CRC:08x}",
                            "member_uncompressed_bytes": member.file_size,
                        },
                        "path_label": None,
                        "evidence_state": None,
                    }
                )

    episodes.sort(key=lambda item: item["episode_id"])
    pair_counts = Counter(
        (
            item["candidate_id"],
            item["log_profile"],
            item["run_id"],
        )
        for item in episodes
    )
    incomplete_pairs = sorted(
        key for key, count in pair_counts.items()
        if count != 2
    )
    if incomplete_pairs and scope == "pilot":
        raise ValueError(f"incomplete payload controls: {incomplete_pairs[:5]}")
    incomplete_pair_set = set(incomplete_pairs)
    excluded_episodes = [
        item
        for item in episodes
        if (
            item["candidate_id"],
            item["log_profile"],
            item["run_id"],
        )
        in incomplete_pair_set
    ]
    if scope == "full" and incomplete_pairs:
        episodes = [
            item
            for item in episodes
            if (
                item["candidate_id"],
                item["log_profile"],
                item["run_id"],
            )
            not in incomplete_pair_set
        ]
        pair_counts = Counter(
            (
                item["candidate_id"],
                item["log_profile"],
                item["run_id"],
            )
            for item in episodes
        )

    summary = {
        "candidate_groups": len({item["candidate_id"] for item in episodes}),
        "independence_groups": len(
            {item["independence_group"] for item in episodes}
        ),
        "episodes": len(episodes),
        "paired_runs": len(pair_counts),
        "observations": sum(item["observation_count"] for item in episodes),
        "platform_episode_counts": dict(
            Counter(item["platform"] for item in episodes)
        ),
        "condition_episode_counts": dict(
            Counter(item["source_condition"] for item in episodes)
        ),
        "log_profile_episode_counts": dict(
            Counter(item["log_profile"] for item in episodes)
        ),
        "unpaired_run_keys_excluded": len(incomplete_pairs),
        "unpaired_episode_files_excluded": len(excluded_episodes),
    }
    return {
        "index_version": "0.2",
        "source": {
            "source_id": "cross_cloud_observability_2026",
            "doi": "10.5281/zenodo.19933893",
            "version": "record-19933893-v2",
            "license": "CC-BY-4.0",
        },
        "policy": {
            "source_scenarios_generated": 0,
            "source_observations_generated": 0,
            "path_labels_generated": 0,
            "evidence_labels_generated": 0,
            "normalization": (
                "episode indexing and source event facet counting only"
            ),
            "condition_is_not_path_label": True,
            "selection_scope": scope,
        },
        "summary": summary,
        "exclusions": {
            "reason": (
                "upstream run key lacks an exact payload/no-payload pair; "
                "no missing episode was synthesized"
            ),
            "unpaired_run_keys": [
                {
                    "candidate_id": candidate_id,
                    "log_profile": log_profile,
                    "run_id": run_id,
                }
                for candidate_id, log_profile, run_id in incomplete_pairs
            ],
            "episode_ids": [
                item["episode_id"] for item in excluded_episodes
            ],
        },
        "episodes": episodes,
    }


def _parse_member(
    platform: str,
    member_name: str,
) -> tuple[str, int, str, str] | None:
    profile_match = re.search(r"/(additional|default)-logs/", member_name)
    if not profile_match:
        return None
    log_profile = profile_match.group(1)
    pattern = (
        rf"/{platform.lower()}-(.+)-(\d+)-(y|n)-logs\.json$"
    )
    match = re.search(pattern, member_name, re.I)
    if not match:
        return None
    attack, run_id, condition = match.groups()
    return attack, int(run_id), condition.lower(), log_profile


def _event_facets(platform: str, record: dict[str, Any]) -> dict[str, str]:
    if platform == "AWS":
        return {
            "operation": str(record.get("eventName") or "unknown"),
            "service": str(record.get("eventSource") or "unknown"),
            "status": (
                "error"
                if record.get("errorCode") or record.get("errorMessage")
                else "success_or_unspecified"
            ),
        }
    if platform == "AZURE":
        operation = record.get("operationName") or {}
        provider = record.get("resourceProviderName") or {}
        status = record.get("status") or {}
        return {
            "operation": str(
                operation.get("value")
                if isinstance(operation, dict)
                else operation
                or "unknown"
            ),
            "service": str(
                provider.get("value")
                if isinstance(provider, dict)
                else provider
                or "unknown"
            ),
            "status": str(
                status.get("value")
                if isinstance(status, dict)
                else status
                or "unknown"
            ),
        }
    payload = record.get("protoPayload") or {}
    status = payload.get("status") or {}
    return {
        "operation": str(payload.get("methodName") or "unknown"),
        "service": str(payload.get("serviceName") or "unknown"),
        "status": (
            str(status.get("code"))
            if isinstance(status, dict) and status.get("code") is not None
            else "success_or_unspecified"
        ),
    }


def render_report(index: dict[str, Any]) -> str:
    summary = index["summary"]
    scope = index["policy"]["selection_scope"]
    title = (
        "Cross-Cloud Pilot 真实遥测剖面"
        if scope == "pilot"
        else "Cross-Cloud 云数据攻击完整候选池剖面"
    )
    lines = [
        f"# {title}",
        "",
        "## 结论",
        "",
        f"- DOI 固定来源：`{index['source']['doi']}`；许可："
        f"`{index['source']['license']}`。",
        f"- {summary['candidate_groups']} 个平台×攻击候选组，归属于 "
        f"{summary['independence_groups']} 个攻击家族；",
        f"- {summary['episodes']} 个公开日志 episode，构成 "
        f"{summary['paired_runs']} 对 payload/no-payload 对照；",
        f"- 共 {summary['observations']} 条原始云审计观测；",
        f"- 排除 {summary['unpaired_run_keys_excluded']} 个上游未完整配对的 run key"
        f"（{summary['unpaired_episode_files_excluded']} 个 episode 文件），未做任何补造；",
        "- 代码只识别上游文件边界并统计事件字段，未生成路径或证据标签。",
        "",
        "## 分布",
        "",
        "| 维度 | 分布 |",
        "|---|---|",
        f"| 平台 | {summary['platform_episode_counts']} |",
        f"| 条件 | {summary['condition_episode_counts']} |",
        f"| 日志配置 | {summary['log_profile_episode_counts']} |",
        "",
        "## 实验使用边界",
        "",
        "1. `source_condition` 只表示作者是否执行 payload，不等同于路径 Valid；",
        "2. 同一攻击家族的所有平台、运行与日志配置必须放在同一 split；",
        "3. 运行重复可用于估计方差，不可冒充独立攻击路径样本；",
        "4. path/evidence gold labels 仍需人工阅读脚本和原始日志后建立。",
        "",
    ]
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
