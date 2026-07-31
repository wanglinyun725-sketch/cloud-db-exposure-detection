#!/usr/bin/env python3
"""Audit acquired sources and build a provenance-only candidate catalogue.

The output is not a benchmark and contains no generated labels. It inventories
official upstream artifacts, identifies cloud/data-relevant material for human
review, and provides raw source references for the annotation pilot.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.profile_incident_negative_controls import (  # noqa: E402
    build_profile as build_incident_negative_profile,
)

REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST = REAL_ROOT / "acquisition_manifest.json"
OUT = REAL_ROOT / "source_audit.json"
REPORT = ROOT / "docs" / "real_source_audit_report.md"

CLOUD_TERMS = {
    "aws",
    "azure",
    "gcp",
    "cloud",
    "cloudtrail",
    "iam",
    "s3",
    "rds",
    "ec2",
    "lambda",
    "entra",
    "kubernetes",
    "eks",
    "bigquery",
}
DATA_TERMS = {
    "database",
    "rds",
    "sql",
    "snapshot",
    "secret",
    "secrets",
    "s3",
    "bucket",
    "storage",
    "blob",
    "bigquery",
    "bigtable",
    "spanner",
    "dynamodb",
    "cosmos",
    "efs",
    "share",
    "exfil",
    "credential",
}
HIGH_VALUE_TERMS = {
    "rds": 5,
    "database": 5,
    "sql": 5,
    "bigquery": 5,
    "bigtable": 5,
    "spanner": 5,
    "secret": 4,
    "secrets": 4,
    "snapshot": 4,
    "s3": 3,
    "bucket": 3,
    "storage": 3,
    "blob": 3,
    "data": 2,
    "exfil": 2,
    "share": 1,
}

CROSS_CLOUD_DATA_ATTACKS = {
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

CROSS_CLOUD_PILOT_ATTACKS = (
    "automated_exfiltration",
    "credentials_from_password_stores",
)


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    verification = verify_manifest(manifest)
    paths = artifact_paths(manifest)

    mitre = audit_mitre(paths["mitre_attack_stix"]["enterprise-attack.json"])
    cloudgoat = audit_cloudgoat(paths["cloudgoat"]["snapshot.zip"])
    cloudfoxable = audit_cloudfoxable(paths["cloudfoxable"]["snapshot.zip"])
    stratus = audit_stratus(paths["stratus_red_team"]["snapshot.zip"])
    splunk = audit_splunk(
        paths["splunk_attack_data"]["repository-tree.json"],
        source_commit(manifest, "splunk_attack_data"),
    )
    cloudfox = audit_cloudfox(paths["cloudfox"]["snapshot.zip"])
    cross_cloud = audit_cross_cloud_observability(
        paths["cross_cloud_observability_2026"]["attack_scripts.zip"],
        {
            "AWS": paths["cross_cloud_observability_2026"][
                "aws_logs_redacted.zip"
            ],
            "AZURE": paths["cross_cloud_observability_2026"][
                "azure_logs_redacted.zip"
            ],
            "GCP": paths["cross_cloud_observability_2026"][
                "gcp_logs_redacted.zip"
            ],
        },
        paths["cross_cloud_observability_2026"]["log_analysis.zip"],
    )
    incident_negative = build_incident_negative_profile()

    catalogues = {
        "mitre_attack_stix": mitre,
        "cloudgoat": cloudgoat,
        "cloudfoxable": cloudfoxable,
        "stratus_red_team": stratus,
        "splunk_attack_data": splunk,
        "cloudfox": cloudfox,
        "cross_cloud_observability_2026": cross_cloud,
        "cloud_incident_reports_2016_2024": {
            "summary": incident_negative["summary"],
            "candidates": incident_negative["candidates"],
        },
    }
    pilot = build_pilot_catalog(catalogues)
    result = {
        "audit_version": "0.1",
        "policy": {
            "generated_samples": 0,
            "generated_labels": 0,
            "purpose": "provenance inventory and human-annotation candidate selection",
        },
        "acquisition_verification": verification,
        "source_summaries": {
            source: data["summary"] for source, data in catalogues.items()
        },
        "pilot_annotation_candidates": pilot,
        "catalogues": {
            source: data["candidates"] for source, data in catalogues.items()
        },
    }
    OUT.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT.write_text(render_report(result), encoding="utf-8")
    print(json.dumps(result["source_summaries"], ensure_ascii=False, indent=2))
    print(f"pilot candidates={len(pilot)}")
    print(f"wrote {OUT}")
    print(f"wrote {REPORT}")


def verify_manifest(manifest: dict) -> dict:
    checked = []
    all_match = True
    for source in manifest["sources"]:
        for artifact in source["artifacts"]:
            path = ROOT / artifact["relative_path"]
            digest = sha256_file(path)
            matches = digest == artifact["sha256"]
            all_match &= matches
            checked.append(
                {
                    "source_id": source["source_id"],
                    "artifact": artifact["name"],
                    "exists": path.exists(),
                    "sha256_matches": matches,
                    "bytes_matches": path.stat().st_size == artifact["bytes"],
                }
            )
    return {
        "artifacts_checked": len(checked),
        "all_sha256_match": all_match,
        "details": checked,
    }


def artifact_paths(manifest: dict) -> dict[str, dict[str, Path]]:
    return {
        source["source_id"]: {
            item["name"]: ROOT / item["relative_path"]
            for item in source["artifacts"]
        }
        for source in manifest["sources"]
    }


def source_commit(manifest: dict, source_id: str) -> str:
    return next(
        source["commit"]
        for source in manifest["sources"]
        if source["source_id"] == source_id
    )


def audit_mitre(path: Path) -> dict:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    by_id = {item.get("id"): item for item in objects}
    attack_patterns = {
        item["id"]: item
        for item in objects
        if item.get("type") == "attack-pattern"
        and not item.get("revoked")
        and not item.get("x_mitre_deprecated")
    }
    cloud_techniques = {}
    platform_counts = Counter()
    for object_id, item in attack_patterns.items():
        platforms = item.get("x_mitre_platforms", [])
        platform_counts.update(platforms)
        text = " ".join(
            [item.get("name", ""), item.get("description", ""), *platforms]
        )
        if _has_any(text, CLOUD_TERMS):
            cloud_techniques[object_id] = item

    candidates = []
    for item in objects:
        if item.get("type") != "relationship" or item.get("relationship_type") != "uses":
            continue
        target = cloud_techniques.get(item.get("target_ref"))
        source = by_id.get(item.get("source_ref"), {})
        if target is None:
            continue
        text = " ".join(
            [
                target.get("name", ""),
                item.get("description", ""),
                source.get("name", ""),
            ]
        )
        if not _has_any(text, DATA_TERMS):
            continue
        external_id = next(
            (
                ref.get("external_id")
                for ref in target.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        candidates.append(
            {
                "candidate_id": item["id"],
                "kind": "procedure_relationship",
                "source_object_id": source.get("id"),
                "source_object_type": source.get("type"),
                "source_name": source.get("name"),
                "technique_object_id": target.get("id"),
                "technique_id": external_id,
                "technique_name": target.get("name"),
                "platforms": target.get("x_mitre_platforms", []),
                "raw_ref": f"enterprise-attack.json#object={item['id']}",
                "review_score": _review_score(text),
            }
        )
    candidates.sort(key=lambda row: (-row["review_score"], row["candidate_id"]))
    return {
        "summary": {
            "objects_total": len(objects),
            "active_attack_patterns": len(attack_patterns),
            "cloud_relevant_techniques": len(cloud_techniques),
            "cloud_data_procedure_candidates": len(candidates),
            "top_platforms": dict(platform_counts.most_common(10)),
        },
        "candidates": candidates,
    }


def audit_cloudgoat(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        manifests = [
            name
            for name in names
            if re.search(
                r"/cloudgoat/scenarios/(aws|azure)/([^/]+)/manifest\.ya?ml$",
                name,
                re.I,
            )
        ]
        candidates = []
        for manifest_path in manifests:
            match = re.search(
                r"/cloudgoat/scenarios/(aws|azure)/([^/]+)/manifest\.ya?ml$",
                manifest_path,
                re.I,
            )
            platform, scenario = match.groups()
            if scenario in {"scenario_template", "static", "azure_test"}:
                continue
            base = str(PurePosixPath(manifest_path).parent)
            related = [name for name in names if name.startswith(base + "/")]
            text = "\n".join(
                _read_zip_text(archive, name)
                for name in related
                if name.lower().endswith((".md", ".yml", ".yaml"))
            )
            if not _has_any(f"{scenario} {text}", DATA_TERMS):
                continue
            candidates.append(
                {
                    "candidate_id": f"cloudgoat:{platform}:{scenario}",
                    "kind": "executable_scenario",
                    "platform": platform.upper(),
                    "scenario": scenario,
                    "manifest_path": manifest_path,
                    "readme_paths": [
                        name for name in related if name.lower().endswith(".md")
                    ],
                    "terraform_file_count": sum(
                        name.lower().endswith(".tf") for name in related
                    ),
                    "has_cheat_sheet": any(
                        name.lower().endswith("cheat_sheet.md") for name in related
                    ),
                    "raw_ref": f"snapshot.zip#{base}/",
                    "review_score": _review_score(f"{scenario} {text}"),
                }
            )
    candidates.sort(key=lambda row: (-row["review_score"], row["candidate_id"]))
    return {
        "summary": {
            "scenario_manifests": len(manifests),
            "cloud_data_scenario_candidates": len(candidates),
            "platform_counts": dict(Counter(row["platform"] for row in candidates)),
        },
        "candidates": candidates,
    }


def audit_cloudfoxable(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        manifests = [
            name
            for name in names
            if re.search(r"/aws/challenges/([^/]+)/challenge\.ya?ml$", name, re.I)
        ]
        candidates = []
        for manifest_path in manifests:
            challenge = re.search(
                r"/aws/challenges/([^/]+)/challenge\.ya?ml$",
                manifest_path,
                re.I,
            ).group(1)
            base = str(PurePosixPath(manifest_path).parent)
            related = [name for name in names if name.startswith(base + "/")]
            text = "\n".join(
                _read_zip_text(archive, name)
                for name in related
                if name.lower().endswith((".md", ".yml", ".yaml"))
            )
            if not _has_any(f"{challenge} {text}", DATA_TERMS):
                continue
            candidates.append(
                {
                    "candidate_id": f"cloudfoxable:aws:{challenge}",
                    "kind": "executable_challenge",
                    "platform": "AWS",
                    "challenge": challenge,
                    "manifest_path": manifest_path,
                    "terraform_file_count": sum(
                        name.lower().endswith(".tf") for name in related
                    ),
                    "raw_ref": f"snapshot.zip#{base}/",
                    "review_score": _review_score(f"{challenge} {text}"),
                }
            )
    candidates.sort(key=lambda row: (-row["review_score"], row["candidate_id"]))
    return {
        "summary": {
            "challenge_manifests": len(manifests),
            "cloud_data_challenge_candidates": len(candidates),
        },
        "candidates": candidates,
    }


def audit_stratus(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        docs = [
            name
            for name in archive.namelist()
            if re.search(r"/docs/attack-techniques/[^/]+/[^/]+\.md$", name)
            and not name.lower().endswith("/index.md")
        ]
        candidates = []
        for doc_path in docs:
            content = _read_zip_text(archive, doc_path)
            filename = PurePosixPath(doc_path).stem
            if not _has_any(f"{filename} {content}", DATA_TERMS):
                continue
            platform = PurePosixPath(doc_path).parent.name
            candidates.append(
                {
                    "candidate_id": f"stratus:{filename}",
                    "kind": "executable_attack_technique",
                    "platform": platform,
                    "technique": filename,
                    "documentation_path": doc_path,
                    "raw_ref": f"snapshot.zip#{doc_path}",
                    "review_score": _review_score(f"{filename} {content}"),
                }
            )
    candidates.sort(key=lambda row: (-row["review_score"], row["candidate_id"]))
    return {
        "summary": {
            "documented_attack_techniques": len(docs),
            "cloud_data_technique_candidates": len(candidates),
            "platform_counts": dict(Counter(row["platform"] for row in candidates)),
        },
        "candidates": candidates,
    }


def audit_splunk(path: Path, commit: str) -> dict:
    tree = json.loads(path.read_text(encoding="utf-8"))
    blobs = [
        item["path"]
        for item in tree.get("tree", [])
        if item.get("type") == "blob"
        and item["path"].startswith("datasets/attack_techniques/")
    ]
    by_directory = defaultdict(list)
    for blob in blobs:
        by_directory[str(PurePosixPath(blob).parent)].append(blob)

    candidates = []
    for directory, files in by_directory.items():
        text = " ".join([directory, *files])
        if not _has_any(text, CLOUD_TERMS) or not _has_any(text, DATA_TERMS):
            continue
        metadata = [
            file for file in files if file.lower().endswith((".yml", ".yaml"))
        ]
        observations = [
            file
            for file in files
            if file.lower().endswith((".json", ".log", ".csv", ".xml"))
        ]
        if not observations:
            continue
        candidates.append(
            {
                "candidate_id": f"splunk:{directory}",
                "kind": "published_attack_telemetry",
                "dataset_directory": directory,
                "metadata_files": metadata,
                "observation_files": observations,
                "raw_urls": [
                    f"https://raw.githubusercontent.com/splunk/attack_data/{commit}/{file}"
                    for file in [*metadata, *observations]
                ],
                "raw_ref": f"repository-tree.json#{directory}",
                "review_score": _review_score(text),
            }
        )
    candidates.sort(key=lambda row: (-row["review_score"], row["candidate_id"]))
    return {
        "summary": {
            "tree_truncated": tree.get("truncated", False),
            "attack_dataset_directories": len(by_directory),
            "cloud_data_telemetry_candidates": len(candidates),
            "candidate_observation_files": sum(
                len(row["observation_files"]) for row in candidates
            ),
        },
        "candidates": candidates,
    }


def audit_cloudfox(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        source_files = [
            name
            for name in archive.namelist()
            if re.search(r"/(aws|azure|gcp)/[^/]+\.go$", name)
            and not name.lower().endswith("_test.go")
        ]
        candidates = []
        for source_path in source_files:
            filename = PurePosixPath(source_path).stem
            content = _read_zip_text(archive, source_path)
            if not _has_any(f"{filename} {content}", DATA_TERMS):
                continue
            platform = PurePosixPath(source_path).parent.name
            candidates.append(
                {
                    "candidate_id": f"cloudfox:{platform}:{filename}",
                    "kind": "real_tool_adapter_candidate",
                    "platform": platform.upper(),
                    "module": filename,
                    "source_path": source_path,
                    "raw_ref": f"snapshot.zip#{source_path}",
                    "review_score": _review_score(f"{filename} {content}"),
                }
            )
    candidates.sort(key=lambda row: (-row["review_score"], row["candidate_id"]))
    return {
        "summary": {
            "cloud_command_source_files": len(source_files),
            "data_relevant_tool_candidates": len(candidates),
            "platform_counts": dict(Counter(row["platform"] for row in candidates)),
        },
        "candidates": candidates,
    }


def audit_cross_cloud_observability(
    attack_scripts_path: Path,
    log_paths: dict[str, Path],
    analysis_path: Path,
) -> dict:
    """Inventory the DOI-pinned paired attack/no-payload telemetry."""
    visibility: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    with zipfile.ZipFile(analysis_path) as archive:
        for name in archive.namelist():
            match = re.search(
                r"visibility_(aws|azure|gcp)_(default|additional)\.csv$",
                name,
                re.I,
            )
            if not match:
                continue
            platform, log_profile = match.groups()
            content = _read_zip_text(archive, name)
            for row_number, row in enumerate(
                csv.DictReader(io.StringIO(content)),
                start=2,
            ):
                attack = (row.get("attack") or "").strip()
                if not attack:
                    continue
                visibility[(platform.upper(), attack)][log_profile] = {
                    "payload": row.get("payload"),
                    "visible": row.get("visible"),
                    "attack_count": _safe_int(row.get("attack_count")),
                    "abnormal_rows_mean": _safe_float(
                        row.get("abnormal_rows_cnt_mean")
                    ),
                    "raw_ref": f"{analysis_path.name}#{name}:row={row_number}",
                }

    with zipfile.ZipFile(attack_scripts_path) as archive:
        script_text = {
            name: _read_zip_text(archive, name)
            for name in archive.namelist()
            if name.lower().endswith((".sh", ".py", ".json", ".md"))
        }

    logs_by_platform: dict[str, list[str]] = {}
    log_file_totals = {}
    for platform, path in log_paths.items():
        with zipfile.ZipFile(path) as archive:
            names = [
                name
                for name in archive.namelist()
                if name.lower().endswith(".json")
            ]
        logs_by_platform[platform] = names
        log_file_totals[platform] = len(names)

    candidates = []
    all_attacks = set()
    for (platform, attack), profiles in visibility.items():
        all_attacks.add(attack)
        text = attack.replace("_", " ")
        if attack not in CROSS_CLOUD_DATA_ATTACKS:
            continue
        prefix = f"{platform.lower()}-{attack}-"
        raw_logs = [
            name
            for name in logs_by_platform.get(platform, [])
            if PurePosixPath(name).name.lower().startswith(prefix.lower())
        ]
        payload_count = sum("-y-" in name.lower() for name in raw_logs)
        no_payload_count = sum("-n-" in name.lower() for name in raw_logs)
        clean_count = sum("-clean-" in name.lower() for name in raw_logs)
        normalized_attack = attack.replace("_", "-").lower()
        platform_segment = {
            "AWS": "/aws-attacks/",
            "AZURE": "/azure-attacks/",
            "GCP": "/gcp-attacks/",
        }[platform]
        related_scripts = [
            name
            for name, content in script_text.items()
            if platform_segment in name
            and (
                normalized_attack in name.replace("_", "-").lower()
                or attack.lower() in content.lower()
            )
        ]
        if not related_scripts:
            if platform == "AWS":
                related_scripts = [
                    name for name in script_text
                    if name.endswith("/storage_attacks.sh")
                ]
            elif platform == "GCP":
                related_scripts = [
                    name for name in script_text
                    if name.endswith("/storage-attacks.py")
                ]
        candidates.append(
            {
                "candidate_id": (
                    f"crosscloud:{platform.lower()}:{attack}"
                ),
                "kind": "published_cross_cloud_paired_telemetry",
                "platform": platform,
                "attack": attack,
                "log_profiles": profiles,
                "raw_log_file_count": len(raw_logs),
                "payload_log_file_count": payload_count,
                "no_payload_log_file_count": no_payload_count,
                "clean_log_file_count": clean_count,
                "has_payload_control_pair": (
                    payload_count > 0 and no_payload_count > 0
                ),
                "attack_script_refs": [
                    f"{attack_scripts_path.name}#{name}"
                    for name in related_scripts
                ],
                "raw_log_examples": [
                    f"{log_paths[platform].name}#{name}"
                    for name in raw_logs[:6]
                ],
                "raw_ref": (
                    f"{log_paths[platform].name}#"
                    f"{platform.lower()}-{attack}-*"
                ),
                "review_score": _review_score(text),
            }
        )
    candidates.sort(
        key=lambda row: (
            -row["review_score"],
            row["platform"],
            row["candidate_id"],
        )
    )
    return {
        "summary": {
            "doi_record": "10.5281/zenodo.19933893",
            "source_declared_subscription_attacks": 35,
            "visibility_attack_names": len(all_attacks),
            "json_log_files": log_file_totals,
            "cloud_data_candidate_groups": len(candidates),
            "paired_candidate_groups": sum(
                row["has_payload_control_pair"] for row in candidates
            ),
            "platform_counts": dict(
                Counter(row["platform"] for row in candidates)
            ),
        },
        "candidates": candidates,
    }


def build_pilot_catalog(catalogues: dict, limit: int = 30) -> list[dict]:
    # Fixed source quotas prevent one verbose repository from dominating the
    # pilot. They are selection quotas only, not benchmark class balancing.
    quotas = {
        "cloudgoat": 5,
        "cloudfoxable": 4,
        "stratus_red_team": 5,
        "splunk_attack_data": 5,
        "mitre_attack_stix": 5,
    }
    selected = []
    seen = set()
    for source, quota in quotas.items():
        for row in catalogues[source]["candidates"][:quota]:
            selected.append(_pilot_row(source, row))
            seen.add((source, row["candidate_id"]))
    cross_source = "cross_cloud_observability_2026"
    for platform in ("AWS", "AZURE", "GCP"):
        rows_by_attack = {
            row["attack"]: row
            for row in catalogues[cross_source]["candidates"]
            if row["platform"] == platform
        }
        for attack in CROSS_CLOUD_PILOT_ATTACKS:
            row = rows_by_attack[attack]
            selected.append(_pilot_row(cross_source, row))
            seen.add((cross_source, row["candidate_id"]))
    quotas[cross_source] = 6
    remainder = []
    for source in quotas:
        for row in catalogues[source]["candidates"]:
            if (source, row["candidate_id"]) not in seen:
                remainder.append(_pilot_row(source, row))
    remainder.sort(
        key=lambda row: (-row["review_score"], row["source_id"], row["candidate_id"])
    )
    selected.extend(remainder[: max(0, limit - len(selected))])
    return selected[:limit]


def _pilot_row(source: str, row: dict) -> dict:
    return {
        "source_id": source,
        "candidate_id": row["candidate_id"],
        "kind": row["kind"],
        "raw_ref": row["raw_ref"],
        "review_score": row["review_score"],
        "independence_group": (
            f"crosscloud-family:{row['attack']}"
            if "attack" in row
            else row["candidate_id"]
        ),
        "annotation_status": "pending_human_review",
        "label_origin": None,
    }


def render_report(result: dict) -> str:
    summaries = result["source_summaries"]
    verification = result["acquisition_verification"]
    lines = [
        "# RealPathBench-CD 首批真实来源审计",
        "",
        "## 审计结论",
        "",
        f"- 固定原始工件：{verification['artifacts_checked']} 个；"
        f"SHA-256 全部匹配：{verification['all_sha256_match']}。",
        "- 本报告只做来源盘点与人工标注候选筛选，没有生成 benchmark 样本或标签。",
        "- 候选数量不是最终样本量；必须经人工阅读、路径重建、证据回链和去重后才能纳入。",
        "",
        "## 来源盘点",
        "",
        "| 来源 | 官方内容规模 | 云数据相关候选 | 定位 |",
        "|---|---:|---:|---|",
        f"| MITRE ATT&CK STIX | {summaries['mitre_attack_stix']['objects_total']} objects | "
        f"{summaries['mitre_attack_stix']['cloud_data_procedure_candidates']} procedures | CTI/引用 |",
        f"| CloudGoat | {summaries['cloudgoat']['scenario_manifests']} scenario manifests | "
        f"{summaries['cloudgoat']['cloud_data_scenario_candidates']} scenarios | 可执行靶场 |",
        f"| CloudFoxable | {summaries['cloudfoxable']['challenge_manifests']} challenges | "
        f"{summaries['cloudfoxable']['cloud_data_challenge_candidates']} challenges | 可执行靶场 |",
        f"| Stratus Red Team | {summaries['stratus_red_team']['documented_attack_techniques']} techniques | "
        f"{summaries['stratus_red_team']['cloud_data_technique_candidates']} techniques | 可执行原子攻击 |",
        f"| Splunk Attack Data | {summaries['splunk_attack_data']['attack_dataset_directories']} dataset dirs | "
        f"{summaries['splunk_attack_data']['cloud_data_telemetry_candidates']} telemetry groups | 公开攻击日志 |",
        f"| CloudFox | {summaries['cloudfox']['cloud_command_source_files']} command files | "
        f"{summaries['cloudfox']['data_relevant_tool_candidates']} tool modules | Agent 工具适配 |",
        f"| Cross-Cloud Observability | "
        f"{summaries['cross_cloud_observability_2026']['source_declared_subscription_attacks']} attacks / "
        f"{sum(summaries['cross_cloud_observability_2026']['json_log_files'].values())} JSON logs | "
        f"{summaries['cross_cloud_observability_2026']['cloud_data_candidate_groups']} data-path groups | "
        "AWS/Azure/GCP 配对攻击遥测 |",
        f"| Cloud Incident Reports | "
        f"{summaries['cloud_incident_reports_2016_2024']['source_reports']} production reports | "
        f"{summaries['cloud_incident_reports_2016_2024']['cloud_data_keyword_candidates']} keyword-routed candidates | "
        "仅 external negative control 人工候选 |",
        "",
        "## Pilot 人工标注队列",
        "",
        "| # | 来源 | 候选 ID | 类型 | 状态 |",
        "|---:|---|---|---|---|",
    ]
    for index, item in enumerate(result["pilot_annotation_candidates"], 1):
        lines.append(
            f"| {index} | {item['source_id']} | `{item['candidate_id']}` | "
            f"{item['kind']} | {item['annotation_status']} |"
        )
    lines.extend(
        [
            "",
            "## 准入门",
            "",
            "每个候选只有同时满足以下条件才会成为 RealPathBench-CD 样本：",
            "",
            "1. 至少存在一个可定义入口和一个高价值数据目标；",
            "2. 多步关系能由原始 Terraform、日志、walkthrough 或 CTI 引用支持；",
            "3. 每条 gold edge 保存原始证据定位；",
            "4. 不依赖当前验证器自动生成标签；",
            "5. 与已纳入案例不属于同一基础场景的轻微变体；",
            "6. 人工审阅明确记录 `accept/reject/needs_execution` 及理由。",
            "",
        ]
    )
    return "\n".join(lines)


def _read_zip_text(archive: zipfile.ZipFile, name: str) -> str:
    if name.endswith("/"):
        return ""
    try:
        return archive.read(name).decode("utf-8", errors="replace")
    except KeyError:
        return ""


def _has_any(text: str, terms: set[str]) -> bool:
    normalized = text.lower().replace("_", " ").replace("-", " ")
    tokens = set(re.findall(r"[a-z0-9]+", normalized))
    return any(term in tokens for term in terms)


def _review_score(text: str) -> int:
    normalized = text.lower().replace("_", " ").replace("-", " ")
    tokens = re.findall(r"[a-z0-9]+", normalized)
    counts = Counter(tokens)
    return sum(weight * min(counts[term], 5) for term, weight in HIGH_VALUE_TERMS.items())


def _safe_int(value: str | None) -> int | None:
    try:
        return int(value) if value not in {None, ""} else None
    except ValueError:
        return None


def _safe_float(value: str | None) -> float | None:
    try:
        return float(value) if value not in {None, ""} else None
    except ValueError:
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
