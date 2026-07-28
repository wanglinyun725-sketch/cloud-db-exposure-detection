"""Profile real cloud reliability incidents as human-screened negative controls.

The source contains production incident reports, not attack telemetry.  This
script performs only deterministic keyword routing and provenance indexing.
It never labels a report as benign, non-attack, or a path; those decisions are
reserved for human review.
"""
from __future__ import annotations

from collections import Counter
import csv
import hashlib
import html
import io
import json
from pathlib import Path
import re
import sys
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
OUT_PATH = REAL_ROOT / "incident_negative_control_candidates.json"
REPORT_PATH = ROOT / "docs" / "incident_negative_control_profile.md"

SOURCE_ID = "cloud_incident_reports_2016_2024"
MEMBERS = {
    "AWS": "2_clean_data/aws.csv",
    "AZURE": "2_clean_data/azure.csv",
    "GCP": "2_clean_data/gcp.csv",
}
DATA_PATTERNS = {
    "database": r"\b(?:database|databases|db)\b",
    "rds_aurora": r"\b(?:rds|aurora|redshift)\b",
    "sql": r"\b(?:sql|postgres|postgresql|mysql|mariadb)\b",
    "nosql": r"\b(?:dynamodb|bigtable|datastore|firestore|cosmos)\b",
    "analytics": r"\b(?:bigquery|dataflow|synapse)\b",
    "storage": r"\b(?:storage|s3|bucket|blob|object store)\b",
    "backup": r"\b(?:backup|snapshot|restore)\b",
    "secret": r"\b(?:secret|key vault|secrets manager)\b",
    "spanner": r"\bspanner\b",
}
SECURITY_PATTERNS = {
    "attack": r"\b(?:attack|attacker|cyberattack)\b",
    "breach": r"\b(?:breach|compromise|compromised)\b",
    "unauthorized": r"\b(?:unauthorized|malicious)\b",
    "vulnerability": r"\b(?:vulnerability|exploit|credential theft)\b",
    "denial_of_service": r"\b(?:ddos|denial of service)\b",
}


def main() -> None:
    profile = build_profile()
    OUT_PATH.write_text(
        json.dumps(profile, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT_PATH.write_text(render_report(profile), encoding="utf-8")
    print(json.dumps(profile["summary"], ensure_ascii=False, indent=2))
    print(f"wrote {OUT_PATH}")
    print(f"wrote {REPORT_PATH}")


def build_profile() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    source = next(
        item for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    artifact = source["artifacts"][0]
    archive_path = ROOT / artifact["relative_path"]
    actual_sha = _sha256_file(archive_path)
    if actual_sha != artifact["sha256"]:
        raise ValueError("incident archive SHA-256 mismatch")

    candidates = []
    total_by_vendor = Counter()
    candidate_by_vendor = Counter()
    security_hit_by_vendor = Counter()
    with zipfile.ZipFile(archive_path) as archive:
        for vendor, member in MEMBERS.items():
            raw = archive.read(member)
            wrapper = io.TextIOWrapper(
                io.BytesIO(raw),
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            )
            csv.field_size_limit(sys.maxsize)
            reader = csv.DictReader(wrapper)
            for row_index, row in enumerate(reader):
                total_by_vendor[vendor] += 1
                normalized = _normalized_text(row)
                data_facets = sorted(
                    name
                    for name, pattern in DATA_PATTERNS.items()
                    if re.search(pattern, normalized, re.I)
                )
                if not data_facets:
                    continue
                security_hits = sorted(
                    name
                    for name, pattern in SECURITY_PATTERNS.items()
                    if re.search(pattern, normalized, re.I)
                )
                candidate_by_vendor[vendor] += 1
                security_hit_by_vendor[vendor] += int(bool(security_hits))
                canonical_row = json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                report_id = (
                    f"cloud-incident:{vendor.lower()}:{row_index:05d}"
                )
                candidates.append(
                    {
                        "candidate_id": report_id,
                        "independence_group": report_id,
                        "vendor": vendor,
                        "service_hint": _service_hint(row),
                        "year": row.get("year"),
                        "data_relevance_facets": data_facets,
                        "security_term_hits": security_hits,
                        "report_preview": _plain_text(
                            _description(row)
                        )[:500],
                        "raw_ref": {
                            "archive_relative_path": artifact[
                                "relative_path"
                            ],
                            "archive_sha256": artifact["sha256"],
                            "member_path": member,
                            "record_index": row_index,
                            "record_sha256": hashlib.sha256(
                                canonical_row
                            ).hexdigest(),
                        },
                        "human_screening": {
                            "cloud_data_relevant": None,
                            "non_attack_confirmed": None,
                            "usable_as_negative_control": None,
                            "annotator_id": None,
                            "reviewer_id": None,
                            "rationale": None,
                        },
                        "path_label": None,
                        "evidence_state": None,
                    }
                )

    candidates.sort(key=lambda item: item["candidate_id"])
    return {
        "profile_version": "0.1",
        "source": {
            "source_id": SOURCE_ID,
            "doi": "10.5281/zenodo.14010282",
            "version": source["commit"],
            "license": "CC-BY-4.0",
            "archive_sha256": artifact["sha256"],
            "upstream_checksum": artifact.get("upstream_checksum"),
        },
        "policy": {
            "generated_reports": 0,
            "generated_labels": 0,
            "generated_paths": 0,
            "keyword_match_is_not_a_label": True,
            "negative_control_requires_human_confirmation": True,
            "purpose": (
                "external false-positive control candidate routing only"
            ),
        },
        "summary": {
            "source_reports": sum(total_by_vendor.values()),
            "source_reports_by_vendor": dict(total_by_vendor),
            "cloud_data_keyword_candidates": len(candidates),
            "candidates_by_vendor": dict(candidate_by_vendor),
            "candidates_with_security_terms": sum(
                security_hit_by_vendor.values()
            ),
            "security_term_hits_by_vendor": dict(
                security_hit_by_vendor
            ),
            "author_published_human_labels": 460,
        },
        "candidates": candidates,
    }


def render_report(profile: dict[str, Any]) -> str:
    summary = profile["summary"]
    return "\n".join(
        [
            "# 真实云可靠性事件负对照候选剖面",
            "",
            "## 数据定位",
            "",
            f"- 固定 DOI：`{profile['source']['doi']}`；许可："
            f"`{profile['source']['license']}`；",
            f"- 原始生产事件报告：{summary['source_reports']} 份，分布为 "
            f"{summary['source_reports_by_vendor']}；",
            f"- 机械关键词路由出的云数据相关候选："
            f"{summary['cloud_data_keyword_candidates']} 份；",
            f"- 其中包含安全相关词的候选："
            f"{summary['candidates_with_security_terms']} 份，必须优先人工排除；",
            "- 数据集作者发布了 460 份人工信息抽取标注，但这些不是攻击路径标签。",
            "",
            "## 使用边界",
            "",
            "1. 该来源是生产可靠性/可用性事件报告，不是攻击遥测；",
            "2. 关键词命中只用于把报告送交人工阅读，不代表数据库路径或非攻击标签；",
            "3. 只有双人确认“云数据相关且非攻击”的报告才能进入 external negative control；",
            "4. 负对照用于测量 Agent 的攻击路径幻觉率、错误结束率和 abstention；",
            "5. 不得将 3,087 份报告或关键词候选计作正向攻击路径样本；",
            "6. 每个候选保留 archive/member/record index 与行级 SHA-256。",
            "",
        ]
    )


def _normalized_text(row: dict[str, Any]) -> str:
    return _plain_text(
        " ".join(str(value or "") for value in row.values())
    ).lower()


def _plain_text(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html.unescape(str(value)))
    return re.sub(r"\s+", " ", text).strip()


def _description(row: dict[str, Any]) -> str:
    return str(
        row.get("description")
        or row.get("external_description")
        or ""
    )


def _service_hint(row: dict[str, Any]) -> str | None:
    return (
        row.get("service")
        or row.get("service_name")
        or row.get("status")
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()
