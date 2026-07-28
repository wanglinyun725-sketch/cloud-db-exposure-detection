"""Export an unlabeled, vendor-stratified real incident screening packet."""
from __future__ import annotations

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

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
PROFILE_PATH = REAL_ROOT / "incident_negative_control_candidates.json"
SCHEMA_PATH = REAL_ROOT / "negative_control_annotation_schema.json"
OUT_PATH = (
    REAL_ROOT
    / "annotation"
    / "negative_control_round1_unlabeled.json"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "annotation_packets"
    / "negative_control_round1.md"
)


def main() -> None:
    packet = build_packet()
    validate_packet(packet)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REPORT_PATH.write_text(render_markdown(packet), encoding="utf-8")
    print(
        json.dumps(
            {
                "cases": len(packet["cases"]),
                "independence_groups": packet["summary"][
                    "independence_groups"
                ],
                "vendors": packet["summary"]["cases_by_vendor"],
                "generated_labels": 0,
                "json_output": str(OUT_PATH.relative_to(ROOT)),
                "markdown_output": str(REPORT_PATH.relative_to(ROOT)),
            },
            ensure_ascii=False,
        )
    )


def build_packet(per_vendor: int = 10) -> dict[str, Any]:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    selected = []
    for vendor in ("AWS", "AZURE", "GCP"):
        candidates = [
            item for item in profile["candidates"]
            if item["vendor"] == vendor
            and not item["security_term_hits"]
        ]
        selected.extend(_diverse_sample(candidates, per_vendor))
    full_rows = _load_full_rows(selected)
    cases = []
    for candidate in sorted(selected, key=lambda item: item["candidate_id"]):
        row = full_rows[candidate["candidate_id"]]
        independence_group, group_basis = _incident_independence_group(
            candidate,
            row,
        )
        actual_hash = hashlib.sha256(
            json.dumps(
                row,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if actual_hash != candidate["raw_ref"]["record_sha256"]:
            raise ValueError(
                f"record hash mismatch: {candidate['candidate_id']}"
            )
        cases.append(
            {
                "candidate_id": candidate["candidate_id"],
                "independence_group": independence_group,
                "independence_group_basis": group_basis,
                "source": {
                    "source_id": profile["source"]["source_id"],
                    "doi": profile["source"]["doi"],
                    "version": profile["source"]["version"],
                    "license": profile["source"]["license"],
                },
                "vendor": candidate["vendor"],
                "service_hint": candidate["service_hint"],
                "year": candidate["year"],
                "data_relevance_facets": candidate[
                    "data_relevance_facets"
                ],
                "security_term_hits": candidate["security_term_hits"],
                "report_text": _plain_text(_description(row)),
                "raw_ref": candidate["raw_ref"],
                "screening": {
                    "status": "pending",
                    "label_origin": None,
                    "cloud_data_relevant": None,
                    "non_attack_confirmed": None,
                    "usable_as_negative_control": None,
                    "primary_annotator": None,
                    "reviewer": None,
                    "rationale": None,
                },
            }
        )
    return {
        "packet_version": "0.1",
        "packet_kind": "unlabeled_real_incident_negative_control_screening",
        "policy": {
            "generated_reports": 0,
            "generated_labels": 0,
            "keyword_or_sampling_decisions_are_labels": False,
            "admission_requires_two_humans": True,
            "warning": (
                "These are real reliability incidents, not presumed negatives. "
                "Only reviewed human decisions may enter experiments."
            ),
        },
        "schema_ref": str(SCHEMA_PATH.relative_to(ROOT).as_posix()),
        "summary": {
            "cases": len(cases),
            "independence_groups": len({
                item["independence_group"] for item in cases
            }),
            "cases_by_vendor": {
                vendor: sum(
                    item["vendor"] == vendor for item in cases
                )
                for vendor in ("AWS", "AZURE", "GCP")
            },
            "distinct_data_facets": sorted({
                facet
                for item in cases
                for facet in item["data_relevance_facets"]
            }),
        },
        "cases": cases,
    }


def validate_packet(packet: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for case in packet["cases"]:
        jsonschema.validate(case, schema)
        if any(
            value is not None
            for key, value in case["screening"].items()
            if key != "status"
        ):
            raise ValueError("screening packet contains a prefilled label")
        if case["screening"]["status"] != "pending":
            raise ValueError("screening packet is not pending")


def _diverse_sample(
    candidates: list[dict[str, Any]],
    count: int,
) -> list[dict[str, Any]]:
    remaining = {
        item["candidate_id"]: item
        for item in candidates
    }
    selected = []
    facet_counts: dict[str, int] = {}
    while remaining and len(selected) < count:
        best = min(
            remaining.values(),
            key=lambda item: (
                sum(
                    facet_counts.get(facet, 0)
                    for facet in item["data_relevance_facets"]
                ),
                -len(item["data_relevance_facets"]),
                item["candidate_id"],
            ),
        )
        selected.append(best)
        remaining.pop(best["candidate_id"])
        for facet in best["data_relevance_facets"]:
            facet_counts[facet] = facet_counts.get(facet, 0) + 1
    if len(selected) != count:
        raise ValueError(f"not enough candidates for sample size {count}")
    return selected


def _load_full_rows(
    candidates: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    by_member: dict[str, dict[int, str]] = {}
    for item in candidates:
        raw_ref = item["raw_ref"]
        by_member.setdefault(raw_ref["member_path"], {})[
            raw_ref["record_index"]
        ] = item["candidate_id"]
    archive_path = ROOT / candidates[0]["raw_ref"][
        "archive_relative_path"
    ]
    rows = {}
    csv.field_size_limit(sys.maxsize)
    with zipfile.ZipFile(archive_path) as archive:
        for member, wanted in by_member.items():
            wrapper = io.TextIOWrapper(
                archive.open(member),
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            )
            for row_index, row in enumerate(csv.DictReader(wrapper)):
                candidate_id = wanted.get(row_index)
                if candidate_id is not None:
                    rows[candidate_id] = row
    missing = {
        item["candidate_id"] for item in candidates
    } - set(rows)
    if missing:
        raise ValueError(f"missing source rows: {sorted(missing)}")
    return rows


def render_markdown(packet: dict[str, Any]) -> str:
    lines = [
        "# 真实云事件 external negative control 首轮人工筛选包",
        "",
        "> 本包中的报告来自固定 DOI 数据集。脚本只做关键词路由、分层抽样和原文复制，",
        "> 没有把任何案例判定为非攻击。每例必须由两名人类独立筛选。",
        "",
        "## 筛选问题",
        "",
        "1. 报告是否确实涉及数据库、存储、备份、secret 或数据处理服务？",
        "2. 原文是否明确属于可靠性/配置/软件故障，而非攻击、安全事件或未决原因？",
        "3. 是否适合作为“Agent 应 abstain/不得声称攻击路径”的负对照？",
        "",
        f"- 案例数：{packet['summary']['cases']}",
        f"- 独立事件组：{packet['summary']['independence_groups']}",
        f"- 厂商分布：{packet['summary']['cases_by_vendor']}",
        f"- 数据相关切面：{packet['summary']['distinct_data_facets']}",
        "- 自动标签数：0",
        "",
    ]
    for index, case in enumerate(packet["cases"], 1):
        lines.extend(
            [
                f"## {index}. `{case['candidate_id']}`",
                "",
                f"- 厂商：{case['vendor']}",
                f"- 服务提示：{case['service_hint']}",
                f"- 年份：{case['year']}",
                f"- 机械关键词切面：{case['data_relevance_facets']}",
                f"- 原始定位：`{case['raw_ref']['member_path']}#record="
                f"{case['raw_ref']['record_index']}`",
                "",
                "### 原文",
                "",
                case["report_text"],
                "",
                "### 人工填写",
                "",
                "- cloud_data_relevant：`<true | false>`",
                "- non_attack_confirmed：`<true | false>`",
                "- usable_as_negative_control：`<true | false>`",
                "- rationale：`<必须引用原文>`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def _description(row: dict[str, Any]) -> str:
    return str(
        row.get("description")
        or row.get("external_description")
        or ""
    )


def _incident_independence_group(
    candidate: dict[str, Any],
    row: dict[str, Any],
) -> tuple[str, str]:
    """Group multi-service rows that explicitly cite one upstream incident."""
    description = _description(row)
    gcp_match = re.search(
        r"status\.cloud\.google\.com/incident/([a-z0-9_-]+/\d+)",
        description,
        flags=re.IGNORECASE,
    )
    if gcp_match:
        token = gcp_match.group(1).casefold().replace("/", ":")
        return f"reliability-incident:gcp:{token}", "upstream_incident_url"
    tracking_match = re.search(
        r"\btracking\s+id\s+([a-z0-9]+-[a-z0-9]+)\b",
        _plain_text(description),
        flags=re.IGNORECASE,
    )
    if tracking_match:
        return (
            "reliability-incident:azure:"
            + tracking_match.group(1).casefold(),
            "upstream_tracking_id",
        )
    return (
        "reliability-record:" + candidate["raw_ref"]["record_sha256"],
        "source_record_sha256",
    )


def _plain_text(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html.unescape(str(value)))
    return re.sub(r"\s+", " ", text).strip()


if __name__ == "__main__":
    main()
