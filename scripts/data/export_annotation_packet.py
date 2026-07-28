"""Export a label-free human annotation packet from pinned source material.

The exporter performs a mechanical copy/formatting operation only.  It must
not infer nodes, edges, evidence states, path states, admission decisions or
annotator rationales.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
DEFAULT_JSON = REAL_ROOT / "annotation" / "pilot_round1_unlabeled.json"
DEFAULT_MARKDOWN = ROOT / "docs" / "annotation_packets" / "pilot_round1.md"
FULL_JSON = REAL_ROOT / "annotation" / "full_pool_unlabeled.json"
FULL_MARKDOWN = ROOT / "docs" / "annotation_packets" / "full_pool.md"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_packet(scope: str = "round1") -> dict[str, Any]:
    if scope not in {"round1", "full"}:
        raise ValueError("scope must be round1 or full")
    registry = yaml.safe_load(
        (REAL_ROOT / "source_registry.yaml").read_text(encoding="utf-8")
    )
    source_by_id = {
        source["source_id"]: source
        for source in registry["sources"]
    }
    index = _load_json(
        REAL_ROOT
        / (
            "pilot_observation_index.json"
            if scope == "round1"
            else "splunk_full_observation_index.json"
        )
    )
    manifest = _load_json(
        REAL_ROOT
        / (
            "pilot_telemetry_manifest.json"
            if scope == "round1"
            else "splunk_full_telemetry_manifest.json"
        )
    )
    acquisition_manifest = _load_json(
        REAL_ROOT / "acquisition_manifest.json"
    )
    source_audit = _load_json(REAL_ROOT / "source_audit.json")
    cross_cloud_index = _load_json(
        REAL_ROOT
        / (
            "cross_cloud_pilot_episode_index.json"
            if scope == "round1"
            else "cross_cloud_full_episode_index.json"
        )
    )
    artifacts_by_candidate = {
        item["candidate_id"]: item
        for item in manifest["candidates"]
    }
    observations_by_case: dict[str, list[dict[str, Any]]] = {}
    for observation in index["observations"]:
        clean = deepcopy(observation)
        clean.pop("path_label", None)
        clean.pop("evidence_state", None)
        observations_by_case.setdefault(
            observation["candidate_id"], []
        ).append(clean)

    cases = []
    for candidate in index["cases"]:
        candidate_id = candidate["candidate_id"]
        source_registry = source_by_id[candidate["source_id"]]
        source_manifest = artifacts_by_candidate[candidate_id]
        raw_artifacts = [
            {
                "raw_ref": artifact["relative_path"],
                "sha256": artifact["sha256"],
                "upstream_path": artifact["upstream_path"],
                "git_blob_sha": artifact.get("git_blob_sha"),
                "lfs_oid_sha256": artifact.get("lfs_oid_sha256"),
            }
            for artifact in source_manifest["artifacts"]
        ]
        cases.append(
            {
                "case_id": candidate_id,
                "source": {
                    "source_id": candidate["source_id"],
                    "upstream_url": source_registry["upstream_url"],
                    "version_or_commit": source_registry["version_or_commit"],
                    "license": source_registry["license"],
                    # Splunk Attack Data is published lab/attack-range
                    # telemetry, not an independently verified production
                    # incident, so the conservative tier is B.
                    "provenance_level": "B",
                    "raw_artifacts": raw_artifacts,
                },
                "annotation": {
                    "status": "pending",
                    "label_origin": None,
                    "primary_annotator": None,
                    "reviewer": None,
                    "adjudication": None,
                },
                "nodes": [],
                "edges": [],
                "path_labels": [],
                "tool_tasks": [],
                "candidate_metadata": {
                    key: deepcopy(value)
                    for key, value in candidate.items()
                    if key not in {"observation_ids", "annotation_status"}
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
                "observations": observations_by_case.get(candidate_id, []),
                "episode_refs": [],
            }
        )

    cross_source = source_by_id["cross_cloud_observability_2026"]
    cross_artifacts = {
        item["name"]: item
        for item in next(
            source["artifacts"]
            for source in acquisition_manifest["sources"]
            if source["source_id"] == "cross_cloud_observability_2026"
        )
    }
    cross_candidates = {
        item["candidate_id"]: item
        for item in source_audit["catalogues"][
            "cross_cloud_observability_2026"
        ]
    }
    if scope == "round1":
        cross_pilot = [
            item
            for item in source_audit["pilot_annotation_candidates"]
            if item["source_id"] == "cross_cloud_observability_2026"
        ]
    else:
        selected_candidate_ids = sorted({
            episode["candidate_id"]
            for episode in cross_cloud_index["episodes"]
        })
        cross_pilot = [
            {
                "source_id": "cross_cloud_observability_2026",
                "candidate_id": candidate_id,
                "independence_group": (
                    "crosscloud-family:" + candidate_id.split(":")[2]
                ),
            }
            for candidate_id in selected_candidate_ids
        ]
    for pilot_item in cross_pilot:
        candidate_id = pilot_item["candidate_id"]
        candidate = cross_candidates[candidate_id]
        platform_archive = {
            "AWS": "aws_logs_redacted.zip",
            "AZURE": "azure_logs_redacted.zip",
            "GCP": "gcp_logs_redacted.zip",
        }[candidate["platform"]]
        raw_artifacts = []
        for artifact_name in (
            "README.md",
            "attack_scripts.zip",
            platform_archive,
            "log_analysis.zip",
        ):
            artifact = cross_artifacts[artifact_name]
            raw_artifacts.append(
                {
                    "raw_ref": artifact["relative_path"],
                    "sha256": artifact["sha256"],
                    "upstream_checksum": artifact.get(
                        "upstream_checksum"
                    ),
                }
            )
        episode_refs = [
            {
                key: deepcopy(value)
                for key, value in episode.items()
                if key not in {"path_label", "evidence_state"}
            }
            for episode in cross_cloud_index["episodes"]
            if episode["candidate_id"] == candidate_id
        ]
        cases.append(
            {
                "case_id": candidate_id,
                "source": {
                    "source_id": "cross_cloud_observability_2026",
                    "upstream_url": cross_source["upstream_url"],
                    "version_or_commit": cross_source[
                        "version_or_commit"
                    ],
                    "license": cross_source["license"],
                    "provenance_level": "B",
                    "raw_artifacts": raw_artifacts,
                },
                "annotation": {
                    "status": "pending",
                    "label_origin": None,
                    "primary_annotator": None,
                    "reviewer": None,
                    "adjudication": None,
                },
                "nodes": [],
                "edges": [],
                "path_labels": [],
                "tool_tasks": [],
                "candidate_metadata": {
                    "description": (
                        "DOI-published paired payload/no-payload "
                        f"{candidate['platform']} telemetry for "
                        f"{candidate['attack']}."
                    ),
                    "author": "Dhooghe et al.",
                    "published_date": "2026-04-30",
                    "environment": "controlled cloud subscription",
                    "platform": candidate["platform"],
                    "attack": candidate["attack"],
                    "independence_group": pilot_item[
                        "independence_group"
                    ],
                    "attack_script_refs": candidate[
                        "attack_script_refs"
                    ],
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
                "observations": [],
                "episode_refs": episode_refs,
            }
        )

    return {
        "packet_version": "0.2",
        "packet_kind": "unlabeled_human_annotation_workspace",
        "policy": {
            "source_cases_generated": 0,
            "path_labels_generated": 0,
            "evidence_labels_generated": 0,
            "admission_decisions_generated": 0,
            "allowed_label_origin": [
                "human_primary",
                "human_reviewed",
                "human_adjudicated",
            ],
            "warning": (
                "This packet is not a released benchmark split. "
                "All annotation fields must be completed by named human roles."
            ),
            "selection_scope": scope,
        },
        "schema_ref": "data/real_sources/realpathbench_v2_schema.json",
        "source_commit": source_by_id["splunk_attack_data"]["version_or_commit"],
        "source_versions": {
            "splunk_attack_data": source_by_id["splunk_attack_data"][
                "version_or_commit"
            ],
            "cross_cloud_observability_2026": cross_source[
                "version_or_commit"
            ],
        },
        "cases": cases,
    }


def validate_packet(packet: dict[str, Any]) -> None:
    schema = _load_json(REAL_ROOT / "realpathbench_v2_schema.json")
    for case in packet["cases"]:
        jsonschema.validate(
            case,
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
        if any(
            case["admission_screen"][field] is not None
            for field in case["admission_screen"]
        ):
            raise ValueError("annotation packet contains a prefilled human field")
        for observation in case["observations"]:
            if "path_label" in observation or "evidence_state" in observation:
                raise ValueError("annotation packet contains generated labels")
        for episode in case.get("episode_refs", []):
            if "path_label" in episode or "evidence_state" in episode:
                raise ValueError("annotation packet contains generated labels")


def render_markdown(packet: dict[str, Any]) -> str:
    scope = packet["policy"].get("selection_scope", "round1")
    title = (
        "RealPathBench-CD v2 首轮人工标注包"
        if scope == "round1"
        else "RealPathBench-CD v2 完整候选池人工标注包"
    )
    lines = [
        f"# {title}",
        "",
        "> 该文件只整理固定上游版本中的真实发布遥测，不包含任何 AI/脚本生成的",
        "> 准入决定、节点、边、证据状态或路径标签。请结合",
        "> `docs/realpathbench_annotation_protocol.md` 完成人工标注。",
        "",
        "## 标注顺序",
        "",
        "1. 阅读案例元数据、全部原始文件和下面的观测索引；",
        "2. 独立填写 `admission_screen`，先决定 accept / needs_execution / reject；",
        "3. 仅对 accept 案例人工建立 nodes、edges、path_labels 与 tool_tasks；",
        "4. 每条边逐项填写带 support/refute 极性的 evidence_items；",
        "5. 填入稳定匿名标注者 ID，并将状态改为 `primary_complete`；",
        "6. Reviewer 在不知道 primary 路径状态的条件下独立复核。",
        "",
        f"- 固定上游版本：`{packet['source_versions']}`",
        f"- 待人工筛选案例数：{len(packet['cases'])}",
        "- 自动生成标签数：0",
        "",
    ]
    for number, case in enumerate(packet["cases"], start=1):
        metadata = case["candidate_metadata"]
        lines.extend(
            [
                f"## {number}. `{case['case_id']}`",
                "",
                f"- 描述：{metadata.get('description', '')}",
                f"- 发布者：{metadata.get('author', '')}",
                f"- 发布日期：{metadata.get('published_date', '')}",
                f"- 环境：{metadata.get('environment', '')}",
                f"- ATT&CK：{', '.join(metadata.get('mitre_techniques', []))}",
                f"- 原始文件数：{len(case['source']['raw_artifacts'])}",
                f"- 规范化观测数：{len(case['observations'])}",
                f"- 上游 episode 数：{len(case.get('episode_refs', []))}",
                "",
                "### 准入判断（人工填写）",
                "",
                "- [ ] 有外部或低权限入口",
                "- [ ] 存在多步关系，而非单点事件",
                "- [ ] 终点为数据库、存储、备份、secret 或其他数据资产",
                "- [ ] 关键边均有原始证据",
                "- [ ] 不是近重复案例",
                "- 决定：`<accept | needs_execution | reject>`",
                "- 理由：`<人工填写>`",
                "",
                "### 观测索引",
                "",
                "| observation_id | timestamp | actor_type | service | operation | status | raw record |",
                "|---|---:|---|---|---|---|---|",
            ]
        )
        for observation in case["observations"]:
            raw_ref = observation["raw_ref"]
            raw_record = (
                f"`{raw_ref['upstream_path']}#record="
                f"{raw_ref['record_index']}`"
            )
            lines.append(
                "| {id} | {time} | {actor} | {service} | {operation} | "
                "{status} | {raw} |".format(
                    id=observation["observation_id"],
                    time=observation.get("timestamp", ""),
                    actor=observation.get("actor_type", ""),
                    service=observation.get("service", ""),
                    operation=observation.get("operation", ""),
                    status=observation.get("event_status", ""),
                    raw=raw_record,
                )
            )
        if case.get("episode_refs"):
            lines.extend(
                [
                    "",
                    "### 上游配对 episode",
                    "",
                    "| episode_id | profile | run | source condition | observations | member SHA-256 |",
                    "|---|---|---:|---|---:|---|",
                ]
            )
            for episode in case["episode_refs"]:
                lines.append(
                    "| {episode} | {profile} | {run} | {condition} | "
                    "{count} | `{sha}` |".format(
                        episode=episode["episode_id"],
                        profile=episode["log_profile"],
                        run=episode["run_id"],
                        condition=episode["source_condition"],
                        count=episode["observation_count"],
                        sha=episode["raw_ref"]["member_sha256"],
                    )
                )
        lines.extend(["", "### 原始文件完整性", ""])
        for artifact in case["source"]["raw_artifacts"]:
            artifact_ref = artifact.get(
                "upstream_path",
                artifact["raw_ref"],
            )
            lines.append(
                f"- `{artifact_ref}` — SHA-256 "
                f"`{artifact['sha256']}`"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scope",
        choices=("round1", "full"),
        default="round1",
    )
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--markdown-output",
        type=Path,
    )
    args = parser.parse_args()
    json_output = args.json_output or (
        DEFAULT_JSON if args.scope == "round1" else FULL_JSON
    )
    markdown_output = args.markdown_output or (
        DEFAULT_MARKDOWN if args.scope == "round1" else FULL_MARKDOWN
    )

    packet = build_packet(scope=args.scope)
    validate_packet(packet)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(
        render_markdown(packet) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "cases": len(packet["cases"]),
                "generated_labels": 0,
                "json_output": str(json_output.relative_to(ROOT)),
                "markdown_output": str(
                    markdown_output.relative_to(ROOT)
                ),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
