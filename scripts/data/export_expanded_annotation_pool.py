"""Export a provenance-only annotation pool from pinned upstream materials.

The exporter copies real source text and structured objects.  It does not
generate admission decisions, graph edges, evidence states or path labels.
Executable-lab and CTI-only cases are conservatively marked provenance C until
human review and, where required, isolated execution produce runtime evidence.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.cross_cloud_environment import (  # noqa: E402
    CrossCloudTelemetryEnvironment,
)

REAL_ROOT = ROOT / "data" / "real_sources"
AUDIT_PATH = REAL_ROOT / "source_audit.json"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
BASE_PACKET_PATH = (
    REAL_ROOT / "annotation" / "full_pool_unlabeled.json"
)
OUTPUT_PATH = (
    REAL_ROOT / "annotation" / "expanded_full_pool_unlabeled.json"
)
REPORT_PATH = (
    ROOT / "docs" / "annotation_packets" / "expanded_full_pool.md"
)
CROSS_CLOUD_INDEX_PATH = (
    REAL_ROOT / "cross_cloud_full_episode_index.json"
)
STRATUS_DETONATION_INDEX_PATH = (
    REAL_ROOT / "stratus_detonation_log_index.json"
)
OTRF_RUNTIME_INDEX_PATH = (
    REAL_ROOT / "otrf_cloud_breach_s3_runtime_index.json"
)
V03_OUTPUT_PATH = (
    REAL_ROOT
    / "annotation"
    / "expanded_full_pool_v0_3_unlabeled.json"
)
V03_REPORT_PATH = (
    ROOT / "docs" / "annotation_packets" / "expanded_full_pool_v0_3.md"
)
V04_OUTPUT_PATH = (
    REAL_ROOT
    / "annotation"
    / "expanded_full_pool_v0_4_unlabeled.json"
)
V04_REPORT_PATH = (
    ROOT / "docs" / "annotation_packets" / "expanded_full_pool_v0_4.md"
)
V05_OUTPUT_PATH = (
    REAL_ROOT
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)
V05_REPORT_PATH = (
    ROOT / "docs" / "annotation_packets" / "expanded_full_pool_v0_5.md"
)

STATIC_SOURCE_SPECS = {
    "cloudgoat": {
        "upstream_url": "https://github.com/RhinoSecurityLabs/cloudgoat",
        "license": "BSD-3-Clause",
        "artifact": "snapshot.zip",
    },
    "cloudfoxable": {
        "upstream_url": "https://github.com/BishopFox/cloudfoxable",
        "license": "MIT",
        "artifact": "snapshot.zip",
    },
    "stratus_red_team": {
        "upstream_url": "https://github.com/DataDog/stratus-red-team",
        "license": "Apache-2.0",
        "artifact": "snapshot.zip",
    },
    "mitre_attack_stix": {
        "upstream_url": (
            "https://github.com/mitre-attack/attack-stix-data"
        ),
        "license": (
            "MITRE ATT&CK research-development-commercial license "
            "with attribution"
        ),
        "artifact": "enterprise-attack.json",
    },
}


def build_expanded_pool(
    *,
    mitre_limit: int = 20,
    include_qualified_otrf: bool = False,
    runtime_admissible_only: bool = False,
    hydrate_cross_cloud_details: bool = False,
) -> dict[str, Any]:
    if mitre_limit < 0:
        raise ValueError("mitre_limit must be non-negative")
    if runtime_admissible_only and not include_qualified_otrf:
        raise ValueError(
            "runtime-admissible revision requires the qualified OTRF source"
        )
    if hydrate_cross_cloud_details and not runtime_admissible_only:
        raise ValueError(
            "Cross-Cloud detail hydration requires runtime-admissible mode"
        )
    base = json.loads(BASE_PACKET_PATH.read_text(encoding="utf-8"))
    audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest_by_source = {
        item["source_id"]: item for item in manifest["sources"]
    }
    cases = deepcopy(base["cases"])
    for case in cases:
        case["runtime_instances"] = _runtime_instances(
            case,
            hydrate_details=hydrate_cross_cloud_details,
        )
        case["instance_labels"] = []
        metadata = case.setdefault("candidate_metadata", {})
        if not metadata.get("independence_group"):
            techniques = metadata.get("mitre_techniques") or []
            metadata["independence_group"] = (
                "splunk-technique:" + techniques[0]
                if techniques
                else "source-case:" + case["case_id"]
            )
    cloudgoat_cases = _archive_source_cases(
        "cloudgoat",
        audit["catalogues"]["cloudgoat"],
        manifest_by_source["cloudgoat"],
    )
    if include_qualified_otrf:
        _attach_otrf_cloud_breach_runtime(cloudgoat_cases)
    cases.extend(cloudgoat_cases)
    cases.extend(
        _archive_source_cases(
            "cloudfoxable",
            audit["catalogues"]["cloudfoxable"],
            manifest_by_source["cloudfoxable"],
        )
    )
    stratus_cases = _archive_source_cases(
        "stratus_red_team",
        audit["catalogues"]["stratus_red_team"],
        manifest_by_source["stratus_red_team"],
    )
    _attach_stratus_detonation_runtime(stratus_cases)
    cases.extend(stratus_cases)
    mitre_candidates = sorted(
        audit["catalogues"]["mitre_attack_stix"],
        key=lambda item: (
            -int(item.get("review_score") or 0),
            item["candidate_id"],
        ),
    )[:mitre_limit]
    cases.extend(
        _mitre_cases(
            mitre_candidates,
            manifest_by_source["mitre_attack_stix"],
        )
    )
    runtime_exclusions = []
    if runtime_admissible_only:
        for case in cases:
            retained = []
            for instance in case.get("runtime_instances", []):
                if int(instance.get("observation_count") or 0) <= 0:
                    runtime_exclusions.append({
                        "case_id": case["case_id"],
                        "instance_id": instance["instance_id"],
                        "reason": (
                            "zero upstream observations; cannot enter the "
                            "frozen runtime environment"
                        ),
                    })
                else:
                    retained.append(instance)
            case["runtime_instances"] = retained
    case_ids = [case["case_id"] for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("expanded pool contains duplicate case IDs")
    source_counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    runtime_instance_count = 0
    runtime_case_count = 0
    runtime_source_counts: dict[str, int] = {}
    for case in cases:
        source_id = case["source"]["source_id"]
        level = case["source"]["provenance_level"]
        source_counts[source_id] = source_counts.get(source_id, 0) + 1
        level_counts[level] = level_counts.get(level, 0) + 1
        case_runtime_count = len(case.get("runtime_instances", []))
        runtime_instance_count += case_runtime_count
        if case_runtime_count:
            runtime_case_count += 1
            evidence_sources = {
                instance.get("runtime_source_id") or source_id
                for instance in case.get("runtime_instances", [])
            }
            for evidence_source in evidence_sources:
                runtime_source_counts[evidence_source] = (
                    runtime_source_counts.get(evidence_source, 0) + 1
                )
        case.setdefault("runtime_instances", [])
        case.setdefault("instance_labels", [])
        _assert_unlabeled(case)
    return {
        "packet_version": (
            "0.5"
            if hydrate_cross_cloud_details
            else (
                "0.4"
                if runtime_admissible_only
                else ("0.3" if include_qualified_otrf else "0.2")
            )
        ),
        "packet_kind": "expanded_unlabeled_human_annotation_workspace",
        "policy": {
            "source_cases_generated": 0,
            "source_materials_synthesized": 0,
            "path_labels_generated": 0,
            "evidence_labels_generated": 0,
            "admission_decisions_generated": 0,
            "static_routing_is_not_gold": True,
            "provenance_c_requires_human_review_and_runtime_evidence": True,
            "published_stratus_detonation_logs_are_provenance_b": True,
            **(
                {"runtime_instances_must_have_observations": True}
                if runtime_admissible_only
                else {}
            ),
            **(
                {
                    "cross_cloud_detail_fields_preserved": True,
                    "cross_cloud_detail_fields": [
                        "schema",
                        "source_ip",
                        "request",
                        "response",
                    ],
                    "cross_cloud_detail_hydration_label_usage": "none",
                }
                if hydrate_cross_cloud_details
                else {}
            ),
            **(
                {"published_otrf_cloudtrail_is_provenance_b": True}
                if include_qualified_otrf
                else {}
            ),
            "warning": (
                "This is a candidate pool, not a released benchmark. "
                "Static C-level cases cannot enter the main test set "
                "without appropriate runtime evidence."
            ),
        },
        "schema_ref": "data/real_sources/realpathbench_v2_schema.json",
        "base_packet": str(BASE_PACKET_PATH.relative_to(ROOT)),
        "selection": {
            "cloudgoat": "all cloud/data candidates from source audit",
            "cloudfoxable": "all cloud/data candidates from source audit",
            "stratus_red_team": (
                "all cloud/data candidates from source audit; attach every "
                "matching pinned Grimoire detonation log without labels"
            ),
            "mitre_attack_stix": (
                f"top {mitre_limit} deterministic review-score routes; "
                "human admission still required"
            ),
            **(
                {
                    "otrf_security_datasets": (
                        "attach all 103 pinned CloudTrail rows to the "
                        "existing CloudGoat cloud_breach_s3 candidate; "
                        "retain the CloudGoat lineage group"
                    )
                }
                if include_qualified_otrf
                else {}
            ),
            **(
                {
                    "runtime_admission": (
                        "exclude only zero-observation upstream instances; "
                        "retain the candidate case, source lineage and every "
                        "non-empty paired instance; no attack/path label used"
                    )
                }
                if runtime_admissible_only
                else {}
            ),
            **(
                {
                    "cross_cloud_detail_hydration": (
                        "copy get_event_detail output produced from the same "
                        "pinned raw archive and deterministic blinding layer; "
                        "do not read evaluator metadata or source condition"
                    )
                }
                if hydrate_cross_cloud_details
                else {}
            ),
        },
        "summary": {
            "candidate_cases": len(cases),
            "source_counts": dict(sorted(source_counts.items())),
            "provenance_level_counts": dict(sorted(level_counts.items())),
            "generated_labels": 0,
            "runtime_backed_cases": runtime_case_count,
            "runtime_instances": runtime_instance_count,
            "runtime_source_case_counts": dict(
                sorted(runtime_source_counts.items())
            ),
            **(
                {
                    "runtime_admission_exclusions": runtime_exclusions,
                    "runtime_admission_exclusion_count": len(
                        runtime_exclusions
                    ),
                }
                if runtime_admissible_only
                else {}
            ),
            **(
                {
                    "cross_cloud_detail_hydrated_instances": sum(
                        1
                        for case in cases
                        for instance in case.get("runtime_instances", [])
                        if instance.get("environment_kind")
                        == "cross_cloud_opaque_episode"
                    )
                }
                if hydrate_cross_cloud_details
                else {}
            ),
            **(
                {
                    "runtime_lineage_warnings": {
                        "otrf_security_datasets": (
                            "independent telemetry publisher but not an "
                            "independent attack scenario; grouped with "
                            "cloudgoat-scenario:cloud_breach_s3"
                        )
                    }
                }
                if include_qualified_otrf
                else {}
            ),
        },
        "cases": cases,
    }


def _archive_source_cases(
    source_id: str,
    candidates: list[dict[str, Any]],
    manifest_source: dict[str, Any],
) -> list[dict[str, Any]]:
    artifact = _artifact(
        manifest_source,
        STATIC_SOURCE_SPECS[source_id]["artifact"],
    )
    archive_path = ROOT / artifact["relative_path"]
    output = []
    with zipfile.ZipFile(archive_path) as archive:
        archive_names = set(archive.namelist())
        for candidate in sorted(
            candidates,
            key=lambda item: item["candidate_id"],
        ):
            paths = _candidate_member_paths(
                source_id,
                candidate,
                archive_names,
            )
            materials = [
                _read_zip_material(archive, member_path)
                for member_path in paths
            ]
            mapped_ids = _mapped_technique_ids(materials)
            output.append(
                _pending_case(
                    source_id,
                    candidate,
                    manifest_source,
                    artifact,
                    materials,
                    _independence_group(
                        source_id,
                        candidate,
                        mapped_ids,
                    ),
                    mapped_ids,
                )
            )
    return output


def _attach_stratus_detonation_runtime(
    cases: list[dict[str, Any]],
) -> None:
    """Upgrade only cases with pinned real-detonation CloudTrail logs."""
    index = json.loads(
        STRATUS_DETONATION_INDEX_PATH.read_text(encoding="utf-8")
    )
    if (
        index.get("source_id") != "stratus_red_team"
        or index.get("policy", {}).get("generated_events") != 0
        or index.get("policy", {}).get("generated_labels") != 0
    ):
        raise ValueError("invalid Stratus detonation-log index policy")
    by_candidate = {
        item["candidate_id"]: item
        for item in index["cases"]
        if item.get("routed_as_cloud_data_candidate")
    }
    attached = 0
    for case in cases:
        runtime = by_candidate.get(case["case_id"])
        if runtime is None:
            continue
        observations = deepcopy(runtime["observations"])
        if (
            not observations
            or len(observations) != runtime["observation_count"]
        ):
            raise ValueError(
                f"{case['case_id']} has invalid Stratus runtime observations"
            )
        member_sha = runtime["log_member_sha256"]
        instance_id = "instance-" + sha256(
            (
                case["case_id"]
                + ":stratus-grimoire:"
                + member_sha
            ).encode("utf-8")
        ).hexdigest()[:20]
        case["source"]["provenance_level"] = "B"
        case["source"]["raw_artifacts"].append({
            "raw_ref": (
                index["source_archive"]["relative_path"]
                + "#"
                + runtime["log_member_path"]
            ),
            "sha256": member_sha,
        })
        metadata = case["candidate_metadata"]
        metadata["runtime_observations_in_packet"] = len(observations)
        metadata["runtime_evidence_origin"] = (
            "upstream Stratus documentation: real detonation in a test "
            "AWS environment using Grimoire, anonymized with LogLicker"
        )
        metadata["runtime_environment"] = runtime["environment"]
        case["runtime_instances"] = [{
            "instance_id": instance_id,
            "environment_kind": "stratus_grimoire_detonation",
            "platform": "AWS",
            "log_profile": "cloudtrail_detonation",
            "observations": observations,
            "observation_count": len(observations),
            "selection_origin": (
                "all events copied from the matching pinned upstream "
                "detonation-log member; no event or label generated"
            ),
        }]
        attached += 1
    if attached != index["summary"]["routed_cloud_data_cases"]:
        raise ValueError(
            "not every routed Stratus detonation log matched a candidate"
        )


def _attach_otrf_cloud_breach_runtime(
    cases: list[dict[str, Any]],
) -> None:
    """Attach the complete third-party capture without adding a new group."""
    index = json.loads(
        OTRF_RUNTIME_INDEX_PATH.read_text(encoding="utf-8")
    )
    association = index.get("candidate_association") or {}
    policy = index.get("policy") or {}
    if (
        index.get("source_id") != "otrf_security_datasets"
        or association.get("candidate_id")
        != "cloudgoat:aws:cloud_breach_s3"
        or association.get("independence_group")
        != "cloudgoat-scenario:cloud_breach_s3"
        or policy.get("generated_events") != 0
        or policy.get("generated_labels") != 0
        or policy.get("independent_attack_scenario") is not False
    ):
        raise ValueError("invalid OTRF CloudGoat runtime index policy")
    case = next(
        (
            item for item in cases
            if item["case_id"] == association["candidate_id"]
        ),
        None,
    )
    if case is None:
        raise ValueError("OTRF runtime candidate is absent from CloudGoat")
    if (
        case["candidate_metadata"]["independence_group"]
        != association["independence_group"]
        or case.get("runtime_instances")
    ):
        raise ValueError("OTRF runtime would alter lineage or overwrite data")
    observations = deepcopy(index["observations"])
    if len(observations) != index["summary"]["cloudtrail_events"]:
        raise ValueError("OTRF runtime observation count changed")
    archive = index["source_archive"]
    metadata_artifact = index["source_metadata"]["artifact"]
    member = index["log_member"]
    instance_id = "instance-" + sha256(
        (
            case["case_id"]
            + ":otrf:"
            + member["sha256"]
        ).encode("utf-8")
    ).hexdigest()[:20]
    case["source"]["provenance_level"] = "B"
    case["source"]["raw_artifacts"].extend([
        {
            "raw_ref": metadata_artifact["relative_path"],
            "sha256": metadata_artifact["sha256"],
        },
        {
            "raw_ref": (
                archive["relative_path"] + "#" + member["path"]
            ),
            "sha256": member["sha256"],
        },
    ])
    metadata = case["candidate_metadata"]
    metadata["runtime_observations_in_packet"] = len(observations)
    metadata["runtime_evidence_source"] = "otrf_security_datasets"
    metadata["runtime_evidence_origin"] = (
        "OTRF SDAWS-200914011940: independently published CloudTrail "
        "capture from a CloudGoat cloud-breach-s3 simulation"
    )
    metadata["runtime_environment"] = (
        "real_isolated_cloudgoat_derived_aws_emulation"
    )
    metadata["runtime_scenario_independent"] = False
    case["runtime_instances"] = [{
        "instance_id": instance_id,
        "environment_kind": "otrf_cloudgoat_attack_emulation",
        "runtime_source_id": "otrf_security_datasets",
        "platform": "AWS",
        "log_profile": "aws_cloudtrail_jsonl",
        "observations": observations,
        "observation_count": len(observations),
        "selection_origin": (
            "all 103 records copied from the sole pinned upstream "
            "member; no event, label or independence group generated"
        ),
    }]


def _candidate_member_paths(
    source_id: str,
    candidate: dict[str, Any],
    archive_names: set[str],
) -> list[str]:
    if source_id == "cloudgoat":
        prefix = candidate["raw_ref"].split("#", 1)[1]
        preferred = {
            candidate["manifest_path"],
            *candidate.get("readme_paths", []),
        }
        preferred.update(
            name for name in archive_names
            if name.startswith(prefix)
            and name.lower().endswith((".tf", ".tf.json"))
        )
    elif source_id == "cloudfoxable":
        prefix = candidate["raw_ref"].split("#", 1)[1]
        preferred = {candidate["manifest_path"]}
        preferred.update(
            name for name in archive_names
            if name.startswith(prefix)
            and name.lower().endswith((".tf", ".tf.json", ".md"))
        )
    else:
        preferred = {candidate["documentation_path"]}
    missing = preferred - archive_names
    if missing:
        raise ValueError(
            f"{candidate['candidate_id']} has missing archive members: "
            f"{sorted(missing)}"
        )
    return sorted(preferred)


def _read_zip_material(
    archive: zipfile.ZipFile,
    member_path: str,
) -> dict[str, Any]:
    raw = archive.read(member_path)
    return {
        "raw_ref": f"snapshot.zip#{member_path}",
        "member_path": member_path,
        "member_sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
        "content_kind": Path(member_path).suffix.lower().lstrip("."),
        "text": raw.decode("utf-8", errors="replace"),
        "copy_policy": "decoded upstream bytes; no generated content",
    }


def _mitre_cases(
    candidates: list[dict[str, Any]],
    manifest_source: dict[str, Any],
) -> list[dict[str, Any]]:
    artifact = _artifact(manifest_source, "enterprise-attack.json")
    source_path = ROOT / artifact["relative_path"]
    bundle = json.loads(source_path.read_text(encoding="utf-8"))
    by_id = {
        item["id"]: item for item in bundle.get("objects", [])
        if isinstance(item, dict) and item.get("id")
    }
    output = []
    for candidate in candidates:
        object_ids = [
            candidate["candidate_id"],
            candidate["source_object_id"],
            candidate["technique_object_id"],
        ]
        materials = []
        for object_id in object_ids:
            if object_id not in by_id:
                raise ValueError(f"missing MITRE object {object_id}")
            value = by_id[object_id]
            canonical = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            materials.append(
                {
                    "raw_ref": (
                        "enterprise-attack.json#object=" + object_id
                    ),
                    "object_id": object_id,
                    "canonical_object_sha256": sha256(
                        canonical
                    ).hexdigest(),
                    "structured_object": value,
                    "copy_policy": (
                        "structured object copied from pinned STIX bundle"
                    ),
                }
            )
        output.append(
            _pending_case(
                "mitre_attack_stix",
                candidate,
                manifest_source,
                artifact,
                materials,
                (
                    "mitre-source-object:"
                    + candidate["source_object_id"]
                ),
                [candidate.get("technique_id")],
            )
        )
    return output


def _pending_case(
    source_id: str,
    candidate: dict[str, Any],
    manifest_source: dict[str, Any],
    artifact: dict[str, Any],
    materials: list[dict[str, Any]],
    independence_group: str,
    mapped_ids: list[str],
) -> dict[str, Any]:
    metadata = deepcopy(candidate)
    metadata.update(
        {
            "independence_group": independence_group,
            "runtime_observations_in_packet": 0,
            "mapped_technique_ids": [
                item for item in mapped_ids if item
            ],
            "routing_origin": (
                "deterministic keyword/metadata routing of pinned "
                "upstream material; not a label"
            ),
        }
    )
    return {
        "case_id": candidate["candidate_id"],
        "source": {
            "source_id": source_id,
            "upstream_url": STATIC_SOURCE_SPECS[source_id][
                "upstream_url"
            ],
            "version_or_commit": manifest_source["commit"],
            "license": STATIC_SOURCE_SPECS[source_id]["license"],
            "provenance_level": "C",
            "raw_artifacts": [
                {
                    "raw_ref": artifact["relative_path"],
                    "sha256": artifact["sha256"],
                }
            ],
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
        "instance_labels": [],
        "candidate_metadata": metadata,
        "source_materials": materials,
        "runtime_instances": [],
        "admission_screen": {
            "external_or_low_privilege_entry_defined": None,
            "multi_step_path_present": None,
            "cloud_data_target_present": None,
            "critical_edges_have_raw_evidence": None,
            "not_a_near_duplicate": None,
            "decision": None,
            "rationale": None,
        },
    }


def _mapped_technique_ids(
    materials: list[dict[str, Any]],
) -> list[str]:
    text = "\n".join(
        material.get("text", "") for material in materials
    )
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3}|\.A\d{3})?\b", text)))


def _independence_group(
    source_id: str,
    candidate: dict[str, Any],
    mapped_ids: list[str],
) -> str:
    if source_id == "stratus_red_team" and mapped_ids:
        return "stratus-technique:" + "+".join(mapped_ids)
    if source_id == "cloudgoat":
        return "cloudgoat-scenario:" + candidate["scenario"]
    if source_id == "cloudfoxable":
        return "cloudfoxable-challenge:" + candidate["challenge"]
    return source_id + ":" + candidate["candidate_id"]


def _artifact(
    manifest_source: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    return next(
        item for item in manifest_source["artifacts"]
        if item["name"] == name
    )


def _assert_unlabeled(case: dict[str, Any]) -> None:
    if case["annotation"]["status"] != "pending":
        raise ValueError(f"{case['case_id']} is not pending")
    if case["annotation"]["label_origin"] is not None:
        raise ValueError(f"{case['case_id']} has a label origin")
    for section in (
        "nodes",
        "edges",
        "path_labels",
        "tool_tasks",
        "instance_labels",
    ):
        if case[section]:
            raise ValueError(f"{case['case_id']} has generated {section}")
    if case["admission_screen"]["decision"] is not None:
        raise ValueError(f"{case['case_id']} has an admission decision")


def _published_telemetry_platform(case: dict[str, Any]) -> str:
    """Infer the cloud from source metadata without consulting any label."""
    schemas = {
        str(item.get("schema", "")).casefold()
        for item in case.get("observations") or []
    }
    if any("azure" in schema for schema in schemas):
        return "AZURE"
    if any(
        marker in schema
        for schema in schemas
        for marker in ("aws", "cloudtrail", "ocsf_api_activity")
    ):
        return "AWS"
    if any("gcp" in schema or "google" in schema for schema in schemas):
        return "GCP"

    case_id = str(case.get("case_id", "")).casefold()
    for marker, platform in (
        ("aws_", "AWS"),
        ("azure_", "AZURE"),
        ("gcp_", "GCP"),
    ):
        if marker in case_id:
            return platform
    raise ValueError(
        f"{case.get('case_id')} published telemetry has no label-free "
        "platform signal"
    )


def _runtime_instances(
    case: dict[str, Any],
    *,
    hydrate_details: bool = False,
) -> list[dict[str, Any]]:
    """Freeze label-empty real telemetry instances for later blind scoring."""
    observations = case.get("observations") or []
    if observations:
        instance_id = "instance-" + sha256(
            (case["case_id"] + ":published-telemetry").encode("utf-8")
        ).hexdigest()[:20]
        return [
            {
                "instance_id": instance_id,
                "environment_kind": "published_telemetry",
                "platform": _published_telemetry_platform(case),
                "observation_ids": [
                    item["observation_id"] for item in observations
                ],
                "observation_count": len(observations),
                "selection_origin": (
                    "all normalized observations copied from the pinned "
                    "published telemetry case"
                ),
            }
        ]

    refs = case.get("episode_refs") or []
    if not refs:
        return []
    by_profile_run: dict[
        tuple[str, int],
        dict[str, dict[str, Any]],
    ] = {}
    for ref in refs:
        key = (ref["log_profile"], int(ref["run_id"]))
        by_profile_run.setdefault(key, {})[
            ref["source_condition"]
        ] = ref
    complete = [
        (profile, run_id, conditions)
        for (profile, run_id), conditions in by_profile_run.items()
        if set(conditions) == {"payload_absent", "payload_present"}
    ]
    if not complete:
        raise ValueError(
            f"{case['case_id']} lacks a complete upstream telemetry pair"
        )
    _, _, selected = min(
        complete,
        key=lambda item: (
            item[0] != "default",
            item[0],
            item[1],
        ),
    )
    instances = []
    # Conditions are used only to select a complete source-published pair.
    # They are deliberately omitted from the human/policy-visible instance.
    for ref in selected.values():
        environment = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            CROSS_CLOUD_INDEX_PATH,
            ref["episode_id"],
            budget=None,
        )
        output = environment.execute("search_events", {})
        normalized = deepcopy(output["tool_result"]["events"])
        if hydrate_details:
            normalized = [
                deepcopy(environment.execute(
                    "get_event_detail",
                    {"observation_id": item["observation_id"]},
                )["tool_result"]["events"][0])
                for item in normalized
            ]
        instances.append(
            {
                "instance_id": environment.public_context["episode_handle"],
                "environment_kind": "cross_cloud_opaque_episode",
                "platform": environment.public_context["platform"],
                "log_profile": environment.public_context["log_profile"],
                "observations": normalized,
                "observation_count": len(normalized),
                "selection_origin": (
                    "one member of a complete paired upstream run selected "
                    "deterministically; source condition withheld"
                ),
            }
        )
    return sorted(instances, key=lambda item: item["instance_id"])


def render_report(packet: dict[str, Any]) -> str:
    summary = packet["summary"]
    lines = [
        "# RealPathBench-CD 扩展无标签候选池",
        "",
        "## 结论",
        "",
        f"- 候选案例：{summary['candidate_cases']}；生成标签：0。",
        f"- 冻结的无标签真实运行实例：{summary['runtime_instances']}；"
        "实例级人工标签：0。",
        "- Cross-Cloud 成对实例在导出时移除上游 present/absent 条件，"
        "只保留真实规范化 observations 与哈希引用。",
        "- 新增内容均复制自固定 commit/版本的上游仓库；脚本只做确定性路由、",
        "  解包、哈希和格式转换。",
        "- CloudGoat、CloudFoxable、MITRE 及无匹配爆破日志的 Stratus 静态材料",
        "  保守记为 C 级；11 个带官方真实爆破日志的 Stratus 候选升级为 B 级。",
        *(
            [
                "- v0.3 将 OTRF 的完整 103 条 CloudTrail 接到既有 "
                "CloudGoat cloud_breach_s3 案例；发布者新增但独立组不增加。"
            ]
            if "otrf_security_datasets"
            in summary["runtime_source_case_counts"]
            else []
        ),
        "- B 级运行时来源仍不等于 gold；人工未接纳前不得进入主测试集。",
        "",
        "## 来源分布",
        "",
        "| 来源 | 候选数 |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {source_id} | {count} |"
        for source_id, count in summary["source_counts"].items()
    )
    lines.extend(
        [
            "",
            "## 溯源结构",
            "",
            "每个新增案例保存归档 SHA-256、归档内成员路径、成员 SHA-256、",
            "原始文本或原始 STIX 对象、独立分组和执行状态。所有人工字段为空。",
            "",
            "## 研究边界",
            "",
            "候选数大于 80 不等于已有 80 个 gold。`needs_execution`、reject 和",
            "同源近重复不会计入 main included cases；最终样本量只能在盲法双人",
            "标注与必要的隔离执行完成后报告。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--include-qualified-otrf",
        action="store_true",
        help=(
            "Build v0.3 with OTRF runtime; the default preserves the "
            "v0.2 packet used by the frozen annotation pilot."
        ),
    )
    parser.add_argument(
        "--runtime-admissible-only",
        action="store_true",
        help=(
            "Build v0.4: retain OTRF and remove only zero-observation "
            "runtime instances before human annotation."
        ),
    )
    parser.add_argument(
        "--hydrate-cross-cloud-details",
        action="store_true",
        help=(
            "Build v0.5: v0.4 admission plus label-free schema, source IP, "
            "request and response detail from the same pinned telemetry."
        ),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    packet = build_expanded_pool(
        include_qualified_otrf=(
            args.include_qualified_otrf
            or args.runtime_admissible_only
            or args.hydrate_cross_cloud_details
        ),
        runtime_admissible_only=(
            args.runtime_admissible_only
            or args.hydrate_cross_cloud_details
        ),
        hydrate_cross_cloud_details=args.hydrate_cross_cloud_details,
    )
    output_path = args.output or (
        V05_OUTPUT_PATH
        if args.hydrate_cross_cloud_details
        else (
            V04_OUTPUT_PATH
            if args.runtime_admissible_only
            else (
                V03_OUTPUT_PATH
                if args.include_qualified_otrf
                else OUTPUT_PATH
            )
        )
    )
    report_path = args.report or (
        V05_REPORT_PATH
        if args.hydrate_cross_cloud_details
        else (
            V04_REPORT_PATH
            if args.runtime_admissible_only
            else (
                V03_REPORT_PATH
                if args.include_qualified_otrf
                else REPORT_PATH
            )
        )
    )
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    if not report_path.is_absolute():
        report_path = ROOT / report_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_report(packet), encoding="utf-8")
    print(
        json.dumps(
            {
                "candidate_cases": packet["summary"]["candidate_cases"],
                "source_counts": packet["summary"]["source_counts"],
                "generated_labels": 0,
                "output": str(output_path.relative_to(ROOT)),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
