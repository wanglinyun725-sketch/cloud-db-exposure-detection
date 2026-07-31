"""Build a blind, label-empty packet for real configuration lineages.

The packet copies immutable IaC bytes and verified locators from the existing
configuration-oracle queue.  It deliberately omits upstream expected outcomes
and never upgrades configuration literals to runtime reachability.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping
from zipfile import ZipFile

import yaml


LABEL_ARRAYS = (
    "nodes",
    "edges",
    "path_labels",
    "tool_tasks",
    "instance_labels",
)


def build_configuration_annotation_packet(
    root: str | Path,
    *,
    queue_path: str | Path,
    registry_path: str | Path,
    schema_path: str | Path,
) -> dict[str, Any]:
    """Return a deterministic 10-lineage configuration review packet."""
    root = Path(root).resolve()
    queue_path = _resolve(root, queue_path)
    registry_path = _resolve(root, registry_path)
    schema_path = _resolve(root, schema_path)
    queue = _read_json(queue_path)
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    if not isinstance(registry, Mapping):
        raise ValueError("source registry root must be an object")
    registry_by_id = {
        str(item["source_id"]): item
        for item in registry.get("sources") or []
    }

    cases = []
    groups: set[str] = set()
    sources: set[str] = set()
    platforms: set[str] = set()
    for source_case in queue.get("cases") or []:
        case = _build_case(root, source_case, registry_by_id)
        group = case["candidate_metadata"]["independence_group"]
        if group in groups:
            raise ValueError(f"duplicate configuration group: {group}")
        groups.add(group)
        sources.add(case["source"]["source_id"])
        platforms.add(case["candidate_metadata"]["platform"])
        cases.append(case)
    cases.sort(key=lambda item: item["case_id"])
    if len(cases) != 10 or len(groups) != 10:
        raise ValueError("configuration packet must contain 10 full groups")

    case_ids = [case["case_id"] for case in cases]
    group_ids = sorted(groups)
    return {
        "packet_version": "1.0",
        "packet_kind": "configuration_supplemental_10_unlabeled",
        "protocol_id": "configuration_double_human_v1",
        "protocol_status": "frozen_before_human_labels",
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "source_bytes_copied_from_pinned_archives": True,
            "upstream_expected_outcomes_hidden": True,
            "configuration_literal_is_runtime_reachability": False,
            "configuration_gold_and_runtime_gold_are_separate": True,
            "runtime_reachability_without_active_probe": "Unknown",
            "two_independent_humans_required": True,
            "third_human_adjudication_for_disputes": True,
            "llm_annotation_prohibited": True,
        },
        "base_queue": _binding(root, queue_path),
        "source_registry": _binding(root, registry_path),
        "selection": {
            "rule": (
                "all ten independent pinned configuration lineages, "
                "selected before human labels without consulting expected "
                "outcomes"
            ),
            "selected_case_ids": case_ids,
            "selected_case_ids_sha256": _stable_hash(case_ids),
            "selected_independence_groups": group_ids,
            "selected_independence_groups_sha256": _stable_hash(group_ids),
        },
        "summary": {
            "case_count": len(cases),
            "independence_group_count": len(groups),
            "source_count": len(sources),
            "sources": sorted(sources),
            "platforms": sorted(platforms),
            "runtime_instance_count": 0,
            "verified_configuration_assertions": sum(
                len(case["configuration_evidence"])
                for case in cases
            ),
            "human_gold_cases": 0,
            "human_gold_independence_groups": 0,
        },
        "schema_ref": {
            "path": schema_path.relative_to(root).as_posix(),
            "sha256": sha256(schema_path.read_bytes()).hexdigest(),
        },
        "cases": cases,
    }


def _build_case(
    root: Path,
    source_case: Mapping[str, Any],
    registry_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    source_id = str(source_case.get("source_id") or "")
    registry = registry_by_id.get(source_id)
    if not isinstance(registry, Mapping):
        raise ValueError(f"configuration source is unregistered: {source_id}")
    revision = str(source_case.get("revision") or "")
    if registry.get("version_or_commit") != revision:
        raise ValueError(f"configuration revision mismatch: {source_id}")

    assertions = source_case.get("configuration_assertions")
    if not isinstance(assertions, list) or not assertions:
        raise ValueError("configuration case lacks assertions")
    source_materials = _source_materials(root, assertions)
    raw_artifacts = sorted(
        {
            (
                str(assertion["raw_ref"]["archive_relative_path"]),
                str(assertion["raw_ref"]["archive_sha256"]),
            )
            for assertion in assertions
        }
    )
    configuration_evidence = []
    for assertion in assertions:
        item = deepcopy(assertion)
        item.pop("literal_interpretation", None)
        if item.get("fact_state") != "VerifiedLiteralPresence":
            raise ValueError("configuration assertion is not byte-verified")
        configuration_evidence.append(item)

    evidence_layers = deepcopy(source_case.get("evidence_layers") or [])
    if not evidence_layers or evidence_layers[0].get(
        "status"
    ) != "verified_literal_facts_only":
        raise ValueError("configuration evidence layers are incomplete")
    platform = str(source_case.get("platform") or "").upper()
    provenance = str(registry.get("provenance_level") or "")
    if provenance not in {"A", "B", "C"}:
        provenance = "C"

    return {
        "case_id": str(source_case["case_id"]),
        "source": {
            "source_id": source_id,
            "upstream_url": registry["upstream_url"],
            "version_or_commit": revision,
            "license": registry["license"],
            "provenance_level": provenance,
            "raw_artifacts": [
                {"raw_ref": path, "sha256": digest}
                for path, digest in raw_artifacts
            ],
        },
        "annotation": {
            "status": "pending",
            "label_origin": None,
            "primary_annotator": None,
            "reviewer": None,
            "adjudication": None,
        },
        "candidate_metadata": {
            "candidate_id": str(source_case["case_id"]),
            "kind": "deterministic_configuration_lineage",
            "platform": platform,
            "independence_group": str(
                source_case["independence_group"]
            ),
            "runtime_backed": False,
            "runtime_reachability": "Unknown",
            "routing_origin": (
                "pre-label byte-level routing from pinned upstream IaC; "
                "not an exposure or reachability label"
            ),
        },
        "data_target": deepcopy(source_case["data_target"]),
        "configuration_evidence": configuration_evidence,
        "source_materials": source_materials,
        "evidence_layers": evidence_layers,
        "oracle_tasks": _oracle_tasks(evidence_layers),
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
        **{field: [] for field in LABEL_ARRAYS},
    }


def _source_materials(
    root: Path,
    assertions: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    references: dict[tuple[str, str], Mapping[str, Any]] = {}
    for assertion in assertions:
        raw_ref = assertion.get("raw_ref")
        if not isinstance(raw_ref, Mapping):
            raise ValueError("configuration assertion lacks raw_ref")
        key = (
            str(raw_ref.get("archive_relative_path") or ""),
            str(raw_ref.get("archive_member") or ""),
        )
        references[key] = raw_ref

    materials = []
    archives: dict[Path, ZipFile] = {}
    try:
        for (archive_relative, member), raw_ref in sorted(
            references.items()
        ):
            archive_path = _resolve(root, archive_relative)
            archive_digest = sha256(archive_path.read_bytes()).hexdigest()
            if archive_digest != raw_ref.get("archive_sha256"):
                raise ValueError("configuration archive hash mismatch")
            archive = archives.get(archive_path)
            if archive is None:
                archive = ZipFile(archive_path)
                archives[archive_path] = archive
            member_bytes = archive.read(member)
            if (
                sha256(member_bytes).hexdigest()
                != raw_ref.get("archive_member_sha256")
            ):
                raise ValueError("configuration member hash mismatch")
            materials.append({
                "raw_ref": f"{archive_relative}#{member}",
                "archive_sha256": archive_digest,
                "member_path": member,
                "member_sha256": sha256(member_bytes).hexdigest(),
                "bytes": len(member_bytes),
                "content_kind": "terraform_hcl",
                "text": member_bytes.decode("utf-8", errors="replace"),
                "copy_policy": (
                    "exact decoded upstream archive member; no generated "
                    "configuration or label"
                ),
            })
    finally:
        for archive in archives.values():
            archive.close()
    return materials


def _oracle_tasks(
    layers: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    output = []
    for layer in layers:
        if layer.get("layer") == "provider_native_analysis":
            output.append({
                "evidence_layer": "provider_native_analysis",
                "status": "pending",
                "required_scope": layer.get("required_scope"),
                "accepted_oracles": deepcopy(
                    layer.get("accepted_oracles") or []
                ),
                "absent_finding_state": "Unknown",
                "expected_outcome": None,
            })
        elif layer.get("layer") == "authorized_active_probe":
            output.append({
                "evidence_layer": "authorized_active_probe",
                "status": "pending",
                "required_scope": layer.get("required_scope"),
                "accepted_oracle": layer.get("accepted_oracle"),
                "expected_outcome": None,
            })
    return output


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {value}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _binding(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
