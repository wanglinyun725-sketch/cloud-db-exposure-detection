"""Fail-closed audit of the confirmatory annotation reserve supply.

This module does not decide whether a candidate is an attack path and never
creates labels.  It only checks whether the frozen primary packet plus
hash-bound, structurally screened reserve candidates provide enough material
to tolerate a preregistered amount of human rejection.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


def build_reserve_adequacy_audit(
    root: str | Path,
    *,
    primary_packet_path: str | Path,
    structural_audit_path: str | Path,
    reserve_candidate_paths: Sequence[str | Path],
    target_gold_groups: int = 30,
    minimum_reserve_groups: int = 5,
) -> dict[str, Any]:
    """Build a deterministic, label-blind annotation-supply audit."""
    root = Path(root).resolve()
    if target_gold_groups < 1:
        raise ValueError("target_gold_groups must be positive")
    if minimum_reserve_groups < 0:
        raise ValueError("minimum_reserve_groups cannot be negative")

    packet_path = _resolve(root, primary_packet_path)
    audit_path = _resolve(root, structural_audit_path)
    packet = _read_object(packet_path)
    structural_audit = _read_object(audit_path)

    primary_cases = packet.get("cases")
    if not isinstance(primary_cases, list) or not primary_cases:
        raise ValueError("primary packet must contain non-empty cases")
    primary_groups = _independence_groups(primary_cases, "primary")
    if len(primary_groups) != target_gold_groups:
        raise ValueError(
            "frozen primary packet does not contain exactly "
            f"{target_gold_groups} independence groups"
        )

    eligible_ids = structural_audit.get("eligible_dataset_ids")
    if not isinstance(eligible_ids, list):
        raise ValueError("structural audit lacks eligible_dataset_ids")
    eligible_ids = {str(value) for value in eligible_ids}
    if structural_audit.get("policy", {}).get(
        "structural_triage_is_not_human_admission"
    ) is not True:
        raise ValueError("structural audit must remain label-blind")

    reserve_rows: list[dict[str, Any]] = []
    reserve_groups: set[str] = set()
    for candidate_path_value in reserve_candidate_paths:
        candidate_path = _resolve(root, candidate_path_value)
        candidate = _read_object(candidate_path)
        row = _validate_reserve_candidate(
            root,
            candidate,
            eligible_ids=eligible_ids,
        )
        group = row["independence_group"]
        if group in primary_groups:
            raise ValueError(
                f"reserve group collides with primary packet: {group}"
            )
        if group in reserve_groups:
            raise ValueError(f"duplicate reserve group: {group}")
        reserve_groups.add(group)
        row["candidate_binding"] = _binding(root, candidate_path)
        reserve_rows.append(row)

    reserve_rows.sort(key=lambda row: row["independence_group"])
    primary_count = len(primary_groups)
    reserve_count = len(reserve_groups)
    total_screenable = primary_count + reserve_count
    missing_reserve = max(0, minimum_reserve_groups - reserve_count)
    robust_supply_ready = reserve_count >= minimum_reserve_groups

    return {
        "audit_version": "1.0",
        "audit_kind": "confirmatory_annotation_supply",
        "status": (
            "reserve_supply_ready"
            if robust_supply_ready
            else "insufficient_reserve"
        ),
        "policy": {
            "statistical_unit": "independence_group",
            "target_human_gold_groups": target_gold_groups,
            "minimum_structurally_eligible_reserve_groups": (
                minimum_reserve_groups
            ),
            "reserve_fraction_of_target": (
                minimum_reserve_groups / target_gold_groups
            ),
            "reserve_is_operational_attrition_buffer": True,
            "reserve_is_not_human_gold": True,
            "structural_screen_is_not_admission": True,
            "generated_events": 0,
            "generated_labels": 0,
            "publication_gate_unchanged": True,
        },
        "inputs": {
            "primary_packet": _binding(root, packet_path),
            "structural_audit": _binding(root, audit_path),
            "reserve_candidates": [
                row["candidate_binding"] for row in reserve_rows
            ],
        },
        "summary": {
            "primary_independence_groups": primary_count,
            "structurally_eligible_reserve_groups": reserve_count,
            "total_screenable_independence_groups": total_screenable,
            "target_human_gold_groups": target_gold_groups,
            "primary_rejections_tolerated_before_supply_shortfall": (
                reserve_count
            ),
            "minimum_reserve_groups": minimum_reserve_groups,
            "missing_reserve_groups": missing_reserve,
            "robust_annotation_supply_ready": robust_supply_ready,
            "new_human_gold": 0,
        },
        "primary_independence_groups": sorted(primary_groups),
        "reserve_candidates": reserve_rows,
        "interpretation": (
            "The primary packet has no attrition margin unless a reserve "
            "candidate later passes the same independent double-human "
            "admission and adjudication protocol. Structural eligibility "
            "alone must never be reported as human gold."
        ),
        "required_next_action": (
            None
            if robust_supply_ready
            else (
                "Acquire and structurally screen at least "
                f"{missing_reserve} additional independent real-runtime "
                "candidate group(s), then submit all reserves to the frozen "
                "double-human protocol."
            )
        ),
    }


def _validate_reserve_candidate(
    root: Path,
    candidate: Mapping[str, Any],
    *,
    eligible_ids: set[str],
) -> dict[str, Any]:
    if candidate.get("candidate_kind") != "unlabeled_runtime_reserve":
        raise ValueError("reserve candidate has wrong kind")
    case_id = str(candidate.get("case_id") or "")
    marker = "attack_techniques/"
    if marker not in case_id:
        raise ValueError("reserve case_id does not expose upstream dataset")
    dataset_id = case_id.split(marker, 1)[1]
    if dataset_id not in eligible_ids:
        raise ValueError(
            f"candidate is not structurally eligible: {dataset_id}"
        )
    group = str(candidate.get("independence_group") or "")
    if not group:
        raise ValueError("reserve candidate lacks independence_group")

    annotation = candidate.get("annotation")
    if (
        not isinstance(annotation, Mapping)
        or annotation.get("status") != "pending"
        or annotation.get("label_origin") is not None
    ):
        raise ValueError("reserve candidate contains a label or is not pending")
    for field in ("nodes", "edges", "path_labels", "tool_tasks"):
        if candidate.get(field) != []:
            raise ValueError(f"reserve candidate field must be empty: {field}")

    metadata = candidate.get("candidate_metadata")
    policy = candidate.get("policy")
    if (
        not isinstance(metadata, Mapping)
        or metadata.get("structural_multistep_observed") is not True
        or metadata.get("human_admission_required") is not True
    ):
        raise ValueError("reserve candidate lacks structural screen evidence")
    if (
        not isinstance(policy, Mapping)
        or policy.get("raw_events_generated") != 0
        or policy.get("labels_generated") != 0
        or policy.get("candidate_is_not_gold") is not True
        or policy.get("publication_use_before_double_human_review") is not False
    ):
        raise ValueError("reserve candidate violates label-blind policy")

    source = candidate.get("source")
    if not isinstance(source, Mapping):
        raise ValueError("reserve candidate lacks source provenance")
    for key in ("metadata_artifact", "raw_artifact"):
        artifact = source.get(key)
        if not isinstance(artifact, Mapping):
            raise ValueError(f"reserve source lacks {key}")
        path = _resolve(root, str(artifact.get("path") or ""))
        digest = sha256(path.read_bytes()).hexdigest()
        if digest != artifact.get("sha256"):
            raise ValueError(f"reserve source hash mismatch: {key}")

    return {
        "case_id": case_id,
        "dataset_id": dataset_id,
        "independence_group": group,
        "source_id": source.get("source_id"),
        "structural_multistep_observed": True,
        "human_admission_status": "pending",
        "counts_as_human_gold": False,
    }


def _independence_groups(
    cases: Sequence[Any],
    label: str,
) -> set[str]:
    groups: set[str] = set()
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError(f"{label} packet contains a non-object case")
        metadata = case.get("candidate_metadata")
        group = (
            metadata.get("independence_group")
            if isinstance(metadata, Mapping)
            else None
        )
        if not isinstance(group, str) or not group:
            raise ValueError(f"{label} case lacks independence_group")
        groups.add(group)
    return groups


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _resolve(root: Path, path: str | Path) -> Path:
    value = Path(path)
    resolved = value.resolve() if value.is_absolute() else (root / value).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {path}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _binding(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }
