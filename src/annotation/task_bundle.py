"""Per-case human task bundles with lossless, hash-checked merging."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from typing import Any, Mapping

from src.annotation.negative_control_workflow import (
    validate_negative_assignment,
)
from src.annotation.workflow import validate_submission


LABEL_FIELDS = (
    "nodes",
    "edges",
    "path_labels",
    "tool_tasks",
    "instance_labels",
)


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def build_case_bundle(
    assignment: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Split one assignment without altering or duplicating case content."""
    cases = assignment.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("assignment cases must be a non-empty array")
    identity_fields_and_ids = [_identity(case) for case in cases]
    case_ids = [item_id for _, item_id in identity_fields_and_ids]
    if (
        any(not isinstance(case_id, str) or not case_id for case_id in case_ids)
        or len(case_ids) != len(set(case_ids))
    ):
        raise ValueError("assignment case IDs must be non-empty and unique")
    header = deepcopy(assignment)
    del header["cases"]
    documents: dict[str, dict[str, Any]] = {}
    entries = []
    for index, case in enumerate(cases, start=1):
        identity_field, item_id = _identity(case)
        suffix = sha256(item_id.encode("utf-8")).hexdigest()[:12]
        filename = f"case_{index:03d}_{suffix}.json"
        documents[filename] = deepcopy(case)
        entries.append({
            "ordinal": index,
            "identity_field": identity_field,
            "item_id": item_id,
            "file": filename,
            "source_context_sha256": case.get("source_context_sha256"),
        })
    manifest = {
        "bundle_version": "0.1",
        "assignment_id": assignment.get("assignment_id"),
        "packet_sha256": assignment.get("packet_sha256"),
        "role": assignment.get("role"),
        "annotator_id": assignment.get("annotator_id"),
        "assignment_header": header,
        "assignment_header_sha256": _stable_hash(header),
        "case_count": len(cases),
        "entries": entries,
    }
    return manifest, documents


def merge_case_bundle(
    manifest: dict[str, Any],
    documents: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    """Reassemble a bundle and reject missing, extra or source-altered cases."""
    header = manifest.get("assignment_header")
    if not isinstance(header, dict):
        raise ValueError("bundle lacks assignment_header")
    if _stable_hash(header) != manifest.get("assignment_header_sha256"):
        raise ValueError("assignment header hash mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("bundle entries must be a non-empty array")
    expected_files = {entry.get("file") for entry in entries}
    if set(documents) != expected_files:
        missing = sorted(expected_files - set(documents))
        extra = sorted(set(documents) - expected_files)
        raise ValueError(
            f"bundle file set changed; missing={missing}, extra={extra}"
        )
    cases = []
    for entry in sorted(entries, key=lambda item: item["ordinal"]):
        case = deepcopy(documents[entry["file"]])
        if case.get(entry["identity_field"]) != entry.get("item_id"):
            raise ValueError(f"case identity changed in {entry['file']}")
        if (
            case.get("source_context_sha256")
            != entry.get("source_context_sha256")
        ):
            raise ValueError(f"source context digest changed in {entry['file']}")
        _assert_source_context(case, entry["file"])
        cases.append(case)
    if len(cases) != manifest.get("case_count"):
        raise ValueError("bundle case count changed")
    return {**deepcopy(header), "cases": cases}


def assignment_progress(assignment: dict[str, Any]) -> dict[str, Any]:
    """Report completion without interpreting or generating human labels."""
    cases = assignment.get("cases")
    if not isinstance(cases, list):
        raise ValueError("assignment cases must be an array")
    rows = []
    counts = {"blank": 0, "in_progress": 0, "valid_complete": 0, "invalid": 0}
    for case in cases:
        decision = (case.get("admission_screen") or {}).get("decision")
        blank = (
            case.get("human_attestation") is False
            and case.get("completed_at") is None
            and decision is None
            and all(not case.get(field) for field in LABEL_FIELDS)
        )
        validation_error = None
        if blank:
            state = "blank"
        elif (
            case.get("human_attestation") is True
            and case.get("completed_at") is not None
            and decision is not None
        ):
            try:
                validate_submission(case)
            except (ValueError, TypeError) as exc:
                state = "invalid"
                validation_error = str(exc)
            else:
                state = "valid_complete"
        else:
            state = "in_progress"
        counts[state] += 1
        rows.append({
            "case_id": case.get("case_id"),
            "state": state,
            "decision": decision,
            "validation_error": validation_error,
        })
    return {
        "progress_version": "0.1",
        "assignment_id": assignment.get("assignment_id"),
        "role": assignment.get("role"),
        "annotator_id": assignment.get("annotator_id"),
        "case_count": len(cases),
        "counts": counts,
        "ready_for_agreement": (
            bool(cases) and counts["valid_complete"] == len(cases)
        ),
        "cases": rows,
    }


def negative_assignment_progress(
    assignment: dict[str, Any],
) -> dict[str, Any]:
    """Report negative-screening progress without assigning any decision."""
    cases = assignment.get("cases")
    if not isinstance(cases, list):
        raise ValueError("assignment cases must be an array")
    rows = []
    counts = {"blank": 0, "in_progress": 0, "valid_complete": 0, "invalid": 0}
    header = deepcopy(assignment)
    header["cases"] = []
    for case in cases:
        screening = case.get("screening") or {}
        blank = (
            case.get("human_attestation") is False
            and case.get("completed_at") is None
            and all(value is None for value in screening.values())
        )
        validation_error = None
        if blank:
            state = "blank"
        elif (
            case.get("human_attestation") is True
            and case.get("completed_at") is not None
        ):
            single = deepcopy(header)
            single["cases"] = [deepcopy(case)]
            try:
                validate_negative_assignment(single)
            except (ValueError, TypeError) as exc:
                state = "invalid"
                validation_error = str(exc)
            else:
                state = "valid_complete"
        else:
            state = "in_progress"
        counts[state] += 1
        rows.append({
            "candidate_id": case.get("candidate_id"),
            "state": state,
            "validation_error": validation_error,
        })
    return {
        "progress_version": "0.1",
        "assignment_id": assignment.get("assignment_id"),
        "role": assignment.get("role"),
        "annotator_id": assignment.get("annotator_id"),
        "case_count": len(cases),
        "counts": counts,
        "ready_for_agreement": (
            bool(cases) and counts["valid_complete"] == len(cases)
        ),
        "cases": rows,
    }


def _identity(case: dict[str, Any]) -> tuple[str, str]:
    for field in ("case_id", "candidate_id"):
        value = case.get(field)
        if isinstance(value, str) and value:
            return field, value
    raise ValueError("case lacks case_id/candidate_id")


def _assert_source_context(case: dict[str, Any], filename: str) -> None:
    fields = case.get("source_context_fields")
    if not isinstance(fields, list) or not fields:
        raise ValueError(f"source context field list missing in {filename}")
    if any(field not in case for field in fields):
        raise ValueError(f"source context value missing in {filename}")
    context = {field: case[field] for field in fields}
    if _stable_hash(context) != case.get("source_context_sha256"):
        raise ValueError(f"source context content changed in {filename}")
