"""Blind two-human screening for real reliability-incident controls."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any


ROLES = {"primary", "reviewer", "adjudicator"}
AI_ID_MARKERS = {
    "ai",
    "assistant",
    "chatgpt",
    "claude",
    "copilot",
    "gemini",
    "gpt",
    "llm",
    "model",
    "qwen",
}
SCREEN_FIELDS = {
    "cloud_data_relevant",
    "non_attack_confirmed",
    "usable_as_negative_control",
    "rationale",
}


def create_negative_assignment(
    packet: dict[str, Any],
    role: str,
    annotator_id: str,
) -> dict[str, Any]:
    """Create a blank primary/reviewer assignment from the same source bytes."""
    _validate_human(role, annotator_id)
    if role == "adjudicator":
        raise ValueError("adjudicator assignments require explicit disputes")
    _assert_source_packet_unlabeled(packet)
    packet_sha = _stable_hash(packet)
    cases = []
    for source_case in packet["cases"]:
        context = {
            key: deepcopy(value)
            for key, value in source_case.items()
            if key != "screening"
        }
        cases.append({
            **context,
            "workflow_version": "0.1",
            "packet_sha256": packet_sha,
            "role": role,
            "annotator_id": annotator_id,
            "human_attestation": False,
            "completed_at": None,
            "source_context_fields": sorted(context),
            "source_context_sha256": _stable_hash(context),
            "screening": {
                "cloud_data_relevant": None,
                "non_attack_confirmed": None,
                "usable_as_negative_control": None,
                "rationale": None,
            },
        })
    return {
        "assignment_version": "0.1",
        "assignment_id": (
            f"negative-{role}-"
            + sha256(
                f"{packet_sha}:{annotator_id}".encode("utf-8")
            ).hexdigest()[:16]
        ),
        "role": role,
        "annotator_id": annotator_id,
        "packet_sha256": packet_sha,
        "policy": {
            "source_labels_copied": 0,
            "other_annotator_labels_visible": 0,
            "human_attestation_required": True,
        },
        "cases": cases,
    }


def create_negative_adjudication_assignment(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
    adjudicator_id: str,
) -> dict[str, Any]:
    _validate_assignment(primary)
    _validate_assignment(reviewer)
    _validate_pair(primary, reviewer)
    _validate_human("adjudicator", adjudicator_id)
    if adjudicator_id in {
        primary["annotator_id"],
        reviewer["annotator_id"],
    }:
        raise ValueError("adjudicator must be a third human")
    left = {item["candidate_id"]: item for item in primary["cases"]}
    right = {item["candidate_id"]: item for item in reviewer["cases"]}
    cases = []
    for candidate_id in sorted(left):
        if _screen_decision(left[candidate_id]) == _screen_decision(
            right[candidate_id]
        ):
            continue
        context = _source_context(left[candidate_id])
        cases.append({
            **deepcopy(context),
            "workflow_version": "0.1",
            "packet_sha256": primary["packet_sha256"],
            "role": "adjudicator",
            "annotator_id": adjudicator_id,
            "human_attestation": False,
            "completed_at": None,
            "source_context_fields": sorted(context),
            "source_context_sha256": _stable_hash(context),
            "screening": {
                "cloud_data_relevant": None,
                "non_attack_confirmed": None,
                "usable_as_negative_control": None,
                "rationale": None,
            },
            "dispute_context": {
                "primary": deepcopy(left[candidate_id]["screening"]),
                "reviewer": deepcopy(right[candidate_id]["screening"]),
            },
        })
    return {
        "assignment_version": "0.1",
        "assignment_id": (
            "negative-adjudicator-"
            + sha256(
                (
                    f"{primary['packet_sha256']}:{adjudicator_id}:"
                    + ",".join(item["candidate_id"] for item in cases)
                ).encode("utf-8")
            ).hexdigest()[:16]
        ),
        "role": "adjudicator",
        "annotator_id": adjudicator_id,
        "packet_sha256": primary["packet_sha256"],
        "policy": {
            "independent_labels_visible": 2,
            "disputed_cases_only": True,
            "human_attestation_required": True,
        },
        "cases": cases,
    }


def mark_negative_assignment_completed(
    assignment: dict[str, Any],
) -> dict[str, Any]:
    output = deepcopy(assignment)
    completed_at = datetime.now(timezone.utc).isoformat()
    for case in output["cases"]:
        case["human_attestation"] = True
        case["completed_at"] = completed_at
    return output


def compare_negative_assignments(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
) -> dict[str, Any]:
    _validate_assignment(primary)
    _validate_assignment(reviewer)
    _validate_pair(primary, reviewer)
    left = {item["candidate_id"]: item for item in primary["cases"]}
    right = {item["candidate_id"]: item for item in reviewer["cases"]}
    agreements = []
    disputes = []
    for candidate_id in sorted(left):
        same = (
            _screen_decision(left[candidate_id])
            == _screen_decision(right[candidate_id])
        )
        (agreements if same else disputes).append(candidate_id)
    return {
        "packet_sha256": primary["packet_sha256"],
        "cases": len(left),
        "exact_agreements": len(agreements),
        "exact_agreement_rate": len(agreements) / len(left) if left else 1.0,
        "agreed_candidate_ids": agreements,
        "cases_needing_adjudication": disputes,
    }


def validate_negative_assignment(assignment: dict[str, Any]) -> None:
    """Public validation entry point for a completed assignment file."""
    _validate_assignment(assignment)


def finalize_negative_assignments(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
    adjudication: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report = compare_negative_assignments(primary, reviewer)
    left = {item["candidate_id"]: item for item in primary["cases"]}
    right = {item["candidate_id"]: item for item in reviewer["cases"]}
    adjudicated: dict[str, dict[str, Any]] = {}
    if report["cases_needing_adjudication"]:
        if adjudication is None:
            raise ValueError("disagreements require a third human")
        _validate_assignment(adjudication)
        if adjudication.get("role") != "adjudicator":
            raise ValueError("third assignment must have adjudicator role")
        if adjudication["annotator_id"] in {
            primary["annotator_id"],
            reviewer["annotator_id"],
        }:
            raise ValueError("adjudicator must be a third human")
        adjudicated = {
            item["candidate_id"]: item
            for item in adjudication["cases"]
        }
        if set(adjudicated) != set(report["cases_needing_adjudication"]):
            raise ValueError("adjudication case set differs from disputes")

    finalized = []
    for candidate_id in sorted(left):
        source_case = left[candidate_id]
        disputed = candidate_id in report["cases_needing_adjudication"]
        chosen = adjudicated[candidate_id] if disputed else source_case
        decision = _screen_decision(chosen)
        usable = all(decision)
        context = _source_context(source_case)
        instance_id = (
            "negative-instance-"
            + sha256(candidate_id.encode("utf-8")).hexdigest()[:20]
        )
        finalized.append({
            **deepcopy(context),
            "case_kind": "external_negative_control",
            "case_id": "negative-" + sha256(
                candidate_id.encode("utf-8")
            ).hexdigest()[:20],
            "independence_group": context["independence_group"],
            "runtime_instances": [
                {
                    "instance_id": instance_id,
                    "environment_kind": "published_incident_report",
                    "observation_count": 1,
                }
            ],
            "screening": {
                "status": "adjudicated" if disputed else (
                    "reviewed" if usable else "rejected"
                ),
                "label_origin": (
                    "human_adjudicated" if disputed else "human_reviewed"
                ),
                "cloud_data_relevant": decision[0],
                "non_attack_confirmed": decision[1],
                "usable_as_negative_control": decision[2],
                "primary_annotator": primary["annotator_id"],
                "reviewer": reviewer["annotator_id"],
                "adjudicator": (
                    adjudication["annotator_id"] if disputed else None
                ),
                "primary_rationale": left[candidate_id][
                    "screening"
                ]["rationale"],
                "reviewer_rationale": right[candidate_id][
                    "screening"
                ]["rationale"],
                "final_rationale": chosen["screening"]["rationale"],
            },
            "source_context_fields": source_case["source_context_fields"],
            "source_context_sha256": source_case[
                "source_context_sha256"
            ],
        })
    return {
        "release_version": "0.1",
        "release_kind": "human_screened_external_negative_controls",
        "packet_sha256": primary["packet_sha256"],
        "agreement": report,
        "summary": {
            "finalized_cases": len(finalized),
            "usable_negative_controls": sum(
                item["screening"]["usable_as_negative_control"]
                and item["screening"]["cloud_data_relevant"]
                and item["screening"]["non_attack_confirmed"]
                for item in finalized
            ),
            "adjudicated_cases": sum(
                item["screening"]["status"] == "adjudicated"
                for item in finalized
            ),
        },
        "cases": finalized,
    }


def _validate_assignment(assignment: dict[str, Any]) -> None:
    role = assignment.get("role")
    annotator_id = assignment.get("annotator_id")
    _validate_human(role, annotator_id)
    cases = assignment.get("cases")
    if not isinstance(cases, list):
        raise ValueError("assignment cases must be an array")
    for case in cases:
        if case.get("role") != role or case.get("annotator_id") != annotator_id:
            raise ValueError("case role/annotator differs from assignment")
        if case.get("packet_sha256") != assignment.get("packet_sha256"):
            raise ValueError("case packet hash differs from assignment")
        if case.get("human_attestation") is not True:
            raise ValueError("completed screening requires human attestation")
        try:
            datetime.fromisoformat(
                str(case.get("completed_at")).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("completed_at must be ISO-8601") from exc
        context = _source_context(case)
        if _stable_hash(context) != case.get("source_context_sha256"):
            raise ValueError("source context changed after assignment")
        screening = case.get("screening")
        if not isinstance(screening, dict) or set(screening) != SCREEN_FIELDS:
            raise ValueError("screening fields do not match protocol")
        for field in SCREEN_FIELDS - {"rationale"}:
            if not isinstance(screening[field], bool):
                raise ValueError(f"{field} must be a human boolean")
        if (
            not isinstance(screening["rationale"], str)
            or not screening["rationale"].strip()
        ):
            raise ValueError("screening rationale is required")


def _validate_pair(primary: dict[str, Any], reviewer: dict[str, Any]) -> None:
    if primary.get("role") != "primary" or reviewer.get("role") != "reviewer":
        raise ValueError("expected primary and reviewer assignments")
    if primary["annotator_id"] == reviewer["annotator_id"]:
        raise ValueError("primary and reviewer must be different humans")
    if primary.get("packet_sha256") != reviewer.get("packet_sha256"):
        raise ValueError("paired assignments use different source packets")
    left = {item["candidate_id"]: item for item in primary["cases"]}
    right = {item["candidate_id"]: item for item in reviewer["cases"]}
    if set(left) != set(right):
        raise ValueError("paired assignments have different case sets")
    for candidate_id in left:
        if _source_context(left[candidate_id]) != _source_context(
            right[candidate_id]
        ):
            raise ValueError("paired assignments use different source context")


def _assert_source_packet_unlabeled(packet: dict[str, Any]) -> None:
    if packet.get("packet_kind") != (
        "unlabeled_real_incident_negative_control_screening"
    ):
        raise ValueError("not an unlabeled negative-control source packet")
    cases = packet.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("source packet has no cases")
    for case in cases:
        screening = case.get("screening") or {}
        if screening.get("status") != "pending":
            raise ValueError("source packet contains finalized screening")
        if any(
            value is not None
            for key, value in screening.items()
            if key != "status"
        ):
            raise ValueError("source packet contains prefilled screening")


def _source_context(case: dict[str, Any]) -> dict[str, Any]:
    fields = case.get("source_context_fields")
    if not isinstance(fields, list) or not fields:
        raise ValueError("missing frozen source context fields")
    if any(field not in case for field in fields):
        raise ValueError("missing frozen source context value")
    return {field: deepcopy(case[field]) for field in fields}


def _screen_decision(case: dict[str, Any]) -> tuple[bool, bool, bool]:
    screening = case["screening"]
    return (
        screening["cloud_data_relevant"],
        screening["non_attack_confirmed"],
        screening["usable_as_negative_control"],
    )


def _validate_human(role: Any, annotator_id: Any) -> None:
    if role not in ROLES:
        raise ValueError(f"invalid annotation role: {role}")
    if not isinstance(annotator_id, str) or not annotator_id.strip():
        raise ValueError("annotator_id is required")
    tokens = {
        token
        for token in annotator_id.casefold().replace("-", " ").split()
    }
    if tokens & AI_ID_MARKERS:
        raise ValueError("annotator_id appears to identify an AI/model")


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
