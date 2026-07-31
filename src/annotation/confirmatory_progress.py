"""Audit double-human confirmatory progress at the lineage level."""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
from typing import Any

from src.annotation.task_bundle import assignment_progress
from src.annotation.workflow import compare_assignments


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def audit_confirmatory_progress(
    packet: dict[str, Any],
    primary: dict[str, Any],
    reviewer: dict[str, Any],
) -> dict[str, Any]:
    """Return a label-blind progress gate without inventing human decisions."""
    if packet.get("packet_kind") != "runtime_confirmatory_30_unlabeled":
        raise ValueError("unexpected confirmatory packet")
    expected_packet_hash = _stable_hash(packet)
    if primary.get("role") != "primary":
        raise ValueError("primary assignment has the wrong role")
    if reviewer.get("role") != "reviewer":
        raise ValueError("reviewer assignment has the wrong role")
    if primary.get("annotator_id") == reviewer.get("annotator_id"):
        raise ValueError("the two blind annotators must be different humans")
    if (
        primary.get("packet_sha256") != expected_packet_hash
        or reviewer.get("packet_sha256") != expected_packet_hash
    ):
        raise ValueError("assignments do not match the frozen packet")

    case_to_group = {
        case["case_id"]: case["candidate_metadata"]["independence_group"]
        for case in packet["cases"]
    }
    expected_case_ids = set(case_to_group)
    primary_ids = {case["case_id"] for case in primary["cases"]}
    reviewer_ids = {case["case_id"] for case in reviewer["cases"]}
    if primary_ids != expected_case_ids or reviewer_ids != expected_case_ids:
        raise ValueError("assignment case set differs from frozen packet")

    group_to_cases: dict[str, set[str]] = defaultdict(set)
    for case_id, group_id in case_to_group.items():
        group_to_cases[group_id].add(case_id)
    if len(group_to_cases) != 30:
        raise ValueError("confirmatory packet must contain 30 lineages")

    primary_progress = assignment_progress(primary)
    reviewer_progress = assignment_progress(reviewer)
    primary_complete_cases = {
        row["case_id"]
        for row in primary_progress["cases"]
        if row["state"] == "valid_complete"
    }
    reviewer_complete_cases = {
        row["case_id"]
        for row in reviewer_progress["cases"]
        if row["state"] == "valid_complete"
    }

    def complete_groups(case_ids: set[str]) -> set[str]:
        return {
            group_id
            for group_id, group_cases in group_to_cases.items()
            if group_cases <= case_ids
        }

    primary_complete_groups = complete_groups(primary_complete_cases)
    reviewer_complete_groups = complete_groups(reviewer_complete_cases)
    jointly_complete_groups = (
        primary_complete_groups & reviewer_complete_groups
    )
    fully_ready = len(jointly_complete_groups) == len(group_to_cases)
    agreement = (
        compare_assignments(primary, reviewer)
        if fully_ready
        else None
    )
    disputed_cases = (
        agreement["cases_needing_adjudication"] if agreement else []
    )
    disputed_groups = sorted({
        case_to_group[case_id] for case_id in disputed_cases
    })
    resolved_without_adjudication = (
        len(group_to_cases) - len(disputed_groups)
        if fully_ready
        else 0
    )
    return {
        "gate_version": "1.0",
        "protocol_id": packet["protocol_id"],
        "packet_sha256": expected_packet_hash,
        "statistical_unit": "independence_group",
        "summary": {
            "target_independence_groups": len(group_to_cases),
            "case_count": len(expected_case_ids),
            "primary_valid_complete_cases": len(
                primary_complete_cases
            ),
            "reviewer_valid_complete_cases": len(
                reviewer_complete_cases
            ),
            "primary_complete_groups": len(primary_complete_groups),
            "reviewer_complete_groups": len(reviewer_complete_groups),
            "jointly_complete_groups": len(jointly_complete_groups),
            "resolved_without_adjudication_groups": (
                resolved_without_adjudication
            ),
            "pending_adjudication_groups": len(disputed_groups),
            "human_gold_independence_groups": 0,
            "remaining_to_double_blind_target": (
                len(group_to_cases) - len(jointly_complete_groups)
            ),
        },
        "primary_progress": primary_progress["counts"],
        "reviewer_progress": reviewer_progress["counts"],
        "ready_for_agreement": fully_ready,
        "agreement": agreement,
        "disputed_independence_groups": disputed_groups,
        "human_gold_gate": {
            "minimum_double_blind_labeled_groups": 30,
            "double_blind_complete": fully_ready,
            "all_disputes_adjudicated": (
                fully_ready and not disputed_groups
            ),
            "passes": False,
            "reason": (
                "Final human gold remains zero until every jointly completed "
                "dispute has a valid third-human adjudication and the frozen "
                "assignments are finalized."
            ),
        },
    }
