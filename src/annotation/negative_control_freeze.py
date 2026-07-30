"""Fail-closed finalization for external negative-control screening."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from src.annotation.negative_control_workflow import (
    compare_negative_assignments,
    finalize_negative_assignments,
)
from src.annotation.task_bundle import negative_assignment_progress


def evaluate_negative_control_freeze(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
    *,
    adjudicator: dict[str, Any] | None = None,
    minimum_usable: int = 20,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return readiness and only emit a release after every human gate."""
    primary_progress = negative_assignment_progress(primary)
    reviewer_progress = negative_assignment_progress(reviewer)
    report: dict[str, Any] = {
        "freeze_gate_version": "1.0",
        "packet_sha256": primary.get("packet_sha256"),
        "stage": "awaiting_double_blind",
        "ready_to_publish": False,
        "experiment_eligible": False,
        "minimum_usable_negative_controls": minimum_usable,
        "primary_progress": primary_progress["counts"],
        "reviewer_progress": reviewer_progress["counts"],
        "agreement": None,
        "adjudication": {
            "required_cases": [],
            "provided": adjudicator is not None,
            "valid_complete": False,
        },
        "release_sha256": None,
    }
    if not (
        primary_progress["ready_for_agreement"]
        and reviewer_progress["ready_for_agreement"]
    ):
        return report, None

    agreement = compare_negative_assignments(primary, reviewer)
    disputed = list(agreement["cases_needing_adjudication"])
    report["agreement"] = agreement
    report["adjudication"]["required_cases"] = disputed
    if disputed:
        report["stage"] = "awaiting_adjudication"
        if adjudicator is None:
            return report, None
        adjudicator_progress = negative_assignment_progress(adjudicator)
        report["adjudication"]["progress"] = (
            adjudicator_progress["counts"]
        )
        if not adjudicator_progress["ready_for_agreement"]:
            return report, None
        try:
            release = finalize_negative_assignments(
                primary,
                reviewer,
                adjudicator,
            )
        except (TypeError, ValueError) as exc:
            report["adjudication"]["validation_error"] = str(exc)
            return report, None
        report["adjudication"]["valid_complete"] = True
    else:
        if adjudicator is not None:
            raise ValueError(
                "adjudicator assignment was supplied but no case is disputed"
            )
        release = finalize_negative_assignments(primary, reviewer)
        report["adjudication"]["valid_complete"] = True

    usable = int(release["summary"]["usable_negative_controls"])
    report.update({
        "stage": "frozen",
        "ready_to_publish": True,
        "experiment_eligible": usable >= minimum_usable,
        "finalized_cases": int(release["summary"]["finalized_cases"]),
        "usable_negative_controls": usable,
        "adjudicated_cases": int(
            release["summary"]["adjudicated_cases"]
        ),
        "release_sha256": _stable_hash(release),
    })
    return report, release


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
