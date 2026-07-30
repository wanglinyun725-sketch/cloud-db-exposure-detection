import json
from pathlib import Path

from src.annotation.negative_control_freeze import (
    evaluate_negative_control_freeze,
)
from src.annotation.negative_control_workflow import (
    create_negative_adjudication_assignment,
    create_negative_assignment,
    mark_negative_assignment_completed,
)
from tests.test_negative_control_workflow import _completed


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT / "data" / "real_sources" / "annotation"
    / "negative_control_round1_unlabeled.json"
)


def test_blank_negative_screening_never_emits_release():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    primary = create_negative_assignment(packet, "primary", "human-a")
    reviewer = create_negative_assignment(packet, "reviewer", "human-b")

    report, release = evaluate_negative_control_freeze(
        primary,
        reviewer,
    )

    assert report["stage"] == "awaiting_double_blind"
    assert report["ready_to_publish"] is False
    assert release is None


def test_matching_negative_screening_freezes_eligible_release():
    primary = _completed("primary", "human-a")
    reviewer = _completed("reviewer", "human-b")

    report, release = evaluate_negative_control_freeze(
        primary,
        reviewer,
    )

    assert report["stage"] == "frozen"
    assert report["experiment_eligible"] is True
    assert report["usable_negative_controls"] == 30
    assert release["release_kind"] == (
        "human_screened_external_negative_controls"
    )


def test_negative_dispute_is_fail_closed_until_adjudicated():
    primary = _completed("primary", "human-a")
    reviewer = _completed("reviewer", "human-b")
    reviewer["cases"][0]["screening"][
        "usable_as_negative_control"
    ] = False

    report, release = evaluate_negative_control_freeze(
        primary,
        reviewer,
    )

    assert report["stage"] == "awaiting_adjudication"
    assert release is None

    adjudicator = create_negative_adjudication_assignment(
        primary,
        reviewer,
        "human-c",
    )
    adjudicator["cases"][0]["screening"] = {
        "cloud_data_relevant": True,
        "non_attack_confirmed": True,
        "usable_as_negative_control": False,
        "rationale": "Third human independently resolved the report.",
    }
    adjudicator = mark_negative_assignment_completed(adjudicator)
    report, release = evaluate_negative_control_freeze(
        primary,
        reviewer,
        adjudicator=adjudicator,
    )

    assert report["stage"] == "frozen"
    assert report["usable_negative_controls"] == 29
    assert report["experiment_eligible"] is True
    assert release["summary"]["adjudicated_cases"] == 1
