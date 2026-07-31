from copy import deepcopy
from datetime import datetime, timezone

from scripts.data.build_confirmatory_annotation_v1 import build_packet
from src.annotation.confirmatory_freeze import (
    evaluate_confirmatory_freeze,
)
from src.annotation.workflow import (
    create_adjudication_assignment,
    create_assignment,
)


def _complete_nonaccepted(
    assignment: dict,
    *,
    decision: str = "reject",
) -> dict:
    output = deepcopy(assignment)
    for case in output["cases"]:
        case["human_attestation"] = True
        case["completed_at"] = datetime.now(timezone.utc).isoformat()
        case["admission_screen"] = {
            "external_or_low_privilege_entry_defined": False,
            "multi_step_path_present": True,
            "cloud_data_target_present": True,
            "critical_edges_have_raw_evidence": True,
            "not_a_near_duplicate": True,
            "decision": decision,
            "rationale": "A human independently reviewed the frozen evidence.",
        }
    return output


def test_blank_double_blind_tasks_never_emit_gold():
    packet = build_packet()
    primary = create_assignment(packet, "primary", "human-a")
    reviewer = create_assignment(packet, "reviewer", "human-b")

    report, release, split = evaluate_confirmatory_freeze(
        packet,
        primary,
        reviewer,
    )

    assert report["stage"] == "awaiting_double_blind"
    assert report["human_gold_independence_groups"] == 0
    assert release is None
    assert split is None


def test_complete_matching_humans_freeze_all_30_lineages():
    packet = build_packet()
    primary = _complete_nonaccepted(
        create_assignment(packet, "primary", "human-a")
    )
    reviewer = _complete_nonaccepted(
        create_assignment(packet, "reviewer", "human-b")
    )

    report, release, split = evaluate_confirmatory_freeze(
        packet,
        primary,
        reviewer,
    )

    assert report["stage"] == "frozen"
    assert report["ready_to_publish"] is True
    assert report["human_gold_independence_groups"] == 30
    assert report["decisions"] == {"reject": 52}
    assert len(release["cases"]) == 52
    assert split["summary"]["cases"] == 52
    assert split["summary"]["analytic_independence_groups"] == 0


def test_disagreement_requires_a_third_human_before_gold():
    packet = build_packet()
    primary = _complete_nonaccepted(
        create_assignment(packet, "primary", "human-a")
    )
    reviewer = _complete_nonaccepted(
        create_assignment(packet, "reviewer", "human-b")
    )
    reviewer["cases"][0]["admission_screen"]["decision"] = (
        "needs_execution"
    )

    report, release, split = evaluate_confirmatory_freeze(
        packet,
        primary,
        reviewer,
    )

    assert report["stage"] == "awaiting_adjudication"
    assert report["adjudication"]["required_cases"] == [
        reviewer["cases"][0]["case_id"]
    ]
    assert report["human_gold_independence_groups"] == 0
    assert release is None
    assert split is None


def test_completed_third_human_resolves_dispute_and_freezes():
    packet = build_packet()
    primary = _complete_nonaccepted(
        create_assignment(packet, "primary", "human-a")
    )
    reviewer = _complete_nonaccepted(
        create_assignment(packet, "reviewer", "human-b")
    )
    reviewer["cases"][0]["admission_screen"]["decision"] = (
        "needs_execution"
    )
    adjudicator = _complete_nonaccepted(
        create_adjudication_assignment(
            primary,
            reviewer,
            "human-c",
        )
    )

    report, release, split = evaluate_confirmatory_freeze(
        packet,
        primary,
        reviewer,
        adjudicator=adjudicator,
    )

    assert report["stage"] == "frozen"
    assert report["adjudication"]["valid_complete"] is True
    assert report["human_gold_independence_groups"] == 30
    first = {
        item["case_id"]: item for item in release["cases"]
    }[primary["cases"][0]["case_id"]]
    assert first["annotation"]["status"] == "rejected"
    assert first["annotation"]["label_origin"] == "human_adjudicated"
    assert split["summary"]["cases"] == 52
