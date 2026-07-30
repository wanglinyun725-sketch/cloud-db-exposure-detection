from scripts.data.build_confirmatory_annotation_v1 import build_packet
from src.annotation.confirmatory_progress import (
    audit_confirmatory_progress,
)
from src.annotation.workflow import create_assignment


def test_blank_assignments_report_zero_human_gold_by_lineage():
    packet = build_packet()
    primary = create_assignment(packet, "primary", "annotator_01")
    reviewer = create_assignment(packet, "reviewer", "annotator_02")

    report = audit_confirmatory_progress(packet, primary, reviewer)

    assert report["statistical_unit"] == "independence_group"
    assert report["summary"] == {
        "target_independence_groups": 30,
        "case_count": 52,
        "primary_valid_complete_cases": 0,
        "reviewer_valid_complete_cases": 0,
        "primary_complete_groups": 0,
        "reviewer_complete_groups": 0,
        "jointly_complete_groups": 0,
        "resolved_without_adjudication_groups": 0,
        "pending_adjudication_groups": 0,
        "human_gold_independence_groups": 0,
        "remaining_to_double_blind_target": 30,
    }
    assert report["ready_for_agreement"] is False
    assert report["agreement"] is None
    assert report["human_gold_gate"]["passes"] is False


def test_same_human_cannot_fill_both_blind_roles():
    packet = build_packet()
    primary = create_assignment(packet, "primary", "annotator_01")
    reviewer = create_assignment(packet, "reviewer", "annotator_02")
    reviewer["annotator_id"] = primary["annotator_id"]

    try:
        audit_confirmatory_progress(packet, primary, reviewer)
    except ValueError as exc:
        assert "different humans" in str(exc)
    else:
        raise AssertionError("same-human double annotation was accepted")
