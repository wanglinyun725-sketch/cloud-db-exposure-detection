from scripts.data.build_confirmatory_annotation_v1 import build_packet
from src.annotation.workflow import create_assignment


def test_confirmatory_packet_is_prelabel_frozen_and_group_complete():
    packet = build_packet()

    assert packet["summary"]["case_count"] == 52
    assert packet["summary"]["independence_group_count"] == 30
    assert packet["summary"]["excluded_collision_group_count"] == 2
    assert packet["summary"]["source_count"] == 4
    assert packet["summary"]["human_gold_independence_groups"] == 0
    assert packet["policy"]["generated_labels"] == 0
    assert packet["policy"]["selection_uses_gold"] is False
    assert packet["selection"]["excluded_collision_groups"] == [
        "crosscloud-family:data_manipulation",
        "crosscloud-family:data_staged",
    ]
    selected_groups = set(
        packet["selection"]["selected_independence_groups"]
    )
    assert {
        case["candidate_metadata"]["independence_group"]
        for case in packet["cases"]
    } == selected_groups
    assert all(
        case["annotation"]["status"] == "pending"
        and case["annotation"]["label_origin"] is None
        and not case["nodes"]
        and not case["edges"]
        and not case["path_labels"]
        and case["admission_screen"]["decision"] is None
        for case in packet["cases"]
    )


def test_primary_and_reviewer_start_blind_and_label_empty():
    packet = build_packet()
    primary = create_assignment(packet, "primary", "annotator_01")
    reviewer = create_assignment(packet, "reviewer", "annotator_02")

    assert primary["packet_sha256"] == reviewer["packet_sha256"]
    assert primary["annotator_id"] != reviewer["annotator_id"]
    assert len(primary["cases"]) == len(reviewer["cases"]) == 52
    assert primary["policy"]["other_annotator_labels_visible"] == 0
    assert reviewer["policy"]["other_annotator_labels_visible"] == 0
    for left, right in zip(primary["cases"], reviewer["cases"]):
        assert left["case_id"] == right["case_id"]
        assert left["source_context_sha256"] == right[
            "source_context_sha256"
        ]
        assert left["admission_screen"]["decision"] is None
        assert right["admission_screen"]["decision"] is None
        assert not left["nodes"] and not right["nodes"]
