from __future__ import annotations

from scripts.data.build_runtime_annotation_queue_v1 import build_queue


def test_runtime_queue_is_frozen_label_empty_and_group_complete() -> None:
    queue = build_queue()

    assert queue["packet_kind"] == (
        "runtime_ready_annotation_queue_unlabeled"
    )
    assert queue["summary"]["independence_group_count"] == 32
    assert queue["summary"]["case_count"] == 58
    assert queue["summary"]["runtime_instance_count"] == 91
    assert queue["summary"]["human_gold_independence_groups"] == 0
    assert queue["policy"]["selection_uses_gold"] is False
    assert queue["policy"]["generated_labels"] == 0
    assert len(queue["selection"][
        "near_duplicate_review_required_groups"
    ]) == 2

    selected_groups = set(
        queue["selection"]["selected_independence_groups"]
    )
    case_groups = {
        case["candidate_metadata"]["independence_group"]
        for case in queue["cases"]
    }
    assert case_groups == selected_groups
    for case in queue["cases"]:
        assert case["annotation"]["status"] == "pending"
        assert not case["nodes"]
        assert not case["edges"]
        assert not case["path_labels"]
        assert case["admission_screen"]["decision"] is None
