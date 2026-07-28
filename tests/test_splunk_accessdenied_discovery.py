from __future__ import annotations

from scripts.data.build_splunk_accessdenied_discovery import build


def test_accessdenied_discovery_is_real_label_free_normalization() -> None:
    payload = build()
    assert payload["summary"] == {
        "raw_records": 1150,
        "candidate_cases": 5,
        "observations": 5,
        "independence_groups": 1,
        "service_counts": {
            "ssm.amazonaws.com": 1,
            "secretsmanager.amazonaws.com": 1,
            "redshift.amazonaws.com": 1,
            "rds.amazonaws.com": 1,
            "dynamodb.amazonaws.com": 1,
        },
    }
    assert payload["policy"]["generated_samples"] == 0
    assert payload["policy"]["generated_labels"] == 0
    assert payload["policy"]["success_control_available"] is False
    assert all(case["path_label"] is None for case in payload["cases"])
    assert all(case["evidence_state"] is None for case in payload["cases"])


def test_accessdenied_discovery_preserves_exact_provider_denials() -> None:
    payload = build()
    assert {
        observation["event_status"]
        for observation in payload["observations"]
    } == {"AccessDenied"}
    assert {
        observation["actor_id"]
        for observation in payload["observations"]
    } == {"arn:aws:iam::731544447609:user/cloudsploit"}
    assert all(
        observation["raw_ref"]["sha256"]
        == "4f52389f17745abf5fa1cf30c055d4f9d34022fcfb8e5c2544c70177da228433"
        for observation in payload["observations"]
    )
    assert len({
        observation["raw_ref"]["record_index"]
        for observation in payload["observations"]
    }) == 5
