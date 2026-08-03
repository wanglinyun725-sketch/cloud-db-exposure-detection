import json
from pathlib import Path

from src.oracle_gold.execution_queue import build_execution_queue


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "data/real_sources/oracle/executable_oracle_registry_v1.json"
POLICY = "configs/oracle_execution_policy_v1.yaml"
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_execution_queue_v1.json"
)


def _build():
    return build_execution_queue(
        ROOT,
        registry_path=REGISTRY,
        policy_path=POLICY,
    )


def test_committed_execution_queue_is_reproducible():
    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == _build()


def test_queue_is_label_blind_and_execution_disabled():
    queue = _build()

    assert queue["status"] == (
        "execution_disabled_pending_isolated_credentials"
    )
    assert queue["summary"] == {
        "pending_independence_groups": 40,
        "platform_task_counts": {
            "AWS": 28,
            "AZURE": 5,
            "GCP": 7,
        },
        "required_tools": [
            "aws", "az", "curl", "gcloud", "terraform"
        ],
        "authorized_tasks": 0,
        "executed_tasks": 0,
        "new_oracle_gold_groups": 0,
        "configuration_verified_groups": 10,
        "telemetry_artifact_verified_groups": 30,
    }
    assert all(
        task["expected_truth_state"] is None
        and task["safety"]["execution_authorized"] is False
        and task["status"] == "pending"
        and len(task["platform_tasks"]) == 1
        and task["platform_tasks"][0]["platform"]
        == task["selected_oracle_unit"]["platform"]
        for task in queue["tasks"]
    )
    assert queue["policy"]["generated_events"] == 0
    assert queue["policy"]["generated_labels"] == 0
    verified_groups = {
        task["independence_group"]
        for task in queue["tasks"]
        if any(
            channel["channel"] == "configuration"
            and channel["status"] == "verified"
            for platform in task["platform_tasks"]
            for channel in platform["channels"]
        )
    }
    assert len(verified_groups) == 10
