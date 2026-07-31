from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

from src.annotation.workflow import (
    create_assignment,
    validate_submission,
)
from src.data.configuration_annotation_packet import (
    build_configuration_annotation_packet,
)


ROOT = Path(__file__).resolve().parents[1]
QUEUE = (
    "data/real_sources/annotation/"
    "configuration_oracle_queue_v1_unlabeled.json"
)
REGISTRY = "data/real_sources/source_registry.yaml"
SCHEMA = "data/real_sources/realpathbench_v2_schema.json"
COMMITTED = (
    ROOT / "data" / "real_sources" / "annotation"
    / "configuration_supplemental_10_unlabeled.json"
)


def _build():
    return build_configuration_annotation_packet(
        ROOT,
        queue_path=QUEUE,
        registry_path=REGISTRY,
        schema_path=SCHEMA,
    )


def test_committed_configuration_packet_is_reproducible():
    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == _build()


def test_packet_copies_real_source_bytes_but_no_labels():
    packet = _build()

    assert packet["summary"] == {
        "case_count": 10,
        "independence_group_count": 10,
        "source_count": 5,
        "sources": [
            "awsgoat",
            "azuregoat",
            "cloudfoxable",
            "gcpgoat",
            "terragoat",
        ],
        "platforms": ["AWS", "AZURE", "GCP"],
        "runtime_instance_count": 0,
        "verified_configuration_assertions": 17,
        "human_gold_cases": 0,
        "human_gold_independence_groups": 0,
    }
    assert packet["policy"]["generated_events"] == 0
    assert packet["policy"]["generated_labels"] == 0
    for case in packet["cases"]:
        assert case["annotation"]["status"] == "pending"
        assert case["annotation"]["label_origin"] is None
        assert case["runtime_instances"] == []
        assert all(
            case[field] == []
            for field in (
                "nodes",
                "edges",
                "path_labels",
                "tool_tasks",
                "instance_labels",
            )
        )
        assert case["source_materials"]
        assert all(
            material["text"]
            for material in case["source_materials"]
        )


def test_existing_blind_workflow_supports_configuration_packet():
    packet = _build()
    primary = create_assignment(
        packet,
        "primary",
        "configuration_annotator_01",
    )
    reviewer = create_assignment(
        packet,
        "reviewer",
        "configuration_annotator_02",
    )

    assert len(primary["cases"]) == 10
    assert primary["packet_sha256"] == reviewer["packet_sha256"]
    assert primary["cases"][0]["source_context_sha256"] == reviewer[
        "cases"
    ][0]["source_context_sha256"]
    submission = deepcopy(primary["cases"][0])
    submission["human_attestation"] = True
    submission["completed_at"] = datetime.now(timezone.utc).isoformat()
    submission["admission_screen"] = {
        "external_or_low_privilege_entry_defined": False,
        "multi_step_path_present": False,
        "cloud_data_target_present": True,
        "critical_edges_have_raw_evidence": True,
        "not_a_near_duplicate": True,
        "decision": "needs_execution",
        "rationale": (
            "Configuration facts are traceable, but provider-native or "
            "runtime evidence is still required."
        ),
    }

    validate_submission(submission)
