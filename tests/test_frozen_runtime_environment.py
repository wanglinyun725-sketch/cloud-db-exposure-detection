from copy import deepcopy
import json
from pathlib import Path
import unittest

from src.agent.frozen_runtime_environment import (
    FrozenRuntimeInstanceEnvironment,
)
from src.graph.path_ontology import ontology_reference


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_unlabeled.json"
)


def _reviewed_splunk_case():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    case = deepcopy(next(
        item for item in packet["cases"]
        if item["source"]["source_id"] == "splunk_attack_data"
        and item["runtime_instances"]
    ))
    case["annotation"] = {
        "status": "reviewed",
        "label_origin": "human_reviewed",
        "primary_annotator": "human-a",
        "reviewer": "human-b",
        "adjudication": None,
    }
    case["path_ontology"] = ontology_reference()
    case["admission_screen"]["decision"] = "accept"
    case["nodes"] = [
        {"id": "human-gold-actor", "type": "identity", "raw_refs": ["raw-a"]},
        {"id": "human-gold-db", "type": "database", "raw_refs": ["raw-b"]},
    ]
    case["edges"] = [
        {
            "edge_id": "human-gold-edge",
            "source": "human-gold-actor",
            "target": "human-gold-db",
            "type": "access_data",
            "evidence_state": "Supported",
            "evidence_items": [],
            "raw_refs": ["raw-a"],
            "annotator_rationale": "fixture",
        }
    ]
    case["path_labels"] = [
        {
            "path_id": "human-gold-path",
            "node_ids": ["human-gold-actor", "human-gold-db"],
            "edge_ids": ["human-gold-edge"],
            "state": "Valid",
            "certificate_raw_refs": ["raw-a"],
        }
    ]
    case["instance_labels"] = [
        {
            "instance_id": case["runtime_instances"][0]["instance_id"],
            "overall_state": "Valid",
            "path_states": [
                {"path_id": "human-gold-path", "state": "Valid"}
            ],
            "evidence_raw_refs": ["raw-a"],
            "annotator_rationale": "fixture",
        }
    ]
    return case


class FrozenRuntimeEnvironmentTests(unittest.TestCase):
    def test_policy_view_hides_case_names_and_all_human_gold(self):
        case = _reviewed_splunk_case()
        instance_id = case["runtime_instances"][0]["instance_id"]
        environment = FrozenRuntimeInstanceEnvironment(
            case,
            instance_id,
            budget=20,
        )

        output = environment.execute("summarize_case", {})
        policy_text = json.dumps(
            {
                "public_context": environment.public_context,
                "output": output,
            },
            ensure_ascii=False,
        )

        self.assertNotIn(case["case_id"], policy_text)
        self.assertNotIn("human-gold-path", policy_text)
        self.assertNotIn("human-gold-edge", policy_text)
        self.assertNotIn(
            case["candidate_metadata"]["description"],
            policy_text,
        )
        self.assertIn("human-gold-path", json.dumps(
            environment.evaluation_metadata(),
            ensure_ascii=False,
        ))

    def test_pending_or_unlabeled_case_cannot_enter_runtime(self):
        case = _reviewed_splunk_case()
        instance_id = case["runtime_instances"][0]["instance_id"]
        case["annotation"]["status"] = "pending"

        with self.assertRaisesRegex(ValueError, "reviewed/adjudicated"):
            FrozenRuntimeInstanceEnvironment(case, instance_id)


if __name__ == "__main__":
    unittest.main()
