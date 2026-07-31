import json
from pathlib import Path
import unittest

import yaml

from src.agent.frozen_negative_control_environment import (
    FrozenNegativeControlEnvironment,
)
from src.annotation.negative_control_workflow import (
    create_negative_assignment,
    finalize_negative_assignments,
    mark_negative_assignment_completed,
)
from src.experiments.ec_react_execution import (
    run_frozen_instance,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "negative_control_round1_unlabeled.json"
)
CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"


class AbstainPolicy:
    def propose(self, _view):
        return {
            "kind": "finish",
            "thought": "Do not assert an unsupported attack path.",
            "decision": "no_verified_path",
            "hypothesis": "No evidence-grounded attack path was established.",
        }


def _reviewed_negative():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    completed = []
    for role, annotator in (("primary", "human-a"), ("reviewer", "human-b")):
        assignment = create_negative_assignment(packet, role, annotator)
        for case in assignment["cases"]:
            case["screening"] = {
                "cloud_data_relevant": True,
                "non_attack_confirmed": True,
                "usable_as_negative_control": True,
                "rationale": "Human-confirmed reliability incident.",
            }
        completed.append(mark_negative_assignment_completed(assignment))
    return finalize_negative_assignments(*completed)["cases"][0]


class FrozenNegativeControlEnvironmentTests(unittest.TestCase):
    def test_screening_is_hidden_and_gold_is_invalid(self):
        case = _reviewed_negative()
        instance_id = case["runtime_instances"][0]["instance_id"]
        environment = FrozenNegativeControlEnvironment(
            case,
            instance_id,
            budget=10,
        )
        visible = json.dumps(
            {
                "context": environment.public_context,
                "summary": environment.execute("summarize_case", {}),
            },
            ensure_ascii=False,
        )
        metadata = environment.evaluation_metadata()

        self.assertNotIn("non_attack_confirmed", visible)
        self.assertNotIn("usable_as_negative_control", visible)
        self.assertEqual(
            "Invalid",
            metadata["gold_instance_label"]["overall_state"],
        )
        self.assertEqual([], metadata["gold_paths"])

    def test_same_runner_scores_correct_rejection_on_negative_control(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        method = next(
            item for item in config["methods"]
            if item["method_id"] == "fixed_order"
        )
        shared = {
            **config["shared_execution"],
            "orchestration_backend": "linear",
        }
        case = _reviewed_negative()
        instance_id = case["runtime_instances"][0]["instance_id"]
        record = run_frozen_instance(
            case,
            instance_id,
            method=method,
            shared_execution=shared,
            policy=AbstainPolicy(),
            budget=10,
            repeat=0,
            seed=1729,
        )

        self.assertTrue(record["score"]["correct_rejection"])
        self.assertIsNone(record["score"]["valid_path_recall_at_k"])
        self.assertTrue(record["human_gold_used_for_scoring_only"])


if __name__ == "__main__":
    unittest.main()
