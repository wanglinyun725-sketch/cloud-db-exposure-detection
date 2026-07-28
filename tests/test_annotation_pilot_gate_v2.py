from copy import deepcopy
import json
from pathlib import Path
import unittest

from src.annotation.pilot_gate import _stable_hash, evaluate_pilot_gate


ROOT = Path(__file__).resolve().parents[1]
PILOT_PATH = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_pilot_round2_unlabeled.json"
)
GATE_PATH = ROOT / "configs" / "human_annotation_pilot_gate_v2.json"


class AnnotationPilotGateV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pilot = json.loads(PILOT_PATH.read_text(encoding="utf-8"))
        cls.gate = json.loads(GATE_PATH.read_text(encoding="utf-8"))

    def passing_release(self):
        cases = deepcopy(self.pilot["cases"])
        for case in cases:
            case["annotation"]["status"] = "reviewed"
            case["annotation"]["label_origin"] = "human_reviewed"
            case["admission_screen"]["decision"] = "accept"
        return {
            "release_version": "human-annotation-0.2",
            "packet_sha256": _stable_hash(self.pilot),
            "agreement": {
                "independent_cases": 23,
                "admission_exact_agreement": 0.9,
                "admission_cohen_kappa": 0.75,
                "mean_edge_identity_f1": 0.8,
                "matched_edge_state_count": 20,
                "edge_state_macro_f1_on_matched_edges": 0.8,
                "matched_path_state_count": 20,
                "mean_path_state_accuracy": 0.8,
                "path_state_cohen_kappa_on_matched_paths": 0.7,
                "matched_instance_state_count": 30,
                "instance_state_cohen_kappa": 0.7,
                "instance_state_macro_f1": 0.8,
            },
            "adjudication": {"required": 3, "completed": 3},
            "cases": cases,
        }

    def test_v2_gate_accepts_complete_three_source_release(self):
        result = evaluate_pilot_gate(
            self.passing_release(), self.pilot, self.gate
        )
        self.assertTrue(result["passes"], result["failed_checks"])
        self.assertEqual(3, result["summary"]["accepted_source_count"])

    def test_v2_gate_requires_stratus_source_to_survive_review(self):
        release = self.passing_release()
        for case in release["cases"]:
            if case["source"]["source_id"] == "stratus_red_team":
                case["annotation"]["status"] = "rejected"
                case["admission_screen"]["decision"] = "reject"
        result = evaluate_pilot_gate(release, self.pilot, self.gate)
        self.assertFalse(result["passes"])
        self.assertIn(
            "minimum_accepted_source_count", result["failed_checks"]
        )


if __name__ == "__main__":
    unittest.main()
