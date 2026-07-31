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
    / "runtime_pilot_round1_unlabeled.json"
)
GATE_PATH = ROOT / "configs" / "human_annotation_pilot_gate_v1.json"


class AnnotationPilotGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pilot = json.loads(PILOT_PATH.read_text(encoding="utf-8"))
        cls.gate = json.loads(GATE_PATH.read_text(encoding="utf-8"))

    def passing_release(self):
        cases = deepcopy(self.pilot["cases"])
        for case in cases:
            case["annotation"]["status"] = "reviewed"
            case["annotation"]["label_origin"] = "human_reviewed"
        return {
            "release_version": "human-annotation-0.1",
            "packet_sha256": _stable_hash(self.pilot),
            "agreement": {
                "independent_cases": 19,
                "admission_exact_agreement": 0.9,
                "admission_cohen_kappa": 0.75,
                "mean_edge_identity_f1": 0.8,
                "matched_edge_state_count": 20,
                "edge_state_macro_f1_on_matched_edges": 0.8,
                "matched_path_state_count": 15,
                "mean_path_state_accuracy": 0.8,
                "path_state_cohen_kappa_on_matched_paths": 0.7,
                "matched_instance_state_count": 25,
                "instance_state_cohen_kappa": 0.7,
                "instance_state_macro_f1": 0.8,
            },
            "adjudication": {"required": 3, "completed": 3},
            "cases": cases,
        }

    def test_preregistered_gate_passes_only_complete_quality_release(self):
        result = evaluate_pilot_gate(
            self.passing_release(), self.pilot, self.gate
        )
        self.assertTrue(result["passes"], result["failed_checks"])
        self.assertFalse(result["failed_checks"])

    def test_low_edge_agreement_cannot_be_waived(self):
        release = self.passing_release()
        release["agreement"]["mean_edge_identity_f1"] = 0.69
        result = evaluate_pilot_gate(release, self.pilot, self.gate)
        self.assertFalse(result["passes"])
        self.assertIn("mean_edge_identity_f1", result["failed_checks"])

    def test_incomplete_adjudication_and_needs_execution_fail(self):
        release = self.passing_release()
        release["adjudication"]["completed"] = 2
        release["cases"][0]["annotation"]["status"] = "needs_execution"
        result = evaluate_pilot_gate(release, self.pilot, self.gate)
        self.assertFalse(result["passes"])
        self.assertIn("all_disputes_adjudicated", result["failed_checks"])
        self.assertIn(
            "no_unresolved_needs_execution", result["failed_checks"]
        )

    def test_undefined_kappa_requires_perfect_observed_agreement(self):
        release = self.passing_release()
        release["agreement"]["admission_cohen_kappa"] = None
        result = evaluate_pilot_gate(release, self.pilot, self.gate)
        self.assertFalse(result["passes"])
        release["agreement"]["admission_exact_agreement"] = 1.0
        result = evaluate_pilot_gate(release, self.pilot, self.gate)
        self.assertTrue(result["passes"], result["failed_checks"])


if __name__ == "__main__":
    unittest.main()
