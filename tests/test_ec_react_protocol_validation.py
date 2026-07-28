import json
import unittest
from pathlib import Path

from src.agent.ec_react_protocol_validation import (
    run_protocol_validation,
    select_protocol_pairs,
)


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = (
    ROOT / "data" / "real_sources" / "cross_cloud_full_episode_index.json"
)


class ECReactProtocolValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))

    def test_selection_has_one_complete_pair_per_platform_attack(self):
        selected = select_protocol_pairs(self.index)
        groups = {}
        for episode in selected:
            groups.setdefault(
                (episode["platform"], episode["attack"]),
                set(),
            ).add(episode["source_condition"])

        self.assertEqual(72, len(selected))
        self.assertEqual(36, len(groups))
        self.assertTrue(all(
            conditions == {"payload_absent", "payload_present"}
            for conditions in groups.values()
        ))
        self.assertEqual(
            {"AWS", "AZURE", "GCP"},
            {episode["platform"] for episode in selected},
        )

    def test_real_episode_backends_match_without_label_leakage(self):
        result = run_protocol_validation(
            ROOT,
            INDEX_PATH,
            budget=30,
            limit=1,
        )

        self.assertTrue(result["protocol_valid"])
        self.assertFalse(result["research_effectiveness_result"])
        self.assertEqual(0, result["backend_mismatch_count"])
        self.assertEqual(0, result["policy_leakage_failure_count"])
        self.assertIn(
            "decision_by_source_condition",
            result["descriptive_diagnostics"],
        )


if __name__ == "__main__":
    unittest.main()
