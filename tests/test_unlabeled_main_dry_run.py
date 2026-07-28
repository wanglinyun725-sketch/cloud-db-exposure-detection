import json
from pathlib import Path
import unittest

import yaml

from src.experiments.unlabeled_main_dry_run import (
    build_unlabeled_dry_run_schedule,
    run_unlabeled_main_dry_run,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)


class UnlabeledMainDryRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        cls.packet = json.loads(PACKET.read_text(encoding="utf-8"))

    def test_schedule_covers_exact_frozen_non_llm_matrix(self):
        schedule = build_unlabeled_dry_run_schedule(
            self.config, self.packet
        )
        self.assertEqual(1911, len(schedule))
        self.assertEqual(
            {"fixed_order", "random_tool", "full_query"},
            {row["method_id"] for row in schedule},
        )
        self.assertEqual(
            {10, 20, 30},
            {row["budget"] for row in schedule},
        )
        self.assertEqual(
            91,
            len({row["instance_id"] for row in schedule}),
        )
        self.assertEqual(
            len(schedule),
            len({row["dry_run_id"] for row in schedule}),
        )

    def test_dry_run_has_no_effectiveness_claim_or_gold_score(self):
        result = run_unlabeled_main_dry_run(
            ROOT, CONFIG, PACKET, limit=2
        )
        self.assertTrue(result["dry_run_valid"])
        self.assertFalse(result["research_effectiveness_result"])
        self.assertEqual(2, result["completed_runs"])
        self.assertEqual(0, result["backend_mismatch_count"])
        self.assertEqual(0, result["hard_budget_violation_count"])
        self.assertTrue(all(
            "score" not in row for row in result["rows"]
        ))


if __name__ == "__main__":
    unittest.main()
