import unittest
from pathlib import Path

from src.experiments.pareto_action_space_audit import (
    audit_pareto_action_space,
)


ROOT = Path(__file__).resolve().parents[1]
INDEX = (
    ROOT / "data" / "real_sources" / "cross_cloud_full_episode_index.json"
)


class ParetoActionSpaceAuditTests(unittest.TestCase):
    def test_real_episode_audit_is_cross_tool_and_non_effectiveness(self):
        result = audit_pareto_action_space(
            ROOT,
            INDEX,
            limit=2,
        )

        self.assertEqual(2, result["episodes"])
        self.assertFalse(result["research_effectiveness_result"])
        self.assertFalse(result["probe_failures"])
        coverage = result["external_prior_coverage"]
        self.assertEqual(
            "sigma_cloud_operation_prior_v1",
            coverage["prior_id"],
        )
        self.assertGreater(
            coverage["unique_platform_operations"],
            0,
        )
        self.assertLessEqual(coverage["unique_coverage_rate"], 1.0)
        detail = result["stages"]["after_detail"]
        self.assertEqual(2, detail["episodes_reaching_stage"])
        self.assertIn(
            "get_event_detail",
            detail["full_action_tool_counts"],
        )
        self.assertGreater(
            detail["mean_full_count"],
            detail["mean_frontier_count"],
        )


if __name__ == "__main__":
    unittest.main()
