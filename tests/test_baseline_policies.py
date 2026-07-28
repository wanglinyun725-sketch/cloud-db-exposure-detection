import json
from pathlib import Path
import unittest

from src.agent.baseline_policies import (
    FixedOrderPathPolicy,
    FullQueryPathPolicy,
    RandomToolPathPolicy,
)
from src.agent.cross_cloud_environment import CrossCloudTelemetryEnvironment
from src.agent.ec_react import ECReactRunner


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "data" / "real_sources" / "cross_cloud_pilot_episode_index.json"


def _episode_id():
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return next(
        item["episode_id"]
        for item in index["episodes"]
        if item["platform"] == "AWS"
        and item["attack"] == "automated_exfiltration"
        and item["log_profile"] == "additional"
        and item["run_id"] == 0
        and item["source_condition"] == "payload_present"
    )


class BaselinePolicyTests(unittest.TestCase):
    def _run(self, policy):
        environment = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=40,
        )
        return ECReactRunner(
            policy,
            task_mode="path_discovery",
            finish_guard_mode="record",
            pareto_guard=False,
            four_value_memory=False,
            budget_stop=False,
            max_steps=12,
            max_path_candidates=5,
        ).run(environment, environment.public_context)

    def test_fixed_and_seeded_random_baselines_emit_same_path_schema(self):
        fixed = self._run(FixedOrderPathPolicy())
        random_a = self._run(RandomToolPathPolicy(seed=1729))
        random_b = self._run(RandomToolPathPolicy(seed=1729))

        self.assertTrue(fixed.path_candidates)
        self.assertTrue(random_a.path_candidates)
        self.assertEqual(
            random_a.path_candidates,
            random_b.path_candidates,
        )
        for result in (fixed, random_a):
            self.assertTrue(all(
                item.get("normalized_path", {}).get("evidence_assignments")
                for item in result.path_candidates
            ))

    def test_full_query_can_only_cite_rows_rendered_to_policy(self):
        result = self._run(FullQueryPathPolicy())

        self.assertTrue(result.path_candidates)
        cited = {
            assignment["observation_id"]
            for report in result.path_candidates
            for assignment in report["normalized_path"][
                "evidence_assignments"
            ]
        }
        full_query = next(
            item for item in result.trace
            if item["status"] == "tool_executed"
            and item["proposal"].get("tool_name") == "search_events"
            and item["proposal"].get("arguments") == {}
        )
        visible = {
            item["observation_id"]
            for item in full_query["observation"]["events"]
        }
        self.assertTrue(cited.issubset(visible))


if __name__ == "__main__":
    unittest.main()
