import json
from pathlib import Path
import unittest

from src.agent.cross_cloud_environment import CrossCloudTelemetryEnvironment
from src.agent.ec_react import ECReactRunner, pareto_action_candidates


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


class DominatedSearchPolicy:
    def propose(self, view):
        if not view["history"]:
            return {
                "kind": "tool",
                "thought": "Reveal operations.",
                "tool_name": "summarize_case",
                "arguments": {},
            }
        operation_counts = (
            view["history"][0]["observation"]["operation_counts"]
        )
        service_counts = (
            view["history"][0]["observation"]["service_counts"]
        )
        frontier = {
            item["arguments"]["operation"]
            for item in (
                {
                    "arguments": candidate.arguments,
                }
                for candidate in pareto_action_candidates(
                    operation_counts,
                    service_counts=service_counts,
                    platform=view["public_context"].get("platform"),
                    apply_pareto=True,
                )
            )
            if "operation" in item["arguments"]
        }
        dominated = sorted(set(operation_counts) - frontier)
        if dominated:
            return {
                "kind": "tool",
                "thought": "Deliberately choose a dominated search.",
                "tool_name": "search_events",
                "arguments": {"operation": dominated[0]},
            }
        return {
            "kind": "finish",
            "thought": "No dominated operation is available.",
            "decision": "abstain",
            "hypothesis": "No test action.",
            "evidence_observation_ids": [],
        }


class BudgetAwareViewPolicy:
    def propose(self, view):
        if not view["history"]:
            return {
                "kind": "tool",
                "thought": "Reveal operations.",
                "tool_name": "summarize_case",
                "arguments": {},
            }
        if view["pareto_actions"]:
            action = view["pareto_actions"][0]
            return {
                "kind": "tool",
                "thought": "Use the available candidate action.",
                "tool_name": action["tool_name"],
                "arguments": action["arguments"],
            }
        return {
            "kind": "finish",
            "thought": "Stop because no action fits the remaining budget.",
            "decision": "abstain",
            "hypothesis": "No budget-feasible search remains.",
            "evidence_observation_ids": [],
        }


class ECReactComponentTests(unittest.TestCase):
    def _environment(self, budget):
        return CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=budget,
        )

    def test_pareto_ablation_changes_whether_dominated_action_is_admitted(self):
        guarded_environment = self._environment(40)
        guarded = ECReactRunner(
            DominatedSearchPolicy(),
            pareto_guard=True,
            max_invalid_actions=1,
        ).run(guarded_environment, guarded_environment.public_context)
        ablated_environment = self._environment(40)
        ablated = ECReactRunner(
            DominatedSearchPolicy(),
            pareto_guard=False,
            max_steps=2,
        ).run(ablated_environment, ablated_environment.public_context)

        self.assertEqual(1, guarded.valid_tool_calls)
        self.assertEqual(1, guarded.invalid_actions)
        self.assertIn("Pareto frontier", guarded.trace[-1]["error"])
        self.assertEqual(2, ablated.valid_tool_calls)
        self.assertEqual(0, ablated.invalid_actions)

    def test_budget_stop_hides_actions_that_cannot_fit_hard_budget(self):
        guarded_environment = self._environment(2)
        guarded = ECReactRunner(
            BudgetAwareViewPolicy(),
            budget_stop=True,
        ).run(guarded_environment, guarded_environment.public_context)
        ablated_environment = self._environment(2)
        ablated = ECReactRunner(
            BudgetAwareViewPolicy(),
            budget_stop=False,
            max_invalid_actions=1,
        ).run(ablated_environment, ablated_environment.public_context)

        self.assertEqual(0, guarded.invalid_actions)
        self.assertEqual(1, ablated.invalid_actions)
        self.assertEqual(1, guarded.spent)
        self.assertEqual(1, ablated.spent)
        self.assertIn("ToolBudgetError", ablated.trace[-1]["error"])


if __name__ == "__main__":
    unittest.main()
