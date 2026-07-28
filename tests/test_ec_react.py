import json
import unittest
from pathlib import Path

from src.agent.cross_cloud_environment import CrossCloudTelemetryEnvironment
from src.agent.ec_react import (
    ActionCandidate,
    ECReactRunner,
    ProgressiveTelemetryPolicy,
    _dominates,
    pareto_action_candidates,
)
from src.agent.ec_react_langgraph import ECReactLangGraphRunner
from src.agent.published_telemetry_environment import ToolActionError


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "data" / "real_sources" / "cross_cloud_pilot_episode_index.json"


def _episode_id() -> str:
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


class AlwaysInvalidPolicy:
    def propose(self, view):
        return {
            "kind": "tool",
            "thought": "Try to escape the current case.",
            "tool_name": "search_events",
            "arguments": {"candidate_id": "hidden"},
        }


class ExplodingPolicy:
    def propose(self, view):
        raise RuntimeError("temporary provider failure")


class ECReactTests(unittest.TestCase):
    def test_pareto_filter_removes_dominated_action(self):
        strong = ActionCandidate(
            "search_events",
            {"operation": "GetSecretValue"},
            external_rule_gain=5,
            coverage_gain=10,
            estimated_cost=3,
        )
        weak = ActionCandidate(
            "search_events",
            {"operation": "ListThings"},
            external_rule_gain=0,
            coverage_gain=5,
            estimated_cost=4,
        )
        self.assertTrue(_dominates(strong, weak))

        frontier = pareto_action_candidates(
            {"DeleteBucket": 10, "ListThings": 10},
            platform="AWS",
        )
        self.assertEqual(
            ["DeleteBucket"],
            [item.arguments["operation"] for item in frontier],
        )

    def test_pareto_ablation_exposes_complete_feasible_action_space(self):
        frontier = pareto_action_candidates(
            {"DeleteBucket": 10, "ListThings": 10},
            platform="AWS",
            apply_pareto=True,
        )
        unfiltered = pareto_action_candidates(
            {"DeleteBucket": 10, "ListThings": 10},
            platform="AWS",
            apply_pareto=False,
        )

        self.assertEqual(1, len(frontier))
        self.assertEqual(2, len(unfiltered))

    def test_external_rule_prior_has_an_independent_ablation(self):
        grounded = pareto_action_candidates(
            {"DeleteBucket": 10, "ListThings": 10},
            platform="AWS",
            use_external_rule_prior=True,
        )
        ablated = pareto_action_candidates(
            {"DeleteBucket": 10, "ListThings": 10},
            platform="AWS",
            use_external_rule_prior=False,
        )

        self.assertEqual(
            ["DeleteBucket"],
            [item.arguments["operation"] for item in grounded],
        )
        self.assertEqual(2, len(ablated))
        self.assertEqual(
            {0},
            {item.external_rule_gain for item in ablated},
        )

    def test_visible_evidence_generates_cross_tool_action_candidates(self):
        visible_events = {
            "obs-1": {
                "observation_id": "obs-1",
                "operation": "ListDatabases",
                "service": "rds",
                "actor_id": "principal-1",
                "event_status": "access_denied",
                "request": {
                    "resource": "arn:aws:rds:us-east-1:123456789012:db:prod"
                },
            }
        }
        candidates = pareto_action_candidates(
            {"ListDatabases": 3},
            service_counts={"rds": 3},
            visible_events=visible_events,
            observation_count=10,
            apply_pareto=False,
        )
        actions = {
            (item.tool_name, next(iter(item.arguments), None))
            for item in candidates
        }

        self.assertIn(("search_events", "operation"), actions)
        self.assertIn(("search_events", "service"), actions)
        self.assertIn(("search_events", "event_status"), actions)
        self.assertIn(("get_event_detail", "observation_id"), actions)
        self.assertIn(("actor_timeline", "actor_id"), actions)
        self.assertIn(("resource_search", "term"), actions)

    def test_pareto_guard_rejects_dominated_cross_tool_service_search(self):
        runner = ECReactRunner(ProgressiveTelemetryPolicy())
        operation_counts = {"DeleteBucket": 10}
        service_counts = {"inventory": 10}
        candidates = pareto_action_candidates(
            operation_counts,
            service_counts=service_counts,
            platform="AWS",
        )

        with self.assertRaisesRegex(ToolActionError, "Pareto frontier"):
            runner._guard_tool_action(
                "search_events",
                {"service": "inventory"},
                candidates,
                operation_counts,
                service_counts,
                {},
                10,
                40,
            )

    def test_unknown_result_actions_use_conservative_budget_upper_bound(self):
        visible_events = {
            "obs-1": {
                "observation_id": "obs-1",
                "operation": "ListDatabases",
                "service": "rds",
                "actor_id": "principal-1",
                "event_status": "access_denied",
                "request": {"resource": "database-production-primary"},
            }
        }
        candidates = pareto_action_candidates(
            {"ListDatabases": 1},
            service_counts={"rds": 1},
            visible_events=visible_events,
            observation_count=20,
            remaining_budget=3,
            apply_pareto=False,
        )
        tools = {item.tool_name for item in candidates}
        status_searches = [
            item
            for item in candidates
            if item.arguments.get("event_status") == "access_denied"
        ]

        self.assertIn("get_event_detail", tools)
        self.assertNotIn("actor_timeline", tools)
        self.assertNotIn("resource_search", tools)
        self.assertFalse(status_searches)

    def test_offline_policy_runs_guarded_progressive_tool_loop(self):
        environment = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=40,
        )

        result = ECReactRunner(ProgressiveTelemetryPolicy()).run(
            environment,
            environment.public_context,
        )
        visible_trace = json.dumps(result.trace, ensure_ascii=False)

        self.assertEqual("candidate_evidence_found", result.decision)
        self.assertEqual(3, result.valid_tool_calls)
        self.assertEqual(0, result.invalid_actions)
        self.assertGreater(result.spent, 0)
        self.assertEqual(1, len(result.evidence_observation_ids))
        self.assertTrue(result.evidence_raw_refs)
        self.assertNotIn("automated_exfiltration", visible_trace)
        self.assertNotIn("payload_present", visible_trace)
        detail_event = next(
            item["observation"]["events"][0]
            for item in result.trace
            if item["status"] == "tool_executed"
            and item["observation"]["tool"] == "get_event_detail"
        )
        self.assertIn("schema", detail_event)
        self.assertIn("request", detail_event)

    def test_invalid_actions_are_rejected_without_spending_budget(self):
        environment = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=10,
        )

        result = ECReactRunner(
            AlwaysInvalidPolicy(),
            max_invalid_actions=2,
        ).run(environment, environment.public_context)

        self.assertEqual("abstain", result.decision)
        self.assertEqual("invalid_action_limit", result.stop_reason)
        self.assertEqual(2, result.invalid_actions)
        self.assertEqual(0, result.valid_tool_calls)
        self.assertEqual(0, result.spent)

    def test_langgraph_backend_matches_framework_independent_runner(self):
        linear_environment = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=40,
        )
        graph_environment = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=40,
        )

        linear = ECReactRunner(ProgressiveTelemetryPolicy()).run(
            linear_environment,
            linear_environment.public_context,
        )
        graph = ECReactLangGraphRunner(
            ProgressiveTelemetryPolicy()
        ).run(
            graph_environment,
            graph_environment.public_context,
        )

        self.assertEqual(linear.decision, graph.decision)
        self.assertEqual(linear.stop_reason, graph.stop_reason)
        self.assertEqual(linear.valid_tool_calls, graph.valid_tool_calls)
        self.assertEqual(linear.invalid_actions, graph.invalid_actions)
        self.assertEqual(linear.spent, graph.spent)
        self.assertEqual(
            [
                (
                    item["status"],
                    item["proposal"].get("tool_name"),
                )
                for item in linear.trace
            ],
            [
                (
                    item["status"],
                    item["proposal"].get("tool_name"),
                )
                for item in graph.trace
            ],
        )

    def test_policy_failures_are_guarded_consistently_by_both_backends(self):
        results = []
        for runner_class in (ECReactRunner, ECReactLangGraphRunner):
            environment = CrossCloudTelemetryEnvironment.from_file(
                ROOT,
                INDEX_PATH,
                _episode_id(),
                budget=10,
            )
            result = runner_class(
                ExplodingPolicy(),
                max_invalid_actions=2,
            ).run(environment, environment.public_context)
            results.append(result)

        for result in results:
            self.assertEqual("abstain", result.decision)
            self.assertEqual("invalid_action_limit", result.stop_reason)
            self.assertEqual(2, result.invalid_actions)
            self.assertEqual(0, result.spent)
        self.assertEqual(
            [item["error"] for item in results[0].trace],
            [item["error"] for item in results[1].trace],
        )


if __name__ == "__main__":
    unittest.main()
