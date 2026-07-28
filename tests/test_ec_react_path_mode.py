import json
import unittest
from pathlib import Path

from src.agent.cross_cloud_environment import CrossCloudTelemetryEnvironment
from src.agent.ec_react import ECReactRunner
from src.agent.ec_react_langgraph import ECReactLangGraphRunner


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


class OneEdgePathPolicy:
    def __init__(self, hallucinate=False):
        self.hallucinate = hallucinate

    def propose(self, view):
        executed = [
            item for item in view["history"]
            if item["status"] == "tool_executed"
        ]
        if not executed:
            return {
                "kind": "tool",
                "thought": "Reveal operation facets.",
                "tool_name": "summarize_case",
                "arguments": {},
            }
        if len(executed) == 1:
            action = view["pareto_actions"][0]
            return {
                "kind": "tool",
                "thought": "Inspect a budget-efficient operation.",
                "tool_name": action["tool_name"],
                "arguments": action["arguments"],
            }
        citation = view["visible_evidence_ledger"][0]
        visible_event = executed[-1]["observation"]["events"][0]
        if self.hallucinate:
            citation = {**citation, "observation_id": "obs-never-visible"}
        return {
            "kind": "finish",
            "thought": "Propose one evidence-grounded transition.",
            "decision": "path_found",
            "hypothesis": "The visible operation supports a candidate transition.",
            "path_candidate": {
                "path_id": "proposed-path-1",
                "nodes": [
                    {
                        "node_id": "n1",
                        "type": "identity",
                        "label": "observed cloud identity",
                    },
                    {
                        "node_id": "n2",
                        "type": "resource",
                        "label": "observed cloud resource",
                    },
                ],
                "edges": [
                    {
                        "edge_id": "e1",
                        "source": "n1",
                        "target": "n2",
                        "type": "observed_operation",
                    }
                ],
                "evidence_assignments": [
                    {
                        "observation_id": citation["observation_id"],
                        "call_id": citation["call_id"],
                        "polarity": "support",
                        "edge_ids": ["e1"],
                        "test": {
                            "field": "operation",
                            "operator": "eq",
                            "value": visible_event["operation"],
                        },
                    }
                ],
            },
        }


class EmptyHypothesisUnknownPolicy:
    def propose(self, view):
        return {
            "kind": "finish",
            "thought": "Visible evidence does not establish a verified path.",
            "decision": "no_verified_path",
            "hypothesis": "",
        }


class ProgressiveTwoPathPolicy:
    def __init__(self):
        self.memory_sizes = []

    def propose(self, view):
        executed = [
            item for item in view["history"]
            if item["status"] == "tool_executed"
        ]
        if not executed:
            return {
                "kind": "tool",
                "thought": "Reveal operation facets.",
                "tool_name": "summarize_case",
                "arguments": {},
            }
        if len(executed) == 1:
            action = view["pareto_actions"][0]
            return {
                "kind": "tool",
                "thought": "Inspect a Pareto-efficient operation.",
                "tool_name": action["tool_name"],
                "arguments": action["arguments"],
            }
        submitted = view["submitted_path_candidates"]
        self.memory_sizes.append(len(view["four_value_claim_memory"]))
        if submitted < 2:
            citation = view["visible_evidence_ledger"][0]
            event = executed[-1]["observation"]["events"][0]
            return {
                "kind": "submit_path",
                "thought": f"Submit ranked path candidate {submitted + 1}.",
                "hypothesis": "A visible operation grounds this transition.",
                "path_candidate": {
                    "path_id": f"ranked-path-{submitted + 1}",
                    "nodes": [
                        {
                            "node_id": "n1",
                            "type": "identity",
                            "label": "cloud identity",
                        },
                        {
                            "node_id": "n2",
                            "type": "resource",
                            "label": "cloud resource",
                        },
                    ],
                    "edges": [
                        {
                            "edge_id": "e1",
                            "source": "n1",
                            "target": "n2",
                            "type": (
                                "observed_operation"
                                if submitted == 0
                                else "access_data"
                            ),
                        }
                    ],
                    "evidence_assignments": [
                        {
                            "observation_id": citation["observation_id"],
                            "call_id": citation["call_id"],
                            "polarity": "support",
                            "edge_ids": ["e1"],
                            "test": {
                                "field": "operation",
                                "operator": "eq",
                                "value": event["operation"],
                            },
                        }
                    ],
                },
            }
        return {
            "kind": "finish",
            "thought": "The ranked candidate set is complete.",
            "decision": "search_complete",
            "hypothesis": "Two evidence-grounded alternatives were submitted.",
        }


class UnknownFinishWithoutHypothesisPolicy:
    def propose(self, view):
        return {
            "kind": "finish",
            "thought": "No runtime evidence supports a decisive path.",
            "decision": "no_verified_path",
        }


class ECReactPathModeTests(unittest.TestCase):
    def _environment(self):
        return CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            _episode_id(),
            budget=40,
        )

    def test_strict_path_finish_requires_and_returns_cp_cert(self):
        environment = self._environment()
        result = ECReactRunner(
            OneEdgePathPolicy(),
            task_mode="path_discovery",
        ).run(environment, environment.public_context)

        self.assertEqual("evidence_certified_paths", result.decision)
        self.assertEqual("Valid", result.path_verdict["state"])
        self.assertTrue(result.certificate["sufficient"])
        self.assertTrue(result.certificate_audit["raw_refs_complete"])
        self.assertIn("human gold", result.certificate_scope)
        self.assertEqual([], result.verification_errors)
        self.assertEqual(1, len(result.path_candidates))

    def test_nonpositive_finish_normalizes_missing_hypothesis_auditably(self):
        environment = self._environment()
        result = ECReactRunner(
            UnknownFinishWithoutHypothesisPolicy(),
            task_mode="path_discovery",
        ).run(environment, environment.public_context)

        self.assertEqual("no_verified_path", result.decision)
        self.assertEqual(0, result.invalid_actions)
        self.assertEqual(
            ["hypothesis_from_thought"],
            result.trace[0]["proposal"]["protocol_normalizations"],
        )

    def test_record_guard_preserves_unverified_baseline_false_positive(self):
        environment = self._environment()
        result = ECReactRunner(
            OneEdgePathPolicy(hallucinate=True),
            task_mode="path_discovery",
            finish_guard_mode="record",
        ).run(environment, environment.public_context)

        self.assertEqual("unverified_paths_proposed", result.decision)
        self.assertIsNone(result.certificate)
        self.assertTrue(result.verification_errors)
        self.assertEqual(
            "obs-never-visible",
            result.path_candidates[0]["path_candidate"][
                "evidence_assignments"
            ][0]["observation_id"],
        )

    def test_strict_guard_rejects_same_false_positive_and_abstains(self):
        environment = self._environment()
        result = ECReactRunner(
            OneEdgePathPolicy(hallucinate=True),
            task_mode="path_discovery",
            finish_guard_mode="strict",
            max_invalid_actions=1,
        ).run(environment, environment.public_context)

        self.assertEqual("abstain", result.decision)
        self.assertEqual("invalid_action_limit", result.stop_reason)
        self.assertEqual(1, len(result.path_candidates))
        self.assertIn("path verification failed", result.trace[-1]["error"])

    def test_langgraph_and_linear_path_verification_are_semantically_identical(self):
        results = []
        for runner_class in (ECReactRunner, ECReactLangGraphRunner):
            environment = self._environment()
            result = runner_class(
                OneEdgePathPolicy(),
                task_mode="path_discovery",
            ).run(environment, environment.public_context)
            results.append(result)

        self.assertEqual(results[0].decision, results[1].decision)
        self.assertEqual(results[0].path_verdict, results[1].path_verdict)
        self.assertEqual(results[0].certificate, results[1].certificate)
        self.assertEqual(
            results[0].certificate_audit,
            results[1].certificate_audit,
        )
        self.assertEqual(results[0].spent, results[1].spent)

    def test_empty_unknown_hypothesis_normalization_matches_backends(self):
        results = []
        for runner_class in (ECReactRunner, ECReactLangGraphRunner):
            environment = self._environment()
            result = runner_class(
                EmptyHypothesisUnknownPolicy(),
                task_mode="path_discovery",
            ).run(environment, environment.public_context)
            results.append(result)

        for result in results:
            self.assertEqual("no_verified_path", result.decision)
            self.assertEqual(0, result.invalid_actions)
            self.assertEqual(
                "Visible evidence does not establish a verified path.",
                result.hypothesis,
            )
            self.assertIn(
                "hypothesis_from_thought",
                result.trace[-1]["proposal"]["protocol_normalizations"],
            )

    def test_progressive_top_k_submission_and_four_value_memory_match_backends(self):
        results = []
        policies = []
        for runner_class in (ECReactRunner, ECReactLangGraphRunner):
            environment = self._environment()
            policy = ProgressiveTwoPathPolicy()
            result = runner_class(
                policy,
                task_mode="path_discovery",
                max_path_candidates=5,
            ).run(environment, environment.public_context)
            results.append(result)
            policies.append(policy)

        for result, policy in zip(results, policies):
            self.assertEqual("evidence_certified_paths", result.decision)
            self.assertEqual(2, len(result.path_candidates))
            self.assertEqual(2, len(result.verified_path_candidates))
            self.assertEqual(
                2,
                sum(
                    item["status"] == "path_candidate_accepted"
                    for item in result.trace
                ),
            )
            self.assertIn(1, policy.memory_sizes)
        self.assertEqual(results[0].decision, results[1].decision)
        self.assertEqual(
            results[0].verified_path_candidates,
            results[1].verified_path_candidates,
        )

    def test_four_value_memory_ablation_removes_feedback_not_path_schema(self):
        environment = self._environment()
        policy = ProgressiveTwoPathPolicy()
        result = ECReactRunner(
            policy,
            task_mode="path_discovery",
            four_value_memory=False,
        ).run(environment, environment.public_context)

        self.assertEqual(2, len(result.path_candidates))
        self.assertTrue(policy.memory_sizes)
        self.assertEqual({0}, set(policy.memory_sizes))


if __name__ == "__main__":
    unittest.main()
