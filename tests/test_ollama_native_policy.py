import json
import unittest
from unittest.mock import patch

from src.agent.ec_react import (
    OllamaNativeReActPolicy,
    _compact_tool_output,
)


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class OllamaNativePolicyTests(unittest.TestCase):
    def test_policy_projection_preserves_provider_scope_semantics(self):
        compact = _compact_tool_output({
            "receipt": {
                "tool_name": "search_events",
                "call_id": 1,
                "cost": 1,
                "result_count": 1,
            },
            "tool_result": {
                "events": [{
                    "observation_id": "obs-rds",
                    "operation": "ModifyDBInstance",
                    "provider_decision": "allow",
                    "oracle_kind": "AWS CloudTrail control-plane outcome",
                    "scope_completeness": (
                        "incomplete_for_database_data_plane"
                    ),
                }],
            },
            "remaining_budget": 3,
        })

        event = compact["events"][0]
        self.assertEqual(
            "incomplete_for_database_data_plane",
            event["scope_completeness"],
        )
        self.assertEqual(
            "AWS CloudTrail control-plane outcome",
            event["oracle_kind"],
        )

    @patch("src.agent.ec_react.urllib.request.urlopen")
    def test_native_policy_disables_thinking_and_requires_json(self, mocked):
        mocked.return_value = _FakeResponse({
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "kind": "finish",
                    "thought": "done",
                    "decision": "search_complete",
                    "hypothesis": "test",
                }),
            }
        })
        policy = OllamaNativeReActPolicy(
            "local-model",
            base_url="http://127.0.0.1:11434",
            seed=1729,
        )

        proposal = policy.propose({
            "task_mode": "path_discovery",
            "observed_evidence_ids": [],
            "finish_contract": {},
        })

        self.assertEqual("finish", proposal["kind"])
        request = mocked.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertIs(False, payload["think"])
        self.assertEqual("object", payload["format"]["type"])
        self.assertEqual(
            ["kind", "thought"], payload["format"]["required"]
        )
        self.assertIs(False, payload["stream"])
        self.assertEqual(1729, payload["options"]["seed"])

    @patch("src.agent.ec_react.urllib.request.urlopen")
    def test_native_policy_hides_tools_when_frontier_is_empty(self, mocked):
        mocked.return_value = _FakeResponse({
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "kind": "finish",
                    "thought": "done",
                    "decision": "search_complete",
                    "hypothesis": "test",
                }),
            }
        })
        policy = OllamaNativeReActPolicy("local-model")
        policy.propose({
            "task_mode": "path_discovery",
            "observed_evidence_ids": ["obs-1"],
            "pareto_actions": [],
            "tool_contracts": [{"name": "search_events"}],
            "finish_contract": {},
        })
        request = mocked.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        model_view = json.loads(payload["messages"][1]["content"])
        self.assertEqual([], model_view["tool_contracts"])
        self.assertEqual(
            ["submit_path", "finish"],
            model_view["allowed_next_kinds"],
        )
        self.assertEqual(
            ["submit_path", "finish"],
            payload["format"]["properties"]["kind"]["enum"],
        )

    @patch("src.agent.ec_react.urllib.request.urlopen")
    def test_native_policy_constrains_tool_arguments_to_frontier(
        self, mocked
    ):
        mocked.return_value = _FakeResponse({
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "kind": "tool",
                    "thought": "search",
                    "tool_name": "search_events",
                    "arguments": {"operation": "CopyObject"},
                }),
            }
        })
        policy = OllamaNativeReActPolicy("local-model")
        policy.propose({
            "task_mode": "path_discovery",
            "observed_evidence_ids": [],
            "pareto_actions": [{
                "tool_name": "search_events",
                "arguments": {"operation": "CopyObject"},
            }],
            "tool_contracts": [{"name": "search_events"}],
            "finish_contract": {},
        })
        request = mocked.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        properties = payload["format"]["properties"]
        self.assertEqual(
            ["search_events"], properties["tool_name"]["enum"]
        )
        argument_variant = properties["arguments"]["anyOf"][0]
        self.assertFalse(argument_variant["additionalProperties"])
        self.assertEqual(
            "CopyObject",
            argument_variant["properties"]["operation"]["const"],
        )

    @patch("src.agent.ec_react.urllib.request.urlopen")
    def test_external_rule_prior_constrains_provider_evidence_polarity(
        self, mocked
    ):
        mocked.return_value = _FakeResponse({
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "kind": "finish",
                    "thought": "done",
                    "decision": "search_complete",
                    "hypothesis": "test",
                }),
            }
        })
        policy = OllamaNativeReActPolicy("local-model")
        policy.propose({
            "task_mode": "path_discovery",
            "method_components": {"external_rule_prior": True},
            "observed_evidence_ids": ["obs-deny", "obs-control"],
            "pareto_actions": [],
            "tool_contracts": [],
            "finish_contract": {},
            "history": [{
                "observation": {
                    "events": [
                        {
                            "observation_id": "obs-deny",
                            "provider_decision": "deny",
                        },
                        {
                            "observation_id": "obs-control",
                            "provider_decision": "allow_control_later_state",
                        },
                    ]
                }
            }],
        })

        request = mocked.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        candidate = payload["format"]["properties"]["path_candidate"]
        properties = candidate["properties"]
        self.assertEqual(
            ["NotReachable"],
            properties["claimed_state"]["enum"],
        )
        evidence_variant = properties["evidence_assignments"]["items"][
            "anyOf"
        ][0]
        evidence = evidence_variant["properties"]
        self.assertEqual(
            "obs-deny",
            evidence["observation_id"]["const"],
        )
        self.assertEqual("refute", evidence["polarity"]["const"])
        test_variants = evidence["test"]["anyOf"]
        provider_test = next(
            item for item in test_variants
            if item["properties"]["field"]["const"]
            == "provider_decision"
        )
        self.assertEqual(
            "deny",
            provider_test["properties"]["value"]["const"],
        )

    @patch("src.agent.ec_react.urllib.request.urlopen")
    def test_control_only_provider_evidence_forces_unknown_finish(
        self, mocked
    ):
        mocked.return_value = _FakeResponse({
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "kind": "finish",
                    "thought": "runtime evidence is absent",
                    "decision": "no_verified_path",
                    "hypothesis": "configuration is not runtime proof",
                }),
            }
        })
        policy = OllamaNativeReActPolicy("local-model")
        policy.propose({
            "task_mode": "path_discovery",
            "method_components": {"external_rule_prior": True},
            "observed_evidence_ids": ["obs-config"],
            "pareto_actions": [],
            "tool_contracts": [],
            "finish_contract": {},
            "history": [{
                "observation": {
                    "events": [{
                        "observation_id": "obs-config",
                        "provider_decision": "not_run",
                    }]
                }
            }],
        })

        request = mocked.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(
            ["finish"],
            payload["format"]["properties"]["kind"]["enum"],
        )
        self.assertEqual(
            ["no_verified_path", "abstain"],
            payload["format"]["properties"]["decision"]["enum"],
        )
        self.assertEqual(
            ["kind", "thought", "decision", "hypothesis"],
            payload["format"]["required"],
        )
        model_view = json.loads(payload["messages"][1]["content"])
        self.assertEqual(["finish"], model_view["allowed_next_kinds"])
        self.assertIn("Unknown", model_view["provider_evidence_state"])

    @patch("src.agent.ec_react.urllib.request.urlopen")
    def test_incomplete_provider_allow_forces_unknown_finish(self, mocked):
        mocked.return_value = _FakeResponse({
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "kind": "finish",
                    "thought": "control plane is not data plane",
                    "decision": "no_verified_path",
                    "hypothesis": "database records remain unverified",
                }),
            }
        })
        policy = OllamaNativeReActPolicy("local-model")
        policy.propose({
            "task_mode": "path_discovery",
            "method_components": {"external_rule_prior": True},
            "observed_evidence_ids": ["obs-rds"],
            "pareto_actions": [],
            "tool_contracts": [],
            "finish_contract": {},
            "history": [{
                "observation": {
                    "events": [{
                        "observation_id": "obs-rds",
                        "provider_decision": "allow",
                        "scope_completeness": (
                            "incomplete_for_database_data_plane"
                        ),
                    }]
                }
            }],
        })

        request = mocked.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(
            ["finish"],
            payload["format"]["properties"]["kind"]["enum"],
        )
        self.assertEqual(
            ["no_verified_path", "abstain"],
            payload["format"]["properties"]["decision"]["enum"],
        )
        self.assertFalse(payload["format"]["additionalProperties"])
        self.assertEqual(
            1,
            payload["format"]["properties"]["hypothesis"]["minLength"],
        )
        self.assertNotIn(
            "path_candidate", payload["format"]["properties"]
        )
        self.assertNotIn("tool_name", payload["format"]["properties"])
        self.assertNotIn("arguments", payload["format"]["properties"])
        model_view = json.loads(payload["messages"][1]["content"])
        self.assertIn("Unknown", model_view["provider_evidence_state"])


if __name__ == "__main__":
    unittest.main()
