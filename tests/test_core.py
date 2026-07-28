import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch

import src.agent.agent_graph as agent_graph
from src.agent.active_investigator import investigate, truth_has_valid_path
from src.agent.evidence_environment import PartialEvidenceEnvironment
from src.graph.graph_builder import load_samples
from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes
from src.graph.constrained_search import constrained_dfs
from src.graph.gate_score import load_config, verify_path
from src.graph.path_utils import EvidencePath, edge_aware_path_key, path_from_label
from src.eval.metrics import path_recall_at_k
from scripts.build_sddp_evidence_slice import build_slice
from web_app import app


def _edge_attrs(status="Supported"):
    return {
        "status": status,
        "strength": 1.0,
        "confidence": 1.0,
        "time": "2026-01-01T00:00:00Z",
    }


class CoreSmokeTests(unittest.TestCase):
    def test_utf8_config_and_samples_load_on_windows(self):
        config = load_config()
        samples = load_samples("data/pathbench_60.json")

        self.assertIn("gate_thresholds", config)
        self.assertEqual(60, len(samples))

    def test_langgraph_processes_every_candidate_path(self):
        sample = next(
            item
            for item in load_samples("data/pathbench_60.json")
            if item["sample_id"] == "S1_finance_008"
        )
        config = load_config()

        with (
            patch.object(agent_graph, "get_llm_client", return_value=None),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            linear_results = agent_graph.run_linear(sample, config)
            graph_results = agent_graph.run_graph(sample, config)

        signature = lambda results: [
            (
                tuple(item["path"]),
                item["gate_result"]["path_type"],
                item["gate_result"]["score"],
            )
            for item in results
        ]
        self.assertEqual(signature(linear_results), signature(graph_results))
        self.assertEqual(2, len(graph_results))

    def test_empty_candidate_set_returns_no_results(self):
        sample = {
            "sample_id": "empty",
            "scenario": "empty",
            "industry": "test",
            "nodes": [],
            "edges": [],
            "gold_paths": [],
            "expected_type": "Insufficient_Evidence",
        }

        with (
            patch.object(agent_graph, "get_llm_client", return_value=None),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            results = agent_graph.run_graph(sample, load_config())

        self.assertEqual([], results)

    def test_web_dashboard_smoke(self):
        response = app.test_client().get("/")

        self.assertEqual(200, response.status_code)
        self.assertIn("text/html", response.content_type)
        self.assertGreater(len(response.data), 1000)

    def test_parallel_edges_keep_the_explored_edge_identity(self):
        sample = {
            "sample_id": "parallel",
            "scenario": "parallel",
            "nodes": [
                {"id": "internet", "type": "Network", "attrs": {"public_exposed": True}},
                {"id": "role", "type": "Identity", "attrs": {}},
                {"id": "table", "type": "DBObject", "attrs": {"kind": "table"}},
                {"id": "tag", "type": "SensitiveTag", "attrs": {"level": 4, "confidence": 1.0}},
            ],
            "edges": [
                {"source": "internet", "target": "role", "type": "can_connect", "attrs": _edge_attrs()},
                # Insert the semantically wrong parallel edge first to ensure
                # verification does not silently select it.
                {"source": "role", "target": "table", "type": "accessed", "attrs": _edge_attrs(status="Contradicted")},
                {"source": "role", "target": "table", "type": "has_permission", "attrs": _edge_attrs()},
                {"source": "table", "target": "tag", "type": "classified_as", "attrs": _edge_attrs()},
            ],
        }
        graph = build_graph(sample)

        paths = constrained_dfs(graph, ["internet"], ["tag"], min_depth=3, max_depth=3)

        self.assertEqual(1, len(paths))
        self.assertEqual(
            ["can_connect", "has_permission", "classified_as"],
            paths[0].edge_types,
        )
        self.assertEqual("Valid", verify_path(graph, paths[0])["state"])

    def test_metrics_distinguish_same_nodes_with_different_edges(self):
        gold = EvidencePath(["a", "b"], ["permission-edge"], ["has_permission"])
        wrong = EvidencePath(["a", "b"], ["audit-edge"], ["accessed"])

        self.assertEqual(0.0, path_recall_at_k([wrong], [gold], 1))
        self.assertEqual(1.0, path_recall_at_k([gold], [gold], 1))

    def test_sddp_controlled_contract_is_retrievable_and_verifiable(self):
        input_dir = Path("output/sddp_slices/example_input")
        expected_states = {
            "controlled_exposure": "Valid",
            "controlled_missing": "Insufficient",
            "controlled_refuted": "Invalid",
        }
        config = load_config()

        for variant, expected in expected_states.items():
            with self.subTest(variant=variant):
                sample = build_slice(input_dir, f"test_{variant}", variant)
                graph = build_graph(sample)
                gold = path_from_label(sample["path_labels"][0])
                candidates = constrained_dfs(
                    graph,
                    get_entry_nodes(graph),
                    get_target_nodes(graph),
                    config["search"]["min_depth"],
                    config["search"]["max_depth"],
                )

                self.assertEqual(expected, verify_path(graph, gold)["state"])
                self.assertIn(
                    edge_aware_path_key(gold),
                    {edge_aware_path_key(path) for path in candidates},
                )

    def test_partial_environment_hides_semantics_until_query(self):
        sample = {
            "sample_id": "partial",
            "scenario": "partial",
            "nodes": [
                {"id": "internet", "type": "Network", "attrs": {"public_exposed": True}},
                {"id": "role", "type": "Identity", "attrs": {}},
            ],
            "edges": [
                {
                    "source": "internet",
                    "target": "role",
                    "type": "can_connect",
                    "attrs": {**_edge_attrs(), "raw_evidence": "network-log"},
                },
            ],
        }
        graph = build_graph(sample)
        env = PartialEvidenceEnvironment(graph, budget=1)
        edge_id = sample["edges"][0]["edge_id"]

        hidden = env.observed_graph.get_edge_data("internet", "role", edge_id)
        self.assertEqual("Unknown", hidden["status"])
        self.assertEqual("not_queried", hidden["raw_evidence"])

        observation = env.query(edge_id)

        self.assertEqual("Supported", observation.status)
        self.assertEqual("network-log", env.observed_graph.get_edge_data("internet", "role", edge_id)["raw_evidence"])
        self.assertEqual(1, env.spent)

    def test_active_investigator_returns_auditable_certificate(self):
        sample = {
            "sample_id": "active",
            "scenario": "active",
            "nodes": [
                {"id": "internet", "type": "Network", "attrs": {"public_exposed": True}},
                {"id": "role", "type": "Identity", "attrs": {}},
                {"id": "table", "type": "DBObject", "attrs": {"kind": "table"}},
                {"id": "tag", "type": "SensitiveTag", "attrs": {"level": 4, "confidence": 1.0}},
            ],
            "edges": [
                {"source": "internet", "target": "role", "type": "can_connect", "attrs": _edge_attrs()},
                {"source": "role", "target": "table", "type": "has_permission", "attrs": _edge_attrs()},
                {"source": "table", "target": "tag", "type": "classified_as", "attrs": _edge_attrs()},
            ],
        }
        graph = build_graph(sample)
        path = EvidencePath(
            ["internet", "role", "table", "tag"],
            [edge["edge_id"] for edge in sample["edges"]],
            ["can_connect", "has_permission", "classified_as"],
        )

        result = investigate(graph, [path], policy="fixed_order", budget=4)

        self.assertTrue(truth_has_valid_path(graph, [path]))
        self.assertEqual("valid_found", result.decision)
        self.assertEqual(path.edge_ids, result.certificate_edge_ids)
        self.assertEqual(3, result.tool_calls)

    def test_active_investigator_abstains_when_queried_evidence_remains_unknown(self):
        sample = {
            "sample_id": "active-unknown",
            "scenario": "active-unknown",
            "nodes": [
                {"id": "internet", "type": "Network", "attrs": {"public_exposed": True}},
                {"id": "role", "type": "Identity", "attrs": {}},
                {"id": "table", "type": "DBObject", "attrs": {"kind": "table"}},
                {"id": "tag", "type": "SensitiveTag", "attrs": {"level": 4, "confidence": 1.0}},
            ],
            "edges": [
                {"source": "internet", "target": "role", "type": "can_connect", "attrs": _edge_attrs(status="Unknown")},
                {"source": "role", "target": "table", "type": "has_permission", "attrs": _edge_attrs()},
                {"source": "table", "target": "tag", "type": "classified_as", "attrs": _edge_attrs()},
            ],
        }
        graph = build_graph(sample)
        path = EvidencePath(
            ["internet", "role", "table", "tag"],
            [edge["edge_id"] for edge in sample["edges"]],
            ["can_connect", "has_permission", "classified_as"],
        )

        result = investigate(graph, [path], policy="full_scan")

        self.assertEqual("insufficient_evidence", result.decision)
        self.assertIsNone(result.predicted_has_valid)
        self.assertEqual([], result.certificate_edge_ids)

    def test_active_investigator_uses_minimal_shared_refutation_certificate(self):
        sample = {
            "sample_id": "active-negative",
            "scenario": "active-negative",
            "nodes": [
                {"id": "internet", "type": "Network", "attrs": {"public_exposed": True}},
                {"id": "role", "type": "Identity", "attrs": {}},
                {"id": "table-a", "type": "DBObject", "attrs": {"kind": "table"}},
                {"id": "table-b", "type": "DBObject", "attrs": {"kind": "table"}},
                {"id": "tag-a", "type": "SensitiveTag", "attrs": {"level": 4, "confidence": 1.0}},
                {"id": "tag-b", "type": "SensitiveTag", "attrs": {"level": 4, "confidence": 1.0}},
            ],
            "edges": [
                {"edge_id": "shared-refutation", "source": "internet", "target": "role", "type": "can_connect", "attrs": _edge_attrs(status="Contradicted")},
                {"edge_id": "perm-a", "source": "role", "target": "table-a", "type": "has_permission", "attrs": _edge_attrs()},
                {"edge_id": "tag-a", "source": "table-a", "target": "tag-a", "type": "classified_as", "attrs": _edge_attrs()},
                {"edge_id": "perm-b", "source": "role", "target": "table-b", "type": "has_permission", "attrs": _edge_attrs()},
                {"edge_id": "tag-b", "source": "table-b", "target": "tag-b", "type": "classified_as", "attrs": _edge_attrs()},
            ],
        }
        graph = build_graph(sample)
        paths = [
            EvidencePath(
                ["internet", "role", "table-a", "tag-a"],
                ["shared-refutation", "perm-a", "tag-a"],
                ["can_connect", "has_permission", "classified_as"],
            ),
            EvidencePath(
                ["internet", "role", "table-b", "tag-b"],
                ["shared-refutation", "perm-b", "tag-b"],
                ["can_connect", "has_permission", "classified_as"],
            ),
        ]

        result = investigate(graph, paths, policy="full_scan")

        self.assertEqual("no_valid_path", result.decision)
        self.assertFalse(result.predicted_has_valid)
        self.assertEqual(["shared-refutation"], result.certificate_edge_ids)


if __name__ == "__main__":
    unittest.main()
