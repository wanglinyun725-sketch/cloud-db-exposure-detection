import unittest

from src.experiments.path_scoring import score_path_discovery


def _metadata(overall="Valid", path_state="Valid"):
    return {
        "case_id": "case-1",
        "instance_id": "instance-1",
        "independence_group": "group-1",
        "source_id": "real-source",
        "provenance_level": "B",
        "gold_nodes": [
            {"id": "a", "type": "Identity"},
            {"id": "b", "type": "Database"},
        ],
        "gold_edges": [
            {
                "edge_id": "gold-edge",
                "source": "a",
                "target": "b",
                "type": "data_access",
            }
        ],
        "gold_paths": [
            {
                "path_id": "gold-path",
                "node_ids": ["a", "b"],
                "edge_ids": ["gold-edge"],
                "state": path_state,
            }
        ],
        "gold_instance_label": {
            "instance_id": "instance-1",
            "overall_state": overall,
            "path_states": [
                {"path_id": "gold-path", "state": path_state}
            ],
        },
    }


def _proposal(node_types, edge_type, verified):
    return {
        "verified": verified,
        "normalized_path": {
            "path_id": "predicted",
            "nodes": [
                {
                    "node_id": f"n{index}",
                    "type": node_type,
                    "label": node_type,
                }
                for index, node_type in enumerate(node_types)
            ],
            "edges": [
                {
                    "edge_id": "e1",
                    "source": "n0",
                    "target": "n1",
                    "type": edge_type,
                }
            ],
        },
        "errors": [] if verified else ["citation failed"],
    }


class PathScoringTests(unittest.TestCase):
    def test_internal_certificate_and_human_semantics_are_separate(self):
        result = {
            "decision": "evidence_certified_path",
            "spent": 7,
            "valid_tool_calls": 2,
            "invalid_actions": 1,
            "path_candidates": [
                _proposal(["Identity", "Database"], "data_access", True),
                _proposal(["Identity", "Queue"], "publish", True),
                _proposal(["Identity", "Database"], "data_access", False),
            ],
        }

        score = score_path_discovery(result, _metadata(), k=5)

        self.assertEqual(1.0, score["valid_path_recall_at_k"])
        self.assertTrue(score["exact_path_match"])
        self.assertEqual(1, score["first_correct_path_rank"])
        self.assertEqual(0.5, score["semantic_false_path_rate"])
        self.assertAlmostEqual(1 / 3, score["unsupported_evidence_rate"])
        self.assertAlmostEqual(2 / 3, score["hallucinated_path_rate"])
        self.assertAlmostEqual(
            0.5,
            score["certified_fine_edge_precision_at_k"],
        )
        self.assertEqual(
            1.0,
            score["certified_fine_edge_recall_at_k"],
        )
        self.assertAlmostEqual(
            2 / 3,
            score["certified_fine_edge_f1_at_k"],
        )
        self.assertAlmostEqual(
            1 / 3,
            score["raw_fine_edge_precision_at_k"],
        )
        self.assertEqual(0.5, score["raw_fine_edge_f1_at_k"])
        self.assertEqual(7, score["query_cost"])

    def test_certified_but_wrong_path_does_not_match_gold(self):
        result = {
            "decision": "evidence_certified_path",
            "path_candidates": [
                _proposal(["Identity", "Queue"], "publish", True)
            ],
        }

        score = score_path_discovery(result, _metadata())

        self.assertEqual(0.0, score["valid_path_recall_at_k"])
        self.assertFalse(score["exact_path_match"])
        self.assertEqual(1.0, score["semantic_false_path_rate"])
        self.assertEqual(
            0.0,
            score["certified_fine_edge_f1_at_k"],
        )

    def test_empty_prediction_is_correct_rejection_only_for_invalid_gold(self):
        score = score_path_discovery(
            {
                "decision": "no_verified_path",
                "path_candidates": [],
            },
            _metadata(overall="Invalid", path_state="Invalid"),
        )

        self.assertTrue(score["correct_rejection"])
        self.assertIsNone(score["valid_path_recall_at_k"])
        self.assertIsNone(score["certified_fine_edge_f1_at_k"])

    def test_explicit_aliases_match_canonical_fine_types_not_literal_strings(self):
        metadata = _metadata()
        metadata["gold_nodes"][0]["type"] = "identity"
        metadata["gold_nodes"][1]["type"] = "database"
        metadata["gold_edges"][0]["type"] = "access_data"
        result = {
            "decision": "evidence_certified_path",
            "path_candidates": [
                _proposal(["principal", "db"], "data_access", True)
            ],
        }

        score = score_path_discovery(result, metadata)

        self.assertTrue(score["canonical_exact_path_match"])
        self.assertFalse(score["literal_exact_path_match"])
        self.assertEqual(
            "cloud_data_path_v1",
            score["path_ontology"]["ontology_id"],
        )

    def test_coarse_match_is_sensitivity_only_and_never_primary_credit(self):
        metadata = _metadata()
        metadata["gold_nodes"][0]["type"] = "identity"
        metadata["gold_nodes"][1]["type"] = "database"
        metadata["gold_edges"][0]["type"] = "read_data"
        result = {
            "decision": "evidence_certified_path",
            "path_candidates": [
                _proposal(
                    ["identity", "object_storage"],
                    "access_data",
                    True,
                )
            ],
        }

        score = score_path_discovery(result, metadata)

        self.assertFalse(score["canonical_exact_path_match"])
        self.assertTrue(score["coarse_exact_path_match"])
        self.assertFalse(score["proposal_rows"][0]["semantic_match"])
        self.assertEqual(1.0, score["semantic_false_path_rate"])
        self.assertEqual(
            0.0,
            score["certified_fine_edge_f1_at_k"],
        )

    def test_invalid_ontology_edges_count_as_unmatched_predictions(self):
        result = {
            "decision": "unverified_paths_proposed",
            "path_candidates": [
                _proposal(
                    ["Identity", "not_a_node_type"],
                    "not_an_edge_type",
                    True,
                ),
                _proposal(
                    ["Identity", "Database"],
                    "data_access",
                    True,
                ),
            ],
        }

        score = score_path_discovery(result, _metadata())

        self.assertEqual(
            0.5,
            score["certified_fine_edge_precision_at_k"],
        )
        self.assertEqual(
            1.0,
            score["certified_fine_edge_recall_at_k"],
        )
        self.assertAlmostEqual(
            2 / 3,
            score["certified_fine_edge_f1_at_k"],
        )


if __name__ == "__main__":
    unittest.main()
