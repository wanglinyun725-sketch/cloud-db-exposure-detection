import unittest

from src.agent.path_proposal import (
    record_visible_observations,
    verify_path_proposal,
)


def _candidate(assignments):
    return {
        "path_id": "path-1",
        "nodes": [
            {
                "node_id": "n1",
                "type": "external_actor",
                "label": "external actor",
            },
            {"node_id": "n2", "type": "identity", "label": "cloud identity"},
            {
                "node_id": "n3",
                "type": "data_object",
                "label": "database records",
            },
        ],
        "edges": [
            {
                "edge_id": "e1",
                "source": "n1",
                "target": "n2",
                "type": "use_credential",
            },
            {
                "edge_id": "e2",
                "source": "n2",
                "target": "n3",
                "type": "access_data",
            },
        ],
        "evidence_assignments": assignments,
    }


def _ledger():
    return {
        "obs-1": [
            {
                "call_id": 3,
                "tool_name": "search_events",
                "cost": 4.0,
                "raw_ref": {"sha256": "a" * 64, "record_index": 1},
                "visible_event": {
                    "observation_id": "obs-1",
                    "operation": "AssumeRole",
                },
            }
        ],
        "obs-2": [
            {
                "call_id": 3,
                "tool_name": "search_events",
                "cost": 4.0,
                "raw_ref": {"sha256": "a" * 64, "record_index": 2},
                "visible_event": {
                    "observation_id": "obs-2",
                    "operation": "GetObject",
                },
            }
        ],
    }


class PathProposalTests(unittest.TestCase):
    def test_noncanonical_type_is_rejected_with_frozen_suggestion(self):
        candidate = _candidate([])
        candidate["nodes"][0]["type"] = "actor"
        candidate["edges"][0]["type"] = "credential_use"

        report = verify_path_proposal(candidate, _ledger())

        self.assertFalse(report["structurally_valid"])
        self.assertTrue(any(
            "use identity" in error for error in report["errors"]
        ))
        self.assertTrue(any(
            "use use_credential" in error for error in report["errors"]
        ))
        self.assertEqual(
            "cloud_data_path_v1",
            report["path_ontology"]["ontology_id"],
        )

    def test_valid_path_receives_four_value_verdict_and_minimal_certificate(self):
        report = verify_path_proposal(
            _candidate(
                [
                    {
                        "observation_id": "obs-1",
                        "call_id": 3,
                        "polarity": "support",
                        "edge_ids": ["e1"],
                        "test": {
                            "field": "operation",
                            "operator": "eq",
                            "value": "AssumeRole",
                        },
                    },
                    {
                        "observation_id": "obs-2",
                        "call_id": 3,
                        "polarity": "support",
                        "edge_ids": ["e2"],
                        "test": {
                            "field": "operation",
                            "operator": "eq",
                            "value": "GetObject",
                        },
                    },
                ]
            ),
            _ledger(),
        )

        self.assertTrue(report["verified"])
        self.assertEqual("Valid", report["verdict"]["state"])
        self.assertEqual(1, len(report["evidence_items"]))
        self.assertEqual(4.0, report["certificate"]["total_cost"])
        self.assertTrue(report["certificate_audit"]["irreducible"])

    def test_unobserved_call_is_preserved_as_verification_failure(self):
        report = verify_path_proposal(
            _candidate(
                [
                    {
                        "observation_id": "obs-1",
                        "call_id": 99,
                        "polarity": "support",
                        "edge_ids": ["e1", "e2"],
                        "test": {
                            "field": "operation",
                            "operator": "exists",
                            "value": True,
                        },
                    }
                ]
            ),
            _ledger(),
        )

        self.assertFalse(report["verified"])
        self.assertTrue(report["structurally_valid"])
        self.assertIn("not visible in tool call 99", report["errors"][0])
        self.assertEqual(99, report["path_candidate"]["evidence_assignments"][0]["call_id"])

    def test_disconnected_path_fails_before_evidence_verification(self):
        candidate = _candidate([])
        candidate["edges"][1]["source"] = "n1"

        report = verify_path_proposal(candidate, _ledger())

        self.assertFalse(report["verified"])
        self.assertFalse(report["structurally_valid"])
        self.assertTrue(
            any("must connect n2 -> n3" in item for item in report["errors"])
        )

    def test_conflicting_edge_never_receives_positive_certificate(self):
        report = verify_path_proposal(
            _candidate(
                [
                    {
                        "observation_id": "obs-1",
                        "call_id": 3,
                        "polarity": "support",
                        "edge_ids": ["e1", "e2"],
                        "test": {
                            "field": "operation",
                            "operator": "exists",
                            "value": True,
                        },
                    },
                    {
                        "observation_id": "obs-2",
                        "call_id": 3,
                        "polarity": "refute",
                        "edge_ids": ["e2"],
                        "test": {
                            "field": "operation",
                            "operator": "eq",
                            "value": "GetObject",
                        },
                    },
                ]
            ),
            _ledger(),
        )

        self.assertFalse(report["verified"])
        self.assertEqual("Conflict", report["verdict"]["state"])
        self.assertIsNone(report["certificate"])

    def test_explicitly_refuted_path_receives_negative_certificate(self):
        candidate = _candidate(
            [
                {
                    "observation_id": "obs-1",
                    "call_id": 3,
                    "polarity": "support",
                    "edge_ids": ["e1"],
                    "test": {
                        "field": "operation",
                        "operator": "eq",
                        "value": "AssumeRole",
                    },
                },
                {
                    "observation_id": "obs-2",
                    "call_id": 3,
                    "polarity": "refute",
                    "edge_ids": ["e2"],
                    "test": {
                        "field": "operation",
                        "operator": "eq",
                        "value": "GetObject",
                    },
                },
            ]
        )
        candidate["claimed_state"] = "NotReachable"

        report = verify_path_proposal(candidate, _ledger())

        self.assertTrue(report["verified"])
        self.assertEqual("Invalid", report["verdict"]["state"])
        self.assertEqual("negative", report["certificate"]["kind"])
        self.assertTrue(report["certificate_audit"]["sufficient"])
        self.assertTrue(report["certificate_audit"]["irreducible"])

    def test_failed_executable_test_cannot_become_support(self):
        report = verify_path_proposal(
            _candidate(
                [
                    {
                        "observation_id": "obs-1",
                        "call_id": 3,
                        "polarity": "support",
                        "edge_ids": ["e1", "e2"],
                        "test": {
                            "field": "operation",
                            "operator": "eq",
                            "value": "DeleteDatabase",
                        },
                    }
                ]
            ),
            _ledger(),
        )

        self.assertFalse(report["verified"])
        self.assertTrue(
            any("executable test failed" in item for item in report["errors"])
        )

    def test_provider_polarity_cannot_be_reversed_by_the_model(self):
        ledger = _ledger()
        ledger["obs-2"][0]["visible_event"]["provider_decision"] = "deny"
        support_report = verify_path_proposal(
            _candidate([
                {
                    "observation_id": "obs-2",
                    "call_id": 3,
                    "polarity": "support",
                    "edge_ids": ["e1", "e2"],
                    "test": {
                        "field": "operation",
                        "operator": "eq",
                        "value": "GetObject",
                    },
                }
            ]),
            ledger,
        )
        self.assertFalse(support_report["verified"])
        self.assertTrue(any(
            "provider denial as positive support" in error
            for error in support_report["errors"]
        ))

        candidate = _candidate([
            {
                "observation_id": "obs-2",
                "call_id": 3,
                "polarity": "refute",
                "edge_ids": ["e2"],
                "test": {
                    "field": "provider_decision",
                    "operator": "eq",
                    "value": "deny",
                },
            }
        ])
        candidate["claimed_state"] = "NotReachable"
        refute_report = verify_path_proposal(candidate, ledger)
        self.assertTrue(refute_report["verified"])
        self.assertEqual("negative", refute_report["certificate"]["kind"])

    def test_incomplete_provider_scope_cannot_certify_end_to_end_path(self):
        ledger = _ledger()
        ledger["obs-2"][0]["visible_event"].update({
            "provider_decision": "allow",
            "scope_completeness": "incomplete_for_database_data_plane",
        })
        report = verify_path_proposal(
            _candidate([{
                "observation_id": "obs-2",
                "call_id": 3,
                "polarity": "support",
                "edge_ids": ["e1", "e2"],
                "test": {
                    "field": "provider_decision",
                    "operator": "eq",
                    "value": "allow",
                },
            }]),
            ledger,
        )

        self.assertFalse(report["verified"])
        self.assertTrue(any(
            "non-decisive scope" in error for error in report["errors"]
        ))

    def test_provider_scope_ablation_exposes_the_unsafe_counterfactual(self):
        ledger = _ledger()
        ledger["obs-2"][0]["visible_event"].update({
            "provider_decision": "allow",
            "scope_completeness": "incomplete_for_database_data_plane",
        })
        candidate = _candidate([{
            "observation_id": "obs-2",
            "call_id": 3,
            "polarity": "support",
            "edge_ids": ["e1", "e2"],
            "test": {
                "field": "provider_decision",
                "operator": "eq",
                "value": "allow",
            },
        }])

        guarded = verify_path_proposal(candidate, ledger)
        ablated = verify_path_proposal(
            candidate,
            ledger,
            provider_scope_gate=False,
        )

        self.assertFalse(guarded["verified"])
        self.assertTrue(ablated["verified"])
        self.assertEqual("Valid", ablated["verdict"]["state"])
        self.assertIn(
            "provider-scope-ablation-disabled",
            ablated["certificate_scope"],
        )

    def test_visibility_ledger_records_only_policy_rendered_events(self):
        ledger = {}
        tool_output = {
            "receipt": {
                "call_id": 2,
                "tool_name": "search_events",
                "cost": 3,
            },
            "tool_result": {
                "events": [
                    {
                        "observation_id": "visible",
                        "raw_ref": {"sha256": "a" * 64},
                    },
                    {
                        "observation_id": "hidden",
                        "raw_ref": {"sha256": "b" * 64},
                    },
                ]
            },
        }
        compact = {
            "events": [
                {"observation_id": "visible", "operation": "GetObject"}
            ]
        }

        record_visible_observations(ledger, tool_output, compact)

        self.assertEqual(["visible"], list(ledger))
        self.assertEqual(2, ledger["visible"][0]["call_id"])
        self.assertEqual(
            "GetObject",
            ledger["visible"][0]["visible_event"]["operation"],
        )


if __name__ == "__main__":
    unittest.main()
