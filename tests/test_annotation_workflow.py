from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from pathlib import Path

import jsonschema

from src.annotation.workflow import (
    REAL_SCHEMA_PATH,
    compare_assignments,
    compare_pair,
    create_adjudication_assignment,
    create_assignment,
    finalize_assignments,
    finalize_pair,
    validate_submission,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "pilot_round1_unlabeled.json"
)


def completed_submission(template, decision="accept"):
    value = deepcopy(template)
    value["human_attestation"] = True
    value["completed_at"] = datetime.now(timezone.utc).isoformat()
    value["admission_screen"] = {
        "external_or_low_privilege_entry_defined": True,
        "multi_step_path_present": True,
        "cloud_data_target_present": True,
        "critical_edges_have_raw_evidence": True,
        "not_a_near_duplicate": True,
        "decision": decision,
        "rationale": "Human reviewed the pinned source records.",
    }
    if decision != "accept":
        return value
    value["nodes"] = [
        {"id": "actor", "type": "identity", "raw_refs": ["raw#actor"]},
        {"id": "db", "type": "database", "raw_refs": ["raw#db"]},
    ]
    value["edges"] = [
        {
            "edge_id": "e1",
            "source": "actor",
            "target": "db",
            "type": "access_data",
            "evidence_state": "Supported",
            "evidence_items": [
                {
                    "evidence_id": "obs-1",
                    "polarity": "support",
                    "raw_ref": "raw#record=1",
                    "query_cost": 1,
                    "source": "audit",
                }
            ],
            "raw_refs": ["raw#record=1"],
            "annotator_rationale": "The source event records access.",
        }
    ]
    value["path_labels"] = [
        {
            "path_id": "p1",
            "node_ids": ["actor", "db"],
            "edge_ids": ["e1"],
            "state": "Valid",
            "certificate_raw_refs": ["raw#record=1"],
        }
    ]
    value["tool_tasks"] = [
        {
            "tool_name": "get_event_detail",
            "query_scope": {"observation_id": "obs-1"},
            "observable_raw_refs": ["raw#record=1"],
            "query_cost": 1,
        }
    ]
    value["instance_labels"] = [
        {
            "instance_id": instance["instance_id"],
            "overall_state": "Valid",
            "path_states": [
                {"path_id": "p1", "state": "Valid"}
            ],
            "evidence_raw_refs": ["raw#record=1"],
            "annotator_rationale": (
                "The human reviewed this runtime instance independently."
            ),
        }
        for instance in value["runtime_instances"]
    ]
    return value


class AnnotationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = json.loads(PACKET.read_text(encoding="utf-8"))

    def test_primary_and_reviewer_assignments_are_blank_and_blind(self):
        primary = create_assignment(self.packet, "primary", "human-a")
        reviewer = create_assignment(self.packet, "reviewer", "human-b")

        self.assertEqual(
            primary["packet_sha256"],
            reviewer["packet_sha256"],
        )
        self.assertEqual(0, reviewer["policy"]["other_annotator_labels_visible"])
        self.assertTrue(all(
            not case["edges"] and not case["path_labels"]
            and not case["instance_labels"]
            for case in reviewer["cases"]
        ))
        self.assertTrue(reviewer["cases"][0]["observations"])
        self.assertTrue(reviewer["cases"][0]["source_context_sha256"])
        self.assertNotIn("human-a", json.dumps(reviewer))

    def test_evaluator_only_episode_conditions_are_hidden_from_humans(self):
        packet = deepcopy(self.packet)
        packet["cases"][0]["episode_refs"] = [
            {
                "episode_id": "visible-name:y",
                "source_condition": "payload_present",
                "condition_origin": "upstream",
            }
        ]
        assignment = create_assignment(packet, "primary", "human-a")
        serialized = json.dumps(assignment)
        self.assertNotIn("episode_refs", assignment["cases"][0])
        self.assertNotIn("payload_present", serialized)
        self.assertNotIn("visible-name:y", serialized)

    def test_model_identity_and_missing_attestation_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "AI/model"):
            create_assignment(self.packet, "primary", "gpt_annotator")
        assignment = create_assignment(self.packet, "primary", "human-a")
        with self.assertRaisesRegex(ValueError, "human_attestation"):
            validate_submission(assignment["cases"][0])

    def test_source_material_cannot_change_after_assignment(self):
        assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        submission = completed_submission(assignment["cases"][0])
        submission["observations"][0]["operation"] = "tampered"

        with self.assertRaisesRegex(ValueError, "context hash"):
            validate_submission(submission)

    def test_accepted_human_gold_rejects_noncanonical_type_aliases(self):
        assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        submission = completed_submission(assignment["cases"][0])
        submission["nodes"][0]["type"] = "Identity"
        submission["edges"][0]["type"] = "data_access"

        with self.assertRaisesRegex(ValueError, "noncanonical"):
            validate_submission(submission)

    def test_accept_requires_every_frozen_admission_criterion(self):
        assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        submission = completed_submission(assignment["cases"][0])
        submission["admission_screen"][
            "external_or_low_privilege_entry_defined"
        ] = False

        with self.assertRaisesRegex(
            ValueError,
            "requires all admission criteria true",
        ):
            validate_submission(submission)

    def test_independent_matching_submissions_finalize_as_reviewed(self):
        primary_assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        reviewer_assignment = create_assignment(
            self.packet,
            "reviewer",
            "human-b",
        )
        primary = completed_submission(primary_assignment["cases"][0])
        reviewer = completed_submission(reviewer_assignment["cases"][0])

        validate_submission(primary)
        validate_submission(reviewer)
        comparison = compare_pair(primary, reviewer)
        final = finalize_pair(primary, reviewer)

        self.assertTrue(comparison["exact_label_payload_agreement"])
        self.assertFalse(comparison["needs_adjudication"])
        self.assertEqual("reviewed", final["annotation"]["status"])
        self.assertEqual(
            "human_reviewed",
            final["annotation"]["label_origin"],
        )
        schema = json.loads(REAL_SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(final, schema)

    def test_same_person_cannot_be_primary_and_reviewer(self):
        primary_assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        reviewer_assignment = create_assignment(
            self.packet,
            "reviewer",
            "human-a",
        )
        primary = completed_submission(primary_assignment["cases"][0])
        reviewer = completed_submission(reviewer_assignment["cases"][0])

        with self.assertRaisesRegex(ValueError, "different humans"):
            compare_pair(primary, reviewer)

    def test_disagreement_cannot_finalize_without_third_human(self):
        primary_assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        reviewer_assignment = create_assignment(
            self.packet,
            "reviewer",
            "human-b",
        )
        primary = completed_submission(primary_assignment["cases"][0])
        reviewer = completed_submission(
            reviewer_assignment["cases"][0],
            decision="reject",
        )

        comparison = compare_pair(primary, reviewer)
        self.assertTrue(comparison["needs_adjudication"])
        with self.assertRaisesRegex(ValueError, "adjudicator"):
            finalize_pair(primary, reviewer)

    def test_assignment_agreement_uses_cases_not_edges_as_statistical_units(self):
        primary = create_assignment(self.packet, "primary", "human-a")
        reviewer = create_assignment(self.packet, "reviewer", "human-b")
        primary["cases"] = [
            completed_submission(case, decision="reject")
            for case in primary["cases"][:2]
        ]
        reviewer["cases"] = [
            completed_submission(case, decision="reject")
            for case in reviewer["cases"][:2]
        ]

        report = compare_assignments(primary, reviewer)

        self.assertEqual(2, report["independent_cases"])
        self.assertEqual(1.0, report["admission_exact_agreement"])
        self.assertEqual(1.0, report["admission_cohen_kappa"])

    def test_assignment_agreement_reports_state_metrics(self):
        primary = create_assignment(self.packet, "primary", "human-a")
        reviewer = create_assignment(self.packet, "reviewer", "human-b")
        primary["cases"] = [
            completed_submission(primary["cases"][0])
        ]
        reviewer["cases"] = [
            completed_submission(reviewer["cases"][0])
        ]

        report = compare_assignments(primary, reviewer)

        self.assertEqual(1, report["matched_edge_state_count"])
        self.assertEqual(
            1.0,
            report["edge_state_macro_f1_on_matched_edges"],
        )
        self.assertEqual(1, report["matched_path_state_count"])
        self.assertEqual(
            1.0,
            report["path_state_cohen_kappa_on_matched_paths"],
        )
        self.assertEqual(1, report["matched_instance_state_count"])
        self.assertEqual(1.0, report["instance_state_cohen_kappa"])
        self.assertEqual(1.0, report["instance_state_macro_f1"])

    def test_runtime_instance_state_must_be_complete_and_consistent(self):
        assignment = create_assignment(
            self.packet,
            "primary",
            "human-a",
        )
        submission = completed_submission(assignment["cases"][0])
        submission["instance_labels"][0]["overall_state"] = "Invalid"

        with self.assertRaisesRegex(ValueError, "overall_state must be Valid"):
            validate_submission(submission)

    def test_batch_adjudication_and_finalization(self):
        primary = create_assignment(self.packet, "primary", "human-a")
        reviewer = create_assignment(self.packet, "reviewer", "human-b")
        primary["cases"] = [
            completed_submission(primary["cases"][0])
        ]
        reviewer["cases"] = [
            completed_submission(
                reviewer["cases"][0],
                decision="reject",
            )
        ]

        adjudication = create_adjudication_assignment(
            primary,
            reviewer,
            "human-c",
        )
        self.assertEqual(1, len(adjudication["cases"]))
        self.assertEqual(
            2,
            adjudication["policy"]["independent_labels_visible"],
        )
        adjudication["cases"] = [
            completed_submission(
                adjudication["cases"][0],
                decision="reject",
            )
        ]
        release = finalize_assignments(
            primary,
            reviewer,
            adjudication,
        )

        self.assertEqual(1, len(release["cases"]))
        self.assertEqual(1, release["adjudication"]["completed"])
        self.assertEqual(
            "rejected",
            release["cases"][0]["annotation"]["status"],
        )

    def test_needs_execution_is_not_frozen_as_reviewed_gold(self):
        primary = create_assignment(self.packet, "primary", "human-a")
        reviewer = create_assignment(self.packet, "reviewer", "human-b")
        primary_case = completed_submission(
            primary["cases"][0],
            decision="needs_execution",
        )
        reviewer_case = completed_submission(
            reviewer["cases"][0],
            decision="needs_execution",
        )

        final = finalize_pair(primary_case, reviewer_case)

        self.assertEqual(
            "needs_execution",
            final["annotation"]["status"],
        )
        self.assertEqual(
            "needs_execution",
            final["admission_screen"]["decision"],
        )


if __name__ == "__main__":
    unittest.main()
