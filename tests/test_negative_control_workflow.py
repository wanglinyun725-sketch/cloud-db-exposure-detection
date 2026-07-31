import json
from pathlib import Path
import unittest

from src.annotation.negative_control_workflow import (
    compare_negative_assignments,
    create_negative_adjudication_assignment,
    create_negative_assignment,
    finalize_negative_assignments,
    mark_negative_assignment_completed,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "negative_control_round1_unlabeled.json"
)


def _completed(role, annotator, values=(True, True, True)):
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assignment = create_negative_assignment(packet, role, annotator)
    for case in assignment["cases"]:
        case["screening"] = {
            "cloud_data_relevant": values[0],
            "non_attack_confirmed": values[1],
            "usable_as_negative_control": values[2],
            "rationale": "Human read the cited provider report text.",
        }
    return mark_negative_assignment_completed(assignment)


class NegativeControlWorkflowTests(unittest.TestCase):
    def test_assignments_are_blank_independent_and_source_frozen(self):
        packet = json.loads(PACKET.read_text(encoding="utf-8"))
        primary = create_negative_assignment(packet, "primary", "human-a")
        reviewer = create_negative_assignment(packet, "reviewer", "human-b")

        self.assertEqual(
            primary["packet_sha256"],
            reviewer["packet_sha256"],
        )
        self.assertTrue(all(
            value is None
            for value in primary["cases"][0]["screening"].values()
        ))
        self.assertEqual(0, primary["policy"]["other_annotator_labels_visible"])

    def test_matching_humans_release_reviewed_negative_controls(self):
        primary = _completed("primary", "human-a")
        reviewer = _completed("reviewer", "human-b")

        report = compare_negative_assignments(primary, reviewer)
        release = finalize_negative_assignments(primary, reviewer)

        self.assertEqual(1.0, report["exact_agreement_rate"])
        self.assertEqual(30, release["summary"]["usable_negative_controls"])
        self.assertTrue(all(
            case["case_kind"] == "external_negative_control"
            for case in release["cases"]
        ))
        self.assertTrue(all(
            case["screening"]["label_origin"] == "human_reviewed"
            for case in release["cases"]
        ))

    def test_disagreement_requires_distinct_third_human(self):
        primary = _completed("primary", "human-a")
        reviewer = _completed("reviewer", "human-b")
        reviewer["cases"][0]["screening"][
            "usable_as_negative_control"
        ] = False

        with self.assertRaisesRegex(ValueError, "third human"):
            finalize_negative_assignments(primary, reviewer)

        adjudication = create_negative_adjudication_assignment(
            primary,
            reviewer,
            "human-c",
        )
        self.assertEqual(1, len(adjudication["cases"]))
        adjudication["cases"][0]["screening"] = {
            "cloud_data_relevant": True,
            "non_attack_confirmed": True,
            "usable_as_negative_control": False,
            "rationale": "Third human resolved the disputed report.",
        }
        adjudication = mark_negative_assignment_completed(adjudication)
        release = finalize_negative_assignments(
            primary,
            reviewer,
            adjudication,
        )
        disputed = next(
            item for item in release["cases"]
            if item["candidate_id"]
            == adjudication["cases"][0]["candidate_id"]
        )
        self.assertEqual("adjudicated", disputed["screening"]["status"])
        self.assertFalse(
            disputed["screening"]["usable_as_negative_control"]
        )

    def test_ai_identity_is_rejected(self):
        packet = json.loads(PACKET.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(ValueError, "AI/model"):
            create_negative_assignment(packet, "primary", "qwen model")


if __name__ == "__main__":
    unittest.main()
