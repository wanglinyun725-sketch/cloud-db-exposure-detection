import json
from pathlib import Path
import unittest

from scripts.data.build_provider_semantic_review_packet import build
from src.annotation.workflow import create_assignment


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "provider_semantic_review_round1_unlabeled.json"
)


class ProviderSemanticReviewPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))

    def test_packet_is_reproducible_and_has_no_labels(self):
        self.assertEqual(self.packet, build())
        self.assertEqual(20, self.packet["summary"]["case_count"])
        self.assertEqual(
            14, self.packet["summary"]["independence_group_count"]
        )
        self.assertEqual(0, self.packet["summary"]["human_gold_cases"])
        for case in self.packet["cases"]:
            self.assertEqual("pending", case["annotation"]["status"])
            self.assertIsNone(case["annotation"]["label_origin"])
            self.assertFalse(case["nodes"])
            self.assertFalse(case["edges"])
            self.assertFalse(case["path_labels"])
            self.assertTrue(case["runtime_instances"])

    def test_existing_blind_assignment_workflow_accepts_packet(self):
        primary = create_assignment(
            self.packet, "primary", "human-reviewer-01"
        )
        reviewer = create_assignment(
            self.packet, "reviewer", "human-reviewer-02"
        )

        self.assertEqual(20, len(primary["cases"]))
        self.assertEqual(20, len(reviewer["cases"]))
        self.assertEqual(
            primary["packet_sha256"], reviewer["packet_sha256"]
        )
        self.assertNotEqual(
            primary["annotator_id"], reviewer["annotator_id"]
        )
        self.assertTrue(all(
            item["policy"]["source_labels_copied"] == 0
            for item in (primary, reviewer)
        ))


if __name__ == "__main__":
    unittest.main()
