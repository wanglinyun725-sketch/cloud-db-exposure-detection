import json
from pathlib import Path
import unittest

from scripts.data.build_provider_path_candidate_workbench import build


ROOT = Path(__file__).resolve().parents[1]
WORKBENCH_PATH = (
    ROOT
    / "data"
    / "real_sources"
    / "provider_path_candidate_workbench_v1.json"
)


class ProviderPathCandidateWorkbenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workbench = json.loads(
            WORKBENCH_PATH.read_text(encoding="utf-8")
        )

    def test_builder_is_reproducible_and_label_empty(self):
        self.assertEqual(self.workbench, build())
        self.assertEqual(
            "provider_runtime_candidates_not_gold",
            self.workbench["dataset_stage"],
        )
        self.assertEqual(
            0, self.workbench["policy"]["generated_cloud_events"]
        )
        self.assertEqual(
            0, self.workbench["policy"]["generated_gold_labels"]
        )
        self.assertTrue(all(
            item["path_label"] is None
            and item["evidence_state"] is None
            and item["review_status"] == "semantic_review_required"
            for item in self.workbench["candidates"]
        ))

    def test_conservative_counts_and_success_filter(self):
        summary = self.workbench["summary"]

        self.assertEqual(20, summary["path_candidate_groups"])
        self.assertEqual(14, summary["conservative_lineage_groups"])
        self.assertEqual(10, summary["multi_event_path_groups"])
        self.assertEqual(10, summary["direct_runtime_edge_groups"])
        self.assertEqual(0, summary["groups_with_exact_tuple_conflict"])
        self.assertEqual(
            {"GCP": 514},
            self.workbench["source_scan"][
                "provider_error_events_excluded_from_support"
            ],
        )

    def test_every_representative_has_immutable_raw_evidence(self):
        for candidate in self.workbench["candidates"]:
            self.assertTrue(
                candidate["oracle_precheck"][
                    "provider_success_records_present"
                ]
            )
            for event in candidate["representative"]["support_events"]:
                raw_ref = event["raw_ref"]
                self.assertEqual(64, len(raw_ref["archive_sha256"]))
                self.assertEqual(64, len(raw_ref["member_sha256"]))
                self.assertTrue(raw_ref["json_pointer"].startswith("$"))
                self.assertEqual("success", event["provider_outcome"])


if __name__ == "__main__":
    unittest.main()
