import json
from pathlib import Path
import unittest

from scripts.data.profile_provider_success_candidates import (
    SUCCESS_OPERATIONS,
)


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = (
    ROOT / "output" / "provider_success_candidate_inventory.json"
)


class ProviderSuccessCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads(
            INVENTORY_PATH.read_text(encoding="utf-8")
        )

    def test_inventory_is_real_event_candidate_only(self):
        policy = self.inventory["policy"]

        self.assertEqual(0, policy["generated_events"])
        self.assertEqual(0, policy["generated_labels"])
        self.assertTrue(policy["payload_present_members_only"])
        self.assertTrue(policy["provider_success_record_required"])
        self.assertTrue(policy["success_is_edge_evidence_not_full_path_gold"])
        self.assertTrue(all(
            item["path_label"] is None
            and item["evidence_state"] is None
            and item["review_status"] == "candidate_only"
            for item in self.inventory["candidates"]
        ))

    def test_operation_allowlist_and_pinned_counts(self):
        summary = self.inventory["summary"]

        self.assertEqual(
            {"GCP": 514},
            summary["provider_error_events_excluded"],
        )
        self.assertEqual(58, summary["candidate_operation_groups"])
        self.assertEqual(17, summary["conservative_lineage_groups"])
        self.assertEqual(28, summary["scenario_variant_groups"])
        self.assertEqual(30, summary["high_priority_non_root_groups"])
        self.assertTrue(all(
            item["operation"] in SUCCESS_OPERATIONS[item["provider"]]
            for item in self.inventory["candidates"]
        ))

    def test_v3_source_scenarios_have_success_leads(self):
        keys = {
            (
                item["provider"],
                item["scenario_family"],
                item["operation"],
            )
            for item in self.inventory["candidates"]
        }

        self.assertIn(
            (
                "AWS",
                "credentials_from_password_stores",
                "secretsmanager.amazonaws.com::GetSecretValue",
            ),
            keys,
        )
        self.assertIn(
            (
                "GCP",
                "credentials_from_password_stores",
                (
                    "secretmanager.googleapis.com::"
                    "google.cloud.secretmanager.v1."
                    "SecretManagerService.AccessSecretVersion"
                ),
            ),
            keys,
        )
        self.assertIn(
            (
                "GCP",
                "archive_collected_data",
                "storage.googleapis.com::storage.objects.get",
            ),
            keys,
        )


if __name__ == "__main__":
    unittest.main()
