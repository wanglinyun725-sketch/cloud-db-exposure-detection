import json
import unittest
from pathlib import Path

from scripts.data.build_gcp_scheduled_transfer_negative_candidate import (
    build_candidate,
)


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "output" / "explicit_denial_candidate_inventory.json"


class ExplicitDenialCandidateTests(unittest.TestCase):
    def test_inventory_never_treats_silence_or_background_delivery_as_denial_gold(self):
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

        self.assertFalse(
            inventory["policy"]["absence_of_event_means_denial"]
        )
        self.assertFalse(inventory["policy"]["matched_success_is_gold"])
        self.assertEqual(
            10,
            inventory["summary"]["reviewable_data_denial_claims"],
        )
        self.assertTrue(
            all(
                not item["background_telemetry"]
                and not item["control_or_cleanup"]
                for item in inventory["data_relevant_denial_candidates"]
            )
        )

    def test_gcp_candidate_is_one_case_with_ten_real_runs_and_null_gold(self):
        candidate = build_candidate()

        self.assertEqual(
            "NotReachable",
            candidate["path_hypothesis"]["provisional_path_state"],
        )
        self.assertEqual(10, candidate["replication"]["independent_runs"])
        self.assertGreaterEqual(
            candidate["replication"]["total_denied_attempts"],
            40,
        )
        self.assertTrue(
            candidate["replication"]["all_runs_same_final_edge_state"]
        )
        self.assertIsNone(candidate["annotation"]["human_gold_label"])
        self.assertEqual(
            "NotReachable",
            candidate["annotation"]["provider_oracle_gold_label"],
        )
        self.assertEqual(
            "provider_native_runtime",
            candidate["annotation"]["label_origin"],
        )
        self.assertTrue(
            candidate["provider_oracle_certificate"]["sufficient"]
        )
        self.assertEqual(
            "provider_native_runtime",
            candidate["provider_oracle_certificate"]["label_origin"],
        )
        self.assertTrue(
            all(
                instance["provider_status_code"] == 7
                and instance["denied_permission"]
                == "storage.objects.list"
                and instance["deterministic_final_edge_state"]
                == "Contradicted"
                for instance in candidate["replication"]["instances"]
            )
        )
        self.assertTrue(
            all(
                set(instance["causal_control_refs"])
                == {
                    "create_function",
                    "create_scheduler",
                    "act_as_service_account",
                    "denied_bucket_list",
                    "admin_bucket_list_success_control",
                }
                for instance in candidate["replication"]["instances"]
            )
        )


if __name__ == "__main__":
    unittest.main()
