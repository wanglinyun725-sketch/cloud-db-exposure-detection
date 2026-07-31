import json
from pathlib import Path
import unittest

from scripts.data.build_splunk_denial_expansion import build


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = (
    ROOT / "data" / "real_sources" / "splunk_denial_expansion_v1.json"
)


class SplunkDenialExpansionTests(unittest.TestCase):
    def test_builder_is_reproducible_and_label_free(self):
        built = build()
        frozen = json.loads(INDEX_PATH.read_text(encoding="utf-8"))

        self.assertEqual(frozen, built)
        self.assertEqual(3, built["summary"]["candidate_cases"])
        self.assertEqual(6, built["summary"]["observations"])
        self.assertEqual(1, built["summary"]["independence_groups"])
        self.assertEqual(0, built["policy"]["generated_samples"])
        self.assertEqual(0, built["policy"]["generated_labels"])

    def test_each_case_has_exact_denial_and_same_scope_control(self):
        by_id = {
            item["observation_id"]: item
            for item in build()["observations"]
        }
        for case in build()["cases"]:
            pair = [by_id[item] for item in case["observation_ids"]]
            denied = next(
                item for item in pair
                if item["pair_role"] == "denied_principal"
            )
            control = next(
                item for item in pair
                if item["pair_role"] == "same_scope_success_control"
            )
            self.assertEqual("AccessDenied", denied["event_status"])
            self.assertEqual("Success", control["event_status"])
            self.assertEqual(case["denied_principal"], denied["actor_id"])
            self.assertEqual(case["control_principal"], control["actor_id"])
            for field in (
                "account_id",
                "region",
                "service",
                "operation",
                "target_resource",
            ):
                self.assertEqual(denied[field], control[field])
            self.assertLess(denied["timestamp"], control["timestamp"])
            self.assertIsNone(denied["path_label"])
            self.assertIsNone(denied["evidence_state"])


if __name__ == "__main__":
    unittest.main()
