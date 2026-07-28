import json
import unittest

from scripts.data.export_expanded_annotation_pool import (
    V03_OUTPUT_PATH,
    build_expanded_pool,
)


class ExpandedAnnotationPoolV03Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = json.loads(
            V03_OUTPUT_PATH.read_text(encoding="utf-8")
        )

    def test_v03_is_exact_deterministic_next_revision(self):
        self.assertEqual(
            self.packet,
            build_expanded_pool(include_qualified_otrf=True),
        )
        self.assertEqual("0.3", self.packet["packet_version"])
        self.assertEqual(57, self.packet["summary"][
            "runtime_backed_cases"
        ])
        self.assertEqual(93, self.packet["summary"]["runtime_instances"])
        self.assertEqual(
            {"B": 57, "C": 93},
            self.packet["summary"]["provenance_level_counts"],
        )
        self.assertEqual(
            {
                "cross_cloud_observability_2026": 36,
                "otrf_security_datasets": 1,
                "splunk_attack_data": 9,
                "stratus_red_team": 11,
            },
            self.packet["summary"]["runtime_source_case_counts"],
        )

    def test_otrf_upgrades_existing_cloudgoat_case_without_new_group(self):
        case = next(
            item for item in self.packet["cases"]
            if item["case_id"] == "cloudgoat:aws:cloud_breach_s3"
        )
        self.assertEqual("B", case["source"]["provenance_level"])
        self.assertEqual(
            "cloudgoat-scenario:cloud_breach_s3",
            case["candidate_metadata"]["independence_group"],
        )
        self.assertFalse(
            case["candidate_metadata"]["runtime_scenario_independent"]
        )
        self.assertEqual(1, len(case["runtime_instances"]))
        instance = case["runtime_instances"][0]
        self.assertEqual(
            "otrf_security_datasets", instance["runtime_source_id"]
        )
        self.assertEqual(103, instance["observation_count"])
        self.assertTrue(all(
            event["path_label"] is None
            and event["evidence_state"] is None
            for event in instance["observations"]
        ))
        self.assertFalse(case["instance_labels"])
        self.assertEqual("pending", case["annotation"]["status"])

    def test_v03_does_not_increase_candidate_or_independence_counts(self):
        self.assertEqual(150, self.packet["summary"]["candidate_cases"])
        groups = {
            case["candidate_metadata"]["independence_group"]
            for case in self.packet["cases"]
        }
        self.assertEqual(113, len(groups))
        warning = self.packet["summary"]["runtime_lineage_warnings"][
            "otrf_security_datasets"
        ]
        self.assertIn("not an independent attack scenario", warning)


if __name__ == "__main__":
    unittest.main()
