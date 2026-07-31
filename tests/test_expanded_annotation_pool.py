import unittest

from scripts.data.export_expanded_annotation_pool import (
    build_expanded_pool,
)


class ExpandedAnnotationPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = build_expanded_pool()

    def test_pool_expands_real_candidates_without_labels(self):
        summary = self.packet["summary"]

        self.assertEqual(150, summary["candidate_cases"])
        self.assertEqual(0, summary["generated_labels"])
        self.assertEqual(26, summary["source_counts"]["cloudgoat"])
        self.assertEqual(8, summary["source_counts"]["cloudfoxable"])
        self.assertEqual(
            51,
            summary["source_counts"]["stratus_red_team"],
        )
        self.assertEqual(
            20,
            summary["source_counts"]["mitre_attack_stix"],
        )
        self.assertEqual(
            9,
            summary["source_counts"]["splunk_attack_data"],
        )
        self.assertGreaterEqual(
            len(summary["source_counts"]),
            6,
        )
        self.assertEqual(92, summary["runtime_instances"])
        self.assertEqual(56, summary["runtime_backed_cases"])
        self.assertEqual(
            {
                "cross_cloud_observability_2026": 36,
                "splunk_attack_data": 9,
                "stratus_red_team": 11,
            },
            summary["runtime_source_case_counts"],
        )

    def test_static_candidates_are_c_level_traceable_and_unlabeled(self):
        static = [
            case for case in self.packet["cases"]
            if case["source"]["source_id"] in {
                "cloudgoat",
                "cloudfoxable",
                "mitre_attack_stix",
            }
        ]

        self.assertTrue(static)
        self.assertTrue(all(
            case["source"]["provenance_level"] == "C"
            for case in static
        ))
        self.assertTrue(all(
            case["annotation"]["status"] == "pending"
            and case["annotation"]["label_origin"] is None
            and case["admission_screen"]["decision"] is None
            and not case["nodes"]
            and not case["edges"]
            and not case["path_labels"]
            and not case["tool_tasks"]
            and not case["instance_labels"]
            and not case["runtime_instances"]
            for case in static
        ))
        self.assertTrue(all(
            case["source_materials"]
            and case["candidate_metadata"][
                "runtime_observations_in_packet"
            ] == 0
            for case in static
        ))

    def test_stratus_real_detonation_logs_upgrade_only_matching_cases(self):
        stratus = [
            case for case in self.packet["cases"]
            if case["source"]["source_id"] == "stratus_red_team"
        ]
        runtime = [case for case in stratus if case["runtime_instances"]]
        static = [case for case in stratus if not case["runtime_instances"]]

        self.assertEqual(11, len(runtime))
        self.assertEqual(40, len(static))
        self.assertTrue(all(
            case["source"]["provenance_level"] == "B"
            and case["runtime_instances"][0]["environment_kind"]
            == "stratus_grimoire_detonation"
            for case in runtime
        ))
        self.assertTrue(all(
            case["source"]["provenance_level"] == "C"
            for case in static
        ))
        observations = [
            event
            for case in runtime
            for instance in case["runtime_instances"]
            for event in instance["observations"]
        ]
        self.assertEqual(139, len(observations))
        self.assertTrue(all(
            event["path_label"] is None
            and event["evidence_state"] is None
            and event["candidate_id"]
            and event["raw_ref"]["member_sha256"]
            for event in observations
        ))

    def test_case_and_independence_identifiers_are_present(self):
        cases = self.packet["cases"]
        case_ids = [case["case_id"] for case in cases]

        self.assertEqual(len(case_ids), len(set(case_ids)))
        self.assertTrue(all(
            case.get("candidate_metadata", {}).get(
                "independence_group"
            )
            for case in cases
        ))

    def test_cross_cloud_runtime_pair_is_real_opaque_and_label_empty(self):
        cross_cloud = next(
            case for case in self.packet["cases"]
            if case["source"]["source_id"]
            == "cross_cloud_observability_2026"
        )
        instances = cross_cloud["runtime_instances"]

        self.assertEqual(2, len(instances))
        self.assertFalse(cross_cloud["instance_labels"])
        self.assertTrue(all(item["observations"] for item in instances))
        serialized = str(instances).casefold()
        self.assertNotIn("payload_present", serialized)
        self.assertNotIn("payload_absent", serialized)
        self.assertTrue(all(
            event.get("path_label") is None
            and event.get("evidence_state") is None
            for instance in instances
            for event in instance["observations"]
        ))

    def test_every_runtime_instance_has_an_explicit_cloud_platform(self):
        instances = [
            instance
            for case in self.packet["cases"]
            for instance in case["runtime_instances"]
        ]
        self.assertEqual(92, len(instances))
        self.assertEqual(
            {"AWS": 43, "AZURE": 25, "GCP": 24},
            {
                platform: sum(
                    item["platform"] == platform for item in instances
                )
                for platform in {"AWS", "AZURE", "GCP"}
            },
        )
        self.assertTrue(all(
            instance["platform"] in {"AWS", "AZURE", "GCP"}
            for instance in instances
        ))


if __name__ == "__main__":
    unittest.main()
