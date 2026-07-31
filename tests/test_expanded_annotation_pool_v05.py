import json
import unittest

from scripts.data.export_expanded_annotation_pool import (
    V05_OUTPUT_PATH,
    build_expanded_pool,
)


class ExpandedAnnotationPoolV05Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = json.loads(
            V05_OUTPUT_PATH.read_text(encoding="utf-8")
        )

    def test_v05_is_exact_detail_preserving_revision(self):
        self.assertEqual(
            self.packet,
            build_expanded_pool(
                include_qualified_otrf=True,
                runtime_admissible_only=True,
                hydrate_cross_cloud_details=True,
            ),
        )
        summary = self.packet["summary"]
        self.assertEqual("0.5", self.packet["packet_version"])
        self.assertEqual(150, summary["candidate_cases"])
        self.assertEqual(113, len({
            case["candidate_metadata"]["independence_group"]
            for case in self.packet["cases"]
        }))
        self.assertEqual(91, summary["runtime_instances"])
        self.assertEqual(
            70, summary["cross_cloud_detail_hydrated_instances"]
        )

    def test_every_cross_cloud_observation_has_blind_source_detail(self):
        instances = [
            instance
            for case in self.packet["cases"]
            if case["source"]["source_id"]
            == "cross_cloud_observability_2026"
            for instance in case["runtime_instances"]
        ]
        observations = [
            item
            for instance in instances
            for item in instance["observations"]
        ]
        self.assertEqual(70, len(instances))
        self.assertTrue(observations)
        self.assertTrue(all(
            item.get("schema")
            and "request" in item
            and "response" in item
            and item.get("raw_ref", {}).get("sha256")
            and item.get("path_label") is None
            and item.get("evidence_state") is None
            for item in observations
        ))
        serialized = json.dumps(
            instances, ensure_ascii=False
        ).casefold()
        self.assertNotIn("payload_present", serialized)
        self.assertNotIn("payload_absent", serialized)


if __name__ == "__main__":
    unittest.main()
