import unittest

from scripts.data.export_annotation_packet import (
    build_packet,
    render_markdown,
    validate_packet,
)


class AnnotationPacketTests(unittest.TestCase):
    def test_packet_contains_only_pinned_unlabeled_source_material(self):
        packet = build_packet()

        validate_packet(packet)
        rendered = render_markdown(packet)
        self.assertEqual(11, len(packet["cases"]))
        self.assertIn("payload_present", rendered)
        self.assertEqual(0, packet["policy"]["path_labels_generated"])
        self.assertEqual(0, packet["policy"]["evidence_labels_generated"])
        for case in packet["cases"]:
            with self.subTest(case=case["case_id"]):
                self.assertEqual("pending", case["annotation"]["status"])
                self.assertIsNone(case["annotation"]["label_origin"])
                self.assertEqual([], case["nodes"])
                self.assertEqual([], case["edges"])
                self.assertEqual([], case["path_labels"])
                self.assertTrue(
                    case["observations"] or case["episode_refs"]
                )
                self.assertTrue(all(
                    value is None
                    for value in case["admission_screen"].values()
                ))

        cross_cloud = [
            case for case in packet["cases"]
            if case["source"]["source_id"]
            == "cross_cloud_observability_2026"
        ]
        self.assertEqual(6, len(cross_cloud))
        self.assertEqual(
            240,
            sum(len(case["episode_refs"]) for case in cross_cloud),
        )
        self.assertEqual(
            {"payload_present", "payload_absent"},
            {
                episode["source_condition"]
                for case in cross_cloud
                for episode in case["episode_refs"]
            },
        )

    def test_full_pool_is_unlabeled_and_grouped_by_twelve_attack_families(self):
        packet = build_packet(scope="full")

        validate_packet(packet)
        self.assertEqual("full", packet["policy"]["selection_scope"])
        self.assertEqual(45, len(packet["cases"]))
        self.assertEqual(
            9,
            len([
                case for case in packet["cases"]
                if case["source"]["source_id"] == "splunk_attack_data"
            ]),
        )
        cross_cloud = [
            case for case in packet["cases"]
            if case["source"]["source_id"]
            == "cross_cloud_observability_2026"
        ]
        self.assertEqual(36, len(cross_cloud))
        self.assertEqual(
            12,
            len({
                case["candidate_metadata"]["independence_group"]
                for case in cross_cloud
            }),
        )
        self.assertEqual(
            1424,
            sum(len(case["episode_refs"]) for case in cross_cloud),
        )
        for case in packet["cases"]:
            self.assertEqual("pending", case["annotation"]["status"])
            self.assertIsNone(case["annotation"]["label_origin"])
            self.assertEqual([], case["nodes"])
            self.assertEqual([], case["edges"])
            self.assertEqual([], case["path_labels"])


if __name__ == "__main__":
    unittest.main()
