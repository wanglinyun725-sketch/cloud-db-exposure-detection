import unittest

from scripts.data.export_negative_control_packet import (
    build_packet,
    validate_packet,
)


class NegativeControlPacketTests(unittest.TestCase):
    def test_packet_is_vendor_stratified_source_text_without_labels(self):
        packet = build_packet()

        validate_packet(packet)
        self.assertEqual(30, packet["summary"]["cases"])
        self.assertEqual(29, packet["summary"]["independence_groups"])
        self.assertEqual(
            {"AWS": 10, "AZURE": 10, "GCP": 10},
            packet["summary"]["cases_by_vendor"],
        )
        self.assertEqual(0, packet["policy"]["generated_labels"])
        groups = {
            case["candidate_id"]: case["independence_group"]
            for case in packet["cases"]
        }
        self.assertEqual(
            groups["cloud-incident:gcp:00010"],
            groups["cloud-incident:gcp:00011"],
        )
        self.assertLess(len(set(groups.values())), len(groups))
        for case in packet["cases"]:
            self.assertGreater(len(case["report_text"]), 0)
            self.assertEqual([], case["security_term_hits"])
            self.assertEqual("pending", case["screening"]["status"])
            self.assertIsNone(case["screening"]["label_origin"])
            self.assertTrue(all(
                value is None
                for key, value in case["screening"].items()
                if key != "status"
            ))


if __name__ == "__main__":
    unittest.main()
