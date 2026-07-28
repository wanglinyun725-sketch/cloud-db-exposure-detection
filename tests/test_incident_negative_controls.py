import unittest

from scripts.data.profile_incident_negative_controls import build_profile


class IncidentNegativeControlTests(unittest.TestCase):
    def test_profile_preserves_real_reports_without_assigning_attack_labels(self):
        profile = build_profile()
        summary = profile["summary"]

        self.assertEqual(3087, summary["source_reports"])
        self.assertEqual(
            {"AWS": 774, "AZURE": 127, "GCP": 2186},
            summary["source_reports_by_vendor"],
        )
        self.assertGreater(summary["cloud_data_keyword_candidates"], 0)
        self.assertEqual(460, summary["author_published_human_labels"])
        self.assertEqual(0, profile["policy"]["generated_labels"])
        self.assertTrue(
            profile["policy"][
                "negative_control_requires_human_confirmation"
            ]
        )
        for candidate in profile["candidates"]:
            with self.subTest(candidate=candidate["candidate_id"]):
                self.assertIsNone(candidate["path_label"])
                self.assertIsNone(candidate["evidence_state"])
                self.assertTrue(all(
                    value is None
                    for value in candidate["human_screening"].values()
                ))
                self.assertRegex(
                    candidate["raw_ref"]["archive_sha256"],
                    r"^[0-9a-f]{64}$",
                )
                self.assertRegex(
                    candidate["raw_ref"]["record_sha256"],
                    r"^[0-9a-f]{64}$",
                )


if __name__ == "__main__":
    unittest.main()
