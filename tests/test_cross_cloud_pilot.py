import unittest

from scripts.data.profile_cross_cloud_pilot import build_index


class CrossCloudPilotTests(unittest.TestCase):
    def test_pilot_has_complete_source_published_payload_pairs(self):
        index = build_index()
        summary = index["summary"]

        self.assertEqual(6, summary["candidate_groups"])
        self.assertEqual(2, summary["independence_groups"])
        self.assertEqual(240, summary["episodes"])
        self.assertEqual(120, summary["paired_runs"])
        self.assertEqual(
            {"payload_present": 120, "payload_absent": 120},
            summary["condition_episode_counts"],
        )
        self.assertGreater(summary["observations"], 0)
        for episode in index["episodes"]:
            with self.subTest(episode=episode["episode_id"]):
                self.assertIsNone(episode["path_label"])
                self.assertIsNone(episode["evidence_state"])
                self.assertRegex(
                    episode["raw_ref"]["archive_sha256"],
                    r"^[0-9a-f]{64}$",
                )
                self.assertRegex(
                    episode["raw_ref"]["member_sha256"],
                    r"^[0-9a-f]{64}$",
                )

    def test_full_pool_expands_to_twelve_independent_attack_families(self):
        index = build_index(scope="full")
        summary = index["summary"]

        self.assertEqual(36, summary["candidate_groups"])
        self.assertEqual(12, summary["independence_groups"])
        self.assertEqual(1424, summary["episodes"])
        self.assertEqual(712, summary["paired_runs"])
        self.assertEqual(
            {"payload_present": 712, "payload_absent": 712},
            summary["condition_episode_counts"],
        )
        self.assertEqual(5, summary["unpaired_run_keys_excluded"])
        self.assertEqual(5, summary["unpaired_episode_files_excluded"])
        self.assertEqual(
            12,
            len({item["attack"] for item in index["episodes"]}),
        )
        pair_counts = {}
        for episode in index["episodes"]:
            key = (
                episode["candidate_id"],
                episode["log_profile"],
                episode["run_id"],
            )
            pair_counts[key] = pair_counts.get(key, 0) + 1
            self.assertIsNone(episode["path_label"])
            self.assertIsNone(episode["evidence_state"])
        self.assertTrue(all(count == 2 for count in pair_counts.values()))


if __name__ == "__main__":
    unittest.main()
