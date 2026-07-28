from hashlib import sha256
import json
from pathlib import Path
import unittest
from zipfile import ZipFile

from scripts.data.profile_stratus_detonation_logs import (
    OUTPUT_PATH,
    build_index,
)


class StratusDetonationLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))

    def test_index_is_exact_deterministic_build(self):
        self.assertEqual(self.index, build_index())
        self.assertEqual(
            {
                "detonation_log_files": 35,
                "cloudtrail_events": 310,
                "routed_cloud_data_cases": 11,
                "routed_cloud_data_events": 139,
                "unrouted_technique_logs": 24,
                "unique_operations": 54,
                "unique_services": 14,
            },
            self.index["summary"],
        )

    def test_upstream_attestation_and_label_boundary_are_explicit(self):
        self.assertIn(
            "real detonation in a test environment",
            self.index["upstream_evidence_statement"],
        )
        self.assertEqual(0, self.index["policy"]["generated_events"])
        self.assertEqual(0, self.index["policy"]["generated_labels"])
        self.assertTrue(all(
            event["path_label"] is None
            and event["evidence_state"] is None
            for case in self.index["cases"]
            for event in case["observations"]
        ))

    def test_every_record_is_bound_to_the_pinned_archive_member(self):
        archive_path = Path(__file__).resolve().parents[1] / self.index[
            "source_archive"
        ]["relative_path"]
        self.assertEqual(
            self.index["source_archive"]["sha256"],
            sha256(archive_path.read_bytes()).hexdigest(),
        )
        with ZipFile(archive_path) as archive:
            member_hashes = {
                case["log_member_path"]: sha256(
                    archive.read(case["log_member_path"])
                ).hexdigest()
                for case in self.index["cases"]
            }
        self.assertTrue(all(
            member_hashes[case["log_member_path"]]
            == case["log_member_sha256"]
            and all(
                event["raw_ref"]["member_sha256"]
                == case["log_member_sha256"]
                and event["candidate_id"]
                == "stratus:" + case["technique"]
                for event in case["observations"]
            )
            for case in self.index["cases"]
        ))


if __name__ == "__main__":
    unittest.main()
