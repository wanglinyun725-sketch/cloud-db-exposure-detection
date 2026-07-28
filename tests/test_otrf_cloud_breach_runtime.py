from hashlib import sha256
import json
from pathlib import Path
import unittest
from zipfile import ZipFile

from scripts.data.profile_otrf_cloud_breach_runtime import (
    EXPECTED_MEMBER,
    OUTPUT_PATH,
    build_index,
)


ROOT = Path(__file__).resolve().parents[1]


class OtrfCloudBreachRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))

    def test_index_is_exact_and_source_grounded(self):
        self.assertEqual(self.index, build_index())
        self.assertEqual(103, self.index["summary"]["cloudtrail_events"])
        self.assertEqual(26, self.index["summary"]["unique_operations"])
        self.assertEqual(6, self.index["summary"]["unique_services"])
        self.assertEqual(
            "cloudgoat:aws:cloud_breach_s3",
            self.index["candidate_association"]["candidate_id"],
        )
        self.assertFalse(
            self.index["policy"]["independent_attack_scenario"]
        )

    def test_member_and_every_observation_are_hash_bound_and_unlabeled(self):
        artifact = self.index["source_archive"]
        archive_path = ROOT / artifact["relative_path"]
        self.assertEqual(
            artifact["sha256"],
            sha256(archive_path.read_bytes()).hexdigest(),
        )
        with ZipFile(archive_path) as archive:
            raw = archive.read(EXPECTED_MEMBER)
        self.assertEqual(
            self.index["log_member"]["sha256"],
            sha256(raw).hexdigest(),
        )
        self.assertTrue(all(
            event["raw_ref"]["archive_sha256"] == artifact["sha256"]
            and event["raw_ref"]["member_sha256"]
            == self.index["log_member"]["sha256"]
            and event["path_label"] is None
            and event["evidence_state"] is None
            for event in self.index["observations"]
        ))

    def test_qualified_runtime_is_not_silently_added_to_frozen_v2_pool(self):
        packet = json.loads(
            (
                ROOT
                / "data"
                / "real_sources"
                / "annotation"
                / "expanded_full_pool_unlabeled.json"
            ).read_text(encoding="utf-8")
        )
        case = next(
            item for item in packet["cases"]
            if item["case_id"] == "cloudgoat:aws:cloud_breach_s3"
        )
        self.assertFalse(case["runtime_instances"])
        self.assertEqual("C", case["source"]["provenance_level"])


if __name__ == "__main__":
    unittest.main()
