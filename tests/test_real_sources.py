import hashlib
import json
import unittest
from pathlib import Path

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
REAL_ROOT = ROOT / "data" / "real_sources"


class RealSourceIntegrityTests(unittest.TestCase):
    def test_acquisition_manifest_has_no_run_time_drift_fields(self):
        manifest = json.loads(
            (
                REAL_ROOT / "acquisition_manifest.json"
            ).read_text(encoding="utf-8")
        )

        self.assertNotIn("generated_at", manifest)
        self.assertTrue(
            manifest["policy"]["manifest_is_deterministic"]
        )
        self.assertTrue(
            manifest["policy"]["download_status_is_not_recorded"]
        )
        self.assertTrue(all(
            artifact["status"] == "verified"
            for source in manifest["sources"]
            for artifact in source["artifacts"]
        ))

    def test_source_registry_has_no_pending_provenance_fields(self):
        registry = yaml.safe_load(
            (REAL_ROOT / "source_registry.yaml").read_text(encoding="utf-8")
        )

        self.assertGreaterEqual(len(registry["sources"]), 4)
        for source in registry["sources"]:
            with self.subTest(source=source["source_id"]):
                for field in registry["policy"]["required_fields"]:
                    self.assertIn(field, source)
                    self.assertNotEqual("pending", source[field])
                self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")

    def test_acquired_artifacts_match_pinned_hashes(self):
        manifest_path = REAL_ROOT / "acquisition_manifest.json"
        if not manifest_path.exists():
            self.skipTest("run scripts/data/acquire_real_sources.py first")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        for source in manifest["sources"]:
            for artifact in source["artifacts"]:
                with self.subTest(
                    source=source["source_id"], artifact=artifact["name"]
                ):
                    path = ROOT / artifact["relative_path"]
                    if not path.exists():
                        self.skipTest(
                            "raw artifacts are intentionally not versioned; "
                            "run scripts/data/acquire_real_sources.py"
                        )
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    self.assertEqual(artifact["sha256"], digest)
                    self.assertEqual(artifact["bytes"], path.stat().st_size)
                    if artifact.get("upstream_checksum", "").startswith("md5:"):
                        upstream_md5 = hashlib.md5(path.read_bytes()).hexdigest()
                        self.assertEqual(
                            artifact["upstream_checksum"],
                            f"md5:{upstream_md5}",
                        )
                    if artifact.get("upstream_checksum", "").startswith(
                        "sha256:"
                    ):
                        self.assertEqual(
                            artifact["upstream_checksum"],
                            f"sha256:{digest}",
                        )

    def test_pilot_observations_are_unlabeled_and_traceable(self):
        index = json.loads(
            (REAL_ROOT / "pilot_observation_index.json").read_text(encoding="utf-8")
        )

        self.assertGreater(index["summary"]["observations"], 0)
        for observation in index["observations"]:
            with self.subTest(observation=observation["observation_id"]):
                self.assertIsNone(observation["path_label"])
                self.assertIsNone(observation["evidence_state"])
                self.assertRegex(
                    observation["raw_ref"]["sha256"], r"^[0-9a-f]{64}$"
                )
                self.assertIsInstance(
                    observation["raw_ref"]["record_index"], int
                )

    def test_cross_cloud_source_has_paired_payload_controls(self):
        audit = json.loads(
            (REAL_ROOT / "source_audit.json").read_text(encoding="utf-8")
        )
        summary = audit["source_summaries"][
            "cross_cloud_observability_2026"
        ]
        candidates = audit["catalogues"]["cross_cloud_observability_2026"]

        self.assertEqual(35, summary["source_declared_subscription_attacks"])
        self.assertEqual(8327, sum(summary["json_log_files"].values()))
        self.assertEqual(36, summary["cloud_data_candidate_groups"])
        self.assertEqual(36, summary["paired_candidate_groups"])
        self.assertTrue(all(
            item["has_payload_control_pair"] for item in candidates
        ))

        pilot = [
            item for item in audit["pilot_annotation_candidates"]
            if item["source_id"] == "cross_cloud_observability_2026"
        ]
        self.assertEqual(6, len(pilot))
        self.assertEqual(
            {
                "crosscloud-family:automated_exfiltration",
                "crosscloud-family:credentials_from_password_stores",
            },
            {item["independence_group"] for item in pilot},
        )

    def test_incident_reports_are_registered_only_as_negative_control_candidates(self):
        registry = yaml.safe_load(
            (REAL_ROOT / "source_registry.yaml").read_text(encoding="utf-8")
        )
        source = next(
            item for item in registry["sources"]
            if item["source_id"] == "cloud_incident_reports_2016_2024"
        )
        audit = json.loads(
            (REAL_ROOT / "source_audit.json").read_text(encoding="utf-8")
        )
        summary = audit["source_summaries"][
            "cloud_incident_reports_2016_2024"
        ]

        self.assertEqual(
            "approved_as_external_negative_control_candidate",
            source["inclusion_status"],
        )
        self.assertEqual(3087, summary["source_reports"])
        self.assertEqual(996, summary["cloud_data_keyword_candidates"])
        self.assertEqual(4, summary["candidates_with_security_terms"])

    def test_schema_forbids_ai_or_script_as_label_origin(self):
        schema = json.loads(
            (REAL_ROOT / "realpathbench_v2_schema.json").read_text(encoding="utf-8")
        )
        annotation_schema = schema["properties"]["annotation"]
        allowed = annotation_schema["properties"]["label_origin"]["enum"]

        self.assertEqual(
            [None, "human_primary", "human_reviewed", "human_adjudicated"],
            allowed,
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(
                {
                    "status": "primary_complete",
                    "label_origin": "ai_generated",
                    "primary_annotator": "model",
                    "reviewer": None,
                    "adjudication": None,
                },
                annotation_schema,
            )

    def test_pending_case_is_unlabeled_and_completed_statuses_require_human_origin(self):
        schema = json.loads(
            (REAL_ROOT / "realpathbench_v2_schema.json").read_text(encoding="utf-8")
        )
        annotation_schema = schema["properties"]["annotation"]
        pending = {
            "status": "pending",
            "label_origin": None,
            "primary_annotator": None,
            "reviewer": None,
            "adjudication": None,
        }

        jsonschema.validate(pending, annotation_schema)

        pending["label_origin"] = "human_primary"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(pending, annotation_schema)

        pending["status"] = "primary_complete"
        jsonschema.validate(pending, annotation_schema)

        pending["label_origin"] = None
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(pending, annotation_schema)

    def test_edge_schema_requires_typed_support_and_refutation_for_conflict(self):
        schema = json.loads(
            (REAL_ROOT / "realpathbench_v2_schema.json").read_text(encoding="utf-8")
        )
        edge_schema = schema["properties"]["edges"]["items"]
        base = {
            "edge_id": "edge-1",
            "source": "actor",
            "target": "database",
            "type": "accessed",
            "raw_refs": ["sha256:artifact#record=1"],
            "annotator_rationale": "Two source-grounded observations disagree.",
        }
        support = {
            "evidence_id": "obs-support",
            "polarity": "support",
            "raw_ref": "sha256:artifact#record=1",
            "query_cost": 1,
            "source": "audit",
        }
        refute = {
            "evidence_id": "obs-refute",
            "polarity": "refute",
            "raw_ref": "sha256:artifact#record=2",
            "query_cost": 1,
            "source": "policy",
        }

        jsonschema.validate(
            {
                **base,
                "evidence_state": "Conflict",
                "evidence_items": [support, refute],
            },
            edge_schema,
        )

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(
                {
                    **base,
                    "evidence_state": "Conflict",
                    "evidence_items": [support],
                },
                edge_schema,
            )

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(
                {
                    **base,
                    "evidence_state": "Supported",
                    "evidence_items": [support, refute],
                },
                edge_schema,
            )

        jsonschema.validate(
            {
                **base,
                "evidence_state": "Unknown",
                "evidence_items": [],
            },
            edge_schema,
        )


if __name__ == "__main__":
    unittest.main()
