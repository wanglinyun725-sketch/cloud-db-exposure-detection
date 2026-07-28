import json
import tempfile
import unittest
from pathlib import Path

from scripts.experiments.run_cp_cert_experiments import (
    ROOT,
    evaluate_case,
    run,
)


def evidence_item(evidence_id, polarity, record, cost=1):
    return {
        "evidence_id": evidence_id,
        "polarity": polarity,
        "raw_ref": f"sha256:artifact#record={record}",
        "query_cost": cost,
        "source": "audit",
    }


def reviewed_case():
    return {
        "case_id": "human-reviewed-fixture",
        "source": {
            "source_id": "test-source",
            "upstream_url": "https://example.org/source",
            "version_or_commit": "v1",
            "license": "test-only",
            "provenance_level": "B",
            "raw_artifacts": [
                {
                    "raw_ref": "fixture.json",
                    "sha256": "a" * 64,
                }
            ],
        },
        "annotation": {
            "status": "reviewed",
            "label_origin": "human_reviewed",
            "primary_annotator": "annotator-a",
            "reviewer": "annotator-b",
            "adjudication": None,
        },
        "nodes": [
            {"id": "actor", "type": "Identity", "raw_refs": ["fixture#actor"]},
            {"id": "db", "type": "Database", "raw_refs": ["fixture#db"]},
        ],
        "edges": [
            {
                "edge_id": "entry",
                "source": "actor",
                "target": "db",
                "type": "can_connect",
                "evidence_state": "Supported",
                "evidence_items": [
                    evidence_item("support-shared", "support", 1, cost=2)
                ],
                "raw_refs": ["sha256:artifact#record=1"],
                "annotator_rationale": "Reviewed support observation.",
            },
            {
                "edge_id": "permission",
                "source": "actor",
                "target": "db",
                "type": "has_permission",
                "evidence_state": "Supported",
                "evidence_items": [
                    evidence_item("support-permission", "support", 2)
                ],
                "raw_refs": ["sha256:artifact#record=2"],
                "annotator_rationale": "Reviewed permission observation.",
            },
        ],
        "path_labels": [
            {
                "path_id": "p1",
                "node_ids": ["actor", "db"],
                "edge_ids": ["entry", "permission"],
                "state": "Valid",
                "certificate_raw_refs": [
                    "sha256:artifact#record=1",
                    "sha256:artifact#record=2",
                ],
            }
        ],
        "tool_tasks": [],
    }


class CPCertExperimentGateTests(unittest.TestCase):
    def test_reviewed_case_produces_audited_exact_and_greedy_rows(self):
        result = evaluate_case(reviewed_case())

        self.assertEqual(2, len(result["certificates"]))
        self.assertEqual(
            {"exact", "greedy"},
            {row["method"] for row in result["certificates"]},
        )
        self.assertTrue(all(
            row["audit"]["sufficient"] and row["audit"]["irreducible"]
            for row in result["certificates"]
        ))

    def test_pending_real_packet_is_refused_and_writes_no_result(self):
        packet = (
            ROOT
            / "data"
            / "real_sources"
            / "annotation"
            / "pilot_round1_unlabeled.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            with self.assertRaisesRegex(ValueError, "not reviewed/adjudicated"):
                run(packet, output)
            self.assertFalse(output.exists())

    def test_declared_path_state_must_match_recomputed_state(self):
        case = reviewed_case()
        case["path_labels"][0]["state"] = "Invalid"

        with self.assertRaisesRegex(ValueError, "declared path state"):
            evaluate_case(case)


if __name__ == "__main__":
    unittest.main()
