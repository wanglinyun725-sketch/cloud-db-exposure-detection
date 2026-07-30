from copy import deepcopy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.experiments.run_cp_cert_experiments import (
    ROOT,
    _cp_cert_claim_gate,
    _stable_hash,
    evaluate_case,
    run,
    summarize,
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
        "candidate_metadata": {
            "independence_group": "fixture-lineage-1",
        },
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
            row["audit"]["valid"]
            for row in result["certificates"]
        ))
        self.assertEqual(
            "fixture-lineage-1",
            result["independence_group"],
        )

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

    def test_independence_group_is_required_for_inference(self):
        case = reviewed_case()
        del case["candidate_metadata"]

        with self.assertRaisesRegex(ValueError, "independence_group"):
            evaluate_case(case)

    def test_summary_collapses_cases_within_lineage_before_ci(self):
        first = evaluate_case(reviewed_case())
        second_case = deepcopy(reviewed_case())
        second_case["case_id"] = "same-lineage-second-case"
        second = evaluate_case(second_case)

        summary = summarize([first, second])

        self.assertEqual(2, summary["independent_cases"])
        self.assertEqual(1, summary["independence_groups"])
        self.assertTrue(summary["pseudo_replication_guard"])
        self.assertEqual(
            1,
            summary["by_method"]["exact"]["group_level_metrics"][
                "total_cost"
            ]["independence_groups"],
        )
        self.assertIn(
            "total_cost",
            summary["paired_exact_minus_greedy"]["metrics"],
        )

    def test_frozen_manifest_selects_only_held_out_accepted_cases(self):
        development = reviewed_case()
        development["case_id"] = "development-case"
        development["candidate_metadata"]["independence_group"] = "g-dev"
        development["admission_screen"] = {"decision": "accept"}
        held_out = reviewed_case()
        held_out["case_id"] = "held-out-case"
        held_out["candidate_metadata"]["independence_group"] = "g-test"
        held_out["admission_screen"] = {"decision": "accept"}
        rejected = reviewed_case()
        rejected["case_id"] = "rejected-case"
        rejected["candidate_metadata"]["independence_group"] = "g-reject"
        rejected["annotation"]["status"] = "rejected"
        rejected["path_labels"] = []
        rejected["admission_screen"] = {"decision": "reject"}
        release = {
            "packet_sha256": "e" * 64,
            "cases": [development, held_out, rejected],
        }
        manifest = {
            "packet_sha256": release["packet_sha256"],
            "gold_release_sha256": _stable_hash(release),
            "assignments": [
                {
                    "case_id": "development-case",
                    "independence_group": "g-dev",
                    "split": "development",
                },
                {
                    "case_id": "held-out-case",
                    "independence_group": "g-test",
                    "split": "test",
                },
                {
                    "case_id": "rejected-case",
                    "independence_group": "g-reject",
                    "split": "excluded",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            input_path = base / "release.json"
            split_path = base / "split.json"
            output_path = base / "result.json"
            input_path.write_text(json.dumps(release), encoding="utf-8")
            split_path.write_text(json.dumps(manifest), encoding="utf-8")

            report = run(
                input_path,
                output_path,
                split_manifest_path=split_path,
            )

        self.assertEqual(["test"], report["selected_splits"])
        self.assertEqual(
            ["held-out-case"],
            [item["case_id"] for item in report["cases"]],
        )
        self.assertFalse(report["research_effectiveness_result"])
        self.assertFalse(
            report["cp_cert_claim_gate"]["gates"][
                "minimum_independence_groups"
            ]
        )

    def test_frozen_manifest_refuses_release_or_group_drift(self):
        case = reviewed_case()
        case["admission_screen"] = {"decision": "accept"}
        release = {
            "packet_sha256": "f" * 64,
            "cases": [case],
        }
        assignment = {
            "case_id": case["case_id"],
            "independence_group": "fixture-lineage-1",
            "split": "test",
        }
        manifest = {
            "packet_sha256": release["packet_sha256"],
            "gold_release_sha256": "0" * 64,
            "assignments": [assignment],
        }

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            input_path = base / "release.json"
            split_path = base / "split.json"
            input_path.write_text(json.dumps(release), encoding="utf-8")
            split_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "gold release hash"):
                run(
                    input_path,
                    base / "hash-result.json",
                    split_manifest_path=split_path,
                )

            manifest["gold_release_sha256"] = _stable_hash(release)
            manifest["assignments"][0]["independence_group"] = "wrong"
            split_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "group mismatch"):
                run(
                    input_path,
                    base / "group-result.json",
                    split_manifest_path=split_path,
                )

    def test_claim_gate_requires_complete_oracle_coverage(self):
        metric = {
            "independence_groups": 15,
            "mean": 1.0,
            "ci_low": 1.0,
            "ci_high": 1.0,
        }
        summary = {
            "independence_groups": 15,
            "by_method": {
                "exact": {
                    "group_level_metrics": {
                        "valid_certificate": dict(metric),
                        "raw_ref_complete": dict(metric),
                        "optimality_verified": {
                            **metric,
                            "independence_groups": 14,
                        },
                        "size_reduction": {
                            **metric,
                            "mean": 0.2,
                            "ci_low": 0.1,
                            "ci_high": 0.3,
                        },
                        "cost_reduction": {
                            **metric,
                            "mean": 0.2,
                            "ci_low": 0.1,
                            "ci_high": 0.3,
                        },
                    },
                },
            },
        }

        incomplete = _cp_cert_claim_gate(summary, split_bound=True)
        self.assertFalse(
            incomplete["gates"]["exact_optimality_oracle_verified"]
        )
        self.assertFalse(incomplete["eligible"])

        summary["by_method"]["exact"]["group_level_metrics"][
            "optimality_verified"
        ] = dict(metric)
        complete = _cp_cert_claim_gate(summary, split_bound=True)
        self.assertTrue(complete["eligible"])


if __name__ == "__main__":
    unittest.main()
