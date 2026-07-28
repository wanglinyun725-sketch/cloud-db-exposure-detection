import json
from pathlib import Path
import tempfile
import unittest

import yaml

from src.experiments.ec_react_preflight import (
    _validate_external_action_prior_config,
    _validate_negative_release,
    _validate_path_ontology_config,
    _validate_splits,
    run_preflight,
)
from tests.test_frozen_negative_control_environment import _reviewed_negative


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "pilot_round1_unlabeled.json"
)


def stable_hash(value):
    from hashlib import sha256

    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class ECReactPreflightTests(unittest.TestCase):
    def test_project_config_refuses_missing_human_gold_and_keys(self):
        report = run_preflight(ROOT, CONFIG, environ={})

        self.assertFalse(report["ready"])
        self.assertTrue(any(
            "human gold release is missing" in blocker
            for blocker in report["blockers"]
        ))
        self.assertTrue(any(
            "human annotation pilot release is missing" in blocker
            for blocker in report["blockers"]
        ))
        self.assertTrue(report["annotation_pilot_gate"]["configured"])
        self.assertFalse(report["annotation_pilot_gate"]["passes"])
        self.assertTrue(any(
            "DASHSCOPE_API_KEY" in blocker
            for blocker in report["blockers"]
        ))
        self.assertFalse(report["secrets_in_report"])
        self.assertEqual(
            "cloud_data_path_v1",
            report["path_ontology"]["reference"]["ontology_id"],
        )

    def test_ontology_hash_mismatch_is_a_hard_preflight_blocker(self):
        blockers = []
        summary = _validate_path_ontology_config(
            ROOT,
            {
                "protocol_version": "0.3",
                "path_ontology": {
                    "path": "configs/path_ontology_v1.json",
                    "ontology_id": "cloud_data_path_v1",
                    "sha256": "0" * 64,
                    "require_canonical_gold": True,
                    "require_canonical_agent_output": True,
                    "primary_match": "canonical_fine_exact",
                    "coarse_match_reporting": "sensitivity_only",
                },
            },
            {"path_ontology_id": "cloud_data_path_v1"},
            blockers,
        )

        self.assertTrue(summary["configured"])
        self.assertTrue(any("SHA-256" in item for item in blockers))

    def test_external_prior_hash_mismatch_is_a_hard_blocker(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        declared = dict(config["external_action_prior"])
        declared["sha256"] = "0" * 64
        blockers = []

        summary = _validate_external_action_prior_config(
            ROOT,
            {
                "protocol_version": "0.3",
                "external_action_prior": declared,
            },
            config["shared_execution"],
            blockers,
        )

        self.assertTrue(summary["configured"])
        self.assertTrue(any("SHA-256" in item for item in blockers))

    def test_ready_synthetic_release_uses_group_safe_split(self):
        packet = json.loads(PACKET.read_text(encoding="utf-8"))
        packet_sha = stable_hash(packet)
        source = packet["cases"][0]["source"]
        candidate_metadata = {
            "independence_group": "source-case-1",
        }
        source_context = {
            "source": source,
            "candidate_metadata": candidate_metadata,
        }
        case_id = packet["cases"][0]["case_id"]
        release = {
            "release_version": "human-annotation-0.1",
            "packet_sha256": packet_sha,
            "cases": [
                {
                    "case_id": case_id,
                    "source": source,
                    "candidate_metadata": candidate_metadata,
                    "source_context_fields": sorted(source_context),
                    "source_context_sha256": stable_hash(
                        source_context
                    ),
                    "annotation": {
                        "status": "rejected",
                        "label_origin": "human_reviewed",
                        "primary_annotator": "human-a",
                        "reviewer": "human-b",
                        "adjudication": None,
                    },
                    "admission_screen": {
                        "external_or_low_privilege_entry_defined": False,
                        "multi_step_path_present": False,
                        "cloud_data_target_present": True,
                        "critical_edges_have_raw_evidence": False,
                        "not_a_near_duplicate": True,
                        "decision": "reject",
                        "rationale": "Two humans rejected this candidate.",
                    },
                    "nodes": [],
                    "edges": [],
                    "path_labels": [],
                    "tool_tasks": [],
                    "instance_labels": [],
                }
            ],
        }
        split = {
            "packet_sha256": packet_sha,
            "assignments": [
                {
                    "case_id": case_id,
                    "independence_group": "source-case-1",
                    "split": "excluded",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source_path = directory / "packet.json"
            release_path = directory / "release.json"
            split_path = directory / "split.json"
            config_path = directory / "config.yaml"
            source_path.write_text(
                json.dumps(packet),
                encoding="utf-8",
            )
            release_path.write_text(
                json.dumps(release),
                encoding="utf-8",
            )
            split_path.write_text(
                json.dumps(split),
                encoding="utf-8",
            )
            config = {
                "protocol_version": "0.1",
                "experiment_id": "test",
                "data": {
                    "source_packet": str(source_path),
                    "gold_release": str(release_path),
                    "split_manifest": str(split_path),
                    "minimum_finalized_cases": 1,
                    "minimum_included_cases": 0,
                    "minimum_independence_groups": 0,
                    "minimum_runtime_backed_cases": 0,
                    "minimum_frozen_test_cases": 0,
                    "statistical_unit": "independence_group",
                    "allowed_splits": ["excluded"],
                },
                "shared_execution": {
                    "tool_schema_id": "test-tools",
                    "output_contract_id": "test-path-output",
                    "pareto_action_space_id": (
                        "cross_tool_visible_sigma_v0.3"
                    ),
                    "external_action_prior_id": (
                        "sigma_cloud_operation_prior_v1"
                    ),
                    "task_mode": "path_discovery",
                    "max_steps": 2,
                    "max_path_candidates": 1,
                    "hard_budget_enforced": True,
                    "executable_evidence_tests": True,
                    "budget_grid": [1],
                    "llm_repeats": 5,
                    "deterministic_repeats": 1,
                },
                "methods": [
                    {
                        "method_id": "fixed",
                        "family": "deterministic",
                        "tool_schema_id": "test-tools",
                        "max_steps": 2,
                        "max_path_candidates": 1,
                        "output_contract_id": "test-path-output",
                        "pareto_guard": False,
                        "external_rule_prior": False,
                        "four_value_memory": False,
                        "budget_stop": False,
                        "evidence_citation_guard": False,
                        "finish_guard_mode": "record",
                    }
                ],
                "models": [],
                "statistics": {
                    "cluster_bootstrap_resamples": 1000,
                    "paired_permutation_resamples": 1000,
                },
                "reporting": {
                    "forbid_smoke_as_effectiveness_result": True,
                },
            }
            config_path.write_text(
                yaml.safe_dump(config),
                encoding="utf-8",
            )

            report = run_preflight(
                ROOT,
                config_path,
                environ={},
            )

        self.assertTrue(report["ready"], report["blockers"])
        self.assertEqual(0, report["planned_runs_if_ready"])
        self.assertEqual(
            0,
            report["planned_runs_at_minimum_case_target"],
        )
        self.assertEqual(1, report["split_summary"]["independence_groups"])

    def test_excluded_duplicate_does_not_create_false_split_leakage(self):
        release = {
            "cases": [
                {
                    "case_id": "accepted",
                    "source": {"provenance_level": "B"},
                    "admission_screen": {"decision": "accept"},
                },
                {
                    "case_id": "rejected",
                    "source": {"provenance_level": "C"},
                    "admission_screen": {"decision": "reject"},
                },
            ]
        }
        manifest = {
            "packet_sha256": "packet",
            "assignments": [
                {
                    "case_id": "accepted",
                    "independence_group": "same-upstream-family",
                    "split": "test",
                },
                {
                    "case_id": "rejected",
                    "independence_group": "same-upstream-family",
                    "split": "excluded",
                },
            ],
        }
        blockers = []

        summary = _validate_splits(
            manifest,
            release,
            "packet",
            {"test", "excluded"},
            1,
            blockers,
        )

        self.assertFalse(
            any("cross splits" in item for item in blockers),
            blockers,
        )
        self.assertEqual(1, summary["independence_groups"])

    def test_reviewed_negative_release_passes_human_and_runtime_gate(self):
        packet_path = (
            ROOT
            / "data"
            / "real_sources"
            / "annotation"
            / "negative_control_round1_unlabeled.json"
        )
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        blockers = []
        summary = _validate_negative_release(
            {
                "release_kind": (
                    "human_screened_external_negative_controls"
                ),
                "packet_sha256": stable_hash(packet),
                "cases": [_reviewed_negative()],
            },
            stable_hash(packet),
            1,
            blockers,
        )

        self.assertEqual([], blockers)
        self.assertEqual(1, summary["usable_negative_controls"])
        self.assertEqual(1, summary["usable_runtime_instances"])


if __name__ == "__main__":
    unittest.main()
