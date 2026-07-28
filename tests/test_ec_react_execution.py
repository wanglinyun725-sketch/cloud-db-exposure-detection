from pathlib import Path
import unittest

import yaml

from src.experiments.ec_react_execution import (
    build_run_schedule,
    policy_for_non_llm_method,
    run_frozen_instance,
)
from tests.test_frozen_runtime_environment import _reviewed_splunk_case
from tests.test_frozen_negative_control_environment import _reviewed_negative


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"


class ECReactExecutionTests(unittest.TestCase):
    def test_frozen_non_llm_run_is_scored_and_reproducibly_identified(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        method = next(
            item for item in config["methods"]
            if item["method_id"] == "fixed_order"
        )
        shared = dict(config["shared_execution"])
        shared["orchestration_backend"] = "linear"
        case = _reviewed_splunk_case()
        instance_id = case["runtime_instances"][0]["instance_id"]

        records = []
        for _ in range(2):
            policy = policy_for_non_llm_method(
                "fixed_order",
                seed=1729,
                max_path_candidates=shared["max_path_candidates"],
            )
            records.append(run_frozen_instance(
                case,
                instance_id,
                method=method,
                shared_execution=shared,
                policy=policy,
                budget=10,
                repeat=0,
                seed=1729,
                config_sha256="a" * 64,
            ))

        self.assertTrue(records[0]["research_effectiveness_result"])
        self.assertTrue(records[0]["human_gold_used_for_scoring_only"])
        self.assertFalse(records[0]["secrets_in_record"])
        self.assertEqual(records[0]["run_id"], records[1]["run_id"])
        self.assertEqual(
            records[0]["result_digest"],
            records[1]["result_digest"],
        )
        self.assertEqual(
            instance_id,
            records[0]["score"]["instance_id"],
        )
        self.assertEqual(
            case["source"]["source_id"],
            records[0]["scenario_source_id"],
        )
        self.assertEqual(
            case["source"]["source_id"],
            records[0]["runtime_evidence_source_id"],
        )
        self.assertEqual(
            case["runtime_instances"][0]["platform"],
            records[0]["platform"],
        )

    def test_run_contract_rejects_unfair_output_schema_change(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        method = dict(next(
            item for item in config["methods"]
            if item["method_id"] == "fixed_order"
        ))
        method["output_contract_id"] = "easier-baseline-output"
        case = _reviewed_splunk_case()

        with self.assertRaisesRegex(ValueError, "output contract"):
            run_frozen_instance(
                case,
                case["runtime_instances"][0]["instance_id"],
                method=method,
                shared_execution={
                    **config["shared_execution"],
                    "orchestration_backend": "linear",
                },
                policy=policy_for_non_llm_method(
                    "fixed_order",
                    seed=1,
                    max_path_candidates=5,
                ),
                budget=10,
                repeat=0,
                seed=1,
            )

    def test_run_contract_rejects_unfrozen_pareto_action_space(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        method = next(
            item for item in config["methods"]
            if item["method_id"] == "fixed_order"
        )
        case = _reviewed_splunk_case()

        with self.assertRaisesRegex(ValueError, "Pareto action space"):
            run_frozen_instance(
                case,
                case["runtime_instances"][0]["instance_id"],
                method=method,
                shared_execution={
                    **config["shared_execution"],
                    "orchestration_backend": "linear",
                    "pareto_action_space_id": "operation_only_v0.1",
                },
                policy=policy_for_non_llm_method(
                    "fixed_order",
                    seed=1,
                    max_path_candidates=5,
                ),
                budget=10,
                repeat=0,
                seed=1,
            )

    def test_schedule_uses_runtime_instances_and_frozen_repeat_seeds(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        case = _reviewed_splunk_case()
        schedule = build_run_schedule(
            config,
            {"cases": [case]},
            {
                "assignments": [
                    {
                        "case_id": case["case_id"],
                        "independence_group": "group-1",
                        "split": "test",
                    }
                ]
            },
            splits={"test"},
        )

        # 7 LLM methods * 2 models * 3 budgets * 5 repeats
        # + 1 randomized * 3 * 5 + 2 deterministic * 3 * 1.
        self.assertEqual(231, len(schedule))
        self.assertEqual(
            {1729, 2718, 3141, 5772, 8111},
            {
                item["seed"] for item in schedule
                if item["method_id"] == "vanilla_react"
            },
        )
        self.assertEqual(
            231,
            len({item["schedule_id"] for item in schedule}),
        )
        self.assertEqual(
            {case["source"]["source_id"]},
            {item["scenario_source_id"] for item in schedule},
        )
        self.assertEqual(
            {case["source"]["source_id"]},
            {item["runtime_evidence_source_id"] for item in schedule},
        )

    def test_schedule_adds_reviewed_negatives_only_to_external_control_split(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        case = _reviewed_splunk_case()
        negative = _reviewed_negative()
        schedule = build_run_schedule(
            config,
            {"cases": [case]},
            {
                "assignments": [
                    {
                        "case_id": case["case_id"],
                        "independence_group": "group-1",
                        "split": "test",
                    }
                ]
            },
            negative_release={"cases": [negative]},
            splits={"external_negative_control"},
        )

        self.assertEqual(231, len(schedule))
        self.assertEqual(
            {"external_negative_control"},
            {item["split"] for item in schedule},
        )
        self.assertEqual(
            {negative["case_id"]},
            {item["case_id"] for item in schedule},
        )


if __name__ == "__main__":
    unittest.main()
