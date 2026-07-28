import json
from pathlib import Path
import unittest

from scripts.data.build_provider_oracle_protocol_v4 import build
from src.agent.baseline_policies import ProviderAwarePathPolicy
from src.agent.ec_react import ECReactRunner
from src.agent.frozen_provider_oracle_environment import (
    FrozenProviderOracleEnvironment,
)
from src.experiments.provider_oracle_scoring import (
    score_provider_oracle_state,
)


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v4_public.json"
)
GOLD_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v4_gold.json"
)
SPLIT_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v4_splits.json"
)


class ProviderOracleProtocolV4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public = json.loads(PUBLIC_PATH.read_text(encoding="utf-8"))
        cls.gold = json.loads(GOLD_PATH.read_text(encoding="utf-8"))

    def test_builder_is_reproducible_and_gold_is_separate(self):
        public, gold, splits = build()

        self.assertEqual(
            public, json.loads(PUBLIC_PATH.read_text(encoding="utf-8"))
        )
        self.assertEqual(
            gold, json.loads(GOLD_PATH.read_text(encoding="utf-8"))
        )
        self.assertEqual(
            splits, json.loads(SPLIT_PATH.read_text(encoding="utf-8"))
        )
        public_text = json.dumps(public, ensure_ascii=False)
        self.assertNotIn('"gold_state"', public_text)
        self.assertNotIn('"label_origin"', public_text)
        self.assertNotIn('"support_observation_ids"', public_text)
        self.assertEqual(12, len(public["cases"]))
        self.assertEqual(7, gold["provider_oracle_gold_cases"])
        self.assertEqual(5, gold["epistemic_control_cases"])
        self.assertEqual(
            10,
            len({item["independence_group"] for item in gold["cases"]}),
        )

    def test_new_runtime_sources_have_exact_success_evidence(self):
        new_cases = {
            item["source_id"]: item for item in self.gold["cases"]
            if item["source_id"] in {
                "stratus_red_team",
                "splunk_attack_data",
            }
        }

        self.assertEqual(
            {"stratus_red_team", "splunk_attack_data"},
            set(new_cases),
        )
        observations = {
            item["observation_id"]: item
            for item in self.public["observations"]
        }
        for metadata in new_cases.values():
            self.assertEqual("Reachable", metadata["gold_state"])
            for observation_id in metadata["support_observation_ids"]:
                observation = observations[observation_id]
                self.assertEqual("Success", observation["event_status"])
                self.assertEqual(
                    "allow", observation["provider_decision"]
                )
                self.assertTrue(observation["raw_ref"])

    def test_all_configuration_controls_remain_unknown(self):
        controls = [
            item for item in self.gold["cases"]
            if item["label_origin"] == "protocol_coverage_control"
        ]

        self.assertEqual(5, len(controls))
        self.assertTrue(all(
            item["gold_state"] == "Unknown"
            and item["gold_tier"] is None
            and not item["support_observation_ids"]
            and not item["refute_observation_ids"]
            for item in controls
        ))

    def test_provider_aware_reference_resolves_every_case(self):
        for metadata in self.gold["cases"]:
            environment = FrozenProviderOracleEnvironment(
                self.public, metadata, budget=4
            )
            result = ECReactRunner(
                ProviderAwarePathPolicy(),
                task_mode="path_discovery",
                max_steps=12,
                max_path_candidates=5,
            ).run(environment, environment.public_context)
            score = score_provider_oracle_state(
                result, environment.evaluation_metadata()
            )
            self.assertTrue(
                score["semantically_correct_state"],
                metadata["case_id"],
            )


if __name__ == "__main__":
    unittest.main()
