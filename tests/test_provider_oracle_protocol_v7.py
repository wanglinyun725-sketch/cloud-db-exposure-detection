import json
from pathlib import Path
import unittest

from scripts.data.build_provider_oracle_protocol_v7 import build
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
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v7_public.json"
)
GOLD_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v7_gold.json"
)
SPLIT_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v7_splits.json"
)


class ProviderOracleProtocolV7Tests(unittest.TestCase):
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
        self.assertNotIn('"negative_certificate"', public_text)
        self.assertEqual(21, len(public["cases"]))
        self.assertEqual(16, gold["provider_oracle_gold_cases"])
        self.assertEqual(5, gold["epistemic_control_cases"])
        self.assertEqual(
            13,
            len({item["independence_group"] for item in gold["cases"]}),
        )
        self.assertEqual(
            4,
            len({
                item["independence_group"] for item in gold["cases"]
                if item["gold_state"] == "NotReachable"
            }),
        )
        source_splits = {}
        for assignment in splits["assignments"]:
            source_splits.setdefault(assignment["source_id"], set()).add(
                assignment["split"]
            )
        self.assertTrue(all(
            len(values) == 1 for values in source_splits.values()
        ))
        groups_by_split = {
            split: {
                item["independence_group"]
                for item in splits["assignments"]
                if item["split"] == split
            }
            for split in ("development", "source_held_out_test")
        }
        self.assertEqual(6, len(groups_by_split["development"]))
        self.assertEqual(
            7, len(groups_by_split["source_held_out_test"])
        )

    def test_new_denials_disclose_missing_success_control(self):
        new_cases = [
            item for item in self.gold["cases"]
            if item["case_id"].startswith(
                "oracle-v7:splunk-accessdenied:"
            )
        ]
        self.assertEqual(5, len(new_cases))
        self.assertEqual(
            1, len({item["independence_group"] for item in new_cases})
        )
        observations = {
            item["observation_id"]: item
            for item in self.public["observations"]
        }
        for metadata in new_cases:
            self.assertEqual([], metadata["control_observation_ids"])
            self.assertEqual(
                "not_available",
                metadata["negative_certificate"][
                    "target_existence_control"
                ],
            )
            denial = observations[metadata["refute_observation_ids"][0]]
            self.assertEqual("AccessDenied", denial["event_status"])

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
