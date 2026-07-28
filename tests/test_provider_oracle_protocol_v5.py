import json
from pathlib import Path
import unittest

from scripts.data.build_provider_oracle_protocol_v5 import build
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
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v5_public.json"
)
GOLD_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v5_gold.json"
)
SPLIT_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v5_splits.json"
)


class ProviderOracleProtocolV5Tests(unittest.TestCase):
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
        self.assertNotIn('"refute_observation_ids"', public_text)
        self.assertEqual(13, len(public["cases"]))
        self.assertEqual(8, gold["provider_oracle_gold_cases"])
        self.assertEqual(5, gold["epistemic_control_cases"])
        self.assertEqual(
            11,
            len({item["independence_group"] for item in gold["cases"]}),
        )

    def test_s3_kms_negative_has_exact_denial_and_success_control(self):
        metadata = next(
            item for item in self.gold["cases"]
            if item["case_id"]
            == "oracle-v5:splunk:s3-kms-pending-deletion"
        )
        observations = {
            item["observation_id"]: item
            for item in self.public["observations"]
        }
        denied = observations[metadata["refute_observation_ids"][0]]
        control = observations[metadata["control_observation_ids"][0]]

        self.assertEqual("NotReachable", metadata["gold_state"])
        self.assertEqual(
            "KMS.KMSInvalidStateException", denied["event_status"]
        )
        self.assertEqual("deny", denied["provider_decision"])
        self.assertEqual("Success", control["event_status"])
        self.assertEqual(
            "allow_control_later_state", control["provider_decision"]
        )
        self.assertEqual(denied["actor_id"], control["actor_id"])
        self.assertEqual(denied["request"], control["request"])
        self.assertEqual(
            denied["raw_ref"]["sha256"],
            control["raw_ref"]["sha256"],
        )

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
