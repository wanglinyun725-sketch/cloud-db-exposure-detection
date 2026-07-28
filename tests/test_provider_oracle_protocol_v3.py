import json
from pathlib import Path
import unittest

from scripts.data.build_provider_oracle_protocol_v3 import build
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
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v3_public.json"
)
GOLD_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v3_gold.json"
)
SPLIT_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v3_splits.json"
)


class ProviderOracleProtocolV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public = json.loads(PUBLIC_PATH.read_text(encoding="utf-8"))
        cls.gold = json.loads(GOLD_PATH.read_text(encoding="utf-8"))

    def test_builder_is_reproducible_and_keeps_gold_separate(self):
        public, gold, splits = build()

        self.assertEqual(
            public,
            json.loads(PUBLIC_PATH.read_text(encoding="utf-8")),
        )
        self.assertEqual(
            gold,
            json.loads(GOLD_PATH.read_text(encoding="utf-8")),
        )
        self.assertEqual(
            splits,
            json.loads(SPLIT_PATH.read_text(encoding="utf-8")),
        )
        public_text = json.dumps(public, ensure_ascii=False)
        self.assertNotIn('"gold_state"', public_text)
        self.assertNotIn('"label_origin"', public_text)
        self.assertNotIn('"support_observation_ids"', public_text)
        self.assertEqual(0, public["policy"]["generated_cloud_events"])
        self.assertEqual(6, len(public["cases"]))
        self.assertEqual(11, len(public["observations"]))
        self.assertEqual(5, gold["provider_oracle_gold_cases"])
        self.assertEqual(1, gold["epistemic_control_cases"])

    def test_environment_blinds_case_and_state_but_exposes_raw_outcome(self):
        metadata = next(
            item
            for item in self.gold["cases"]
            if item["gold_state"] == "NotReachable"
        )
        environment = FrozenProviderOracleEnvironment(
            self.public, metadata, budget=8
        )
        search = environment.execute("search_events", {})
        denied_id = next(
            item["observation_id"]
            for item in search["tool_result"]["events"]
            if item["event_status"] == "Code:7"
        )
        visible = {
            "context": environment.public_context,
            "schema": environment.action_schema(),
            "search": search,
            "detail": environment.execute(
                "get_event_detail",
                {"observation_id": denied_id},
            ),
        }
        text = json.dumps(visible, ensure_ascii=False)

        self.assertNotIn(metadata["case_id"], text)
        self.assertNotIn('"gold_state"', text)
        self.assertEqual(
            ["Reachable", "NotReachable", "Unknown"],
            visible["context"]["allowed_path_states"],
        )
        self.assertIn('"Code:7"', text)
        self.assertIn('"provider_decision": "deny"', text)

    def test_provider_aware_policy_resolves_all_three_states(self):
        observed = {}
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
            observed[metadata["gold_state"]] = score

        self.assertEqual(
            {"Reachable", "NotReachable", "Unknown"},
            set(observed),
        )
        self.assertTrue(all(
            item["semantically_correct_state"]
            for item in observed.values()
        ))
        self.assertTrue(observed["NotReachable"]["correct_rejection"])
        self.assertTrue(observed["Unknown"]["correct_abstention"])


if __name__ == "__main__":
    unittest.main()
