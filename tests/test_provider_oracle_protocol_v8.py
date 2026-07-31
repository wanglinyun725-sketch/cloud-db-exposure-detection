import json
from pathlib import Path
import unittest

from scripts.data.build_provider_oracle_protocol_v8 import build
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
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v8_public.json"
)
GOLD_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v8_gold.json"
)
SPLIT_PATH = (
    ROOT / "data" / "real_sources" / "provider_oracle_protocol_v8_splits.json"
)


class ProviderOracleProtocolV8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public = json.loads(PUBLIC_PATH.read_text(encoding="utf-8"))
        cls.gold = json.loads(GOLD_PATH.read_text(encoding="utf-8"))
        cls.gold_by_id = {
            item["case_id"]: item for item in cls.gold["cases"]
        }
        cls.observations = {
            item["observation_id"]: item
            for item in cls.public["observations"]
        }

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
        self.assertNotIn('"positive_certificate"', public_text)
        self.assertNotIn('"negative_certificate"', public_text)
        self.assertNotIn('"unknown_certificate"', public_text)
        self.assertEqual(25, len(public["cases"]))
        self.assertEqual(18, gold["provider_oracle_gold_cases"])
        self.assertEqual(7, gold["epistemic_control_cases"])
        self.assertEqual(
            16,
            len({item["independence_group"] for item in gold["cases"]}),
        )
        self.assertEqual(
            5,
            len({
                item["independence_group"] for item in gold["cases"]
                if item["gold_state"] == "NotReachable"
            }),
        )

    def test_snapshot_pair_has_exact_allow_and_deny_certificates(self):
        positive = self.gold_by_id[
            "oracle-v8:splunk:snapshot-external-share"
        ]
        negative = self.gold_by_id[
            "oracle-v8:splunk:snapshot-invalid-grantee"
        ]
        self.assertEqual(
            positive["independence_group"],
            negative["independence_group"],
        )
        self.assertEqual("provider_oracle_gold_v2", positive[
            "provider_oracle_contract"
        ])
        self.assertEqual("provider_oracle_gold_v2", negative[
            "provider_oracle_contract"
        ])
        self.assertEqual(
            "effective_permission_exposure",
            positive["positive_certificate"]["certificate_type"],
        )
        self.assertFalse(
            positive["positive_certificate"]["mandatory_conditions"][
                "snapshot_encrypted"
            ]
        )
        share = self.observations[positive["support_observation_ids"][0]]
        create = self.observations[positive["control_observation_ids"][0]]
        self.assertEqual("ModifySnapshotAttribute", share["operation"])
        self.assertTrue(share["response"]["_return"])
        self.assertEqual("CreateSnapshot", create["operation"])
        self.assertFalse(create["response"]["encrypted"])

        denial = self.observations[negative["refute_observation_ids"][0]]
        control = self.observations[negative["control_observation_ids"][0]]
        self.assertEqual(
            "Client.InvalidAMIAttributeItemValue",
            denial["error_code"],
        )
        self.assertEqual("deny", denial["provider_decision"])
        self.assertEqual("allow", control["provider_decision"])
        self.assertEqual(
            denial["request"]["snapshotId"],
            control["request"]["snapshotId"],
        )

    def test_successful_control_plane_calls_remain_unknown(self):
        unknown_ids = {
            "oracle-v8:splunk:rds-password-reset-without-query",
            "oracle-v8:splunk:s3-acl-without-effective-access-control",
        }
        for case_id in unknown_ids:
            metadata = self.gold_by_id[case_id]
            self.assertEqual("Unknown", metadata["gold_state"])
            self.assertEqual(
                "protocol_coverage_control",
                metadata["label_origin"],
            )
            self.assertEqual([], metadata["support_observation_ids"])
            self.assertEqual([], metadata["refute_observation_ids"])
            self.assertTrue(metadata["control_observation_ids"])
            for observation_id in metadata["control_observation_ids"]:
                observation = self.observations[observation_id]
                self.assertEqual("Success", observation["event_status"])
                self.assertEqual("allow", observation["provider_decision"])
                self.assertIn(
                    "incomplete",
                    observation["scope_completeness"],
                )

    def test_compact_search_exposes_public_scope_without_gold(self):
        case_id = "oracle-v8:splunk:rds-password-reset-without-query"
        environment = FrozenProviderOracleEnvironment(
            self.public,
            self.gold_by_id[case_id],
            budget=4,
        )

        output = environment.execute(
            "search_events",
            {"operation": "ModifyDBInstance"},
        )

        self.assertEqual(2, len(output["tool_result"]["events"]))
        for event in output["tool_result"]["events"]:
            self.assertEqual(
                "incomplete_for_database_data_plane",
                event["scope_completeness"],
            )
            self.assertEqual(
                "AWS CloudTrail control-plane outcome",
                event["oracle_kind"],
            )
        rendered = json.dumps(output, ensure_ascii=False)
        self.assertNotIn('"gold_state"', rendered)
        self.assertNotIn('"label_origin"', rendered)

    def test_source_and_lineage_split_remain_disjoint(self):
        splits = json.loads(SPLIT_PATH.read_text(encoding="utf-8"))
        source_splits = {}
        group_splits = {}
        for assignment in splits["assignments"]:
            source_splits.setdefault(
                assignment["source_id"], set()
            ).add(assignment["split"])
            group_splits.setdefault(
                assignment["independence_group"], set()
            ).add(assignment["split"])
        self.assertTrue(all(
            len(values) == 1 for values in source_splits.values()
        ))
        self.assertTrue(all(
            len(values) == 1 for values in group_splits.values()
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
        self.assertEqual(10, len(groups_by_split["source_held_out_test"]))

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
