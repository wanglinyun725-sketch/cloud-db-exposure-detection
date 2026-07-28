from copy import deepcopy
import json
from pathlib import Path
import unittest

from src.agent.unlabeled_runtime_environment import (
    UnlabeledRuntimeInstanceEnvironment,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_3_unlabeled.json"
)


class UnlabeledRuntimeEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = json.loads(PACKET.read_text(encoding="utf-8"))

    def _case_by_runtime_source(self, source_id):
        return next(
            case
            for case in self.packet["cases"]
            if any(
                (
                    instance.get("runtime_source_id")
                    or case["source"]["source_id"]
                ) == source_id
                for instance in case["runtime_instances"]
            )
        )

    def test_four_real_runtime_sources_share_one_blind_contract(self):
        for source_id in (
            "cross_cloud_observability_2026",
            "splunk_attack_data",
            "stratus_red_team",
            "otrf_security_datasets",
        ):
            with self.subTest(source_id=source_id):
                case = self._case_by_runtime_source(source_id)
                instance = next(
                    item
                    for item in case["runtime_instances"]
                    if (
                        item.get("runtime_source_id")
                        or case["source"]["source_id"]
                    ) == source_id
                )
                environment = UnlabeledRuntimeInstanceEnvironment(
                    case, instance["instance_id"], budget=None
                )
                summary = environment.execute("summarize_case", {})
                events = environment.execute("search_events", {})
                visible = json.dumps(
                    {
                        "public_context": environment.public_context,
                        "summary": summary,
                        "events": events,
                    },
                    ensure_ascii=False,
                )
                self.assertEqual(
                    instance["observation_count"],
                    summary["tool_result"]["observation_count"],
                )
                self.assertNotIn(case["case_id"], visible)
                self.assertNotIn(instance["instance_id"], visible)
                self.assertEqual(
                    source_id,
                    environment.audit_metadata()[
                        "runtime_evidence_source_id"
                    ],
                )

    def test_nonpending_or_labeled_data_is_rejected(self):
        case = deepcopy(
            self._case_by_runtime_source("splunk_attack_data")
        )
        instance_id = case["runtime_instances"][0]["instance_id"]
        case["annotation"]["status"] = "reviewed"
        with self.assertRaisesRegex(ValueError, "pending"):
            UnlabeledRuntimeInstanceEnvironment(case, instance_id)

        case["annotation"]["status"] = "pending"
        case["nodes"] = [{"id": "not-allowed"}]
        with self.assertRaisesRegex(ValueError, "nodes"):
            UnlabeledRuntimeInstanceEnvironment(case, instance_id)

    def test_empty_upstream_episode_has_valid_empty_result_semantics(self):
        case = next(
            case
            for case in self.packet["cases"]
            if any(
                instance["observation_count"] == 0
                for instance in case["runtime_instances"]
            )
        )
        instance = next(
            item
            for item in case["runtime_instances"]
            if item["observation_count"] == 0
        )
        environment = UnlabeledRuntimeInstanceEnvironment(
            case, instance["instance_id"], budget=10
        )
        summary = environment.execute("summarize_case", {})
        search = environment.execute("search_events", {})
        self.assertEqual(0, summary["tool_result"]["observation_count"])
        self.assertEqual([], search["tool_result"]["events"])
        self.assertIn(
            "Unknown",
            search["tool_result"]["empty_result_semantics"],
        )


if __name__ == "__main__":
    unittest.main()
