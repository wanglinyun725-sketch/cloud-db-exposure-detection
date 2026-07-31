from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import unittest

from scripts.data.build_runtime_annotation_pilot import (
    CONFIG_V2_PATH,
    OUTPUT_V2_PATH,
    build_runtime_pilot,
)
from src.annotation.workflow import create_assignment


class RuntimeAnnotationPilotV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(
            OUTPUT_V2_PATH.read_text(encoding="utf-8")
        )

    def test_v2_is_exact_frozen_label_independent_build(self):
        self.assertEqual(
            self.artifact,
            build_runtime_pilot(CONFIG_V2_PATH),
        )
        self.assertEqual(
            "runtime_annotation_pilot_v1",
            self.artifact["supersedes"]["protocol_id"],
        )
        self.assertEqual(0, self.artifact["summary"]["human_gold_cases"])

    def test_v2_has_three_runtime_sources_and_expected_balance(self):
        cases = self.artifact["cases"]
        instances = [
            instance
            for case in cases
            for instance in case["runtime_instances"]
        ]
        self.assertEqual(23, len(cases))
        self.assertEqual(35, len(instances))
        self.assertEqual(14, self.artifact["summary"][
            "independence_group_count"
        ])
        self.assertEqual(389, sum(
            instance["observation_count"] for instance in instances
        ))
        self.assertEqual(
            Counter({
                "cross_cloud_observability_2026": 12,
                "splunk_attack_data": 7,
                "stratus_red_team": 4,
            }),
            Counter(case["source"]["source_id"] for case in cases),
        )
        self.assertEqual(
            Counter({"AWS": 18, "AZURE": 9, "GCP": 8}),
            Counter(instance["platform"] for instance in instances),
        )

    def test_v2_blind_assignments_contain_no_labels_or_conditions(self):
        for role, annotator in (
            ("primary", "human-01"),
            ("reviewer", "human-02"),
        ):
            assignment = create_assignment(
                deepcopy(self.artifact), role, annotator
            )
            payload = json.dumps(assignment, ensure_ascii=False)
            self.assertNotIn("episode_refs", payload)
            self.assertNotIn("source_condition", payload)
            self.assertNotIn("payload_present", payload)
            self.assertNotIn("payload_absent", payload)
            self.assertTrue(all(
                not case["nodes"]
                and not case["edges"]
                and not case["path_labels"]
                and not case["tool_tasks"]
                and not case["instance_labels"]
                for case in assignment["cases"]
            ))


if __name__ == "__main__":
    unittest.main()
