from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import unittest

from scripts.data.build_runtime_annotation_pilot import (
    CONFIG_PATH,
    OUTPUT_PATH,
    build_runtime_pilot,
)
from src.annotation.workflow import create_assignment


ROOT = Path(__file__).resolve().parents[1]


class RuntimeAnnotationPilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cls.artifact = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
        cls.base = json.loads(
            (ROOT / cls.config["base_packet"]).read_text(encoding="utf-8")
        )

    def test_frozen_artifact_is_exact_deterministic_build(self):
        self.assertEqual(self.artifact, build_runtime_pilot())
        self.assertEqual(
            "frozen_before_human_labels",
            self.artifact["protocol_status"],
        )
        self.assertEqual(0, self.artifact["summary"]["human_gold_cases"])

    def test_selected_cases_are_unchanged_complete_base_groups(self):
        base_by_id = {case["case_id"]: case for case in self.base["cases"]}
        selected_ids = {
            case["case_id"] for case in self.artifact["cases"]
        }
        for case in self.artifact["cases"]:
            self.assertEqual(base_by_id[case["case_id"]], case)

        selected_groups = {
            case["candidate_metadata"]["independence_group"]
            for case in self.artifact["cases"]
        }
        for case in self.base["cases"]:
            group = case["candidate_metadata"]["independence_group"]
            if group in selected_groups:
                self.assertIn(case["case_id"], selected_ids)

    def test_pilot_is_runtime_backed_balanced_and_group_complete(self):
        cases = self.artifact["cases"]
        instances = [
            instance
            for case in cases
            for instance in case["runtime_instances"]
        ]
        self.assertEqual(19, len(cases))
        self.assertEqual(31, len(instances))
        self.assertEqual(
            Counter({"AWS": 14, "AZURE": 9, "GCP": 8}),
            Counter(instance["platform"] for instance in instances),
        )
        self.assertEqual(
            317,
            sum(instance["observation_count"] for instance in instances),
        )

        grouped = defaultdict(list)
        for case in cases:
            grouped[case["candidate_metadata"]["independence_group"]].append(
                case
            )
        self.assertEqual(10, len(grouped))
        for group, group_cases in grouped.items():
            if group.startswith("crosscloud-family:"):
                self.assertEqual(3, len(group_cases))
                self.assertEqual(
                    {"AWS", "AZURE", "GCP"},
                    {
                        case["candidate_metadata"]["platform"]
                        for case in group_cases
                    },
                )
                self.assertEqual(
                    6,
                    sum(
                        len(case["runtime_instances"])
                        for case in group_cases
                    ),
                )

    def test_no_human_or_generated_labels_exist(self):
        for case in self.artifact["cases"]:
            self.assertEqual("pending", case["annotation"]["status"])
            self.assertIsNone(case["annotation"]["label_origin"])
            self.assertTrue(all(
                value is None
                for value in case["admission_screen"].values()
            ))
            for field in (
                "nodes",
                "edges",
                "path_labels",
                "tool_tasks",
                "instance_labels",
            ):
                self.assertFalse(case[field])

    def test_independent_human_templates_are_blank_and_condition_blind(self):
        primary = create_assignment(
            deepcopy(self.artifact), "primary", "human-01"
        )
        reviewer = create_assignment(
            deepcopy(self.artifact), "reviewer", "human-02"
        )
        self.assertEqual(
            primary["packet_sha256"], reviewer["packet_sha256"]
        )
        self.assertNotEqual(
            primary["annotator_id"], reviewer["annotator_id"]
        )
        for assignment in (primary, reviewer):
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
