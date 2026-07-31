import json
import unittest

from scripts.data.export_expanded_annotation_pool import (
    V04_OUTPUT_PATH,
    build_expanded_pool,
)


class ExpandedAnnotationPoolV04Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = json.loads(
            V04_OUTPUT_PATH.read_text(encoding="utf-8")
        )

    def test_v04_is_exact_runtime_admissible_revision(self):
        self.assertEqual(
            self.packet,
            build_expanded_pool(
                include_qualified_otrf=True,
                runtime_admissible_only=True,
            ),
        )
        summary = self.packet["summary"]
        self.assertEqual("0.4", self.packet["packet_version"])
        self.assertEqual(150, summary["candidate_cases"])
        self.assertEqual(113, len({
            case["candidate_metadata"]["independence_group"]
            for case in self.packet["cases"]
        }))
        self.assertEqual(57, summary["runtime_backed_cases"])
        self.assertEqual(91, summary["runtime_instances"])
        self.assertEqual(2, summary[
            "runtime_admission_exclusion_count"
        ])
        self.assertEqual(
            {
                "episode-474f69871e39c8b2",
                "episode-a13c1b45df3244f2",
            },
            {
                item["instance_id"]
                for item in summary["runtime_admission_exclusions"]
            },
        )

    def test_every_retained_runtime_instance_is_executable_and_unlabeled(self):
        instances = [
            instance
            for case in self.packet["cases"]
            for instance in case["runtime_instances"]
        ]
        self.assertTrue(instances)
        self.assertTrue(all(
            instance["observation_count"] > 0 for instance in instances
        ))
        self.assertTrue(all(
            case["annotation"]["status"] == "pending"
            and case["annotation"]["label_origin"] is None
            and not case["nodes"]
            and not case["edges"]
            and not case["path_labels"]
            and not case["instance_labels"]
            for case in self.packet["cases"]
        ))


if __name__ == "__main__":
    unittest.main()
