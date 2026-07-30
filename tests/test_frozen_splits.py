import unittest

from src.experiments.frozen_splits import build_frozen_split_manifest


def _case(case_id, group, provenance="B", decision="accept", source="s1"):
    status = {
        "accept": "reviewed",
        "reject": "rejected",
        "needs_execution": "needs_execution",
    }[decision]
    return {
        "case_id": case_id,
        "source": {
            "source_id": source,
            "provenance_level": provenance,
        },
        "annotation": {
            "status": status,
            "label_origin": "human_reviewed",
        },
        "admission_screen": {"decision": decision},
        "candidate_metadata": {"independence_group": group},
        # Deliberately conflicting payloads: splitting must ignore labels.
        "nodes": [{"id": f"secret-{case_id}"}],
        "edges": [{"edge_id": f"secret-{case_id}"}],
        "path_labels": [
            {"state": "Valid" if case_id.endswith("1") else "Invalid"}
        ],
        "instance_labels": [{"overall_state": "Conflict"}],
    }


class FrozenSplitTests(unittest.TestCase):
    def test_groups_never_cross_splits_and_c_level_never_enters_test(self):
        release = {
            "packet_sha256": "a" * 64,
            "cases": [
                _case("b-1", "g-b"),
                _case("b-2", "g-b"),
                _case("c-1", "g-c", provenance="C"),
                _case("d-1", "g-d"),
                _case("e-1", "g-e"),
                _case("f-1", "g-f"),
                _case("rejected", "g-b", decision="reject"),
                _case("queued", "g-q", decision="needs_execution"),
            ],
        }
        manifest = build_frozen_split_manifest(release, seed=17)
        by_group = {}
        by_id = {}
        for item in manifest["assignments"]:
            by_id[item["case_id"]] = item["split"]
            if item["split"] not in {"excluded", "execution_queue"}:
                by_group.setdefault(
                    item["independence_group"], set()
                ).add(item["split"])

        self.assertTrue(all(len(splits) == 1 for splits in by_group.values()))
        self.assertIn(by_id["c-1"], {"development", "validation"})
        self.assertEqual("excluded", by_id["rejected"])
        self.assertEqual("execution_queue", by_id["queued"])
        self.assertEqual([], manifest["policy"]["label_fields_consulted"])

    def test_output_is_deterministic_and_external_source_is_held_out(self):
        release = {
            "packet_sha256": "b" * 64,
            "cases": [
                _case("a-1", "g-a", source="internal"),
                _case("a-2", "g-a", source="external"),
                _case("b-1", "g-b", source="internal"),
            ],
        }
        left = build_frozen_split_manifest(
            release,
            seed=29,
            external_source_ids={"external"},
        )
        right = build_frozen_split_manifest(
            release,
            seed=29,
            external_source_ids={"external"},
        )

        self.assertEqual(left, right)
        group_a = {
            item["split"] for item in left["assignments"]
            if item["independence_group"] == "g-a"
        }
        self.assertEqual({"external_test"}, group_a)

    def test_c_level_provenance_overrides_external_holdout(self):
        release = {
            "packet_sha256": "d" * 64,
            "cases": [
                _case(
                    "c-external",
                    "g-c-external",
                    provenance="C",
                    source="external",
                ),
                _case(
                    "b-external",
                    "g-b-external",
                    provenance="B",
                    source="external",
                ),
            ],
        }

        manifest = build_frozen_split_manifest(
            release,
            seed=31,
            external_source_ids={"external"},
        )
        by_id = {
            item["case_id"]: item["split"]
            for item in manifest["assignments"]
        }

        self.assertIn(
            by_id["c-external"],
            {"development", "validation"},
        )
        self.assertEqual("external_test", by_id["b-external"])

    def test_pending_release_is_refused(self):
        release = {
            "packet_sha256": "c" * 64,
            "cases": [
                {
                    **_case("a-1", "g-a"),
                    "annotation": {
                        "status": "pending",
                        "label_origin": None,
                    },
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "not finalized"):
            build_frozen_split_manifest(release, seed=1)


if __name__ == "__main__":
    unittest.main()
