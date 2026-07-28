import unittest

from scripts.experiments.run_provider_oracle_llm_pilot_v1 import (
    _deduplicate_scheduled_rows,
    _merge_compatible_manifest,
)


class ProviderOracleLLMRunnerResumeTests(unittest.TestCase):
    def test_duplicate_schedule_records_are_not_counted_twice(self):
        rows = [
            {"schedule_id": "a", "value": "first"},
            {"schedule_id": "a", "value": "duplicate"},
            {"schedule_id": "b", "value": "only"},
            {"schedule_id": "outside", "value": "ignored"},
        ]
        selected, duplicates = _deduplicate_scheduled_rows(
            rows, {"a", "b"}
        )
        self.assertEqual(2, len(selected))
        self.assertEqual(1, duplicates)
        self.assertEqual(
            {"a": "first", "b": "only"},
            {item["schedule_id"]: item["value"] for item in selected},
        )

    def test_compatible_resume_merges_instead_of_overwriting_schedule(self):
        common = {
            "experiment_id": "pilot",
            "protocol_version": "8.0-pilot",
            "config_sha256": "config",
            "implementation_bundle_sha256": "implementation",
            "public_packet_sha256": "public",
            "gold_packet_sha256": "gold",
        }
        existing = {
            **common,
            "filters": {"cases": ["a"]},
            "schedule": [{"schedule_id": "one"}],
        }
        current = {
            **common,
            "filters": {"cases": ["b"]},
            "schedule": [
                {"schedule_id": "one"},
                {"schedule_id": "two"},
            ],
        }
        merged = _merge_compatible_manifest(existing, current)
        self.assertEqual(2, merged["scheduled_runs"])
        self.assertEqual(
            {"one", "two"},
            {item["schedule_id"] for item in merged["schedule"]},
        )
        self.assertEqual(
            2, len(merged["filters"]["resume_invocations"])
        )


if __name__ == "__main__":
    unittest.main()
