import unittest
from pathlib import Path

from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
    ToolActionError,
    ToolBudgetError,
)


INDEX_PATH = Path("data/real_sources/pilot_observation_index.json")
RDS_CASE = "splunk:datasets/attack_techniques/T1110.002/aws_rds_password_reset"
SNAPSHOT_CASE = "splunk:datasets/attack_techniques/T1537/aws_snapshot_exfil"


class PublishedTelemetryEnvironmentTests(unittest.TestCase):
    def test_action_schema_does_not_reveal_observations(self):
        env = PublishedTelemetryEnvironment.from_file(INDEX_PATH, RDS_CASE)

        schema = env.action_schema()

        self.assertIn("search_events", schema)
        self.assertNotIn("ModifyDBCluster", str(schema))
        self.assertEqual(0, env.spent)

    def test_case_summary_and_filtered_search_have_auditable_cost(self):
        env = PublishedTelemetryEnvironment.from_file(
            INDEX_PATH,
            RDS_CASE,
            budget=10,
        )

        summary = env.execute("summarize_case")
        search = env.execute(
            "search_events",
            {"operation": "ModifyDBInstance"},
        )

        self.assertEqual(5, summary["tool_result"]["observation_count"])
        self.assertEqual(2, len(search["tool_result"]["events"]))
        self.assertEqual(1, summary["receipt"]["cost"])
        self.assertEqual(2, search["receipt"]["cost"])
        self.assertEqual(3, env.spent)
        self.assertEqual(2, len(search["receipt"]["raw_refs"]))
        self.assertNotIn("path_label", str(search))
        self.assertNotIn("evidence_state", str(search))

    def test_detail_is_restricted_to_current_case(self):
        rds_env = PublishedTelemetryEnvironment.from_file(INDEX_PATH, RDS_CASE)
        snapshot_env = PublishedTelemetryEnvironment.from_file(
            INDEX_PATH,
            SNAPSHOT_CASE,
        )
        snapshot_search = snapshot_env.execute(
            "search_events",
            {"operation": "CreateSnapshot"},
        )
        other_case_observation = snapshot_search["tool_result"]["events"][0][
            "observation_id"
        ]

        with self.assertRaises(ToolActionError):
            rds_env.execute(
                "get_event_detail",
                {"observation_id": other_case_observation},
            )

    def test_unknown_filters_and_budget_overrun_are_rejected_without_spend(self):
        env = PublishedTelemetryEnvironment.from_file(
            INDEX_PATH,
            SNAPSHOT_CASE,
            budget=1,
        )

        with self.assertRaises(ToolActionError):
            env.execute("search_events", {"candidate_id": SNAPSHOT_CASE})
        with self.assertRaises(ToolBudgetError):
            env.execute("search_events")

        self.assertEqual(0, env.spent)
        self.assertEqual([], env.trace)

    def test_resource_search_returns_raw_provenance(self):
        env = PublishedTelemetryEnvironment.from_file(INDEX_PATH, SNAPSHOT_CASE)

        result = env.execute("resource_search", {"term": "snapshot"})

        self.assertGreater(len(result["tool_result"]["events"]), 0)
        self.assertGreater(len(result["receipt"]["raw_refs"]), 0)
        for raw_ref in result["receipt"]["raw_refs"]:
            self.assertRegex(raw_ref["sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("record_index", raw_ref)


if __name__ == "__main__":
    unittest.main()
