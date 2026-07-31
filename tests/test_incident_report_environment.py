import json
import unittest
from pathlib import Path

from src.agent.incident_report_environment import (
    IncidentReportToolEnvironment,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "negative_control_round1_unlabeled.json"
)


class IncidentReportEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        packet = json.loads(PACKET.read_text(encoding="utf-8"))
        cls.case = packet["cases"][0]

    def test_public_surface_hides_screening_and_report_text(self):
        env = IncidentReportToolEnvironment(self.case, budget=5)
        public = json.dumps(
            {
                "context": env.public_context,
                "tools": env.action_schema(),
            },
            ensure_ascii=False,
        )

        self.assertNotIn("non_attack_confirmed", public)
        self.assertNotIn("usable_as_negative_control", public)
        self.assertNotIn(self.case["report_text"][:50], public)
        self.assertNotIn("data_relevance_facets", public)

    def test_report_is_only_observed_through_budgeted_traceable_tools(self):
        env = IncidentReportToolEnvironment(self.case, budget=6)
        summary = env.execute("summarize_case", {})
        operation = next(iter(
            summary["tool_result"]["operation_counts"]
        ))
        search = env.execute(
            "search_events",
            {"operation": operation},
        )
        event = search["tool_result"]["events"][0]
        detail = env.execute(
            "get_event_detail",
            {"observation_id": event["observation_id"]},
        )

        self.assertGreater(env.spent, 0)
        self.assertEqual(3, len(env.trace))
        self.assertIn(
            self.case["report_text"][:80],
            detail["tool_result"]["events"][0]["request"],
        )
        self.assertEqual(
            self.case["raw_ref"]["record_sha256"],
            detail["tool_result"]["events"][0]["raw_ref"][
                "record_sha256"
            ],
        )

    def test_screening_is_separate_evaluation_metadata(self):
        env = IncidentReportToolEnvironment(self.case)
        hidden = env.evaluation_metadata()

        self.assertEqual(
            self.case["screening"],
            hidden["screening"],
        )
        self.assertNotIn("screening", env.public_context)


if __name__ == "__main__":
    unittest.main()
