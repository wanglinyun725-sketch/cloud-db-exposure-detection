import unittest
from pathlib import Path

from src.agent.ec_react import ECReactRunner
from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
)


ROOT = Path(__file__).resolve().parents[1]
INDEX = (
    ROOT
    / "data"
    / "real_sources"
    / "splunk_full_observation_index.json"
)
CANDIDATE_ID = (
    "splunk:datasets/attack_techniques/T1530/"
    "aws_exfil_high_no_getobject"
)


class VisibilityCapturePolicy:
    def __init__(self):
        self.final_view = None

    def propose(self, view):
        executed = [
            item for item in view["history"]
            if item["status"] == "tool_executed"
        ]
        if not executed:
            return {
                "kind": "tool",
                "thought": "Reveal aggregate facets.",
                "tool_name": "summarize_case",
                "arguments": {},
            }
        if len(executed) == 1:
            return {
                "kind": "tool",
                "thought": "Query the high-volume operation.",
                "tool_name": "search_events",
                "arguments": {"operation": "GetObject"},
            }
        self.final_view = view
        return {
            "kind": "finish",
            "thought": "Stop after checking the visible evidence boundary.",
            "decision": "abstain",
            "hypothesis": "Protocol visibility check complete.",
            "evidence_observation_ids": [],
        }


class ECReactVisibilityTests(unittest.TestCase):
    def test_only_events_rendered_to_policy_become_citable(self):
        environment = PublishedTelemetryEnvironment.from_file(
            INDEX,
            CANDIDATE_ID,
            budget=30,
        )
        policy = VisibilityCapturePolicy()

        result = ECReactRunner(policy).run(
            environment,
            {"case_handle": "opaque"},
        )

        visible_events = result.trace[1]["observation"]["events"]
        visible_ids = {
            item["observation_id"] for item in visible_events
        }
        self.assertEqual(12, len(visible_ids))
        self.assertEqual(
            visible_ids,
            set(policy.final_view["observed_evidence_ids"]),
        )
        self.assertEqual(
            100,
            result.trace[1]["observation"]["result_count"],
        )
        self.assertTrue(
            result.trace[1]["observation"][
                "results_truncated_in_policy_view"
            ]
        )


if __name__ == "__main__":
    unittest.main()

