import json
import unittest
from pathlib import Path

from src.agent.cross_cloud_environment import (
    CrossCloudTelemetryEnvironment,
)


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "data" / "real_sources" / "cross_cloud_pilot_episode_index.json"
FULL_INDEX_PATH = (
    ROOT / "data" / "real_sources" / "cross_cloud_full_episode_index.json"
)


def _episode(platform: str, condition: str) -> str:
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return next(
        item["episode_id"]
        for item in index["episodes"]
        if item["platform"] == platform
        and item["attack"] == "automated_exfiltration"
        and item["log_profile"] == "additional"
        and item["run_id"] == 0
        and item["source_condition"] == condition
    )


class CrossCloudEnvironmentTests(unittest.TestCase):
    def test_public_context_and_action_schema_hide_attack_condition(self):
        episode_id = _episode("AWS", "payload_present")
        env = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            episode_id,
        )

        visible = json.dumps(
            {
                "context": env.public_context,
                "tools": env.action_schema(),
            },
            ensure_ascii=False,
        )

        self.assertNotIn("automated_exfiltration", visible)
        self.assertNotIn("payload_present", visible)
        self.assertNotIn(episode_id, visible)
        self.assertIn("AWS", visible)

    def test_tool_results_are_budgeted_and_traceable_without_label_leakage(self):
        episode_id = _episode("AWS", "payload_present")
        env = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            episode_id,
            budget=50,
        )

        summary = env.execute("summarize_case")
        operation = min(
            summary["tool_result"]["operation_counts"],
            key=summary["tool_result"]["operation_counts"].get,
        )
        search = env.execute("search_events", {"operation": operation})
        observation_id = search["tool_result"]["events"][0]["observation_id"]
        detail = env.execute(
            "get_event_detail",
            {"observation_id": observation_id},
        )
        visible = json.dumps(
            [summary, search, detail],
            ensure_ascii=False,
        )

        self.assertGreater(env.spent, 0)
        self.assertGreater(len(env.trace), 0)
        self.assertNotIn("automated_exfiltration", visible)
        self.assertNotIn("payload_present", visible)
        raw_ref = detail["receipt"]["raw_refs"][0]
        self.assertRegex(raw_ref["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("record_index", raw_ref)

    def test_all_three_platforms_load_real_events(self):
        for platform in ("AWS", "AZURE", "GCP"):
            with self.subTest(platform=platform):
                env = CrossCloudTelemetryEnvironment.from_file(
                    ROOT,
                    INDEX_PATH,
                    _episode(platform, "payload_absent"),
                )
                result = env.execute("summarize_case")
                self.assertGreater(
                    result["tool_result"]["observation_count"],
                    0,
                )

    def test_evaluation_metadata_is_separate_from_public_context(self):
        episode_id = _episode("GCP", "payload_absent")
        env = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            INDEX_PATH,
            episode_id,
        )

        hidden = env.evaluation_metadata()

        self.assertEqual("payload_absent", hidden["source_condition"])
        self.assertEqual(
            "automated_exfiltration",
            hidden["attack"],
        )
        self.assertIn("member_path", hidden["raw_ref"])
        self.assertNotIn("source_condition", env.public_context)
        self.assertNotIn("attack", env.public_context)

    def test_source_scenario_names_inside_resources_are_blinded(self):
        index = json.loads(FULL_INDEX_PATH.read_text(encoding="utf-8"))
        episode = next(
            item for item in index["episodes"]
            if item["platform"] == "GCP"
            and item["attack"] == "archive_collected_data"
            and item["log_profile"] == "default"
            and item["run_id"] == 0
            and item["source_condition"] == "payload_present"
        )
        env = CrossCloudTelemetryEnvironment.from_file(
            ROOT,
            FULL_INDEX_PATH,
            episode["episode_id"],
            budget=100,
        )
        summary = env.execute("summarize_case")
        outputs = [summary]
        for operation in summary["tool_result"]["operation_counts"]:
            search = env.execute(
                "search_events",
                {"operation": operation},
            )
            outputs.append(search)
            for event in search["tool_result"]["events"]:
                outputs.append(env.execute(
                    "get_event_detail",
                    {"observation_id": event["observation_id"]},
                ))

        visible = json.dumps(
            {
                "context": env.public_context,
                "outputs": outputs,
            },
            ensure_ascii=False,
        ).casefold()
        hidden = env.evaluation_metadata()

        self.assertNotIn("archive_collected_data", visible)
        self.assertIn("opaque-resource-", visible)
        self.assertEqual("archive_collected_data", hidden["attack"])
        self.assertEqual(
            "deterministic_v1",
            hidden["policy_blinding"]["version"],
        )


if __name__ == "__main__":
    unittest.main()
