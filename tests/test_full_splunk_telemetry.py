from hashlib import sha256
import json
from pathlib import Path
import unittest

from scripts.data.profile_pilot_telemetry import (
    normalize_observation,
    parse_splunk_kv_line,
)


class FullSplunkTelemetryTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_full_manifest_and_index_are_hash_verified_and_unlabeled(self):
        manifest = json.loads(
            (
                self.ROOT
                / "data"
                / "real_sources"
                / "splunk_full_telemetry_manifest.json"
            ).read_text(encoding="utf-8")
        )
        index = json.loads(
            (
                self.ROOT
                / "data"
                / "real_sources"
                / "splunk_full_observation_index.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(9, len(manifest["candidates"]))
        self.assertEqual(9, index["summary"]["cases"])
        self.assertEqual(176, index["summary"]["observations"])
        for candidate in manifest["candidates"]:
            for artifact in candidate["artifacts"]:
                path = self.ROOT / artifact["relative_path"]
                self.assertEqual(
                    artifact["sha256"],
                    sha256(path.read_bytes()).hexdigest(),
                )
        self.assertTrue(all(
            observation["path_label"] is None
            and observation["evidence_state"] is None
            for observation in index["observations"]
        ))
        self.assertIn(
            "azure_ad_audit",
            {item["schema"] for item in index["observations"]},
        )
        self.assertIn(
            "splunk_key_value_event",
            {item["schema"] for item in index["observations"]},
        )

    def test_splunk_key_value_event_is_preserved_and_normalized(self):
        line = (
            '1681175400, search_name="ESCU - AWS Exfiltration", '
            'aws_account_id="111", bucketName="security-content", '
            'risk_score="64.0", src_ip="12.26.0.38", '
            'user_arn="arn:aws:iam::111:user/console", '
            'user_type="IAMUser"'
        )
        record = parse_splunk_kv_line(line)
        artifact = {
            "sha256": "a" * 64,
            "relative_path": "raw.log",
            "upstream_path": "upstream.log",
            "git_blob_sha": "b" * 40,
        }

        observation = normalize_observation(
            record,
            artifact,
            0,
            "candidate",
        )

        self.assertEqual(
            "splunk_key_value_event",
            observation["schema"],
        )
        self.assertEqual(
            "ESCU - AWS Exfiltration",
            observation["operation"],
        )
        self.assertEqual(
            "arn:aws:iam::111:user/console",
            observation["actor_id"],
        )

    def test_azure_audit_event_keeps_actor_and_target(self):
        record = {
            "time": "2026-06-10T09:14:22Z",
            "resourceId": "/tenants/t/providers/Microsoft.aadiam",
            "operationName": "Update service principal",
            "tenantId": "tenant",
            "callerIpAddress": "203.0.113.1",
            "properties": {
                "result": "success",
                "initiatedBy": {
                    "user": {
                        "userPrincipalName": "analyst@example.com",
                    }
                },
                "targetResources": [{"id": "sp-1"}],
            },
        }
        artifact = {
            "sha256": "a" * 64,
            "relative_path": "azure.log",
            "upstream_path": "azure.log",
            "git_blob_sha": "b" * 40,
        }

        observation = normalize_observation(
            record,
            artifact,
            0,
            "candidate",
        )

        self.assertEqual("azure_ad_audit", observation["schema"])
        self.assertEqual(
            "analyst@example.com",
            observation["actor_id"],
        )
        self.assertEqual("Microsoft.aadiam", observation["service"])


if __name__ == "__main__":
    unittest.main()
