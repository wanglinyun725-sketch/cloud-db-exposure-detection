from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from src.annotation.local_review_app import create_local_review_app
from src.annotation.task_bundle import build_case_bundle
from src.annotation.workflow import create_assignment


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_pilot_round2_unlabeled.json"
)


class LocalReviewAppTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.task_dir = Path(self.temporary.name)
        packet = json.loads(
            RUNTIME_PACKET.read_text(encoding="utf-8")
        )
        assignment = create_assignment(
            packet,
            "primary",
            "local-review-test",
        )
        assignment["cases"] = [deepcopy(assignment["cases"][0])]
        manifest, documents = build_case_bundle(assignment)
        (self.task_dir / "assignment_manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        for filename, case in documents.items():
            (self.task_dir / filename).write_text(
                json.dumps(case),
                encoding="utf-8",
            )
        self.filename = next(iter(documents))
        self.case_path = self.task_dir / self.filename
        self.original = json.loads(
            self.case_path.read_text(encoding="utf-8")
        )
        self.app = create_local_review_app(self.task_dir)
        self.app.testing = True
        self.client = self.app.test_client()
        self.nonce = self.app.config["ANNOTATION_NONCE"]

    def tearDown(self):
        self.temporary.cleanup()

    def _form(self, **overrides):
        form = {
            "_nonce": self.nonce,
            "action": "draft",
            "external_or_low_privilege_entry_defined": "",
            "multi_step_path_present": "",
            "cloud_data_target_present": "",
            "critical_edges_have_raw_evidence": "",
            "not_a_near_duplicate": "",
            "decision": "",
            "rationale": "human draft",
            "nodes": "[]",
            "edges": "[]",
            "path_labels": "[]",
            "tool_tasks": "[]",
            "instance_labels": "[]",
        }
        form.update(overrides)
        return form

    def test_index_and_case_page_are_human_only(self):
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertIn("不调用 LLM", response.get_data(as_text=True))
        case_response = self.client.get(f"/case/{self.filename}")
        self.assertEqual(200, case_response.status_code)
        self.assertIn(
            self.original["case_id"],
            case_response.get_data(as_text=True),
        )

    def test_draft_changes_only_editable_fields_and_preserves_source_hash(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(),
        )
        self.assertEqual(302, response.status_code)
        saved = json.loads(
            self.case_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.original["source_context_sha256"],
            saved["source_context_sha256"],
        )
        self.assertEqual(self.original["source"], saved["source"])
        self.assertEqual("human draft", saved["admission_screen"]["rationale"])
        self.assertFalse(saved["human_attestation"])

    def test_invalid_completion_does_not_mutate_task(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                action="complete",
                external_or_low_privilege_entry_defined="true",
                multi_step_path_present="true",
                cloud_data_target_present="true",
                critical_edges_have_raw_evidence="true",
                not_a_near_duplicate="true",
                decision="accept",
            ),
        )
        self.assertEqual(400, response.status_code)
        current = json.loads(
            self.case_path.read_text(encoding="utf-8")
        )
        self.assertEqual(self.original, current)
        self.assertIn(
            "accepted case requires",
            response.get_data(as_text=True),
        )

    def test_valid_human_reject_is_completed_and_becomes_immutable(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                action="complete",
                external_or_low_privilege_entry_defined="false",
                multi_step_path_present="false",
                cloud_data_target_present="true",
                critical_edges_have_raw_evidence="false",
                not_a_near_duplicate="true",
                decision="reject",
                rationale="Human found no evidenced multi-step path.",
            ),
        )
        self.assertEqual(302, response.status_code)
        completed = json.loads(
            self.case_path.read_text(encoding="utf-8")
        )
        self.assertTrue(completed["human_attestation"])
        self.assertIsNotNone(completed["completed_at"])

        second = self.client.post(
            f"/case/{self.filename}",
            data=self._form(),
        )
        self.assertEqual(409, second.status_code)

    def test_csrf_and_path_traversal_are_rejected(self):
        forbidden = self.client.post(
            f"/case/{self.filename}",
            data=self._form(_nonce="wrong"),
        )
        self.assertEqual(403, forbidden.status_code)
        missing = self.client.get("/case/not-in-manifest.json")
        self.assertEqual(404, missing.status_code)


if __name__ == "__main__":
    unittest.main()
