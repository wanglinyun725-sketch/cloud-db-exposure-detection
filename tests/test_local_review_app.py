from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from src.annotation.local_review_app import create_local_review_app
from src.annotation.negative_control_workflow import (
    create_negative_assignment,
)
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
NEGATIVE_PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "negative_control_round1_unlabeled.json"
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
        self.assertIn(
            "证据判定与 JSON 填写手册",
            response.get_data(as_text=True),
        )
        self.assertIn(
            "已完成谱系",
            response.get_data(as_text=True),
        )
        self.assertIn(
            "独立谱系",
            response.get_data(as_text=True),
        )
        self.assertIn(
            "逐条观测索引",
            case_response.get_data(as_text=True),
        )

    def test_guide_is_neutral_and_explains_scope_and_four_values(self):
        response = self.client.get("/guide")
        text = response.get_data(as_text=True)

        self.assertEqual(200, response.status_code)
        self.assertIn("不推荐标签", text)
        self.assertIn("needs_execution", text)
        self.assertIn("Conflict", text)
        self.assertIn("作用域检查", text)
        self.assertIn("REPLACE_", text)

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

    def test_completion_precheck_does_not_write_or_attest(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                action="check",
                external_or_low_privilege_entry_defined="false",
                multi_step_path_present="false",
                cloud_data_target_present="true",
                critical_edges_have_raw_evidence="false",
                not_a_near_duplicate="true",
                decision="reject",
                rationale="Human precheck with explicit negative criteria.",
            ),
        )

        self.assertEqual(200, response.status_code)
        self.assertIn(
            "任务文件尚未改动",
            response.get_data(as_text=True),
        )
        self.assertEqual(
            self.original,
            json.loads(self.case_path.read_text(encoding="utf-8")),
        )

    def test_example_placeholder_cannot_be_completed(self):
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
                rationale="REPLACE_human_reason",
            ),
        )

        self.assertEqual(400, response.status_code)
        self.assertIn("REPLACE_", response.get_data(as_text=True))
        self.assertEqual(
            self.original,
            json.loads(self.case_path.read_text(encoding="utf-8")),
        )

    def test_csrf_and_path_traversal_are_rejected(self):
        forbidden = self.client.post(
            f"/case/{self.filename}",
            data=self._form(_nonce="wrong"),
        )
        self.assertEqual(403, forbidden.status_code)
        missing = self.client.get("/case/not-in-manifest.json")
        self.assertEqual(404, missing.status_code)


class NegativeLocalReviewAppTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.task_dir = Path(self.temporary.name)
        packet = json.loads(
            NEGATIVE_PACKET.read_text(encoding="utf-8")
        )
        assignment = create_negative_assignment(
            packet,
            "primary",
            "negative-local-review-test",
        )
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
            "cloud_data_relevant": "",
            "non_attack_confirmed": "",
            "usable_as_negative_control": "",
            "rationale": "Human read the frozen provider report.",
        }
        form.update(overrides)
        return form

    def test_negative_index_case_and_guide_use_the_screening_schema(self):
        index = self.client.get("/")
        case = self.client.get(f"/case/{self.filename}")
        guide = self.client.get("/guide")

        self.assertEqual("negative", self.app.config[
            "ANNOTATION_WORKFLOW_KIND"
        ])
        self.assertEqual(200, index.status_code)
        self.assertIn("负对照筛选", index.get_data(as_text=True))
        self.assertIn("0/29", index.get_data(as_text=True))
        self.assertEqual(200, case.status_code)
        self.assertIn(
            self.original["candidate_id"],
            case.get_data(as_text=True),
        )
        self.assertIn("cloud_data_relevant", case.get_data(as_text=True))
        self.assertEqual(200, guide.status_code)
        self.assertIn("不推荐答案", guide.get_data(as_text=True))

    def test_negative_draft_only_changes_screening(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                cloud_data_relevant="true",
            ),
        )

        self.assertEqual(302, response.status_code)
        saved = json.loads(self.case_path.read_text(encoding="utf-8"))
        self.assertTrue(saved["screening"]["cloud_data_relevant"])
        self.assertEqual(
            self.original["source_context_sha256"],
            saved["source_context_sha256"],
        )
        self.assertEqual(self.original["report_text"], saved["report_text"])
        self.assertFalse(saved["human_attestation"])

    def test_negative_precheck_is_valid_but_does_not_write(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                action="check",
                cloud_data_relevant="true",
                non_attack_confirmed="true",
                usable_as_negative_control="true",
            ),
        )

        self.assertEqual(200, response.status_code)
        self.assertIn(
            "任务文件尚未改动",
            response.get_data(as_text=True),
        )
        self.assertEqual(
            self.original,
            json.loads(self.case_path.read_text(encoding="utf-8")),
        )

    def test_usable_negative_requires_both_prerequisites(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                action="complete",
                cloud_data_relevant="true",
                non_attack_confirmed="false",
                usable_as_negative_control="true",
            ),
        )

        self.assertEqual(400, response.status_code)
        self.assertIn("requires cloud-data relevance", response.get_data(
            as_text=True
        ))
        self.assertEqual(
            self.original,
            json.loads(self.case_path.read_text(encoding="utf-8")),
        )

    def test_valid_negative_completion_is_immutable(self):
        response = self.client.post(
            f"/case/{self.filename}",
            data=self._form(
                action="complete",
                cloud_data_relevant="true",
                non_attack_confirmed="true",
                usable_as_negative_control="false",
            ),
        )

        self.assertEqual(302, response.status_code)
        completed = json.loads(self.case_path.read_text(encoding="utf-8"))
        self.assertTrue(completed["human_attestation"])
        second = self.client.post(
            f"/case/{self.filename}",
            data=self._form(),
        )
        self.assertEqual(409, second.status_code)


if __name__ == "__main__":
    unittest.main()
