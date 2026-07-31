from copy import deepcopy
import json
from pathlib import Path
import unittest

from src.annotation.task_bundle import (
    assignment_progress,
    build_case_bundle,
    merge_case_bundle,
    negative_assignment_progress,
)
from src.annotation.negative_control_workflow import (
    create_negative_assignment,
)
from src.annotation.workflow import create_assignment


ROOT = Path(__file__).resolve().parents[1]
PILOT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "runtime_pilot_round1_unlabeled.json"
)
NEGATIVE_PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "negative_control_round1_unlabeled.json"
)


class AnnotationTaskBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        packet = json.loads(PILOT.read_text(encoding="utf-8"))
        cls.assignment = create_assignment(
            packet, "primary", "human-bundle"
        )

    def test_split_and_merge_are_lossless(self):
        manifest, documents = build_case_bundle(self.assignment)
        merged = merge_case_bundle(manifest, documents)
        self.assertEqual(self.assignment, merged)
        self.assertEqual(19, manifest["case_count"])
        self.assertEqual(19, len(documents))

    def test_missing_or_extra_case_file_is_rejected(self):
        manifest, documents = build_case_bundle(self.assignment)
        missing = dict(documents)
        del missing[next(iter(missing))]
        with self.assertRaisesRegex(ValueError, "file set changed"):
            merge_case_bundle(manifest, missing)
        extra = dict(documents)
        extra["invented.json"] = {}
        with self.assertRaisesRegex(ValueError, "file set changed"):
            merge_case_bundle(manifest, extra)

    def test_source_context_edit_is_rejected(self):
        manifest, documents = build_case_bundle(self.assignment)
        edited = deepcopy(documents)
        filename = next(iter(edited))
        edited[filename]["source"]["license"] = "changed"
        with self.assertRaisesRegex(ValueError, "source context content changed"):
            merge_case_bundle(manifest, edited)

    def test_blank_progress_is_reported_without_filling_labels(self):
        report = assignment_progress(self.assignment)
        self.assertEqual(19, report["counts"]["blank"])
        self.assertEqual(0, report["counts"]["valid_complete"])
        self.assertFalse(report["ready_for_agreement"])

    def test_negative_assignment_bundle_is_lossless_and_reports_progress(self):
        packet = json.loads(NEGATIVE_PACKET.read_text(encoding="utf-8"))
        assignment = create_negative_assignment(
            packet, "primary", "human-negative"
        )
        manifest, documents = build_case_bundle(assignment)
        self.assertEqual(assignment, merge_case_bundle(manifest, documents))
        report = negative_assignment_progress(assignment)
        self.assertEqual(30, report["counts"]["blank"])
        self.assertFalse(report["ready_for_agreement"])


if __name__ == "__main__":
    unittest.main()
