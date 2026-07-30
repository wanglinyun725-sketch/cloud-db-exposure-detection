from hashlib import sha256
import json
import zipfile

import pytest

from src.experiments.final_deliverables_v2 import (
    REQUIRED_REVIEW_CHECKS,
    build_final_deliverables_manifest,
    build_review_stress_test_bundle,
    validate_review_stress_test_bundle,
    write_once_json,
)


def _write_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False),
        encoding="utf-8",
    )


def _passing_decision(tmp_path):
    path = tmp_path / "decision.json"
    _write_json(path, {
        "claim_allowed": True,
        "overall_status": "pass",
        "posthoc_metric_substitution_allowed": False,
    })
    return path


def _reports(tmp_path, decision):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("real evidence", encoding="utf-8")
    decision_hash = sha256(decision.read_bytes()).hexdigest()
    paths = {}
    for index, (review_type, required) in enumerate(
        sorted(REQUIRED_REVIEW_CHECKS.items()),
        start=1,
    ):
        report = {
            "review_version": "2.0",
            "review_type": review_type,
            "status": "completed",
            "verdict": "pass",
            "reviewer_id": f"reviewer-{index}",
            "reviewer_kind": "human",
            "independent_of_artifact_authorship": True,
            "confirmatory_decision_sha256": decision_hash,
            "checks": [
                {
                    "check_id": check_id,
                    "verdict": "pass",
                    "evidence_paths": [evidence.name],
                }
                for check_id in sorted(required)
            ],
            "findings": [
                {
                    "severity": "major",
                    "resolution_status": "resolved",
                }
            ],
        }
        path = tmp_path / f"{review_type}.json"
        _write_json(path, report)
        paths[review_type] = path
    return paths


def test_review_bundle_and_final_artifacts_are_hash_bound(tmp_path):
    decision = _passing_decision(tmp_path)
    reports = _reports(tmp_path, decision)
    bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        report_paths=reports,
    )
    bundle_path = tmp_path / "reviews.json"
    _write_json(bundle_path, bundle)
    validate_review_stress_test_bundle(
        tmp_path,
        bundle,
        decision_path=decision,
    )
    artifact_paths = {
        "thesis": tmp_path / "thesis.pdf",
        "defense": tmp_path / "defense.pptx",
        "reproduction": tmp_path / "reproduction.zip",
    }
    artifact_paths["thesis"].write_bytes(b"%PDF-1.7\n%%EOF\n")
    with zipfile.ZipFile(artifact_paths["defense"], "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<presentation/>")
    with zipfile.ZipFile(artifact_paths["reproduction"], "w") as archive:
        archive.writestr("README.md", "reproduce")
        archive.writestr(
            "configs/ec_react_main_v2_frozen.yaml",
            "freeze_status: FROZEN",
        )
        archive.writestr(
            "scripts/experiments/run_research_pipeline_v2.py",
            "print('run')",
        )
        archive.writestr("requirements.txt", "pyyaml")

    manifest = build_final_deliverables_manifest(
        tmp_path,
        decision_path=decision,
        thesis_pdf=artifact_paths["thesis"],
        defense_deck=artifact_paths["defense"],
        reproduction_bundle=artifact_paths["reproduction"],
        review_stress_tests=bundle_path,
        git_commit="a" * 40,
    )

    assert manifest["status"] == "complete"
    assert manifest["review_gate_passed"] is True
    assert {item["kind"] for item in manifest["artifacts"]} == {
        "thesis_pdf",
        "defense_deck",
        "reproduction_bundle",
        "review_stress_tests",
    }


def test_review_bundle_rejects_duplicate_reviewers(tmp_path):
    decision = _passing_decision(tmp_path)
    reports = _reports(tmp_path, decision)
    for path in reports.values():
        report = json.loads(path.read_text(encoding="utf-8"))
        report["reviewer_id"] = "same-reviewer"
        _write_json(path, report)

    with pytest.raises(ValueError, match="distinct reviewer"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            report_paths=reports,
        )


def test_review_bundle_rejects_unresolved_major_finding(tmp_path):
    decision = _passing_decision(tmp_path)
    reports = _reports(tmp_path, decision)
    report = json.loads(reports["method"].read_text(encoding="utf-8"))
    report["findings"][0]["resolution_status"] = "open"
    _write_json(reports["method"], report)

    with pytest.raises(ValueError, match="unresolved"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            report_paths=reports,
        )


def test_review_bundle_rejects_failed_confirmatory_decision(tmp_path):
    decision = _passing_decision(tmp_path)
    reports = _reports(tmp_path, decision)
    value = json.loads(decision.read_text(encoding="utf-8"))
    value["claim_allowed"] = False
    value["overall_status"] = "fail"
    _write_json(decision, value)

    with pytest.raises(ValueError, match="passing preregistered"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            report_paths=reports,
        )


def test_review_bundle_detects_report_drift(tmp_path):
    decision = _passing_decision(tmp_path)
    reports = _reports(tmp_path, decision)
    bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        report_paths=reports,
    )
    reports["statistics"].write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        validate_review_stress_test_bundle(
            tmp_path,
            bundle,
            decision_path=decision,
        )


def test_write_once_refuses_different_payload(tmp_path):
    path = tmp_path / "frozen.json"
    write_once_json(path, {"status": "complete"})
    write_once_json(path, {"status": "complete"})

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        write_once_json(path, {"status": "different"})
