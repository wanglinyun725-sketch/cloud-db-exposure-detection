from hashlib import sha256
import json
import zipfile

import pytest

from src.experiments.final_deliverables_v2 import (
    REQUIRED_REVIEW_CHECKS,
    _validate_reproduction_result_binding,
    build_final_deliverables_manifest,
    build_review_stress_test_bundle,
    validate_review_stress_test_bundle,
    write_once_json,
)
from src.experiments.artifact_chain_v2 import (
    build_analysis_binding,
    build_decision_binding,
)


def _write_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False),
        encoding="utf-8",
    )


def _passing_decision(tmp_path):
    config = tmp_path / "frozen.yaml"
    config.write_text("freeze_status: FROZEN\n", encoding="utf-8")
    config_hash = sha256(config.read_bytes()).hexdigest()
    run_manifest = tmp_path / "run_manifest.json"
    _write_json(run_manifest, {
        "config_sha256": config_hash,
        "scheduled_runs": 1,
        "schedule": [{"schedule_id": "s1"}],
        "secrets_in_manifest": False,
    })
    runs = tmp_path / "runs.jsonl"
    record = {"schedule_id": "s1", "config_sha256": config_hash}
    runs.write_text(json.dumps(record) + "\n", encoding="utf-8")
    analysis = {
        "run_records": 1,
        "artifact_binding": build_analysis_binding(
            tmp_path,
            config_path=config,
            run_manifest_path=run_manifest,
            runs_path=runs,
            records=[record],
        ),
    }
    analysis_path = tmp_path / "analysis.json"
    _write_json(analysis_path, analysis)
    path = tmp_path / "decision.json"
    decision = {
        "claim_allowed": True,
        "overall_status": "pass",
        "posthoc_metric_substitution_allowed": False,
        "artifact_binding": build_decision_binding(
            tmp_path,
            config_path=config,
            analysis_path=analysis_path,
            analysis=analysis,
        ),
    }
    _write_json(path, decision)
    return path


def _cp_result(tmp_path, *, eligible=False):
    gates = {
        "frozen_held_out_split_bound": True,
        "minimum_independence_groups": eligible,
        "all_certificates_valid": True,
        "all_raw_references_verified": True,
        "exact_optimality_oracle_verified": True,
        "positive_ci_lower_bound_for_compression": True,
    }
    path = tmp_path / "cp_cert_experiment_results.json"
    _write_json(path, {
        "experiment": "cp_cert_reviewed_human_gold",
        "selected_splits": ["test"],
        "research_effectiveness_result": eligible,
        "cp_cert_claim_gate": {
            "eligible": eligible,
            "gates": gates,
            "posthoc_threshold_change_allowed": False,
        },
    })
    return path


def _reports(tmp_path, decision, cp_result):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("real evidence", encoding="utf-8")
    decision_hash = sha256(decision.read_bytes()).hexdigest()
    cp_cert_hash = sha256(cp_result.read_bytes()).hexdigest()
    cp_cert_claim_allowed = json.loads(
        cp_result.read_text(encoding="utf-8")
    )["research_effectiveness_result"]
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
            "cp_cert_result_sha256": cp_cert_hash,
            "cp_cert_innovation_claim_allowed": cp_cert_claim_allowed,
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
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        cp_cert_result_path=cp_result,
        report_paths=reports,
    )
    bundle_path = tmp_path / "reviews.json"
    _write_json(bundle_path, bundle)
    validate_review_stress_test_bundle(
        tmp_path,
        bundle,
        decision_path=decision,
        cp_cert_result_path=cp_result,
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
        cp_member = (
            "output/ec_react_main_v2/"
            "cp_cert_experiment_results.json"
        )
        archive.writestr(cp_member, cp_result.read_bytes())
        archive.writestr("bundle_manifest.json", json.dumps({
            "confirmatory_decision_sha256": sha256(
                decision.read_bytes()
            ).hexdigest(),
            "files": [{
                "path": cp_member,
                "sha256": sha256(cp_result.read_bytes()).hexdigest(),
            }],
        }))

    manifest = build_final_deliverables_manifest(
        tmp_path,
        decision_path=decision,
        cp_cert_result_path=cp_result,
        thesis_pdf=artifact_paths["thesis"],
        defense_deck=artifact_paths["defense"],
        reproduction_bundle=artifact_paths["reproduction"],
        review_stress_tests=bundle_path,
        git_commit="a" * 40,
    )

    assert manifest["status"] == "complete"
    assert manifest["review_gate_passed"] is True
    assert manifest["cp_cert_innovation_claim_allowed"] is False
    assert {item["kind"] for item in manifest["artifacts"]} == {
        "thesis_pdf",
        "defense_deck",
        "reproduction_bundle",
        "review_stress_tests",
    }


def test_review_bundle_rejects_duplicate_reviewers(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    for path in reports.values():
        report = json.loads(path.read_text(encoding="utf-8"))
        report["reviewer_id"] = "same-reviewer"
        _write_json(path, report)

    with pytest.raises(ValueError, match="distinct reviewer"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            cp_cert_result_path=cp_result,
            report_paths=reports,
        )


def test_review_bundle_rejects_unresolved_major_finding(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    report = json.loads(reports["method"].read_text(encoding="utf-8"))
    report["findings"][0]["resolution_status"] = "open"
    _write_json(reports["method"], report)

    with pytest.raises(ValueError, match="unresolved"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            cp_cert_result_path=cp_result,
            report_paths=reports,
        )


def test_review_bundle_rejects_failed_confirmatory_decision(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    value = json.loads(decision.read_text(encoding="utf-8"))
    value["claim_allowed"] = False
    value["overall_status"] = "fail"
    _write_json(decision, value)

    with pytest.raises(ValueError, match="passing preregistered"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            cp_cert_result_path=cp_result,
            report_paths=reports,
        )


def test_review_bundle_detects_report_drift(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        cp_cert_result_path=cp_result,
        report_paths=reports,
    )
    reports["statistics"].write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        validate_review_stress_test_bundle(
            tmp_path,
            bundle,
            decision_path=decision,
            cp_cert_result_path=cp_result,
        )


def test_review_bundle_detects_evidence_drift(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        cp_cert_result_path=cp_result,
        report_paths=reports,
    )
    (tmp_path / "evidence.txt").write_text(
        "changed after review",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="evidence hash mismatch"):
        validate_review_stress_test_bundle(
            tmp_path,
            bundle,
            decision_path=decision,
            cp_cert_result_path=cp_result,
        )


def test_review_bundle_rejects_cp_cert_claim_status_drift(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path)
    reports = _reports(tmp_path, decision, cp_result)
    report = json.loads(
        reports["statistics"].read_text(encoding="utf-8")
    )
    report["cp_cert_innovation_claim_allowed"] = True
    _write_json(reports["statistics"], report)

    with pytest.raises(ValueError, match="claim status mismatch"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            cp_cert_result_path=cp_result,
            report_paths=reports,
        )


def test_cp_cert_eligibility_cannot_disagree_with_sub_gates(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path, eligible=True)
    report = json.loads(cp_result.read_text(encoding="utf-8"))
    report["cp_cert_claim_gate"]["gates"][
        "all_certificates_valid"
    ] = False
    _write_json(cp_result, report)
    reports = _reports(tmp_path, decision, cp_result)

    with pytest.raises(ValueError, match="disagrees with sub-gates"):
        build_review_stress_test_bundle(
            tmp_path,
            decision_path=decision,
            cp_cert_result_path=cp_result,
            report_paths=reports,
        )


def test_passing_cp_cert_gate_propagates_without_becoming_mandatory(tmp_path):
    decision = _passing_decision(tmp_path)
    cp_result = _cp_result(tmp_path, eligible=True)
    reports = _reports(tmp_path, decision, cp_result)

    bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        cp_cert_result_path=cp_result,
        report_paths=reports,
    )

    assert (
        bundle["cp_cert_result"]["innovation_claim_allowed"]
        is True
    )


def test_reproduction_bundle_rejects_inner_cp_cert_drift(tmp_path):
    path = tmp_path / "reproduction.zip"
    decision_hash = "a" * 64
    expected_cp_hash = sha256(b"expected").hexdigest()
    member = (
        "output/ec_react_main_v2/"
        "cp_cert_experiment_results.json"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, b"tampered")
        archive.writestr("bundle_manifest.json", json.dumps({
            "confirmatory_decision_sha256": decision_hash,
            "files": [{
                "path": member,
                "sha256": expected_cp_hash,
            }],
        }))

    with pytest.raises(ValueError, match="CP-Cert binding mismatch"):
        _validate_reproduction_result_binding(
            path,
            decision_sha256=decision_hash,
            cp_cert_result_sha256=expected_cp_hash,
        )


def test_write_once_refuses_different_payload(tmp_path):
    path = tmp_path / "frozen.json"
    write_once_json(path, {"status": "complete"})
    write_once_json(path, {"status": "complete"})

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        write_once_json(path, {"status": "different"})
