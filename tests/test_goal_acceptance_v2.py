from hashlib import sha256
import json
import zipfile

from src.experiments.final_deliverables_v2 import (
    REQUIRED_REVIEW_CHECKS,
    build_final_deliverables_manifest,
    build_review_stress_test_bundle,
)
from src.experiments.artifact_chain_v2 import (
    build_analysis_binding,
    build_decision_binding,
)
from src.experiments.goal_acceptance_v2 import (
    _deliverables_pass,
    _model_locks_pass,
    render_goal_acceptance_markdown,
)


def test_model_gate_requires_both_local_digest_and_exact_strong_snapshot():
    models = {
        "qwen2_5_7b_local": {
            "require_runtime_digest": True,
            "frozen_runtime_digest": "a" * 64,
        },
        "gpt_5_4_snapshot": {
            "require_exact_version": True,
            "default_model": "gpt-5.4-2026-03-05",
        },
    }
    assert _model_locks_pass(models) is True
    models["qwen2_5_7b_local"]["frozen_runtime_digest"] = None
    assert _model_locks_pass(models) is False


def test_deliverables_must_be_bound_to_the_final_decision(tmp_path):
    config = tmp_path / "frozen.yaml"
    config.write_text("freeze_status: FROZEN\n", encoding="utf-8")
    config_hash = sha256(config.read_bytes()).hexdigest()
    run_manifest = tmp_path / "run_manifest.json"
    run_manifest.write_text(json.dumps({
        "config_sha256": config_hash,
        "scheduled_runs": 1,
        "schedule": [{"schedule_id": "s1"}],
        "secrets_in_manifest": False,
    }), encoding="utf-8")
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
    analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
    decision = tmp_path / "decision.json"
    decision_value = {
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
    decision.write_text(json.dumps(decision_value), encoding="utf-8")
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("evidence", encoding="utf-8")
    decision_hash = sha256(decision.read_bytes()).hexdigest()
    report_paths = {}
    for index, (review_type, checks) in enumerate(
        sorted(REQUIRED_REVIEW_CHECKS.items())
    ):
        path = tmp_path / f"{review_type}.json"
        path.write_text(json.dumps({
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
                for check_id in sorted(checks)
            ],
            "findings": [],
        }), encoding="utf-8")
        report_paths[review_type] = path
    review_bundle = build_review_stress_test_bundle(
        tmp_path,
        decision_path=decision,
        report_paths=report_paths,
    )
    review_path = tmp_path / "reviews.json"
    review_path.write_text(json.dumps(review_bundle), encoding="utf-8")
    thesis = tmp_path / "thesis.pdf"
    thesis.write_bytes(b"%PDF-1.7\n%%EOF\n")
    defense = tmp_path / "defense.pptx"
    with zipfile.ZipFile(defense, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<presentation/>")
    reproduction = tmp_path / "reproduction.zip"
    with zipfile.ZipFile(reproduction, "w") as archive:
        for path in (
            "README.md",
            "configs/ec_react_main_v2_frozen.yaml",
            "scripts/experiments/run_research_pipeline_v2.py",
            "requirements.txt",
        ):
            archive.writestr(path, path)
    manifest = build_final_deliverables_manifest(
        tmp_path,
        decision_path=decision,
        thesis_pdf=thesis,
        defense_deck=defense,
        reproduction_bundle=reproduction,
        review_stress_tests=review_path,
        git_commit="a" * 40,
    )

    assert _deliverables_pass(tmp_path, manifest, decision) is True
    manifest["confirmatory_decision_sha256"] = "0" * 64
    assert _deliverables_pass(tmp_path, manifest, decision) is False


def test_markdown_renders_blocked_gates_without_subjective_score():
    report = {
        "objective_complete": False,
        "passed_gates": 1,
        "total_gates": 2,
        "gates": {"dataset": True, "human_gold": False},
        "blockers": [{"gate": "human_gold", "reason": "missing"}],
        "evidence": {},
    }

    rendered = render_goal_acceptance_markdown(report)

    assert "| `dataset` | PASS |" in rendered
    assert "| `human_gold` | BLOCKED |" in rendered
    assert "主观分数" in rendered
