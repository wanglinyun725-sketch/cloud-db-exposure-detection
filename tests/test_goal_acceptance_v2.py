from hashlib import sha256

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
    decision = tmp_path / "decision.json"
    decision.write_text("{}", encoding="utf-8")
    artifacts = []
    for kind in (
        "thesis_pdf",
        "defense_deck",
        "reproduction_bundle",
        "review_stress_tests",
    ):
        path = tmp_path / f"{kind}.bin"
        path.write_text(kind, encoding="utf-8")
        artifacts.append({
            "kind": kind,
            "path": path.name,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        })
    manifest = {
        "status": "complete",
        "confirmatory_decision_sha256": sha256(
            decision.read_bytes()
        ).hexdigest(),
        "artifacts": artifacts,
    }

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
