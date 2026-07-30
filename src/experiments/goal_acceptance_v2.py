"""Objective, evidence-backed acceptance audit for the graduate goal."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

import yaml

from src.experiments.ec_react_execution import schedule_design_errors
from src.experiments.artifact_chain_v2 import validate_decision_binding
from src.experiments.final_deliverables_v2 import (
    validate_review_stress_test_bundle,
)


REQUIRED_PLATFORMS = {"AWS", "AZURE", "GCP"}
REQUIRED_METHODS = {
    "ec_react_full",
    "vanilla_react",
    "fixed_order",
    "random_tool",
    "full_query",
    "ablate_pareto",
    "ablate_provider_scope_gate",
    "ablate_external_rule_prior",
    "ablate_four_value_memory",
    "ablate_budget_stop",
    "ablate_evidence_cert",
}
REQUIRED_DELIVERABLE_KINDS = {
    "thesis_pdf",
    "defense_deck",
    "reproduction_bundle",
    "review_stress_tests",
}


def build_goal_acceptance(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    inventory = _read_optional(
        root / "output" / "research_design"
        / "executable_lineage_inventory_v1.json"
    )
    confirmatory = _read_optional(
        root / "output" / "research_design"
        / "confirmatory_freeze_readiness_v1.json"
    )
    negative = _read_optional(
        root / "output" / "research_design"
        / "negative_control_freeze_readiness_v1.json"
    )
    decision_path = (
        root / "output" / "ec_react_main_v2"
        / "confirmatory_decision.json"
    )
    decision = _read_optional(decision_path)
    frozen_path = root / "configs" / "ec_react_main_v2_frozen.yaml"
    frozen_manifest_path = (
        root / "output" / "research_design"
        / "ec_react_main_v2_freeze_manifest.json"
    )
    frozen = _read_yaml_optional(frozen_path)
    frozen_manifest = _read_optional(frozen_manifest_path)
    draft = yaml.safe_load(
        (
            root / "configs" / "ec_react_main_v2_draft.yaml"
        ).read_text(encoding="utf-8")
    )
    deliverables_path = (
        root / "output" / "research_design"
        / "final_deliverables_v2_manifest.json"
    )
    deliverables = _read_optional(deliverables_path)

    inventory_summary = (inventory or {}).get("summary") or {}
    dataset_gate = bool(
        inventory_summary.get("conservative_independence_groups", 0) >= 40
        and inventory_summary.get("source_count", 0) >= 6
        and REQUIRED_PLATFORMS
        <= set(inventory_summary.get("platforms") or [])
    )
    confirmatory_gate = bool(
        (confirmatory or {}).get("ready_to_publish") is True
        and (confirmatory or {}).get(
            "human_gold_independence_groups", 0
        )
        >= 30
    )
    negative_gate = bool(
        (negative or {}).get("ready_to_publish") is True
        and (negative or {}).get("experiment_eligible") is True
        and (negative or {}).get("usable_negative_controls", 0) >= 20
    )
    methods = {
        item.get("method_id") for item in draft.get("methods") or []
    }
    models = {
        item.get("model_id"): item for item in draft.get("models") or []
    }
    method_gate = bool(
        REQUIRED_METHODS <= methods
        and schedule_design_errors(draft) == []
        and _model_locks_pass(models)
    )
    frozen_gate = bool(
        frozen is not None
        and frozen.get("freeze_status") == "FROZEN"
        and frozen_manifest is not None
        and frozen_manifest.get("status") == "FROZEN"
        and _manifest_file_matches(
            frozen_manifest,
            "frozen_config",
            frozen_path,
        )
    )
    decision_gate = bool(
        decision is not None
        and decision.get("claim_allowed") is True
        and decision.get("overall_status") == "pass"
        and decision.get("posthoc_metric_substitution_allowed") is False
        and _decision_chain_passes(root, decision)
    )
    deliverables_gate = _deliverables_pass(
        root,
        deliverables,
        decision_path,
    )
    git_sync = _git_sync_status(root)
    git_gate = git_sync["synchronized"] is True

    gates = {
        "real_cross_cloud_benchmark": dataset_gate,
        "thirty_lineage_double_human_gold": confirmatory_gate,
        "twenty_human_screened_negative_controls": negative_gate,
        "ec_react_and_baselines_implemented": method_gate,
        "hash_bound_protocol_frozen": frozen_gate,
        "confirmatory_experiment_claim_passed": decision_gate,
        "final_deliverables_bound_to_results": deliverables_gate,
        "research_branch_synchronized_to_remote": git_gate,
    }
    blocker_text = {
        "real_cross_cloud_benchmark": (
            "保守库存必须包含不少于40个独立谱系、不少于6个来源并覆盖"
            "AWS/Azure/GCP"
        ),
        "thirty_lineage_double_human_gold": (
            "30个谱系仍需两位不同真人独立标注并完成分歧仲裁"
        ),
        "twenty_human_screened_negative_controls": (
            "至少20个外部负对照仍需完成双人筛选"
        ),
        "ec_react_and_baselines_implemented": (
            "必要方法、模型锁或显式实验调度尚不完整"
        ),
        "hash_bound_protocol_frozen": (
            "绑定gold、split、代码版本与哈希的FROZEN协议尚不存在"
        ),
        "confirmatory_experiment_claim_passed": (
            "冻结双模型实验尚未通过F1、相对增益与安全门槛"
        ),
        "final_deliverables_bound_to_results": (
            "论文、答辩材料、复现包和三轮审稿压力测试尚未绑定最终决策哈希"
        ),
        "research_branch_synchronized_to_remote": (
            "本地研究分支仍有未同步到上游的提交"
        ),
    }
    blockers = [
        {
            "gate": name,
            "reason": blocker_text[name],
        }
        for name, passes in gates.items()
        if not passes
    ]
    return {
        "audit_version": "2.0",
        "assessment": (
            "repository evidence only; no subjective score and no "
            "school-specific grade guarantee"
        ),
        "objective_complete": all(gates.values()),
        "passed_gates": sum(gates.values()),
        "total_gates": len(gates),
        "gates": gates,
        "blockers": blockers,
        "evidence": {
            "dataset": {
                "conservative_independence_groups": (
                    inventory_summary.get(
                        "conservative_independence_groups", 0
                    )
                ),
                "source_count": inventory_summary.get("source_count", 0),
                "platforms": inventory_summary.get("platforms") or [],
            },
            "confirmatory_human_gold": {
                "stage": (confirmatory or {}).get("stage", "missing"),
                "independence_groups": (confirmatory or {}).get(
                    "human_gold_independence_groups", 0
                ),
            },
            "negative_controls": {
                "stage": (negative or {}).get("stage", "missing"),
                "usable": (negative or {}).get(
                    "usable_negative_controls", 0
                ),
            },
            "method": {
                "required_methods_present": sorted(
                    REQUIRED_METHODS & methods
                ),
                "schedule_errors": schedule_design_errors(draft),
                "model_locks_pass": _model_locks_pass(models),
            },
            "frozen_protocol": {
                "config_present": frozen_path.is_file(),
                "manifest_present": frozen_manifest_path.is_file(),
            },
            "confirmatory_decision": (
                decision
                if decision is not None
                else {"status": "missing"}
            ),
            "deliverables_manifest": {
                "path": _portable(root, deliverables_path),
                "present": deliverables_path.is_file(),
            },
            "git": git_sync,
        },
    }


def render_goal_acceptance_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Graduate Goal v2 机器验收",
        "",
        f"- objective_complete：`{str(report['objective_complete']).lower()}`",
        f"- 通过门槛：{report['passed_gates']}/{report['total_gates']}",
        "- 口径：只读取仓库证据，不提供主观分数或学校成绩保证。",
        "",
        "## 验收矩阵",
        "",
        "| 门槛 | 状态 |",
        "|---|---|",
    ]
    for name, passes in report["gates"].items():
        lines.append(f"| `{name}` | {'PASS' if passes else 'BLOCKED'} |")
    lines.extend(["", "## 当前阻断项", ""])
    if report["blockers"]:
        for item in report["blockers"]:
            lines.append(f"- `{item['gate']}`：{item['reason']}")
    else:
        lines.append("- 无。")
    lines.extend(["", "## 关键证据", "", "```json"])
    lines.append(json.dumps(
        report["evidence"],
        ensure_ascii=False,
        indent=2,
    ))
    lines.extend(["```", ""])
    return "\n".join(lines)


def _model_locks_pass(models: Mapping[str, Mapping[str, Any]]) -> bool:
    local = models.get("qwen2_5_7b_local") or {}
    strong = models.get("gpt_5_4_snapshot") or {}
    digest = local.get("frozen_runtime_digest")
    return bool(
        local.get("require_runtime_digest") is True
        and isinstance(digest, str)
        and len(digest) == 64
        and strong.get("require_exact_version") is True
        and strong.get("default_model") == "gpt-5.4-2026-03-05"
    )


def _deliverables_pass(
    root: Path,
    manifest: Mapping[str, Any] | None,
    decision_path: Path,
) -> bool:
    if manifest is None or manifest.get("status") != "complete":
        return False
    if (
        manifest.get("claim_allowed") is not True
        or manifest.get("review_gate_passed") is not True
        or manifest.get("posthoc_metric_substitution_allowed") is not False
    ):
        return False
    git_commit = manifest.get("git_commit")
    if not (
        isinstance(git_commit, str)
        and len(git_commit) == 40
        and all(character in "0123456789abcdef" for character in git_commit)
    ):
        return False
    if not decision_path.is_file():
        return False
    expected_decision = sha256(decision_path.read_bytes()).hexdigest()
    if manifest.get("confirmatory_decision_sha256") != expected_decision:
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return False
    by_kind = {
        item.get("kind"): item
        for item in artifacts
        if isinstance(item, Mapping)
    }
    if not REQUIRED_DELIVERABLE_KINDS <= set(by_kind):
        return False
    for kind in REQUIRED_DELIVERABLE_KINDS:
        item = by_kind[kind]
        path = Path(str(item.get("path", "")))
        path = path if path.is_absolute() else root / path
        if not path.is_file():
            return False
        if item.get("sha256") != sha256(path.read_bytes()).hexdigest():
            return False
    review_path = Path(str(by_kind["review_stress_tests"]["path"]))
    review_path = (
        review_path if review_path.is_absolute() else root / review_path
    )
    try:
        review_bundle = json.loads(review_path.read_text(encoding="utf-8"))
        if not isinstance(review_bundle, dict):
            return False
        validate_review_stress_test_bundle(
            root,
            review_bundle,
            decision_path=decision_path,
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return True


def _manifest_file_matches(
    manifest: Mapping[str, Any],
    key: str,
    path: Path,
) -> bool:
    item = manifest.get(key)
    return bool(
        isinstance(item, Mapping)
        and path.is_file()
        and item.get("sha256") == sha256(path.read_bytes()).hexdigest()
    )


def _decision_chain_passes(
    root: Path,
    decision: Mapping[str, Any],
) -> bool:
    try:
        validate_decision_binding(root, decision)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return True


def _git_sync_status(root: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["git", "rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        return {
            "synchronized": False,
            "reason": completed.stderr.strip() or "no upstream",
        }
    behind, ahead = [
        int(value) for value in completed.stdout.split()
    ]
    branch = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    ).stdout.strip()
    return {
        "branch": branch,
        "behind_upstream": behind,
        "ahead_of_upstream": ahead,
        "synchronized": behind == 0 and ahead == 0,
    }


def _read_optional(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else None


def _read_yaml_optional(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else None


def _portable(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path.resolve())
