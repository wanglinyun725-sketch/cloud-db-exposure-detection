"""Generate an evidence-bounded graduation-project readiness assessment."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSON = ROOT / "output" / "research_readiness_current.json"
DEFAULT_REPORT = ROOT / "output" / "research_readiness_current.md"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def build_audit(root: Path = ROOT) -> dict[str, Any]:
    config = yaml.safe_load(
        (root / "configs" / "ec_react_main_v1.yaml").read_text(
            encoding="utf-8"
        )
    )
    expanded_path = (
        root / config["data"]["source_packet"]
    )
    pilot_path = (
        root / config["data"]["annotation_pilot_packet"]
    )
    negative_path = (
        root / config["data"]["negative_source_packet"]
    )
    expanded = _load_json(expanded_path)
    pilot = _load_json(pilot_path)
    negative = _load_json(negative_path)
    preflight = _load_json(root / "output" / "ec_react_main_preflight.json")
    protocol = _load_json(
        root / "output" / "ec_react_protocol_validation.json"
    )
    action_audit = _load_json(
        root / "output" / "pareto_action_space_audit.json"
    )
    runtime_contract_audit = _load_json(
        root / "output" / "runtime_tool_contract_audit.json"
    )
    unlabeled_main_dry_run = _load_json(
        root / "output" / "unlabeled_main_dry_run.json"
    )
    cases = expanded["cases"]
    runtime_cases = [case for case in cases if case["runtime_instances"]]
    runtime_instances = [
        instance
        for case in runtime_cases
        for instance in case["runtime_instances"]
    ]
    source_counts = Counter(case["source"]["source_id"] for case in cases)
    runtime_source_case_counts: Counter[str] = Counter()
    for case in runtime_cases:
        candidate_source = case["source"]["source_id"]
        evidence_sources = {
            instance.get("runtime_source_id") or candidate_source
            for instance in case["runtime_instances"]
        }
        runtime_source_case_counts.update(evidence_sources)
    groups = {
        case["candidate_metadata"]["independence_group"] for case in cases
    }
    finalized_gold = [
        case
        for case in cases
        if case["annotation"]["status"] in {"reviewed", "adjudicated"}
    ]
    negative_finalized = [
        case
        for case in negative["cases"]
        if (case.get("screening") or {}).get("status")
        in {"reviewed", "adjudicated"}
    ]
    methods = config["methods"]
    method_family_counts = Counter(method["family"] for method in methods)

    rubric = [
        {
            "dimension": "research_problem_value",
            "weight": 0.10,
            "score": 8.5,
            "basis": "云数据攻击/暴露路径的可验证主动发现具有明确研究价值",
        },
        {
            "dimension": "engineering_reliability",
            "weight": 0.15,
            "score": 9.0,
            "basis": "线性/LangGraph 双后端、硬预算、引用守卫和完整自动测试",
        },
        {
            "dimension": "real_data_and_provenance",
            "weight": 0.20,
            "score": 7.0,
            "basis": "真实固定来源丰富，但当前人工 gold 与负对照 release 均为 0",
        },
        {
            "dimension": "method_contribution",
            "weight": 0.20,
            "score": 7.5,
            "basis": "三项代码贡献已形成，但尚无主实验支持独立效果",
        },
        {
            "dimension": "experiment_design",
            "weight": 0.15,
            "score": 8.0,
            "basis": "盲法、预注册门槛、group-safe split、消融与统计协议已冻结",
        },
        {
            "dimension": "completed_empirical_evidence",
            "weight": 0.15,
            "score": 1.5,
            "basis": "当前只有工程审计；research_effectiveness_result 仍为 false",
        },
        {
            "dimension": "reproducibility",
            "weight": 0.05,
            "score": 9.0,
            "basis": "来源哈希、配置、协议输出和 preflight 可机器复核",
        },
    ]
    weighted_score = sum(
        item["weight"] * item["score"] for item in rubric
    )
    hard_gates = {
        "pilot_human_release_and_gate": (
            preflight["annotation_pilot_gate"]["passes"] is True
        ),
        "minimum_80_accepted_independence_groups": (
            preflight["release_summary"]["included_independence_groups"]
            >= 80
        ),
        "minimum_30_runtime_backed_accepted_cases": (
            preflight["release_summary"]["runtime_backed_included_cases"]
            >= 30
        ),
        "minimum_20_reviewed_external_negatives": (
            preflight["negative_release_summary"][
                "usable_negative_controls"
            ]
            >= 20
        ),
        "frozen_group_safe_split": (
            preflight["split_summary"]["assignments"] > 0
        ),
        "main_experiment_preflight_ready": preflight["ready"] is True,
        "all_source_runtime_contract_valid": (
            runtime_contract_audit["audit_valid"] is True
            and runtime_contract_audit["source_packet_sha256"]
            == _file_hash(expanded_path)
        ),
        "non_llm_main_execution_contract_valid": (
            unlabeled_main_dry_run["dry_run_valid"] is True
            and unlabeled_main_dry_run["packet_sha256"]
            == _file_hash(expanded_path)
            and unlabeled_main_dry_run["config_sha256"]
            == _file_hash(root / "configs" / "ec_react_main_v1.yaml")
            and unlabeled_main_dry_run["completed_runs"]
            == unlabeled_main_dry_run["scheduled_runs"]
        ),
        "human_gold_effectiveness_results_exist": False,
    }
    excellent_now = all(hard_gates.values()) and weighted_score >= 8.5

    return {
        "audit_version": "0.2",
        "assessment_scope": (
            "current repository evidence; no school-specific grade guarantee"
        ),
        "dataset": {
            "candidate_cases": len(cases),
            "source_counts": dict(sorted(source_counts.items())),
            "source_count": len(source_counts),
            "independence_groups": len(groups),
            "runtime_backed_cases": len(runtime_cases),
            "runtime_instances": len(runtime_instances),
            "runtime_source_case_counts": dict(sorted(
                runtime_source_case_counts.items()
            )),
            "runtime_platform_instances": dict(sorted(Counter(
                instance["platform"] for instance in runtime_instances
            ).items())),
            "human_finalized_gold_cases": len(finalized_gold),
            "negative_candidates": len(negative["cases"]),
            "human_finalized_negative_cases": len(negative_finalized),
            "expanded_packet_sha256": _file_hash(expanded_path),
        },
        "runtime_pilot": {
            **pilot["summary"],
            "packet_sha256": _file_hash(pilot_path),
            "gate_configured": (
                preflight["annotation_pilot_gate"]["configured"]
            ),
            "gate_passes": preflight["annotation_pilot_gate"]["passes"],
        },
        "method": {
            "methods": len(methods),
            "method_family_counts": dict(sorted(method_family_counts.items())),
            "orchestration_backend": config["shared_execution"][
                "orchestration_backend"
            ],
            "required_reporting_slices": config["reporting"][
                "required_slices"
            ],
            "source_heterogeneity": config["statistics"][
                "source_heterogeneity"
            ],
            "linear_langgraph_backend_mismatch_count": protocol[
                "backend_mismatch_count"
            ],
            "policy_leakage_failure_count": protocol[
                "policy_leakage_failure_count"
            ],
            "protocol_valid": protocol["protocol_valid"],
            "protocol_research_effectiveness_result": protocol[
                "research_effectiveness_result"
            ],
            "all_source_runtime_contract_valid": (
                runtime_contract_audit["audit_valid"]
            ),
            "all_source_runtime_instances_audited": (
                runtime_contract_audit["runtime_instances"]
            ),
            "all_source_tool_contract_failure_count": (
                runtime_contract_audit["tool_contract_failure_count"]
            ),
            "all_source_backend_mismatch_count": (
                runtime_contract_audit["backend_mismatch_count"]
            ),
            "all_source_policy_leakage_failure_count": (
                runtime_contract_audit["policy_leakage_failure_count"]
            ),
            "all_source_runtime_research_effectiveness_result": (
                runtime_contract_audit["research_effectiveness_result"]
            ),
            "unlabeled_main_dry_run_valid": (
                unlabeled_main_dry_run["dry_run_valid"]
            ),
            "unlabeled_main_runtime_instances": (
                unlabeled_main_dry_run["runtime_instances"]
            ),
            "unlabeled_main_scheduled_runs": (
                unlabeled_main_dry_run["scheduled_runs"]
            ),
            "unlabeled_main_completed_runs": (
                unlabeled_main_dry_run["completed_runs"]
            ),
            "unlabeled_main_method_runs": (
                unlabeled_main_dry_run["method_runs"]
            ),
            "unlabeled_main_backend_mismatch_count": (
                unlabeled_main_dry_run["backend_mismatch_count"]
            ),
            "unlabeled_main_budget_violation_count": (
                unlabeled_main_dry_run["hard_budget_violation_count"]
            ),
            "unlabeled_main_execution_failure_count": (
                unlabeled_main_dry_run["execution_failure_count"]
            ),
            "unlabeled_main_research_effectiveness_result": (
                unlabeled_main_dry_run["research_effectiveness_result"]
            ),
            "runtime_payload_capable_instances": (
                runtime_contract_audit["data_shape"][
                    "payload_capable_instances"
                ]
            ),
            "runtime_payload_limited_instances": (
                runtime_contract_audit["data_shape"][
                    "payload_absent_from_normalized_view_instances"
                ]
            ),
            "pareto_research_effectiveness_result": action_audit[
                "research_effectiveness_result"
            ],
            "pareto_after_detail_mean_pruning_rate": action_audit[
                "stages"
            ]["after_detail"]["mean_pruning_rate"],
            "sigma_unique_operation_coverage_rate": action_audit[
                "external_prior_coverage"
            ]["unique_coverage_rate"],
            "sigma_event_weighted_coverage_rate": action_audit[
                "external_prior_coverage"
            ]["event_weighted_coverage_rate"],
        },
        "innovation_status": [
            {
                "innovation": "RealPathBench-CD",
                "implementation": "implemented",
                "empirical_status": "provisional_until_human_gold",
            },
            {
                "innovation": "EC-ReAct progressive tool-use discovery",
                "implementation": "implemented_and_protocol_validated",
                "empirical_status": "no_human_gold_effectiveness_result",
            },
            {
                "innovation": "CP-Cert four-valued minimal certificate",
                "implementation": "implemented_and_oracle_tested",
                "empirical_status": "no_real_human_gold_main_result",
            },
        ],
        "preflight": {
            "ready": preflight["ready"],
            "blocker_count": len(preflight["blockers"]),
            "blockers": preflight["blockers"],
            "planned_runs_at_minimum_case_target": preflight[
                "planned_runs_at_minimum_case_target"
            ],
        },
        "rubric": rubric,
        "weighted_current_score_out_of_10": round(weighted_score, 2),
        "excellent_hard_gates": hard_gates,
        "excellent_now": excellent_now,
        "verdict": (
            "当前不能客观认定为优秀研究生毕业设计；研究设计与工程具有优秀潜力，"
            "但人工 gold、真实负对照和主实验效果证据尚未完成。"
        ),
    }


def render_report(audit: dict[str, Any]) -> str:
    dataset = audit["dataset"]
    pilot = audit["runtime_pilot"]
    method = audit["method"]
    lines = [
        "# Cloud DB PathBench 当前研究就绪度复评",
        "",
        "## 结论",
        "",
        audit["verdict"],
        "",
        f"当前加权分为 **{audit['weighted_current_score_out_of_10']}/10**。"
        "该分数反映仓库当前已完成证据，不是对未来结果的预测；同时设置优秀硬门槛，"
        "因此不能靠工程分高来抵消主实验尚未完成。",
        "",
        "## 已经成立的事实",
        "",
        f"- 真实来源候选 {dataset['candidate_cases']} 例，"
        f"{dataset['independence_groups']} 个独立组，"
        f"{dataset['source_count']} 个正向来源；",
        f"- 运行时案例 {dataset['runtime_backed_cases']} 例、"
        f"运行实例 {dataset['runtime_instances']} 个，平台分布"
        f" {dataset['runtime_platform_instances']}；",
        f"- 正式 pilot 为 {pilot['case_count']} 例、"
        f"{pilot['runtime_instance_count']} 个实例、"
        f"{pilot['independence_group_count']} 个完整独立组、"
        f"{pilot['observation_count']} 条观测；",
        f"- 方法矩阵包含 {method['methods']} 个方法，"
        f"线性/LangGraph 后端不一致 "
        f"{method['linear_langgraph_backend_mismatch_count']}，"
        f"策略隐藏标签泄漏 {method['policy_leakage_failure_count']}；",
        f"- v0.5 的 {method['all_source_runtime_instances_audited']} 个"
        "可执行真实运行实例已完成四来源共同工具契约审计："
        f"契约失败 {method['all_source_tool_contract_failure_count']}、"
        f"后端不一致 {method['all_source_backend_mismatch_count']}、"
        f"策略泄漏 {method['all_source_policy_leakage_failure_count']}；"
        "该结果仍不是效果实验；",
        f"- 在全部 {method['unlabeled_main_runtime_instances']} 个运行实例上，"
        f"已完成 {method['unlabeled_main_completed_runs']}/"
        f"{method['unlabeled_main_scheduled_runs']} 次无标签主条件干跑："
        f"执行失败 {method['unlabeled_main_execution_failure_count']}、"
        f"预算违规 {method['unlabeled_main_budget_violation_count']}、"
        "线性/LangGraph 不一致 "
        f"{method['unlabeled_main_backend_mismatch_count']}；"
        "它只证明执行契约成立，未计算任何正确率或召回率；",
        f"- Pareto 动作空间在详情阶段平均裁剪 "
        f"{method['pareto_after_detail_mean_pruning_rate']:.2%}；"
        "这只是效率侧工程证据。",
        "",
        "## 尚未成立的事实",
        "",
        f"- 人工 finalized gold：{dataset['human_finalized_gold_cases']}；",
        f"- 人工 finalized 负对照："
        f"{dataset['human_finalized_negative_cases']}；",
        "- EC-ReAct 路径发现准确率/召回率优于基线：尚无合格主实验；",
        "- 三项创新均已实现代码骨架，但目前没有一项完成真实人工 gold 上的"
        "独立效果闭环；",
        "- Sigma 外部规则先验的唯一 operation 覆盖率仅"
        f" {method['sigma_unique_operation_coverage_rate']:.2%}，"
        "必须保留独立消融，不能把零命中解释为良性。",
        "",
        "## 优秀硬门槛",
        "",
        "| 门槛 | 当前 |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {key} | {'通过' if value else '未通过'} |"
        for key, value in audit["excellent_hard_gates"].items()
    )
    lines.extend([
        "",
        "## 分项评分",
        "",
        "| 维度 | 权重 | 当前分 | 依据 |",
        "|---|---:|---:|---|",
    ])
    lines.extend(
        f"| {item['dimension']} | {item['weight']:.0%} | "
        f"{item['score']:.1f} | {item['basis']} |"
        for item in audit["rubric"]
    )
    lines.extend([
        "",
        "## 当前阻断项",
        "",
    ])
    lines.extend(
        f"- {blocker}" for blocker in audit["preflight"]["blockers"]
    )
    lines.extend([
        "",
        "LangGraph 在本项目中是可替换的工程编排后端，不单独算创新点；"
        "线性后端语义等价测试用于证明方法不依赖框架。真正可主张的贡献仍应是"
        "真实数据基准、EC-ReAct 的渐进证据发现机制和 CP-Cert 证书方法，"
        "且必须由后续人工 gold 主实验决定能否作为独立创新点成立。",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    audit = build_audit(ROOT)
    DEFAULT_JSON.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_JSON.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    DEFAULT_REPORT.write_text(render_report(audit), encoding="utf-8")
    print(json.dumps({
        "score": audit["weighted_current_score_out_of_10"],
        "excellent_now": audit["excellent_now"],
        "preflight_blockers": audit["preflight"]["blocker_count"],
        "report": str(DEFAULT_REPORT.relative_to(ROOT)),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
