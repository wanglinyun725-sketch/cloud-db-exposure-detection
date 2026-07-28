"""Gold-free dry-run of the exact main path-discovery execution contract."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.agent.ec_react import ECReactRunner
from src.agent.ec_react_langgraph import ECReactLangGraphRunner
from src.agent.unlabeled_runtime_environment import (
    UnlabeledRuntimeInstanceEnvironment,
)
from src.experiments.ec_react_execution import (
    _validate_run_contract,
    policy_for_non_llm_method,
)


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def build_unlabeled_dry_run_schedule(
    config: Mapping[str, Any],
    packet: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Mirror every non-LLM main condition without loading a gold label."""
    shared = config["shared_execution"]
    seeds = list(shared["random_seeds"])
    rows = []
    methods = [
        item for item in config["methods"]
        if item["family"] in {"deterministic", "randomized"}
    ]
    for case in sorted(packet["cases"], key=lambda item: item["case_id"]):
        for instance in sorted(
            case.get("runtime_instances", []),
            key=lambda item: item["instance_id"],
        ):
            for method in methods:
                repeats = (
                    int(shared["llm_repeats"])
                    if method["family"] == "randomized"
                    else int(shared["deterministic_repeats"])
                )
                if repeats > len(seeds):
                    raise ValueError(
                        "dry-run repeats exceed frozen random seeds"
                    )
                for budget in shared["budget_grid"]:
                    for repeat in range(repeats):
                        identity = {
                            "case_id": case["case_id"],
                            "instance_id": instance["instance_id"],
                            "method_id": method["method_id"],
                            "budget": budget,
                            "repeat": repeat,
                            "seed": seeds[repeat],
                        }
                        rows.append({
                            **identity,
                            "scenario_source_id": case["source"]["source_id"],
                            "runtime_evidence_source_id": (
                                instance.get("runtime_source_id")
                                or case["source"]["source_id"]
                            ),
                            "platform": instance["platform"],
                            "dry_run_id": (
                                "dry-" + _stable_hash(identity)[:24]
                            ),
                        })
    return rows


def _runner(
    runner_class: type,
    policy: Any,
    method: Mapping[str, Any],
    shared: Mapping[str, Any],
) -> Any:
    return runner_class(
        policy,
        max_steps=int(shared["max_steps"]),
        task_mode="path_discovery",
        finish_guard_mode=method["finish_guard_mode"],
        pareto_guard=method["pareto_guard"],
        external_rule_prior=method["external_rule_prior"],
        four_value_memory=method["four_value_memory"],
        budget_stop=method["budget_stop"],
        max_path_candidates=int(shared["max_path_candidates"]),
    )


def run_unlabeled_main_dry_run(
    root: str | Path,
    config_path: str | Path,
    packet_path: str | Path,
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    """Execute non-LLM main conditions with no scoring or effectiveness claim."""
    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive or None")
    root = Path(root).resolve()
    config_path = Path(config_path)
    packet_path = Path(packet_path)
    if not config_path.is_absolute():
        config_path = root / config_path
    if not packet_path.is_absolute():
        packet_path = root / packet_path
    config_path = config_path.resolve()
    packet_path = packet_path.resolve()
    config_bytes = config_path.read_bytes()
    packet_bytes = packet_path.read_bytes()
    config = yaml.safe_load(config_bytes.decode("utf-8"))
    packet = json.loads(packet_bytes.decode("utf-8"))
    schedule = build_unlabeled_dry_run_schedule(config, packet)
    if limit is not None:
        schedule = schedule[:limit]
    case_by_id = {
        case["case_id"]: case for case in packet["cases"]
    }
    method_by_id = {
        method["method_id"]: method for method in config["methods"]
    }
    shared = config["shared_execution"]
    rows = []
    failures = []
    for schedule_row in schedule:
        case = case_by_id[schedule_row["case_id"]]
        method = method_by_id[schedule_row["method_id"]]
        budget = schedule_row["budget"]
        repeat = schedule_row["repeat"]
        try:
            _validate_run_contract(method, shared, budget, repeat)
            linear_environment = UnlabeledRuntimeInstanceEnvironment(
                case, schedule_row["instance_id"], budget=budget
            )
            graph_environment = UnlabeledRuntimeInstanceEnvironment(
                case, schedule_row["instance_id"], budget=budget
            )
            linear_policy = policy_for_non_llm_method(
                method["method_id"],
                seed=schedule_row["seed"],
                max_path_candidates=shared["max_path_candidates"],
            )
            graph_policy = policy_for_non_llm_method(
                method["method_id"],
                seed=schedule_row["seed"],
                max_path_candidates=shared["max_path_candidates"],
            )
            linear = asdict(_runner(
                ECReactRunner,
                linear_policy,
                method,
                shared,
            ).run(
                linear_environment,
                linear_environment.public_context,
            ))
            graph = asdict(_runner(
                ECReactLangGraphRunner,
                graph_policy,
                method,
                shared,
            ).run(
                graph_environment,
                graph_environment.public_context,
            ))
            if linear["spent"] > budget or graph["spent"] > budget:
                raise ValueError("runner exceeded the frozen hard budget")
        except Exception as exc:
            failures.append({
                "dry_run_id": schedule_row["dry_run_id"],
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
        rows.append({
            **schedule_row,
            "backend_equivalent": linear == graph,
            "result_sha256": _stable_hash(linear),
            "decision": linear["decision"],
            "stop_reason": linear["stop_reason"],
            "spent": linear["spent"],
            "valid_tool_calls": linear["valid_tool_calls"],
            "invalid_actions": linear["invalid_actions"],
            "path_candidates": len(linear["path_candidates"]),
            "verified_path_candidates": len(
                linear["verified_path_candidates"]
            ),
        })

    backend_mismatches = [
        row["dry_run_id"]
        for row in rows
        if not row["backend_equivalent"]
    ]
    overspent = [
        row["dry_run_id"]
        for row in rows
        if row["spent"] > row["budget"]
    ]
    source_counts = Counter(
        row["runtime_evidence_source_id"] for row in rows
    )
    method_counts = Counter(row["method_id"] for row in rows)
    decision_counts = Counter(row["decision"] for row in rows)
    expected = len(schedule)
    valid = (
        len(rows) == expected
        and not failures
        and not backend_mismatches
        and not overspent
    )
    return {
        "dry_run_version": "0.1",
        "purpose": (
            "gold-free validation of all frozen non-LLM main-experiment "
            "path-discovery conditions on every retained runtime instance"
        ),
        "research_effectiveness_result": False,
        "warning": (
            "No human gold is loaded and no path score is computed. "
            "This is an execution-contract result only."
        ),
        "config_path": str(config_path.relative_to(root)),
        "config_sha256": sha256(config_bytes).hexdigest(),
        "packet_path": str(packet_path.relative_to(root)),
        "packet_sha256": sha256(packet_bytes).hexdigest(),
        "runtime_instances": len({
            row["instance_id"] for row in schedule
        }),
        "scheduled_runs": expected,
        "completed_runs": len(rows),
        "method_runs": dict(sorted(method_counts.items())),
        "runtime_evidence_source_runs": dict(sorted(
            source_counts.items()
        )),
        "decision_counts": dict(sorted(decision_counts.items())),
        "backend_mismatch_count": len(backend_mismatches),
        "backend_mismatch_dry_run_ids": backend_mismatches,
        "hard_budget_violation_count": len(overspent),
        "hard_budget_violation_dry_run_ids": overspent,
        "execution_failure_count": len(failures),
        "execution_failures": failures,
        "dry_run_valid": valid,
        "rows": rows,
    }
