"""Frozen single-run execution for EC-ReAct and fair baselines."""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from time import perf_counter
from typing import Any, Mapping

from src.agent.baseline_policies import (
    FixedOrderPathPolicy,
    FullQueryPathPolicy,
    RandomToolPathPolicy,
)
from src.agent.ec_react import ECReactRunner, PARETO_ACTION_SPACE_ID
from src.agent.ec_react_langgraph import ECReactLangGraphRunner
from src.agent.sigma_semantic_prior import SIGMA_SEMANTIC_PRIOR
from src.agent.frozen_runtime_environment import (
    FrozenRuntimeInstanceEnvironment,
)
from src.agent.frozen_negative_control_environment import (
    FrozenNegativeControlEnvironment,
)
from src.experiments.path_scoring import score_path_discovery
from src.graph.path_ontology import ontology_reference


def run_frozen_instance(
    gold_case: dict[str, Any],
    instance_id: str,
    *,
    method: Mapping[str, Any],
    shared_execution: Mapping[str, Any],
    policy: Any,
    budget: int,
    repeat: int,
    seed: int,
    model_id: str | None = None,
    model_name: str | None = None,
    model_digest: str | None = None,
    config_sha256: str | None = None,
) -> dict[str, Any]:
    """Run and score one independently labeled telemetry instance."""
    _validate_run_contract(method, shared_execution, budget, repeat)
    environment_class = (
        FrozenNegativeControlEnvironment
        if gold_case.get("case_kind") == "external_negative_control"
        else FrozenRuntimeInstanceEnvironment
    )
    environment = environment_class(gold_case, instance_id, budget=budget)
    runner_class = {
        "linear": ECReactRunner,
        "langgraph": ECReactLangGraphRunner,
    }.get(shared_execution["orchestration_backend"])
    if runner_class is None:
        raise ValueError("orchestration_backend must be linear or langgraph")
    runner = runner_class(
        policy,
        max_steps=int(shared_execution["max_steps"]),
        task_mode="path_discovery",
        finish_guard_mode=method["finish_guard_mode"],
        pareto_guard=method["pareto_guard"],
        external_rule_prior=method["external_rule_prior"],
        four_value_memory=method["four_value_memory"],
        budget_stop=method["budget_stop"],
        provider_scope_gate=method.get("provider_scope_gate", True),
        max_path_candidates=int(
            shared_execution["max_path_candidates"]
        ),
    )
    metadata = environment.evaluation_metadata()
    run_identity = {
        "case_id": metadata["case_id"],
        "instance_id": instance_id,
        "method_id": method["method_id"],
        "model_id": model_id,
        "model_name": model_name,
        "model_digest": model_digest,
        "budget": budget,
        "repeat": repeat,
        "seed": seed,
        "config_sha256": config_sha256,
    }
    run_id = "run-" + _stable_hash(run_identity)[:24]
    started = perf_counter()
    result = runner.run(environment, environment.public_context)
    latency_seconds = perf_counter() - started
    score = score_path_discovery(
        result,
        metadata,
        k=int(shared_execution["max_path_candidates"]),
    )
    result_payload = asdict(result)
    return {
        "execution_version": "0.3",
        "run_id": run_id,
        **run_identity,
        "source_id": metadata["source_id"],
        "scenario_source_id": metadata["scenario_source_id"],
        "runtime_evidence_source_id": metadata[
            "runtime_evidence_source_id"
        ],
        "platform": metadata["platform"],
        "independence_group": metadata["independence_group"],
        "provenance_level": metadata["provenance_level"],
        "orchestration_backend": shared_execution[
            "orchestration_backend"
        ],
        "pareto_action_space_id": shared_execution[
            "pareto_action_space_id"
        ],
        "external_action_prior_id": shared_execution[
            "external_action_prior_id"
        ],
        "method_components": {
            key: method[key]
            for key in (
                "pareto_guard",
                "external_rule_prior",
                "four_value_memory",
                "budget_stop",
                "provider_scope_gate",
                "evidence_citation_guard",
                "finish_guard_mode",
            )
            if key in method
        },
        "hard_budget_enforced": True,
        "human_gold_used_for_scoring_only": True,
        "research_effectiveness_result": True,
        "gold_digest": _stable_hash(metadata),
        "latency_seconds": latency_seconds,
        "result": result_payload,
        "score": score,
        "result_digest": _stable_hash(
            {
                "result": result_payload,
                "score": score,
            }
        ),
        "secrets_in_record": False,
    }


def policy_for_non_llm_method(
    method_id: str,
    *,
    seed: int,
    max_path_candidates: int,
) -> Any:
    if method_id == "fixed_order":
        return FixedOrderPathPolicy(max_path_candidates)
    if method_id == "random_tool":
        return RandomToolPathPolicy(seed, max_path_candidates)
    if method_id == "full_query":
        return FullQueryPathPolicy(max_path_candidates)
    raise ValueError(f"no non-LLM policy for method: {method_id}")


def build_run_schedule(
    config: Mapping[str, Any],
    gold_release: Mapping[str, Any],
    split_manifest: Mapping[str, Any],
    *,
    negative_release: Mapping[str, Any] | None = None,
    splits: set[str] | None = None,
    method_ids: set[str] | None = None,
    model_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Build a deterministic instance-level schedule without loading secrets."""
    shared = config["shared_execution"]
    seeds = list(shared["random_seeds"])
    llm_repeats = int(shared["llm_repeats"])
    deterministic_repeats = int(shared["deterministic_repeats"])
    if llm_repeats > len(seeds) or deterministic_repeats > len(seeds):
        raise ValueError("frozen repeat count exceeds available random seeds")
    methods = [
        item for item in config["methods"]
        if method_ids is None or item["method_id"] in method_ids
    ]
    models = [
        item for item in config.get("models", [])
        if model_ids is None or item["model_id"] in model_ids
    ]
    assignments = {
        item["case_id"]: item
        for item in split_manifest["assignments"]
    }
    scheduled_cases: list[tuple[Mapping[str, Any], str]] = []
    for case in sorted(
        gold_release["cases"],
        key=lambda item: item["case_id"],
    ):
        if (
            (case.get("admission_screen") or {}).get("decision")
            != "accept"
        ):
            continue
        assignment = assignments.get(case["case_id"])
        if assignment is None:
            raise ValueError(
                f"case {case['case_id']} is missing from split manifest"
            )
        split = assignment["split"]
        if splits is not None and split not in splits:
            continue
        scheduled_cases.append((case, split))
    if negative_release is not None:
        for case in sorted(
            negative_release.get("cases", []),
            key=lambda item: item["case_id"],
        ):
            screening = case.get("screening") or {}
            if not all(
                screening.get(field) is True
                for field in (
                    "cloud_data_relevant",
                    "non_attack_confirmed",
                    "usable_as_negative_control",
                )
            ):
                continue
            split = "external_negative_control"
            if splits is not None and split not in splits:
                continue
            scheduled_cases.append((case, split))

    rows = []
    for case, split in scheduled_cases:
        for instance in sorted(
            case.get("runtime_instances", []),
            key=lambda item: item["instance_id"],
        ):
            for method in methods:
                family = method["family"]
                if family == "llm":
                    conditions = [
                        (model["model_id"], repeat, seeds[repeat])
                        for model in models
                        for repeat in range(llm_repeats)
                    ]
                elif family == "randomized":
                    conditions = [
                        (None, repeat, seeds[repeat])
                        for repeat in range(llm_repeats)
                    ]
                else:
                    conditions = [
                        (None, repeat, seeds[repeat])
                        for repeat in range(deterministic_repeats)
                    ]
                for budget in shared["budget_grid"]:
                    for model_id, repeat, seed in conditions:
                        identity = {
                            "case_id": case["case_id"],
                            "instance_id": instance["instance_id"],
                            "split": split,
                            "method_id": method["method_id"],
                            "model_id": model_id,
                            "budget": budget,
                            "repeat": repeat,
                            "seed": seed,
                        }
                        rows.append({
                            **identity,
                            "scenario_source_id": case["source"][
                                "source_id"
                            ],
                            "runtime_evidence_source_id": (
                                instance.get("runtime_source_id")
                                or case["source"]["source_id"]
                            ),
                            "platform": instance.get(
                                "platform", "unspecified"
                            ),
                            "schedule_id": (
                                "schedule-" + _stable_hash(identity)[:24]
                            ),
                        })
    return rows


def _validate_run_contract(
    method: Mapping[str, Any],
    shared: Mapping[str, Any],
    budget: int,
    repeat: int,
) -> None:
    if budget not in shared.get("budget_grid", []):
        raise ValueError("budget is not in the frozen budget grid")
    if repeat < 0:
        raise ValueError("repeat must be non-negative")
    if method.get("tool_schema_id") != shared.get("tool_schema_id"):
        raise ValueError("method tool schema differs from shared schema")
    if method.get("output_contract_id") != shared.get(
        "output_contract_id"
    ):
        raise ValueError("method output contract differs from shared contract")
    if method.get("max_steps") != shared.get("max_steps"):
        raise ValueError("method max_steps differs from shared max_steps")
    if method.get("max_path_candidates") != shared.get(
        "max_path_candidates"
    ):
        raise ValueError("method path limit differs from shared path limit")
    if shared.get("hard_budget_enforced") is not True:
        raise ValueError("hard budget must remain enabled")
    if shared.get("executable_evidence_tests") is not True:
        raise ValueError("executable evidence tests must remain enabled")
    if shared.get("pareto_action_space_id") != PARETO_ACTION_SPACE_ID:
        raise ValueError("shared Pareto action space differs from frozen code")
    if shared.get("external_action_prior_id") != (
        SIGMA_SEMANTIC_PRIOR.payload["prior_id"]
    ):
        raise ValueError(
            "shared external action prior differs from frozen code"
        )
    if shared.get("path_ontology_id") != ontology_reference()["ontology_id"]:
        raise ValueError("shared path ontology differs from frozen ontology")
    expected_finish_mode = (
        "strict" if method.get("evidence_citation_guard") else "record"
    )
    if method.get("finish_guard_mode") != expected_finish_mode:
        raise ValueError("citation guard and finish mode disagree")


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
