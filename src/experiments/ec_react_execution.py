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
    schedule_arms = config.get("schedule_arms")
    schedule_errors = schedule_design_errors(config)
    if schedule_errors:
        raise ValueError(
            "invalid explicit schedule design: "
            + "; ".join(schedule_errors)
        )
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
    scheduled_identities: set[str] = set()
    for case, split in scheduled_cases:
        for instance in sorted(
            case.get("runtime_instances", []),
            key=lambda item: item["instance_id"],
        ):
            if schedule_arms:
                arm_conditions = _explicit_arm_conditions(
                    schedule_arms,
                    config["methods"],
                    config.get("models", []),
                    seeds,
                    split=split,
                    method_ids=method_ids,
                    model_ids=model_ids,
                )
            else:
                arm_conditions = _cartesian_conditions(
                    methods,
                    models,
                    shared,
                    seeds,
                )
            for (
                arm_id,
                method,
                budget,
                model_id,
                repeat,
                seed,
            ) in arm_conditions:
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
                identity_hash = _stable_hash(identity)
                if identity_hash in scheduled_identities:
                    raise ValueError(
                        "duplicate experimental condition across schedule "
                        f"arms for {identity}"
                    )
                scheduled_identities.add(identity_hash)
                rows.append({
                    **identity,
                    "schedule_arm_id": arm_id,
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
                    "schedule_id": "schedule-" + identity_hash[:24],
                })
    return rows


def schedule_design_errors(
    config: Mapping[str, Any],
) -> list[str]:
    """Return deterministic validation errors for optional explicit arms."""
    arms = config.get("schedule_arms")
    if arms is None:
        return []
    if not isinstance(arms, list) or not arms:
        return ["schedule_arms must be a non-empty list"]
    methods = {
        item.get("method_id"): item
        for item in config.get("methods", [])
        if isinstance(item, Mapping)
    }
    models = {
        item.get("model_id"): item
        for item in config.get("models", [])
        if isinstance(item, Mapping)
    }
    shared = config.get("shared_execution") or {}
    allowed_budgets = set(shared.get("budget_grid") or [])
    seed_count = len(shared.get("random_seeds") or [])
    errors: list[str] = []
    arm_ids: set[str] = set()
    conditions: dict[tuple[Any, ...], str] = {}
    for index, arm in enumerate(arms):
        if not isinstance(arm, Mapping):
            errors.append(f"schedule arm {index} must be an object")
            continue
        arm_id = arm.get("arm_id")
        if not isinstance(arm_id, str) or not arm_id:
            errors.append(f"schedule arm {index} has no arm_id")
            continue
        if arm_id in arm_ids:
            errors.append(f"duplicate schedule arm_id {arm_id}")
        arm_ids.add(arm_id)
        selected_methods = arm.get("method_ids")
        if not isinstance(selected_methods, list) or not selected_methods:
            errors.append(f"schedule arm {arm_id} has no methods")
            continue
        unknown_methods = sorted(set(selected_methods) - set(methods))
        if unknown_methods:
            errors.append(
                f"schedule arm {arm_id} has unknown methods "
                f"{unknown_methods}"
            )
            continue
        families = {
            methods[method_id].get("family")
            for method_id in selected_methods
        }
        if len(families) != 1:
            errors.append(
                f"schedule arm {arm_id} mixes method families"
            )
            continue
        family = next(iter(families))
        selected_models = arm.get("model_ids")
        if not isinstance(selected_models, list):
            errors.append(
                f"schedule arm {arm_id} model_ids must be a list"
            )
            continue
        if family == "llm":
            if not selected_models:
                errors.append(
                    f"LLM schedule arm {arm_id} has no models"
                )
                continue
            unknown_models = sorted(set(selected_models) - set(models))
            if unknown_models:
                errors.append(
                    f"schedule arm {arm_id} has unknown models "
                    f"{unknown_models}"
                )
                continue
        elif selected_models:
            errors.append(
                f"non-LLM schedule arm {arm_id} must not name models"
            )
            continue
        budgets = arm.get("budgets")
        if not isinstance(budgets, list) or not budgets:
            errors.append(f"schedule arm {arm_id} has no budgets")
            continue
        invalid_budgets = sorted(set(budgets) - allowed_budgets)
        if invalid_budgets:
            errors.append(
                f"schedule arm {arm_id} has budgets outside the frozen "
                f"grid: {invalid_budgets}"
            )
            continue
        repeats = arm.get("repeats")
        if (
            not isinstance(repeats, int)
            or isinstance(repeats, bool)
            or repeats < 1
            or repeats > seed_count
        ):
            errors.append(
                f"schedule arm {arm_id} repeats must be between 1 and "
                f"{seed_count}"
            )
            continue
        condition_models = selected_models if family == "llm" else [None]
        for method_id in selected_methods:
            for model_id in condition_models:
                for budget in budgets:
                    for repeat in range(repeats):
                        condition = (
                            method_id,
                            model_id,
                            budget,
                            repeat,
                        )
                        previous = conditions.get(condition)
                        if previous is not None:
                            errors.append(
                                f"schedule arms {previous} and {arm_id} "
                                f"duplicate condition {condition}"
                            )
                        conditions[condition] = arm_id
    return errors


def planned_runs_per_instance(config: Mapping[str, Any]) -> int:
    """Count frozen conditions per runtime instance."""
    return planned_runs_per_instance_for_selection(config)


def planned_runs_per_instance_for_selection(
    config: Mapping[str, Any],
    *,
    method_ids: set[str] | None = None,
    model_ids: set[str] | None = None,
) -> int:
    """Count frozen conditions after an explicit execution filter."""
    errors = schedule_design_errors(config)
    if errors:
        raise ValueError("; ".join(errors))
    shared = config["shared_execution"]
    arms = config.get("schedule_arms")
    if not arms:
        budgets = len(shared.get("budget_grid") or [])
        llm_repeats = int(shared.get("llm_repeats") or 0)
        deterministic_repeats = int(
            shared.get("deterministic_repeats") or 0
        )
        model_count = len(config.get("models") or [])
        total = 0
        for method in config.get("methods") or []:
            if (
                method_ids is not None
                and method.get("method_id") not in method_ids
            ):
                continue
            if method.get("family") == "llm":
                selected_model_count = (
                    model_count
                    if model_ids is None
                    else len([
                        item for item in config.get("models") or []
                        if item.get("model_id") in model_ids
                    ])
                )
                total += (
                    budgets * llm_repeats * selected_model_count
                )
            elif method.get("family") == "randomized":
                total += budgets * llm_repeats
            else:
                total += budgets * deterministic_repeats
        return total
    methods = {
        item["method_id"]: item for item in config["methods"]
    }
    total = 0
    for arm in arms:
        selected_methods = [
            item for item in arm["method_ids"]
            if method_ids is None or item in method_ids
        ]
        if not selected_methods:
            continue
        family = methods[selected_methods[0]]["family"]
        if family == "llm":
            selected_models = [
                item for item in arm["model_ids"]
                if model_ids is None or item in model_ids
            ]
            model_count = len(selected_models)
        else:
            model_count = 1
        total += (
            len(selected_methods)
            * model_count
            * len(arm["budgets"])
            * int(arm["repeats"])
        )
    return total


def _explicit_arm_conditions(
    arms: list[Mapping[str, Any]],
    all_methods: list[Mapping[str, Any]],
    all_models: list[Mapping[str, Any]],
    seeds: list[int],
    *,
    split: str,
    method_ids: set[str] | None,
    model_ids: set[str] | None,
) -> list[tuple[str, Mapping[str, Any], int, str | None, int, int]]:
    methods = {item["method_id"]: item for item in all_methods}
    known_models = {item["model_id"] for item in all_models}
    output = []
    for arm in arms:
        allowed_splits = arm.get("splits")
        if allowed_splits is not None and split not in allowed_splits:
            continue
        for method_id in arm["method_ids"]:
            if method_ids is not None and method_id not in method_ids:
                continue
            method = methods[method_id]
            if method["family"] == "llm":
                selected_models = [
                    item for item in arm["model_ids"]
                    if item in known_models
                    and (model_ids is None or item in model_ids)
                ]
            else:
                selected_models = [None]
            for budget in arm["budgets"]:
                for selected_model in selected_models:
                    for repeat in range(int(arm["repeats"])):
                        output.append((
                            arm["arm_id"],
                            method,
                            int(budget),
                            selected_model,
                            repeat,
                            seeds[repeat],
                        ))
    return output


def _cartesian_conditions(
    methods: list[Mapping[str, Any]],
    models: list[Mapping[str, Any]],
    shared: Mapping[str, Any],
    seeds: list[int],
) -> list[tuple[str, Mapping[str, Any], int, str | None, int, int]]:
    output = []
    for method in methods:
        family = method["family"]
        if family == "llm":
            conditions = [
                (model["model_id"], repeat, seeds[repeat])
                for model in models
                for repeat in range(int(shared["llm_repeats"]))
            ]
        elif family == "randomized":
            conditions = [
                (None, repeat, seeds[repeat])
                for repeat in range(int(shared["llm_repeats"]))
            ]
        else:
            conditions = [
                (None, repeat, seeds[repeat])
                for repeat in range(
                    int(shared["deterministic_repeats"])
                )
            ]
        for budget in shared["budget_grid"]:
            for model_id, repeat, seed in conditions:
                output.append((
                    "legacy_cartesian",
                    method,
                    int(budget),
                    model_id,
                    repeat,
                    seed,
                ))
    return output


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
