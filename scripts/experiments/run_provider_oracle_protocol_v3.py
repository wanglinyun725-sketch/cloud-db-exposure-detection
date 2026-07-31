"""Run the leakage-separated provider-oracle protocol-v3 pilot."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import math
from pathlib import Path
import statistics
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.baseline_policies import (  # noqa: E402
    FixedOrderPathPolicy,
    FullQueryPathPolicy,
    ProviderAwarePathPolicy,
    RandomToolPathPolicy,
)
from src.agent.ec_react import ECReactRunner  # noqa: E402
from src.agent.frozen_provider_oracle_environment import (  # noqa: E402
    FrozenProviderOracleEnvironment,
)
from src.experiments.provider_oracle_scoring import (  # noqa: E402
    score_provider_oracle_state,
)


DEFAULT_CONFIG = ROOT / "configs" / "provider_oracle_protocol_v3.json"
DEFAULT_OUTPUT = ROOT / "output" / "provider_oracle_protocol_v3_results.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _policy(
    method: dict[str, Any],
    *,
    seed: int,
    max_path_candidates: int,
) -> Any:
    name = method["policy"]
    if name == "ProviderAwarePathPolicy":
        return ProviderAwarePathPolicy()
    if name == "FixedOrderPathPolicy":
        return FixedOrderPathPolicy(max_path_candidates)
    if name == "FullQueryPathPolicy":
        return FullQueryPathPolicy(max_path_candidates)
    if name == "RandomToolPathPolicy":
        return RandomToolPathPolicy(seed, max_path_candidates)
    raise ValueError(f"unknown provider-oracle policy: {name}")


def run(config_path: Path) -> dict[str, Any]:
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes.decode("utf-8"))
    public_path = ROOT / config["data"]["public_packet"]
    gold_path = ROOT / config["data"]["evaluator_gold"]
    split_path = ROOT / config["data"]["split_manifest"]
    public = _load(public_path)
    gold = _load(gold_path)
    splits = _load(split_path)
    if public.get("dataset_role") != "agent_visible":
        raise ValueError("public packet role is invalid")
    if gold.get("dataset_role") != "evaluator_only":
        raise ValueError("gold packet role is invalid")
    public_ids = {item["candidate_id"] for item in public["cases"]}
    gold_ids = {item["case_id"] for item in gold["cases"]}
    if public_ids != gold_ids:
        raise ValueError("public/gold case sets differ")
    assignments = {
        item["case_id"]: item for item in splits["assignments"]
    }
    if set(assignments) != gold_ids:
        raise ValueError("split manifest differs from gold cases")

    execution = config["execution"]
    rows = []
    for metadata in sorted(gold["cases"], key=lambda item: item["case_id"]):
        for method in config["methods"]:
            seeds = (
                execution["random_seeds"]
                if method["family"] == "randomized"
                else execution["random_seeds"][:1]
            )
            for budget in execution["budget_grid"]:
                for repeat, seed in enumerate(seeds):
                    environment = FrozenProviderOracleEnvironment(
                        public,
                        metadata,
                        budget=budget,
                    )
                    policy = _policy(
                        method,
                        seed=seed,
                        max_path_candidates=execution[
                            "max_path_candidates"
                        ],
                    )
                    runner = ECReactRunner(
                        policy,
                        max_steps=execution["max_steps"],
                        task_mode="path_discovery",
                        finish_guard_mode=method["finish_guard_mode"],
                        pareto_guard=method["pareto_guard"],
                        external_rule_prior=method["external_rule_prior"],
                        four_value_memory=method["four_value_memory"],
                        budget_stop=method["budget_stop"],
                        provider_scope_gate=method.get(
                            "provider_scope_gate",
                            True,
                        ),
                        max_path_candidates=execution[
                            "max_path_candidates"
                        ],
                    )
                    result = runner.run(
                        environment, environment.public_context
                    )
                    score = score_provider_oracle_state(
                        result, environment.evaluation_metadata()
                    )
                    identity = {
                        "protocol_version": config["protocol_version"],
                        "case_id": metadata["case_id"],
                        "method_id": method["method_id"],
                        "budget": budget,
                        "repeat": repeat,
                        "seed": seed,
                    }
                    run_id = "provider-run-" + sha256(
                        json.dumps(
                            identity,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()[:20]
                    rows.append(
                        {
                            "run_id": run_id,
                            **identity,
                            "split": assignments[
                                metadata["case_id"]
                            ]["split"],
                            "independence_group": metadata[
                                "independence_group"
                            ],
                            "platform": metadata["platform"],
                            "label_origin": metadata["label_origin"],
                            "method_components": {
                                key: method[key]
                                for key in (
                                    "pareto_guard",
                                    "external_rule_prior",
                                    "four_value_memory",
                                    "budget_stop",
                                    "provider_scope_gate",
                                    "finish_guard_mode",
                                )
                                if key in method
                            },
                            "result": asdict(result),
                            "score": score,
                        }
                    )
    return {
        "experiment_id": config["experiment_id"],
        "protocol_version": config["protocol_version"],
        "research_effectiveness_result": False,
        "warning": (
            "This is a protocol-scale pilot. Repeated random seeds and "
            "source retries are not additional independent cases; no "
            "population-level significance claim is permitted."
        ),
        "config_path": str(config_path.relative_to(ROOT)),
        "config_sha256": sha256(config_bytes).hexdigest(),
        "public_packet_path": str(public_path.relative_to(ROOT)),
        "public_packet_sha256": sha256(public_path.read_bytes()).hexdigest(),
        "gold_packet_path": str(gold_path.relative_to(ROOT)),
        "gold_packet_sha256": sha256(gold_path.read_bytes()).hexdigest(),
        "agent_loaded_gold": False,
        "human_gold_cases": gold["human_gold_cases"],
        "provider_oracle_gold_cases": gold[
            "provider_oracle_gold_cases"
        ],
        "epistemic_control_cases": gold["epistemic_control_cases"],
        "independence_groups": len({
            item["independence_group"] for item in gold["cases"]
        }),
        "summary": summarize(rows),
        "rows": rows,
    }


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(
            (row["method_id"], row["budget"]), []
        ).append(row)
    output = []
    for (method_id, budget), selected in sorted(groups.items()):
        scores = [item["score"] for item in selected]
        provider = [
            item for item in scores if item["provider_oracle_gold"]
        ]
        controls = [
            item for item in scores if item["epistemic_control"]
        ]
        by_independence_group: dict[str, list[dict[str, Any]]] = {}
        for row in selected:
            by_independence_group.setdefault(
                row["independence_group"], []
            ).append(row)

        provider_group_state = []
        provider_group_semantic = []
        negative_group_rejection = []
        control_group_abstention = []
        false_reachable_groups = []
        group_query_costs = []
        provider_group_edge_f1 = []
        for group_rows in by_independence_group.values():
            group_scores = [item["score"] for item in group_rows]
            provider_scores = [
                item for item in group_scores
                if item["provider_oracle_gold"]
            ]
            negative_scores = [
                item for item in provider_scores
                if item["gold_state"] == "NotReachable"
            ]
            control_scores = [
                item for item in group_scores
                if item["epistemic_control"]
            ]
            if provider_scores:
                # Strict clustered success: every case and randomized repeat
                # inside one lineage must succeed before that lineage counts.
                provider_group_state.append(all(
                    item["state_correct"] for item in provider_scores
                ))
                provider_group_semantic.append(all(
                    item["semantically_correct_state"]
                    for item in provider_scores
                ))
                provider_group_edge_f1.append(_mean(
                    item["gold_path_edge_f1"]
                    for item in provider_scores
                ))
            if negative_scores:
                negative_group_rejection.append(all(
                    item["correct_rejection"]
                    for item in negative_scores
                ))
            if control_scores:
                control_group_abstention.append(all(
                    item["correct_abstention"]
                    for item in control_scores
                ))
            false_reachable_groups.append(any(
                item["false_reachable"] for item in group_scores
            ))
            group_query_costs.append(_mean(
                item["query_cost"] for item in group_scores
            ))

        provider_state_rate = _mean(provider_group_state)
        provider_semantic_rate = _mean(provider_group_semantic)
        rejection_rate = _mean(negative_group_rejection)
        abstention_rate = _mean(control_group_abstention)
        false_reachable_rate = _mean(false_reachable_groups)
        output.append(
            {
                "method_id": method_id,
                "budget": budget,
                "runs": len(selected),
                "case_count": len({
                    item["case_id"] for item in selected
                }),
                "independence_groups": len({
                    item["independence_group"] for item in selected
                }),
                "effective_provider_gold_groups": len(
                    provider_group_state
                ),
                "effective_negative_groups": len(
                    negative_group_rejection
                ),
                "effective_unknown_control_groups": len(
                    control_group_abstention
                ),
                "aggregation": (
                    "strict_independence_group; all cases and repeats in a "
                    "lineage must pass for binary success"
                ),
                "provider_gold_state_accuracy": provider_state_rate,
                "provider_gold_state_accuracy_ci95": _wilson_interval(
                    provider_group_state
                ),
                (
                    "provider_gold_semantically_grounded_accuracy"
                ): provider_semantic_rate,
                (
                    "provider_gold_semantically_grounded_accuracy_ci95"
                ): _wilson_interval(provider_group_semantic),
                "correct_rejection_rate": rejection_rate,
                "correct_rejection_rate_ci95": _wilson_interval(
                    negative_group_rejection
                ),
                "unknown_control_abstention_rate": abstention_rate,
                "unknown_control_abstention_rate_ci95": _wilson_interval(
                    control_group_abstention
                ),
                "false_reachable_rate": false_reachable_rate,
                "false_reachable_rate_ci95": _wilson_interval(
                    false_reachable_groups
                ),
                "mean_query_cost": _mean(group_query_costs),
                "mean_gold_path_edge_f1": _mean(
                    provider_group_edge_f1
                ),
                "diagnostic_case_run_metrics": {
                    "provider_gold_state_accuracy": _mean(
                        item["state_correct"] for item in provider
                    ),
                    (
                        "provider_gold_semantically_grounded_accuracy"
                    ): _mean(
                        item["semantically_correct_state"]
                        for item in provider
                    ),
                    "correct_rejection_rate": _mean(
                        item["correct_rejection"]
                        for item in provider
                        if item["gold_state"] == "NotReachable"
                    ),
                    "unknown_control_abstention_rate": _mean(
                        item["correct_abstention"] for item in controls
                    ),
                    "false_reachable_rate": _mean(
                        item["false_reachable"] for item in scores
                    ),
                },
            }
        )
    return output


def _mean(values) -> float | None:
    materialized = list(values)
    if not materialized:
        return None
    return statistics.fmean(materialized)


def _wilson_interval(
    outcomes,
    *,
    z: float = 1.959963984540054,
) -> list[float] | None:
    """Return a two-sided Wilson interval for independent binary groups."""
    materialized = [bool(value) for value in outcomes]
    n = len(materialized)
    if not n:
        return None
    proportion = sum(materialized) / n
    z2 = z * z
    denominator = 1 + z2 / n
    center = (proportion + z2 / (2 * n)) / denominator
    half_width = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / n
            + z2 / (4 * n * n)
        )
        / denominator
    )
    return [center - half_width, center + half_width]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = run(args.config.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(
        {
            "protocol_version": report["protocol_version"],
            "runs": len(report["rows"]),
            "independence_groups": report["independence_groups"],
            "provider_oracle_gold_cases": report[
                "provider_oracle_gold_cases"
            ],
            "research_effectiveness_result": False,
            "output": str(args.output),
        },
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
