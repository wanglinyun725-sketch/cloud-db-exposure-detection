"""Offline protocol validation across real three-cloud telemetry pairs.

This module validates orchestration equivalence, guard behavior and label
leakage.  It deliberately does not estimate attack-path effectiveness because
the source-published payload condition is not a human path gold label.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from src.agent.cross_cloud_environment import (
    CrossCloudTelemetryEnvironment,
)
from src.agent.ec_react import ECReactRunner, ProgressiveTelemetryPolicy
from src.agent.ec_react_langgraph import ECReactLangGraphRunner


def select_protocol_pairs(
    episode_index: dict[str, Any],
) -> list[dict[str, Any]]:
    """Select one complete real y/n pair per platform×attack group.

    The default log profile is preferred; the run ID is then chosen
    lexicographically.  No episodes or labels are generated.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for episode in episode_index.get("episodes", []):
        key = (episode["platform"], episode["attack"])
        grouped.setdefault(key, []).append(episode)

    selected: list[dict[str, Any]] = []
    for key in sorted(grouped):
        by_profile_run: dict[
            tuple[str, int],
            dict[str, dict[str, Any]],
        ] = {}
        for episode in grouped[key]:
            pair_key = (episode["log_profile"], episode["run_id"])
            by_profile_run.setdefault(pair_key, {})[
                episode["source_condition"]
            ] = episode
        complete = [
            (profile, run_id, conditions)
            for (profile, run_id), conditions in by_profile_run.items()
            if set(conditions) == {"payload_absent", "payload_present"}
        ]
        if not complete:
            raise ValueError(
                "no complete source-published pair for "
                f"{key[0]}×{key[1]}"
            )
        profile, run_id, conditions = min(
            complete,
            key=lambda item: (
                item[0] != "default",
                item[0],
                item[1],
            ),
        )
        del profile, run_id
        selected.extend(
            [
                conditions["payload_absent"],
                conditions["payload_present"],
            ]
        )
    return selected


def validate_episode(
    root: str | Path,
    index_path: str | Path,
    episode: dict[str, Any],
    *,
    budget: int = 30,
) -> dict[str, Any]:
    """Run both orchestrators on one episode and compare complete results."""
    root = Path(root)
    index_path = Path(index_path)
    linear_environment = CrossCloudTelemetryEnvironment.from_file(
        root,
        index_path,
        episode["episode_id"],
        budget=budget,
    )
    graph_environment = CrossCloudTelemetryEnvironment.from_file(
        root,
        index_path,
        episode["episode_id"],
        budget=budget,
    )
    linear = ECReactRunner(ProgressiveTelemetryPolicy()).run(
        linear_environment,
        linear_environment.public_context,
    )
    graph = ECReactLangGraphRunner(
        ProgressiveTelemetryPolicy()
    ).run(
        graph_environment,
        graph_environment.public_context,
    )
    linear_payload = asdict(linear)
    graph_payload = asdict(graph)
    visible_policy_text = json.dumps(
        {
            "public_context": linear_environment.public_context,
            "trace": linear_payload["trace"],
        },
        ensure_ascii=False,
        sort_keys=True,
    ).casefold()
    hidden_terms = {
        episode["episode_id"].casefold(),
        episode["candidate_id"].casefold(),
        episode["attack"].casefold(),
        episode["source_condition"].casefold(),
    }
    leaked_terms = sorted(
        term for term in hidden_terms
        if term and term in visible_policy_text
    )
    return {
        "episode_id": episode["episode_id"],
        "independence_group": episode["independence_group"],
        "platform": episode["platform"],
        "attack": episode["attack"],
        "log_profile": episode["log_profile"],
        "run_id": episode["run_id"],
        "source_condition": episode["source_condition"],
        "backend_equivalent": linear_payload == graph_payload,
        "hidden_terms_visible_to_policy": leaked_terms,
        "linear": linear_payload,
        "langgraph": graph_payload,
    }


def run_protocol_validation(
    root: str | Path,
    index_path: str | Path,
    *,
    budget: int = 30,
    limit: int | None = None,
) -> dict[str, Any]:
    """Validate a deterministic, source-stratified real telemetry subset."""
    if budget <= 0:
        raise ValueError("budget must be positive")
    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive or None")
    root = Path(root)
    index_path = Path(index_path)
    raw_bytes = index_path.read_bytes()
    index = json.loads(raw_bytes.decode("utf-8"))
    selected = select_protocol_pairs(index)
    if limit is not None:
        selected = selected[:limit]
    rows = [
        validate_episode(
            root,
            index_path,
            episode,
            budget=budget,
        )
        for episode in selected
    ]
    backend_mismatches = [
        row["episode_id"]
        for row in rows
        if not row["backend_equivalent"]
    ]
    leakage_failures = [
        {
            "episode_id": row["episode_id"],
            "terms": row["hidden_terms_visible_to_policy"],
        }
        for row in rows
        if row["hidden_terms_visible_to_policy"]
    ]
    conditions = sorted({
        row["source_condition"] for row in rows
    })
    decision_by_condition = {
        condition: dict(sorted(Counter(
            row["linear"]["decision"]
            for row in rows
            if row["source_condition"] == condition
        ).items()))
        for condition in conditions
    }
    return {
        "validation_version": "0.1",
        "purpose": (
            "orchestration equivalence, guard and hidden-label leakage "
            "validation on real published telemetry"
        ),
        "research_effectiveness_result": False,
        "warning": (
            "Source payload conditions are not human attack-path gold. "
            "These rows must not be reported as main-method accuracy."
        ),
        "source_index": str(index_path.relative_to(root)),
        "source_index_sha256": sha256(raw_bytes).hexdigest(),
        "selection_policy": (
            "one complete source-published pair per platform×attack; "
            "prefer default profile and smallest run ID"
        ),
        "budget_per_run": budget,
        "episodes": len(rows),
        "platform_attack_groups": len({
            (row["platform"], row["attack"]) for row in rows
        }),
        "independence_groups": len({
            row["independence_group"] for row in rows
        }),
        "source_conditions": conditions,
        "descriptive_diagnostics": {
            "decision_by_source_condition": decision_by_condition,
            "mean_valid_tool_calls": (
                sum(
                    row["linear"]["valid_tool_calls"] for row in rows
                ) / len(rows)
                if rows else 0.0
            ),
            "mean_query_cost": (
                sum(row["linear"]["spent"] for row in rows) / len(rows)
                if rows else 0.0
            ),
            "interpretation": (
                "Descriptive engineering diagnostics only. In particular, "
                "a candidate_evidence_found decision is not a verified "
                "attack path and must not be scored as a true positive."
            ),
        },
        "backend_mismatch_count": len(backend_mismatches),
        "backend_mismatch_episode_ids": backend_mismatches,
        "policy_leakage_failure_count": len(leakage_failures),
        "policy_leakage_failures": leakage_failures,
        "protocol_valid": (
            not backend_mismatches and not leakage_failures
        ),
        "rows": rows,
    }
