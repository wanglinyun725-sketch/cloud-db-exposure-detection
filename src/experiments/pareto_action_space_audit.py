"""Engineering audit for the frozen cross-tool Pareto action space."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from statistics import mean, median
from typing import Any

from src.agent.cross_cloud_environment import CrossCloudTelemetryEnvironment
from src.agent.ec_react import (
    PARETO_ACTION_SPACE_ID,
    _action_key,
    _compact_tool_output,
    _visible_event_map,
    pareto_action_candidates,
)
from src.agent.ec_react_protocol_validation import select_protocol_pairs
from src.agent.path_proposal import record_visible_observations
from src.agent.sigma_semantic_prior import SIGMA_SEMANTIC_PRIOR


def audit_pareto_action_space(
    root: str | Path,
    index_path: str | Path,
    *,
    budgets: tuple[int, ...] = (10, 20, 30),
    limit: int | None = None,
) -> dict[str, Any]:
    """Audit candidate generation on real episodes without evaluating labels."""
    root = Path(root).resolve()
    index_path = Path(index_path).resolve()
    index = json.loads(index_path.read_text(encoding="utf-8"))
    selected = select_protocol_pairs(index)
    if limit is not None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        selected = selected[:limit]

    episode_rows = [
        _audit_episode(root, index_path, episode, budgets)
        for episode in selected
    ]
    stage_names = ("after_summary", "after_search", "after_detail")
    return {
        "audit_version": "0.1",
        "pareto_action_space_id": PARETO_ACTION_SPACE_ID,
        "source_index": str(index_path.relative_to(root)),
        "episodes": len(episode_rows),
        "platforms": sorted({
            row["platform"] for row in episode_rows
        }),
        "budgets": list(budgets),
        "external_prior_coverage": _external_prior_coverage(selected),
        "trajectory": (
            "summarize_case -> first frontier search -> first frontier detail"
        ),
        "stages": {
            stage: _aggregate_stage(episode_rows, stage, budgets)
            for stage in stage_names
        },
        "probe_failures": [
            {
                "episode_id": row["episode_id"],
                "stop_reason": row["probe_stop_reason"],
            }
            for row in episode_rows
            if row["probe_stop_reason"]
            not in {"detail_observed", "empty_telemetry"}
        ],
        "empty_telemetry_episodes": sum(
            row["probe_stop_reason"] == "empty_telemetry"
            for row in episode_rows
        ),
        "episode_rows": episode_rows,
        "research_effectiveness_result": False,
        "interpretation": (
            "Engineering evidence about action-space coverage and pruning only; "
            "no human gold or attack-effectiveness claim is used."
        ),
    }


def _audit_episode(
    root: Path,
    index_path: Path,
    episode: dict[str, Any],
    budgets: tuple[int, ...],
) -> dict[str, Any]:
    environment = CrossCloudTelemetryEnvironment.from_file(
        root,
        index_path,
        episode["episode_id"],
        budget=None,
    )
    ledger: dict[str, list[dict[str, Any]]] = {}
    executed: set[str] = set()

    summary = environment.execute("summarize_case", {})
    executed.add(_action_key("summarize_case", {}))
    _record(ledger, summary)
    operation_counts = dict(
        summary["tool_result"].get("operation_counts", {})
    )
    service_counts = dict(
        summary["tool_result"].get("service_counts", {})
    )
    observation_count = int(
        summary["tool_result"].get("observation_count", 0)
    )
    stages = {
        "after_summary": _stage_snapshot(
            operation_counts,
            service_counts,
            ledger,
            observation_count,
            executed,
            budgets,
            episode["platform"],
        )
    }
    if observation_count == 0:
        return _episode_payload(
            episode,
            stages,
            "empty_telemetry",
        )

    search = next(
        (
            item for item in _frontier(
                operation_counts,
                service_counts,
                ledger,
                observation_count,
                executed,
                episode["platform"],
            )
            if item.tool_name == "search_events"
        ),
        None,
    )
    if search is None:
        return _episode_payload(
            episode,
            stages,
            "no_frontier_search",
        )
    search_output = environment.execute(
        search.tool_name,
        search.arguments,
    )
    executed.add(_action_key(search.tool_name, search.arguments))
    _record(ledger, search_output)
    stages["after_search"] = _stage_snapshot(
        operation_counts,
        service_counts,
        ledger,
        observation_count,
        executed,
        budgets,
        episode["platform"],
    )

    detail = next(
        (
            item for item in _frontier(
                operation_counts,
                service_counts,
                ledger,
                observation_count,
                executed,
                episode["platform"],
            )
            if item.tool_name == "get_event_detail"
        ),
        None,
    )
    if detail is None:
        return _episode_payload(
            episode,
            stages,
            "no_frontier_detail",
        )
    detail_output = environment.execute(
        detail.tool_name,
        detail.arguments,
    )
    executed.add(_action_key(detail.tool_name, detail.arguments))
    _record(ledger, detail_output)
    stages["after_detail"] = _stage_snapshot(
        operation_counts,
        service_counts,
        ledger,
        observation_count,
        executed,
        budgets,
        episode["platform"],
    )
    return _episode_payload(episode, stages, "detail_observed")


def _record(
    ledger: dict[str, list[dict[str, Any]]],
    output: dict[str, Any],
) -> None:
    record_visible_observations(
        ledger,
        output,
        _compact_tool_output(output),
    )


def _frontier(
    operation_counts: dict[str, int],
    service_counts: dict[str, int],
    ledger: dict[str, list[dict[str, Any]]],
    observation_count: int,
    executed: set[str],
    platform: str,
):
    return pareto_action_candidates(
        operation_counts,
        executed,
        service_counts=service_counts,
        visible_events=_visible_event_map(ledger),
        observation_count=observation_count,
        platform=platform,
        apply_pareto=True,
    )


def _stage_snapshot(
    operation_counts: dict[str, int],
    service_counts: dict[str, int],
    ledger: dict[str, list[dict[str, Any]]],
    observation_count: int,
    executed: set[str],
    budgets: tuple[int, ...],
    platform: str,
) -> dict[str, Any]:
    arguments = {
        "service_counts": service_counts,
        "visible_events": _visible_event_map(ledger),
        "observation_count": observation_count,
        "platform": platform,
    }
    full = pareto_action_candidates(
        operation_counts,
        executed,
        apply_pareto=False,
        **arguments,
    )
    frontier = pareto_action_candidates(
        operation_counts,
        executed,
        apply_pareto=True,
        **arguments,
    )
    full_keys = {
        _action_key(item.tool_name, item.arguments) for item in full
    }
    frontier_keys = {
        _action_key(item.tool_name, item.arguments) for item in frontier
    }
    if not frontier_keys.issubset(full_keys):
        raise AssertionError("Pareto frontier is not a subset of full actions")
    return {
        "full_count": len(full),
        "frontier_count": len(frontier),
        "pruned_count": len(full) - len(frontier),
        "pruning_rate": (
            (len(full) - len(frontier)) / len(full)
            if full
            else 0.0
        ),
        "full_tools": _tool_counts(full),
        "frontier_tools": _tool_counts(frontier),
        "budget_feasible_full": {
            str(budget): sum(
                item.estimated_cost <= budget for item in full
            )
            for budget in budgets
        },
        "budget_feasible_frontier": {
            str(budget): sum(
                item.estimated_cost <= budget for item in frontier
            )
            for budget in budgets
        },
    }


def _tool_counts(candidates) -> dict[str, int]:
    return dict(sorted(Counter(
        item.tool_name for item in candidates
    ).items()))


def _episode_payload(
    episode: dict[str, Any],
    stages: dict[str, dict[str, Any]],
    stop_reason: str,
) -> dict[str, Any]:
    return {
        "episode_id": episode["episode_id"],
        "platform": episode["platform"],
        "independence_group": episode["independence_group"],
        "stages": stages,
        "probe_stop_reason": stop_reason,
    }


def _aggregate_stage(
    rows: list[dict[str, Any]],
    stage: str,
    budgets: tuple[int, ...],
) -> dict[str, Any]:
    snapshots = [
        row["stages"][stage]
        for row in rows
        if stage in row["stages"]
    ]
    full_tools = Counter()
    frontier_tools = Counter()
    for item in snapshots:
        full_tools.update(item["full_tools"])
        frontier_tools.update(item["frontier_tools"])
    return {
        "episodes_reaching_stage": len(snapshots),
        "mean_full_count": _mean(snapshots, "full_count"),
        "median_full_count": _median(snapshots, "full_count"),
        "mean_frontier_count": _mean(snapshots, "frontier_count"),
        "median_frontier_count": _median(snapshots, "frontier_count"),
        "mean_pruning_rate": _mean(snapshots, "pruning_rate"),
        "full_action_tool_counts": dict(sorted(full_tools.items())),
        "frontier_action_tool_counts": dict(
            sorted(frontier_tools.items())
        ),
        "mean_budget_feasible_full": {
            str(budget): (
                mean(
                    item["budget_feasible_full"][str(budget)]
                    for item in snapshots
                )
                if snapshots
                else 0.0
            )
            for budget in budgets
        },
        "mean_budget_feasible_frontier": {
            str(budget): (
                mean(
                    item["budget_feasible_frontier"][str(budget)]
                    for item in snapshots
                )
                if snapshots
                else 0.0
            )
            for budget in budgets
        },
    }


def _mean(rows: list[dict[str, Any]], field: str) -> float:
    return mean(row[field] for row in rows) if rows else 0.0


def _median(rows: list[dict[str, Any]], field: str) -> float:
    return median(row[field] for row in rows) if rows else 0.0


def _external_prior_coverage(
    episodes: list[dict[str, Any]],
) -> dict[str, Any]:
    operation_events: Counter[tuple[str, str]] = Counter()
    for episode in episodes:
        for operation, count in episode.get(
            "operation_counts",
            {},
        ).items():
            operation_events[
                (episode["platform"], operation)
            ] += int(count)
    rows = [
        {
            "platform": platform,
            "operation": operation,
            "events": count,
            "matching_rules": SIGMA_SEMANTIC_PRIOR.score(
                operation,
                platform,
            ),
        }
        for (platform, operation), count in operation_events.items()
    ]
    supported = [row for row in rows if row["matching_rules"] > 0]
    total_events = sum(row["events"] for row in rows)
    supported_events = sum(row["events"] for row in supported)
    platforms = sorted({row["platform"] for row in rows})
    return {
        "prior_id": SIGMA_SEMANTIC_PRIOR.payload["prior_id"],
        "unique_platform_operations": len(rows),
        "supported_unique_platform_operations": len(supported),
        "unique_coverage_rate": (
            len(supported) / len(rows) if rows else 0.0
        ),
        "events": total_events,
        "supported_events": supported_events,
        "event_weighted_coverage_rate": (
            supported_events / total_events if total_events else 0.0
        ),
        "by_platform": {
            platform: _platform_prior_coverage(rows, platform)
            for platform in platforms
        },
        "interpretation": (
            "A zero match means no pinned Sigma rule support, not benign."
        ),
    }


def _platform_prior_coverage(
    rows: list[dict[str, Any]],
    platform: str,
) -> dict[str, Any]:
    selected = [row for row in rows if row["platform"] == platform]
    supported = [
        row for row in selected if row["matching_rules"] > 0
    ]
    events = sum(row["events"] for row in selected)
    supported_events = sum(row["events"] for row in supported)
    return {
        "unique_platform_operations": len(selected),
        "supported_unique_platform_operations": len(supported),
        "unique_coverage_rate": (
            len(supported) / len(selected) if selected else 0.0
        ),
        "event_weighted_coverage_rate": (
            supported_events / events if events else 0.0
        ),
    }
