"""Refutation-aware path search for partial evidence graphs."""
from __future__ import annotations

from dataclasses import dataclass, field

from src.graph.constrained_search import VALID_EDGE_TRANSITIONS
from src.graph.gate_score import gate_score, compute_evidence_vector, verify_path
from src.graph.path_utils import EvidencePath


@dataclass(order=True)
class SearchItem:
    priority: float
    node: str = field(compare=False)
    path: EvidencePath = field(compare=False)
    last_edge_type: str | None = field(compare=False)
    visited: set[str] = field(compare=False)
    score: float = field(compare=False, default=0.0)
    query_cost: int = field(compare=False, default=0)


def refute_aware_beam_search(
    G,
    entry_nodes: list[str],
    target_nodes: list[str],
    min_depth: int = 4,
    max_depth: int = 8,
    beam_width: int = 4,
    top_k: int = 20,
    use_temporal: bool = True,
    use_query_cost: bool = True,
    use_refute_scoring: bool = True,
) -> dict:
    target_set = set(target_nodes)
    frontier = [
        SearchItem(
            0.0,
            start,
            EvidencePath([start]),
            None,
            {start},
            _node_score(G, start),
            0,
        )
        for start in entry_nodes
    ]
    completed = []
    expanded = 0
    generated = 0

    for _depth in range(max_depth):
        next_frontier = []
        for item in frontier:
            current_edges = list(G.edges(item.node, keys=True, data=True))
            expanded += len(current_edges)
            for _, neighbor, edge_key, edge_data in current_edges:
                if neighbor in item.visited:
                    continue
                edge_type = edge_data.get("edge_type", "")
                if item.last_edge_type is not None and edge_type not in VALID_EDGE_TRANSITIONS.get(item.last_edge_type, set()):
                    continue
                new_path = item.path.extended(neighbor, edge_key, edge_type)
                new_score = item.score + _edge_score(edge_data, use_temporal, use_refute_scoring) + _node_score(G, neighbor)
                query_cost = item.query_cost + int(edge_data.get("query_cost", 1))
                rank_score = new_score
                if use_query_cost:
                    rank_score -= 0.15 * query_cost
                rank_score -= 0.02 * (len(new_path) - 1)
                generated += 1
                next_item = SearchItem(-rank_score, neighbor, new_path, edge_type, item.visited | {neighbor}, new_score, query_cost)
                if neighbor in target_set and min_depth <= len(new_path) - 1 <= max_depth:
                    completed.append(next_item)
                if len(new_path) - 1 < max_depth:
                    next_frontier.append(next_item)
        next_frontier.sort()
        frontier = next_frontier[:beam_width]
        if not frontier:
            break

    ranked = sorted(completed, key=lambda item: _complete_path_score(G, item, use_query_cost), reverse=True)
    return {
        "paths": [item.path for item in ranked[:top_k]],
        "expanded_edges": expanded,
        "generated_paths": generated,
        "completed_paths": len(completed),
    }


def _complete_path_score(G, item: SearchItem, use_query_cost: bool = True) -> float:
    verification = verify_path(G, item.path)
    state_bonus = {"Valid": 3.0, "Insufficient": 0.5, "Invalid": -3.0}[verification["state"]]
    risk_score = gate_score(compute_evidence_vector(G, item.path))["score"]
    score = state_bonus + item.score + risk_score - 0.4 * len(verification["missing"]) - 1.2 * len(verification["refuted"])
    if use_query_cost:
        score -= 0.15 * item.query_cost
    return score


def _edge_score(edge_data: dict, use_temporal: bool = True, use_refute_scoring: bool = True) -> float:
    strength = float(edge_data.get("strength", edge_data.get("confidence", 0.5)))
    status = edge_data.get("status", "Supported")
    
    if use_temporal and edge_data.get("temporal_conflict"):
        return -2.0
    
    if use_refute_scoring:
        if status == "Contradicted":
            return -1.5 - (1.0 - strength)
        if status == "Unknown":
            return -0.3
    
    return 0.4 + strength


def _node_score(G, node: str) -> float:
    data = G.nodes.get(node, {})
    ntype = data.get("node_type")
    if ntype == "SensitiveTag":
        return 1.5 * data.get("level", 0) * data.get("confidence", 1.0) / 4.0
    if ntype == "DBObject" and data.get("kind") in {"field", "table"}:
        return 0.2
    if ntype == "AuditEvent":
        return 0.2 * data.get("anomaly_score", 0.0)
    return 0.0
