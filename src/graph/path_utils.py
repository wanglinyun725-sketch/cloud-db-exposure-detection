"""Edge-aware path helpers with backwards compatibility for node-only paths."""
from __future__ import annotations

from itertools import product
from typing import Iterable


class EvidencePath(list):
    """A node-list path that also records the exact MultiDiGraph edges used.

    It intentionally subclasses ``list`` so existing display, serialization,
    and agent code that expects ``list[str]`` keeps working.
    """

    def __init__(
        self,
        nodes: Iterable[str] = (),
        edge_ids: Iterable[str] | None = None,
        edge_types: Iterable[str] | None = None,
    ):
        super().__init__(nodes)
        self.edge_ids = list(edge_ids or [])
        self.edge_types = list(edge_types or [])
        expected = max(len(self) - 1, 0)
        if self.edge_ids and len(self.edge_ids) != expected:
            raise ValueError("edge_ids must have exactly len(nodes)-1 entries")
        if self.edge_types and len(self.edge_types) != expected:
            raise ValueError("edge_types must have exactly len(nodes)-1 entries")

    def extended(self, node: str, edge_id: str, edge_type: str) -> "EvidencePath":
        return EvidencePath(
            [*self, node],
            [*self.edge_ids, str(edge_id)],
            [*self.edge_types, edge_type],
        )


def path_from_label(label: dict) -> EvidencePath:
    return EvidencePath(
        label.get("path", []),
        label.get("edge_ids") or [],
        label.get("edge_types") or [],
    )


def edge_aware_path_key(path) -> tuple:
    """Return a strict key when edge references exist, else a legacy node key."""
    nodes = tuple(path)
    edge_ids = tuple(getattr(path, "edge_ids", ()) or ())
    edge_types = tuple(getattr(path, "edge_types", ()) or ())
    if edge_ids:
        return ("edges", nodes, edge_ids)
    if edge_types:
        return ("types", nodes, edge_types)
    return ("nodes", nodes)


def get_path_edge(G, path, index: int) -> dict | None:
    """Get the exact edge used at one path hop when references are available."""
    src, dst = path[index], path[index + 1]
    group = G.get_edge_data(src, dst) or {}
    if not group:
        return None

    edge_ids = getattr(path, "edge_ids", ()) or ()
    if index < len(edge_ids):
        edge_data = group.get(edge_ids[index])
        if edge_data is not None:
            return edge_data

    edge_types = getattr(path, "edge_types", ()) or ()
    if index < len(edge_types):
        matches = [
            (key, data)
            for key, data in group.items()
            if data.get("edge_type") == edge_types[index]
        ]
        if matches:
            return sorted(matches, key=lambda item: str(item[0]))[0][1]

    # Compatibility only: legacy paths have no edge reference. New searches
    # and regenerated path labels never use this branch.
    return next(iter(group.values()))


def path_query_cost(G, path) -> int:
    return sum(
        int((get_path_edge(G, path, index) or {}).get("query_cost", 1))
        for index in range(max(len(path) - 1, 0))
    )


def assign_edge_ids(sample: dict) -> dict:
    """Add stable per-sample IDs to raw JSON edges in-place."""
    used: set[str] = set()
    for index, edge in enumerate(sample.get("edges", [])):
        base = str(edge.get("edge_id") or edge.get("id") or f"e{index:04d}")
        edge_id = base
        suffix = 1
        while edge_id in used:
            suffix += 1
            edge_id = f"{base}:{suffix}"
        used.add(edge_id)
        edge["edge_id"] = edge_id
    return sample


def resolve_edge_sequence(
    sample: dict,
    nodes: list[str],
    valid_transitions: dict[str, set[str]] | None = None,
    required_edge_types: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Resolve a legacy node path to the best explicit edge sequence.

    Resolution is deterministic. It favours sequences satisfying the search
    transition grammar and containing the required exposure edge types.
    """
    if len(nodes) < 2:
        return [], []
    assign_edge_ids(sample)
    by_pair: dict[tuple[str, str], list[dict]] = {}
    for edge in sample.get("edges", []):
        by_pair.setdefault((edge["source"], edge["target"]), []).append(edge)

    choices = [by_pair.get(pair, []) for pair in zip(nodes[:-1], nodes[1:])]
    if any(not options for options in choices):
        return [], []

    required = required_edge_types or set()
    best = None
    best_score = None
    for sequence in product(*choices):
        types = [edge.get("type", "") for edge in sequence]
        transition_matches = 0
        transition_failures = 0
        if valid_transitions is not None:
            for previous, current in zip(types[:-1], types[1:]):
                if current in valid_transitions.get(previous, set()):
                    transition_matches += 1
                else:
                    transition_failures += 1
        required_matches = len(required.intersection(types))
        supported = sum(
            edge.get("attrs", {}).get("status", "Supported") == "Supported"
            for edge in sequence
        )
        score = (
            transition_failures == 0,
            required_matches == len(required),
            required_matches,
            transition_matches,
            supported,
        )
        if best_score is None or score > best_score:
            best = sequence
            best_score = score

    return (
        [str(edge["edge_id"]) for edge in best],
        [edge.get("type", "") for edge in best],
    )


def annotate_path_labels(
    sample: dict,
    valid_transitions: dict[str, set[str]] | None = None,
    required_edge_types: set[str] | None = None,
) -> dict:
    """Attach explicit edge references to every path label in-place."""
    assign_edge_ids(sample)
    for label in sample.get("path_labels", []):
        edge_ids, edge_types = resolve_edge_sequence(
            sample,
            label.get("path", []),
            valid_transitions,
            required_edge_types,
        )
        label["edge_ids"] = edge_ids
        label["edge_types"] = edge_types
    return sample
