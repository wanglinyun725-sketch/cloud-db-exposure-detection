"""Partial-observation environment for active evidence acquisition.

The topology and edge types form a structural hypothesis graph.  Semantic
evidence (status, strength, timestamp and raw evidence) remains hidden until
the agent explicitly queries an edge.  This separates path hypothesis
generation from evidence acquisition and prevents query cost from being used
as a penalty on evidence that was already visible.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field

import networkx as nx


HIDDEN_EDGE_ATTRS = {
    "status": "Unknown",
    "strength": 0.5,
    "confidence": 0.0,
    "time": None,
    "observed_at": None,
    "t": None,
    "raw_evidence": "not_queried",
    "temporal_conflict": False,
}


@dataclass
class QueryObservation:
    edge_id: str
    source: str
    target: str
    edge_type: str
    cost: int
    status: str
    temporal_conflict: bool


@dataclass
class PartialEvidenceEnvironment:
    """A deterministic environment backed by a fully observed truth graph."""

    truth_graph: nx.MultiDiGraph
    budget: int | None = None
    observed_graph: nx.MultiDiGraph = field(init=False)
    spent: int = field(init=False, default=0)
    queried_edge_ids: set[str] = field(init=False, default_factory=set)
    trace: list[QueryObservation] = field(init=False, default_factory=list)
    _edge_index: dict[str, tuple[str, str, str]] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.observed_graph = nx.MultiDiGraph()
        self.observed_graph.graph.update(deepcopy(self.truth_graph.graph))
        for node, attrs in self.truth_graph.nodes(data=True):
            self.observed_graph.add_node(node, **deepcopy(attrs))
        for source, target, edge_key, attrs in self.truth_graph.edges(keys=True, data=True):
            edge_id = str(attrs.get("edge_id", edge_key))
            visible = deepcopy(attrs)
            visible.update(HIDDEN_EDGE_ATTRS)
            # Query cost and the relation type are part of the action schema,
            # not query results, so the policy may use them before acquisition.
            visible["edge_id"] = edge_id
            visible["edge_type"] = attrs.get("edge_type", "")
            visible["query_cost"] = int(attrs.get("query_cost", 1))
            self.observed_graph.add_edge(source, target, key=edge_key, **visible)
            self._edge_index[edge_id] = (source, target, edge_key)

    def query(self, edge_id: str) -> QueryObservation | None:
        """Reveal one edge if it has not been queried and budget permits it."""
        edge_id = str(edge_id)
        if edge_id in self.queried_edge_ids:
            return None
        if edge_id not in self._edge_index:
            raise KeyError(f"unknown edge_id: {edge_id}")

        source, target, edge_key = self._edge_index[edge_id]
        truth = self.truth_graph.get_edge_data(source, target, edge_key)
        cost = int(truth.get("query_cost", 1))
        if self.budget is not None and self.spent + cost > self.budget:
            return None

        observed = self.observed_graph.get_edge_data(source, target, edge_key)
        observed.clear()
        observed.update(deepcopy(truth))
        observed["edge_id"] = edge_id
        self.spent += cost
        self.queried_edge_ids.add(edge_id)

        result = QueryObservation(
            edge_id=edge_id,
            source=source,
            target=target,
            edge_type=truth.get("edge_type", ""),
            cost=cost,
            status=truth.get("status", "Supported"),
            temporal_conflict=bool(truth.get("temporal_conflict", False)),
        )
        self.trace.append(result)
        return result

    def is_queried(self, edge_id: str) -> bool:
        return str(edge_id) in self.queried_edge_ids

    def edge_cost(self, edge_id: str) -> int:
        source, target, edge_key = self._edge_index[str(edge_id)]
        return int(self.truth_graph.get_edge_data(source, target, edge_key).get("query_cost", 1))

    def edge_type(self, edge_id: str) -> str:
        source, target, edge_key = self._edge_index[str(edge_id)]
        return self.observed_graph.get_edge_data(source, target, edge_key).get("edge_type", "")

    def remaining_budget(self) -> int | None:
        if self.budget is None:
            return None
        return self.budget - self.spent

    def can_query(self, edge_id: str) -> bool:
        if self.is_queried(edge_id):
            return False
        remaining = self.remaining_budget()
        return remaining is None or self.edge_cost(edge_id) <= remaining
