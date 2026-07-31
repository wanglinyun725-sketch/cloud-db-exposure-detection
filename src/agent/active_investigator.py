"""Budget-aware active verification of structural exposure-path hypotheses."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from random import Random

from src.agent.evidence_environment import PartialEvidenceEnvironment
from src.graph.gate_score import verify_path
from src.verification.cp_cert import EvidenceItem, build_negative_certificate


REFUTING_STATUSES = {"Contradicted"}


@dataclass
class InvestigationResult:
    policy: str
    decision: str
    predicted_has_valid: bool | None
    spent: int
    tool_calls: int
    certificate_edge_ids: list[str]
    valid_path: list[str] | None
    valid_path_edge_ids: list[str] | None
    trace: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


def investigate(
    truth_graph,
    candidate_paths,
    policy: str = "impact_per_cost",
    budget: int | None = None,
    seed: int = 0,
    block_priors: dict[str, float] | None = None,
) -> InvestigationResult:
    """Actively verify candidates until finding a valid path or proving none.

    Policies:
      * ``full_scan`` queries every candidate edge.
      * ``fixed_order`` verifies candidates in their supplied order.
      * ``impact_per_cost`` chooses the edge affecting the most still-viable
        candidates per unit query cost, with a small near-completion bonus.
      * ``voi_per_cost`` uses blocker probabilities learned on a disjoint
        development split to estimate pruning/completion value per unit cost.
      * ``random`` is a seeded action-order baseline.
    """
    paths = list(candidate_paths)
    env = PartialEvidenceEnvironment(truth_graph, budget=budget)
    if not paths:
        return _pack(env, policy, "no_candidates", False, [], None)

    if policy == "full_scan":
        for edge_id in _unique_edges(paths):
            if env.can_query(edge_id):
                env.query(edge_id)
        return _finalize(env, paths, policy)

    rng = Random(seed)
    while True:
        valid = _first_valid(env, paths)
        if valid is not None:
            return _pack(env, policy, "valid_found", True, list(valid.edge_ids), valid)

        viable = [path for path in paths if not _path_blocked(env, path)]
        if not viable:
            certificate = _rejection_certificate(env, paths)
            return _pack(env, policy, "no_valid_path", False, certificate, None)

        queryable = {
            edge_id
            for path in viable
            for edge_id in path.edge_ids
            if env.can_query(edge_id)
        }
        if not queryable:
            has_unqueried = any(
                not env.is_queried(edge_id)
                for path in viable
                for edge_id in path.edge_ids
            )
            decision = "budget_exhausted" if has_unqueried else "insufficient_evidence"
            return _pack(env, policy, decision, None, [], None)

        if policy == "fixed_order":
            edge_id = _fixed_order_action(env, viable)
        elif policy == "impact_per_cost":
            edge_id = _impact_per_cost_action(env, viable)
        elif policy == "voi_per_cost":
            if block_priors is None:
                raise ValueError("voi_per_cost requires block_priors")
            edge_id = _voi_per_cost_action(env, viable, block_priors)
        elif policy == "random":
            edge_id = rng.choice(sorted(queryable))
        else:
            raise ValueError(f"unknown policy: {policy}")
        env.query(edge_id)


def truth_has_valid_path(truth_graph, candidate_paths) -> bool:
    return any(verify_path(truth_graph, path)["state"] == "Valid" for path in candidate_paths)


def total_candidate_query_cost(graph, candidate_paths) -> int:
    edge_ids = _unique_edges(candidate_paths)
    index = {
        str(attrs.get("edge_id", key)): int(attrs.get("query_cost", 1))
        for _, _, key, attrs in graph.edges(keys=True, data=True)
    }
    return sum(index[edge_id] for edge_id in edge_ids)


def estimate_block_priors(graphs, alpha: float = 1.0) -> dict[str, float]:
    """Estimate P(edge blocks a path | edge type) with beta smoothing."""
    counts: dict[str, list[int]] = {}
    for graph in graphs:
        for _, _, attrs in graph.edges(data=True):
            edge_type = attrs.get("edge_type", "")
            blocked = (
                attrs.get("status", "Supported") in REFUTING_STATUSES
                or attrs.get("temporal_conflict", False)
            )
            bucket = counts.setdefault(edge_type, [0, 0])
            bucket[0] += int(blocked)
            bucket[1] += 1
    return {
        edge_type: (blocked + alpha) / (total + 2.0 * alpha)
        for edge_type, (blocked, total) in counts.items()
    }


def _fixed_order_action(env, viable):
    for path in viable:
        for edge_id in path.edge_ids:
            if env.can_query(edge_id):
                return edge_id
    raise RuntimeError("no queryable action")


def _impact_per_cost_action(env, viable):
    scores = {}
    for path_rank, path in enumerate(viable):
        unknown = [edge_id for edge_id in path.edge_ids if not env.is_queried(edge_id)]
        if not unknown:
            continue
        # Resolving a nearly complete path can terminate the investigation.
        completion_weight = 1.0 + 1.0 / len(unknown)
        # Supplied candidate rank is a weak, deterministic structural prior.
        rank_weight = 1.0 / (1.0 + 0.05 * path_rank)
        for edge_id in unknown:
            if env.can_query(edge_id):
                scores[edge_id] = scores.get(edge_id, 0.0) + completion_weight * rank_weight
    return max(
        scores,
        key=lambda edge_id: (
            scores[edge_id] / max(env.edge_cost(edge_id), 1),
            scores[edge_id],
            -env.edge_cost(edge_id),
            edge_id,
        ),
    )


def _voi_per_cost_action(env, viable, block_priors):
    """Choose the maximum estimated decision value per acquisition cost.

    For an edge e and current viable frontier F_t:

        VOI(e) = [p_block(e) * N_prune(e)
                  + (1-p_block(e)) * N_complete(e)] / cost(e)

    N_prune counts viable paths containing e. N_complete counts paths for
    which e is the last unresolved item.  The policy never reads hidden edge
    status; p_block is estimated outside this function on development data.
    """
    stats = {}
    for path in viable:
        unresolved = [edge_id for edge_id in path.edge_ids if not env.is_queried(edge_id)]
        for edge_id in unresolved:
            if not env.can_query(edge_id):
                continue
            item = stats.setdefault(edge_id, {"prune": 0, "complete": 0})
            item["prune"] += 1
            item["complete"] += int(len(unresolved) == 1)

    def key(edge_id):
        probability = block_priors.get(env.edge_type(edge_id), 0.5)
        value = (
            probability * stats[edge_id]["prune"]
            + (1.0 - probability) * stats[edge_id]["complete"]
        )
        return (
            value / max(env.edge_cost(edge_id), 1),
            value,
            stats[edge_id]["prune"],
            -env.edge_cost(edge_id),
            edge_id,
        )

    return max(stats, key=key)


def _first_valid(env, paths):
    for path in paths:
        if all(env.is_queried(edge_id) for edge_id in path.edge_ids):
            if verify_path(env.observed_graph, path)["state"] == "Valid":
                return path
    return None


def _path_blocked(env, path) -> bool:
    for index, edge_id in enumerate(path.edge_ids):
        if not env.is_queried(edge_id):
            continue
        source, target = path[index], path[index + 1]
        edge = env.observed_graph.get_edge_data(source, target, edge_id) or {}
        if edge.get("status", "Unknown") in REFUTING_STATUSES:
            return True
        if edge.get("temporal_conflict", False):
            return True
    if all(env.is_queried(edge_id) for edge_id in path.edge_ids):
        # A fully queried but Unknown premise is still insufficient evidence;
        # only explicit refutation can support a negative certificate.
        return verify_path(env.observed_graph, path)["state"] == "Invalid"
    return False


def _rejection_certificate(env, paths):
    refutations = []
    for path in paths:
        for index, edge_id in enumerate(path.edge_ids):
            if not env.is_queried(edge_id):
                continue
            source, target = path[index], path[index + 1]
            edge = env.observed_graph.get_edge_data(source, target, edge_id) or {}
            if (
                edge.get("status", "Unknown") in REFUTING_STATUSES
                or edge.get("temporal_conflict", False)
            ):
                refutations.append(
                    EvidenceItem(
                        evidence_id=edge_id,
                        polarity="refute",
                        claim_ids=(edge_id,),
                        raw_ref=str(edge.get("raw_evidence") or f"edge:{edge_id}"),
                        cost=float(edge.get("query_cost", 1)),
                        source=str(edge.get("source", "unknown")),
                    )
                )
    unique_refutations = list({
        item.evidence_id: item for item in refutations
    }.values())
    path_claims = {
        f"path-{index}": tuple(path.edge_ids)
        for index, path in enumerate(paths)
    }
    certificate = build_negative_certificate(
        path_claims,
        unique_refutations,
        method="auto",
    )
    return list(certificate.evidence_ids)


def _finalize(env, paths, policy):
    valid = _first_valid(env, paths)
    if valid is not None:
        return _pack(env, policy, "valid_found", True, list(valid.edge_ids), valid)
    if all(_path_blocked(env, path) for path in paths):
        return _pack(
            env,
            policy,
            "no_valid_path",
            False,
            _rejection_certificate(env, paths),
            None,
        )
    has_unqueried = any(
        not env.is_queried(edge_id)
        for path in paths
        for edge_id in path.edge_ids
    )
    decision = "budget_exhausted" if has_unqueried else "insufficient_evidence"
    return _pack(env, policy, decision, None, [], None)


def _pack(env, policy, decision, prediction, certificate, valid_path):
    return InvestigationResult(
        policy=policy,
        decision=decision,
        predicted_has_valid=prediction,
        spent=env.spent,
        tool_calls=len(env.trace),
        certificate_edge_ids=list(certificate),
        valid_path=list(valid_path) if valid_path is not None else None,
        valid_path_edge_ids=list(valid_path.edge_ids) if valid_path is not None else None,
        trace=[asdict(item) for item in env.trace],
    )


def _unique_edges(paths):
    return list(dict.fromkeys(edge_id for path in paths for edge_id in path.edge_ids))
