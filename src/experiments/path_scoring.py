"""Human-gold scoring for evidence-certified path proposals."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from src.graph.path_ontology import (
    canonicalize_type,
    coarse_type,
    ontology_reference,
)

def score_path_discovery(
    result: Any,
    evaluation_metadata: Mapping[str, Any],
    *,
    k: int = 5,
) -> dict[str, Any]:
    """Score raw proposals, internal evidence checks, and semantic gold match.

    CP-Cert's internal ``verified`` flag is never treated as human-ground-truth
    correctness.  A certificate can be auditable yet semantically wrong; only
    a match to a path independently labeled Valid for this runtime instance is
    counted as a correct discovery.
    """
    if k <= 0:
        raise ValueError("k must be positive")
    payload = asdict(result) if is_dataclass(result) else dict(result)
    gold_paths = {
        item["path_id"]: item
        for item in evaluation_metadata["gold_paths"]
    }
    gold_nodes = {
        item["id"]: item
        for item in evaluation_metadata["gold_nodes"]
    }
    instance_label = evaluation_metadata["gold_instance_label"]
    path_states = {
        item["path_id"]: item["state"]
        for item in instance_label["path_states"]
    }
    if set(path_states) != set(gold_paths):
        raise ValueError("instance path states differ from gold path definitions")

    valid_gold_ids = [
        path_id
        for path_id, state in path_states.items()
        if state == "Valid"
    ]
    valid_gold_signatures = {
        path_id: _gold_signature(
            gold_paths[path_id],
            gold_nodes,
            evaluation_metadata["gold_edges"],
        )
        for path_id in valid_gold_ids
    }
    valid_gold_literal_signatures = {
        path_id: _gold_signature(
            gold_paths[path_id],
            gold_nodes,
            evaluation_metadata["gold_edges"],
            representation="literal",
        )
        for path_id in valid_gold_ids
    }
    valid_gold_coarse_signatures = {
        path_id: _gold_signature(
            gold_paths[path_id],
            gold_nodes,
            evaluation_metadata["gold_edges"],
            representation="coarse",
        )
        for path_id in valid_gold_ids
    }
    proposals = list(payload.get("path_candidates") or [])[:k]
    certified = [
        item for item in proposals if item.get("verified") is True
    ]
    proposal_rows = []
    raw_fine_signatures = []
    certified_fine_signatures = []
    raw_invalid_edge_count = 0
    certified_invalid_edge_count = 0
    matched_gold: set[str] = set()
    correct_ranks: list[int] = []
    for rank, proposal in enumerate(proposals, start=1):
        signature = _predicted_signature(
            proposal.get("normalized_path")
        )
        literal_signature = _predicted_signature(
            proposal.get("normalized_path"),
            representation="literal",
        )
        coarse_signature = _predicted_signature(
            proposal.get("normalized_path"),
            representation="coarse",
        )
        raw_edge_count = _raw_edge_count(
            proposal.get("normalized_path")
        )
        if signature is None:
            raw_invalid_edge_count += raw_edge_count
            if proposal.get("verified"):
                certified_invalid_edge_count += raw_edge_count
        else:
            raw_fine_signatures.append(signature)
            if proposal.get("verified"):
                certified_fine_signatures.append(signature)
        exact_gold_ids = sorted(
            path_id
            for path_id, gold_signature in valid_gold_signatures.items()
            if signature is not None and signature == gold_signature
        )
        if proposal.get("verified") and exact_gold_ids:
            matched_gold.update(exact_gold_ids)
            correct_ranks.append(rank)
        literal_gold_ids = sorted(
            path_id
            for path_id, gold_signature
            in valid_gold_literal_signatures.items()
            if (
                literal_signature is not None
                and literal_signature == gold_signature
            )
        )
        coarse_gold_ids = sorted(
            path_id
            for path_id, gold_signature
            in valid_gold_coarse_signatures.items()
            if (
                coarse_signature is not None
                and coarse_signature == gold_signature
            )
        )
        best_edge_f1 = max(
            (
                _edge_sequence_f1(signature, gold_signature)
                for gold_signature in valid_gold_signatures.values()
            ),
            default=(1.0 if not valid_gold_signatures and signature is None else 0.0),
        )
        best_coarse_edge_f1 = max(
            (
                _edge_sequence_f1(coarse_signature, gold_signature)
                for gold_signature
                in valid_gold_coarse_signatures.values()
            ),
            default=(
                1.0
                if (
                    not valid_gold_coarse_signatures
                    and coarse_signature is None
                )
                else 0.0
            ),
        )
        proposal_rows.append(
            {
                "rank": rank,
                "path_id": (
                    (proposal.get("normalized_path") or {}).get("path_id")
                ),
                "internally_certified": bool(proposal.get("verified")),
                "exact_valid_gold_path_ids": exact_gold_ids,
                "literal_exact_valid_gold_path_ids": literal_gold_ids,
                "coarse_exact_valid_gold_path_ids": coarse_gold_ids,
                "ontology_types_valid": signature is not None,
                "semantic_match": bool(
                    proposal.get("verified") and exact_gold_ids
                ),
                "literal_semantic_match": bool(
                    proposal.get("verified") and literal_gold_ids
                ),
                "coarse_semantic_match": bool(
                    proposal.get("verified") and coarse_gold_ids
                ),
                "best_valid_gold_edge_f1": best_edge_f1,
                "best_valid_gold_coarse_edge_f1": best_coarse_edge_f1,
                "verification_errors": list(proposal.get("errors") or []),
            }
        )

    semantic_correct_count = sum(
        item["semantic_match"] for item in proposal_rows
    )
    unsupported_count = sum(
        not item["internally_certified"] for item in proposal_rows
    )
    semantic_false_positive_count = sum(
        item["internally_certified"] and not item["semantic_match"]
        for item in proposal_rows
    )
    hallucinated_count = unsupported_count + semantic_false_positive_count
    ontology_invalid_count = sum(
        not item["ontology_types_valid"] for item in proposal_rows
    )
    overall_state = instance_label["overall_state"]
    no_certified_positive = not certified
    unsafe_false_reachable = (
        overall_state != "Valid" and not no_certified_positive
    )
    certified_fine_scores = _edge_set_scores(
        certified_fine_signatures,
        list(valid_gold_signatures.values()),
        invalid_predicted_edge_count=certified_invalid_edge_count,
    )
    raw_fine_scores = _edge_set_scores(
        raw_fine_signatures,
        list(valid_gold_signatures.values()),
        invalid_predicted_edge_count=raw_invalid_edge_count,
    )
    return {
        "scoring_version": "0.4",
        "path_ontology": ontology_reference(),
        "case_id": evaluation_metadata["case_id"],
        "instance_id": evaluation_metadata["instance_id"],
        "independence_group": evaluation_metadata["independence_group"],
        "source_id": evaluation_metadata["source_id"],
        "scenario_source_id": evaluation_metadata.get(
            "scenario_source_id", evaluation_metadata["source_id"]
        ),
        "runtime_evidence_source_id": evaluation_metadata.get(
            "runtime_evidence_source_id",
            evaluation_metadata["source_id"],
        ),
        "platform": evaluation_metadata.get("platform", "unspecified"),
        "provenance_level": evaluation_metadata["provenance_level"],
        "gold_overall_state": overall_state,
        "gold_valid_path_count": len(valid_gold_ids),
        "proposed_path_count_at_k": len(proposals),
        "internally_certified_path_count_at_k": len(certified),
        "semantically_correct_path_count_at_k": semantic_correct_count,
        "matched_valid_gold_path_count_at_k": len(matched_gold),
        "valid_path_recall_at_k": (
            len(matched_gold) / len(valid_gold_ids)
            if valid_gold_ids
            else None
        ),
        "exact_path_match": bool(matched_gold),
        "canonical_exact_path_match": bool(matched_gold),
        "literal_exact_path_match": any(
            item["literal_semantic_match"] for item in proposal_rows
        ),
        "coarse_exact_path_match": any(
            item["coarse_semantic_match"] for item in proposal_rows
        ),
        "first_correct_path_rank": min(correct_ranks) if correct_ranks else None,
        "reciprocal_rank": (
            1.0 / min(correct_ranks) if correct_ranks else 0.0
        ),
        "mean_best_edge_f1": (
            sum(item["best_valid_gold_edge_f1"] for item in proposal_rows)
            / len(proposal_rows)
            if proposal_rows
            else 0.0
        ),
        "mean_best_coarse_edge_f1": (
            sum(
                item["best_valid_gold_coarse_edge_f1"]
                for item in proposal_rows
            )
            / len(proposal_rows)
            if proposal_rows
            else 0.0
        ),
        "certified_fine_edge_precision_at_k": certified_fine_scores[
            "precision"
        ],
        "certified_fine_edge_recall_at_k": certified_fine_scores[
            "recall"
        ],
        "certified_fine_edge_f1_at_k": certified_fine_scores["f1"],
        "raw_fine_edge_precision_at_k": raw_fine_scores["precision"],
        "raw_fine_edge_recall_at_k": raw_fine_scores["recall"],
        "raw_fine_edge_f1_at_k": raw_fine_scores["f1"],
        "ontology_invalid_predicted_path_rate": (
            ontology_invalid_count / len(proposals) if proposals else 0.0
        ),
        "unsupported_evidence_rate": (
            unsupported_count / len(proposals) if proposals else 0.0
        ),
        "semantic_false_path_rate": (
            semantic_false_positive_count / len(certified)
            if certified
            else 0.0
        ),
        "hallucinated_path_rate": (
            hallucinated_count / len(proposals) if proposals else 0.0
        ),
        "correct_rejection": (
            overall_state == "Invalid" and no_certified_positive
        ),
        "correct_abstention": (
            overall_state in {"Insufficient", "Conflict"}
            and no_certified_positive
            and payload.get("decision") in {
                "abstain",
                "no_verified_path",
                "search_complete",
            }
        ),
        "unsafe_false_reachable": unsafe_false_reachable,
        "query_cost": payload.get("spent", 0),
        "valid_tool_calls": payload.get("valid_tool_calls", 0),
        "invalid_actions": payload.get("invalid_actions", 0),
        "decision": payload.get("decision"),
        "proposal_rows": proposal_rows,
        "certificate_scope": (
            "Internal certification is reported separately from human-gold "
            "semantic correctness. Fine canonical ontology matching is "
            "primary; literal and coarse-family matches are sensitivity "
            "analyses only."
        ),
    }


def _edge_set_scores(
    predicted_signatures: list[
        tuple[tuple[str, ...], tuple[str, ...]]
    ],
    gold_signatures: list[
        tuple[tuple[str, ...], tuple[str, ...]]
    ],
    *,
    invalid_predicted_edge_count: int = 0,
) -> dict[str, float | None]:
    """Micro precision/recall/F1 over canonical transition multisets.

    All certified top-K paths contribute to the predicted denominator, so
    emitting extra alternatives cannot improve recall without a precision
    cost. Ontology-invalid raw edges count as unmatched predictions.
    Negative/Unknown instances have no valid gold edge set and therefore
    return ``None`` instead of inflating path F1 through empty-set matches.
    """
    predicted: dict[tuple[str, str, str], int] = {}
    gold: dict[tuple[str, str, str], int] = {}
    for signature in predicted_signatures:
        _merge_multiset(predicted, _transition_multiset(*signature))
    for signature in gold_signatures:
        _merge_multiset(gold, _transition_multiset(*signature))
    if not gold:
        return {"precision": None, "recall": None, "f1": None}
    matched = sum(
        min(predicted.get(key, 0), gold.get(key, 0))
        for key in set(predicted) | set(gold)
    )
    predicted_total = (
        sum(predicted.values()) + invalid_predicted_edge_count
    )
    gold_total = sum(gold.values())
    precision = matched / predicted_total if predicted_total else 0.0
    recall = matched / gold_total
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {"precision": precision, "recall": recall, "f1": f1}


def _merge_multiset(
    target: dict[tuple[str, str, str], int],
    source: dict[tuple[str, str, str], int],
) -> None:
    for key, count in source.items():
        target[key] = target.get(key, 0) + count


def _raw_edge_count(path: Any) -> int:
    if not isinstance(path, Mapping):
        return 0
    edges = path.get("edges")
    return len(edges) if isinstance(edges, list) else 0


def _gold_signature(
    path: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
    edges: list[dict[str, Any]],
    *,
    representation: str = "canonical",
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    edge_by_id = {item["edge_id"]: item for item in edges}
    signature = _type_signature(
        [nodes[node_id]["type"] for node_id in path["node_ids"]],
        [edge_by_id[edge_id]["type"] for edge_id in path["edge_ids"]],
        representation,
    )
    if signature is None:
        raise ValueError(
            f"gold path {path['path_id']} contains a type outside the "
            "frozen path ontology"
        )
    return signature


def _predicted_signature(
    path: Any,
    *,
    representation: str = "canonical",
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    if not isinstance(path, Mapping):
        return None
    nodes = path.get("nodes")
    edges = path.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return None
    try:
        return _type_signature(
            [item["type"] for item in nodes],
            [item["type"] for item in edges],
            representation,
        )
    except (KeyError, TypeError):
        return None


def _edge_sequence_f1(
    predicted: tuple[tuple[str, ...], tuple[str, ...]] | None,
    gold: tuple[tuple[str, ...], tuple[str, ...]],
) -> float:
    if predicted is None:
        return 0.0
    predicted_edges = _transition_multiset(*predicted)
    gold_edges = _transition_multiset(*gold)
    matched = sum(
        min(predicted_edges.get(key, 0), gold_edges.get(key, 0))
        for key in set(predicted_edges) | set(gold_edges)
    )
    precision = (
        matched / sum(predicted_edges.values())
        if predicted_edges
        else (1.0 if not gold_edges else 0.0)
    )
    recall = (
        matched / sum(gold_edges.values())
        if gold_edges
        else (1.0 if not predicted_edges else 0.0)
    )
    return (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )


def _transition_multiset(
    node_types: tuple[str, ...],
    edge_types: tuple[str, ...],
) -> dict[tuple[str, str, str], int]:
    output: dict[tuple[str, str, str], int] = {}
    if len(edge_types) != len(node_types) - 1:
        return output
    for index, edge_type in enumerate(edge_types):
        key = (node_types[index], edge_type, node_types[index + 1])
        output[key] = output.get(key, 0) + 1
    return output


def _normalize(value: Any) -> str:
    return " ".join(str(value).strip().casefold().replace("_", " ").split())


def _type_signature(
    node_types: list[Any],
    edge_types: list[Any],
    representation: str,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    if representation == "literal":
        return (
            tuple(_normalize(value) for value in node_types),
            tuple(_normalize(value) for value in edge_types),
        )
    if representation not in {"canonical", "coarse"}:
        raise ValueError(f"unknown type representation: {representation}")
    if representation == "canonical":
        resolved_nodes = [
            canonicalize_type(value, "node", allow_alias=True)
            for value in node_types
        ]
        resolved_edges = [
            canonicalize_type(value, "edge", allow_alias=True)
            for value in edge_types
        ]
    else:
        resolved_nodes = [
            coarse_type(value, "node") for value in node_types
        ]
        resolved_edges = [
            coarse_type(value, "edge") for value in edge_types
        ]
    if any(value is None for value in [*resolved_nodes, *resolved_edges]):
        return None
    return (
        tuple(str(value) for value in resolved_nodes),
        tuple(str(value) for value in resolved_edges),
    )
