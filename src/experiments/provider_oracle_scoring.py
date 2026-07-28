"""Evaluator-only scoring for provider-oracle path-state predictions."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping


STATES = {"Reachable", "NotReachable", "Unknown"}


def score_provider_oracle_state(
    result: Any,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Score state, evidence polarity, path coverage, and abstention.

    Internal CP-Cert verification proves only that the cited observation was
    visible and passed the submitted executable test. Semantic grounding is
    recomputed here against the separately loaded provider-oracle release.
    """
    payload = asdict(result) if is_dataclass(result) else dict(result)
    proposals = list(payload.get("path_candidates") or [])
    verified = [
        item for item in proposals if item.get("verified") is True
    ]
    ranked_states = [
        (item.get("normalized_path") or {}).get(
            "claimed_state", "Reachable"
        )
        for item in verified
    ]
    predicted_state = ranked_states[0] if ranked_states else "Unknown"
    if predicted_state not in STATES:
        predicted_state = "Unknown"

    support_gold = set(metadata.get("support_observation_ids") or [])
    refute_gold = set(metadata.get("refute_observation_ids") or [])
    control_gold = set(metadata.get("control_observation_ids") or [])
    cited_support: set[str] = set()
    cited_refute: set[str] = set()
    all_cited: set[str] = set()
    for proposal in verified:
        for assignment in (
            (proposal.get("normalized_path") or {}).get(
                "evidence_assignments", []
            )
        ):
            observation_id = assignment["observation_id"]
            all_cited.add(observation_id)
            if assignment["polarity"] == "support":
                cited_support.add(observation_id)
            else:
                cited_refute.add(observation_id)

    if predicted_state == "Reachable":
        decisive_evidence_correct = bool(cited_support & support_gold)
    elif predicted_state == "NotReachable":
        decisive_evidence_correct = bool(cited_refute & refute_gold)
    else:
        decisive_evidence_correct = not verified

    gold_path = metadata["path"]
    gold_edge_types = [item["type"] for item in gold_path["edges"]]
    predicted_edge_types = [
        edge["type"]
        for proposal in verified[:1]
        for edge in (
            (proposal.get("normalized_path") or {}).get("edges") or []
        )
    ]
    matched_edges = _multiset_overlap(
        Counter(gold_edge_types),
        Counter(predicted_edge_types),
    )
    edge_precision = (
        matched_edges / len(predicted_edge_types)
        if predicted_edge_types
        else 0.0
    )
    edge_recall = (
        matched_edges / len(gold_edge_types) if gold_edge_types else 0.0
    )
    edge_f1 = (
        2 * edge_precision * edge_recall / (edge_precision + edge_recall)
        if edge_precision + edge_recall
        else 0.0
    )
    gold_state = metadata["gold_state"]
    state_correct = predicted_state == gold_state
    provider_gold = metadata["label_origin"] == "provider_native_runtime"
    return {
        "scoring_version": "provider-oracle-state-v1",
        "case_id": metadata["case_id"],
        "independence_group": metadata["independence_group"],
        "platform": metadata["platform"],
        "gold_state": gold_state,
        "predicted_state": predicted_state,
        "state_correct": state_correct,
        "provider_oracle_gold": provider_gold,
        "epistemic_control": not provider_gold,
        "label_origin": metadata["label_origin"],
        "gold_tier": metadata.get("gold_tier"),
        "decisive_evidence_correct": decisive_evidence_correct,
        "semantically_correct_state": (
            state_correct and decisive_evidence_correct
        ),
        "correct_rejection": (
            gold_state == "NotReachable"
            and predicted_state == "NotReachable"
            and decisive_evidence_correct
        ),
        "correct_abstention": (
            gold_state == "Unknown"
            and predicted_state == "Unknown"
            and not verified
        ),
        "false_reachable": (
            predicted_state == "Reachable"
            and gold_state != "Reachable"
        ),
        "support_evidence_coverage": _coverage(
            cited_support, support_gold
        ),
        "refute_evidence_coverage": _coverage(
            cited_refute, refute_gold
        ),
        "control_evidence_coverage": _coverage(all_cited, control_gold),
        "gold_path_edge_precision": edge_precision,
        "gold_path_edge_recall": edge_recall,
        "gold_path_edge_f1": edge_f1,
        "verified_candidate_count": len(verified),
        "proposed_candidate_count": len(proposals),
        "query_cost": payload.get("spent", 0),
        "valid_tool_calls": payload.get("valid_tool_calls", 0),
        "invalid_actions": payload.get("invalid_actions", 0),
        "runner_decision": payload.get("decision"),
        "scope": (
            "State scoring is evaluator-side. Provider gold and the "
            "configuration-only Unknown controls are reported separately; "
            "protocol pilots are not population-effectiveness results."
        ),
    }


def _coverage(observed: set[str], gold: set[str]) -> float | None:
    if not gold:
        return None
    return len(observed & gold) / len(gold)


def _multiset_overlap(
    left: Counter[str],
    right: Counter[str],
) -> int:
    return sum(
        min(left.get(key, 0), right.get(key, 0))
        for key in set(left) | set(right)
    )
