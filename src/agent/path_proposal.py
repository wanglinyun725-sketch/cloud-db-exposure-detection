"""Schema and deterministic verification for Agent-proposed attack paths.

The policy is allowed to *propose* a path, but it cannot declare that path
verified.  This module checks graph structure, evidence visibility, four-value
claim states, and a minimum-cost positive or negative CP-Cert certificate.
Failed proposals remain serializable so experiments can measure hallucinations
and unsupported-path false positives instead of silently repairing them.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any, Mapping

from src.graph.path_ontology import (
    canonicalize_type,
    ontology_reference,
    policy_ontology_contract,
    suggested_canonical_type,
)
from src.verification.cp_cert import (
    EvidenceItem,
    build_negative_certificate,
    build_positive_certificate,
    verify_certificate,
    verify_path_claims,
)

PATH_STATE_CLAIMS = {"Reachable", "NotReachable"}


PATH_DECISIONS = {
    "path_found",
    "search_complete",
    "no_verified_path",
    "abstain",
}


def path_proposal_schema() -> dict[str, Any]:
    """Return the compact finish contract shown to the ReAct policy."""
    return {
        "progressive_submission": (
            "Use kind=submit_path with thought, hypothesis, and one "
            "path_candidate; continue investigating until ready to finish."
        ),
        "path_ontology": policy_ontology_contract(),
        "positive_finish": {
            "kind": "finish",
            "decision": "path_found",
            "hypothesis": "non-empty string",
            "path_candidate": {
                "path_id": "non-empty string",
                "claimed_state": (
                    "Reachable or NotReachable; omitted means Reachable "
                    "for backward compatibility"
                ),
                "nodes": [
                    {
                        "node_id": "unique string",
                        "type": "canonical node ID from path_ontology",
                        "label": "non-empty string",
                    }
                ],
                "edges": [
                    {
                        "edge_id": "unique string",
                        "source": "node_id",
                        "target": "next node_id",
                        "type": "canonical edge ID from path_ontology",
                    }
                ],
                "evidence_assignments": [
                    {
                        "observation_id": "policy-visible observation ID",
                        "call_id": "tool call that exposed the observation",
                        "polarity": "support or refute",
                        "edge_ids": ["one or more proposed edge IDs"],
                        "test": {
                            "field": "a field rendered in that observation",
                            "operator": "eq, contains, or exists",
                            "value": "required except exists uses a boolean",
                        },
                    }
                ],
            },
        },
        "non_positive_finish": {
            "kind": "finish",
            "decision": "search_complete, no_verified_path, or abstain",
            "hypothesis": "non-empty string",
        },
        "semantics": [
            "nodes and edges must form one ordered directed chain",
            "an observation is citable only through a tool call that exposed it",
            "every evidence assignment needs an executable test that passes",
            "empty tool results are Unknown and never refute an edge",
            "NotReachable requires an explicit refutation that intersects "
            "the submitted candidate path",
            "the certificate validates structure and observable grounding, "
            "not agreement with external human ground truth",
        ],
    }


def record_visible_observations(
    ledger: dict[str, list[dict[str, Any]]],
    tool_output: Mapping[str, Any],
    compact_observation: Mapping[str, Any],
) -> None:
    """Record only observations actually rendered in the policy view.

    A tool may return hundreds of rows while the policy view is truncated.
    Rows outside that view must never become citable.  Each visible row is
    linked to the exact call and charged call cost used by CP-Cert.
    """
    visible_events = {
        event.get("observation_id"): dict(event)
        for event in compact_observation.get("events", [])
        if isinstance(event, Mapping) and event.get("observation_id")
    }
    visible_ids = set(visible_events)
    receipt = tool_output.get("receipt") or {}
    call_id = receipt.get("call_id")
    cost = receipt.get("cost")
    tool_name = receipt.get("tool_name")
    if not isinstance(call_id, int) or not isinstance(cost, (int, float)):
        raise ValueError("tool receipt requires integer call_id and numeric cost")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool receipt requires a non-empty tool_name")

    for event in (tool_output.get("tool_result") or {}).get("events", []):
        if not isinstance(event, Mapping):
            continue
        observation_id = event.get("observation_id")
        if observation_id not in visible_ids:
            continue
        raw_ref = event.get("raw_ref")
        access = {
            "call_id": call_id,
            "tool_name": tool_name,
            "cost": float(cost),
            "raw_ref": dict(raw_ref) if isinstance(raw_ref, Mapping) else None,
            "visible_event": visible_events[observation_id],
        }
        accesses = ledger.setdefault(str(observation_id), [])
        if not any(item.get("call_id") == call_id for item in accesses):
            accesses.append(access)


def compact_evidence_ledger(
    ledger: Mapping[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Expose citation handles and costs without exposing hidden labels."""
    rows = []
    for observation_id in sorted(ledger):
        for access in sorted(
            ledger[observation_id],
            key=lambda item: (item.get("call_id", 0), item.get("tool_name", "")),
        ):
            rows.append(
                {
                    "observation_id": observation_id,
                    "call_id": access.get("call_id"),
                    "tool_name": access.get("tool_name"),
                    "cost": access.get("cost"),
                    "raw_ref_available": isinstance(access.get("raw_ref"), dict),
                    "visible_fields": sorted(
                        (access.get("visible_event") or {}).keys()
                    ),
                }
            )
    return rows


def verify_path_proposal(
    path_candidate: Any,
    evidence_ledger: Mapping[str, list[dict[str, Any]]],
    *,
    certificate_method: str = "auto",
    exact_item_limit: int = 24,
) -> dict[str, Any]:
    """Validate and CP-Cert one proposed path without mutating the proposal."""
    errors: list[str] = []
    normalized = _normalize_path_candidate(path_candidate, errors)
    report: dict[str, Any] = {
        "path_candidate": path_candidate,
        "normalized_path": normalized,
        "structurally_valid": not errors,
        "evidence_items": [],
        "verdict": None,
        "certificate": None,
        "certificate_audit": None,
        "path_ontology": ontology_reference(),
        "certificate_scope": (
            "Internal structural, citation-visibility, provider-scope, "
            "executable-test, and positive/negative evidence-cover certificate "
            "only; broader semantic "
            "correctness must be scored against independent human gold or "
            "a separately frozen provider-oracle gold release."
        ),
        "verified": False,
        "errors": errors,
    }
    if errors:
        return report

    evidence_items = _build_evidence_items(
        normalized["evidence_assignments"],
        evidence_ledger,
        errors,
    )
    report["evidence_items"] = [asdict(item) for item in evidence_items]
    if errors:
        return report

    edge_ids = [edge["edge_id"] for edge in normalized["edges"]]
    verdict = verify_path_claims(
        normalized["path_id"],
        edge_ids,
        evidence_items,
    )
    report["verdict"] = verdict.to_dict()
    claimed_state = normalized["claimed_state"]
    expected_verdict = {
        "Reachable": "Valid",
        "NotReachable": "Invalid",
    }[claimed_state]
    if verdict.state != expected_verdict:
        errors.append(
            f"{claimed_state} requires CP-Cert verdict {expected_verdict}; "
            f"verdict was {verdict.state}"
        )
        return report

    if claimed_state == "Reachable":
        certificate = build_positive_certificate(
            normalized["path_id"],
            edge_ids,
            evidence_items,
            method=certificate_method,
            exact_item_limit=exact_item_limit,
        )
        coverage = {
            item.evidence_id: set(item.claim_ids).intersection(edge_ids)
            for item in evidence_items
            if item.polarity == "support"
        }
    else:
        certificate = build_negative_certificate(
            {normalized["path_id"]: edge_ids},
            evidence_items,
            method=certificate_method,
            exact_item_limit=exact_item_limit,
        )
        refute_evidence = tuple(
            item for item in evidence_items if item.polarity == "refute"
        )
        coverage = {
            item.evidence_id: {normalized["path_id"]}
            for item in refute_evidence
            if set(item.claim_ids).intersection(edge_ids)
        }
    audit = verify_certificate(certificate, evidence_items, coverage)
    report["certificate"] = certificate.to_dict()
    report["certificate_audit"] = audit
    required_checks = (
        "sufficient",
        "irreducible",
        "raw_refs_complete",
        "cost_matches",
    )
    failed_checks = [name for name in required_checks if not audit.get(name)]
    if failed_checks:
        errors.append(
            "certificate audit failed: " + ", ".join(sorted(failed_checks))
        )
        return report
    report["verified"] = True
    return report


def evaluate_path_finish_proposal(
    proposal: Mapping[str, Any],
    evidence_ledger: Mapping[str, list[dict[str, Any]]],
    raw_refs_by_id: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate finish content identically across orchestration backends.

    The caller still decides whether an unverified positive is rejected
    (EC-ReAct's strict guard) or returned unchanged for baseline measurement.
    """
    decision = proposal.get("decision")
    if decision not in PATH_DECISIONS:
        raise ValueError(f"invalid path decision: {decision}")
    hypothesis = proposal.get("hypothesis")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("finish requires a non-empty hypothesis")
    if decision != "path_found":
        if proposal.get("path_candidate") is not None:
            raise ValueError(
                "non-positive finish must not include path_candidate"
            )
        return {
            "decision": decision,
            "hypothesis": hypothesis.strip(),
            "stop_reason": "non_positive_path_finish_guard_passed",
            "report": None,
            "evidence_observation_ids": [],
            "evidence_raw_refs": [],
        }

    report = verify_path_proposal(
        proposal.get("path_candidate"),
        evidence_ledger,
    )
    assignments = (
        (report.get("normalized_path") or {}).get(
            "evidence_assignments",
            [],
        )
    )
    evidence_ids = list(
        dict.fromkeys(
            item["observation_id"]
            for item in assignments
            if item.get("observation_id")
        )
    )
    return {
        "decision": (
            "evidence_certified_path"
            if report["verified"]
            else "unverified_path_proposed"
        ),
        "hypothesis": hypothesis.strip(),
        "stop_reason": (
            "cp_cert_internal_evidence_certificate_issued"
            if report["verified"]
            else "unverified_path_recorded_for_evaluation"
        ),
        "report": report,
        "evidence_observation_ids": evidence_ids,
        "evidence_raw_refs": [
            raw_refs_by_id[item]
            for item in evidence_ids
            if item in raw_refs_by_id
        ],
    }


def _normalize_path_candidate(
    candidate: Any,
    errors: list[str],
) -> dict[str, Any] | None:
    if not isinstance(candidate, dict):
        errors.append("path_candidate must be an object")
        return None

    path_id = _non_empty_string(candidate.get("path_id"))
    if path_id is None:
        errors.append("path_candidate.path_id must be a non-empty string")
    claimed_state = candidate.get("claimed_state", "Reachable")
    if claimed_state not in PATH_STATE_CLAIMS:
        errors.append(
            "path_candidate.claimed_state must be Reachable or NotReachable"
        )

    nodes = candidate.get("nodes")
    edges = candidate.get("edges")
    assignments = candidate.get("evidence_assignments")
    if not isinstance(nodes, list) or len(nodes) < 2:
        errors.append("path_candidate.nodes must contain at least two nodes")
        nodes = []
    if not isinstance(edges, list):
        errors.append("path_candidate.edges must be a list")
        edges = []
    if not isinstance(assignments, list):
        errors.append("path_candidate.evidence_assignments must be a list")
        assignments = []

    normalized_nodes: list[dict[str, str]] = []
    node_ids: list[str] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] must be an object")
            continue
        values = {
            name: _non_empty_string(node.get(name))
            for name in ("node_id", "type", "label")
        }
        for name, value in values.items():
            if value is None:
                errors.append(f"nodes[{index}].{name} must be a non-empty string")
        if all(value is not None for value in values.values()):
            canonical = canonicalize_type(
                values["type"],
                "node",
                allow_alias=False,
            )
            if canonical is None:
                suggestion = suggested_canonical_type(
                    values["type"],
                    "node",
                )
                errors.append(
                    f"nodes[{index}].type is not a canonical path ontology "
                    "node ID"
                    + (f"; use {suggestion}" if suggestion else "")
                )
            else:
                values["type"] = canonical
            normalized_nodes.append(values)  # type: ignore[arg-type]
            node_ids.append(values["node_id"])  # type: ignore[arg-type]
    duplicate_nodes = _duplicates(node_ids)
    if duplicate_nodes:
        errors.append(f"duplicate node_id values: {duplicate_nodes}")

    normalized_edges: list[dict[str, str]] = []
    edge_ids: list[str] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] must be an object")
            continue
        values = {
            name: _non_empty_string(edge.get(name))
            for name in ("edge_id", "source", "target", "type")
        }
        for name, value in values.items():
            if value is None:
                errors.append(f"edges[{index}].{name} must be a non-empty string")
        if all(value is not None for value in values.values()):
            canonical = canonicalize_type(
                values["type"],
                "edge",
                allow_alias=False,
            )
            if canonical is None:
                suggestion = suggested_canonical_type(
                    values["type"],
                    "edge",
                )
                errors.append(
                    f"edges[{index}].type is not a canonical path ontology "
                    "edge ID"
                    + (f"; use {suggestion}" if suggestion else "")
                )
            else:
                values["type"] = canonical
            normalized_edges.append(values)  # type: ignore[arg-type]
            edge_ids.append(values["edge_id"])  # type: ignore[arg-type]
    duplicate_edges = _duplicates(edge_ids)
    if duplicate_edges:
        errors.append(f"duplicate edge_id values: {duplicate_edges}")

    if normalized_nodes and len(normalized_edges) != len(normalized_nodes) - 1:
        errors.append("an ordered path requires exactly len(nodes)-1 edges")
    if len(normalized_edges) == len(normalized_nodes) - 1:
        for index, edge in enumerate(normalized_edges):
            expected_source = normalized_nodes[index]["node_id"]
            expected_target = normalized_nodes[index + 1]["node_id"]
            if (
                edge["source"] != expected_source
                or edge["target"] != expected_target
            ):
                errors.append(
                    f"edges[{index}] must connect {expected_source} -> "
                    f"{expected_target}"
                )

    normalized_assignments: list[dict[str, Any]] = []
    seen_assignments: set[tuple[Any, ...]] = set()
    known_edges = set(edge_ids)
    for index, assignment in enumerate(assignments):
        if not isinstance(assignment, dict):
            errors.append(f"evidence_assignments[{index}] must be an object")
            continue
        observation_id = _non_empty_string(
            assignment.get("observation_id")
        )
        call_id = assignment.get("call_id")
        polarity = assignment.get("polarity")
        assigned_edges = assignment.get("edge_ids")
        evidence_test = assignment.get("test")
        if observation_id is None:
            errors.append(
                f"evidence_assignments[{index}].observation_id must be "
                "a non-empty string"
            )
        if not isinstance(call_id, int) or isinstance(call_id, bool) or call_id <= 0:
            errors.append(
                f"evidence_assignments[{index}].call_id must be a positive integer"
            )
        if polarity not in {"support", "refute"}:
            errors.append(
                f"evidence_assignments[{index}].polarity must be support or refute"
            )
        if (
            not isinstance(assigned_edges, list)
            or not assigned_edges
            or not all(_non_empty_string(item) for item in assigned_edges)
        ):
            errors.append(
                f"evidence_assignments[{index}].edge_ids must contain strings"
            )
            assigned_edges = []
        assigned_edges = list(dict.fromkeys(assigned_edges))
        unknown_edges = sorted(set(assigned_edges) - known_edges)
        if unknown_edges:
            errors.append(
                f"evidence_assignments[{index}] cites unknown edges: "
                f"{unknown_edges}"
            )
        normalized_test = _normalize_evidence_test(
            evidence_test,
            f"evidence_assignments[{index}].test",
            errors,
        )
        if (
            observation_id is not None
            and isinstance(call_id, int)
            and not isinstance(call_id, bool)
            and polarity in {"support", "refute"}
            and assigned_edges
            and normalized_test is not None
        ):
            key = (
                observation_id,
                call_id,
                polarity,
                tuple(sorted(assigned_edges)),
                json.dumps(
                    normalized_test,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
            if key in seen_assignments:
                errors.append(
                    f"duplicate evidence assignment at index {index}"
                )
            seen_assignments.add(key)
            normalized_assignments.append(
                {
                    "observation_id": observation_id,
                    "call_id": call_id,
                    "polarity": polarity,
                    "edge_ids": assigned_edges,
                    "test": normalized_test,
                }
            )

    return {
        "path_id": path_id,
        "claimed_state": claimed_state,
        "nodes": normalized_nodes,
        "edges": normalized_edges,
        "evidence_assignments": normalized_assignments,
    }


def _build_evidence_items(
    assignments: list[dict[str, Any]],
    ledger: Mapping[str, list[dict[str, Any]]],
    errors: list[str],
) -> tuple[EvidenceItem, ...]:
    grouped: dict[tuple[int, str], dict[str, Any]] = {}
    for index, assignment in enumerate(assignments):
        observation_id = assignment["observation_id"]
        call_id = assignment["call_id"]
        accesses = ledger.get(observation_id, [])
        access = next(
            (
                item
                for item in accesses
                if item.get("call_id") == call_id
            ),
            None,
        )
        if access is None:
            errors.append(
                f"evidence_assignments[{index}] cites observation "
                f"{observation_id!r} not visible in tool call {call_id}"
            )
            continue
        visible_event = access.get("visible_event")
        provider_decision = (
            visible_event.get("provider_decision")
            if isinstance(visible_event, Mapping)
            else None
        )
        scope_completeness = (
            visible_event.get("scope_completeness")
            if isinstance(visible_event, Mapping)
            else None
        )
        polarity = assignment["polarity"]
        if (
            provider_decision in {"allow", "deny"}
            and isinstance(scope_completeness, str)
            and not _provider_scope_is_decisive(scope_completeness)
        ):
            errors.append(
                f"evidence_assignments[{index}] provider decision "
                f"{provider_decision!r} has non-decisive scope "
                f"{scope_completeness!r}; the end-to-end claim remains Unknown"
            )
            continue
        if provider_decision == "deny" and polarity != "refute":
            errors.append(
                f"evidence_assignments[{index}] cannot use a provider denial "
                "as positive support"
            )
            continue
        if provider_decision == "allow" and polarity != "support":
            errors.append(
                f"evidence_assignments[{index}] cannot use a provider allow "
                "as refutation"
            )
            continue
        if (
            isinstance(provider_decision, str)
            and provider_decision not in {"allow", "deny"}
        ):
            errors.append(
                f"evidence_assignments[{index}] provider decision "
                f"{provider_decision!r} is a control or non-runtime state, "
                "not decisive support/refutation"
            )
            continue
        raw_ref = access.get("raw_ref")
        if not isinstance(raw_ref, dict):
            errors.append(
                f"evidence_assignments[{index}] lacks auditable raw provenance"
            )
            continue
        test_passed, test_detail = _execute_evidence_test(
            visible_event,
            assignment["test"],
        )
        if not test_passed:
            errors.append(
                f"evidence_assignments[{index}] executable test failed: "
                f"{test_detail}"
            )
            continue
        key = (call_id, polarity)
        group = grouped.setdefault(
            key,
            {
                "call_id": call_id,
                "polarity": polarity,
                "tool_name": access["tool_name"],
                "cost": float(access["cost"]),
                "claim_ids": set(),
                "observations": {},
                "tests": [],
            },
        )
        if (
            group["tool_name"] != access["tool_name"]
            or abs(group["cost"] - float(access["cost"])) > 1e-12
        ):
            errors.append(f"inconsistent ledger metadata for tool call {call_id}")
            continue
        group["claim_ids"].update(assignment["edge_ids"])
        group["observations"][observation_id] = raw_ref
        group["tests"].append(
            {
                "observation_id": observation_id,
                **assignment["test"],
                "result": True,
            }
        )

    if errors:
        return ()

    items = []
    for (call_id, polarity), group in sorted(grouped.items()):
        raw_payload = {
            "call_id": call_id,
            "tool_name": group["tool_name"],
            "observations": [
                {
                    "observation_id": observation_id,
                    "raw_ref": group["observations"][observation_id],
                }
                for observation_id in sorted(group["observations"])
            ],
            "executable_tests": sorted(
                group["tests"],
                key=lambda item: (
                    item["observation_id"],
                    item["field"],
                    item["operator"],
                    str(item.get("value")),
                ),
            ),
        }
        items.append(
            EvidenceItem(
                evidence_id=f"tool-call-{call_id}-{polarity}",
                polarity=polarity,
                claim_ids=tuple(sorted(group["claim_ids"])),
                raw_ref=json.dumps(
                    raw_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                cost=group["cost"],
                source=f"tool:{group['tool_name']}",
            )
        )
    return tuple(items)


def _provider_scope_is_decisive(scope: str) -> bool:
    normalized = scope.strip().lower()
    return normalized == "complete" or normalized.startswith("complete_for_")


def _non_empty_string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _normalize_evidence_test(
    value: Any,
    location: str,
    errors: list[str],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{location} must be an object")
        return None
    field = _non_empty_string(value.get("field"))
    operator = value.get("operator")
    expected = value.get("value")
    if field is None or field in {"observation_id", "raw_ref"}:
        errors.append(
            f"{location}.field must be a non-empty observable field other "
            "than observation_id/raw_ref"
        )
    if operator not in {"eq", "contains", "exists"}:
        errors.append(f"{location}.operator must be eq, contains, or exists")
    if operator == "exists":
        if not isinstance(expected, bool):
            errors.append(f"{location}.value must be boolean for exists")
    elif not isinstance(expected, (str, int, float, bool)):
        errors.append(f"{location}.value must be a JSON scalar")
    elif operator == "contains" and not str(expected):
        errors.append(f"{location}.value must be non-empty for contains")
    if field is None or operator not in {"eq", "contains", "exists"}:
        return None
    return {
        "field": field,
        "operator": operator,
        "value": expected,
    }


def _execute_evidence_test(
    visible_event: Any,
    test: Mapping[str, Any],
) -> tuple[bool, str]:
    if not isinstance(visible_event, Mapping):
        return False, "no policy-visible event projection is recorded"
    field = test["field"]
    operator = test["operator"]
    expected = test["value"]
    if field not in visible_event:
        return False, f"field {field!r} was not rendered to the policy"
    actual = visible_event.get(field)
    if operator == "exists":
        exists = actual is not None and (
            not isinstance(actual, str) or bool(actual.strip())
        )
        passed = exists is expected
    elif operator == "eq":
        if isinstance(actual, str) or isinstance(expected, str):
            passed = str(actual).casefold() == str(expected).casefold()
        else:
            passed = actual == expected
    else:
        passed = str(expected).casefold() in str(actual).casefold()
    return (
        passed,
        (
            f"{field} {operator} {expected!r} evaluated against "
            f"{actual!r}: {passed}"
        ),
    )


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)
