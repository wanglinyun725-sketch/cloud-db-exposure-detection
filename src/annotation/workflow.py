"""Blind two-human annotation, agreement and adjudication gates."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

import jsonschema

from src.graph.path_ontology import (
    ontology_reference,
    validate_canonical_gold_types,
)

ROOT = Path(__file__).resolve().parents[2]
REAL_SCHEMA_PATH = (
    ROOT / "data" / "real_sources" / "realpathbench_v2_schema.json"
)
ROLES = {"primary", "reviewer", "adjudicator"}
DECISIONS = {"accept", "needs_execution", "reject"}
AI_ID_MARKERS = {
    "ai",
    "assistant",
    "chatgpt",
    "claude",
    "copilot",
    "gemini",
    "gpt",
    "llm",
    "model",
    "qwen",
}
LABEL_FIELDS = {
    "admission_screen",
    "annotation",
    "case_id",
    "edges",
    "instance_labels",
    "nodes",
    "path_labels",
    "tool_tasks",
}
HUMAN_HIDDEN_SOURCE_FIELDS = {
    # Cross-Cloud episode IDs and source conditions reveal the upstream
    # payload-present/absent condition.  Runtime observations and their
    # pinned hashes remain visible, so annotators can still inspect evidence.
    "episode_refs",
}


def create_assignment(
    packet: dict[str, Any],
    role: str,
    annotator_id: str,
) -> dict[str, Any]:
    """Create a label-empty assignment from the common source packet.

    The function accepts only the original unlabeled packet, never another
    annotator's submission.  Reviewer assignments therefore cannot inherit
    primary labels.
    """
    _validate_role_and_human_id(role, annotator_id)
    if role == "adjudicator":
        raise ValueError("adjudicator assignments require explicit disputes")
    _assert_packet_unlabeled(packet)
    packet_digest = _stable_hash(packet)
    ontology = ontology_reference()
    cases = []
    for case in packet["cases"]:
        source_case = _with_runtime_instances(case)
        source_context = {
            key: deepcopy(value)
            for key, value in source_case.items()
            if (
                key not in LABEL_FIELDS
                and key not in HUMAN_HIDDEN_SOURCE_FIELDS
            )
        }
        cases.append(
            {
                "workflow_version": "0.1",
                "packet_sha256": packet_digest,
                "case_id": case["case_id"],
                "role": role,
                "annotator_id": annotator_id,
                "human_attestation": False,
                "completed_at": None,
                "path_ontology": deepcopy(ontology),
                **source_context,
                "source_context_fields": sorted(source_context),
                "source_context_sha256": _stable_hash(source_context),
                "admission_screen": {
                    "external_or_low_privilege_entry_defined": None,
                    "multi_step_path_present": None,
                    "cloud_data_target_present": None,
                    "critical_edges_have_raw_evidence": None,
                    "not_a_near_duplicate": None,
                    "decision": None,
                    "rationale": None,
                },
                "nodes": [],
                "edges": [],
                "path_labels": [],
                "tool_tasks": [],
                "instance_labels": [],
            }
        )
    return {
        "assignment_version": "0.1",
        "assignment_id": (
            f"{role}-" + sha256(
                f"{packet_digest}:{annotator_id}".encode("utf-8")
            ).hexdigest()[:16]
        ),
        "role": role,
        "annotator_id": annotator_id,
        "packet_sha256": packet_digest,
        "policy": {
            "source_labels_copied": 0,
            "other_annotator_labels_visible": 0,
            "human_attestation_required": True,
        },
        "cases": cases,
    }


def create_adjudication_assignment(
    primary_assignment: dict[str, Any],
    reviewer_assignment: dict[str, Any],
    adjudicator_id: str,
) -> dict[str, Any]:
    """Create third-human templates only for independently disputed cases."""
    _validate_role_and_human_id("adjudicator", adjudicator_id)
    report = compare_assignments(primary_assignment, reviewer_assignment)
    if adjudicator_id in {
        primary_assignment.get("annotator_id"),
        reviewer_assignment.get("annotator_id"),
    }:
        raise ValueError("adjudicator must be a third human")

    primary_by_id = {
        item["case_id"]: item for item in primary_assignment["cases"]
    }
    reviewer_by_id = {
        item["case_id"]: item for item in reviewer_assignment["cases"]
    }
    cases = []
    for case_id in report["cases_needing_adjudication"]:
        primary = primary_by_id[case_id]
        reviewer = reviewer_by_id[case_id]
        source_context = _source_context(primary)
        cases.append(
            {
                "workflow_version": "0.1",
                "packet_sha256": report["packet_sha256"],
                "case_id": case_id,
                "role": "adjudicator",
                "annotator_id": adjudicator_id,
                "human_attestation": False,
                "completed_at": None,
                "path_ontology": deepcopy(primary["path_ontology"]),
                **deepcopy(source_context),
                "source_context_fields": sorted(source_context),
                "source_context_sha256": _stable_hash(source_context),
                "admission_screen": {
                    "external_or_low_privilege_entry_defined": None,
                    "multi_step_path_present": None,
                    "cloud_data_target_present": None,
                    "critical_edges_have_raw_evidence": None,
                    "not_a_near_duplicate": None,
                    "decision": None,
                    "rationale": None,
                },
                "nodes": [],
                "edges": [],
                "path_labels": [],
                "tool_tasks": [],
                "instance_labels": [],
                "dispute_context": {
                    "primary_payload": _label_payload(primary),
                    "reviewer_payload": _label_payload(reviewer),
                    "agreement": compare_pair(primary, reviewer),
                },
            }
        )
    return {
        "assignment_version": "0.1",
        "assignment_id": (
            "adjudicator-"
            + sha256(
                (
                    f"{report['packet_sha256']}:{adjudicator_id}:"
                    f"{','.join(report['cases_needing_adjudication'])}"
                ).encode("utf-8")
            ).hexdigest()[:16]
        ),
        "role": "adjudicator",
        "annotator_id": adjudicator_id,
        "packet_sha256": report["packet_sha256"],
        "policy": {
            "source_labels_copied": 0,
            "independent_labels_visible": 2,
            "human_attestation_required": True,
            "disputed_cases_only": True,
        },
        "cases": cases,
    }


def validate_submission(submission: dict[str, Any]) -> None:
    role = submission.get("role")
    annotator_id = submission.get("annotator_id")
    _validate_role_and_human_id(role, annotator_id)
    if submission.get("human_attestation") is not True:
        raise ValueError("completed submission requires human_attestation=true")
    if not submission.get("completed_at"):
        raise ValueError("completed_at is required")
    try:
        datetime.fromisoformat(
            str(submission["completed_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("completed_at must be ISO-8601") from exc
    _validate_source_context(submission)
    if submission.get("path_ontology") != ontology_reference():
        raise ValueError("submission path ontology reference is missing/stale")

    screen = submission.get("admission_screen") or {}
    required_screen = {
        "external_or_low_privilege_entry_defined",
        "multi_step_path_present",
        "cloud_data_target_present",
        "critical_edges_have_raw_evidence",
        "not_a_near_duplicate",
        "decision",
        "rationale",
    }
    if set(screen) != required_screen:
        raise ValueError("admission_screen fields do not match protocol")
    if screen["decision"] not in DECISIONS:
        raise ValueError("admission decision is incomplete")
    if not isinstance(screen["rationale"], str) or not screen["rationale"].strip():
        raise ValueError("admission rationale is required")
    for field in required_screen - {"decision", "rationale"}:
        if not isinstance(screen[field], bool):
            raise ValueError(f"{field} must be a human boolean decision")
    if screen["decision"] == "accept":
        failed_admission_fields = sorted(
            field
            for field in required_screen - {"decision", "rationale"}
            if screen[field] is not True
        )
        if failed_admission_fields:
            raise ValueError(
                "accepted case requires all admission criteria true: "
                + ", ".join(failed_admission_fields)
            )

    schema = _real_schema()
    for section in (
        "nodes",
        "edges",
        "path_labels",
        "tool_tasks",
        "instance_labels",
    ):
        if not isinstance(submission.get(section), list):
            raise ValueError(f"{section} must be an array")
        item_schema = schema["properties"][section]["items"]
        for item in submission[section]:
            jsonschema.validate(item, item_schema)

    if screen["decision"] == "accept":
        for section in ("nodes", "edges", "path_labels", "tool_tasks"):
            if not submission[section]:
                raise ValueError(
                    f"accepted case requires non-empty {section}"
                )
        ontology_errors = validate_canonical_gold_types(submission)
        if ontology_errors:
            raise ValueError(
                "noncanonical path ontology types: "
                + "; ".join(ontology_errors)
            )
    _validate_graph_references(submission)
    _validate_instance_references(submission, screen["decision"])


def compare_pair(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
) -> dict[str, Any]:
    _validate_pair(primary, reviewer)
    p_edges = _edge_map(primary)
    r_edges = _edge_map(reviewer)
    edge_keys = set(p_edges) | set(r_edges)
    edge_intersection = set(p_edges) & set(r_edges)
    precision, recall, edge_f1 = _prf(
        len(edge_intersection),
        len(r_edges),
        len(p_edges),
    )
    state_matches = sum(
        p_edges[key]["evidence_state"]
        == r_edges[key]["evidence_state"]
        for key in edge_intersection
    )
    state_accuracy = (
        state_matches / len(edge_intersection)
        if edge_intersection
        else None
    )
    p_paths = _path_map(primary)
    r_paths = _path_map(reviewer)
    matched_paths = set(p_paths) & set(r_paths)
    path_state_matches = sum(
        p_paths[key]["state"] == r_paths[key]["state"]
        for key in matched_paths
    )
    p_instances = _instance_map(primary)
    r_instances = _instance_map(reviewer)
    matched_instances = set(p_instances) & set(r_instances)
    instance_state_matches = sum(
        p_instances[key]["overall_state"]
        == r_instances[key]["overall_state"]
        for key in matched_instances
    )
    return {
        "case_id": primary["case_id"],
        "primary_annotator": primary["annotator_id"],
        "reviewer": reviewer["annotator_id"],
        "admission_agreement": (
            primary["admission_screen"]["decision"]
            == reviewer["admission_screen"]["decision"]
        ),
        "primary_decision": primary["admission_screen"]["decision"],
        "reviewer_decision": reviewer["admission_screen"]["decision"],
        "edge_identity": {
            "primary_count": len(p_edges),
            "reviewer_count": len(r_edges),
            "matched": len(edge_intersection),
            "precision": precision,
            "recall": recall,
            "f1": edge_f1,
        },
        "evidence_state_accuracy_on_matched_edges": state_accuracy,
        "edge_state_disagreements": [
            {
                "edge": list(key),
                "primary": p_edges[key]["evidence_state"],
                "reviewer": r_edges[key]["evidence_state"],
            }
            for key in sorted(edge_intersection)
            if p_edges[key]["evidence_state"]
            != r_edges[key]["evidence_state"]
        ],
        "path_identity": {
            "primary_count": len(p_paths),
            "reviewer_count": len(r_paths),
            "matched": len(matched_paths),
        },
        "path_state_accuracy_on_matched_paths": (
            path_state_matches / len(matched_paths)
            if matched_paths
            else None
        ),
        "instance_identity": {
            "primary_count": len(p_instances),
            "reviewer_count": len(r_instances),
            "matched": len(matched_instances),
        },
        "instance_state_accuracy_on_matched_instances": (
            instance_state_matches / len(matched_instances)
            if matched_instances
            else None
        ),
        "instance_state_disagreements": [
            {
                "instance_id": key,
                "primary": p_instances[key]["overall_state"],
                "reviewer": r_instances[key]["overall_state"],
            }
            for key in sorted(matched_instances)
            if p_instances[key]["overall_state"]
            != r_instances[key]["overall_state"]
        ],
        "exact_label_payload_agreement": (
            _label_payload(primary) == _label_payload(reviewer)
        ),
        "needs_adjudication": (
            _label_payload(primary) != _label_payload(reviewer)
        ),
        "unmatched_edge_count": len(edge_keys - edge_intersection),
    }


def compare_assignments(
    primary_assignment: dict[str, Any],
    reviewer_assignment: dict[str, Any],
) -> dict[str, Any]:
    if primary_assignment.get("role") != "primary":
        raise ValueError("first assignment must be primary")
    if reviewer_assignment.get("role") != "reviewer":
        raise ValueError("second assignment must be reviewer")
    if (
        primary_assignment.get("packet_sha256")
        != reviewer_assignment.get("packet_sha256")
    ):
        raise ValueError("assignments originate from different packets")
    primary_by_id = {
        item["case_id"]: item for item in primary_assignment["cases"]
    }
    reviewer_by_id = {
        item["case_id"]: item for item in reviewer_assignment["cases"]
    }
    if set(primary_by_id) != set(reviewer_by_id):
        raise ValueError("assignment case sets differ")
    pairs = [
        compare_pair(primary_by_id[case_id], reviewer_by_id[case_id])
        for case_id in sorted(primary_by_id)
    ]
    admission_primary = [
        item["primary_decision"] for item in pairs
    ]
    admission_reviewer = [
        item["reviewer_decision"] for item in pairs
    ]
    edge_states_primary: list[str] = []
    edge_states_reviewer: list[str] = []
    path_states_primary: list[str] = []
    path_states_reviewer: list[str] = []
    instance_states_primary: list[str] = []
    instance_states_reviewer: list[str] = []
    for case_id in sorted(primary_by_id):
        primary_edges = _edge_map(primary_by_id[case_id])
        reviewer_edges = _edge_map(reviewer_by_id[case_id])
        for edge_key in sorted(set(primary_edges) & set(reviewer_edges)):
            edge_states_primary.append(
                primary_edges[edge_key]["evidence_state"]
            )
            edge_states_reviewer.append(
                reviewer_edges[edge_key]["evidence_state"]
            )
        primary_paths = _path_map(primary_by_id[case_id])
        reviewer_paths = _path_map(reviewer_by_id[case_id])
        for path_key in sorted(set(primary_paths) & set(reviewer_paths)):
            path_states_primary.append(primary_paths[path_key]["state"])
            path_states_reviewer.append(reviewer_paths[path_key]["state"])
        primary_instances = _instance_map(primary_by_id[case_id])
        reviewer_instances = _instance_map(reviewer_by_id[case_id])
        for instance_id in sorted(
            set(primary_instances) & set(reviewer_instances)
        ):
            instance_states_primary.append(
                primary_instances[instance_id]["overall_state"]
            )
            instance_states_reviewer.append(
                reviewer_instances[instance_id]["overall_state"]
            )

    disputed = [
        item["case_id"] for item in pairs
        if item["needs_adjudication"]
    ]
    return {
        "agreement_version": "0.1",
        "packet_sha256": primary_assignment["packet_sha256"],
        "independent_cases": len(pairs),
        "admission_exact_agreement": _mean(
            item["admission_agreement"] for item in pairs
        ),
        "admission_cohen_kappa": _cohen_kappa(
            admission_primary,
            admission_reviewer,
        ),
        "mean_edge_identity_f1": _mean(
            item["edge_identity"]["f1"] for item in pairs
        ),
        "mean_evidence_state_accuracy": _mean_optional(
            item["evidence_state_accuracy_on_matched_edges"]
            for item in pairs
        ),
        "mean_path_state_accuracy": _mean_optional(
            item["path_state_accuracy_on_matched_paths"]
            for item in pairs
        ),
        "matched_edge_state_count": len(edge_states_primary),
        "edge_state_macro_f1_on_matched_edges": _macro_f1(
            edge_states_primary,
            edge_states_reviewer,
        ),
        "matched_path_state_count": len(path_states_primary),
        "path_state_cohen_kappa_on_matched_paths": _cohen_kappa(
            path_states_primary,
            path_states_reviewer,
        ),
        "matched_instance_state_count": len(instance_states_primary),
        "instance_state_cohen_kappa": _cohen_kappa(
            instance_states_primary,
            instance_states_reviewer,
        ),
        "instance_state_macro_f1": _macro_f1(
            instance_states_primary,
            instance_states_reviewer,
        ),
        "exact_payload_agreement": _mean(
            item["exact_label_payload_agreement"] for item in pairs
        ),
        "adjudication_rate": (
            len(disputed) / len(pairs) if pairs else 0.0
        ),
        "cases_needing_adjudication": disputed,
        "pairs": pairs,
    }


def finalize_pair(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
    adjudicator: dict[str, Any] | None = None,
) -> dict[str, Any]:
    comparison = compare_pair(primary, reviewer)
    if comparison["needs_adjudication"]:
        if adjudicator is None:
            raise ValueError("disagreement requires an adjudicator submission")
        validate_submission(adjudicator)
        if adjudicator["role"] != "adjudicator":
            raise ValueError("third submission must have adjudicator role")
        if adjudicator["case_id"] != primary["case_id"]:
            raise ValueError("adjudicator case_id differs")
        if adjudicator["annotator_id"] in {
            primary["annotator_id"],
            reviewer["annotator_id"],
        }:
            raise ValueError("adjudicator must be a third human")
        if (
            adjudicator["source_context_sha256"]
            != primary["source_context_sha256"]
        ):
            raise ValueError("adjudicator uses different source material")
        chosen = adjudicator
        decision = chosen["admission_screen"]["decision"]
        status = {
            "accept": "adjudicated",
            "needs_execution": "needs_execution",
            "reject": "rejected",
        }[decision]
        label_origin = "human_adjudicated"
        adjudication_text = chosen["admission_screen"]["rationale"]
    else:
        chosen = primary
        decision = chosen["admission_screen"]["decision"]
        status = {
            "accept": "reviewed",
            "needs_execution": "needs_execution",
            "reject": "rejected",
        }[decision]
        label_origin = "human_reviewed"
        adjudication_text = None

    result = {
        "case_id": primary["case_id"],
        **deepcopy(_source_context(primary)),
        "path_ontology": deepcopy(primary["path_ontology"]),
        "source_context_fields": list(
            primary["source_context_fields"]
        ),
        "source_context_sha256": primary["source_context_sha256"],
        "annotation": {
            "status": status,
            "label_origin": label_origin,
            "primary_annotator": primary["annotator_id"],
            "reviewer": reviewer["annotator_id"],
            "adjudication": adjudication_text,
        },
        "nodes": deepcopy(chosen["nodes"]),
        "edges": deepcopy(chosen["edges"]),
        "path_labels": deepcopy(chosen["path_labels"]),
        "tool_tasks": deepcopy(chosen["tool_tasks"]),
        "instance_labels": deepcopy(chosen["instance_labels"]),
        "admission_screen": deepcopy(chosen["admission_screen"]),
        "annotation_audit": {
            "primary_submission_sha256": _stable_hash(primary),
            "reviewer_submission_sha256": _stable_hash(reviewer),
            "adjudicator_submission_sha256": (
                _stable_hash(adjudicator)
                if adjudicator is not None
                else None
            ),
            "agreement": comparison,
        },
    }
    jsonschema.validate(
        result,
        _real_schema(),
        format_checker=jsonschema.FormatChecker(),
    )
    return result


def finalize_assignments(
    primary_assignment: dict[str, Any],
    reviewer_assignment: dict[str, Any],
    adjudicator_assignment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Finalize a complete packet and preserve its agreement audit."""
    agreement = compare_assignments(
        primary_assignment,
        reviewer_assignment,
    )
    primary_by_id = {
        item["case_id"]: item for item in primary_assignment["cases"]
    }
    reviewer_by_id = {
        item["case_id"]: item for item in reviewer_assignment["cases"]
    }
    adjudicator_by_id: dict[str, dict[str, Any]] = {}
    if adjudicator_assignment is not None:
        if adjudicator_assignment.get("role") != "adjudicator":
            raise ValueError("third assignment must have adjudicator role")
        if (
            adjudicator_assignment.get("packet_sha256")
            != agreement["packet_sha256"]
        ):
            raise ValueError("adjudicator assignment uses another packet")
        adjudicator_by_id = {
            item["case_id"]: item
            for item in adjudicator_assignment.get("cases", [])
        }
        unexpected = (
            set(adjudicator_by_id)
            - set(agreement["cases_needing_adjudication"])
        )
        if unexpected:
            raise ValueError(
                "adjudicator assignment contains non-disputed cases"
            )

    cases = []
    for case_id in sorted(primary_by_id):
        needs_adjudication = (
            case_id in agreement["cases_needing_adjudication"]
        )
        adjudicator = adjudicator_by_id.get(case_id)
        if needs_adjudication and adjudicator is None:
            raise ValueError(
                f"missing adjudicator submission for {case_id}"
            )
        cases.append(
            finalize_pair(
                primary_by_id[case_id],
                reviewer_by_id[case_id],
                adjudicator,
            )
        )

    return {
        "release_version": "human-annotation-0.1",
        "packet_sha256": agreement["packet_sha256"],
        "annotation_protocol": (
            "docs/realpathbench_annotation_protocol.md"
        ),
        "agreement": agreement,
        "adjudication": {
            "required": len(
                agreement["cases_needing_adjudication"]
            ),
            "completed": len(adjudicator_by_id),
        },
        "cases": cases,
    }


def mark_completed(submission: dict[str, Any]) -> dict[str, Any]:
    """Convenience helper used by the local UI/CLI after a human attests."""
    out = deepcopy(submission)
    out["human_attestation"] = True
    out["completed_at"] = datetime.now(timezone.utc).isoformat()
    return out


def _validate_pair(
    primary: dict[str, Any],
    reviewer: dict[str, Any],
) -> None:
    validate_submission(primary)
    validate_submission(reviewer)
    if primary["role"] != "primary" or reviewer["role"] != "reviewer":
        raise ValueError("pair roles must be primary and reviewer")
    if primary["annotator_id"] == reviewer["annotator_id"]:
        raise ValueError("primary and reviewer must be different humans")
    if primary["case_id"] != reviewer["case_id"]:
        raise ValueError("paired case IDs differ")
    if primary["packet_sha256"] != reviewer["packet_sha256"]:
        raise ValueError("paired submissions originate from different packets")
    if (
        primary["source_context_sha256"]
        != reviewer["source_context_sha256"]
    ):
        raise ValueError("paired submissions use different source material")


def _validate_role_and_human_id(role: Any, annotator_id: Any) -> None:
    if role not in ROLES:
        raise ValueError(f"invalid annotation role: {role}")
    if not isinstance(annotator_id, str) or not annotator_id.strip():
        raise ValueError("annotator_id is required")
    tokens = {
        token.lower()
        for token in str(annotator_id).replace("-", "_").split("_")
    }
    if tokens.intersection(AI_ID_MARKERS):
        raise ValueError("annotator_id appears to identify an AI/model")


def _assert_packet_unlabeled(packet: dict[str, Any]) -> None:
    for case in packet.get("cases", []):
        annotation = case.get("annotation") or {}
        if annotation.get("status") != "pending":
            raise ValueError("assignment source packet is not pending")
        if annotation.get("label_origin") is not None:
            raise ValueError("assignment source packet contains labels")
        if any(case.get(section) for section in (
            "nodes",
            "edges",
            "path_labels",
            "tool_tasks",
            "instance_labels",
        )):
            raise ValueError("assignment source packet is not label-empty")


def _validate_source_context(submission: dict[str, Any]) -> None:
    fields = submission.get("source_context_fields")
    expected_hash = submission.get("source_context_sha256")
    if (
        not isinstance(fields, list)
        or not fields
        or len(fields) != len(set(fields))
        or "source" not in fields
    ):
        raise ValueError("source_context_fields are invalid")
    missing = [field for field in fields if field not in submission]
    if missing:
        raise ValueError(f"source context is missing fields: {missing}")
    source_context = {
        field: submission[field] for field in fields
    }
    if _stable_hash(source_context) != expected_hash:
        raise ValueError("source context hash mismatch")


def _source_context(
    submission: dict[str, Any],
) -> dict[str, Any]:
    return {
        field: submission[field]
        for field in submission["source_context_fields"]
    }


def _validate_graph_references(submission: dict[str, Any]) -> None:
    node_ids = [item["id"] for item in submission["nodes"]]
    edge_ids = [item["edge_id"] for item in submission["edges"]]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("duplicate node IDs")
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("duplicate edge IDs")
    node_set = set(node_ids)
    edge_set = set(edge_ids)
    for edge in submission["edges"]:
        if edge["source"] not in node_set or edge["target"] not in node_set:
            raise ValueError(f"edge {edge['edge_id']} references unknown node")
    for path in submission["path_labels"]:
        if not set(path["node_ids"]).issubset(node_set):
            raise ValueError(f"path {path['path_id']} references unknown node")
        if not set(path["edge_ids"]).issubset(edge_set):
            raise ValueError(f"path {path['path_id']} references unknown edge")
        if len(path["edge_ids"]) != len(path["node_ids"]) - 1:
            raise ValueError(
                f"path {path['path_id']} edge/node lengths are inconsistent"
            )


def _validate_instance_references(
    submission: dict[str, Any],
    decision: str,
) -> None:
    runtime_instances = submission.get("runtime_instances") or []
    runtime_ids = [
        item.get("instance_id")
        for item in runtime_instances
        if isinstance(item, dict)
    ]
    if len(runtime_ids) != len(runtime_instances) or any(
        not isinstance(item, str) or not item
        for item in runtime_ids
    ):
        raise ValueError("runtime_instances contain invalid instance IDs")
    if len(runtime_ids) != len(set(runtime_ids)):
        raise ValueError("duplicate runtime instance IDs")
    labels = submission["instance_labels"]
    label_ids = [item["instance_id"] for item in labels]
    if len(label_ids) != len(set(label_ids)):
        raise ValueError("duplicate instance labels")
    if decision == "accept" and set(label_ids) != set(runtime_ids):
        raise ValueError(
            "accepted runtime-backed case requires one label for every "
            "runtime instance"
        )
    if not runtime_ids and labels:
        raise ValueError("case without runtime instances cannot have instance labels")
    if not set(label_ids).issubset(runtime_ids):
        raise ValueError("instance label references unknown runtime instance")

    path_ids = {item["path_id"] for item in submission["path_labels"]}
    for label in labels:
        labeled_paths = [
            item["path_id"] for item in label["path_states"]
        ]
        if len(labeled_paths) != len(set(labeled_paths)):
            raise ValueError(
                f"instance {label['instance_id']} has duplicate path states"
            )
        if set(labeled_paths) != path_ids:
            raise ValueError(
                f"instance {label['instance_id']} must label every case path"
            )
        states = [item["state"] for item in label["path_states"]]
        expected = _overall_path_state(states)
        if label["overall_state"] != expected:
            raise ValueError(
                f"instance {label['instance_id']} overall_state must be "
                f"{expected}"
            )


def _overall_path_state(states: list[str]) -> str:
    if "Valid" in states:
        return "Valid"
    if "Conflict" in states:
        return "Conflict"
    if "Insufficient" in states:
        return "Insufficient"
    return "Invalid"


def _edge_map(submission: dict[str, Any]) -> dict[tuple, dict]:
    return {
        (
            edge["source"],
            edge["target"],
            edge["type"],
            tuple(sorted(edge["raw_refs"])),
        ): edge
        for edge in submission["edges"]
    }


def _path_map(submission: dict[str, Any]) -> dict[tuple, dict]:
    edge_by_id = {
        edge["edge_id"]: edge for edge in submission["edges"]
    }
    output = {}
    for path in submission["path_labels"]:
        types = tuple(
            edge_by_id[edge_id]["type"]
            for edge_id in path["edge_ids"]
            if edge_id in edge_by_id
        )
        output[(tuple(path["node_ids"]), types)] = path
    return output


def _instance_map(submission: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["instance_id"]: item
        for item in submission["instance_labels"]
    }


def _label_payload(submission: dict[str, Any]) -> dict[str, Any]:
    return {
        "admission": {
            key: value
            for key, value in submission["admission_screen"].items()
            if key != "rationale"
        },
        "nodes": sorted(
            submission["nodes"],
            key=lambda item: item["id"],
        ),
        "edges": sorted(
            submission["edges"],
            key=lambda item: item["edge_id"],
        ),
        "path_labels": sorted(
            submission["path_labels"],
            key=lambda item: item["path_id"],
        ),
        "tool_tasks": sorted(
            submission["tool_tasks"],
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
            ),
        ),
        "instance_labels": sorted(
            submission["instance_labels"],
            key=lambda item: item["instance_id"],
        ),
    }


def _with_runtime_instances(case: dict[str, Any]) -> dict[str, Any]:
    """Backfill one label-free instance for older telemetry-only packets."""
    out = deepcopy(case)
    if "runtime_instances" in out:
        return out
    observations = out.get("observations") or []
    if observations:
        instance_id = "instance-" + sha256(
            (out["case_id"] + ":published-telemetry").encode("utf-8")
        ).hexdigest()[:20]
        out["runtime_instances"] = [
            {
                "instance_id": instance_id,
                "environment_kind": "published_telemetry",
                "observation_ids": [
                    item["observation_id"] for item in observations
                ],
                "observation_count": len(observations),
                "selection_origin": (
                    "all normalized observations copied from the pinned "
                    "published telemetry case"
                ),
            }
        ]
    else:
        out["runtime_instances"] = []
    return out


def _prf(matched: int, predicted: int, reference: int) -> tuple:
    precision = matched / predicted if predicted else (1.0 if reference == 0 else 0.0)
    recall = matched / reference if reference else (1.0 if predicted == 0 else 0.0)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return precision, recall, f1


def _cohen_kappa(left: list[str], right: list[str]) -> float | None:
    if not left or len(left) != len(right):
        return None
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    labels = set(left) | set(right)
    expected = sum(
        (left.count(label) / len(left))
        * (right.count(label) / len(right))
        for label in labels
    )
    if expected == 1.0:
        return 1.0 if observed == 1.0 else 0.0
    return (observed - expected) / (1.0 - expected)


def _mean(values: Iterable[float | bool]) -> float:
    values = list(values)
    return sum(float(value) for value in values) / len(values) if values else 0.0


def _mean_optional(values: Iterable[float | None]) -> float | None:
    observed = [value for value in values if value is not None]
    return _mean(observed) if observed else None


def _macro_f1(
    reference: list[str],
    predicted: list[str],
) -> float | None:
    if not reference or len(reference) != len(predicted):
        return None
    labels = sorted(set(reference) | set(predicted))
    scores = []
    for label in labels:
        true_positive = sum(
            expected == label and actual == label
            for expected, actual in zip(reference, predicted)
        )
        false_positive = sum(
            expected != label and actual == label
            for expected, actual in zip(reference, predicted)
        )
        false_negative = sum(
            expected == label and actual != label
            for expected, actual in zip(reference, predicted)
        )
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        scores.append(
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
    return _mean(scores)


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _real_schema() -> dict[str, Any]:
    return json.loads(REAL_SCHEMA_PATH.read_text(encoding="utf-8"))
