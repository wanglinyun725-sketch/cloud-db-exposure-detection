"""Evidence semantic normalization for CloudDB exposure graphs."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime

VALID_EVIDENCE_STATUSES = {"Supported", "Contradicted", "Unknown"}
VALID_EVIDENCE_SOURCES = {
    "audit",
    "cloudgoat_ref",
    "db_schema",
    "dlp",
    "generated",
    "iam",
    "manual",
    "network",
    "policy",
    "sg_rule",
    "terraform",
    "unknown",
}

EDGE_SOURCE_BY_TYPE = {
    "can_connect": "network",
    "can_assume": "iam",
    "has_permission": "iam",
    "contains": "db_schema",
    "classified_as": "dlp",
    "accessed": "audit",
    "triggered": "audit",
    "has_risk": "audit",
    "owns": "terraform",
    "protected_by": "policy",
}

DEFAULT_QUERY_COST_BY_TYPE = {
    "can_connect": 1,
    "can_assume": 2,
    "has_permission": 2,
    "contains": 1,
    "classified_as": 1,
    "accessed": 3,
    "triggered": 3,
    "has_risk": 2,
    "owns": 1,
    "protected_by": 1,
}


def normalize_edge_attrs(edge_type: str, attrs: dict | None) -> dict:
    attrs = dict(attrs or {})
    source = attrs.get("source") or EDGE_SOURCE_BY_TYPE.get(edge_type, "unknown")
    timestamp = attrs.get("time") or attrs.get("observed_at") or attrs.get("t")
    confidence = attrs.get("confidence", attrs.get("strength", 1.0))
    status = attrs.get("status") or _infer_status(attrs)
    raw_evidence = attrs.get("raw_evidence") or attrs.get("evidence_ref") or f"{edge_type}:synthetic"
    attrs.update({
        "source": source,
        "time": timestamp,
        "confidence": float(confidence),
        "status": status,
        "query_cost": int(attrs.get("query_cost", DEFAULT_QUERY_COST_BY_TYPE.get(edge_type, 1))),
        "raw_evidence": raw_evidence,
    })
    return attrs


def semanticize_sample(sample: dict) -> dict:
    out = deepcopy(sample)
    for edge in out.get("edges", []):
        edge["attrs"] = normalize_edge_attrs(edge.get("type", ""), edge.get("attrs", {}))
    return out


def evidence_field_stats(samples: list[dict]) -> dict:
    total_edges = 0
    field_counts = {"status": 0, "source": 0, "time": 0, "confidence": 0, "query_cost": 0, "raw_evidence": 0}
    status_counts = {k: 0 for k in sorted(VALID_EVIDENCE_STATUSES)}
    source_counts = {}
    for sample in samples:
        for edge in sample.get("edges", []):
            total_edges += 1
            attrs = edge.get("attrs", {})
            for field in field_counts:
                if attrs.get(field) is not None:
                    field_counts[field] += 1
            status = attrs.get("status")
            if status in status_counts:
                status_counts[status] += 1
            source = attrs.get("source", "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1
    return {
        "total_edges": total_edges,
        "field_coverage": {k: round(v / max(total_edges, 1), 4) for k, v in field_counts.items()},
        "status_counts": status_counts,
        "source_counts": dict(sorted(source_counts.items())),
    }


def validate_semantic_attrs(edge_type: str, attrs: dict) -> list[str]:
    violations = []
    status = attrs.get("status")
    if status is not None and status not in VALID_EVIDENCE_STATUSES:
        violations.append(f"status='{status}' invalid")
    source = attrs.get("source")
    if source is not None and not str(source).strip():
        violations.append("source is empty")
    confidence = attrs.get("confidence")
    if confidence is not None and not 0 <= confidence <= 1:
        violations.append(f"confidence={confidence} out of [0,1]")
    query_cost = attrs.get("query_cost")
    if query_cost is not None and query_cost < 0:
        violations.append(f"query_cost={query_cost} < 0")
    timestamp = attrs.get("time")
    if timestamp:
        try:
            datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except ValueError:
            violations.append(f"time='{timestamp}' is not ISO-8601")
    return violations


def _infer_status(attrs: dict) -> str:
    strength = attrs.get("strength")
    if strength is not None and strength <= 0:
        return "Contradicted"
    return "Supported"
