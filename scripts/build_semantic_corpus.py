#!/usr/bin/env python3
"""Build the C1 semantic evidence corpus with refuted/missing/temporal variants."""
import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.graph.evidence_semantics import evidence_field_stats, semanticize_sample
from src.graph.constrained_search import REQUIRED_EDGE_TYPES, VALID_EDGE_TRANSITIONS
from src.graph.path_utils import assign_edge_ids, resolve_edge_sequence

INPUTS = [
    "data/pathbench_60.json",
    "data/pathbench_cloudgoat.json",
    "data/verification_set/samples_v2.json",
]
BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def main():
    base = []
    variants = []
    for rel in INPUTS:
        dataset = json.load(open(os.path.join(ROOT, rel), encoding="utf-8"))
        source_name = rel.replace("/", ":").replace(".json", "")
        for idx, sample in enumerate(dataset):
            normalized = _normalize_sample(sample, source_name, idx)
            base.append(normalized)
            variants.extend(_make_variants(normalized))

    corpus = base + variants
    out_dir = os.path.join(ROOT, "output", "semantic_corpus")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "cloud_db_semantic_corpus.json")
    stats_path = os.path.join(out_dir, "cloud_db_semantic_corpus_stats.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, indent=2)
    stats = evidence_field_stats(corpus)
    stats.update(_corpus_stats(corpus, base, variants))
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"wrote {out_path}")
    print(f"wrote {stats_path}")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


def _normalize_sample(sample, source_name, idx):
    out = semanticize_sample(sample)
    out["sample_id"] = f"{source_name}:{out.get('sample_id', idx)}"
    out["raw_dataset"] = source_name
    out["variant_type"] = "base"
    out["expected_state"] = _expected_state(out.get("expected_type"))
    out["sample_label"] = out["expected_state"]
    assign_edge_ids(out)
    out["path_labels"] = _build_path_labels(
        out,
        out.get("gold_paths", []),
        out["expected_state"],
        out.get("expected_type"),
        "base",
    )
    for edge_idx, edge in enumerate(out.get("edges", [])):
        attrs = edge.setdefault("attrs", {})
        attrs["time"] = attrs.get("time") or _synthetic_time(idx, edge_idx)
        attrs["raw_evidence"] = attrs.get("raw_evidence") or attrs.get("evidence_ref") or f"{out['sample_id']}:edge:{edge_idx}"
        attrs["evidence_ref"] = attrs.get("evidence_ref") or attrs["raw_evidence"]
    if out.get("expected_state") == "Insufficient":
        _mark_all_hard_edges(out, {"can_connect", "has_permission", "can_assume"}, "Unknown", 0.0)
    return out


def _make_variants(sample):
    if sample.get("expected_type") not in {"Observed_Risk", "Potential_Exposure"}:
        return []
    paths = [path for path in sample.get("gold_paths", []) if len(path) >= 2]
    if not paths:
        return []
    variants = []
    for kind in ["refuted", "missing", "temporal_conflict"]:
        v = copy.deepcopy(sample)
        v["sample_id"] = f"{sample['sample_id']}:{kind}"
        v["variant_type"] = kind
        if kind == "refuted":
            _mark_all_hard_edges(v, {"can_connect", "has_permission", "can_assume"}, "Contradicted", 0.0)
            v["expected_type"] = "Refuted"
            v["expected_state"] = "Invalid"
            v["sample_label"] = "Invalid"
            v["path_labels"] = _build_path_labels(v, paths, "Invalid", "Refuted", kind)
        elif kind == "missing":
            _mark_all_hard_edges(v, {"can_connect", "has_permission", "can_assume"}, "Unknown", 0.0)
            v["expected_type"] = "Insufficient_Evidence"
            v["expected_state"] = "Insufficient"
            v["sample_label"] = "Insufficient"
            v["path_labels"] = _build_path_labels(v, paths, "Insufficient", "Insufficient_Evidence", kind)
        else:
            changed = _mark_all_temporal_edges(v, {"can_connect", "can_assume", "has_permission", "accessed", "triggered", "has_risk"})
            if not changed:
                continue
            v["expected_type"] = "Refuted"
            v["expected_state"] = "Invalid"
            v["sample_label"] = "Invalid"
            v["path_labels"] = _build_path_labels(v, paths, "Invalid", "Refuted", kind)
        variants.append(v)
    
    return variants


def _build_path_labels(sample, paths, state, expected_type, variant_type):
    labels = []
    for path in paths:
        if len(path) < 2:
            continue
        edge_ids, edge_types = resolve_edge_sequence(
            sample,
            path,
            VALID_EDGE_TRANSITIONS,
            REQUIRED_EDGE_TYPES,
        )
        labels.append({
            "path": path,
            "edge_ids": edge_ids,
            "edge_types": edge_types,
            "state": state,
            "expected_type": expected_type,
            "variant_type": variant_type,
            "label_scope": "gold_path",
        })
    return labels


def _mark_all_hard_edges(sample, edge_types, status, strength):
    changed = False
    for edge in sample.get("edges", []):
        if edge.get("type") in edge_types:
            attrs = edge.setdefault("attrs", {})
            attrs["status"] = status
            attrs["strength"] = strength
            attrs["confidence"] = strength
            attrs["raw_evidence"] = f"{attrs.get('raw_evidence')};sample_variant:{status.lower()}"
            changed = True
    return changed


def _mark_all_paths(sample, paths, edge_types, status, strength):
    changed = False
    for path in paths:
        changed = _mark_first_path_edge(sample, path, edge_types, status, strength) or changed
    return changed


def _mark_first_path_edge(sample, path, edge_types, status, strength):
    pairs = set(zip(path[:-1], path[1:]))
    for edge in sample.get("edges", []):
        if (edge.get("source"), edge.get("target")) in pairs and edge.get("type") in edge_types:
            attrs = edge.setdefault("attrs", {})
            attrs["status"] = status
            attrs["strength"] = strength
            attrs["confidence"] = strength
            attrs["raw_evidence"] = f"{attrs.get('raw_evidence')};variant:{status.lower()}"
            return True
    return False


def _mark_all_temporal_edges(sample, edge_types):
    changed = False
    for edge in sample.get("edges", []):
        if edge.get("type") in edge_types:
            attrs = edge.setdefault("attrs", {})
            attrs["time"] = "2025-01-01T00:00:00Z"
            attrs["status"] = "Contradicted"
            attrs["strength"] = 0.0
            attrs["confidence"] = 0.0
            attrs["temporal_conflict"] = True
            attrs["raw_evidence"] = f"{attrs.get('raw_evidence')};sample_variant:temporal_conflict"
            changed = True
    return changed


def _mark_temporal_edges_by_position(sample, paths, position):
    """Mark edges in early (first half) or late (second half) positions of gold paths with temporal_conflict."""
    changed = False
    target_pairs = set()
    
    for path in paths:
        if len(path) < 2:
            continue
        # Build edge pairs for this path
        path_pairs = list(zip(path[:-1], path[1:]))
        mid = len(path_pairs) // 2
        
        if position == "early":
            # First half of edges
            target_pairs.update(path_pairs[:mid] if mid > 0 else path_pairs[:1])
        elif position == "late":
            # Second half of edges
            target_pairs.update(path_pairs[mid:] if mid > 0 else path_pairs[-1:])
    
    # Mark edges that are in target pairs
    for edge in sample.get("edges", []):
        edge_pair = (edge.get("source"), edge.get("target"))
        if edge_pair in target_pairs:
            attrs = edge.setdefault("attrs", {})
            attrs["time"] = "2025-01-01T00:00:00Z"
            attrs["status"] = "Contradicted"
            attrs["strength"] = 0.0
            attrs["confidence"] = 0.0
            attrs["temporal_conflict"] = True
            attrs["raw_evidence"] = f"{attrs.get('raw_evidence')};sample_variant:temporal_conflict_{position}"
            changed = True
    
    return changed


def _make_temporal_conflict(sample, path):
    pairs = set(zip(path[:-1], path[1:]))
    saw_access = False
    for edge in sample.get("edges", []):
        if (edge.get("source"), edge.get("target")) in pairs and edge.get("type") in {"accessed", "triggered", "has_risk"}:
            attrs = edge.setdefault("attrs", {})
            attrs["time"] = "2025-01-01T00:00:00Z"
            attrs["status"] = "Contradicted"
            attrs["temporal_conflict"] = True
            attrs["raw_evidence"] = f"{attrs.get('raw_evidence')};variant:temporal_conflict"
            saw_access = True
    if saw_access:
        return True
    return _mark_first_path_edge(sample, path, {"accessed", "triggered", "has_risk", "has_permission"}, "Contradicted", 0.0)


def _synthetic_time(sample_idx, edge_idx):
    t = BASE_TIME + timedelta(days=sample_idx, minutes=edge_idx * 5)
    return t.isoformat().replace("+00:00", "Z")


def _expected_state(expected_type):
    if expected_type in {"Observed_Risk", "Potential_Exposure", "Low_Risk"}:
        return "Valid"
    if expected_type in {"Refuted", "Invalid_Path"}:
        return "Invalid"
    return "Insufficient"


def _corpus_stats(corpus, base, variants):
    by_variant = {}
    by_expected_state = {}
    by_sample_label = {}
    by_path_label = {}
    by_raw_dataset = {}
    path_label_total = 0
    for sample in corpus:
        by_variant[sample.get("variant_type", "unknown")] = by_variant.get(sample.get("variant_type", "unknown"), 0) + 1
        by_expected_state[sample.get("expected_state", "unknown")] = by_expected_state.get(sample.get("expected_state", "unknown"), 0) + 1
        by_sample_label[sample.get("sample_label", "unknown")] = by_sample_label.get(sample.get("sample_label", "unknown"), 0) + 1
        by_raw_dataset[sample.get("raw_dataset", "unknown")] = by_raw_dataset.get(sample.get("raw_dataset", "unknown"), 0) + 1
        for label in sample.get("path_labels", []):
            path_label_total += 1
            by_path_label[label.get("state", "unknown")] = by_path_label.get(label.get("state", "unknown"), 0) + 1
    return {
        "samples_total": len(corpus),
        "samples_base": len(base),
        "samples_variants": len(variants),
        "path_labels_total": path_label_total,
        "by_variant": dict(sorted(by_variant.items())),
        "by_expected_state": dict(sorted(by_expected_state.items())),
        "by_sample_label": dict(sorted(by_sample_label.items())),
        "by_path_label": dict(sorted(by_path_label.items())),
        "by_raw_dataset": dict(sorted(by_raw_dataset.items())),
    }


if __name__ == "__main__":
    main()
