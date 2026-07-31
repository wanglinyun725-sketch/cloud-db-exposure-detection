"""Deterministic, group-safe split construction for reviewed real-path gold."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from typing import Any, Mapping


ANALYTIC_SPLITS = {"development", "validation", "test", "external_test"}


def build_frozen_split_manifest(
    release: Mapping[str, Any],
    *,
    seed: int,
    ratios: Mapping[str, float] | None = None,
    external_source_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Assign whole independence groups without consulting path labels."""
    if not isinstance(seed, int):
        raise ValueError("split seed must be an integer")
    cases = release.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("reviewed release must contain cases")
    packet_sha = release.get("packet_sha256")
    if not _is_sha256(packet_sha):
        raise ValueError("reviewed release lacks a valid packet_sha256")
    ratios = dict(
        ratios
        or {
            "development": 0.20,
            "validation": 0.20,
            "test": 0.60,
        }
    )
    _validate_ratios(ratios)
    external_source_ids = set(external_source_ids or set())

    fixed_assignments: dict[str, tuple[str, str]] = {}
    analytic_groups: dict[str, list[dict[str, Any]]] = {}
    seen_case_ids: set[str] = set()
    for case in cases:
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("release case lacks case_id")
        if case_id in seen_case_ids:
            raise ValueError(f"duplicate case_id: {case_id}")
        seen_case_ids.add(case_id)
        annotation = case.get("annotation") or {}
        if annotation.get("status") not in {
            "reviewed",
            "adjudicated",
            "needs_execution",
            "rejected",
        }:
            raise ValueError(f"case {case_id} is not finalized")
        decision = (case.get("admission_screen") or {}).get("decision")
        if decision == "reject":
            fixed_assignments[case_id] = (
                "excluded",
                "human admission decision: reject",
            )
            continue
        if decision == "needs_execution":
            fixed_assignments[case_id] = (
                "execution_queue",
                "human admission decision: needs_execution",
            )
            continue
        if decision != "accept":
            raise ValueError(f"case {case_id} lacks a final admission decision")
        group = (case.get("candidate_metadata") or {}).get(
            "independence_group"
        )
        if not isinstance(group, str) or not group:
            raise ValueError(f"accepted case {case_id} lacks independence_group")
        analytic_groups.setdefault(group, []).append(case)

    group_splits: dict[str, tuple[str, str]] = {}

    # Provenance restrictions take precedence over external-holdout status.
    # Otherwise an external C-level group could silently enter effectiveness
    # testing before the restriction below is evaluated.
    c_level = {
        group: members
        for group, members in analytic_groups.items()
        if any(item["source"]["provenance_level"] == "C" for item in members)
    }
    runtime_backed: dict[str, list[dict[str, Any]]] = {}
    for group, members in sorted(analytic_groups.items()):
        if group in c_level:
            continue
        source_ids = {item["source"]["source_id"] for item in members}
        if source_ids & external_source_ids:
            group_splits[group] = (
                "external_test",
                "source-predeclared external holdout",
            )
        else:
            runtime_backed[group] = members

    # C-level evidence can inform development but never frozen effectiveness
    # testing. Mixed-provenance groups inherit the stricter rule.
    c_denominator = ratios["development"] + ratios["validation"]
    for group, split in _balanced_group_assignment(
        c_level,
        {
            "development": ratios["development"] / c_denominator,
            "validation": ratios["validation"] / c_denominator,
        },
        seed,
        namespace="c-level",
    ).items():
        group_splits[group] = (
            split,
            "C-level provenance restricted to development/validation",
        )
    for group, split in _balanced_group_assignment(
        runtime_backed,
        ratios,
        seed,
        namespace="runtime-backed",
    ).items():
        group_splits[group] = (
            split,
            "deterministic group-balanced assignment",
        )

    assignments = []
    for case in sorted(cases, key=lambda item: item["case_id"]):
        case_id = case["case_id"]
        if case_id in fixed_assignments:
            split, reason = fixed_assignments[case_id]
            group = (
                (case.get("candidate_metadata") or {}).get(
                    "independence_group"
                )
                or f"nonanalytic:{case_id}"
            )
        else:
            group = case["candidate_metadata"]["independence_group"]
            split, reason = group_splits[group]
        assignments.append({
            "case_id": case_id,
            "independence_group": group,
            "split": split,
            "assignment_reason": reason,
        })

    split_counts = Counter(item["split"] for item in assignments)
    analytic_group_splits: dict[str, set[str]] = {}
    for item in assignments:
        if item["split"] in ANALYTIC_SPLITS:
            analytic_group_splits.setdefault(
                item["independence_group"], set()
            ).add(item["split"])
    if any(len(values) != 1 for values in analytic_group_splits.values()):
        raise AssertionError("internal error: independence group crossed splits")
    return {
        "manifest_version": "0.1",
        "packet_sha256": packet_sha,
        "gold_release_sha256": _stable_hash(release),
        "seed": seed,
        "policy": {
            "statistical_unit": "independence_group",
            "label_fields_consulted": [],
            "balancing_fields": [
                "admission_screen.decision",
                "candidate_metadata.independence_group",
                "source.source_id",
                "source.provenance_level",
                "case_count",
            ],
            "target_ratios": ratios,
            "external_source_ids": sorted(external_source_ids),
            "c_level_test_forbidden": True,
        },
        "summary": {
            "cases": len(assignments),
            "analytic_independence_groups": len(analytic_group_splits),
            "cases_by_split": dict(sorted(split_counts.items())),
        },
        "assignments": assignments,
    }


def _balanced_group_assignment(
    groups: Mapping[str, list[dict[str, Any]]],
    ratios: Mapping[str, float],
    seed: int,
    *,
    namespace: str,
) -> dict[str, str]:
    if not groups:
        return {}
    total_cases = sum(len(members) for members in groups.values())
    targets = {
        split: total_cases * ratio for split, ratio in ratios.items()
    }
    counts = {split: 0 for split in ratios}
    output: dict[str, str] = {}
    ordered = sorted(
        groups.items(),
        key=lambda item: (
            -len(item[1]),
            _seeded_digest(seed, namespace, item[0]),
            item[0],
        ),
    )
    for group, members in ordered:
        size = len(members)
        split = min(
            ratios,
            key=lambda name: (
                (counts[name] + size - targets[name]) ** 2
                - (counts[name] - targets[name]) ** 2,
                counts[name] / targets[name]
                if targets[name] > 0
                else float("inf"),
                _seeded_digest(seed, group, name),
                name,
            ),
        )
        output[group] = split
        counts[split] += size
    return output


def _validate_ratios(ratios: Mapping[str, float]) -> None:
    if set(ratios) != {"development", "validation", "test"}:
        raise ValueError(
            "ratios must define development, validation and test"
        )
    if any(
        not isinstance(value, (int, float)) or value <= 0
        for value in ratios.values()
    ):
        raise ValueError("all split ratios must be positive")
    if abs(sum(float(value) for value in ratios.values()) - 1.0) > 1e-9:
        raise ValueError("split ratios must sum to one")


def _seeded_digest(*parts: Any) -> str:
    return sha256(
        ":".join(str(part) for part in parts).encode("utf-8")
    ).hexdigest()


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
