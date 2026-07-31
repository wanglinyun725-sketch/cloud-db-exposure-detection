"""Pre-label, source-isolated split construction for Oracle Gold."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from src.oracle_gold.protocol import validate_oracle_registry


def build_oracle_split(
    root: str | Path,
    *,
    registry_path: str | Path,
    policy_path: str | Path,
) -> dict[str, Any]:
    root = Path(root).resolve()
    registry_path = _resolve(root, registry_path)
    policy_path = _resolve(root, policy_path)
    registry = _read(registry_path)
    policy = _read(policy_path)
    audit = validate_oracle_registry(root, registry)
    source_to_split = _source_map(policy)

    assignments = []
    excluded = []
    for record in registry["candidates"]:
        group = record["independence_group"]
        if record.get("counts_toward_oracle_gold") is not True:
            excluded.append({
                "independence_group": group,
                "truth_state": record["truth_state"],
                "reason": "not_qualifying_oracle_gold",
            })
            continue
        splits = {
            source_to_split[source]
            for source in record["source_ids"]
            if source in source_to_split
        }
        unknown_sources = sorted(
            set(record["source_ids"]) - set(source_to_split)
        )
        if unknown_sources:
            raise ValueError(
                f"Oracle source absent from split policy: {unknown_sources}"
            )
        if len(splits) != 1:
            raise ValueError(
                f"Oracle group spans source splits: {group} -> {splits}"
            )
        assignments.append({
            "independence_group": group,
            "source_ids": record["source_ids"],
            "platforms": record["platforms"],
            "truth_state": record["truth_state"],
            "split": next(iter(splits)),
        })
    assignments.sort(key=lambda item: item["independence_group"])
    excluded.sort(key=lambda item: item["independence_group"])
    split_counts: dict[str, int] = {}
    for item in assignments:
        split = item["split"]
        split_counts[split] = split_counts.get(split, 0) + 1
    return {
        "split_version": "1.0.0",
        "split_kind": "executable_oracle_split_v1",
        "status": (
            "ready"
            if audit["completion_gate"]["passes"]
            else "blocked_on_oracle_gold"
        ),
        "oracle_registry_sha256": _stable_hash(registry),
        "bindings": {
            "oracle_registry": _binding(root, registry_path),
            "split_policy": _binding(root, policy_path),
        },
        "policy": {
            "statistical_unit": "independence_group",
            "source_isolation": True,
            "selection_before_gold": True,
            "unknown_and_conflict_excluded": True,
            "post_gold_reassignment_forbidden": True,
        },
        "summary": {
            "qualifying_groups": len(assignments),
            "excluded_or_pending_groups": len(excluded),
            "split_counts": dict(sorted(split_counts.items())),
            "minimum_oracle_gold_groups": 30,
            "minimum_test_and_external_test_groups": 15,
            "gold_gate_passes": (
                audit["qualifying_oracle_gold_groups"] >= 30
            ),
            "test_size_passes": (
                split_counts.get("test", 0)
                + split_counts.get("external_test", 0)
                >= 15
            ),
        },
        "assignments": assignments,
        "excluded": excluded,
    }


def _source_map(policy: Mapping[str, Any]) -> dict[str, str]:
    if policy.get("policy_kind") != "source_isolated_oracle_split":
        raise ValueError("wrong Oracle split policy kind")
    assignments = policy.get("source_assignments")
    if not isinstance(assignments, Mapping):
        raise ValueError("split policy lacks source assignments")
    output: dict[str, str] = {}
    for split, sources in assignments.items():
        if split not in {
            "development",
            "validation",
            "test",
            "external_test",
        }:
            raise ValueError(f"unsupported Oracle split: {split}")
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"Oracle split has no sources: {split}")
        for source in sources:
            source = str(source)
            if source in output:
                raise ValueError(
                    f"Oracle source assigned twice: {source}"
                )
            output[source] = str(split)
    return output


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {value}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _binding(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
