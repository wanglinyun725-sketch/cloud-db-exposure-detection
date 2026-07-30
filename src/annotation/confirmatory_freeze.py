"""Fail-closed finalization for the 30-lineage confirmatory packet."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from src.annotation.confirmatory_progress import (
    audit_confirmatory_progress,
)
from src.annotation.task_bundle import (
    assignment_progress,
    merge_case_bundle,
)
from src.annotation.workflow import (
    compare_assignments,
    finalize_assignments,
)
from src.experiments.frozen_splits import build_frozen_split_manifest


def load_assignment_bundle(directory: str | Path) -> dict[str, Any]:
    """Load and hash-check one per-case task directory."""
    directory = Path(directory)
    manifest_path = directory / "assignment_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(
            f"assignment manifest is missing: {manifest_path}"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    documents = {}
    for entry in manifest.get("entries") or []:
        filename = entry.get("file")
        if not isinstance(filename, str) or not filename:
            raise ValueError("assignment manifest has an invalid task file")
        path = directory / filename
        if not path.is_file():
            raise ValueError(f"assignment task is missing: {path}")
        documents[filename] = json.loads(
            path.read_text(encoding="utf-8")
        )
    return merge_case_bundle(manifest, documents)


def evaluate_confirmatory_freeze(
    packet: dict[str, Any],
    primary: dict[str, Any],
    reviewer: dict[str, Any],
    *,
    adjudicator: dict[str, Any] | None = None,
    split_seed: int = 20260730,
    external_source_ids: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    """Return a freeze report and only emit gold when every human gate passes."""
    progress = audit_confirmatory_progress(packet, primary, reviewer)
    report: dict[str, Any] = {
        "freeze_gate_version": "1.0",
        "packet_sha256": progress["packet_sha256"],
        "statistical_unit": "independence_group",
        "stage": "awaiting_double_blind",
        "ready_to_publish": False,
        "human_gold_independence_groups": 0,
        "progress_summary": progress["summary"],
        "agreement": None,
        "adjudication": {
            "required_cases": [],
            "provided": adjudicator is not None,
            "valid_complete": False,
        },
        "release_sha256": None,
        "split_manifest_sha256": None,
    }
    if not progress["ready_for_agreement"]:
        return report, None, None

    agreement = compare_assignments(primary, reviewer)
    disputed = list(agreement["cases_needing_adjudication"])
    report["agreement"] = agreement
    report["adjudication"]["required_cases"] = disputed
    if disputed:
        report["stage"] = "awaiting_adjudication"
        if adjudicator is None:
            return report, None, None
        adjudicator_progress = assignment_progress(adjudicator)
        report["adjudication"]["progress"] = adjudicator_progress["counts"]
        if not adjudicator_progress["ready_for_agreement"]:
            return report, None, None
        try:
            release = finalize_assignments(
                primary,
                reviewer,
                adjudicator,
            )
        except (TypeError, ValueError) as exc:
            report["adjudication"]["validation_error"] = str(exc)
            return report, None, None
        report["adjudication"]["valid_complete"] = True
    else:
        if adjudicator is not None:
            raise ValueError(
                "adjudicator assignment was supplied but no case is disputed"
            )
        release = finalize_assignments(primary, reviewer)
        report["adjudication"]["valid_complete"] = True

    split_manifest = build_frozen_split_manifest(
        release,
        seed=split_seed,
        external_source_ids=set(external_source_ids or set()),
    )
    case_to_group = {
        case["case_id"]: case["candidate_metadata"]["independence_group"]
        for case in packet["cases"]
    }
    release_case_ids = {case["case_id"] for case in release["cases"]}
    finalized_groups = {
        case_to_group[case_id] for case_id in release_case_ids
    }
    if len(finalized_groups) != 30:
        raise ValueError(
            "final release does not cover all 30 confirmatory lineages"
        )
    decisions = Counter(
        case["admission_screen"]["decision"] for case in release["cases"]
    )
    report.update({
        "stage": "frozen",
        "ready_to_publish": True,
        "human_gold_independence_groups": len(finalized_groups),
        "finalized_cases": len(release_case_ids),
        "decisions": dict(sorted(decisions.items())),
        "release_sha256": _stable_hash(release),
        "split_manifest_sha256": _stable_hash(split_manifest),
        "split_summary": split_manifest["summary"],
    })
    return report, release, split_manifest


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
