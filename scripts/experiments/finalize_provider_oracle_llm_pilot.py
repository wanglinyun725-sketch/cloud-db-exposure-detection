#!/usr/bin/env python3
"""Finalize a resumable LLM pilot from its frozen manifest and JSONL."""
from __future__ import annotations

import argparse
from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.experiments.run_provider_oracle_protocol_v3 import summarize


SEMANTIC_FIELDS = (
    "predicted_state",
    "gold_state",
    "state_correct",
    "semantically_correct_state",
    "correct_rejection",
    "correct_abstention",
    "false_reachable",
)


def finalize(output_dir: Path) -> dict[str, Any]:
    manifest = json.loads(
        (output_dir / "run_manifest.json").read_text(encoding="utf-8")
    )
    scheduled = {
        item["schedule_id"]: item for item in manifest["schedule"]
    }
    rows = [
        json.loads(line)
        for line in (output_dir / "runs.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    out_of_manifest = 0
    for row in rows:
        schedule_id = row.get("schedule_id")
        if schedule_id not in scheduled:
            out_of_manifest += 1
            continue
        buckets[schedule_id].append(row)

    duplicate_conflicts = []
    selected = []
    for schedule_id in manifest["schedule"]:
        rows_for_schedule = buckets.get(schedule_id["schedule_id"], [])
        if not rows_for_schedule:
            continue
        reference = rows_for_schedule[0]
        reference_semantics = {
            field: reference["score"].get(field)
            for field in SEMANTIC_FIELDS
        }
        for duplicate in rows_for_schedule[1:]:
            duplicate_semantics = {
                field: duplicate["score"].get(field)
                for field in SEMANTIC_FIELDS
            }
            if duplicate_semantics != reference_semantics:
                duplicate_conflicts.append({
                    "schedule_id": schedule_id["schedule_id"],
                    "first": reference_semantics,
                    "duplicate": duplicate_semantics,
                })
        selected.append(reference)

    completed_ids = {item["schedule_id"] for item in selected}
    missing = [
        item for item in manifest["schedule"]
        if item["schedule_id"] not in completed_ids
    ]
    finalized = {
        "finalizer_version": "1.0.0",
        "experiment_id": manifest["experiment_id"],
        "protocol_version": manifest["protocol_version"],
        "research_effectiveness_result": False,
        "manifest_config_sha256": manifest["config_sha256"],
        "manifest_implementation_bundle_sha256": manifest[
            "implementation_bundle_sha256"
        ],
        "model": manifest["model"],
        "scheduled_runs": len(manifest["schedule"]),
        "raw_jsonl_records": len(rows),
        "unique_completed_runs": len(selected),
        "duplicate_records_ignored": sum(
            max(0, len(items) - 1) for items in buckets.values()
        ),
        "duplicate_semantic_conflicts": duplicate_conflicts,
        "out_of_manifest_records": out_of_manifest,
        "missing_schedule": missing,
        "schedule_complete": (
            len(selected) == len(manifest["schedule"])
            and not missing
            and not duplicate_conflicts
        ),
        "independence_groups": len({
            item["independence_group"] for item in selected
        }),
        "summary": summarize(selected),
        "rows": selected,
        "warning": (
            "Repeated seeds diagnose execution stability only. Events, "
            "cases, or duplicate JSONL records are not independent samples."
        ),
    }
    return finalized


def finalize_recovered_grid(
    output_dir: Path,
    config_path: Path,
    case_ids: set[str],
) -> dict[str, Any]:
    """Recover a full schedule when an old runner overwrote its manifest."""
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes.decode("utf-8"))
    config_sha256 = sha256(config_bytes).hexdigest()
    execution = config["execution"]
    repeats = (
        range(int(execution["repeat_count"]))
        if "repeat_count" in execution
        else [int(execution["repeat"])]
    )
    expected = {
        (
            case_id,
            method["method_id"],
            int(repeat),
            int(execution["seed"]) + int(repeat),
            method.get(
                "orchestration_backend",
                execution.get("orchestration_backend", "linear"),
            ),
        )
        for case_id in case_ids
        for method in config["methods"]
        for repeat in repeats
    }
    raw_rows = [
        json.loads(line)
        for line in (output_dir / "runs.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    eligible = [
        row for row in raw_rows
        if row.get("config_sha256") == config_sha256
        and (
            row["case_id"],
            row["method_id"],
            int(row["repeat"]),
            int(row["seed"]),
            row["orchestration_backend"],
        ) in expected
    ]
    buckets: dict[
        tuple[str, str, int, int, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for row in eligible:
        coordinate = (
            row["case_id"],
            row["method_id"],
            int(row["repeat"]),
            int(row["seed"]),
            row["orchestration_backend"],
        )
        buckets[coordinate].append(row)

    conflicts = []
    selected = []
    for coordinate in sorted(expected):
        rows_for_coordinate = buckets.get(coordinate, [])
        if not rows_for_coordinate:
            continue
        reference = rows_for_coordinate[0]
        reference_semantics = {
            field: reference["score"].get(field)
            for field in SEMANTIC_FIELDS
        }
        for duplicate in rows_for_coordinate[1:]:
            duplicate_semantics = {
                field: duplicate["score"].get(field)
                for field in SEMANTIC_FIELDS
            }
            if duplicate_semantics != reference_semantics:
                conflicts.append({
                    "coordinate": list(coordinate),
                    "first": reference_semantics,
                    "duplicate": duplicate_semantics,
                })
        selected.append(reference)

    completed = {
        (
            row["case_id"],
            row["method_id"],
            int(row["repeat"]),
            int(row["seed"]),
            row["orchestration_backend"],
        )
        for row in selected
    }
    missing = [
        list(coordinate) for coordinate in sorted(expected - completed)
    ]
    implementation_hashes = sorted({
        row["implementation_bundle_sha256"] for row in selected
    })
    model_digests = sorted({
        row["model_digest"] for row in selected
    })
    schedule_ids = [row["schedule_id"] for row in selected]
    result = {
        "finalizer_version": "1.1.0",
        "experiment_id": config["experiment_id"],
        "protocol_version": config["protocol_version"],
        "research_effectiveness_result": False,
        "schedule_recovery_mode": True,
        "schedule_recovery_reason": (
            "A pre-lock runner allowed a filtered resume to overwrite the "
            "full manifest. The Cartesian case/method/repeat/seed/backend "
            "grid is reconstructed from the unchanged config and validated "
            "against row-bound config and implementation hashes."
        ),
        "config_path": str(config_path.relative_to(ROOT)),
        "config_sha256": config_sha256,
        "implementation_bundle_sha256_values": implementation_hashes,
        "model_digest_values": model_digests,
        "expected_grid_runs": len(expected),
        "raw_jsonl_records": len(raw_rows),
        "eligible_jsonl_records": len(eligible),
        "unique_completed_runs": len(selected),
        "unique_schedule_ids": len(set(schedule_ids)),
        "duplicate_records_ignored": len(eligible) - len(selected),
        "duplicate_semantic_conflicts": conflicts,
        "out_of_grid_records": len(raw_rows) - len(eligible),
        "missing_grid_coordinates": missing,
        "schedule_complete": (
            len(selected) == len(expected)
            and len(set(schedule_ids)) == len(expected)
            and len(implementation_hashes) == 1
            and len(model_digests) == 1
            and not missing
            and not conflicts
        ),
        "independence_groups": len({
            row["independence_group"] for row in selected
        }),
        "summary": summarize(selected),
        "rows": selected,
        "warning": (
            "This is a recovered behavior-pilot schedule, not a thesis main "
            "effectiveness result. Repeated seeds are not samples."
        ),
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--output-name",
        default="results_finalized.json",
    )
    parser.add_argument("--config", type=Path)
    parser.add_argument("--case-id", action="append")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    if args.config:
        if not args.case_id:
            parser.error("--config recovery mode requires --case-id")
        result = finalize_recovered_grid(
            output_dir,
            args.config.resolve(),
            set(args.case_id),
        )
    else:
        result = finalize(output_dir)
    output_path = output_dir / args.output_name
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "scheduled_runs": result.get(
            "scheduled_runs", result.get("expected_grid_runs")
        ),
        "raw_jsonl_records": result["raw_jsonl_records"],
        "unique_completed_runs": result["unique_completed_runs"],
        "duplicate_records_ignored": result[
            "duplicate_records_ignored"
        ],
        "duplicate_semantic_conflicts": len(
            result["duplicate_semantic_conflicts"]
        ),
        "schedule_complete": result["schedule_complete"],
        "output": str(output_path),
    }, ensure_ascii=False))
    return 0 if result["schedule_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
