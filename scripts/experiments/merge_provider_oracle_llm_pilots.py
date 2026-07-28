#!/usr/bin/env python3
"""Merge compatible resumable LLM pilot shards without re-scoring gold."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.experiments.run_provider_oracle_protocol_v3 import (  # noqa: E402
    summarize,
)


COMPATIBILITY_FIELDS = (
    "experiment_id",
    "protocol_version",
    "config_sha256",
    "implementation_bundle_sha256",
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _file_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256(path.read_bytes()).hexdigest(),
    }


def merge(input_dirs: list[Path], output_path: Path) -> dict[str, Any]:
    if len(input_dirs) < 2:
        raise ValueError("at least two pilot shard directories are required")
    manifests = [_load(path / "run_manifest.json") for path in input_dirs]
    reference = manifests[0]
    for manifest in manifests[1:]:
        for field in COMPATIBILITY_FIELDS:
            if manifest.get(field) != reference.get(field):
                raise ValueError(f"incompatible manifest field: {field}")
        if manifest.get("model") != reference.get("model"):
            raise ValueError("incompatible model manifests")

    rows = []
    seen_schedule_ids: set[str] = set()
    artifacts = []
    for directory in input_dirs:
        result_path = directory / "results.json"
        run_path = directory / "runs.jsonl"
        manifest_path = directory / "run_manifest.json"
        result = _load(result_path)
        for row in result["rows"]:
            schedule_id = row["schedule_id"]
            if schedule_id in seen_schedule_ids:
                raise ValueError(f"duplicate schedule_id: {schedule_id}")
            seen_schedule_ids.add(schedule_id)
            rows.append(row)
        artifacts.append({
            "directory": str(directory.relative_to(ROOT)),
            "results": _file_record(result_path),
            "runs": _file_record(run_path),
            "manifest": _file_record(manifest_path),
        })

    latency_summary = []
    for method_id in sorted({row["method_id"] for row in rows}):
        selected = [row for row in rows if row["method_id"] == method_id]
        latencies = [float(row["latency_seconds"]) for row in selected]
        latency_summary.append({
            "method_id": method_id,
            "runs": len(selected),
            "mean_seconds": statistics.fmean(latencies),
            "sample_sd_seconds": (
                statistics.stdev(latencies) if len(latencies) > 1 else None
            ),
            "min_seconds": min(latencies),
            "max_seconds": max(latencies),
            "semantically_correct_runs": sum(
                bool(row["score"]["semantically_correct_state"])
                for row in selected
            ),
            "invalid_actions": sum(
                int(row["score"]["invalid_actions"]) for row in selected
            ),
        })

    report = {
        "merge_version": "1.0.0",
        "experiment_id": reference["experiment_id"],
        "protocol_version": reference["protocol_version"],
        "research_effectiveness_result": False,
        "warning": (
            "Merged behavior-pilot shards; independence-group aggregation "
            "is valid only because compatibility hashes were identical."
        ),
        "config_sha256": reference["config_sha256"],
        "implementation_bundle_sha256": reference[
            "implementation_bundle_sha256"
        ],
        "model": reference["model"],
        "source_artifacts": artifacts,
        "completed_runs": len(rows),
        "case_count": len({row["case_id"] for row in rows}),
        "independence_groups": len({
            row["independence_group"] for row in rows
        }),
        "summary": summarize(rows),
        "latency_summary": latency_summary,
        "rows": sorted(
            rows,
            key=lambda row: (
                row["case_id"],
                row["method_id"],
                row["repeat"],
            ),
        ),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = merge(
        [path.resolve() for path in args.input_dir],
        args.output.resolve(),
    )
    print(json.dumps({
        "output": str(args.output.resolve()),
        "completed_runs": report["completed_runs"],
        "case_count": report["case_count"],
        "independence_groups": report["independence_groups"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
