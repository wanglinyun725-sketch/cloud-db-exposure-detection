#!/usr/bin/env python3
"""Audit local confirmatory task bundles without generating labels."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.confirmatory_progress import (  # noqa: E402
    audit_confirmatory_progress,
)
from src.annotation.task_bundle import merge_case_bundle  # noqa: E402


DEFAULT_PACKET = (
    ROOT / "data" / "real_sources" / "annotation"
    / "runtime_confirmatory_30_unlabeled.json"
)
DEFAULT_PRIMARY = (
    ROOT / "data" / "real_sources" / "annotation" / "work"
    / "confirmatory_v1_primary_tasks"
)
DEFAULT_REVIEWER = (
    ROOT / "data" / "real_sources" / "annotation" / "work"
    / "confirmatory_v1_reviewer_tasks"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "confirmatory_annotation_progress_v1.json"
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_bundle(directory: Path) -> dict:
    manifest = _read(directory / "assignment_manifest.json")
    documents = {
        entry["file"]: _read(directory / entry["file"])
        for entry in manifest["entries"]
    }
    return merge_case_bundle(manifest, documents)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument(
        "--primary-task-dir", type=Path, default=DEFAULT_PRIMARY
    )
    parser.add_argument(
        "--reviewer-task-dir", type=Path, default=DEFAULT_REVIEWER
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = audit_confirmatory_progress(
        _read(args.packet),
        _load_bundle(args.primary_task_dir),
        _load_bundle(args.reviewer_task_dir),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "summary": report["summary"],
        "human_gold_gate": report["human_gold_gate"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
