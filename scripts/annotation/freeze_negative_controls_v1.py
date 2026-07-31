"""Merge, audit and fail-closed freeze external negative controls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.negative_control_freeze import (  # noqa: E402
    evaluate_negative_control_freeze,
)
from src.annotation.negative_control_workflow import (  # noqa: E402
    create_negative_adjudication_assignment,
)
from src.annotation.task_bundle import (  # noqa: E402
    build_case_bundle,
    load_case_bundle_directory,
)


WORK = ROOT / "data" / "real_sources" / "annotation" / "work"
DEFAULT_PRIMARY = WORK / "negative_primary_tasks"
DEFAULT_REVIEWER = WORK / "negative_reviewer_tasks"
DEFAULT_ADJUDICATOR = WORK / "negative_adjudicator_tasks"
DEFAULT_REPORT = (
    ROOT / "output" / "research_design"
    / "negative_control_freeze_readiness_v1.json"
)
DEFAULT_RELEASE = (
    ROOT / "data" / "real_sources" / "annotation" / "reviewed"
    / "negative_control_round1_reviewed.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--primary-task-dir", type=Path, default=DEFAULT_PRIMARY
    )
    parser.add_argument(
        "--reviewer-task-dir", type=Path, default=DEFAULT_REVIEWER
    )
    parser.add_argument("--adjudicator-task-dir", type=Path)
    parser.add_argument("--adjudicator-id")
    parser.add_argument(
        "--adjudicator-output-dir",
        type=Path,
        default=DEFAULT_ADJUDICATOR,
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
    parser.add_argument("--minimum-usable", type=int, default=20)
    args = parser.parse_args()
    if args.minimum_usable < 1:
        parser.error("--minimum-usable must be positive")

    primary = load_case_bundle_directory(args.primary_task_dir)
    reviewer = load_case_bundle_directory(args.reviewer_task_dir)
    adjudicator = (
        load_case_bundle_directory(args.adjudicator_task_dir)
        if args.adjudicator_task_dir
        else None
    )
    report, release = evaluate_negative_control_freeze(
        primary,
        reviewer,
        adjudicator=adjudicator,
        minimum_usable=args.minimum_usable,
    )
    _write_json(args.report, report, allow_update=True)
    if release is None:
        adjudicator_tasks = None
        if (
            report["stage"] == "awaiting_adjudication"
            and adjudicator is None
            and args.adjudicator_id
        ):
            assignment = create_negative_adjudication_assignment(
                primary,
                reviewer,
                args.adjudicator_id,
            )
            _write_assignment_bundle(
                args.adjudicator_output_dir,
                assignment,
            )
            adjudicator_tasks = _display_path(
                args.adjudicator_output_dir
            )
        print(json.dumps({
            "ready": False,
            "stage": report["stage"],
            "gold_written": False,
            "adjudicator_tasks": adjudicator_tasks,
            "report": _display_path(args.report),
        }, ensure_ascii=False))
        return 2

    _write_json(args.release, release, allow_update=False)
    print(json.dumps({
        "ready": True,
        "stage": report["stage"],
        "experiment_eligible": report["experiment_eligible"],
        "usable_negative_controls": report["usable_negative_controls"],
        "release": _display_path(args.release),
        "report": _display_path(args.report),
    }, ensure_ascii=False))
    return 0 if report["experiment_eligible"] else 3


def _write_assignment_bundle(
    directory: Path,
    assignment: dict[str, Any],
) -> None:
    manifest, documents = build_case_bundle(assignment)
    _write_json(
        directory / "assignment_manifest.json",
        manifest,
        allow_update=False,
    )
    for filename, document in documents.items():
        _write_json(
            directory / filename,
            document,
            allow_update=False,
        )


def _write_json(
    path: Path,
    value: dict[str, Any],
    *,
    allow_update: bool,
) -> None:
    path = path.resolve()
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path.is_file():
        existing = path.read_text(encoding="utf-8")
        if existing == payload:
            return
        if not allow_update:
            raise RuntimeError(
                f"refusing to overwrite a different frozen artifact: {path}"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


if __name__ == "__main__":
    sys.exit(main())
