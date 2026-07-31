"""Merge, audit and fail-closed freeze the confirmatory human gold."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.confirmatory_freeze import (  # noqa: E402
    evaluate_confirmatory_freeze,
    load_assignment_bundle,
)
from src.annotation.task_bundle import build_case_bundle  # noqa: E402
from src.annotation.workflow import (  # noqa: E402
    create_adjudication_assignment,
)


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
DEFAULT_REPORT = (
    ROOT / "output" / "research_design"
    / "confirmatory_freeze_readiness_v1.json"
)
DEFAULT_RELEASE = (
    ROOT / "data" / "real_sources" / "annotation" / "reviewed"
    / "runtime_confirmatory_30_reviewed.json"
)
DEFAULT_SPLIT = (
    ROOT / "data" / "real_sources" / "annotation" / "reviewed"
    / "runtime_confirmatory_30_splits.json"
)
DEFAULT_ADJUDICATOR_TASKS = (
    ROOT / "data" / "real_sources" / "annotation" / "work"
    / "confirmatory_v1_adjudicator_tasks"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument(
        "--primary-task-dir", type=Path, default=DEFAULT_PRIMARY
    )
    parser.add_argument(
        "--reviewer-task-dir", type=Path, default=DEFAULT_REVIEWER
    )
    parser.add_argument("--adjudicator-task-dir", type=Path)
    parser.add_argument(
        "--adjudicator-id",
        help=(
            "Prepare a blind third-human task bundle when disputes exist; "
            "must differ from both annotators."
        ),
    )
    parser.add_argument(
        "--adjudicator-output-dir",
        type=Path,
        default=DEFAULT_ADJUDICATOR_TASKS,
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
    parser.add_argument("--split", type=Path, default=DEFAULT_SPLIT)
    parser.add_argument("--split-seed", type=int, default=20260730)
    parser.add_argument("--external-source", action="append", default=[])
    args = parser.parse_args()

    packet = _read_json(args.packet)
    primary = load_assignment_bundle(args.primary_task_dir)
    reviewer = load_assignment_bundle(args.reviewer_task_dir)
    adjudicator = (
        load_assignment_bundle(args.adjudicator_task_dir)
        if args.adjudicator_task_dir
        else None
    )
    report, release, split_manifest = evaluate_confirmatory_freeze(
        packet,
        primary,
        reviewer,
        adjudicator=adjudicator,
        split_seed=args.split_seed,
        external_source_ids=set(args.external_source),
    )
    _write_json(args.report, report, allow_update=True)
    if release is None or split_manifest is None:
        adjudicator_tasks = None
        if (
            report["stage"] == "awaiting_adjudication"
            and adjudicator is None
            and args.adjudicator_id
        ):
            assignment = create_adjudication_assignment(
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
            "human_gold_independence_groups": 0,
            "report": _display_path(args.report),
            "gold_written": False,
            "adjudicator_tasks": adjudicator_tasks,
        }, ensure_ascii=False))
        return 2

    _write_json(args.release, release, allow_update=False)
    _write_json(args.split, split_manifest, allow_update=False)
    print(json.dumps({
        "ready": True,
        "stage": report["stage"],
        "human_gold_independence_groups": (
            report["human_gold_independence_groups"]
        ),
        "release": _display_path(args.release),
        "split": _display_path(args.split),
        "report": _display_path(args.report),
    }, ensure_ascii=False))
    return 0


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.resolve().read_text(encoding="utf-8"))


def _write_json(
    path: Path,
    value: dict[str, Any],
    *,
    allow_update: bool,
) -> None:
    path = path.resolve()
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    )
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


def _write_assignment_bundle(
    directory: Path,
    assignment: dict[str, Any],
) -> None:
    manifest, documents = build_case_bundle(assignment)
    directory = directory.resolve()
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


if __name__ == "__main__":
    sys.exit(main())
