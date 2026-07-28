"""CLI for blind assignments, validation, agreement and finalization."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.workflow import (  # noqa: E402
    compare_assignments,
    create_adjudication_assignment,
    create_assignment,
    finalize_assignments,
    finalize_pair,
    validate_submission,
)
from src.annotation.task_bundle import (  # noqa: E402
    assignment_progress,
    build_case_bundle,
    merge_case_bundle,
)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create-assignment")
    create.add_argument("--packet", type=Path, required=True)
    create.add_argument("--role", choices=("primary", "reviewer"), required=True)
    create.add_argument("--annotator-id", required=True)
    create.add_argument("--output", type=Path, required=True)

    validate = commands.add_parser("validate-submission")
    validate.add_argument("--submission", type=Path, required=True)

    agreement = commands.add_parser("agreement")
    agreement.add_argument("--primary", type=Path, required=True)
    agreement.add_argument("--reviewer", type=Path, required=True)
    agreement.add_argument("--output", type=Path, required=True)

    adjudicate = commands.add_parser("create-adjudication-assignment")
    adjudicate.add_argument("--primary", type=Path, required=True)
    adjudicate.add_argument("--reviewer", type=Path, required=True)
    adjudicate.add_argument("--annotator-id", required=True)
    adjudicate.add_argument("--output", type=Path, required=True)

    finalize = commands.add_parser("finalize-pair")
    finalize.add_argument("--primary", type=Path, required=True)
    finalize.add_argument("--reviewer", type=Path, required=True)
    finalize.add_argument("--adjudicator", type=Path)
    finalize.add_argument("--output", type=Path, required=True)

    finalize_all = commands.add_parser("finalize-assignments")
    finalize_all.add_argument("--primary", type=Path, required=True)
    finalize_all.add_argument("--reviewer", type=Path, required=True)
    finalize_all.add_argument("--adjudicator", type=Path)
    finalize_all.add_argument("--output", type=Path, required=True)

    split = commands.add_parser("split-assignment")
    split.add_argument("--assignment", type=Path, required=True)
    split.add_argument("--output-dir", type=Path, required=True)

    merge = commands.add_parser("merge-assignment")
    merge.add_argument("--manifest", type=Path, required=True)
    merge.add_argument("--input-dir", type=Path, required=True)
    merge.add_argument("--output", type=Path, required=True)

    progress = commands.add_parser("progress")
    progress.add_argument("--assignment", type=Path, required=True)
    progress.add_argument("--output", type=Path)

    args = parser.parse_args()
    if args.command == "create-assignment":
        assignment = create_assignment(
            _load(args.packet),
            args.role,
            args.annotator_id,
        )
        _write(args.output, assignment)
        print(
            json.dumps(
                {
                    "assignment_id": assignment["assignment_id"],
                    "cases": len(assignment["cases"]),
                    "labels_copied": 0,
                },
                ensure_ascii=False,
            )
        )
        return 0
    if args.command == "split-assignment":
        manifest, documents = build_case_bundle(_load(args.assignment))
        args.output_dir.mkdir(parents=True, exist_ok=True)
        occupied = [
            path
            for path in (
                args.output_dir / "assignment_manifest.json",
                *(args.output_dir / name for name in documents),
            )
            if path.exists()
        ]
        if occupied:
            raise ValueError(
                "refusing to overwrite existing task files: "
                + ", ".join(str(path) for path in occupied)
            )
        _write(args.output_dir / "assignment_manifest.json", manifest)
        for filename, case in documents.items():
            _write(args.output_dir / filename, case)
        print(json.dumps({
            "assignment_id": manifest["assignment_id"],
            "cases": manifest["case_count"],
            "output_dir": str(args.output_dir),
        }, ensure_ascii=False))
        return 0
    if args.command == "merge-assignment":
        manifest = _load(args.manifest)
        documents = {
            entry["file"]: _load(args.input_dir / entry["file"])
            for entry in manifest["entries"]
        }
        merged = merge_case_bundle(manifest, documents)
        _write(args.output, merged)
        print(json.dumps({
            "assignment_id": merged["assignment_id"],
            "cases": len(merged["cases"]),
            "output": str(args.output),
        }, ensure_ascii=False))
        return 0
    if args.command == "progress":
        report = assignment_progress(_load(args.assignment))
        if args.output:
            _write(args.output, report)
        print(json.dumps({
            "assignment_id": report["assignment_id"],
            "counts": report["counts"],
            "ready_for_agreement": report["ready_for_agreement"],
            "output": str(args.output) if args.output else None,
        }, ensure_ascii=False))
        return 0
    if args.command == "validate-submission":
        value = _load(args.submission)
        if "cases" in value:
            for case in value["cases"]:
                validate_submission(case)
            count = len(value["cases"])
        else:
            validate_submission(value)
            count = 1
        print(json.dumps({"valid": True, "cases": count}))
        return 0
    if args.command == "agreement":
        report = compare_assignments(
            _load(args.primary),
            _load(args.reviewer),
        )
        _write(args.output, report)
        print(
            json.dumps(
                {
                    "cases": report["independent_cases"],
                    "cohen_kappa": report["admission_cohen_kappa"],
                    "needs_adjudication": len(
                        report["cases_needing_adjudication"]
                    ),
                },
                ensure_ascii=False,
            )
        )
        return 0
    if args.command == "create-adjudication-assignment":
        assignment = create_adjudication_assignment(
            _load(args.primary),
            _load(args.reviewer),
            args.annotator_id,
        )
        _write(args.output, assignment)
        print(
            json.dumps(
                {
                    "assignment_id": assignment["assignment_id"],
                    "disputed_cases": len(assignment["cases"]),
                },
                ensure_ascii=False,
            )
        )
        return 0
    if args.command == "finalize-pair":
        result = finalize_pair(
            _load(args.primary),
            _load(args.reviewer),
            _load(args.adjudicator) if args.adjudicator else None,
        )
    else:
        result = finalize_assignments(
            _load(args.primary),
            _load(args.reviewer),
            _load(args.adjudicator) if args.adjudicator else None,
        )
    _write(args.output, result)
    if args.command == "finalize-pair":
        summary = {
            "case_id": result["case_id"],
            "status": result["annotation"]["status"],
        }
    else:
        summary = {
            "cases": len(result["cases"]),
            "adjudicated": result["adjudication"]["completed"],
        }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
