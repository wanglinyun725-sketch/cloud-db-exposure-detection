"""CLI for blind human screening of external incident negative controls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.negative_control_workflow import (  # noqa: E402
    compare_negative_assignments,
    create_negative_adjudication_assignment,
    create_negative_assignment,
    finalize_negative_assignments,
    validate_negative_assignment,
)
from src.annotation.task_bundle import (  # noqa: E402
    build_case_bundle,
    merge_case_bundle,
    negative_assignment_progress,
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: dict) -> None:
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

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--primary", type=Path, required=True)
    finalize.add_argument("--reviewer", type=Path, required=True)
    finalize.add_argument("--adjudicator", type=Path)
    finalize.add_argument("--output", type=Path, required=True)

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
        result = create_negative_assignment(
            _load(args.packet),
            args.role,
            args.annotator_id,
        )
        _write(args.output, result)
        summary = {
            "assignment_id": result["assignment_id"],
            "cases": len(result["cases"]),
            "labels_copied": 0,
        }
    elif args.command == "validate-submission":
        result = _load(args.submission)
        validate_negative_assignment(result)
        summary = {"valid": True, "cases": len(result["cases"])}
    elif args.command == "agreement":
        result = compare_negative_assignments(
            _load(args.primary),
            _load(args.reviewer),
        )
        _write(args.output, result)
        summary = {
            "cases": result["cases"],
            "exact_agreement_rate": result["exact_agreement_rate"],
            "needs_adjudication": len(
                result["cases_needing_adjudication"]
            ),
        }
    elif args.command == "create-adjudication-assignment":
        result = create_negative_adjudication_assignment(
            _load(args.primary),
            _load(args.reviewer),
            args.annotator_id,
        )
        _write(args.output, result)
        summary = {
            "assignment_id": result["assignment_id"],
            "disputed_cases": len(result["cases"]),
        }
    elif args.command == "split-assignment":
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
        summary = {
            "assignment_id": manifest["assignment_id"],
            "cases": manifest["case_count"],
            "output_dir": str(args.output_dir),
        }
    elif args.command == "merge-assignment":
        manifest = _load(args.manifest)
        documents = {
            entry["file"]: _load(args.input_dir / entry["file"])
            for entry in manifest["entries"]
        }
        result = merge_case_bundle(manifest, documents)
        _write(args.output, result)
        summary = {
            "assignment_id": result["assignment_id"],
            "cases": len(result["cases"]),
            "output": str(args.output),
        }
    elif args.command == "progress":
        result = negative_assignment_progress(_load(args.assignment))
        if args.output:
            _write(args.output, result)
        summary = {
            "assignment_id": result["assignment_id"],
            "counts": result["counts"],
            "ready_for_agreement": result["ready_for_agreement"],
            "output": str(args.output) if args.output else None,
        }
    else:
        result = finalize_negative_assignments(
            _load(args.primary),
            _load(args.reviewer),
            _load(args.adjudicator) if args.adjudicator else None,
        )
        _write(args.output, result)
        summary = result["summary"]
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
