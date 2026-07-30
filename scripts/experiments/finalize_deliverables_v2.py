"""Create the final hash-bound deliverables manifest, fail closed."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.final_deliverables_v2 import (  # noqa: E402
    build_final_deliverables_manifest,
    write_once_json,
)


DEFAULT_DECISION = (
    ROOT / "output" / "ec_react_main_v2" / "confirmatory_decision.json"
)
DEFAULT_REVIEWS = (
    ROOT / "output" / "research_design"
    / "review_stress_tests_v2_manifest.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "final_deliverables_v2_manifest.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision", type=Path, default=DEFAULT_DECISION)
    parser.add_argument("--thesis-pdf", type=Path, required=True)
    parser.add_argument("--defense-deck", type=Path, required=True)
    parser.add_argument("--reproduction-bundle", type=Path, required=True)
    parser.add_argument("--review-stress-tests", type=Path, default=DEFAULT_REVIEWS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        manifest = build_final_deliverables_manifest(
            ROOT,
            decision_path=args.decision,
            thesis_pdf=args.thesis_pdf,
            defense_deck=args.defense_deck,
            reproduction_bundle=args.reproduction_bundle,
            review_stress_tests=args.review_stress_tests,
            git_commit=_git_head(),
        )
        write_once_json(args.output, manifest)
    except (ValueError, RuntimeError) as error:
        print(json.dumps({
            "ready": False,
            "reason": str(error),
            "manifest_written": False,
        }, ensure_ascii=False))
        return 2
    print(json.dumps({
        "ready": True,
        "status": "complete",
        "manifest": _portable(args.output),
        "artifact_count": len(manifest["artifacts"]),
    }, ensure_ascii=False))
    return 0


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "cannot resolve git HEAD")
    return completed.stdout.strip()


def _portable(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


if __name__ == "__main__":
    sys.exit(main())
