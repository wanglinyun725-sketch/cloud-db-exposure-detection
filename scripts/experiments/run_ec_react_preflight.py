"""Run the non-mutating EC-ReAct main-experiment preflight."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.ec_react_preflight import run_preflight  # noqa: E402


DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"
DEFAULT_OUTPUT = ROOT / "output" / "ec_react_main_preflight.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--method", action="append")
    parser.add_argument("--model", action="append")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Validate frozen planning inputs without requiring API keys.",
    )
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Return a non-zero status when any prerequisite is missing.",
    )
    args = parser.parse_args()
    output_path = args.output.resolve()

    report = run_preflight(
        ROOT,
        args.config,
        selected_method_ids=(
            set(args.method) if args.method else None
        ),
        selected_model_ids=(
            set(args.model) if args.model else None
        ),
        require_model_credentials=not args.plan_only,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        display_output = str(output_path.relative_to(ROOT))
    except ValueError:
        display_output = str(output_path)
    print(
        json.dumps(
            {
                "ready": report["ready"],
                "blockers": len(report["blockers"]),
                "finalized_cases": (
                    report["release_summary"]["finalized_cases"]
                ),
                "source_candidate_cases": (
                    report["source_candidate_cases"]
                ),
                "source_independence_groups": (
                    report["source_independence_groups"]
                ),
                "planned_runs_if_ready": (
                    report["planned_runs_if_ready"]
                ),
                "secrets_in_report": False,
                "output": display_output,
            },
            ensure_ascii=False,
        )
    )
    if args.require_ready and not report["ready"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
