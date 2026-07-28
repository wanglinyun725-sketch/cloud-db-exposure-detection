"""Run the gold-free non-LLM main-experiment contract audit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.unlabeled_main_dry_run import (  # noqa: E402
    run_unlabeled_main_dry_run,
)


DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"
DEFAULT_PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)
DEFAULT_OUTPUT = ROOT / "output" / "unlabeled_main_dry_run.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    result = run_unlabeled_main_dry_run(
        ROOT,
        args.config,
        args.packet,
        limit=args.limit,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "dry_run_valid": result["dry_run_valid"],
        "runtime_instances": result["runtime_instances"],
        "scheduled_runs": result["scheduled_runs"],
        "completed_runs": result["completed_runs"],
        "backend_mismatches": result["backend_mismatch_count"],
        "budget_violations": result["hard_budget_violation_count"],
        "execution_failures": result["execution_failure_count"],
        "research_effectiveness_result": False,
        "output": str(output),
    }, ensure_ascii=False))
    return 0 if result["dry_run_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
