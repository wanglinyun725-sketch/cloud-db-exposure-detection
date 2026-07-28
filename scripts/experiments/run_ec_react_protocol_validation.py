"""Validate EC-ReAct orchestration over a real three-cloud telemetry subset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.ec_react_protocol_validation import (  # noqa: E402
    run_protocol_validation,
)


DEFAULT_INDEX = (
    ROOT / "data" / "real_sources" / "cross_cloud_full_episode_index.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "ec_react_protocol_validation.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--budget", type=int, default=30)
    parser.add_argument(
        "--limit",
        type=int,
        help="Engineering debug only; omit for the complete validation set.",
    )
    args = parser.parse_args()
    output_path = args.output.resolve()

    result = run_protocol_validation(
        ROOT,
        args.index,
        budget=args.budget,
        limit=args.limit,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        display_output = str(output_path.relative_to(ROOT))
    except ValueError:
        display_output = str(output_path)
    print(
        json.dumps(
            {
                "protocol_valid": result["protocol_valid"],
                "episodes": result["episodes"],
                "platform_attack_groups": (
                    result["platform_attack_groups"]
                ),
                "independence_groups": result["independence_groups"],
                "backend_mismatches": (
                    result["backend_mismatch_count"]
                ),
                "policy_leakage_failures": (
                    result["policy_leakage_failure_count"]
                ),
                "research_effectiveness_result": False,
                "output": display_output,
            },
            ensure_ascii=False,
        )
    )
    return 0 if result["protocol_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
