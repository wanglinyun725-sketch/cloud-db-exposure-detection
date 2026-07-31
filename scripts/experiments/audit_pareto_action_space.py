"""Audit cross-tool Pareto candidate coverage on real telemetry episodes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.pareto_action_space_audit import (  # noqa: E402
    audit_pareto_action_space,
)


DEFAULT_INDEX = (
    ROOT / "data" / "real_sources" / "cross_cloud_full_episode_index.json"
)
DEFAULT_OUTPUT = ROOT / "output" / "pareto_action_space_audit.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--limit",
        type=int,
        help="Engineering debug only; omit for all protocol episodes.",
    )
    args = parser.parse_args()
    result = audit_pareto_action_space(
        ROOT,
        args.index,
        limit=args.limit,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        display_output = str(output.relative_to(ROOT))
    except ValueError:
        display_output = str(output)
    print(json.dumps(
        {
            "episodes": result["episodes"],
            "probe_failures": len(result["probe_failures"]),
            "empty_telemetry_episodes": result[
                "empty_telemetry_episodes"
            ],
            "after_detail": result["stages"]["after_detail"],
            "research_effectiveness_result": False,
            "output": display_output,
        },
        ensure_ascii=False,
    ))
    return 0 if not result["probe_failures"] else 1


if __name__ == "__main__":
    sys.exit(main())
