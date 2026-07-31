"""Run the guarded ReAct protocol on one real published telemetry episode."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.cross_cloud_environment import CrossCloudTelemetryEnvironment
from src.agent.ec_react import ECReactRunner, ProgressiveTelemetryPolicy
from src.agent.ec_react_langgraph import ECReactLangGraphRunner


INDEX = ROOT / "data" / "real_sources" / "cross_cloud_pilot_episode_index.json"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episode-id")
    parser.add_argument("--budget", type=int, default=30)
    parser.add_argument(
        "--backend",
        choices=("langgraph", "linear"),
        default="langgraph",
    )
    args = parser.parse_args()

    index = json.loads(INDEX.read_text(encoding="utf-8"))
    episode_id = args.episode_id or next(
        item["episode_id"]
        for item in index["episodes"]
        if item["platform"] == "AWS"
        and item["attack"] == "automated_exfiltration"
        and item["log_profile"] == "additional"
        and item["run_id"] == 0
        and item["source_condition"] == "payload_present"
    )
    environment = CrossCloudTelemetryEnvironment.from_file(
        ROOT,
        INDEX,
        episode_id,
        budget=args.budget,
    )
    runner = (
        ECReactLangGraphRunner(ProgressiveTelemetryPolicy())
        if args.backend == "langgraph"
        else ECReactRunner(ProgressiveTelemetryPolicy())
    )
    result = runner.run(
        environment,
        environment.public_context,
    )
    payload = {
        "protocol": "EC-ReAct offline smoke",
        "orchestration_backend": args.backend,
        "policy_is_llm": False,
        "result": asdict(result),
        "hidden_evaluation_metadata": environment.evaluation_metadata(),
    }
    output_path = (
        ROOT
        / "output"
        / f"cross_cloud_react_smoke_{args.backend}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "decision": result.decision,
                "backend": args.backend,
                "tool_calls": result.valid_tool_calls,
                "spent": result.spent,
                "output": str(output_path.relative_to(ROOT)),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
