#!/usr/bin/env python3
"""Run the leakage-separated provider-oracle protocol-v5 pilot."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.experiments.run_provider_oracle_protocol_v3 import run  # noqa: E402


DEFAULT_CONFIG = ROOT / "configs" / "provider_oracle_protocol_v5.json"
DEFAULT_OUTPUT = ROOT / "output" / "provider_oracle_protocol_v5_results.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = run(args.config.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "protocol_version": report["protocol_version"],
        "runs": len(report["rows"]),
        "independence_groups": report["independence_groups"],
        "provider_oracle_gold_cases": report[
            "provider_oracle_gold_cases"
        ],
        "epistemic_control_cases": report[
            "epistemic_control_cases"
        ],
        "research_effectiveness_result": False,
        "output": str(args.output),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
