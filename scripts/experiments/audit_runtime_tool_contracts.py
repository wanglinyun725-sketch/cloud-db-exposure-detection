"""Audit the common Tool-Use contract on every unlabeled runtime instance."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.runtime_tool_contract_audit import (  # noqa: E402
    run_runtime_tool_contract_audit,
)


DEFAULT_PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)
DEFAULT_OUTPUT = ROOT / "output" / "runtime_tool_contract_audit.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--budget", type=int, default=30)
    parser.add_argument(
        "--limit",
        type=int,
        help="Engineering debug only; omit to audit every runtime instance.",
    )
    args = parser.parse_args()
    output_path = args.output.resolve()
    result = run_runtime_tool_contract_audit(
        ROOT,
        args.packet,
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
    print(json.dumps({
        "audit_valid": result["audit_valid"],
        "runtime_instances": result["runtime_instances"],
        "runtime_cases": result["runtime_cases"],
        "runtime_evidence_sources": result["runtime_evidence_sources"],
        "platforms": result["platforms"],
        "tool_contract_failures": result[
            "tool_contract_failure_count"
        ],
        "backend_mismatches": result["backend_mismatch_count"],
        "policy_leakage_failures": result[
            "policy_leakage_failure_count"
        ],
        "research_effectiveness_result": False,
        "output": display_output,
    }, ensure_ascii=False))
    return 0 if result["audit_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
