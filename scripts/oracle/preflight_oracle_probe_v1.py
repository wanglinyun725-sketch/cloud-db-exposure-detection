#!/usr/bin/env python3
"""Resolve and audit one probe contract without executing cloud commands."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.runtime_preflight import (  # noqa: E402
    preflight_probe_contract,
)


DEFAULT_CONTRACTS = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_probe_contracts_v1.json"
)
DEFAULT_POLICY = ROOT / "configs" / "oracle_execution_policy_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--runtime-context", type=Path, required=True)
    parser.add_argument("--authorization-context", type=Path, required=True)
    parser.add_argument("--contracts", type=Path, default=DEFAULT_CONTRACTS)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    registry = _read_object(args.contracts)
    matches = [
        item
        for item in registry.get("contracts") or []
        if item.get("contract_id") == args.contract_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one contract {args.contract_id!r}, got {len(matches)}"
        )
    policy = yaml.safe_load(args.policy.read_text(encoding="utf-8"))
    if not isinstance(policy, dict):
        raise ValueError("execution policy must be an object")
    runtime = _read_object(args.runtime_context)
    authorization = _read_object(args.authorization_context)
    result = preflight_probe_contract(
        matches[0],
        runtime_values=runtime,
        authorization=authorization,
        policy=policy,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            result.audit_report,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "contract_id": args.contract_id,
        "ready_for_execution": result.audit_report[
            "ready_for_execution"
        ],
        "resolved_step_count": result.audit_report[
            "resolved_step_count"
        ],
        "blocker_count": len(result.audit_report["blockers"]),
        "commands_executed": 0,
    }, ensure_ascii=False))
    return 0 if result.audit_report["ready_for_execution"] else 2


def _read_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
