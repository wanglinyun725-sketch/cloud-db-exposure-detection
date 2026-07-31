#!/usr/bin/env python3
"""Validate an executable Oracle registry without executing cloud actions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.protocol import validate_oracle_registry  # noqa: E402


DEFAULT_REGISTRY = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "executable_oracle_gold_status_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Return 2 unless both preregistered Oracle gates pass.",
    )
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    report = validate_oracle_registry(ROOT, registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False))
    if args.require_ready and not report["completion_gate"]["passes"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
