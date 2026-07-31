#!/usr/bin/env python3
"""Build the non-executing Oracle evidence collection queue."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.execution_queue import build_execution_queue  # noqa: E402


DEFAULT_REGISTRY = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)
DEFAULT_POLICY = ROOT / "configs" / "oracle_execution_policy_v1.yaml"
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_execution_queue_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    queue = build_execution_queue(
        ROOT,
        registry_path=args.registry,
        policy_path=args.policy,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(queue, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(queue["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
