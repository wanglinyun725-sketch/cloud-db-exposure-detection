#!/usr/bin/env python3
"""Apply completed evidence bundles without accepting hand-written labels."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.evidence_bundle import (  # noqa: E402
    apply_completed_evidence_bundles,
)


DEFAULT_REGISTRY = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)
DEFAULT_QUEUE = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_execution_queue_v1.json"
)
DEFAULT_POLICY = ROOT / "configs" / "oracle_execution_policy_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument(
        "--bundle",
        action="append",
        type=Path,
        required=True,
        help="Completed evaluator-only evidence bundle; repeat as needed.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New registry path; input is never overwritten implicitly.",
    )
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    bundles = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in args.bundle
    ]
    output = apply_completed_evidence_bundles(
        ROOT,
        registry,
        bundles,
        queue_path=args.queue,
        policy_path=args.policy,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
