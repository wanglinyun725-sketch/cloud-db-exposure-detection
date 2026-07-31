#!/usr/bin/env python3
"""Build the preregistered source-isolated Oracle split manifest."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.splits import build_oracle_split  # noqa: E402


DEFAULT_REGISTRY = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)
DEFAULT_POLICY = ROOT / "configs" / "oracle_split_policy_v1.json"
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "oracle" / "releases"
    / "executable_oracle_gold_v1_splits.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    manifest = build_oracle_split(
        ROOT,
        registry_path=args.registry,
        policy_path=args.policy,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": manifest["status"],
        **manifest["summary"],
    }, ensure_ascii=False))
    if args.require_ready and manifest["status"] != "ready":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
