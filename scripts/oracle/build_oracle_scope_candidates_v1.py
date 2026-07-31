#!/usr/bin/env python3
"""Build label-free scope candidates from the frozen Oracle registry."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.scope_candidates import (  # noqa: E402
    build_scope_candidate_inventory,
)


DEFAULT_REGISTRY = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_scope_candidates_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = build_scope_candidate_inventory(
        ROOT,
        registry_path=args.registry,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(inventory["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
