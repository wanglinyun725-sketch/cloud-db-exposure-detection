#!/usr/bin/env python3
"""Build outcome-free, non-executing Oracle probe contracts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.probe_contracts import (  # noqa: E402
    build_probe_contract_registry,
)


DEFAULT_SCOPE = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_scope_candidates_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_probe_contracts_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope-inventory", type=Path, default=DEFAULT_SCOPE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    registry = build_probe_contract_registry(
        ROOT,
        scope_inventory_path=args.scope_inventory,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(registry["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
