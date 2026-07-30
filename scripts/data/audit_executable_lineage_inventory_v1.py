#!/usr/bin/env python3
"""Audit the combined runtime/configuration candidate lineage inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.executable_lineage_inventory import (  # noqa: E402
    build_executable_lineage_inventory,
)


DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "executable_lineage_inventory_v1.json"
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build_executable_lineage_inventory(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "summary": payload["summary"],
        "minimum_candidate_gate": payload["minimum_candidate_gate"],
        "human_gold_gate": payload["human_gold_gate"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
