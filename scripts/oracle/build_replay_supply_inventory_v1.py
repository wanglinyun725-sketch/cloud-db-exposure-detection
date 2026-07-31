#!/usr/bin/env python3
"""Build the fail-closed replay-supply inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.replay_supply import (  # noqa: E402
    build_replay_supply_inventory,
)


EXECUTION = ROOT / "data" / "real_sources" / "oracle" / "execution"
DEFAULT_OUTPUT = EXECUTION / "oracle_replay_supply_inventory_v1.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    inventory = build_replay_supply_inventory(
        ROOT,
        acquisition_manifest_path=(
            ROOT / "data" / "real_sources" / "acquisition_manifest.json"
        ),
        oracle_registry_path=(
            ROOT / "data" / "real_sources" / "oracle"
            / "executable_oracle_registry_v1.json"
        ),
        probe_contracts_path=(
            EXECUTION / "oracle_probe_contracts_v1.json"
        ),
        replay_safety_audit_path=(
            EXECUTION / "cross_cloud_replay_safety_audit_v1.json"
        ),
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
