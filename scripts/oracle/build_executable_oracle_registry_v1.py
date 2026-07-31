#!/usr/bin/env python3
"""Build the deterministic, fail-closed executable Oracle registry."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.protocol import build_candidate_registry  # noqa: E402


DEFAULT_RUNTIME = (
    ROOT / "data" / "real_sources" / "annotation"
    / "runtime_confirmatory_30_unlabeled.json"
)
DEFAULT_CONFIGURATION = (
    ROOT / "data" / "real_sources" / "annotation"
    / "configuration_supplemental_10_unlabeled.json"
)
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-packet", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument(
        "--configuration-packet",
        type=Path,
        default=DEFAULT_CONFIGURATION,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    registry = build_candidate_registry(
        ROOT,
        runtime_packet_path=args.runtime_packet,
        configuration_packet_path=args.configuration_packet,
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
