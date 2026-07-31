#!/usr/bin/env python3
"""Audit pinned replay supply without executing upstream code."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.replay_safety import (  # noqa: E402
    build_replay_safety_audit,
)


DEFAULT_MANIFEST = (
    ROOT / "data" / "real_sources" / "acquisition_manifest.json"
)
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "cross_cloud_replay_safety_audit_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--acquisition-manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    audit = build_replay_safety_audit(
        ROOT,
        acquisition_manifest_path=args.acquisition_manifest,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(audit["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
