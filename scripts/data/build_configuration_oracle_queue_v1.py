#!/usr/bin/env python3
"""Build the label-empty deterministic configuration oracle queue."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.configuration_oracle_queue import (  # noqa: E402
    build_configuration_oracle_queue,
)


DEFAULT_OUTPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "configuration_oracle_queue_v1_unlabeled.json"
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build_configuration_oracle_queue(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "summary": payload["summary"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
