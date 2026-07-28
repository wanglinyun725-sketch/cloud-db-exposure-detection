"""Evaluate a finalized human release against the frozen pilot gate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.pilot_gate import evaluate_pilot_gate  # noqa: E402


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument(
        "--pilot",
        type=Path,
        default=(
            ROOT
            / "data"
            / "real_sources"
            / "annotation"
            / "runtime_pilot_round2_unlabeled.json"
        ),
    )
    parser.add_argument(
        "--gate",
        type=Path,
        default=ROOT / "configs" / "human_annotation_pilot_gate_v2.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate_pilot_gate(
        _load(args.release),
        _load(args.pilot),
        _load(args.gate),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["summary"], ensure_ascii=False))
    return 0 if result["passes"] else 2


if __name__ == "__main__":
    sys.exit(main())
