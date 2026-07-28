"""Build the frozen group-safe split manifest after human gold finalization."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.frozen_splits import (  # noqa: E402
    build_frozen_split_manifest,
)


DEFAULT_RELEASE = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "reviewed"
    / "expanded_full_pool_reviewed.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "reviewed"
    / "expanded_full_pool_splits.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=20260727)
    parser.add_argument(
        "--external-source",
        action="append",
        default=[],
        help="Predeclare a complete source as external_test; repeatable.",
    )
    args = parser.parse_args()
    release_path = args.release.resolve()
    if not release_path.is_file():
        print(json.dumps(
            {
                "ready": False,
                "reason": (
                    "reviewed human-gold release is missing; no split was made"
                ),
                "release": str(release_path),
            },
            ensure_ascii=False,
        ))
        return 2
    release = json.loads(release_path.read_text(encoding="utf-8"))
    manifest = build_frozen_split_manifest(
        release,
        seed=args.seed,
        external_source_ids=set(args.external_source),
    )
    output_path = args.output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(
        {
            "ready": True,
            **manifest["summary"],
            "output": str(output_path),
        },
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
