#!/usr/bin/env python3
"""Build the label-empty supplemental configuration packet."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.configuration_annotation_packet import (  # noqa: E402
    build_configuration_annotation_packet,
)


DEFAULT_QUEUE = (
    ROOT / "data" / "real_sources" / "annotation"
    / "configuration_oracle_queue_v1_unlabeled.json"
)
DEFAULT_REGISTRY = (
    ROOT / "data" / "real_sources" / "source_registry.yaml"
)
DEFAULT_SCHEMA = (
    ROOT / "data" / "real_sources" / "realpathbench_v2_schema.json"
)
DEFAULT_OUTPUT = (
    ROOT / "data" / "real_sources" / "annotation"
    / "configuration_supplemental_10_unlabeled.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    packet = build_configuration_annotation_packet(
        ROOT,
        queue_path=args.queue,
        registry_path=args.registry,
        schema_path=args.schema,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(packet["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
