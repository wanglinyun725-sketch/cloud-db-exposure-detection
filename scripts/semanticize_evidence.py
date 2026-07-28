#!/usr/bin/env python3
"""Convert legacy CloudDB samples to C1 semantic evidence format."""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.graph.evidence_semantics import evidence_field_stats, semanticize_sample


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input dataset JSON")
    parser.add_argument("output", help="Output semanticized dataset JSON")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        samples = json.load(f)

    semanticized = [semanticize_sample(sample) for sample in samples]
    stats = evidence_field_stats(semanticized)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(semanticized, f, ensure_ascii=False, indent=2)

    stats_path = args.output.rsplit(".", 1)[0] + "_stats.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print(f"wrote {args.output}")
    print(f"wrote {stats_path}")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
