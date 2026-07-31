#!/usr/bin/env python3
"""Build the frozen confirmatory reserve-supply audit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.reserve_adequacy import (  # noqa: E402
    build_reserve_adequacy_audit,
)


DEFAULT_PRIMARY = (
    ROOT / "data" / "real_sources" / "annotation"
    / "runtime_confirmatory_30_unlabeled.json"
)
DEFAULT_STRUCTURAL_AUDIT = (
    ROOT / "output" / "research_design"
    / "splunk_reserve_source_audit_v1.json"
)
DEFAULT_RESERVE = (
    ROOT / "data" / "real_sources"
    / "splunk_kms_s3_reserve_candidate_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "confirmatory_reserve_adequacy_v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary-packet", type=Path, default=DEFAULT_PRIMARY)
    parser.add_argument(
        "--structural-audit",
        type=Path,
        default=DEFAULT_STRUCTURAL_AUDIT,
    )
    parser.add_argument(
        "--reserve-candidate",
        type=Path,
        action="append",
        default=None,
    )
    parser.add_argument("--target-groups", type=int, default=30)
    parser.add_argument("--minimum-reserve-groups", type=int, default=5)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    reserves = args.reserve_candidate or [DEFAULT_RESERVE]
    audit = build_reserve_adequacy_audit(
        ROOT,
        primary_packet_path=args.primary_packet,
        structural_audit_path=args.structural_audit,
        reserve_candidate_paths=reserves,
        target_gold_groups=args.target_groups,
        minimum_reserve_groups=args.minimum_reserve_groups,
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
