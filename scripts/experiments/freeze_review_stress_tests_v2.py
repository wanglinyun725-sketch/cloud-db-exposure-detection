"""Freeze the three required review stress tests after all checks pass."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.final_deliverables_v2 import (  # noqa: E402
    build_review_stress_test_bundle,
    write_once_json,
)


DEFAULT_DECISION = (
    ROOT / "output" / "ec_react_main_v2" / "confirmatory_decision.json"
)
DEFAULT_CP_CERT_RESULT = (
    ROOT / "output" / "ec_react_main_v2"
    / "cp_cert_experiment_results.json"
)
DEFAULT_PUBLICATION_CLAIMS = (
    ROOT / "output" / "ec_react_main_v2"
    / "publication_claims_v2.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "review_stress_tests_v2_manifest.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision", type=Path, default=DEFAULT_DECISION)
    parser.add_argument(
        "--cp-cert-result",
        type=Path,
        default=DEFAULT_CP_CERT_RESULT,
    )
    parser.add_argument(
        "--publication-claims",
        type=Path,
        default=DEFAULT_PUBLICATION_CLAIMS,
    )
    parser.add_argument("--method-review", type=Path, required=True)
    parser.add_argument("--statistics-review", type=Path, required=True)
    parser.add_argument("--cloud-security-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        bundle = build_review_stress_test_bundle(
            ROOT,
            decision_path=args.decision,
            cp_cert_result_path=args.cp_cert_result,
            publication_claims_path=args.publication_claims,
            report_paths={
                "method": args.method_review,
                "statistics": args.statistics_review,
                "cloud_security": args.cloud_security_review,
            },
        )
        write_once_json(args.output, bundle)
    except (ValueError, RuntimeError) as error:
        print(json.dumps({
            "ready": False,
            "reason": str(error),
            "manifest_written": False,
        }, ensure_ascii=False))
        return 2
    print(json.dumps({
        "ready": True,
        "status": "complete",
        "manifest": _portable(args.output),
        "review_types": bundle["review_types"],
    }, ensure_ascii=False))
    return 0


def _portable(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


if __name__ == "__main__":
    sys.exit(main())
