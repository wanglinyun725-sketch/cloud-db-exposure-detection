"""Build the deterministic thesis/defense publication claim ledger."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.publication_claims_v2 import (  # noqa: E402
    build_publication_claim_ledger,
)


DEFAULT_INVENTORY = (
    ROOT / "output" / "research_design"
    / "executable_lineage_inventory_v1.json"
)
DEFAULT_FREEZE = (
    ROOT / "output" / "research_design"
    / "confirmatory_freeze_readiness_v1.json"
)
DEFAULT_DECISION = (
    ROOT / "output" / "ec_react_main_v2"
    / "confirmatory_decision.json"
)
DEFAULT_CP_CERT = (
    ROOT / "output" / "ec_react_main_v2"
    / "cp_cert_experiment_results.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "ec_react_main_v2"
    / "publication_claims_v2.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument(
        "--confirmatory-freeze",
        type=Path,
        default=DEFAULT_FREEZE,
    )
    parser.add_argument("--decision", type=Path, default=DEFAULT_DECISION)
    parser.add_argument("--cp-cert-result", type=Path, default=DEFAULT_CP_CERT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        ledger = build_publication_claim_ledger(
            ROOT,
            inventory_path=args.inventory,
            confirmatory_freeze_path=args.confirmatory_freeze,
            decision_path=args.decision,
            cp_cert_result_path=args.cp_cert_result,
        )
        _write_once(args.output, ledger)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({
            "ready": False,
            "reason": str(exc),
            "ledger_written": False,
        }, ensure_ascii=False))
        return 2
    print(json.dumps({
        "ready": True,
        "ledger": str(args.output.resolve()),
        "thesis_claim_status": ledger["thesis_claim_status"],
        "mandatory_innovations_claim_allowed": ledger[
            "mandatory_innovations_claim_allowed"
        ],
        "cp_cert_innovation_claim_allowed": ledger[
            "cp_cert_innovation_claim_allowed"
        ],
    }, ensure_ascii=False))
    return 0


def _write_once(path: Path, value: dict) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    path = path.resolve()
    if path.is_file():
        if path.read_bytes() == payload:
            return
        raise ValueError(
            f"refusing to overwrite a different claim ledger: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


if __name__ == "__main__":
    raise SystemExit(main())
