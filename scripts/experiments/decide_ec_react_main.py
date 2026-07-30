"""Apply the preregistered claim gates to a frozen main analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.confirmatory_decision import (  # noqa: E402
    evaluate_confirmatory_decision,
)
from src.experiments.artifact_chain_v2 import (  # noqa: E402
    build_decision_binding,
)


DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v2_draft.yaml"
DEFAULT_ANALYSIS = ROOT / "output" / "ec_react_main_v2" / "analysis.json"
DEFAULT_OUTPUT = (
    ROOT / "output" / "ec_react_main_v2"
    / "confirmatory_decision.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--analysis", type=Path, default=DEFAULT_ANALYSIS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if not args.analysis.resolve().is_file():
        print(json.dumps({
            "ready": False,
            "reason": "frozen main analysis is missing",
            "analysis": str(args.analysis),
        }, ensure_ascii=False))
        return 2
    config_path = args.config.resolve()
    analysis_path = args.analysis.resolve()
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    decision = evaluate_confirmatory_decision(analysis, config)
    decision["artifact_binding"] = build_decision_binding(
        ROOT,
        config_path=config_path,
        analysis_path=analysis_path,
        analysis=analysis,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(decision, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "ready": True,
        "overall_status": decision["overall_status"],
        "claim_allowed": decision["claim_allowed"],
        "output": str(output),
    }, ensure_ascii=False))
    return 0 if decision["claim_allowed"] else 3


if __name__ == "__main__":
    sys.exit(main())
