"""Write the objective Graduate Goal v2 acceptance matrix."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.goal_acceptance_v2 import (  # noqa: E402
    build_goal_acceptance,
    render_goal_acceptance_markdown,
)


DEFAULT_JSON = (
    ROOT / "output" / "research_design"
    / "goal_acceptance_v2.json"
)
DEFAULT_MD = (
    ROOT / "output" / "research_design"
    / "goal_acceptance_v2.md"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MD)
    args = parser.parse_args()
    report = build_goal_acceptance(ROOT)
    json_path = args.json.resolve()
    markdown_path = args.markdown.resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_goal_acceptance_markdown(report),
        encoding="utf-8",
    )
    print(json.dumps({
        "objective_complete": report["objective_complete"],
        "passed_gates": report["passed_gates"],
        "total_gates": report["total_gates"],
        "blockers": len(report["blockers"]),
        "json": _portable(json_path),
        "markdown": _portable(markdown_path),
    }, ensure_ascii=False))
    return 0 if report["objective_complete"] else 2


def _portable(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    sys.exit(main())
