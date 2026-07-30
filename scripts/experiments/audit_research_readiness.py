"""Deprecated compatibility entry point for the objective Goal v2 audit.

The former script emitted a subjective weighted score and checked obsolete
sample targets. Keeping those outputs would create two conflicting definitions
of completion, so this entry point now delegates to the evidence-only audit.
"""
from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.experiments.audit_goal_acceptance_v2 import main  # noqa: E402,F401
from src.experiments.goal_acceptance_v2 import (  # noqa: E402
    build_goal_acceptance,
)


def build_audit(root: str | Path = ROOT):
    """Compatibility alias returning the objective Goal v2 audit."""
    return build_goal_acceptance(root)


if __name__ == "__main__":
    print(
        "DEPRECATED: audit_research_readiness.py now runs "
        "audit_goal_acceptance_v2.py",
        file=sys.stderr,
    )
    sys.exit(main())
