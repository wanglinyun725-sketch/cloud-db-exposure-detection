"""Run the local-only human annotation UI."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.local_review_app import (  # noqa: E402
    create_local_review_app,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--task-dir",
        type=Path,
        required=True,
        help="One split primary/reviewer/adjudicator task directory.",
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    app = create_local_review_app(args.task_dir)
    print(
        "Local human-only annotation UI: "
        f"http://127.0.0.1:{args.port}/"
    )
    print("No LLM or external API is used. Press Ctrl+C to stop.")
    app.run(
        host="127.0.0.1",
        port=args.port,
        debug=False,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
