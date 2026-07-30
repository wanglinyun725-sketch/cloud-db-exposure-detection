"""Package the exact frozen code, data and results into a deterministic ZIP."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.reproduction_bundle_v2 import (  # noqa: E402
    build_reproduction_bundle_bytes,
    read_git_archive,
    write_once_bundle,
)


DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v2_frozen.yaml"
DEFAULT_FREEZE_MANIFEST = (
    ROOT / "output" / "research_design"
    / "ec_react_main_v2_freeze_manifest.json"
)
DEFAULT_EXPERIMENT_DIR = ROOT / "output" / "ec_react_main_v2"
DEFAULT_OUTPUT = (
    ROOT / "output" / "final"
    / "cloud_db_pathbench_reproduction_v2.zip"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--freeze-manifest", type=Path, default=DEFAULT_FREEZE_MANIFEST
    )
    parser.add_argument(
        "--experiment-dir", type=Path, default=DEFAULT_EXPERIMENT_DIR
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        freeze_manifest = json.loads(
            args.freeze_manifest.resolve().read_text(encoding="utf-8")
        )
        commit = freeze_manifest["git_commit"]
        code_files = read_git_archive(_git_archive(commit))
        payload, manifest = build_reproduction_bundle_bytes(
            ROOT,
            frozen_config_path=args.config,
            freeze_manifest_path=args.freeze_manifest,
            experiment_dir=args.experiment_dir,
            code_files=code_files,
        )
        write_once_bundle(args.output, payload)
    except (
        FileNotFoundError,
        KeyError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as error:
        print(json.dumps({
            "ready": False,
            "reason": str(error),
            "bundle_written": False,
        }, ensure_ascii=False))
        return 2
    print(json.dumps({
        "ready": True,
        "bundle": _portable(args.output),
        "sha256": __import__("hashlib").sha256(payload).hexdigest(),
        "files": len(manifest["files"]) + 1,
        "frozen_git_commit": manifest["frozen_git_commit"],
    }, ensure_ascii=False))
    return 0


def _git_archive(commit: str) -> bytes:
    completed = subprocess.run(
        ["git", "archive", "--format=zip", commit],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.decode("utf-8", errors="replace").strip()
            or "git archive failed"
        )
    return completed.stdout


def _portable(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


if __name__ == "__main__":
    sys.exit(main())
