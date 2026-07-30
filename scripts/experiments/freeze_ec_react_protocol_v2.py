"""Freeze the v2 protocol only after data, code and planning gates pass."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.ec_react_preflight import run_preflight  # noqa: E402
from src.experiments.protocol_freeze_v2 import (  # noqa: E402
    build_freeze_manifest,
    build_frozen_protocol,
    collect_frozen_inputs,
    serialize_frozen_protocol,
)


DEFAULT_DRAFT = ROOT / "configs" / "ec_react_main_v2_draft.yaml"
DEFAULT_FROZEN = ROOT / "configs" / "ec_react_main_v2_frozen.yaml"
DEFAULT_MANIFEST = (
    ROOT / "output" / "research_design"
    / "ec_react_main_v2_freeze_manifest.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--draft", type=Path, default=DEFAULT_DRAFT)
    parser.add_argument("--output", type=Path, default=DEFAULT_FROZEN)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    draft_path = args.draft.resolve()
    output_path = args.output.resolve()
    manifest_path = args.manifest.resolve()

    preflight = run_preflight(
        ROOT,
        draft_path,
        require_model_credentials=False,
    )
    if not preflight["ready"]:
        print(json.dumps({
            "ready": False,
            "reason": "plan-only preflight is blocked",
            "blockers": preflight["blockers"],
            "frozen_config_written": False,
        }, ensure_ascii=False))
        return 2
    dirty = _relevant_dirty_paths(draft_path, preflight)
    if dirty:
        print(json.dumps({
            "ready": False,
            "reason": "research code or frozen inputs are not committed",
            "dirty_paths": dirty,
            "frozen_config_written": False,
        }, ensure_ascii=False))
        return 2

    draft_bytes = draft_path.read_bytes()
    draft = yaml.safe_load(draft_bytes.decode("utf-8"))
    git_commit = _git(["rev-parse", "HEAD"]).strip()
    frozen_inputs = collect_frozen_inputs(ROOT, draft)
    frozen = build_frozen_protocol(
        draft,
        frozen_inputs=frozen_inputs,
        git_commit=git_commit,
        draft_sha256=sha256(draft_bytes).hexdigest(),
        manifest_path=_portable(manifest_path),
    )
    frozen_bytes = serialize_frozen_protocol(frozen)
    manifest = build_freeze_manifest(
        draft_path=_portable(draft_path),
        frozen_path=_portable(output_path),
        frozen_config_bytes=frozen_bytes,
        frozen_config=frozen,
    )
    _write_once(output_path, frozen_bytes)
    _write_once(
        manifest_path,
        (
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8"),
    )
    frozen_preflight = run_preflight(
        ROOT,
        output_path,
        require_model_credentials=False,
    )
    if not frozen_preflight["ready"]:
        raise RuntimeError(
            "internal error: emitted frozen config fails plan preflight: "
            + "; ".join(frozen_preflight["blockers"])
        )
    print(json.dumps({
        "ready": True,
        "freeze_status": "FROZEN",
        "frozen_config": _portable(output_path),
        "frozen_config_sha256": manifest["frozen_config"]["sha256"],
        "manifest": _portable(manifest_path),
        "git_commit": git_commit,
    }, ensure_ascii=False))
    return 0


def _relevant_dirty_paths(
    draft_path: Path,
    preflight: dict[str, Any],
) -> list[str]:
    paths = [
        "src",
        "scripts",
        "configs",
        _portable(draft_path),
        _portable(Path(preflight["data"]["source_packet"])),
        _portable(Path(preflight["data"]["gold_release"])),
        _portable(Path(preflight["data"]["split_manifest"])),
        _portable(Path(preflight["data"]["negative_source_packet"])),
        _portable(Path(preflight["data"]["negative_gold_release"])),
    ]
    output = _git(["status", "--porcelain", "--", *paths])
    return [
        line[3:] if len(line) > 3 else line
        for line in output.splitlines()
        if line.strip()
    ]


def _git(arguments: list[str]) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "git command failed: " + (completed.stderr.strip() or "unknown")
        )
    return completed.stdout


def _write_once(path: Path, payload: bytes) -> None:
    if path.is_file():
        if path.read_bytes() == payload:
            return
        raise RuntimeError(
            f"refusing to overwrite different frozen artifact: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _portable(path: Path) -> str:
    path = path.resolve()
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    sys.exit(main())
