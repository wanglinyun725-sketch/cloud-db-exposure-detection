"""Export, seal and import offline blind human annotation handoffs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.annotation.offline_handoff import (  # noqa: E402
    build_outbound_handoff,
    seal_completed_handoff,
    verify_returned_handoff,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export")
    export.add_argument("--task-dir", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--receipt", type=Path, required=True)
    export.add_argument("--git-commit", default=None)

    seal = commands.add_parser("seal")
    seal.add_argument("--workspace", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)

    import_command = commands.add_parser("import")
    import_command.add_argument("--submission", type=Path, required=True)
    import_command.add_argument("--receipt", type=Path, required=True)
    import_command.add_argument("--expected-sha256", required=True)
    import_command.add_argument("--output-dir", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "export":
            archive, receipt = build_outbound_handoff(
                args.task_dir,
                git_commit=args.git_commit or _git_head(),
            )
            _write_once(args.output, archive)
            _write_once(args.receipt, _json_bytes(receipt))
            result = {
                "ready": True,
                "stage": "outbound_blind_handoff",
                "archive": str(args.output.resolve()),
                "receipt": str(args.receipt.resolve()),
                "outbound_sha256": receipt["outbound_archive_sha256"],
                "case_count": receipt.get("case_count"),
            }
        elif args.command == "seal":
            archive, summary = seal_completed_handoff(
                args.workspace,
                observed_git_commit=_git_head(),
            )
            _write_once(args.output, archive)
            result = {
                "ready": True,
                "stage": "sealed_human_submission",
                "archive": str(args.output.resolve()),
                **summary,
            }
        else:
            receipt = json.loads(
                args.receipt.read_text(encoding="utf-8")
            )
            manifest, documents = verify_returned_handoff(
                args.submission.read_bytes(),
                receipt,
                expected_submission_sha256=args.expected_sha256,
            )
            _write_task_directory(
                args.output_dir,
                manifest,
                documents,
            )
            result = {
                "ready": True,
                "stage": "verified_human_submission_import",
                "output_dir": str(args.output_dir.resolve()),
                "assignment_id": manifest.get("assignment_id"),
                "case_count": manifest.get("case_count"),
            }
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({
            "ready": False,
            "reason": str(exc),
        }, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _write_task_directory(
    output_dir: Path,
    manifest: dict,
    documents: dict[str, bytes],
) -> None:
    output_dir = output_dir.resolve()
    targets = [
        output_dir / "assignment_manifest.json",
        *(output_dir / name for name in documents),
    ]
    if any(path.exists() for path in targets):
        raise RuntimeError(
            "refusing to overwrite imported task files"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_once(
        output_dir / "assignment_manifest.json",
        _json_bytes(manifest),
    )
    for name, payload in documents.items():
        _write_once(output_dir / name, payload)


def _write_once(path: Path, payload: bytes) -> None:
    path = path.resolve()
    if path.exists():
        if path.is_file() and path.read_bytes() == payload:
            return
        raise RuntimeError(f"refusing to overwrite different file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip() or "cannot resolve Git HEAD"
        )
    return completed.stdout.strip()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
