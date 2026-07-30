"""Fail-closed orchestration from human freeze to claim decision."""
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
PYTHON = Path(sys.executable)
DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v2_draft.yaml"
DEFAULT_FROZEN_CONFIG = ROOT / "configs" / "ec_react_main_v2_frozen.yaml"
DEFAULT_OUTPUT_DIR = ROOT / "output" / "ec_react_main_v2"
DEFAULT_STATUS = (
    ROOT / "output" / "research_design"
    / "research_pipeline_v2_status.json"
)
DEFAULT_FREEZE_MANIFEST = (
    ROOT / "output" / "research_design"
    / "ec_react_main_v2_freeze_manifest.json"
)
DEFAULT_REPRODUCTION_BUNDLE = (
    ROOT / "output" / "final"
    / "cloud_db_pathbench_reproduction_v2.zip"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("status", "plan", "execute"),
        default="status",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--frozen-config",
        type=Path,
        default=DEFAULT_FROZEN_CONFIG,
        help=(
            "Immutable execution config emitted after human releases are "
            "committed and the draft protocol passes preflight."
        ),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR
    )
    parser.add_argument("--status-output", type=Path, default=DEFAULT_STATUS)
    parser.add_argument(
        "--freeze-manifest",
        type=Path,
        default=DEFAULT_FREEZE_MANIFEST,
    )
    parser.add_argument(
        "--reproduction-output",
        type=Path,
        default=DEFAULT_REPRODUCTION_BUNDLE,
    )
    parser.add_argument("--method", action="append")
    parser.add_argument("--model", action="append")
    args = parser.parse_args()

    config_path = args.config.resolve()
    frozen_config_path = args.frozen_config.resolve()
    output_dir = args.output_dir.resolve()
    status: dict[str, Any] = {
        "pipeline_version": "1.1",
        "mode": args.mode,
        "config": _portable(config_path),
        "frozen_config": _portable(frozen_config_path),
        "output_dir": _portable(output_dir),
        "model_calls_authorized": args.mode == "execute",
        "stages": [],
        "ready": False,
        "final_status": "blocked",
    }
    confirmatory = _run([
        PYTHON,
        ROOT / "scripts" / "annotation"
        / "freeze_confirmatory_v1.py",
    ])
    status["stages"].append({
        "stage": "freeze_confirmatory_gold",
        **confirmatory,
    })
    negative = _run([
        PYTHON,
        ROOT / "scripts" / "annotation"
        / "freeze_negative_controls_v1.py",
    ])
    status["stages"].append({
        "stage": "freeze_negative_controls",
        **negative,
    })

    preflight_output = output_dir / "pipeline_preflight.json"
    preflight_command: list[str | Path] = [
        PYTHON,
        ROOT / "scripts" / "experiments"
        / "run_ec_react_preflight.py",
        "--config",
        config_path,
        "--output",
        preflight_output,
        "--require-ready",
    ]
    if args.mode == "plan":
        preflight_command.append("--plan-only")
    preflight_command.extend(_selection_arguments(args))
    preflight = _run(preflight_command)
    status["stages"].append({
        "stage": "main_preflight",
        **preflight,
    })
    prerequisites_ready = all(
        item["returncode"] == 0
        for item in status["stages"]
    )
    if not prerequisites_ready:
        status["final_status"] = "blocked"
        status["ready"] = False
        _write_status(args.status_output, status)
        return 2

    if args.mode == "status":
        execution_config = _existing_frozen_config(
            config_path,
            frozen_config_path,
        )
        if execution_config is None:
            status["final_status"] = "ready_to_freeze_protocol"
            status["ready"] = False
            _write_status(args.status_output, status)
            return 2
        binding = _validate_frozen_stage(
            execution_config,
            args.freeze_manifest.resolve(),
        )
        status["stages"].append({
            "stage": "frozen_protocol_binding",
            **binding,
        })
        status["ready"] = binding["returncode"] == 0
        status["final_status"] = (
            "ready_for_execution" if status["ready"] else "blocked"
        )
        _write_status(args.status_output, status)
        return 0 if status["ready"] else 2

    run_config_path = config_path

    if args.mode == "execute":
        source_config = yaml.safe_load(
            config_path.read_text(encoding="utf-8")
        )
        if source_config.get("freeze_status") != "FROZEN":
            freeze = _run([
                PYTHON,
                ROOT / "scripts" / "experiments"
                / "freeze_ec_react_protocol_v2.py",
                "--draft",
                config_path,
                "--output",
                frozen_config_path,
                "--manifest",
                args.freeze_manifest.resolve(),
            ])
            status["stages"].append({
                "stage": "freeze_hash_bound_protocol",
                **freeze,
            })
            if freeze["returncode"] != 0:
                status["final_status"] = "protocol_freeze_failed"
                _write_status(args.status_output, status)
                return 2
            run_config_path = frozen_config_path
        binding = _validate_frozen_stage(
            run_config_path,
            args.freeze_manifest.resolve(),
        )
        status["stages"].append({
            "stage": "frozen_protocol_binding",
            **binding,
        })
        if binding["returncode"] != 0:
            status["final_status"] = "frozen_protocol_invalid"
            _write_status(args.status_output, status)
            return 2

        frozen_preflight_output = (
            output_dir / "pipeline_frozen_preflight.json"
        )
        frozen_preflight_command: list[str | Path] = [
            PYTHON,
            ROOT / "scripts" / "experiments"
            / "run_ec_react_preflight.py",
            "--config",
            run_config_path,
            "--output",
            frozen_preflight_output,
            "--require-ready",
        ]
        frozen_preflight_command.extend(_selection_arguments(args))
        frozen_preflight = _run(frozen_preflight_command)
        status["stages"].append({
            "stage": "frozen_main_preflight",
            **frozen_preflight,
        })
        if frozen_preflight["returncode"] != 0:
            status["final_status"] = "frozen_preflight_failed"
            _write_status(args.status_output, status)
            return 2

    run_command: list[str | Path] = [
        PYTHON,
        ROOT / "scripts" / "experiments" / "run_ec_react_main.py",
        "--config",
        run_config_path,
        "--output-dir",
        output_dir,
    ]
    if args.mode == "plan":
        run_command.append("--plan-only")
    run_command.extend(_selection_arguments(args))
    run = _run(run_command)
    status["stages"].append({
        "stage": "plan_schedule" if args.mode == "plan" else "execute_runs",
        **run,
    })
    if run["returncode"] != 0 or args.mode == "plan":
        status["ready"] = run["returncode"] == 0
        status["final_status"] = (
            "plan_validated" if status["ready"] else "blocked"
        )
        _write_status(args.status_output, status)
        return 0 if status["ready"] else 2

    analysis_path = output_dir / "analysis.json"
    analysis = _run([
        PYTHON,
        ROOT / "scripts" / "experiments"
        / "analyze_ec_react_main.py",
        "--config",
        run_config_path,
        "--runs",
        output_dir / "runs.jsonl",
        "--output",
        analysis_path,
    ])
    status["stages"].append({
        "stage": "analyze_frozen_runs",
        **analysis,
    })
    if analysis["returncode"] != 0:
        _write_status(args.status_output, status)
        return 2

    decision = _run([
        PYTHON,
        ROOT / "scripts" / "experiments"
        / "decide_ec_react_main.py",
        "--config",
        run_config_path,
        "--analysis",
        analysis_path,
        "--output",
        output_dir / "confirmatory_decision.json",
    ])
    status["stages"].append({
        "stage": "claim_decision",
        **decision,
    })
    if decision["returncode"] == 0:
        reproduction = _run([
            PYTHON,
            ROOT / "scripts" / "experiments"
            / "package_reproduction_v2.py",
            "--config",
            run_config_path,
            "--freeze-manifest",
            args.freeze_manifest.resolve(),
            "--experiment-dir",
            output_dir,
            "--output",
            args.reproduction_output.resolve(),
        ])
        status["stages"].append({
            "stage": "package_reproduction_bundle",
            **reproduction,
        })
        if reproduction["returncode"] != 0:
            status["ready"] = False
            status["final_status"] = "claim_passed_but_packaging_failed"
            _write_status(args.status_output, status)
            return 2
    status["ready"] = decision["returncode"] == 0
    status["final_status"] = (
        "claim_passed_and_packaged"
        if decision["returncode"] == 0
        else "claim_not_passed"
    )
    _write_status(args.status_output, status)
    return decision["returncode"]


def assert_frozen_for_execution(config: dict[str, Any]) -> None:
    """Prevent a draft protocol from generating confirmatory results."""
    if config.get("freeze_status") != "FROZEN":
        raise ValueError(
            "confirmatory execution requires freeze_status=FROZEN; "
            "draft configs may only be inspected or planned"
        )


def validate_frozen_execution_binding(
    config: dict[str, Any],
    config_path: str | Path,
    manifest_path: str | Path,
    *,
    bound_commit_is_ancestor: bool | None = None,
    committed_drift_paths: list[str] | None = None,
    relevant_dirty_paths: list[str] | None = None,
) -> None:
    """Reject a FROZEN label not bound to the exact manifest and bytes."""
    assert_frozen_for_execution(config)
    config_path = Path(config_path).resolve()
    manifest_path = Path(manifest_path).resolve()
    if not config_path.is_file():
        raise ValueError(f"frozen config is missing: {config_path}")
    if not manifest_path.is_file():
        raise ValueError(f"freeze manifest is missing: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("freeze manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("status") != "FROZEN":
        raise ValueError("freeze manifest status is not FROZEN")
    frozen_item = manifest.get("frozen_config")
    expected_config_sha = sha256(config_path.read_bytes()).hexdigest()
    if not isinstance(frozen_item, dict):
        raise ValueError("freeze manifest lacks frozen_config")
    declared_config = Path(str(frozen_item.get("path") or ""))
    declared_config = (
        declared_config
        if declared_config.is_absolute()
        else ROOT / declared_config
    )
    if declared_config.resolve() != config_path:
        raise ValueError("freeze manifest points to a different config")
    if frozen_item.get("sha256") != expected_config_sha:
        raise ValueError("frozen config SHA-256 differs from freeze manifest")
    binding = config.get("freeze_binding")
    if not isinstance(binding, dict):
        raise ValueError("frozen config lacks freeze_binding")
    if manifest.get("git_commit") != binding.get("git_commit"):
        raise ValueError("freeze manifest Git commit differs from config")
    bound_commit = str(binding.get("git_commit") or "")
    if bound_commit_is_ancestor is None or committed_drift_paths is None:
        observed_ancestor, observed_drift = _committed_research_drift(
            bound_commit,
            config_path,
        )
        if bound_commit_is_ancestor is None:
            bound_commit_is_ancestor = observed_ancestor
        if committed_drift_paths is None:
            committed_drift_paths = observed_drift
    if not bound_commit_is_ancestor:
        raise ValueError(
            "frozen protocol commit is not an ancestor of current HEAD"
        )
    if committed_drift_paths:
        raise ValueError(
            "committed research code/config drifted after protocol freeze: "
            + ", ".join(committed_drift_paths)
        )
    relevant_dirty_paths = (
        _relevant_execution_dirty_paths(config_path, manifest_path)
        if relevant_dirty_paths is None
        else relevant_dirty_paths
    )
    if relevant_dirty_paths:
        raise ValueError(
            "research code/config changed after protocol freeze: "
            + ", ".join(relevant_dirty_paths)
        )
    if manifest.get("inputs") != binding.get("inputs"):
        raise ValueError("freeze manifest inputs differ from config")
    declared_manifest = Path(str(binding.get("manifest_path") or ""))
    declared_manifest = (
        declared_manifest
        if declared_manifest.is_absolute()
        else ROOT / declared_manifest
    )
    if declared_manifest.resolve() != manifest_path:
        raise ValueError(
            "frozen config points to a different freeze manifest"
        )


def _committed_research_drift(
    bound_commit: str,
    config_path: Path,
) -> tuple[bool, list[str]]:
    if (
        len(bound_commit) != 40
        or any(
            character not in "0123456789abcdef"
            for character in bound_commit
        )
    ):
        raise ValueError("frozen protocol has an invalid Git commit")
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", bound_commit, "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise ValueError("cannot compare current HEAD with frozen commit")
    if completed.returncode == 1:
        return False, []
    diff = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            f"{bound_commit}..HEAD",
            "--",
            "src",
            "scripts",
            "configs",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if diff.returncode != 0:
        raise ValueError("cannot audit committed research-code drift")
    allowed = {_portable(config_path).replace("\\", "/")}
    dirty = [
        path.strip().replace("\\", "/")
        for path in diff.stdout.splitlines()
        if path.strip().replace("\\", "/") not in allowed
    ]
    return True, sorted(set(dirty))


def _relevant_execution_dirty_paths(
    config_path: Path,
    manifest_path: Path,
) -> list[str]:
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--", "src", "scripts", "configs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("cannot audit research-code working-tree state")
    allowed = {
        _portable(config_path).replace("\\", "/"),
        _portable(manifest_path).replace("\\", "/"),
    }
    dirty = []
    for line in completed.stdout.splitlines():
        path = line[3:] if len(line) > 3 else line
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        normalized = path.strip('"').replace("\\", "/")
        if normalized and normalized not in allowed:
            dirty.append(normalized)
    return sorted(set(dirty))


def _existing_frozen_config(
    configured_path: Path,
    default_frozen_path: Path,
) -> Path | None:
    configured = yaml.safe_load(configured_path.read_text(encoding="utf-8"))
    if (
        isinstance(configured, dict)
        and configured.get("freeze_status") == "FROZEN"
    ):
        return configured_path
    if not default_frozen_path.is_file():
        return None
    candidate = yaml.safe_load(
        default_frozen_path.read_text(encoding="utf-8")
    )
    return (
        default_frozen_path
        if (
            isinstance(candidate, dict)
            and candidate.get("freeze_status") == "FROZEN"
        )
        else None
    )


def _validate_frozen_stage(
    config_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("frozen config root must be an object")
        validate_frozen_execution_binding(
            config,
            config_path,
            manifest_path,
        )
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        return {
            "returncode": 2,
            "command": None,
            "result": {
                "ready": False,
                "reason": str(exc),
                "config": _portable(config_path),
                "manifest": _portable(manifest_path),
            },
            "stderr": None,
        }
    return {
        "returncode": 0,
        "command": None,
        "result": {
            "ready": True,
            "config": _portable(config_path),
            "config_sha256": sha256(config_path.read_bytes()).hexdigest(),
            "manifest": _portable(manifest_path),
        },
        "stderr": None,
    }


def _selection_arguments(args: argparse.Namespace) -> list[str]:
    output = []
    for value in args.method or []:
        output.extend(["--method", value])
    for value in args.model or []:
        output.extend(["--model", value])
    return output


def _run(command: list[str | Path]) -> dict[str, Any]:
    normalized = [str(item) for item in command]
    completed = subprocess.run(
        normalized,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return {
        "returncode": completed.returncode,
        "command": [_portable(item) for item in normalized],
        "result": _last_json(completed.stdout),
        "stderr": completed.stderr.strip() or None,
    }


def _last_json(value: str) -> Any:
    for line in reversed(value.splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"stdout": value.strip() or None}


def _write_status(path: Path, status: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "ready": status["ready"],
        "final_status": status["final_status"],
        "mode": status["mode"],
        "status": _portable(path),
    }, ensure_ascii=False))


def _portable(value: str | Path) -> str:
    text = str(value)
    path = Path(text)
    if not path.is_absolute():
        return text
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return text


if __name__ == "__main__":
    sys.exit(main())
