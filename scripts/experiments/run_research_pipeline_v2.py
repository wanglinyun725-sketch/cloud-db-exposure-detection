"""Fail-closed orchestration from human freeze to claim decision."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
PYTHON = Path(sys.executable)
DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v2_draft.yaml"
DEFAULT_OUTPUT_DIR = ROOT / "output" / "ec_react_main_v2"
DEFAULT_STATUS = (
    ROOT / "output" / "research_design"
    / "research_pipeline_v2_status.json"
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
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR
    )
    parser.add_argument("--status-output", type=Path, default=DEFAULT_STATUS)
    parser.add_argument("--method", action="append")
    parser.add_argument("--model", action="append")
    args = parser.parse_args()

    config_path = args.config.resolve()
    output_dir = args.output_dir.resolve()
    status: dict[str, Any] = {
        "pipeline_version": "1.0",
        "mode": args.mode,
        "config": _portable(config_path),
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
    if args.mode == "status" or not prerequisites_ready:
        status["final_status"] = (
            "ready_for_execution"
            if prerequisites_ready
            else "blocked"
        )
        status["ready"] = prerequisites_ready
        _write_status(args.status_output, status)
        return 0 if prerequisites_ready else 2

    if args.mode == "execute":
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        try:
            assert_frozen_for_execution(config)
        except ValueError as exc:
            status["stages"].append({
                "stage": "frozen_protocol_gate",
                "returncode": 2,
                "result": {"ready": False, "reason": str(exc)},
            })
            _write_status(args.status_output, status)
            return 2

    run_command: list[str | Path] = [
        PYTHON,
        ROOT / "scripts" / "experiments" / "run_ec_react_main.py",
        "--config",
        config_path,
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
            "plan_frozen" if status["ready"] else "blocked"
        )
        _write_status(args.status_output, status)
        return 0 if status["ready"] else 2

    analysis_path = output_dir / "analysis.json"
    analysis = _run([
        PYTHON,
        ROOT / "scripts" / "experiments"
        / "analyze_ec_react_main.py",
        "--config",
        config_path,
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
        config_path,
        "--analysis",
        analysis_path,
        "--output",
        output_dir / "confirmatory_decision.json",
    ])
    status["stages"].append({
        "stage": "claim_decision",
        **decision,
    })
    status["ready"] = True
    status["final_status"] = (
        "claim_passed" if decision["returncode"] == 0 else "claim_not_passed"
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
