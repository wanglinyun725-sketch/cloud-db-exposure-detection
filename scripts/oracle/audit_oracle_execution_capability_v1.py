#!/usr/bin/env python3
"""Audit local Oracle prerequisites without emitting identities or secrets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.oracle_gold.capability import build_capability_report  # noqa: E402


DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "oracle_execution_capability_v1.json"
)
SENTINEL = "I_AUTHORIZE_ISOLATED_TEST_RESOURCES_ONLY"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check-auth",
        action="store_true",
        help="Run read-only provider identity/scope checks.",
    )
    args = parser.parse_args()
    tools = {
        name: shutil.which(name) is not None
        for name in ("aws", "az", "gcloud", "terraform")
    }
    authentication = {
        "AWS_authenticated": False,
        "AWS_scope_configured": False,
        "AZURE_authenticated": False,
        "AZURE_scope_configured": False,
        "GCP_authenticated": False,
        "GCP_scope_configured": False,
    }
    if args.check_auth:
        authentication.update(_read_only_auth_checks(tools))
    report = build_capability_report(
        tools=tools,
        authentication=authentication,
        authorization_sentinel_present=(
            os.environ.get("PATHBENCH_ORACLE_EXECUTION") == SENTINEL
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "any_execution_authorized": report["any_execution_authorized"],
        "ready_platforms": report["ready_platforms"],
        "secrets_in_report": False,
    }, ensure_ascii=False))
    return 0


def _read_only_auth_checks(tools: dict[str, bool]) -> dict[str, bool]:
    output: dict[str, bool] = {}
    if tools["aws"]:
        output["AWS_authenticated"] = _success([
            "aws", "sts", "get-caller-identity", "--output", "json",
        ])
        output["AWS_scope_configured"] = bool(
            os.environ.get("AWS_PROFILE")
            or os.environ.get("AWS_ACCESS_KEY_ID")
        )
    if tools["az"]:
        output["AZURE_authenticated"] = _success([
            "az", "account", "show", "--output", "none",
        ])
        output["AZURE_scope_configured"] = bool(
            os.environ.get("AZURE_SUBSCRIPTION_ID")
        )
    if tools["gcloud"]:
        output["GCP_authenticated"] = _has_output([
            "gcloud", "auth", "list",
            "--filter=status:ACTIVE",
            "--format=value(account)",
        ])
        output["GCP_scope_configured"] = _has_output([
            "gcloud", "config", "get-value", "project",
        ])
    return output


def _success(command: list[str]) -> bool:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _has_output(command: list[str]) -> bool:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    value = completed.stdout.strip()
    return (
        completed.returncode == 0
        and bool(value)
        and value not in {"(unset)", "unset"}
    )


if __name__ == "__main__":
    raise SystemExit(main())
