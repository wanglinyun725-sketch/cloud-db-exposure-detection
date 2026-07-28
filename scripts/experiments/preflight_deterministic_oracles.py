#!/usr/bin/env python3
"""Read-only preflight for deterministic cloud oracle experiments.

The script never creates cloud resources and never prints account identities,
tokens, or credentials.  It checks local tools and whether each provider has
enough non-secret context to begin an authorized lab run.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "output" / "deterministic_oracle_preflight.json"
LOCAL_TERRAFORM = (
    ROOT / ".tools" / "terraform" / "1.15.8" / "terraform.exe"
)


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    resolved = shutil.which(argv[0]) or argv[0]
    command = [resolved, *argv[1:]]
    if Path(resolved).suffix.casefold() in {".cmd", ".bat"}:
        command = [
            os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
            "/d",
            "/c",
            resolved,
            *argv[1:],
        ]
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


def _tool(
    name: str,
    version_args: list[str],
    *,
    local_fallback: Path | None = None,
) -> dict:
    path = shutil.which(name)
    if path is None and local_fallback and local_fallback.exists():
        path = str(local_fallback)
    if path is None:
        return {
            "installed": False,
            "usable": False,
            "path": None,
            "version_summary": None,
        }
    result = _run([path, *version_args])
    output = (result.stdout or result.stderr).strip().splitlines()
    return {
        "installed": True,
        "usable": result.returncode == 0,
        "path": path,
        "version_summary": output[0][:240] if output else None,
    }


def build_report() -> dict:
    terraform = _tool(
        "terraform",
        ["version", "-json"],
        local_fallback=LOCAL_TERRAFORM,
    )
    aws = _tool("aws", ["--version"])
    azure = _tool("az", ["version"])
    gcloud = _tool("gcloud", ["--version"])

    aws_auth = {"authenticated": False, "check": "not_run"}
    if aws["usable"]:
        result = _run(
            ["aws", "sts", "get-caller-identity", "--output", "json"]
        )
        aws_auth = {
            "authenticated": result.returncode == 0,
            "check": "sts_get_caller_identity",
        }

    azure_auth = {
        "authenticated": False,
        "subscription_selected": False,
        "check": "not_run",
    }
    if azure["usable"]:
        result = _run(["az", "account", "show", "--output", "json"])
        payload = {}
        if result.returncode == 0:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                payload = {}
        azure_auth = {
            "authenticated": result.returncode == 0,
            "subscription_selected": bool(payload.get("id")),
            "check": "az_account_show",
        }

    gcp_auth = {
        "authenticated": False,
        "active_identity_count": 0,
        "project_selected": False,
        "check": "not_run",
    }
    if gcloud["usable"]:
        auth_result = _run(
            [
                "gcloud",
                "auth",
                "list",
                "--filter=status:ACTIVE",
                "--format=json",
            ]
        )
        identities = []
        if auth_result.returncode == 0:
            try:
                identities = json.loads(auth_result.stdout)
            except json.JSONDecodeError:
                identities = []
        project_result = _run(
            ["gcloud", "config", "get-value", "project"]
        )
        project = project_result.stdout.strip()
        gcp_auth = {
            "authenticated": bool(identities),
            "active_identity_count": len(identities),
            "project_selected": bool(project and project != "(unset)"),
            "check": "gcloud_auth_list_and_config_project",
        }

    blockers = []
    if not terraform["usable"]:
        blockers.append("Terraform CLI is unavailable")
    if not aws["usable"]:
        blockers.append("AWS CLI is unavailable or broken")
    elif not aws_auth["authenticated"]:
        blockers.append("AWS CLI has no usable authenticated identity")
    if not azure["usable"]:
        blockers.append("Azure CLI is unavailable")
    elif not azure_auth["subscription_selected"]:
        blockers.append("Azure has no selected authorized subscription")
    if not gcloud["usable"]:
        blockers.append("Google Cloud CLI is unavailable")
    elif not gcp_auth["authenticated"]:
        blockers.append("Google Cloud CLI has no active identity")
    elif not gcp_auth["project_selected"]:
        blockers.append("Google Cloud CLI has no selected lab project")

    return {
        "preflight_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "read_only": True,
            "cloud_resources_created": 0,
            "identities_redacted": True,
        },
        "tools": {
            "terraform": terraform,
            "aws": aws,
            "azure": azure,
            "gcloud": gcloud,
        },
        "authentication": {
            "aws": aws_auth,
            "azure": azure_auth,
            "gcp": gcp_auth,
        },
        "ready": not blockers,
        "blockers": blockers,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
