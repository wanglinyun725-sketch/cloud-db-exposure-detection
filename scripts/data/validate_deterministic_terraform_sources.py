#!/usr/bin/env python3
"""Run read-only Terraform syntax/semantic validation on frozen lab sources.

The command invokes only ``terraform fmt -check`` and ``terraform validate``.
It never invokes plan, apply, refresh, import, or destroy and therefore does
not query or mutate cloud resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TERRAFORM = (
    ROOT / ".tools" / "terraform" / "1.15.8" / "terraform.exe"
)
DEFAULT_SOURCE_ROOT = ROOT / ".tools" / "source_validation"
DEFAULT_OUTPUT = ROOT / "output" / "deterministic_terraform_validation.json"

TARGETS = (
    {
        "target_id": "awsgoat_module_1",
        "source_id": "awsgoat",
        "revision": "b24869ad455ed8d1393d00ecdc15ee638d1c1332",
        "relative_root": (
            "awsgoat/"
            "AWSGoat-b24869ad455ed8d1393d00ecdc15ee638d1c1332/"
            "modules/module-1"
        ),
    },
    {
        "target_id": "awsgoat_module_2",
        "source_id": "awsgoat",
        "revision": "b24869ad455ed8d1393d00ecdc15ee638d1c1332",
        "relative_root": (
            "awsgoat/"
            "AWSGoat-b24869ad455ed8d1393d00ecdc15ee638d1c1332/"
            "modules/module-2"
        ),
    },
    {
        "target_id": "azuregoat",
        "source_id": "azuregoat",
        "revision": "b97045952e6df00de735a7f27fd7c4994dcfe8c0",
        "relative_root": (
            "azuregoat/"
            "AzureGoat-b97045952e6df00de735a7f27fd7c4994dcfe8c0"
        ),
    },
    {
        "target_id": "gcpgoat",
        "source_id": "gcpgoat",
        "revision": "44605c4bff4b2da7611dfce78696bb53db6d8c54",
        "relative_root": (
            "gcpgoat/"
            "GCPGoat-44605c4bff4b2da7611dfce78696bb53db6d8c54"
        ),
    },
)


def _run(terraform: Path, config_root: Path, args: list[str]) -> dict:
    result = subprocess.run(
        [str(terraform), f"-chdir={config_root}", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
        shell=False,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_validate_json(raw: str, returncode: int) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "valid": False,
            "error_count": 1,
            "warning_count": 0,
            "diagnostics": [
                {
                    "severity": "error",
                    "summary": "terraform validate did not return JSON",
                    "detail": raw[:2000],
                }
            ],
            "returncode": returncode,
        }
    return {
        "valid": bool(payload.get("valid")),
        "error_count": int(payload.get("error_count", 0)),
        "warning_count": int(payload.get("warning_count", 0)),
        "diagnostics": [
            {
                "severity": item.get("severity"),
                "summary": item.get("summary"),
                "detail": item.get("detail"),
                "address": item.get("address"),
            }
            for item in payload.get("diagnostics", [])
        ],
        "returncode": returncode,
    }


def validate_sources(
    *,
    terraform: Path = DEFAULT_TERRAFORM,
    source_root: Path = DEFAULT_SOURCE_ROOT,
) -> dict:
    if not terraform.exists():
        raise FileNotFoundError(terraform)
    targets = []
    for target in TARGETS:
        config_root = source_root / target["relative_root"]
        main_tf = config_root / "main.tf"
        if not main_tf.exists():
            raise FileNotFoundError(main_tf)

        fmt = _run(terraform, config_root, ["fmt", "-check", "-recursive"])
        validate = _run(terraform, config_root, ["validate", "-json"])
        parsed_validate = _safe_validate_json(
            validate["stdout"],
            validate["returncode"],
        )
        targets.append(
            {
                **target,
                "main_tf_sha256": _sha256(main_tf),
                "provider_lock_present": (
                    config_root / ".terraform.lock.hcl"
                ).exists(),
                "format_check": {
                    "passed": fmt["returncode"] == 0,
                    "returncode": fmt["returncode"],
                    "unformatted_files": [
                        line.strip()
                        for line in fmt["stdout"].splitlines()
                        if line.strip()
                    ],
                    "stderr": fmt["stderr"][:2000],
                },
                "semantic_validation": parsed_validate,
            }
        )

    return {
        "validation_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "read_only_terraform_commands": [
                "fmt -check -recursive",
                "validate -json",
            ],
            "cloud_resources_created": 0,
            "cloud_api_calls_required": False,
        },
        "terraform": {
            "path": str(terraform),
            "sha256": _sha256(terraform),
        },
        "summary": {
            "targets": len(targets),
            "format_valid": sum(
                target["format_check"]["passed"] for target in targets
            ),
            "semantic_valid": sum(
                target["semantic_validation"]["valid"]
                for target in targets
            ),
            "semantic_invalid": sum(
                not target["semantic_validation"]["valid"]
                for target in targets
            ),
        },
        "targets": targets,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--terraform", type=Path, default=DEFAULT_TERRAFORM)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = validate_sources(
        terraform=args.terraform,
        source_root=args.source_root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
