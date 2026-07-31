"""Sensitive-value-free Oracle execution capability report."""
from __future__ import annotations

from typing import Any, Mapping


def build_capability_report(
    *,
    tools: Mapping[str, bool],
    authentication: Mapping[str, bool],
    authorization_sentinel_present: bool,
) -> dict[str, Any]:
    required = {
        "AWS": ["aws", "terraform"],
        "AZURE": ["az", "terraform"],
        "GCP": ["gcloud", "terraform"],
    }
    platforms = {}
    for platform, names in required.items():
        tool_status = {
            name: bool(tools.get(name, False))
            for name in names
        }
        authenticated = bool(
            authentication.get(f"{platform}_authenticated", False)
        )
        project_scope = bool(
            authentication.get(f"{platform}_scope_configured", False)
        )
        blockers = [
            f"missing_tool:{name}"
            for name, present in tool_status.items()
            if not present
        ]
        if not authenticated:
            blockers.append("not_authenticated")
        if not project_scope:
            blockers.append("isolated_scope_not_configured")
        if not authorization_sentinel_present:
            blockers.append("execution_sentinel_absent")
        platforms[platform] = {
            "tools": tool_status,
            "authenticated": authenticated,
            "isolated_scope_configured": project_scope,
            "execution_authorized": not blockers,
            "blockers": blockers,
        }
    return {
        "report_version": "1.0.0",
        "report_kind": "oracle_execution_capability",
        "secrets_in_report": False,
        "credential_values_recorded": False,
        "authorization_sentinel_present": (
            authorization_sentinel_present
        ),
        "platforms": platforms,
        "ready_platforms": sorted(
            platform
            for platform, status in platforms.items()
            if status["execution_authorized"]
        ),
        "any_execution_authorized": any(
            status["execution_authorized"]
            for status in platforms.values()
        ),
    }
