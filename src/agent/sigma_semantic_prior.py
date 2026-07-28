"""Externally grounded operation prior derived from pinned Sigma cloud rules."""
from __future__ import annotations

from fnmatch import fnmatchcase
import json
from pathlib import Path
from typing import Any


DEFAULT_PRIOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "configs"
    / "sigma_cloud_operation_prior_v1.json"
)


class SigmaSemanticPrior:
    """Count distinct Sigma rules matching a visible cloud operation."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("prior_id") != "sigma_cloud_operation_prior_v1":
            raise ValueError("unsupported Sigma semantic prior")
        patterns = payload.get("patterns")
        if not isinstance(patterns, list) or not patterns:
            raise ValueError("Sigma semantic prior has no patterns")
        self.payload = payload
        self.patterns = tuple(patterns)

    @classmethod
    def from_file(
        cls,
        path: str | Path = DEFAULT_PRIOR_PATH,
    ) -> "SigmaSemanticPrior":
        return cls(json.loads(
            Path(path).read_text(encoding="utf-8")
        ))

    def score(
        self,
        operation: str,
        platform: str | None = None,
    ) -> int:
        return len(self.matching_rule_ids(operation, platform))

    def matching_rule_ids(
        self,
        operation: str,
        platform: str | None = None,
    ) -> tuple[str, ...]:
        value = operation.casefold()
        normalized_platform = (
            platform.upper() if isinstance(platform, str) else None
        )
        matched = {
            pattern["rule_id"]
            for pattern in self.patterns
            if (
                normalized_platform is None
                or pattern["platform"] == normalized_platform
            )
            and _matches(value, pattern)
        }
        return tuple(sorted(matched))


def _matches(value: str, pattern: dict[str, Any]) -> bool:
    match_type = pattern["match_type"]
    values = [item.casefold() for item in pattern["values"]]
    if match_type == "exact":
        return any(value == item for item in values)
    if match_type == "glob":
        return any(fnmatchcase(value, item) for item in values)
    if match_type == "startswith":
        return any(value.startswith(item) for item in values)
    if match_type == "endswith":
        return any(value.endswith(item) for item in values)
    if match_type == "contains":
        return any(item in value for item in values)
    if match_type == "all_startswith":
        return all(value.startswith(item) for item in values)
    if match_type == "all_endswith":
        return all(value.endswith(item) for item in values)
    if match_type == "all_contains":
        return all(item in value for item in values)
    raise ValueError(f"unsupported Sigma match type: {match_type}")


SIGMA_SEMANTIC_PRIOR = SigmaSemanticPrior.from_file()
