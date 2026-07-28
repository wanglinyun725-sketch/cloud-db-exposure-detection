"""Derive a deterministic operation prior from pinned Sigma cloud rules."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Iterable
from zipfile import ZipFile

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEFAULT_ARCHIVE = (
    ROOT
    / "data"
    / "real_sources"
    / "raw"
    / "sigmahq"
    / "sigma-r2026-07-01.zip"
)
DEFAULT_OUTPUT = (
    ROOT / "configs" / "sigma_cloud_operation_prior_v1.json"
)
ARCHIVE_PREFIX = "sigma-r2026-07-01/rules/cloud/"
PLATFORM_FIELDS = {
    "AWS": {"eventname"},
    "AZURE": {"operationname", "operationnamevalue"},
    "GCP": {
        "gcp.audit.method_name",
        "data.protopayload.methodname",
        "protopayload.methodname",
    },
}
SUPPORTED_MODIFIERS = {"startswith", "endswith", "contains", "all"}


def build_prior(archive_path: str | Path) -> dict[str, Any]:
    archive_path = Path(archive_path).resolve()
    patterns: list[dict[str, Any]] = []
    rules_total = 0
    rule_ids_with_patterns: set[str] = set()
    excluded_filter_subtrees = 0
    unsupported_modifier_fields = 0

    with ZipFile(archive_path) as archive:
        members = sorted(
            name
            for name in archive.namelist()
            if name.startswith(ARCHIVE_PREFIX)
            and name.endswith((".yml", ".yaml"))
        )
        for member in members:
            platform = _platform_from_member(member)
            if platform is None:
                continue
            rule = yaml.safe_load(archive.read(member)) or {}
            rules_total += 1
            rule_id = str(rule.get("id") or member)
            extracted, excluded, unsupported = _extract_rule_patterns(
                rule.get("detection") or {},
                platform,
                rule_id,
                str(rule.get("title") or ""),
                str(rule.get("status") or "unknown"),
                member.removeprefix("sigma-r2026-07-01/"),
            )
            patterns.extend(extracted)
            excluded_filter_subtrees += excluded
            unsupported_modifier_fields += unsupported
            if extracted:
                rule_ids_with_patterns.add(rule_id)

    unique = {
        (
            item["platform"],
            item["rule_id"],
            item["field"],
            item["match_type"],
            tuple(item["values"]),
        ): item
        for item in patterns
    }
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            item["platform"],
            item["rule_id"],
            item["field"],
            item["match_type"],
            item["values"],
        ),
    )
    return {
        "prior_id": "sigma_cloud_operation_prior_v1",
        "prior_version": "1.0.0",
        "semantic_gain": (
            "count of distinct matching Sigma cloud detection rules"
        ),
        "weighting": "none",
        "label_usage": "none",
        "source": {
            "source_id": "sigmahq_cloud_rules",
            "repository": "https://github.com/SigmaHQ/sigma",
            "release": "r2026-07-01",
            "archive_relative_path": str(
                archive_path.relative_to(ROOT)
            ).replace("\\", "/"),
            "archive_sha256": _sha256(archive_path),
            "license": "Detection Rule License 1.1",
        },
        "extraction": {
            "generated_by": (
                "scripts/data/build_sigma_cloud_operation_prior.py"
            ),
            "positive_detection_selections_only": True,
            "filter_subtrees_excluded": True,
            "platform_fields": {
                key: sorted(value)
                for key, value in PLATFORM_FIELDS.items()
            },
            "rules_total": rules_total,
            "rules_with_operation_patterns": len(
                rule_ids_with_patterns
            ),
            "patterns": len(ordered),
            "excluded_filter_subtrees": excluded_filter_subtrees,
            "unsupported_modifier_fields": unsupported_modifier_fields,
        },
        "patterns": ordered,
    }


def _extract_rule_patterns(
    detection: dict[str, Any],
    platform: str,
    rule_id: str,
    title: str,
    status: str,
    source_path: str,
) -> tuple[list[dict[str, Any]], int, int]:
    output: list[dict[str, Any]] = []
    excluded = 0
    unsupported = 0

    def walk(node: Any, ancestors: tuple[str, ...]) -> None:
        nonlocal excluded, unsupported
        if isinstance(node, dict):
            for raw_key, value in node.items():
                key = str(raw_key)
                if key == "condition":
                    continue
                if key.casefold().startswith("filter"):
                    excluded += 1
                    continue
                base, modifiers = _field_and_modifiers(key)
                if base.casefold() in PLATFORM_FIELDS[platform]:
                    pattern = _pattern_from_value(
                        platform,
                        rule_id,
                        title,
                        status,
                        source_path,
                        base,
                        modifiers,
                        value,
                    )
                    if pattern is None:
                        unsupported += 1
                    else:
                        output.extend(pattern)
                walk(value, ancestors + (key,))
        elif isinstance(node, list):
            for value in node:
                walk(value, ancestors)

    walk(detection, ())
    return output, excluded, unsupported


def _field_and_modifiers(field: str) -> tuple[str, set[str]]:
    parts = field.split("|")
    return parts[0], {item.casefold() for item in parts[1:]}


def _pattern_from_value(
    platform: str,
    rule_id: str,
    title: str,
    status: str,
    source_path: str,
    field: str,
    modifiers: set[str],
    value: Any,
) -> list[dict[str, Any]] | None:
    if modifiers - SUPPORTED_MODIFIERS:
        return None
    values = sorted(set(_string_values(value)))
    if not values:
        return None
    base_match = next(
        (
            item
            for item in ("startswith", "endswith", "contains")
            if item in modifiers
        ),
        "exact",
    )
    if base_match == "exact" and any("*" in item for item in values):
        base_match = "glob"
    if "all" in modifiers and base_match != "exact":
        return [_pattern_payload(
            platform,
            rule_id,
            title,
            status,
            source_path,
            field,
            f"all_{base_match}",
            values,
        )]
    return [
        _pattern_payload(
            platform,
            rule_id,
            title,
            status,
            source_path,
            field,
            base_match,
            [item],
        )
        for item in values
    ]


def _pattern_payload(
    platform: str,
    rule_id: str,
    title: str,
    status: str,
    source_path: str,
    field: str,
    match_type: str,
    values: list[str],
) -> dict[str, Any]:
    return {
        "platform": platform,
        "rule_id": rule_id,
        "title": title,
        "status": status,
        "source_path": source_path,
        "field": field,
        "match_type": match_type,
        "values": values,
    }


def _string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str) and value.strip():
        yield value.strip()
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _platform_from_member(member: str) -> str | None:
    relative = member.removeprefix(ARCHIVE_PREFIX)
    folder = relative.split("/", 1)[0].casefold()
    return {
        "aws": "AWS",
        "azure": "AZURE",
        "gcp": "GCP",
    }.get(folder)


def _sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build_prior(args.archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(
        {
            "output": str(args.output),
            **payload["extraction"],
            "archive_sha256": payload["source"]["archive_sha256"],
        },
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
