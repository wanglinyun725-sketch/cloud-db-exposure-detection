"""Machine gates for the versioned 500-lineage candidate catalogue.

The catalogue is intentionally provenance-only.  Passing this audit means a
candidate is independently traceable to immutable upstream material; it does
not turn the candidate into path gold or claim that an attack succeeded.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import yaml


REQUIRED_SOURCE_FIELDS = {
    "source_id",
    "publisher",
    "upstream_url",
    "source_type",
    "license",
    "version_or_commit",
}
REQUIRED_LINEAGE_FIELDS = {
    "lineage_id",
    "source_id",
    "title",
    "tier",
    "platforms",
    "services",
    "independence_key",
    "independence_rationale",
    "near_duplicate_fingerprint",
    "evidence",
    "generated_event",
    "generated_label",
    "gold_status",
}
ALLOWED_TIERS = {
    "published_runtime_telemetry",
    "executable_lab",
    "deterministic_configuration",
    "cti_procedure",
    "real_incident_report",
    "controlled_repair_counterfactual",
}
ALLOWED_PLATFORMS = {"AWS", "AZURE", "GCP", "CROSS_CLOUD"}
NON_GOLD_STATES = {"candidate_only", "unknown", "pending_oracle"}


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(payload)


def resolve_evidence(root: Path, evidence: dict) -> dict:
    """Resolve one exact evidence locator and verify both artifact and item."""
    artifact_path = root / evidence["artifact_path"]
    result = {
        "artifact_path": evidence["artifact_path"],
        "locator_type": evidence["locator_type"],
        "locator": evidence["locator"],
        "artifact_exists": artifact_path.is_file(),
        "artifact_sha256_matches": False,
        "content_sha256_matches": False,
        "error": None,
    }
    if not artifact_path.is_file():
        result["error"] = "artifact_missing"
        return result
    result["artifact_sha256_matches"] = (
        sha256_file(artifact_path) == evidence["artifact_sha256"]
    )
    try:
        locator_type = evidence["locator_type"]
        locator = evidence["locator"]
        if locator_type == "file":
            if locator not in {"$", artifact_path.name}:
                raise ValueError("file locator must be '$' or the file name")
            digest = sha256_file(artifact_path)
        elif locator_type == "zip_member":
            with ZipFile(artifact_path) as archive:
                payload = archive.read(locator)
            digest = sha256_bytes(payload)
        elif locator_type == "stix_object":
            bundle = json.loads(artifact_path.read_text(encoding="utf-8"))
            matches = [
                item for item in bundle.get("objects", [])
                if item.get("id") == locator
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"STIX locator resolved to {len(matches)} objects"
                )
            digest = canonical_json_sha256(matches[0])
        elif locator_type == "yaml_atomic_guid":
            document = yaml.safe_load(
                artifact_path.read_text(encoding="utf-8")
            )
            matches = [
                item for item in document.get("atomic_tests", [])
                if item.get("auto_generated_guid") == locator
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"atomic GUID resolved to {len(matches)} tests"
                )
            digest = canonical_json_sha256(matches[0])
        else:
            raise ValueError(f"unsupported locator_type={locator_type!r}")
        result["content_sha256_matches"] = (
            digest == evidence["content_sha256"]
        )
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
    return result


def audit_candidate_catalog(
    root: Path,
    catalog: dict,
    *,
    verify_hashes: bool = True,
    target: int = 500,
) -> dict:
    """Apply provenance, independence and non-generation hard gates."""
    source_rows = catalog.get("sources", [])
    lineage_rows = catalog.get("lineages", [])
    source_ids = [row.get("source_id") for row in source_rows]
    duplicate_source_ids = sorted(
        source_id for source_id, count in Counter(source_ids).items()
        if source_id and count > 1
    )
    sources = {row.get("source_id"): row for row in source_rows}

    source_audits = []
    accepted_source_ids = set()
    for row in source_rows:
        blockers = []
        missing = sorted(REQUIRED_SOURCE_FIELDS - row.keys())
        if missing:
            blockers.append(f"missing_fields:{','.join(missing)}")
        if not str(row.get("license", "")).strip() or str(
            row.get("license", "")
        ).casefold() in {"unknown", "unspecified"}:
            blockers.append("license_missing_or_unknown")
        if not str(row.get("version_or_commit", "")).strip():
            blockers.append("version_missing")
        if not str(row.get("upstream_url", "")).startswith(
            ("https://", "http://")
        ):
            blockers.append("stable_url_missing")
        if row.get("source_id") in duplicate_source_ids:
            blockers.append("duplicate_source_id")
        if not blockers:
            accepted_source_ids.add(row["source_id"])
        source_audits.append({
            "source_id": row.get("source_id"),
            "accepted": not blockers,
            "blockers": blockers,
        })

    lineage_ids = [row.get("lineage_id") for row in lineage_rows]
    independence_keys = [row.get("independence_key") for row in lineage_rows]
    duplicate_lineage_ids = {
        key for key, count in Counter(lineage_ids).items() if key and count > 1
    }
    duplicate_independence_keys = {
        key for key, count in Counter(independence_keys).items()
        if key and count > 1
    }
    fingerprints: dict[str, list[str]] = defaultdict(list)
    for row in lineage_rows:
        if row.get("near_duplicate_fingerprint"):
            fingerprints[row["near_duplicate_fingerprint"]].append(
                row.get("lineage_id", "")
            )

    lineage_audits = []
    accepted = []
    evidence_verified = 0
    for row in lineage_rows:
        blockers = []
        warnings = []
        missing = sorted(REQUIRED_LINEAGE_FIELDS - row.keys())
        if missing:
            blockers.append(f"missing_fields:{','.join(missing)}")
        if row.get("source_id") not in accepted_source_ids:
            blockers.append("source_not_accepted")
        if row.get("tier") not in ALLOWED_TIERS:
            blockers.append("invalid_tier")
        platforms = set(row.get("platforms", []))
        if not platforms or not platforms <= ALLOWED_PLATFORMS:
            blockers.append("invalid_or_empty_platforms")
        if not row.get("services"):
            blockers.append("services_empty")
        if row.get("generated_event") is not False:
            blockers.append("generated_event_forbidden")
        if row.get("generated_label") is not False:
            blockers.append("generated_label_forbidden")
        if row.get("gold_status") not in NON_GOLD_STATES:
            blockers.append("candidate_catalog_cannot_assert_gold")
        if row.get("lineage_id") in duplicate_lineage_ids:
            blockers.append("duplicate_lineage_id")
        if row.get("independence_key") in duplicate_independence_keys:
            blockers.append("duplicate_independence_key")
        fingerprint = row.get("near_duplicate_fingerprint")
        colliders = fingerprints.get(fingerprint, [])
        if fingerprint and len(colliders) > 1:
            warnings.append({
                "kind": "near_duplicate_fingerprint_collision",
                "lineage_ids": sorted(colliders),
            })
        evidence_rows = row.get("evidence", [])
        if not evidence_rows:
            blockers.append("evidence_empty")
        evidence_audits = []
        if verify_hashes:
            for evidence in evidence_rows:
                required = {
                    "artifact_path",
                    "artifact_sha256",
                    "locator_type",
                    "locator",
                    "content_sha256",
                    "upstream_url",
                }
                missing_evidence = sorted(required - evidence.keys())
                if missing_evidence:
                    evidence_audits.append({
                        "error": (
                            "missing_evidence_fields:"
                            + ",".join(missing_evidence)
                        )
                    })
                    blockers.append("evidence_schema_invalid")
                    continue
                resolved = resolve_evidence(root, evidence)
                evidence_audits.append(resolved)
                if not (
                    resolved["artifact_exists"]
                    and resolved["artifact_sha256_matches"]
                    and resolved["content_sha256_matches"]
                    and resolved["error"] is None
                ):
                    blockers.append("evidence_integrity_failed")
                else:
                    evidence_verified += 1
        if not blockers:
            accepted.append(row)
        lineage_audits.append({
            "lineage_id": row.get("lineage_id"),
            "accepted": not blockers,
            "blockers": sorted(set(blockers)),
            "warnings": warnings,
            "evidence": evidence_audits,
        })

    platform_counts = Counter()
    service_counts = Counter()
    tier_counts = Counter()
    source_counts = Counter()
    for row in accepted:
        platform_counts.update(row["platforms"])
        service_counts.update(row["services"])
        tier_counts[row["tier"]] += 1
        source_counts[row["source_id"]] += 1
    gold_counts = Counter(row.get("gold_status") for row in lineage_rows)
    return {
        "audit_version": "1.0.0",
        "catalog_version": catalog.get("catalog_version"),
        "target": target,
        "summary": {
            "declared_sources": len(source_rows),
            "accepted_sources": len(accepted_source_ids),
            "declared_lineages": len(lineage_rows),
            "accepted_independent_lineages": len(accepted),
            "gap_to_target": max(0, target - len(accepted)),
            "target_passed": len(accepted) >= target,
            "verified_evidence_locators": evidence_verified,
            "runtime_or_oracle_gold": sum(
                count for state, count in gold_counts.items()
                if state not in NON_GOLD_STATES
            ),
        },
        "separation_assertions": {
            "candidate_count_is_gold_count": False,
            "generated_events_admitted": 0,
            "generated_labels_admitted": 0,
        },
        "accepted_distributions": {
            "tiers": dict(sorted(tier_counts.items())),
            "platforms": dict(sorted(platform_counts.items())),
            "sources": dict(sorted(source_counts.items())),
            "services": dict(service_counts.most_common()),
        },
        "near_duplicate_collision_clusters": [
            {"fingerprint": key, "lineage_ids": sorted(values)}
            for key, values in sorted(fingerprints.items())
            if len(values) > 1
        ],
        "sources": source_audits,
        "lineages": lineage_audits,
    }
