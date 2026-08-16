from __future__ import annotations

import json
from pathlib import Path

import yaml

from src.data.candidate_lineage_catalog import (
    audit_candidate_catalog,
    canonical_json_sha256,
    sha256_file,
)


def _catalog(path: Path, object_digest: str) -> dict:
    return {
        "catalog_version": "test",
        "sources": [{
            "source_id": "source-1",
            "publisher": "Publisher",
            "upstream_url": "https://example.test/repo",
            "source_type": "threat_intelligence",
            "license": "MIT",
            "version_or_commit": "commit-1",
        }],
        "lineages": [{
            "lineage_id": "lineage-1",
            "source_id": "source-1",
            "title": "Procedure",
            "tier": "cti_procedure",
            "platforms": ["AWS"],
            "services": ["object_storage"],
            "independence_key": "relationship--1",
            "independence_rationale": "one upstream relationship",
            "near_duplicate_fingerprint": "actor:T1530",
            "generated_event": False,
            "generated_label": False,
            "gold_status": "candidate_only",
            "evidence": [{
                "artifact_path": path.name,
                "artifact_sha256": sha256_file(path),
                "locator_type": "stix_object",
                "locator": "relationship--1",
                "content_sha256": object_digest,
                "upstream_url": "https://example.test/object",
            }],
        }],
    }


def test_catalog_accepts_exact_stix_locator(tmp_path: Path) -> None:
    relationship = {"id": "relationship--1", "type": "relationship"}
    path = tmp_path / "bundle.json"
    path.write_text(
        json.dumps({"objects": [relationship]}), encoding="utf-8"
    )
    audit = audit_candidate_catalog(
        tmp_path,
        _catalog(path, canonical_json_sha256(relationship)),
        target=1,
    )
    assert audit["summary"]["accepted_independent_lineages"] == 1
    assert audit["summary"]["target_passed"] is True
    assert audit["summary"]["runtime_or_oracle_gold"] == 0


def test_catalog_blocks_duplicate_independence_and_bad_hash(
    tmp_path: Path,
) -> None:
    relationship = {"id": "relationship--1", "type": "relationship"}
    path = tmp_path / "bundle.json"
    path.write_text(
        json.dumps({"objects": [relationship]}), encoding="utf-8"
    )
    catalog = _catalog(path, "0" * 64)
    duplicate = dict(catalog["lineages"][0])
    duplicate["lineage_id"] = "lineage-2"
    catalog["lineages"].append(duplicate)
    audit = audit_candidate_catalog(tmp_path, catalog, target=1)
    assert audit["summary"]["accepted_independent_lineages"] == 0
    assert {
        blocker
        for row in audit["lineages"]
        for blocker in row["blockers"]
    } >= {"duplicate_independence_key", "evidence_integrity_failed"}


def test_catalog_resolves_one_atomic_guid(tmp_path: Path) -> None:
    atomic = {
        "name": "AWS - Read object",
        "auto_generated_guid": "11111111-1111-1111-1111-111111111111",
        "supported_platforms": ["iaas:aws"],
        "executor": {"name": "sh", "command": "aws s3 cp"},
    }
    path = tmp_path / "T1530.yaml"
    path.write_text(
        yaml.safe_dump({"attack_technique": "T1530", "atomic_tests": [atomic]}),
        encoding="utf-8",
    )
    catalog = _catalog(path, "unused")
    evidence = catalog["lineages"][0]["evidence"][0]
    evidence.update({
        "locator_type": "yaml_atomic_guid",
        "locator": atomic["auto_generated_guid"],
        "content_sha256": canonical_json_sha256(atomic),
    })
    audit = audit_candidate_catalog(tmp_path, catalog, target=1)
    assert audit["summary"]["accepted_independent_lineages"] == 1
