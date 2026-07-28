#!/usr/bin/env python3
"""Audit frozen configuration candidates without creating benchmark labels.

The audit proves that every declared source revision, snapshot digest,
Terraform reference, and upstream walkthrough reference exists.  It writes an
inventory report only; all candidate gold fields must remain null.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
CANDIDATES_PATH = REAL_ROOT / "deterministic_config_candidates_v1.json"
DEFAULT_OUTPUT = ROOT / "output" / "deterministic_config_source_audit.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_suffix(names: list[str], suffix: str) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(
            f"archive suffix {suffix!r} resolved to {len(matches)} members"
        )
    return matches[0]


def audit_sources(
    *,
    manifest_path: Path = MANIFEST_PATH,
    candidates_path: Path = CANDIDATES_PATH,
) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    manifest_sources = {
        source["source_id"]: source for source in manifest["sources"]
    }

    source_audits: dict[str, dict] = {}
    archive_names: dict[str, list[str]] = {}
    archive_paths: dict[str, Path] = {}
    for role in candidates["source_roles"]:
        source_id = role["source_id"]
        if source_id not in manifest_sources:
            raise ValueError(f"{source_id} is absent from acquisition manifest")
        source = manifest_sources[source_id]
        if source["commit"] != role["revision"]:
            raise ValueError(
                f"{source_id} revision mismatch: "
                f"{source['commit']} != {role['revision']}"
            )
        snapshot = next(
            (
                artifact
                for artifact in source["artifacts"]
                if artifact["name"] == "snapshot.zip"
            ),
            None,
        )
        if snapshot is None:
            raise ValueError(f"{source_id} has no frozen snapshot.zip")
        snapshot_path = ROOT / snapshot["relative_path"]
        if not snapshot_path.exists():
            raise FileNotFoundError(snapshot_path)
        actual_hash = _sha256(snapshot_path)
        if actual_hash != snapshot["sha256"]:
            raise ValueError(f"{source_id} snapshot digest mismatch")

        with ZipFile(snapshot_path) as archive:
            names = archive.namelist()
        archive_names[source_id] = names
        archive_paths[source_id] = snapshot_path
        source_audits[source_id] = {
            "revision": source["commit"],
            "snapshot_sha256": actual_hash,
            "snapshot_bytes": snapshot_path.stat().st_size,
            "archive_files": sum(not name.endswith("/") for name in names),
            "terraform_files": sum(
                name.casefold().endswith(".tf") for name in names
            ),
            "markdown_files": sum(
                name.casefold().endswith(".md") for name in names
            ),
            "upstream_attack_manual_files": sum(
                "attack-manuals/" in name.casefold()
                and name.casefold().endswith(".md")
                for name in names
            ),
            "role": role["role"],
            "platform": role["platform"],
        }

    case_audits: list[dict] = []
    for case in candidates["cases"]:
        source_id = case["source_id"]
        source_revision = source_audits[source_id]["revision"]
        if case["revision"] != source_revision:
            raise ValueError(f"{case['case_id']} has a stale source revision")
        if case["gold_label"] is not None or case["label_origin"] is not None:
            raise ValueError(
                f"{case['case_id']} was promoted without oracle evidence"
            )
        names = archive_names[source_id]
        resolved_config = [
            _resolve_suffix(names, suffix)
            for suffix in case["configuration_refs"]
        ]
        resolved_claims = [
            _resolve_suffix(names, suffix)
            for suffix in case["upstream_claim_refs"]
        ]
        resolved_assertions = []
        with ZipFile(archive_paths[source_id]) as archive:
            for assertion in case.get("configuration_assertions", []):
                member = _resolve_suffix(names, assertion["member_ref"])
                text = archive.read(member).decode(
                    "utf-8",
                    errors="replace",
                )
                missing = [
                    fragment
                    for fragment in assertion["expected_fragments"]
                    if fragment not in text
                ]
                if missing:
                    raise ValueError(
                        f"{case['case_id']} assertion "
                        f"{assertion['assertion_id']} is missing literal "
                        f"fragments: {missing}"
                    )
                resolved_assertions.append(
                    {
                        "assertion_id": assertion["assertion_id"],
                        "member": member,
                        "literal_fragments_verified": len(
                            assertion["expected_fragments"]
                        ),
                        "literal_interpretation": assertion[
                            "literal_interpretation"
                        ],
                        "result": "verified_against_frozen_source",
                    }
                )
        case_audits.append(
            {
                "case_id": case["case_id"],
                "source_id": source_id,
                "platform": case["platform"],
                "configuration_members": resolved_config,
                "upstream_claim_members": resolved_claims,
                "configuration_assertions": resolved_assertions,
                "mandatory_claim_count": len(case["mandatory_claims"]),
                "evidence_status": case["evidence_status"],
                "gold_label": None,
                "label_origin": None,
                "audit_result": "references_verified_candidate_not_gold",
            }
        )

    return {
        "audit_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
            "candidates": str(candidates_path.relative_to(ROOT)).replace(
                "\\", "/"
            ),
        },
        "policy_assertions": {
            "upstream_walkthrough_is_gold": False,
            "generated_labels": 0,
            "gold_labels": 0,
            "missing_finding_is_negative": False,
        },
        "summary": {
            "frozen_sources": len(source_audits),
            "candidate_cases": len(case_audits),
            "platforms": sorted(
                {case["platform"] for case in candidates["cases"]}
            ),
            "configuration_refs_verified": sum(
                len(case["configuration_members"]) for case in case_audits
            ),
            "upstream_claim_refs_verified": sum(
                len(case["upstream_claim_members"]) for case in case_audits
            ),
            "configuration_assertions_verified": sum(
                len(case["configuration_assertions"]) for case in case_audits
            ),
            "runtime_gold_cases": 0,
            "configuration_gold_cases": 0,
        },
        "sources": source_audits,
        "cases": case_audits,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--candidates", type=Path, default=CANDIDATES_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = audit_sources(
        manifest_path=args.manifest,
        candidates_path=args.candidates,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "summary": report["summary"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
