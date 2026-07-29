"""Build a label-empty queue for deterministic configuration verification.

Literal IaC facts are verified against immutable upstream archives.  They are
never promoted to provider authorization, runtime reachability, or path gold.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile


PROVIDER_PLANS = {
    "AWS": {
        "configuration_oracles": [
            "AWS IAM Access Analyzer",
            "AWS IAM policy simulation with exact principal/action/resource",
        ],
        "runtime_oracle": (
            "authorized exact-operation probe plus matching CloudTrail record"
        ),
    },
    "Azure": {
        "configuration_oracles": [
            "exact Azure RBAC evaluation",
            "Defender for Cloud attack-path evidence where applicable",
        ],
        "runtime_oracle": (
            "authorized exact-operation probe plus matching Azure data-plane "
            "or activity record"
        ),
    },
    "GCP": {
        "configuration_oracles": [
            "GCP Policy Analyzer",
            "testIamPermissions for exact principal/action/resource",
        ],
        "runtime_oracle": (
            "authorized exact-operation probe plus matching Cloud Audit Log"
        ),
    },
}


def _sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _resolve_suffix(names: list[str], suffix: str) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(
            f"archive suffix {suffix!r} resolved to {len(matches)} members"
        )
    return matches[0]


def _fragment_occurrences(text: str, fragment: str) -> list[dict[str, int]]:
    output = []
    start = 0
    while True:
        offset = text.find(fragment, start)
        if offset < 0:
            break
        line_start = text.count("\n", 0, offset) + 1
        output.append({
            "line_start": line_start,
            "line_end": line_start + fragment.count("\n"),
            "character_offset": offset,
        })
        start = offset + max(1, len(fragment))
    return output


def build_configuration_oracle_queue(
    root: str | Path,
    *,
    candidates_path: str | Path = (
        "data/real_sources/deterministic_config_candidates_v1.json"
    ),
    manifest_path: str | Path = "data/real_sources/acquisition_manifest.json",
) -> dict[str, Any]:
    root = Path(root).resolve()
    candidates_path = _resolve(root, candidates_path)
    manifest_path = _resolve(root, manifest_path)
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_sources = {
        item["source_id"]: item for item in manifest["sources"]
    }

    cases = []
    for candidate in candidates["cases"]:
        source_id = candidate["source_id"]
        source = manifest_sources[source_id]
        if source.get("commit") != candidate["revision"]:
            raise ValueError(
                f"{candidate['case_id']} source revision is not frozen"
            )
        snapshot = next(
            (
                artifact for artifact in source["artifacts"]
                if artifact["name"] == "snapshot.zip"
            ),
            None,
        )
        if snapshot is None:
            raise ValueError(f"{source_id} has no snapshot.zip")
        snapshot_path = root / snapshot["relative_path"]
        snapshot_bytes = snapshot_path.read_bytes()
        snapshot_digest = _sha256_bytes(snapshot_bytes)
        if snapshot_digest != snapshot["sha256"]:
            raise ValueError(f"{source_id} snapshot digest mismatch")

        assertion_rows = []
        with ZipFile(snapshot_path) as archive:
            names = archive.namelist()
            for assertion in candidate["configuration_assertions"]:
                member = _resolve_suffix(
                    names,
                    assertion["member_ref"],
                )
                member_bytes = archive.read(member)
                text = member_bytes.decode("utf-8", errors="replace")
                fragment_rows = []
                for fragment in assertion["expected_fragments"]:
                    occurrences = _fragment_occurrences(text, fragment)
                    if not occurrences:
                        raise ValueError(
                            f"{candidate['case_id']} is missing frozen "
                            f"fragment {fragment!r}"
                        )
                    fragment_rows.append({
                        "fragment_sha256": _sha256_bytes(
                            fragment.encode("utf-8")
                        ),
                        "fragment_length": len(fragment),
                        "occurrence_count": len(occurrences),
                        "occurrences": occurrences,
                    })
                assertion_rows.append({
                    "assertion_id": assertion["assertion_id"],
                    "literal_interpretation": assertion[
                        "literal_interpretation"
                    ],
                    "fact_state": "VerifiedLiteralPresence",
                    "raw_ref": {
                        "source_id": source_id,
                        "revision": candidate["revision"],
                        "archive_relative_path": snapshot["relative_path"],
                        "archive_sha256": snapshot_digest,
                        "archive_member": member,
                        "archive_member_sha256": _sha256_bytes(member_bytes),
                        "archive_member_bytes": len(member_bytes),
                    },
                    "fragment_matches": fragment_rows,
                    "does_not_prove": [
                        "deployed state",
                        "complete-scope provider authorization",
                        "network reachability",
                        "successful data access",
                        "end-to-end path reachability",
                    ],
                })

        platform = candidate["platform"]
        provider_plan = PROVIDER_PLANS[platform]
        cases.append({
            "case_id": candidate["case_id"],
            "independence_group": (
                f"configuration-lineage:{source_id}:"
                f"{candidate['case_id']}"
            ),
            "source_id": source_id,
            "platform": platform,
            "revision": candidate["revision"],
            "candidate_ref": str(
                candidates_path.relative_to(root)
            ).replace("\\", "/"),
            "data_target": candidate["data_target"],
            "configuration_assertions": assertion_rows,
            "evidence_layers": [
                {
                    "layer": "frozen_configuration",
                    "status": "verified_literal_facts_only",
                    "decisive_for_path": False,
                },
                {
                    "layer": "provider_native_analysis",
                    "status": "pending",
                    "required_scope": (
                        "complete exact principal-action-resource scope"
                    ),
                    "accepted_oracles": provider_plan[
                        "configuration_oracles"
                    ],
                    "absent_finding_state": "Unknown",
                    "decisive_for_configuration_gold": True,
                },
                {
                    "layer": "authorized_active_probe",
                    "status": "pending",
                    "required_scope": "isolated authorized lab only",
                    "accepted_oracle": provider_plan["runtime_oracle"],
                    "decisive_for_runtime_gold": True,
                },
            ],
            "admission_status": "needs_execution",
            "gold_label": None,
            "path_state": None,
            "label_origin": None,
            "upstream_expected_outcome_exposed": False,
            "agent_output_exposed": False,
        })

    return {
        "queue_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_stage": "deterministic_configuration_oracle_queue_unlabeled",
        "contract_ref": candidates["contract_ref"],
        "policy": {
            "literal_iac_fact_is_path_gold": False,
            "upstream_walkthrough_is_gold": False,
            "absent_provider_finding_is_negative": False,
            "complete_scope_required": True,
            "runtime_probe_requires_authorized_isolated_lab": True,
            "generated_labels": 0,
        },
        "summary": {
            "cases": len(cases),
            "independence_groups": len({
                item["independence_group"] for item in cases
            }),
            "sources": len({item["source_id"] for item in cases}),
            "platforms": sorted({item["platform"] for item in cases}),
            "verified_literal_assertions": sum(
                len(item["configuration_assertions"]) for item in cases
            ),
            "configuration_gold_cases": 0,
            "runtime_gold_cases": 0,
            "path_gold_cases": 0,
            "needs_execution_cases": sum(
                item["admission_status"] == "needs_execution"
                for item in cases
            ),
        },
        "cases": cases,
    }


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()
