#!/usr/bin/env python3
"""Audit coverage of the pinned Splunk cloud-data telemetry catalogue."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


SOURCE_ID = "splunk_attack_data_2026_expansion"
EXPECTED_COMMIT = "67fe973a954cc35688ad9b4906ed6e85af5892e9"
MANIFEST = ROOT / "data" / "real_sources" / "acquisition_manifest.json"
PRIMARY = (
    ROOT / "data" / "real_sources" / "annotation"
    / "runtime_confirmatory_30_unlabeled.json"
)
STRUCTURAL_AUDIT = (
    ROOT / "output" / "research_design"
    / "splunk_reserve_source_audit_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "research_design"
    / "splunk_cloud_data_catalog_coverage_v1.json"
)
PATH_PREFIX = "datasets/attack_techniques/"
DATA_KEYWORDS = re.compile(
    r"(s3|rds|dynamo|database|cosmos|storage|bucket|snapshot|"
    r"exfil|kms|secret|blob|bigquery|redshift|cloudfunction|datasync)",
    re.IGNORECASE,
)
OUT_OF_SCOPE = {
    "T1048.003/nslookup_exfil": (
        "host/network DNS exfiltration; no provider-native cloud data target"
    ),
    "T1098/windows_multiple_passwords_changed": (
        "Windows identity telemetry; no provider-native cloud data target"
    ),
    "T1552.001/ie_intelliform_storage": (
        "endpoint browser storage telemetry; not cloud-provider telemetry"
    ),
    "T1552.007/kube_audit_get_secret": (
        "Kubernetes secret retrieval; outside the preregistered AWS, Azure, "
        "and GCP provider-native cloud-data scope"
    ),
}


def build_audit(root: str | Path = ROOT) -> dict[str, Any]:
    """Return a deterministic coverage audit with no attack labels."""
    root = Path(root).resolve()
    manifest = _read(root / MANIFEST.relative_to(ROOT))
    source = next(
        (
            item
            for item in manifest.get("sources") or []
            if item.get("source_id") == SOURCE_ID
        ),
        None,
    )
    if (
        not isinstance(source, Mapping)
        or source.get("commit") != EXPECTED_COMMIT
    ):
        raise ValueError("pinned Splunk expansion source is missing")
    tree_artifact = next(
        (
            item
            for item in source.get("artifacts") or []
            if item.get("name") == "repository-tree.json"
        ),
        None,
    )
    if not isinstance(tree_artifact, Mapping):
        raise ValueError("pinned Splunk tree artifact is missing")
    tree_path = root / str(tree_artifact["relative_path"])
    if sha256(tree_path.read_bytes()).hexdigest() != tree_artifact["sha256"]:
        raise ValueError("pinned Splunk tree hash mismatch")
    tree = _read(tree_path)
    if tree.get("sha") != EXPECTED_COMMIT or tree.get("truncated") is True:
        raise ValueError("Splunk tree is truncated or references wrong commit")

    primary = _read(root / PRIMARY.relative_to(ROOT))
    primary_ids = {
        str(case.get("case_id") or "").removeprefix(
            "splunk:datasets/attack_techniques/"
        )
        for case in primary.get("cases") or []
        if str(case.get("case_id") or "").startswith(
            "splunk:datasets/attack_techniques/"
        )
    }
    structural = _read(root / STRUCTURAL_AUDIT.relative_to(ROOT))
    structural_by_id = {
        str(item["dataset_id"]): item
        for item in structural.get("artifacts") or []
    }

    paths = sorted(
        str(item.get("path") or "")
        for item in tree.get("tree") or []
        if str(item.get("path") or "").startswith(PATH_PREFIX)
        and str(item.get("path") or "").endswith((".yml", ".yaml"))
        and DATA_KEYWORDS.search(
            str(item.get("path") or "").removeprefix(PATH_PREFIX)
        )
    )
    rows = []
    for path in paths:
        relative = path.removeprefix(PATH_PREFIX)
        parts = relative.split("/")
        if len(parts) < 3:
            raise ValueError(f"unexpected metadata path: {path}")
        dataset_id = "/".join(parts[:2])
        case_key = "/".join(parts[:2])
        structural_row = structural_by_id.get(dataset_id)
        if case_key in primary_ids:
            disposition = "already_in_frozen_primary_packet"
            reason = "already supplied to the frozen double-human packet"
        elif structural_row is not None:
            disposition = (
                "eligible_unlabeled_reserve"
                if structural_row[
                    "reserve_human_path_screening_eligible"
                ]
                else "structurally_excluded"
            )
            reason = structural_row["exclusion_reason"] or (
                "hash-bound multi-step candidate awaiting human admission"
            )
        elif dataset_id in OUT_OF_SCOPE:
            disposition = "out_of_preregistered_scope"
            reason = OUT_OF_SCOPE[dataset_id]
        else:
            disposition = "unclassified"
            reason = None
        rows.append({
            "dataset_id": dataset_id,
            "metadata_path": path,
            "disposition": disposition,
            "reason": reason,
            "counts_as_human_gold": False,
        })

    counts: dict[str, int] = {}
    for row in rows:
        key = row["disposition"]
        counts[key] = counts.get(key, 0) + 1
    unclassified = counts.get("unclassified", 0)
    return {
        "audit_version": "1.0",
        "source_id": SOURCE_ID,
        "repository": source["repository"],
        "commit": source["commit"],
        "catalogue_rule": {
            "path_prefix": PATH_PREFIX,
            "case_insensitive_keywords": DATA_KEYWORDS.pattern,
            "rule_frozen_before_counting": True,
            "metadata_match_is_not_attack_label": True,
        },
        "inputs": {
            "repository_tree": _binding(root, tree_path),
            "primary_packet": _binding(
                root,
                root / PRIMARY.relative_to(ROOT),
            ),
            "structural_audit": _binding(
                root,
                root / STRUCTURAL_AUDIT.relative_to(ROOT),
            ),
        },
        "summary": {
            "matching_metadata_datasets": len(rows),
            "already_in_frozen_primary_packet": counts.get(
                "already_in_frozen_primary_packet",
                0,
            ),
            "eligible_unlabeled_reserve": counts.get(
                "eligible_unlabeled_reserve",
                0,
            ),
            "structurally_excluded": counts.get(
                "structurally_excluded",
                0,
            ),
            "out_of_preregistered_scope": counts.get(
                "out_of_preregistered_scope",
                0,
            ),
            "unclassified": unclassified,
            "catalogue_coverage_complete": unclassified == 0,
            "new_human_gold": 0,
        },
        "datasets": rows,
    }


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _binding(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    audit = build_audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(audit["summary"], ensure_ascii=False))
    return 0 if audit["summary"]["catalogue_coverage_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
