#!/usr/bin/env python3
"""Build provenance-qualified lineages without producing benchmark gold."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
from zipfile import ZipFile

import yaml


ROOT = (
    Path(".")
    if Path("data/real_sources").is_dir() and Path("src/data").is_dir()
    else Path(__file__).resolve().parents[2]
)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.candidate_lineage_catalog import (  # noqa: E402
    canonical_json_sha256,
    sha256_file,
)


REAL_ROOT = ROOT / "data" / "real_sources"
ACQUISITION_MANIFEST = REAL_ROOT / "acquisition_manifest.json"
SOURCE_AUDIT = REAL_ROOT / "source_audit.json"
ATOMIC_MANIFEST = REAL_ROOT / "atomic_red_team_manifest_v1.json"
OUTPUT = REAL_ROOT / "candidate_lineage_catalog_v1.json"

DATA_TERMS = {
    "backup",
    "bigquery",
    "blob",
    "bucket",
    "credential",
    "data",
    "database",
    "dynamodb",
    "email",
    "exfil",
    "key vault",
    "keyvault",
    "mail",
    "object",
    "rds",
    "s3",
    "secret",
    "snapshot",
    "sql",
    "storage",
    "volume",
}
PLATFORM_MAP = {
    "iaas:aws": "AWS",
    "iaas:azure": "AZURE",
    "azure-ad": "AZURE",
    "iaas:gcp": "GCP",
}
SERVICE_PATTERNS = {
    "object_storage": ("s3", "bucket", "blob", "storage account", "object"),
    "database": ("database", "rds", "sql", "dynamodb", "bigquery"),
    "secret_store": ("secret", "key vault", "keyvault", "credential"),
    "block_storage": ("snapshot", "volume", "disk", "ami"),
    "identity_and_access": (
        "iam", "role", "permission", "service account", "access key",
    ),
    "audit_telemetry": ("cloudtrail", "audit log", "eventhub"),
    "mail_data": ("mail", "email", "exchange", "office 365"),
}


def _artifact_map(manifest: dict) -> dict[str, dict]:
    return {
        artifact["upstream_path"]: artifact
        for artifact in manifest["source"]["artifacts"]
    }


def _acquisition_sources() -> dict[str, dict]:
    manifest = json.loads(
        ACQUISITION_MANIFEST.read_text(encoding="utf-8")
    )
    return {row["source_id"]: row for row in manifest["sources"]}


def _artifact(source: dict, name: str) -> dict:
    return next(row for row in source["artifacts"] if row["name"] == name)


def _zip_member_evidence(artifact: dict, member: str) -> dict:
    path = ROOT / artifact["relative_path"]
    with ZipFile(path) as archive:
        payload = archive.read(member)
    return {
        "artifact_path": artifact["relative_path"],
        "artifact_sha256": artifact["sha256"],
        "locator_type": "zip_member",
        "locator": member,
        "content_sha256": hashlib.sha256(payload).hexdigest(),
        "upstream_url": artifact["url"] + f"#member={member}",
    }


def _source_row(
    source: dict,
    *,
    publisher: str,
    upstream_url: str,
    source_type: str,
    license_name: str,
) -> dict:
    return {
        "source_id": source["source_id"],
        "publisher": publisher,
        "upstream_url": upstream_url,
        "source_type": source_type,
        "license": license_name,
        "version_or_commit": source["commit"],
    }


def _atomic_platforms(values: list[str]) -> list[str]:
    return sorted({PLATFORM_MAP[value] for value in values if value in PLATFORM_MAP})


def _service_facets(text: str) -> list[str]:
    normalized = text.casefold()
    facets = [
        service for service, patterns in SERVICE_PATTERNS.items()
        if any(pattern in normalized for pattern in patterns)
    ]
    return sorted(facets or ["cloud_data_control_plane"])


def _is_atomic_in_scope(test: dict) -> bool:
    platforms = _atomic_platforms(test.get("supported_platforms", []) or [])
    # Every official cloud-platform Atomic is an executable adversary action,
    # permission change, discovery step, or impact action and is in scope for
    # a progressively discovered cloud attack path.  It remains candidate-only
    # until executed and tied to a path oracle.
    return bool(platforms)


def build_atomic_source_and_lineages() -> tuple[dict, list[dict]]:
    manifest = json.loads(ATOMIC_MANIFEST.read_text(encoding="utf-8"))
    source = manifest["source"]
    artifacts = _artifact_map(manifest)
    license_artifact = artifacts["LICENSE.txt"]
    source_row = {
        "source_id": "atomic_red_team",
        "publisher": "Red Canary",
        "upstream_url": source["upstream_url"],
        "source_type": "executable_attack_emulation",
        "license": "MIT",
        "version_or_commit": source["commit"],
        "license_artifact_path": license_artifact["relative_path"],
        "license_sha256": license_artifact["sha256"],
    }
    lineages = []
    seen_guids = set()
    for upstream_path, artifact in sorted(artifacts.items()):
        if not re.fullmatch(r"atomics/T[^/]+/T[^/]+\.yaml", upstream_path):
            continue
        path = ROOT / artifact["relative_path"]
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for index, test in enumerate(document.get("atomic_tests", []) or []):
            if not _is_atomic_in_scope(test):
                continue
            guid = test.get("auto_generated_guid")
            if not guid or guid in seen_guids:
                continue
            seen_guids.add(guid)
            platforms = _atomic_platforms(
                test.get("supported_platforms", []) or []
            )
            text = " ".join([
                str(test.get("name", "")),
                str(test.get("description", "")),
                str(test.get("executor", "")),
            ])
            lineages.append({
                "lineage_id": f"atomic-red-team:{guid}",
                "source_id": "atomic_red_team",
                "title": test["name"],
                "tier": "executable_lab",
                "platforms": platforms,
                "services": _service_facets(text),
                "independence_key": guid,
                "independence_rationale": (
                    "Official Atomic Red Team auto_generated_guid identifies "
                    "one executable test, including command, prerequisites "
                    "and cleanup; repeated executions remain one lineage."
                ),
                "near_duplicate_fingerprint": (
                    f"atomic:{document['attack_technique']}:"
                    f"{'+'.join(platforms)}:{'+'.join(_service_facets(text))}"
                ),
                "attack_technique": document["attack_technique"],
                "upstream_test_index": index,
                "generated_event": False,
                "generated_label": False,
                "gold_status": "candidate_only",
                "evidence": [{
                    "artifact_path": artifact["relative_path"],
                    "artifact_sha256": artifact["sha256"],
                    "locator_type": "yaml_atomic_guid",
                    "locator": guid,
                    "content_sha256": canonical_json_sha256(test),
                    "upstream_url": artifact["url"] + f"#atomic-test-{index + 1}",
                }],
            })
    return source_row, lineages


def build_mitre_source_and_lineages() -> tuple[dict, list[dict]]:
    acquisition = json.loads(
        ACQUISITION_MANIFEST.read_text(encoding="utf-8")
    )
    source_manifest = next(
        row for row in acquisition["sources"]
        if row["source_id"] == "mitre_attack_stix"
    )
    artifact = next(
        row for row in source_manifest["artifacts"]
        if row["name"] == "enterprise-attack.json"
    )
    audit = json.loads(SOURCE_AUDIT.read_text(encoding="utf-8"))
    candidates = audit["catalogues"]["mitre_attack_stix"]
    bundle_path = ROOT / artifact["relative_path"]
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    by_id = {row.get("id"): row for row in bundle.get("objects", [])}
    source_row = {
        "source_id": "mitre_attack_stix",
        "publisher": "MITRE",
        "upstream_url": "https://github.com/mitre-attack/attack-stix-data",
        "source_type": "threat_intelligence",
        "license": "MITRE ATT&CK Terms of Use with attribution",
        "version_or_commit": source_manifest["commit"],
    }
    lineages = []
    for candidate in candidates:
        relationship = by_id[candidate["candidate_id"]]
        source_object = by_id.get(candidate["source_object_id"], {})
        provider_platforms = []
        raw_platforms = candidate.get("platforms", [])
        # The broad upstream audit also routes endpoint techniques such as
        # exfiltration to consumer cloud drives.  The 500-lineage catalogue is
        # about cloud control/data planes, so ATT&CK procedures must carry the
        # official IaaS platform marker.  Text keywords alone are insufficient.
        if "IaaS" not in raw_platforms:
            continue
        description = relationship.get("description", "")
        lowered = description.casefold()
        for term, platform in (
            ("aws", "AWS"), ("amazon", "AWS"),
            ("azure", "AZURE"), ("microsoft", "AZURE"),
            ("gcp", "GCP"), ("google cloud", "GCP"),
        ):
            if term in lowered:
                provider_platforms.append(platform)
        # ATT&CK's IaaS platform is provider-neutral.  Use CROSS_CLOUD only
        # when the procedure text itself does not identify one provider.
        platforms = sorted(set(provider_platforms))
        if not platforms and "IaaS" in raw_platforms:
            platforms = ["CROSS_CLOUD"]
        elif not platforms:
            platforms = ["CROSS_CLOUD"]
        fingerprint = (
            f"mitre:{candidate.get('source_object_type')}:"
            f"{candidate.get('source_object_id')}:"
            f"{candidate.get('technique_id')}"
        )
        lineages.append({
            "lineage_id": f"mitre:{candidate['candidate_id']}",
            "source_id": "mitre_attack_stix",
            "title": (
                f"{candidate.get('source_name')} uses "
                f"{candidate.get('technique_name')}"
            ),
            "tier": "cti_procedure",
            "platforms": platforms,
            "services": _service_facets(
                " ".join([
                    candidate.get("technique_name") or "",
                    description,
                ])
            ),
            "independence_key": candidate["candidate_id"],
            "independence_rationale": (
                "One immutable ATT&CK STIX uses relationship between the "
                "named actor/tool/malware/campaign and technique; citations "
                "are retained in the relationship object."
            ),
            "near_duplicate_fingerprint": fingerprint,
            "source_object_id": candidate.get("source_object_id"),
            "source_object_type": source_object.get("type"),
            "technique_id": candidate.get("technique_id"),
            "generated_event": False,
            "generated_label": False,
            "gold_status": "candidate_only",
            "evidence": [{
                "artifact_path": artifact["relative_path"],
                "artifact_sha256": artifact["sha256"],
                "locator_type": "stix_object",
                "locator": candidate["candidate_id"],
                "content_sha256": canonical_json_sha256(relationship),
                "upstream_url": (
                    artifact["url"]
                    + f"#object={candidate['candidate_id']}"
                ),
            }],
        })
    return source_row, lineages


def build_snapshot_lab_source(
    source_id: str,
    *,
    publisher: str,
    upstream_url: str,
    license_name: str,
    tier: str = "executable_lab",
) -> tuple[dict, list[dict]]:
    acquisition = _acquisition_sources()
    source = acquisition[source_id]
    snapshot = _artifact(source, "snapshot.zip")
    audit = json.loads(SOURCE_AUDIT.read_text(encoding="utf-8"))
    candidates = audit["catalogues"][source_id]
    source_row = _source_row(
        source,
        publisher=publisher,
        upstream_url=upstream_url,
        source_type="executable_cloud_lab",
        license_name=license_name,
    )
    platform_map = {
        "AWS": "AWS",
        "AZURE": "AZURE",
        "GCP": "GCP",
        "azure": "AZURE",
        "entra-id": "AZURE",
    }
    lineages = []
    for candidate in candidates:
        raw_platform = candidate.get("platform")
        if raw_platform not in platform_map:
            # Provider-neutral Kubernetes techniques are outside this
            # AWS/Azure/GCP catalogue unless tied to a provider artifact.
            continue
        member = (
            candidate.get("manifest_path")
            or candidate.get("documentation_path")
        )
        with ZipFile(ROOT / snapshot["relative_path"]) as archive:
            content = archive.read(member).decode("utf-8", errors="replace")
        identifier = (
            candidate.get("scenario")
            or candidate.get("challenge")
            or candidate.get("technique")
            or candidate["candidate_id"]
        )
        services = _service_facets(f"{identifier} {content}")
        lineages.append({
            "lineage_id": candidate["candidate_id"],
            "source_id": source_id,
            "title": str(identifier),
            "tier": tier,
            "platforms": [platform_map[raw_platform]],
            "services": services,
            "independence_key": candidate["candidate_id"],
            "independence_rationale": (
                "One official upstream scenario, challenge, or attack "
                "technique identifier; its repeated deployments and runs "
                "remain one lineage."
            ),
            "near_duplicate_fingerprint": (
                f"lab:{platform_map[raw_platform]}:"
                f"{'+'.join(services)}:{str(identifier).casefold()}"
            ),
            "generated_event": False,
            "generated_label": False,
            "gold_status": "candidate_only",
            "evidence": [_zip_member_evidence(snapshot, member)],
        })
    return source_row, lineages


def build_stratus_full_source() -> tuple[dict, list[dict]]:
    acquisition = _acquisition_sources()
    source = acquisition["stratus_red_team"]
    snapshot = _artifact(source, "snapshot.zip")
    source_row = _source_row(
        source,
        publisher="Datadog",
        upstream_url="https://github.com/DataDog/stratus-red-team",
        source_type="executable_attack_emulation",
        license_name="Apache-2.0",
    )
    platform_map = {"AWS": "AWS", "azure": "AZURE", "GCP": "GCP", "entra-id": "AZURE"}
    pattern = re.compile(
        r"/docs/attack-techniques/(AWS|azure|GCP|entra-id)/([^/]+)\.md$"
    )
    lineages = []
    with ZipFile(ROOT / snapshot["relative_path"]) as archive:
        members = sorted(archive.namelist())
        for member in members:
            match = pattern.search(member)
            if not match or member.casefold().endswith("/index.md"):
                continue
            raw_platform, technique = match.groups()
            content = archive.read(member).decode("utf-8", errors="replace")
            services = _service_facets(f"{technique} {content}")
            lineages.append({
                "lineage_id": f"stratus:{technique}",
                "source_id": "stratus_red_team",
                "title": technique,
                "tier": "executable_lab",
                "platforms": [platform_map[raw_platform]],
                "services": services,
                "independence_key": f"stratus:{technique}",
                "independence_rationale": (
                    "One official Stratus attack-technique identifier with "
                    "documented prerequisites, detonation and cleanup; "
                    "repeated detonations never increase N."
                ),
                "near_duplicate_fingerprint": (
                    f"stratus:{platform_map[raw_platform]}:{technique}"
                ),
                "generated_event": False,
                "generated_label": False,
                "gold_status": "candidate_only",
                "evidence": [_zip_member_evidence(snapshot, member)],
            })
    return source_row, lineages


def build_iam_vulnerable_source() -> tuple[dict, list[dict]]:
    acquisition = _acquisition_sources()
    source = acquisition["iam_vulnerable"]
    snapshot = _artifact(source, "snapshot.zip")
    source_row = _source_row(
        source,
        publisher="Bishop Fox",
        upstream_url="https://github.com/BishopFox/iam-vulnerable",
        source_type="executable_iam_path_library",
        license_name="MIT",
    )
    pattern = re.compile(
        r"/modules/free-resources/privesc-paths/"
        r"(privesc[^/]+\.tf)$",
        re.I,
    )
    excluded_helpers = {"privesc-paths/variables.tf", "service-linked-role-common.tf"}
    lineages = []
    with ZipFile(ROOT / snapshot["relative_path"]) as archive:
        for member in sorted(archive.namelist()):
            match = pattern.search(member)
            if not match or any(member.endswith(value) for value in excluded_helpers):
                continue
            filename = match.group(1)
            content = archive.read(member).decode("utf-8", errors="replace")
            # A deployable path definition must create both an attacker user
            # and at least one policy; helpers and variable files are excluded.
            if "aws_iam_user" not in content or "aws_iam_policy" not in content:
                continue
            mechanism = filename.removesuffix(".tf")
            services = _service_facets(f"{mechanism} {content}")
            lineages.append({
                "lineage_id": f"iam-vulnerable:{mechanism}",
                "source_id": "iam_vulnerable",
                "title": mechanism,
                "tier": "deterministic_configuration",
                "platforms": ["AWS"],
                "services": sorted(set(["identity_and_access", *services])),
                "independence_key": f"iam-vulnerable:{mechanism}",
                "independence_rationale": (
                    "One official Terraform privilege-escalation mechanism "
                    "with its own attacker principal and permission policy; "
                    "supporting resources are not counted separately."
                ),
                "near_duplicate_fingerprint": f"iam-vulnerable:{mechanism.casefold()}",
                "generated_event": False,
                "generated_label": False,
                "gold_status": "candidate_only",
                "evidence": [_zip_member_evidence(snapshot, member)],
            })
    return source_row, lineages


def build_cross_cloud_source_and_lineages() -> tuple[dict, list[dict]]:
    acquisition = _acquisition_sources()
    source = acquisition["cross_cloud_observability_2026"]
    artifacts = {row["name"]: row for row in source["artifacts"]}
    audit = json.loads(SOURCE_AUDIT.read_text(encoding="utf-8"))
    candidates = audit["catalogues"]["cross_cloud_observability_2026"]
    grouped: dict[str, list[dict]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate["attack"], []).append(candidate)
    source_row = _source_row(
        source,
        publisher="Zenodo record authors",
        upstream_url="https://doi.org/10.5281/zenodo.19933893",
        source_type="published_attack_telemetry",
        license_name="CC-BY-4.0",
    )
    lineages = []
    for attack, rows in sorted(grouped.items()):
        platforms = sorted(row["platform"] for row in rows)
        evidence = []
        for row in sorted(rows, key=lambda item: item["platform"]):
            example = row["raw_log_examples"][0]
            archive_name, member = example.split("#", 1)
            evidence.append(_zip_member_evidence(artifacts[archive_name], member))
        services = _service_facets(attack.replace("_", " "))
        lineages.append({
            "lineage_id": f"crosscloud-family:{attack}",
            "source_id": "cross_cloud_observability_2026",
            "title": attack,
            "tier": "published_runtime_telemetry",
            "platforms": platforms,
            "services": services,
            "independence_key": f"crosscloud-family:{attack}",
            "independence_rationale": (
                "One upstream attack family is one lineage across AWS, "
                "Azure and GCP; paired payload/no-payload runs and platform "
                "replicas never increase N."
            ),
            "near_duplicate_fingerprint": f"crosscloud:{attack}",
            "runtime_representation_count": len(rows),
            "generated_event": False,
            "generated_label": False,
            "gold_status": "candidate_only",
            "evidence": evidence,
        })
    return source_row, lineages


def main() -> None:
    sources = []
    lineages = []
    builders = (
        build_mitre_source_and_lineages,
        build_atomic_source_and_lineages,
        lambda: build_snapshot_lab_source(
            "cloudgoat",
            publisher="Rhino Security Labs",
            upstream_url="https://github.com/RhinoSecurityLabs/cloudgoat",
            license_name="BSD-3-Clause",
        ),
        lambda: build_snapshot_lab_source(
            "cloudfoxable",
            publisher="Bishop Fox",
            upstream_url="https://github.com/BishopFox/cloudfoxable",
            license_name="MIT",
        ),
        build_stratus_full_source,
        build_iam_vulnerable_source,
        build_cross_cloud_source_and_lineages,
    )
    for builder in builders:
        source, rows = builder()
        sources.append(source)
        lineages.extend(rows)
    result = {
        "catalog_version": "1.0.0-dev1",
        "policy_path": "configs/candidate_lineage_500_policy_v1.yaml",
        "policy": {
            "candidate_is_gold": False,
            "generated_events": 0,
            "generated_labels": 0,
            "selection_note": (
                "This development catalogue starts with full ATT&CK "
                "cloud-data procedure relationships plus conservative "
                "cloud/data Atomic Red Team tests. Other existing and new "
                "sources are added only after the same hard gates."
            ),
        },
        "sources": sources,
        "lineages": sorted(lineages, key=lambda row: row["lineage_id"]),
        "build_summary": {
            "lineages": len(lineages),
            "sources": len(sources),
            "tiers": dict(Counter(row["tier"] for row in lineages)),
            "platforms": dict(Counter(
                platform
                for row in lineages
                for platform in row["platforms"]
            )),
        },
    }
    OUTPUT.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["build_summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
