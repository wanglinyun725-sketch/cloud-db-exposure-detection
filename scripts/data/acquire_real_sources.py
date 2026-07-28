#!/usr/bin/env python3
"""Acquire immutable upstream artifacts for RealPathBench-CD.

This script does not generate benchmark samples or labels. It downloads exact
official upstream revisions, preserves licenses, computes SHA-256 digests and
records a reproducible acquisition manifest. Raw artifacts are intentionally
ignored by Git because they can be large; the manifest and pinned URLs remain
version-controlled.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RAW_ROOT = ROOT / "data" / "real_sources" / "raw"
MANIFEST_PATH = ROOT / "data" / "real_sources" / "acquisition_manifest.json"
USER_AGENT = "CloudDB-PathBench-Research/0.1"

SOURCES = [
    {
        "source_id": "mitre_attack_stix",
        "repository": "mitre-attack/attack-stix-data",
        "commit": "a6c366439edee3a87b79cf90dc0b93f5d7975956",
        "artifacts": [
            {
                "name": "enterprise-attack.json",
                "url": (
                    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                    "a6c366439edee3a87b79cf90dc0b93f5d7975956/"
                    "enterprise-attack/enterprise-attack.json"
                ),
            },
            {
                "name": "LICENSE.txt",
                "url": (
                    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                    "a6c366439edee3a87b79cf90dc0b93f5d7975956/LICENSE.txt"
                ),
            },
        ],
    },
    {
        "source_id": "splunk_attack_data",
        "repository": "splunk/attack_data",
        "commit": "3821bdb77c66c95b4e529f62a9d00b168446d1a8",
        "artifacts": [
            {
                "name": "repository-tree.json",
                "url": (
                    "https://api.github.com/repos/splunk/attack_data/git/trees/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8?recursive=1"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/LICENSE"
                ),
            },
            {
                "name": "aws_rds_password_reset.yml",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/"
                    "datasets/attack_techniques/T1110.002/"
                    "aws_rds_password_reset/aws_rds_password_reset.yml"
                ),
                "expected_checksum": (
                    "sha256:"
                    "237786d5ce75d76fda7e6b476f5247732745a6493e058078dfa06cf82c148016"
                ),
            },
            {
                "name": "aws_rds_password_reset.json",
                "url": (
                    "https://media.githubusercontent.com/media/splunk/"
                    "attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/"
                    "datasets/attack_techniques/T1110.002/"
                    "aws_rds_password_reset/aws_cloudtrail_events.json"
                ),
                "expected_checksum": (
                    "sha256:"
                    "7015688e41e2afca485d25fcf1fc2e655402fc036e372ca0ad6d2fefc9430c1f"
                ),
            },
            {
                "name": "aws_s3_public_bucket.yml",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/"
                    "datasets/attack_techniques/T1530/"
                    "aws_s3_public_bucket/aws_s3_public_bucket.yml"
                ),
                "expected_checksum": (
                    "sha256:"
                    "943720fbe6c83e840e2397b3816315943f16b575921391b0af824c8707333d8f"
                ),
            },
            {
                "name": "aws_s3_public_bucket.json",
                "url": (
                    "https://media.githubusercontent.com/media/splunk/"
                    "attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/"
                    "datasets/attack_techniques/T1530/"
                    "aws_s3_public_bucket/aws_cloudtrail_events.json"
                ),
                "expected_checksum": (
                    "sha256:"
                    "a7812406c446a6a2c9864f2fe3b07e6b177c18b893dbd2ed0b11b649ddfc7eda"
                ),
            },
            {
                "name": "aws_snapshot_exfil.yml",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/"
                    "datasets/attack_techniques/T1537/"
                    "aws_snapshot_exfil/aws_snapshot_exfil.yml"
                ),
                "expected_checksum": (
                    "sha256:"
                    "31b0a2c4e1c0b52a4e844b47e932f121f2ad3da9230b6b7b666164ac134d09c1"
                ),
            },
            {
                "name": "aws_snapshot_exfil.json",
                "url": (
                    "https://media.githubusercontent.com/media/splunk/"
                    "attack_data/"
                    "3821bdb77c66c95b4e529f62a9d00b168446d1a8/"
                    "datasets/attack_techniques/T1537/"
                    "aws_snapshot_exfil/aws_cloudtrail_events.json"
                ),
                "expected_checksum": (
                    "sha256:"
                    "ac343623bd299b4cbd29b1d718e91b51f00da71fee4fe3de26dca83205676cca"
                ),
            },
        ],
    },
    {
        "source_id": "splunk_attack_data_2026_expansion",
        "repository": "splunk/attack_data",
        "commit": "67fe973a954cc35688ad9b4906ed6e85af5892e9",
        "artifacts": [
            {
                "name": "data.yml",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "67fe973a954cc35688ad9b4906ed6e85af5892e9/"
                    "datasets/attack_techniques/T1580/"
                    "aws_iam_excessive_list_command_usage/data.yml"
                ),
                "expected_checksum": (
                    "sha256:"
                    "32e85cd437e28c89aac8ebaca1172b7dc642fff8a0c3cc4512a81be9dcc40870"
                ),
            },
            {
                "name": "aws_iam_excessive_list_command_usage.json",
                "url": (
                    "https://media.githubusercontent.com/media/splunk/"
                    "attack_data/"
                    "67fe973a954cc35688ad9b4906ed6e85af5892e9/"
                    "datasets/attack_techniques/T1580/"
                    "aws_iam_excessive_list_command_usage/"
                    "aws_iam_excessive_list_command_usage.json"
                ),
                "expected_checksum": (
                    "sha256:"
                    "d0e597bf34919e87ff53d757766a71431847d8788ca80ffe78d8ac23bb498f35"
                ),
            },
            {
                "name": "accessdenied_data.yml",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "67fe973a954cc35688ad9b4906ed6e85af5892e9/"
                    "datasets/attack_techniques/T1580/"
                    "aws_iam_accessdenied_discovery_events/data.yml"
                ),
                "expected_checksum": (
                    "sha256:"
                    "84e385e4d04882586c229db43ae1111f20599c479bf81c0e814e00223e038c0b"
                ),
            },
            {
                "name": "aws_iam_accessdenied_discovery_events.json",
                "url": (
                    "https://media.githubusercontent.com/media/splunk/"
                    "attack_data/"
                    "67fe973a954cc35688ad9b4906ed6e85af5892e9/"
                    "datasets/attack_techniques/T1580/"
                    "aws_iam_accessdenied_discovery_events/"
                    "aws_iam_accessdenied_discovery_events.json"
                ),
                "expected_checksum": (
                    "sha256:"
                    "4f52389f17745abf5fa1cf30c055d4f9d34022fcfb8e5c2544c70177da228433"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/splunk/attack_data/"
                    "67fe973a954cc35688ad9b4906ed6e85af5892e9/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "cloudgoat",
        "repository": "RhinoSecurityLabs/cloudgoat",
        "commit": "abf1ba8f5e47d7ced750fdfa025d51c99f1a43ed",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/RhinoSecurityLabs/cloudgoat/archive/"
                    "abf1ba8f5e47d7ced750fdfa025d51c99f1a43ed.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/RhinoSecurityLabs/cloudgoat/"
                    "abf1ba8f5e47d7ced750fdfa025d51c99f1a43ed/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "cloudfoxable",
        "repository": "BishopFox/cloudfoxable",
        "commit": "fc49b7f637268031515ced9fee4b643d3e68db67",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/BishopFox/cloudfoxable/archive/"
                    "fc49b7f637268031515ced9fee4b643d3e68db67.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/BishopFox/cloudfoxable/"
                    "fc49b7f637268031515ced9fee4b643d3e68db67/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "stratus_red_team",
        "repository": "DataDog/stratus-red-team",
        "commit": "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/DataDog/stratus-red-team/archive/"
                    "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/DataDog/stratus-red-team/"
                    "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0/LICENSE"
                ),
            },
            {
                "name": "NOTICE",
                "url": (
                    "https://raw.githubusercontent.com/DataDog/stratus-red-team/"
                    "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0/NOTICE"
                ),
            },
        ],
    },
    {
        "source_id": "cloudfox",
        "repository": "BishopFox/cloudfox",
        "commit": "ba4ff4701a537750f0aa11b1fb0ffa1f545cc000",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/BishopFox/cloudfox/archive/"
                    "ba4ff4701a537750f0aa11b1fb0ffa1f545cc000.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/BishopFox/cloudfox/"
                    "ba4ff4701a537750f0aa11b1fb0ffa1f545cc000/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "otrf_security_datasets",
        "repository": "OTRF/Security-Datasets",
        "commit": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
        "artifacts": [
            {
                "name": "SDAWS-200914011940.yaml",
                "url": (
                    "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
                    "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/"
                    "datasets/atomic/_metadata/SDAWS-200914011940.yaml"
                ),
                "expected_checksum": (
                    "sha256:"
                    "541c5b7e3ab874f1eca29c14a6bb4a56c2683be5d482cb292ce63513487cd533"
                ),
            },
            {
                "name": "ec2_proxy_s3_exfiltration.zip",
                "url": (
                    "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
                    "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/"
                    "datasets/atomic/aws/collection/"
                    "ec2_proxy_s3_exfiltration.zip"
                ),
                "expected_checksum": (
                    "sha256:"
                    "83cc349afa5672ae46fc38a824946b470f2f3fa39f22889b59dce9fda43fe74d"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
                    "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE"
                ),
                "expected_checksum": (
                    "sha256:"
                    "fce88163b60d67ecabd317b75f7638233e11cbe648fe608ebbf6c10161564686"
                ),
            },
        ],
    },
    {
        "source_id": "cross_cloud_observability_2026",
        "repository": "zenodo:19933893",
        "commit": "record-19933893-v2",
        "artifacts": [
            {
                "name": "README.md",
                "url": (
                    "https://zenodo.org/api/files/"
                    "82e2549e-665e-42f4-8dde-4f78fc07e619/README.md"
                ),
                "expected_checksum": "md5:10eb94c911d603deb5353a4f9bdfa46e",
            },
            {
                "name": "attack_scripts.zip",
                "url": (
                    "https://zenodo.org/api/files/"
                    "82e2549e-665e-42f4-8dde-4f78fc07e619/"
                    "attack_scripts.zip"
                ),
                "expected_checksum": "md5:e448f9e9eafb7482b735c76d2d4ef0d0",
            },
            {
                "name": "aws_logs_redacted.zip",
                "url": (
                    "https://zenodo.org/api/files/"
                    "82e2549e-665e-42f4-8dde-4f78fc07e619/"
                    "aws_logs_redacted.zip"
                ),
                "expected_checksum": "md5:f83ebd4892dcf4d349f51c1c477408dc",
            },
            {
                "name": "azure_logs_redacted.zip",
                "url": (
                    "https://zenodo.org/api/files/"
                    "82e2549e-665e-42f4-8dde-4f78fc07e619/"
                    "azure_logs_redacted.zip"
                ),
                "expected_checksum": "md5:e4e3359913d45fa86739ab39f21123b4",
            },
            {
                "name": "gcp_logs_redacted.zip",
                "url": (
                    "https://zenodo.org/api/files/"
                    "82e2549e-665e-42f4-8dde-4f78fc07e619/"
                    "gcp_logs_redacted.zip"
                ),
                "expected_checksum": "md5:1bd7f6a204359e995e5b140eea9e9d12",
            },
            {
                "name": "log_analysis.zip",
                "url": (
                    "https://zenodo.org/api/files/"
                    "82e2549e-665e-42f4-8dde-4f78fc07e619/"
                    "log_analysis.zip"
                ),
                "expected_checksum": "md5:c57994c6e199cbbf8b091ddcd139515a",
            },
        ],
    },
    {
        "source_id": "cloud_incident_reports_2016_2024",
        "repository": "zenodo:14010282",
        "commit": "record-14010282-v1",
        "artifacts": [
            {
                "name": "data.zip",
                "url": (
                    "https://zenodo.org/api/records/14010282/files/"
                    "data.zip/content"
                ),
                "expected_checksum": "md5:1bb311c9d08c4853a1373e5370231d54",
            },
        ],
    },
    {
        "source_id": "awsgoat",
        "repository": "ine-labs/AWSGoat",
        "commit": "b24869ad455ed8d1393d00ecdc15ee638d1c1332",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/ine-labs/AWSGoat/archive/"
                    "b24869ad455ed8d1393d00ecdc15ee638d1c1332.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/ine-labs/AWSGoat/"
                    "b24869ad455ed8d1393d00ecdc15ee638d1c1332/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "azuregoat",
        "repository": "ine-labs/AzureGoat",
        "commit": "b97045952e6df00de735a7f27fd7c4994dcfe8c0",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/ine-labs/AzureGoat/archive/"
                    "b97045952e6df00de735a7f27fd7c4994dcfe8c0.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/ine-labs/AzureGoat/"
                    "b97045952e6df00de735a7f27fd7c4994dcfe8c0/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "gcpgoat",
        "repository": "ine-labs/GCPGoat",
        "commit": "44605c4bff4b2da7611dfce78696bb53db6d8c54",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/ine-labs/GCPGoat/archive/"
                    "44605c4bff4b2da7611dfce78696bb53db6d8c54.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/ine-labs/GCPGoat/"
                    "44605c4bff4b2da7611dfce78696bb53db6d8c54/LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "iam_vulnerable",
        "repository": "BishopFox/iam-vulnerable",
        "commit": "0f298666f9b7cfa01488b86912afdb211773188a",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/BishopFox/iam-vulnerable/archive/"
                    "0f298666f9b7cfa01488b86912afdb211773188a.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/BishopFox/"
                    "iam-vulnerable/"
                    "0f298666f9b7cfa01488b86912afdb211773188a/"
                    "LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "terragoat",
        "repository": "bridgecrewio/terragoat",
        "commit": "729f8da62c6a85ce4af5ad3d123de97776d954c4",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/bridgecrewio/terragoat/archive/"
                    "729f8da62c6a85ce4af5ad3d123de97776d954c4.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/bridgecrewio/"
                    "terragoat/"
                    "729f8da62c6a85ce4af5ad3d123de97776d954c4/"
                    "LICENSE"
                ),
            },
        ],
    },
    {
        "source_id": "terraform_iam_policy_validator",
        "repository": "awslabs/terraform-iam-policy-validator",
        "commit": "f75804eba3f6bb9e10e3350be33a1caee67b32a3",
        "artifacts": [
            {
                "name": "snapshot.zip",
                "url": (
                    "https://github.com/awslabs/"
                    "terraform-iam-policy-validator/archive/"
                    "f75804eba3f6bb9e10e3350be33a1caee67b32a3.zip"
                ),
            },
            {
                "name": "LICENSE",
                "url": (
                    "https://raw.githubusercontent.com/awslabs/"
                    "terraform-iam-policy-validator/"
                    "f75804eba3f6bb9e10e3350be33a1caee67b32a3/"
                    "LICENSE"
                ),
            },
        ],
    },
]


def main() -> None:
    RAW_ROOT.mkdir(parents=True, exist_ok=True)
    records = []
    for source in SOURCES:
        destination = RAW_ROOT / source["source_id"] / source["commit"]
        destination.mkdir(parents=True, exist_ok=True)
        print(f"[{source['source_id']}] {source['commit']}")
        artifacts = []
        for spec in source["artifacts"]:
            path = destination / spec["name"]
            result = download(
                spec["url"],
                path,
                expected_checksum=spec.get("expected_checksum"),
            )
            artifacts.append(
                {
                    "name": spec["name"],
                    "relative_path": path.relative_to(ROOT).as_posix(),
                    "url": spec["url"],
                    **(
                        {"upstream_checksum": spec["expected_checksum"]}
                        if spec.get("expected_checksum")
                        else {}
                    ),
                    **result,
                }
            )
            print(
                f"  {result['status']:>10} {spec['name']}: "
                f"{result['bytes']} bytes {result['sha256'][:12]}..."
            )
        records.append(
            {
                "source_id": source["source_id"],
                "repository": source["repository"],
                "commit": source["commit"],
                "artifacts": artifacts,
            }
        )

    manifest = {
        "manifest_version": "0.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": Path(__file__).relative_to(ROOT).as_posix(),
        "policy": {
            "sample_generation": False,
            "label_generation": False,
            "raw_artifacts_immutable": True,
            "hash_algorithm": "SHA-256",
        },
        "sources": records,
    }
    _atomic_write_json(MANIFEST_PATH, manifest)
    print(f"wrote {MANIFEST_PATH}")


def download(
    url: str,
    path: Path,
    *,
    expected_checksum: str | None = None,
) -> dict:
    if path.exists():
        _verify_expected_checksum(path, expected_checksum)
        return {
            "status": "verified",
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }

    headers = {"User-Agent": USER_AGENT}
    if "api.github.com" in url:
        headers["Accept"] = "application/vnd.github+json"
    request = urllib.request.Request(url, headers=headers)
    fd, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".part",
    )
    os.close(fd)
    temp_path = Path(temp_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            with temp_path.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
        if size == 0:
            raise RuntimeError(f"empty response from {url}")
        _verify_expected_checksum(temp_path, expected_checksum)
        shutil.move(str(temp_path), path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return {"status": "downloaded", "bytes": size, "sha256": digest.hexdigest()}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_expected_checksum(
    path: Path,
    expected_checksum: str | None,
) -> None:
    if expected_checksum is None:
        return
    algorithm, expected = expected_checksum.split(":", 1)
    if algorithm.lower() == "md5":
        digest = hashlib.md5()  # noqa: S324 - upstream integrity checksum
    elif algorithm.lower() == "sha256":
        digest = hashlib.sha256()
    else:
        raise ValueError(f"unsupported upstream checksum: {algorithm}")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected.lower():
        raise RuntimeError(
            f"upstream checksum mismatch for {path.name}: "
            f"expected {expected_checksum}, got {algorithm.lower()}:{actual}"
        )


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


if __name__ == "__main__":
    main()
