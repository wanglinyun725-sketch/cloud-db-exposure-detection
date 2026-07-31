#!/usr/bin/env python3
"""Download raw telemetry for the human-annotation pilot.

Only upstream files referenced by selected Splunk Attack Data candidates are
downloaded. The script preserves repository-relative paths and records hashes;
it does not transform observations or create labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REAL_ROOT = ROOT / "data" / "real_sources"
AUDIT = REAL_ROOT / "source_audit.json"
ACQUISITION = REAL_ROOT / "acquisition_manifest.json"
OUT = REAL_ROOT / "pilot_telemetry_manifest.json"
USER_AGENT = "CloudDB-PathBench-Research/0.1"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scope",
        choices=("pilot", "all"),
        default="pilot",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    acquisition = json.loads(ACQUISITION.read_text(encoding="utf-8"))
    commit = next(
        source["commit"]
        for source in acquisition["sources"]
        if source["source_id"] == "splunk_attack_data"
    )
    tree_path = next(
        ROOT / artifact["relative_path"]
        for source in acquisition["sources"]
        if source["source_id"] == "splunk_attack_data"
        for artifact in source["artifacts"]
        if artifact["name"] == "repository-tree.json"
    )
    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    blob_index = {
        item["path"]: item
        for item in tree.get("tree", [])
        if item.get("type") == "blob"
    }
    catalogue = {
        item["candidate_id"]: item
        for item in audit["catalogues"]["splunk_attack_data"]
    }
    if args.scope == "all":
        selected_ids = set(catalogue)
    else:
        selected_ids = {
            item["candidate_id"]
            for item in audit["pilot_annotation_candidates"]
            if item["source_id"] == "splunk_attack_data"
        }

    records = []
    for candidate_id in sorted(selected_ids):
        candidate = catalogue[candidate_id]
        files = [
            *candidate.get("metadata_files", []),
            *candidate.get("observation_files", []),
        ]
        artifacts = []
        print(f"[{candidate_id}]")
        for upstream_path in files:
            tree_item = blob_index[upstream_path]
            blob_sha = tree_item["sha"]
            quoted_path = urllib.parse.quote(upstream_path, safe="/")
            blob_url = (
                "https://raw.githubusercontent.com/splunk/attack_data/"
                f"{commit}/{quoted_path}"
            )
            blob = fetch_raw_blob(blob_url)
            destination = (
                REAL_ROOT
                / "raw"
                / "splunk_attack_data"
                / commit
                / "selected"
                / Path(*PurePathParts(upstream_path))
            )
            lfs = parse_lfs_pointer(blob)
            if lfs:
                pointer_path = destination.with_name(destination.name + ".lfs-pointer")
                pointer_result = write_bytes(blob, pointer_path)
                resolved_url = (
                    "https://media.githubusercontent.com/media/splunk/attack_data/"
                    f"{commit}/{quoted_path}"
                )
                result = download(
                    resolved_url,
                    destination,
                    expected_sha256=lfs["sha256"],
                    expected_bytes=lfs["bytes"],
                )
                result.update(
                    {
                        "storage": "git_lfs",
                        "git_blob_sha": blob_sha,
                        "git_blob_url": blob_url,
                        "lfs_pointer_relative_path": pointer_path.relative_to(ROOT).as_posix(),
                        "lfs_pointer_sha256": pointer_result["sha256"],
                        "lfs_oid_sha256": lfs["sha256"],
                        "lfs_bytes": lfs["bytes"],
                        "resolved_url": resolved_url,
                    }
                )
            else:
                result = write_bytes(blob, destination)
                result.update(
                    {
                        "storage": "git_blob",
                        "git_blob_sha": blob_sha,
                        "git_blob_url": blob_url,
                    }
                )
            artifacts.append(
                {
                    "upstream_path": upstream_path,
                    "relative_path": destination.relative_to(ROOT).as_posix(),
                    **result,
                }
            )
            print(
                f"  {result['status']:>10} {upstream_path} "
                f"{result['bytes']} bytes {result['sha256'][:12]}..."
            )
        records.append(
            {
                "candidate_id": candidate_id,
                "source_id": "splunk_attack_data",
                "commit": commit,
                "artifacts": artifacts,
            }
        )

    output = {
        "manifest_version": "0.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "generated_samples": 0,
            "generated_labels": 0,
            "transformed_observations": 0,
            "hash_algorithm": "SHA-256",
        },
        "candidates": records,
    }
    output_path = args.output or (
        OUT
        if args.scope == "pilot"
        else REAL_ROOT / "splunk_full_telemetry_manifest.json"
    )
    output_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {output_path}")


def PurePathParts(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.replace("\\", "/").split("/") if part)


def fetch_raw_blob(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read()
    if not payload:
        raise RuntimeError(f"empty raw Git blob from {url}")
    return payload


def parse_lfs_pointer(blob: bytes) -> dict | None:
    if not blob.startswith(b"version https://git-lfs.github.com/spec/v1"):
        return None
    text = blob.decode("utf-8")
    digest_match = re_search(r"^oid sha256:([0-9a-f]{64})$", text)
    size_match = re_search(r"^size ([0-9]+)$", text)
    if not digest_match or not size_match:
        raise RuntimeError("malformed Git LFS pointer")
    return {"sha256": digest_match, "bytes": int(size_match)}


def re_search(pattern: str, text: str) -> str | None:
    import re

    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def write_bytes(payload: bytes, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected = hashlib.sha256(payload).hexdigest()
    if destination.exists():
        actual = sha256_file(destination)
        if actual != expected:
            raise RuntimeError(f"existing file hash mismatch: {destination}")
        return {
            "status": "verified",
            "bytes": destination.stat().st_size,
            "sha256": actual,
        }
    fd, temp_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".part",
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_bytes(payload)
        shutil.move(str(temp_path), destination)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return {"status": "downloaded", "bytes": len(payload), "sha256": expected}


def download(
    url: str,
    destination: Path,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        digest = sha256_file(destination)
        if expected_sha256 is not None and digest != expected_sha256:
            raise RuntimeError(f"existing LFS object hash mismatch: {destination}")
        if expected_bytes is not None and destination.stat().st_size != expected_bytes:
            raise RuntimeError(f"existing LFS object size mismatch: {destination}")
        return {
            "status": "verified",
            "bytes": destination.stat().st_size,
            "sha256": digest,
        }
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    fd, temp_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".part",
    )
    os.close(fd)
    temp_path = Path(temp_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
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
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise RuntimeError(
                f"LFS SHA-256 mismatch for {url}: "
                f"{digest.hexdigest()} != {expected_sha256}"
            )
        if expected_bytes is not None and size != expected_bytes:
            raise RuntimeError(
                f"LFS size mismatch for {url}: {size} != {expected_bytes}"
            )
        shutil.move(str(temp_path), destination)
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


if __name__ == "__main__":
    main()
