#!/usr/bin/env python3
"""Acquire only immutable Atomic Red Team YAML definitions and its license.

No attack is executed and no event or benchmark label is generated.  The
default transport downloads individual files from a pinned upstream commit;
``--git-repo`` is an equivalent offline path for a verified local Git object
database at the same commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

import yaml


ROOT = (
    Path(".")
    if Path("data/real_sources").is_dir() and Path("src/data").is_dir()
    else Path(__file__).resolve().parents[2]
)
RAW_ROOT = ROOT / "data" / "real_sources" / "raw"
OUTPUT = ROOT / "data" / "real_sources" / "atomic_red_team_manifest_v1.json"
REPOSITORY = "redcanaryco/atomic-red-team"
COMMIT = "1ba1dd8d9ce6f74700f7aec2e60de5632f667f03"
TREE_URL = f"https://api.github.com/repos/{REPOSITORY}/git/trees/{COMMIT}?recursive=1"
RAW_PREFIX = f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/"
YAML_PATTERN = re.compile(r"atomics/T[^/]+/T[^/]+\.yaml$")
CLOUD_PLATFORMS = {"iaas:aws", "iaas:azure", "iaas:gcp", "azure-ad"}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _request(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CloudDB-PathBench-Research/0.2",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = response.read()
    if not payload:
        raise RuntimeError(f"empty response from {url}")
    return payload


def _git(repo: Path, path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), "show", f"{COMMIT}:{path}"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return completed.stdout


def _git_paths(repo: Path) -> list[str]:
    head = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if head != COMMIT:
        raise RuntimeError(f"local Git HEAD {head} does not match {COMMIT}")
    output = subprocess.check_output(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", COMMIT],
        text=True,
    )
    return output.splitlines()


def _write_immutable(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = _sha256(payload)
    if path.exists():
        existing = path.read_bytes()
        if _sha256(existing) != digest:
            raise RuntimeError(f"immutable artifact differs: {path}")
        return digest
    fd, temp_name = tempfile.mkstemp(dir=path.parent, suffix=".part")
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_bytes(payload)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return digest


def _contains_cloud_test(payload: bytes) -> bool:
    document = yaml.safe_load(payload.decode("utf-8")) or {}
    return any(
        set(test.get("supported_platforms", []) or []) & CLOUD_PLATFORMS
        for test in document.get("atomic_tests", []) or []
    )


def acquire(git_repo: Path | None = None) -> dict:
    destination = RAW_ROOT / "atomic_red_team" / COMMIT
    if git_repo is None:
        tree_payload = _request(TREE_URL)
        tree = json.loads(tree_payload)
        paths = [item["path"] for item in tree["tree"] if item["type"] == "blob"]
        fetch = lambda path: _request(RAW_PREFIX + path)  # noqa: E731
    else:
        paths = _git_paths(git_repo)
        tree = {
            "sha": COMMIT,
            "truncated": False,
            "tree": [{"path": path, "type": "blob"} for path in paths],
            "transport_note": "reconstructed from verified local Git tree",
        }
        tree_payload = json.dumps(
            tree, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        fetch = lambda path: _git(git_repo, path)  # noqa: E731

    yaml_paths = sorted(path for path in paths if YAML_PATTERN.fullmatch(path))
    # Selection is based only on the official supported_platforms field.  A
    # later catalogue step applies the narrower cloud-data relevance gate.
    yaml_payloads = {}
    for path in yaml_paths:
        payload = fetch(path)
        if _contains_cloud_test(payload):
            yaml_payloads[path] = payload
    selected_paths = ["LICENSE.txt", *sorted(yaml_payloads)]
    artifacts = []
    tree_path = destination / "repository-tree.json"
    tree_digest = _write_immutable(tree_path, tree_payload)
    artifacts.append({
        "name": "repository-tree.json",
        "upstream_path": "$git-tree",
        "relative_path": tree_path.relative_to(ROOT).as_posix(),
        "url": TREE_URL,
        "bytes": tree_path.stat().st_size,
        "sha256": tree_digest,
    })
    for upstream_path in selected_paths:
        payload = (
            yaml_payloads[upstream_path]
            if upstream_path in yaml_payloads
            else fetch(upstream_path)
        )
        local_path = destination / upstream_path
        digest = _write_immutable(local_path, payload)
        artifacts.append({
            "name": upstream_path,
            "upstream_path": upstream_path,
            "relative_path": local_path.relative_to(ROOT).as_posix(),
            "url": RAW_PREFIX + upstream_path,
            "bytes": len(payload),
            "sha256": digest,
        })
    return {
        "manifest_version": "1.0.0",
        "policy": {
            "sample_generation": False,
            "label_generation": False,
            "attack_execution": False,
            "raw_artifacts_immutable": True,
            "selection": (
                "official atomics/T*/T*.yaml files containing at least one "
                "AWS, Azure, GCP, or Azure AD supported_platforms entry"
            ),
            "repository_yaml_files_scanned": len(yaml_paths),
            "cloud_yaml_files_selected": len(yaml_payloads),
        },
        "source": {
            "source_id": "atomic_red_team",
            "publisher": "Red Canary",
            "repository": REPOSITORY,
            "upstream_url": f"https://github.com/{REPOSITORY}",
            "commit": COMMIT,
            "license": "MIT",
            "artifacts": artifacts,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--git-repo",
        type=Path,
        help="verified local clone at the pinned commit (offline transport)",
    )
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    manifest = acquire(args.git_repo)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "commit": COMMIT,
        "artifacts": len(manifest["source"]["artifacts"]),
        "yaml_files": len(manifest["source"]["artifacts"]) - 2,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
