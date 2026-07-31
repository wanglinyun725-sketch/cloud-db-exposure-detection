"""Deterministic construction of a hash-bound EC-ReAct v2 protocol."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

import yaml


REQUIRED_FROZEN_INPUTS = {
    "source_packet",
    "gold_release",
    "split_manifest",
    "negative_source_packet",
    "negative_gold_release",
    "path_ontology",
    "external_action_prior",
    "external_action_source_archive",
}
ORACLE_REQUIRED_FROZEN_INPUTS = {
    "source_packet",
    "oracle_registry",
    "oracle_record_schema",
    "split_manifest",
    "path_ontology",
    "external_action_prior",
    "external_action_source_archive",
}


def required_frozen_inputs(
    config: Mapping[str, Any],
) -> set[str]:
    """Return the exact artifact set for the configured Gold protocol."""
    data = config.get("data")
    if (
        isinstance(data, Mapping)
        and data.get("gold_protocol") == "executable_oracle_v1"
    ):
        return set(ORACLE_REQUIRED_FROZEN_INPUTS)
    return set(REQUIRED_FROZEN_INPUTS)


def collect_frozen_inputs(
    root: str | Path,
    config: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    """Hash every data or ontology artifact consulted by the protocol."""
    root = Path(root).resolve()
    data = config["data"]
    ontology = config["path_ontology"]
    prior = config["external_action_prior"]
    if data.get("gold_protocol") == "executable_oracle_v1":
        declared = {
            "source_packet": data["source_packet"],
            "oracle_registry": data["oracle_registry"],
            "oracle_record_schema": data["oracle_record_schema"],
            "split_manifest": data["split_manifest"],
            "path_ontology": ontology["path"],
            "external_action_prior": prior["path"],
            "external_action_source_archive": prior[
                "source_archive_path"
            ],
        }
    else:
        declared = {
            "source_packet": data["source_packet"],
            "gold_release": data["gold_release"],
            "split_manifest": data["split_manifest"],
            "negative_source_packet": data["negative_source_packet"],
            "negative_gold_release": data["negative_gold_release"],
            "path_ontology": ontology["path"],
            "external_action_prior": prior["path"],
            "external_action_source_archive": prior[
                "source_archive_path"
            ],
        }
    output = {}
    for name, value in declared.items():
        path = Path(value)
        path = path if path.is_absolute() else (root / path)
        path = path.resolve()
        if not path.is_file():
            raise ValueError(f"frozen input is missing: {name}={path}")
        output[name] = {
            "path": _relative_or_absolute(root, path),
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }
    return output


def build_frozen_protocol(
    draft: Mapping[str, Any],
    *,
    frozen_inputs: Mapping[str, Mapping[str, str]],
    git_commit: str,
    draft_sha256: str,
    manifest_path: str,
) -> dict[str, Any]:
    """Create a deterministic frozen config without timestamps."""
    if not str(draft.get("freeze_status", "")).startswith("DRAFT_"):
        raise ValueError("source protocol must be an explicitly blocked draft")
    if (
        not isinstance(git_commit, str)
        or len(git_commit) != 40
        or any(character not in "0123456789abcdef" for character in git_commit)
    ):
        raise ValueError("git_commit must be a full lowercase SHA-1")
    if not _is_sha256(draft_sha256):
        raise ValueError("draft_sha256 must be a lowercase SHA-256")
    if set(frozen_inputs) != required_frozen_inputs(draft):
        raise ValueError(
            "frozen inputs do not match the required protocol artifacts"
        )
    for name, item in frozen_inputs.items():
        if not _is_sha256(item.get("sha256")):
            raise ValueError(f"frozen input {name} has no valid SHA-256")
    output = deepcopy(dict(draft))
    output["protocol_version"] = "1.0"
    output["freeze_status"] = "FROZEN"
    output["freeze_binding"] = {
        "draft_sha256": draft_sha256,
        "git_commit": git_commit,
        "manifest_path": manifest_path,
        "inputs": deepcopy(dict(frozen_inputs)),
        "timestamp_excluded_for_determinism": True,
    }
    _validate_model_locks(output)
    return output


def serialize_frozen_protocol(config: Mapping[str, Any]) -> bytes:
    """Return stable UTF-8 YAML bytes for hashing and idempotent writes."""
    return yaml.safe_dump(
        dict(config),
        allow_unicode=True,
        sort_keys=False,
        width=100,
    ).encode("utf-8")


def build_freeze_manifest(
    *,
    draft_path: str,
    frozen_path: str,
    frozen_config_bytes: bytes,
    frozen_config: Mapping[str, Any],
) -> dict[str, Any]:
    binding = frozen_config["freeze_binding"]
    return {
        "manifest_version": "1.0",
        "status": "FROZEN",
        "experiment_id": frozen_config["experiment_id"],
        "draft_config": {
            "path": draft_path,
            "sha256": binding["draft_sha256"],
        },
        "frozen_config": {
            "path": frozen_path,
            "sha256": sha256(frozen_config_bytes).hexdigest(),
        },
        "git_commit": binding["git_commit"],
        "inputs": deepcopy(binding["inputs"]),
        "models": [
            {
                "model_id": item["model_id"],
                "default_model": item.get("default_model"),
                "frozen_runtime_digest": item.get(
                    "frozen_runtime_digest"
                ),
                "require_exact_version": item.get(
                    "require_exact_version", False
                ),
            }
            for item in frozen_config.get("models", [])
        ],
        "schedule_arms_sha256": _stable_hash(
            frozen_config.get("schedule_arms") or []
        ),
        "timestamp_excluded_for_determinism": True,
    }


def _validate_model_locks(config: Mapping[str, Any]) -> None:
    for model in config.get("models") or []:
        if model.get("require_runtime_digest") is True:
            if not _is_sha256(model.get("frozen_runtime_digest")):
                raise ValueError(
                    f"model {model.get('model_id')} lacks frozen digest"
                )
        if model.get("require_exact_version") is True:
            value = model.get("default_model")
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"model {model.get('model_id')} lacks exact version"
                )


def _relative_or_absolute(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
