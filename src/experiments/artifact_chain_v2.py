"""Hash-chain validation for frozen EC-ReAct experiment artifacts."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


def build_analysis_binding(
    root: str | Path,
    *,
    config_path: str | Path,
    run_manifest_path: str | Path,
    runs_path: str | Path,
    records: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate complete scheduled execution and return its file bindings."""
    root = Path(root).resolve()
    config_path = _resolve(root, config_path)
    run_manifest_path = _resolve(root, run_manifest_path)
    runs_path = _resolve(root, runs_path)
    config_hash = _file_hash(config_path)
    manifest = _read_json(run_manifest_path)
    if manifest.get("config_sha256") != config_hash:
        raise ValueError("run manifest config hash does not match frozen config")
    if manifest.get("secrets_in_manifest") is not False:
        raise ValueError("run manifest does not explicitly exclude secrets")
    schedule = manifest.get("schedule")
    if not isinstance(schedule, list):
        raise ValueError("run manifest schedule must be a list")
    scheduled_ids = [item.get("schedule_id") for item in schedule]
    if (
        any(not isinstance(value, str) or not value for value in scheduled_ids)
        or len(set(scheduled_ids)) != len(scheduled_ids)
    ):
        raise ValueError("run manifest contains invalid or duplicate schedule IDs")
    if manifest.get("scheduled_runs") != len(scheduled_ids):
        raise ValueError("run manifest scheduled_runs is inconsistent")

    record_ids = [item.get("schedule_id") for item in records]
    if (
        any(not isinstance(value, str) or not value for value in record_ids)
        or len(set(record_ids)) != len(record_ids)
    ):
        raise ValueError("run records contain invalid or duplicate schedule IDs")
    if set(record_ids) != set(scheduled_ids):
        raise ValueError("run records are incomplete or outside the frozen schedule")
    if any(item.get("config_sha256") != config_hash for item in records):
        raise ValueError("a run record was produced with a different config")
    return {
        "config": _binding(root, config_path),
        "run_manifest": _binding(root, run_manifest_path),
        "runs": {
            **_binding(root, runs_path),
            "records": len(records),
        },
    }


def validate_analysis_binding(
    root: str | Path,
    analysis: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Recompute hashes referenced by an analysis artifact."""
    root = Path(root).resolve()
    binding = analysis.get("artifact_binding")
    if not isinstance(binding, Mapping):
        raise ValueError("analysis has no artifact_binding")
    _validate_bound_files(root, binding, {"config", "run_manifest", "runs"})
    if analysis.get("run_records") != binding["runs"].get("records"):
        raise ValueError("analysis run count differs from its runs binding")
    manifest = _read_json(_resolve(root, binding["run_manifest"]["path"]))
    if manifest.get("config_sha256") != binding["config"].get("sha256"):
        raise ValueError("analysis chain has a config/manifest mismatch")
    return dict(binding)


def build_decision_binding(
    root: str | Path,
    *,
    config_path: str | Path,
    analysis_path: str | Path,
    analysis: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Validate analysis inputs before binding a confirmatory decision."""
    root = Path(root).resolve()
    config_path = _resolve(root, config_path)
    analysis_path = _resolve(root, analysis_path)
    analysis_binding = validate_analysis_binding(root, analysis)
    config = _binding(root, config_path)
    if config["sha256"] != analysis_binding["config"].get("sha256"):
        raise ValueError("decision config differs from analysis config")
    return {
        "config": config,
        "analysis": _binding(root, analysis_path),
        "run_manifest": dict(analysis_binding["run_manifest"]),
        "runs": dict(analysis_binding["runs"]),
    }


def validate_decision_binding(
    root: str | Path,
    decision: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Recompute the complete decision-to-runs hash chain."""
    root = Path(root).resolve()
    binding = decision.get("artifact_binding")
    if not isinstance(binding, Mapping):
        raise ValueError("decision has no artifact_binding")
    required = {"config", "analysis", "run_manifest", "runs"}
    _validate_bound_files(root, binding, required)
    analysis = _read_json(_resolve(root, binding["analysis"]["path"]))
    analysis_binding = validate_analysis_binding(root, analysis)
    for name in ("config", "run_manifest", "runs"):
        if binding[name].get("sha256") != analysis_binding[name].get("sha256"):
            raise ValueError(f"decision and analysis disagree on {name}")
    return dict(binding)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError(f"run file is missing: {path}")
    records = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSONL at {path}:{line_number}") from error
        if not isinstance(value, dict):
            raise ValueError(f"JSONL row must be an object at {path}:{line_number}")
        records.append(value)
    return records


def _validate_bound_files(
    root: Path,
    binding: Mapping[str, Any],
    required: set[str],
) -> None:
    if not required <= set(binding):
        raise ValueError(f"artifact binding is missing {sorted(required - set(binding))}")
    for name in required:
        item = binding[name]
        if not isinstance(item, Mapping):
            raise ValueError(f"{name} binding must be an object")
        path = _resolve(root, str(item.get("path", "")))
        if item.get("sha256") != _file_hash(path):
            raise ValueError(f"{name} binding hash mismatch")


def _binding(root: Path, path: Path) -> dict[str, str]:
    return {"path": _portable(root, path), "sha256": _file_hash(path)}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"required file is missing: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"required file is missing: {path}")
    return sha256(path.read_bytes()).hexdigest()


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


def _portable(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path.resolve())
