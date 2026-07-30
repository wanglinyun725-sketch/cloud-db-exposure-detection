"""Deterministic, result-bound reproduction bundle for EC-ReAct v2."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
import zipfile

import yaml

from src.experiments.artifact_chain_v2 import validate_decision_binding


REQUIRED_CODE_PATHS = {
    "README.md",
    "requirements.txt",
    "scripts/experiments/run_research_pipeline_v2.py",
    "scripts/experiments/analyze_ec_react_main.py",
    "scripts/experiments/decide_ec_react_main.py",
}
CORE_RESULT_NAMES = {
    "run_manifest.json",
    "runs.jsonl",
    "analysis.json",
    "confirmatory_decision.json",
}


def build_reproduction_bundle_bytes(
    root: str | Path,
    *,
    frozen_config_path: str | Path,
    freeze_manifest_path: str | Path,
    experiment_dir: str | Path,
    code_files: Mapping[str, bytes],
) -> tuple[bytes, dict[str, Any]]:
    """Validate the complete chain and return deterministic ZIP bytes."""
    root = Path(root).resolve()
    frozen_config_path = _resolve(root, frozen_config_path)
    freeze_manifest_path = _resolve(root, freeze_manifest_path)
    experiment_dir = _resolve(root, experiment_dir)
    frozen = yaml.safe_load(frozen_config_path.read_text(encoding="utf-8"))
    freeze_manifest = _read_json(freeze_manifest_path)
    _validate_freeze(
        root,
        frozen_config_path,
        frozen,
        freeze_manifest,
    )
    git_commit = freeze_manifest.get("git_commit")
    normalized_code = {
        _safe_archive_name(name): payload
        for name, payload in code_files.items()
    }
    if not REQUIRED_CODE_PATHS <= set(normalized_code):
        raise ValueError(
            "frozen repository archive lacks required reproduction code: "
            + repr(sorted(REQUIRED_CODE_PATHS - set(normalized_code)))
        )

    result_paths = {
        name: experiment_dir / name for name in sorted(CORE_RESULT_NAMES)
    }
    decision = _read_json(result_paths["confirmatory_decision.json"])
    if (
        decision.get("claim_allowed") is not True
        or decision.get("overall_status") != "pass"
        or decision.get("posthoc_metric_substitution_allowed") is not False
    ):
        raise ValueError("reproduction packaging requires a passing decision")
    decision_binding = validate_decision_binding(root, decision)
    if (
        decision_binding["config"].get("sha256")
        != _file_hash(frozen_config_path)
    ):
        raise ValueError("decision is not bound to the frozen protocol")
    for name, path in result_paths.items():
        if not path.is_file():
            raise ValueError(f"core result is missing: {name}")
    run_manifest = _read_json(result_paths["run_manifest.json"])
    if run_manifest.get("secrets_in_manifest") is not False:
        raise ValueError("run manifest is not safe for packaging")

    archive_files: dict[str, bytes] = dict(normalized_code)
    _add_file(root, archive_files, frozen_config_path)
    _add_file(root, archive_files, freeze_manifest_path)
    for item in (freeze_manifest.get("inputs") or {}).values():
        if not isinstance(item, Mapping):
            raise ValueError("freeze manifest input binding is malformed")
        path = _resolve(root, str(item.get("path", "")))
        if item.get("sha256") != _file_hash(path):
            raise ValueError("a frozen input hash no longer matches")
        _add_file(root, archive_files, path)
    for path in result_paths.values():
        _add_file(root, archive_files, path)

    reproduce = _reproduce_instructions(
        frozen_config=_portable(root, frozen_config_path),
        experiment_dir=_portable(root, experiment_dir),
    ).encode("utf-8")
    archive_files["REPRODUCE.md"] = reproduce
    file_manifest = [
        {
            "path": name,
            "sha256": sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
        for name, payload in sorted(archive_files.items())
    ]
    bundle_manifest = {
        "manifest_version": "2.0",
        "status": "complete",
        "frozen_git_commit": git_commit,
        "frozen_config_sha256": _file_hash(frozen_config_path),
        "confirmatory_decision_sha256": _file_hash(
            result_paths["confirmatory_decision.json"]
        ),
        "files": file_manifest,
        "secrets_in_bundle": False,
        "deterministic_zip_timestamp": "1980-01-01T00:00:00Z",
    }
    archive_files["bundle_manifest.json"] = (
        json.dumps(bundle_manifest, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    return _deterministic_zip(archive_files), bundle_manifest


def write_once_bundle(path: str | Path, payload: bytes) -> None:
    path = Path(path).resolve()
    if path.is_file():
        if path.read_bytes() == payload:
            return
        raise RuntimeError(f"refusing to overwrite different bundle: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def read_git_archive(payload: bytes) -> dict[str, bytes]:
    if not zipfile.is_zipfile(BytesIO(payload)):
        raise ValueError("git archive is not a ZIP file")
    with zipfile.ZipFile(BytesIO(payload)) as archive:
        return {
            _safe_archive_name(name): archive.read(name)
            for name in archive.namelist()
            if not name.endswith("/")
        }


def _validate_freeze(
    root: Path,
    frozen_config_path: Path,
    frozen: Any,
    manifest: Mapping[str, Any],
) -> None:
    if not isinstance(frozen, Mapping) or frozen.get("freeze_status") != "FROZEN":
        raise ValueError("protocol is not FROZEN")
    if manifest.get("status") != "FROZEN":
        raise ValueError("freeze manifest is not FROZEN")
    config_item = manifest.get("frozen_config")
    if (
        not isinstance(config_item, Mapping)
        or config_item.get("sha256") != _file_hash(frozen_config_path)
    ):
        raise ValueError("freeze manifest config hash mismatch")
    binding = frozen.get("freeze_binding")
    if not isinstance(binding, Mapping):
        raise ValueError("frozen config has no freeze_binding")
    if binding.get("git_commit") != manifest.get("git_commit"):
        raise ValueError("freeze config and manifest git commits differ")
    if binding.get("inputs") != manifest.get("inputs"):
        raise ValueError("freeze config and manifest input bindings differ")


def _add_file(root: Path, files: dict[str, bytes], path: Path) -> None:
    try:
        name = _safe_archive_name(str(path.resolve().relative_to(root)))
    except ValueError as error:
        raise ValueError(f"bundle input is outside repository root: {path}") from error
    payload = path.read_bytes()
    existing = files.get(name)
    if existing is not None and existing != payload:
        raise ValueError(f"bundle path collision with different bytes: {name}")
    files[name] = payload


def _deterministic_zip(files: Mapping[str, bytes]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(
        stream,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name, payload in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)
    return stream.getvalue()


def _reproduce_instructions(*, frozen_config: str, experiment_dir: str) -> str:
    return f"""# Reproduce EC-ReAct v2

This bundle is bound to a passing frozen confirmatory decision. It contains no
API keys. Set `OPENAI_API_KEY` yourself when repeating model calls.

## Re-run the frozen experiment

```powershell
python scripts/experiments/run_research_pipeline_v2.py --mode execute --config {frozen_config}
```

## Recompute analysis and the preregistered decision from included runs

```powershell
python scripts/experiments/analyze_ec_react_main.py --config {frozen_config} --runs {experiment_dir}/runs.jsonl --output {experiment_dir}/analysis.json
python scripts/experiments/decide_ec_react_main.py --config {frozen_config} --analysis {experiment_dir}/analysis.json --output {experiment_dir}/confirmatory_decision.json
```
"""


def _safe_archive_name(value: str) -> str:
    name = value.replace("\\", "/").strip("/")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive path: {value}")
    return str(path)


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
        return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path.resolve()).replace("\\", "/")
