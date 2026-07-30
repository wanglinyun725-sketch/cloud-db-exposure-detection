from hashlib import sha256
import json
from io import BytesIO
import zipfile

import pytest
import yaml

from src.experiments.artifact_chain_v2 import (
    build_analysis_binding,
    build_decision_binding,
)
from src.experiments.reproduction_bundle_v2 import (
    REQUIRED_CODE_PATHS,
    build_reproduction_bundle_bytes,
)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixture(tmp_path):
    input_path = tmp_path / "data" / "gold.json"
    _write_json(input_path, {"cases": []})
    inputs = {
        "gold_release": {
            "path": "data/gold.json",
            "sha256": sha256(input_path.read_bytes()).hexdigest(),
        }
    }
    commit = "a" * 40
    config = tmp_path / "configs" / "ec_react_main_v2_frozen.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(yaml.safe_dump({
        "freeze_status": "FROZEN",
        "freeze_binding": {
            "git_commit": commit,
            "inputs": inputs,
        },
    }), encoding="utf-8")
    freeze_manifest = (
        tmp_path / "output" / "research_design" / "freeze.json"
    )
    _write_json(freeze_manifest, {
        "status": "FROZEN",
        "git_commit": commit,
        "frozen_config": {
            "path": "configs/ec_react_main_v2_frozen.yaml",
            "sha256": sha256(config.read_bytes()).hexdigest(),
        },
        "inputs": inputs,
    })
    experiment = tmp_path / "output" / "ec_react_main_v2"
    experiment.mkdir(parents=True)
    config_hash = sha256(config.read_bytes()).hexdigest()
    run_manifest = experiment / "run_manifest.json"
    _write_json(run_manifest, {
        "config_sha256": config_hash,
        "scheduled_runs": 1,
        "schedule": [{"schedule_id": "s1"}],
        "secrets_in_manifest": False,
    })
    runs = experiment / "runs.jsonl"
    record = {"schedule_id": "s1", "config_sha256": config_hash}
    runs.write_text(json.dumps(record) + "\n", encoding="utf-8")
    analysis = {
        "run_records": 1,
        "artifact_binding": build_analysis_binding(
            tmp_path,
            config_path=config,
            run_manifest_path=run_manifest,
            runs_path=runs,
            records=[record],
        ),
    }
    analysis_path = experiment / "analysis.json"
    _write_json(analysis_path, analysis)
    decision = {
        "claim_allowed": True,
        "overall_status": "pass",
        "posthoc_metric_substitution_allowed": False,
        "artifact_binding": build_decision_binding(
            tmp_path,
            config_path=config,
            analysis_path=analysis_path,
            analysis=analysis,
        ),
    }
    _write_json(experiment / "confirmatory_decision.json", decision)
    code_files = {
        path: path.encode("utf-8") for path in REQUIRED_CODE_PATHS
    }
    return config, freeze_manifest, experiment, code_files


def test_reproduction_bundle_is_deterministic_and_complete(tmp_path):
    config, freeze_manifest, experiment, code_files = _fixture(tmp_path)

    first, manifest = build_reproduction_bundle_bytes(
        tmp_path,
        frozen_config_path=config,
        freeze_manifest_path=freeze_manifest,
        experiment_dir=experiment,
        code_files=code_files,
    )
    second, _ = build_reproduction_bundle_bytes(
        tmp_path,
        frozen_config_path=config,
        freeze_manifest_path=freeze_manifest,
        experiment_dir=experiment,
        code_files=code_files,
    )

    assert first == second
    assert manifest["secrets_in_bundle"] is False
    with zipfile.ZipFile(BytesIO(first)) as archive:
        names = set(archive.namelist())
    assert "bundle_manifest.json" in names
    assert "REPRODUCE.md" in names
    assert "output/ec_react_main_v2/runs.jsonl" in names
    assert "data/gold.json" in names


def test_reproduction_bundle_rejects_result_drift(tmp_path):
    config, freeze_manifest, experiment, code_files = _fixture(tmp_path)
    runs = experiment / "runs.jsonl"
    runs.write_text(runs.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="runs binding hash mismatch"):
        build_reproduction_bundle_bytes(
            tmp_path,
            frozen_config_path=config,
            freeze_manifest_path=freeze_manifest,
            experiment_dir=experiment,
            code_files=code_files,
        )


def test_reproduction_bundle_rejects_missing_frozen_code(tmp_path):
    config, freeze_manifest, experiment, code_files = _fixture(tmp_path)
    code_files.pop("requirements.txt")

    with pytest.raises(ValueError, match="lacks required"):
        build_reproduction_bundle_bytes(
            tmp_path,
            frozen_config_path=config,
            freeze_manifest_path=freeze_manifest,
            experiment_dir=experiment,
            code_files=code_files,
        )
