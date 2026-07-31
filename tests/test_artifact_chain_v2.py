from hashlib import sha256
import json

import pytest

from src.experiments.artifact_chain_v2 import (
    build_analysis_binding,
    build_decision_binding,
    validate_decision_binding,
)


def _write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _chain(tmp_path):
    config = tmp_path / "frozen.yaml"
    config.write_text("freeze_status: FROZEN\n", encoding="utf-8")
    config_hash = sha256(config.read_bytes()).hexdigest()
    schedule = [{"schedule_id": "s1"}, {"schedule_id": "s2"}]
    run_manifest = tmp_path / "run_manifest.json"
    _write_json(run_manifest, {
        "config_sha256": config_hash,
        "scheduled_runs": 2,
        "schedule": schedule,
        "secrets_in_manifest": False,
    })
    records = [
        {"schedule_id": item["schedule_id"], "config_sha256": config_hash}
        for item in schedule
    ]
    runs = tmp_path / "runs.jsonl"
    runs.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n",
        encoding="utf-8",
    )
    analysis = {
        "run_records": 2,
        "artifact_binding": build_analysis_binding(
            tmp_path,
            config_path=config,
            run_manifest_path=run_manifest,
            runs_path=runs,
            records=records,
        ),
    }
    analysis_path = tmp_path / "analysis.json"
    _write_json(analysis_path, analysis)
    decision = {
        "artifact_binding": build_decision_binding(
            tmp_path,
            config_path=config,
            analysis_path=analysis_path,
            analysis=analysis,
        )
    }
    return config, run_manifest, runs, analysis_path, decision


def test_complete_artifact_chain_validates(tmp_path):
    *_, decision = _chain(tmp_path)

    binding = validate_decision_binding(tmp_path, decision)

    assert binding["runs"]["records"] == 2


def test_incomplete_run_schedule_is_rejected(tmp_path):
    config, run_manifest, runs, _, _ = _chain(tmp_path)
    config_hash = sha256(config.read_bytes()).hexdigest()
    records = [{"schedule_id": "s1", "config_sha256": config_hash}]
    runs.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="incomplete"):
        build_analysis_binding(
            tmp_path,
            config_path=config,
            run_manifest_path=run_manifest,
            runs_path=runs,
            records=records,
        )


def test_post_analysis_run_drift_is_rejected(tmp_path):
    *_, runs, _, decision = _chain(tmp_path)
    runs.write_text(runs.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="runs binding hash mismatch"):
        validate_decision_binding(tmp_path, decision)
