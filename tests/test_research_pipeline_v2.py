from hashlib import sha256
import json
from pathlib import Path
import sys

import pytest
import yaml

from scripts.experiments import run_research_pipeline_v2 as pipeline
from scripts.experiments.run_research_pipeline_v2 import (
    _last_json,
    _portable,
    assert_frozen_for_execution,
    validate_frozen_execution_binding,
)


def test_pipeline_decodes_the_last_machine_readable_line():
    output = 'human log\n{"ready":false,"stage":"blocked"}\n'

    assert _last_json(output) == {
        "ready": False,
        "stage": "blocked",
    }


def test_confirmatory_execution_rejects_draft_protocol():
    with pytest.raises(ValueError, match="freeze_status=FROZEN"):
        assert_frozen_for_execution({
            "freeze_status": "DRAFT_BLOCKED_ON_HUMAN_GOLD"
        })

    assert_frozen_for_execution({"freeze_status": "FROZEN"})


def test_pipeline_manifest_uses_repo_relative_paths():
    assert _portable(
        Path.cwd()
        / "configs"
        / "ec_react_main_v2_draft.yaml"
    ) == str(Path("configs") / "ec_react_main_v2_draft.yaml")


def _write_frozen_pair(config_path: Path, manifest_path: Path) -> None:
    config = {
        "freeze_status": "FROZEN",
        "data": {
            "gold_release": "data/gold.json",
            "split_manifest": "data/split.json",
        },
        "freeze_binding": {
            "git_commit": "a" * 40,
            "inputs": {
                "gold_release": {
                    "path": "gold.json",
                    "sha256": "b" * 64,
                }
            },
            "manifest_path": str(manifest_path.resolve()),
        },
    }
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps({
            "status": "FROZEN",
            "git_commit": "a" * 40,
            "inputs": config["freeze_binding"]["inputs"],
            "frozen_config": {
                "path": str(config_path.resolve()),
                "sha256": sha256(config_path.read_bytes()).hexdigest(),
            },
        }),
        encoding="utf-8",
    )


def test_frozen_execution_requires_exact_manifest_and_config_bytes(tmp_path):
    config_path = tmp_path / "frozen.yaml"
    manifest_path = tmp_path / "manifest.json"
    _write_frozen_pair(config_path, manifest_path)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    validate_frozen_execution_binding(
        config,
        config_path,
        manifest_path,
        bound_commit_is_ancestor=True,
        committed_drift_paths=[],
        relevant_dirty_paths=[],
    )
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + "# drift\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="SHA-256 differs"):
        validate_frozen_execution_binding(
            config,
            config_path,
            manifest_path,
            bound_commit_is_ancestor=True,
            committed_drift_paths=[],
            relevant_dirty_paths=[],
        )


def test_frozen_execution_rejects_commit_or_worktree_drift(tmp_path):
    config_path = tmp_path / "frozen.yaml"
    manifest_path = tmp_path / "manifest.json"
    _write_frozen_pair(config_path, manifest_path)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="not an ancestor"):
        validate_frozen_execution_binding(
            config,
            config_path,
            manifest_path,
            bound_commit_is_ancestor=False,
            committed_drift_paths=[],
            relevant_dirty_paths=[],
        )
    with pytest.raises(ValueError, match="committed research code"):
        validate_frozen_execution_binding(
            config,
            config_path,
            manifest_path,
            bound_commit_is_ancestor=True,
            committed_drift_paths=["src/experiments/scoring.py"],
            relevant_dirty_paths=[],
        )
    with pytest.raises(ValueError, match="changed after protocol freeze"):
        validate_frozen_execution_binding(
            config,
            config_path,
            manifest_path,
            bound_commit_is_ancestor=True,
            committed_drift_paths=[],
            relevant_dirty_paths=["src/experiments/scoring.py"],
        )


def test_execute_mode_freezes_draft_then_uses_only_frozen_config(
    tmp_path,
    monkeypatch,
):
    draft_path = tmp_path / "draft.yaml"
    frozen_path = tmp_path / "frozen.yaml"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "experiment"
    status_path = tmp_path / "status.json"
    reproduction_path = tmp_path / "reproduction.zip"
    draft_path.write_text(
        yaml.safe_dump({
            "freeze_status": "DRAFT_BLOCKED_ON_HUMAN_GOLD",
        }),
        encoding="utf-8",
    )
    calls = []

    def fake_run(command):
        normalized = [str(item) for item in command]
        calls.append(normalized)
        script = Path(normalized[1]).name
        if script == "freeze_ec_react_protocol_v2.py":
            _write_frozen_pair(frozen_path, manifest_path)
        returncode = 2 if script == "decide_ec_react_main.py" else 0
        return {
            "returncode": returncode,
            "command": normalized,
            "result": {"ready": returncode == 0},
            "stderr": None,
        }

    monkeypatch.setattr(pipeline, "_run", fake_run)
    monkeypatch.setattr(
        pipeline,
        "_committed_research_drift",
        lambda *_: (True, []),
    )
    monkeypatch.setattr(
        pipeline,
        "_relevant_execution_dirty_paths",
        lambda *_: [],
    )
    monkeypatch.setattr(sys, "argv", [
        "run_research_pipeline_v2.py",
        "--mode",
        "execute",
        "--config",
        str(draft_path),
        "--frozen-config",
        str(frozen_path),
        "--freeze-manifest",
        str(manifest_path),
        "--output-dir",
        str(output_dir),
        "--status-output",
        str(status_path),
        "--reproduction-output",
        str(reproduction_path),
    ])

    assert pipeline.main() == 2
    script_names = [Path(command[1]).name for command in calls]
    assert script_names.index(
        "freeze_ec_react_protocol_v2.py"
    ) < script_names.index("run_ec_react_main.py")
    assert script_names.index(
        "analyze_ec_react_main.py"
    ) < script_names.index("run_cp_cert_experiments.py")
    assert script_names.index(
        "run_cp_cert_experiments.py"
    ) < script_names.index("decide_ec_react_main.py")
    assert script_names.index(
        "decide_ec_react_main.py"
    ) < script_names.index("build_publication_claims_v2.py")
    for script_name in (
        "run_ec_react_main.py",
        "analyze_ec_react_main.py",
        "decide_ec_react_main.py",
    ):
        command = calls[script_names.index(script_name)]
        assert command[command.index("--config") + 1] == str(frozen_path)
    cp_command = calls[
        script_names.index("run_cp_cert_experiments.py")
    ]
    assert cp_command[cp_command.index("--input") + 1] == str(
        (pipeline.ROOT / "data" / "gold.json").resolve()
    )
    assert cp_command[
        cp_command.index("--split-manifest") + 1
    ] == str((pipeline.ROOT / "data" / "split.json").resolve())
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["ready"] is False
    assert status["final_status"] == "claim_not_passed"
    assert any(
        item["stage"] == "evaluate_cp_cert"
        for item in status["stages"]
    )
    assert any(
        item["stage"] == "derive_publication_claims"
        for item in status["stages"]
    )
