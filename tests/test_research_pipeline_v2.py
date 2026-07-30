from pathlib import Path

import pytest

from scripts.experiments.run_research_pipeline_v2 import (
    _last_json,
    _portable,
    assert_frozen_for_execution,
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
