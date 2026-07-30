from hashlib import sha256
from pathlib import Path

import yaml

from src.experiments.protocol_freeze_v2 import (
    REQUIRED_FROZEN_INPUTS,
    build_freeze_manifest,
    build_frozen_protocol,
    serialize_frozen_protocol,
)
from src.experiments.ec_react_preflight import _validate_freeze_binding


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "ec_react_main_v2_draft.yaml"


def _inputs():
    names = [
        "source_packet",
        "gold_release",
        "split_manifest",
        "negative_source_packet",
        "negative_gold_release",
        "path_ontology",
        "external_action_prior",
        "external_action_source_archive",
    ]
    return {
        name: {
            "path": f"{name}.json",
            "sha256": f"{index:x}" * 64,
        }
        for index, name in enumerate(names, start=1)
    }


def test_frozen_protocol_is_deterministic_and_hash_bound():
    draft_bytes = CONFIG.read_bytes()
    draft = yaml.safe_load(draft_bytes.decode("utf-8"))
    frozen = build_frozen_protocol(
        draft,
        frozen_inputs=_inputs(),
        git_commit="c" * 40,
        draft_sha256=sha256(draft_bytes).hexdigest(),
        manifest_path=(
            "output/research_design/"
            "ec_react_main_v2_freeze_manifest.json"
        ),
    )
    first = serialize_frozen_protocol(frozen)
    second = serialize_frozen_protocol(frozen)
    manifest = build_freeze_manifest(
        draft_path="configs/ec_react_main_v2_draft.yaml",
        frozen_path="configs/ec_react_main_v2_frozen.yaml",
        frozen_config_bytes=first,
        frozen_config=frozen,
    )

    assert first == second
    assert frozen["freeze_status"] == "FROZEN"
    assert frozen["protocol_version"] == "1.0"
    assert frozen["freeze_binding"]["git_commit"] == "c" * 40
    assert manifest["frozen_config"]["sha256"] == sha256(first).hexdigest()
    assert manifest["timestamp_excluded_for_determinism"] is True


def test_freezer_rejects_unlocked_model_or_non_draft_source():
    draft = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    draft["models"][0]["frozen_runtime_digest"] = None

    try:
        build_frozen_protocol(
            draft,
            frozen_inputs=_inputs(),
            git_commit="c" * 40,
            draft_sha256="d" * 64,
            manifest_path="manifest.json",
        )
    except ValueError as exc:
        assert "lacks frozen digest" in str(exc)
    else:
        raise AssertionError("unlocked local model was frozen")

    draft["freeze_status"] = "FROZEN"
    try:
        build_frozen_protocol(
            draft,
            frozen_inputs=_inputs(),
            git_commit="c" * 40,
            draft_sha256="d" * 64,
            manifest_path="manifest.json",
        )
    except ValueError as exc:
        assert "blocked draft" in str(exc)
    else:
        raise AssertionError("a non-draft protocol was refrozen")


def test_preflight_rejects_drift_in_any_frozen_input(tmp_path):
    bindings = {}
    for name in REQUIRED_FROZEN_INPUTS:
        path = tmp_path / f"{name}.json"
        path.write_text(name, encoding="utf-8")
        bindings[name] = {
            "path": path.name,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }
    config = {
        "freeze_status": "FROZEN",
        "freeze_binding": {
            "git_commit": "c" * 40,
            "inputs": bindings,
        },
    }
    blockers = []
    _validate_freeze_binding(tmp_path, config, blockers)
    assert blockers == []

    (tmp_path / "gold_release.json").write_text(
        "changed",
        encoding="utf-8",
    )
    _validate_freeze_binding(tmp_path, config, blockers)

    assert any(
        "frozen bound input drifted: gold_release" in item
        for item in blockers
    )
