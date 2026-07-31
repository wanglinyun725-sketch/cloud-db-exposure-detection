import json
from pathlib import Path
import shutil

import pytest

from src.oracle_gold.replay_safety import build_replay_safety_audit


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "real_sources" / "acquisition_manifest.json"
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "cross_cloud_replay_safety_audit_v1.json"
)


def _build():
    return build_replay_safety_audit(
        ROOT,
        acquisition_manifest_path=MANIFEST,
    )


def test_committed_replay_safety_audit_is_reproducible_and_blocking():
    built = _build()

    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == built
    assert built["status"] == (
        "direct_execution_blocked_requires_sanitized_wrapper"
    )
    assert built["summary"]["direct_execution_eligible"] is False
    assert built["summary"]["blocking_finding_count"] > 0
    assert built["summary"]["finding_counts_by_provider"].keys() >= {
        "AWS",
        "AZURE",
        "GCP",
    }
    assert built["bindings"]["artifacts"][1]["sha256"] == (
        "4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900"
    )


def test_known_high_risk_construct_families_are_detected_without_lines():
    built = _build()
    by_rule = built["summary"]["finding_counts_by_rule"]

    for rule_id in ("RS001", "RS003", "RS004", "RS005", "RS006"):
        assert by_rule.get(rule_id, 0) > 0
    assert any(
        finding["member_path"].endswith("Dockerfile")
        and finding["rule_id"] == "RS001"
        for finding in built["findings"]
    )
    serialized = json.dumps(built, sort_keys=True)
    assert '"source_line_retained": false' in serialized
    assert '"snippet"' not in serialized
    assert '"line_text"' not in serialized
    assert '"truth_state"' not in serialized
    assert '"expected_truth_state"' not in serialized


def test_artifact_tampering_is_rejected(tmp_path):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source = next(
        item
        for item in manifest["sources"]
        if item["source_id"] == "cross_cloud_observability_2026"
    )
    isolated_root = tmp_path / "repo"
    for artifact in source["artifacts"]:
        if artifact["name"] not in {"README.md", "attack_scripts.zip"}:
            continue
        source_path = ROOT / artifact["relative_path"]
        target_path = isolated_root / artifact["relative_path"]
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target_path)
    source["artifacts"][0]["sha256"] = "0" * 64
    tampered = isolated_root / "acquisition_manifest.json"
    tampered.write_text(
        json.dumps({"sources": [source]}, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="artifact sha256 mismatch"):
        build_replay_safety_audit(
            isolated_root,
            acquisition_manifest_path=tampered,
        )
