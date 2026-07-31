from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.oracle_gold.protocol import (
    build_candidate_registry,
    validate_oracle_registry,
)


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (
    "data/real_sources/annotation/"
    "runtime_confirmatory_30_unlabeled.json"
)
CONFIGURATION = (
    "data/real_sources/annotation/"
    "configuration_supplemental_10_unlabeled.json"
)
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle"
    / "executable_oracle_registry_v1.json"
)


def _build():
    return build_candidate_registry(
        ROOT,
        runtime_packet_path=RUNTIME,
        configuration_packet_path=CONFIGURATION,
    )


def test_committed_oracle_registry_is_reproducible():
    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == _build()


def test_candidates_are_not_promoted_from_artifacts_alone():
    registry = _build()

    assert registry["summary"] == {
        "candidate_independence_groups": 40,
        "source_count": 9,
        "sources": [
            "awsgoat",
            "azuregoat",
            "cloudfoxable",
            "cloudgoat",
            "cross_cloud_observability_2026",
            "gcpgoat",
            "splunk_attack_data",
            "stratus_red_team",
            "terragoat",
        ],
        "platforms": ["AWS", "AZURE", "GCP"],
        "truth_state_counts": {
            "Reachable": 0,
            "NotReachableWithinScope": 0,
            "Unknown": 40,
            "Conflict": 0,
        },
        "qualifying_oracle_gold_groups": 0,
        "bounded_negative_or_paired_control_groups": 0,
    }
    assert registry["completion_gate"]["passes"] is False
    assert all(
        candidate["truth_state"] == "Unknown"
        and candidate["counts_toward_oracle_gold"] is False
        for candidate in registry["candidates"]
    )


def test_forged_reachable_flag_fails_closed():
    registry = _build()
    candidate = registry["candidates"][0]
    candidate["truth_state"] = "Reachable"
    candidate["counts_toward_oracle_gold"] = True
    registry["summary"]["truth_state_counts"] = {
        "Reachable": 1,
        "NotReachableWithinScope": 0,
        "Unknown": 39,
        "Conflict": 0,
    }
    registry["summary"]["qualifying_oracle_gold_groups"] = 1

    with pytest.raises(ValueError, match="fail-closed gold flag mismatch"):
        validate_oracle_registry(ROOT, registry)


def test_tampered_source_case_binding_is_rejected():
    registry = _build()
    forged = deepcopy(registry)
    forged["candidates"][0]["source_case_bindings"][0][
        "case_sha256"
    ] = "0" * 64

    with pytest.raises(ValueError, match="source case hash mismatch"):
        validate_oracle_registry(ROOT, forged)
