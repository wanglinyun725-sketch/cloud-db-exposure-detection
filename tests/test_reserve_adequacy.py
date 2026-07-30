import json
from pathlib import Path

import pytest

from src.data.reserve_adequacy import (
    _validate_reserve_candidate,
    build_reserve_adequacy_audit,
)


ROOT = Path(__file__).resolve().parents[1]
PRIMARY = (
    "data/real_sources/annotation/"
    "runtime_confirmatory_30_unlabeled.json"
)
STRUCTURAL_AUDIT = (
    "output/research_design/splunk_reserve_source_audit_v1.json"
)
RESERVE = "data/real_sources/splunk_kms_s3_reserve_candidate_v1.json"
COMMITTED = (
    ROOT / "output" / "research_design"
    / "confirmatory_reserve_adequacy_v1.json"
)


def _build():
    return build_reserve_adequacy_audit(
        ROOT,
        primary_packet_path=PRIMARY,
        structural_audit_path=STRUCTURAL_AUDIT,
        reserve_candidate_paths=[RESERVE],
    )


def test_committed_reserve_audit_is_reproducible():
    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == _build()


def test_reserve_gate_reports_real_attrition_risk():
    audit = _build()

    assert audit["status"] == "insufficient_reserve"
    assert audit["summary"] == {
        "primary_independence_groups": 30,
        "structurally_eligible_reserve_groups": 1,
        "total_screenable_independence_groups": 31,
        "target_human_gold_groups": 30,
        "primary_rejections_tolerated_before_supply_shortfall": 1,
        "minimum_reserve_groups": 5,
        "missing_reserve_groups": 4,
        "robust_annotation_supply_ready": False,
        "new_human_gold": 0,
    }
    assert audit["policy"]["generated_events"] == 0
    assert audit["policy"]["generated_labels"] == 0
    assert audit["reserve_candidates"][0][
        "counts_as_human_gold"
    ] is False


def test_candidate_with_injected_label_is_rejected():
    candidate = json.loads((ROOT / RESERVE).read_text(encoding="utf-8"))
    candidate["path_labels"] = ["injected"]

    with pytest.raises(ValueError, match="must be empty"):
        _validate_reserve_candidate(
            ROOT,
            candidate,
            eligible_ids={"T1486/aws_kms_key"},
        )
