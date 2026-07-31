import json
from pathlib import Path

from scripts.data.audit_splunk_cloud_data_catalog_v1 import build_audit


ROOT = Path(__file__).resolve().parents[1]
COMMITTED = (
    ROOT / "output" / "research_design"
    / "splunk_cloud_data_catalog_coverage_v1.json"
)


def test_committed_catalogue_audit_is_reproducible():
    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == build_audit()


def test_pinned_cloud_data_catalogue_is_fully_dispositioned():
    audit = build_audit()

    assert audit["summary"] == {
        "matching_metadata_datasets": 15,
        "already_in_frozen_primary_packet": 8,
        "eligible_unlabeled_reserve": 1,
        "structurally_excluded": 2,
        "out_of_preregistered_scope": 4,
        "unclassified": 0,
        "catalogue_coverage_complete": True,
        "new_human_gold": 0,
    }
    assert all(
        item["counts_as_human_gold"] is False
        for item in audit["datasets"]
    )
