import json
from pathlib import Path

from scripts.data.audit_splunk_reserve_sources_v1 import build_audit


ROOT = Path(__file__).resolve().parents[1]


def test_committed_audit_matches_deterministic_builder():
    audit = build_audit()
    committed = json.loads(
        (
            ROOT / "output" / "research_design"
            / "splunk_reserve_source_audit_v1.json"
        ).read_text(encoding="utf-8")
    )

    assert committed == audit


def test_only_the_exact_linked_multistep_artifact_enters_reserve():
    audit = build_audit()

    assert audit["summary"] == {
        "audited_artifacts": 5,
        "reserve_screening_eligible": 1,
        "structurally_excluded": 4,
        "new_human_gold": 0,
    }
    assert audit["eligible_dataset_ids"] == ["T1486/aws_kms_key"]
    assert audit["policy"]["generated_events"] == 0
    assert audit["policy"]["generated_labels"] == 0
    excluded = [
        item for item in audit["artifacts"]
        if not item["reserve_human_path_screening_eligible"]
    ]
    assert len(excluded) == 4
    assert all(item["exclusion_reason"] for item in excluded)
    assert all(item["human_gold"] is False for item in audit["artifacts"])


def test_repeated_single_operation_never_counts_as_multistep():
    audit = build_audit()
    by_id = {
        item["dataset_id"]: item for item in audit["artifacts"]
    }

    assert by_id["T1537/aws_ami_shared_public"]["record_count"] == 2
    assert by_id["T1537/aws_ami_shared_public"][
        "unique_operations"
    ] == ["ModifyImageAttribute"]
    assert by_id["T1562.008/put_bucketlifecycle"][
        "unique_operations"
    ] == ["PutBucketLifecycle"]
