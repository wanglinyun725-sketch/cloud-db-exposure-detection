from hashlib import sha256
import json
from pathlib import Path

import pytest

from scripts.data.build_splunk_kms_reserve_candidate import (
    EXPECTED_SHA256,
    REQUIRED_OPERATIONS,
    build,
)


ROOT = Path(__file__).resolve().parents[1]


def test_committed_candidate_matches_deterministic_builder():
    candidate = build()
    committed = json.loads(
        (
            ROOT / "data" / "real_sources"
            / "splunk_kms_s3_reserve_candidate_v1.json"
        ).read_text(encoding="utf-8")
    )

    assert committed == candidate


def test_real_kms_reserve_candidate_is_multistep_and_label_empty():
    candidate = build()

    operations = {
        item["operation"] for item in candidate["observations"]
    }
    assert REQUIRED_OPERATIONS <= operations
    assert len(candidate["observations"]) >= 10
    assert candidate["candidate_metadata"][
        "cloud_data_target"
    ].startswith("arn:aws:s3:::")
    assert candidate["candidate_metadata"][
        "failed_data_key_call_observed"
    ] is True
    assert candidate["candidate_metadata"][
        "successful_data_key_call_observed"
    ] is True
    assert candidate["policy"]["labels_generated"] == 0
    assert candidate["policy"]["candidate_is_not_gold"] is True
    assert candidate["annotation"]["status"] == "pending"
    assert candidate["nodes"] == []
    assert candidate["edges"] == []
    assert all(
        item["path_label"] is None
        and item["evidence_state"] is None
        for item in candidate["observations"]
    )


def test_every_observation_is_bound_to_the_pinned_raw_artifact():
    candidate = build()

    assert candidate["source"]["raw_artifact"]["sha256"] == (
        EXPECTED_SHA256
    )
    assert all(
        item["raw_ref"]["sha256"] == EXPECTED_SHA256
        and isinstance(item["raw_ref"]["record_index"], int)
        for item in candidate["observations"]
    )
    ids = [item["observation_id"] for item in candidate["observations"]]
    assert len(ids) == len(set(ids))


def test_candidate_builder_rejects_raw_hash_drift(tmp_path):
    root = tmp_path
    raw = root / "raw.json"
    raw.write_text("{}\n", encoding="utf-8")
    metadata = root / "metadata.yml"
    metadata.write_text("datasets: []\n", encoding="utf-8")
    manifest = {
        "sources": [{
            "source_id": "splunk_attack_data",
            "repository": "splunk/attack_data",
            "commit": (
                "3821bdb77c66c95b4e529f62a9d00b168446d1a8"
            ),
            "artifacts": [
                {
                    "name": "aws_kms_key.json",
                    "relative_path": "raw.json",
                    "sha256": sha256(raw.read_bytes()).hexdigest(),
                    "bytes": raw.stat().st_size,
                    "url": "https://example.invalid/raw",
                },
                {
                    "name": "aws_kms_key.yml",
                    "relative_path": "metadata.yml",
                    "sha256": sha256(metadata.read_bytes()).hexdigest(),
                    "bytes": metadata.stat().st_size,
                    "url": "https://example.invalid/metadata",
                },
            ],
        }],
    }
    manifest_path = (
        root / "data" / "real_sources" / "acquisition_manifest.json"
    )
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="hash changed"):
        build(root)
