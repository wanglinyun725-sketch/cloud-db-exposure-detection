from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

from src.data.lineage_admission_audit import audit_candidate_packet


def _packet(raw_ref: str, digest: str) -> dict:
    return {
        "packet_kind": "test_unlabeled",
        "cases": [{
            "case_id": "case-1",
            "source": {
                "source_id": "source-1",
                "upstream_url": "https://example.test/source",
                "version_or_commit": "commit-1",
                "license": "MIT",
                "provenance_level": "B",
                "raw_artifacts": [{
                    "raw_ref": raw_ref,
                    "sha256": digest,
                }],
            },
            "candidate_metadata": {
                "source_id": "source-1",
                "independence_group": "group-1",
            },
            "annotation": {"status": "pending"},
            "nodes": [],
            "edges": [],
            "path_labels": [],
            "admission_screen": {"decision": None},
            "observations": [{
                "observation_id": "obs-1",
                "schema": "aws_cloudtrail",
                "service": "s3",
                "operation": "GetObject",
                "event_status": "success",
                "raw_ref": {
                    "relative_path": raw_ref,
                    "sha256": digest,
                },
            }],
            "runtime_instances": [{
                "instance_id": "instance-1",
                "platform": "AWS",
                "observation_ids": ["obs-1"],
                "observation_count": 1,
            }],
        }],
    }


def test_audit_accepts_verified_archive_member(tmp_path: Path) -> None:
    payload = b'{"eventName":"GetObject"}'
    archive_path = tmp_path / "raw.zip"
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("logs/event.json", payload)
    packet = _packet(
        "raw.zip#logs/event.json",
        sha256(payload).hexdigest(),
    )

    audit = audit_candidate_packet(tmp_path, packet)

    assert audit["runtime_annotation_ready_groups"] == 1
    assert audit["integrity"]["group_blocker_count"] == 0
    assert audit["generated_gold_labels"] == 0


def test_audit_rejects_hash_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "event.json"
    artifact.write_bytes(b"real")
    packet = _packet("event.json", sha256(b"different").hexdigest())

    audit = audit_candidate_packet(tmp_path, packet)

    assert audit["runtime_annotation_ready_groups"] == 0
    assert audit["integrity"]["group_blocker_count"] == 1
    assert audit["groups"][0]["admission_class"] == (
        "blocked_metadata_or_integrity"
    )


def test_real_packet_stays_label_blind_and_group_aware() -> None:
    root = Path(__file__).resolve().parents[1]
    import json

    packet_path = (
        root
        / "data"
        / "real_sources"
        / "annotation"
        / "expanded_full_pool_v0_5_unlabeled.json"
    )
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    audit = audit_candidate_packet(root, packet, verify_hashes=False)

    assert audit["case_count"] == 150
    assert audit["independence_group_count"] == 113
    assert audit["runtime_annotation_ready_groups"] == 32
    assert audit["generated_gold_labels"] == 0
