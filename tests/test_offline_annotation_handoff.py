from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import zipfile

import pytest

from src.annotation.offline_handoff import (
    build_outbound_handoff,
    seal_completed_handoff,
    verify_returned_handoff,
)
from src.annotation.task_bundle import (
    assignment_progress,
    build_case_bundle,
    merge_case_bundle,
)
from src.annotation.workflow import create_assignment


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT / "data" / "real_sources" / "annotation"
    / "pilot_round1_unlabeled.json"
)


def _write_bundle(directory, assignment):
    manifest, documents = build_case_bundle(assignment)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "assignment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    for name, document in documents.items():
        (directory / name).write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def _complete_rejected(assignment):
    result = deepcopy(assignment)
    for case in result["cases"]:
        case["human_attestation"] = True
        case["completed_at"] = datetime.now(timezone.utc).isoformat()
        case["admission_screen"] = {
            "external_or_low_privilege_entry_defined": False,
            "multi_step_path_present": True,
            "cloud_data_target_present": True,
            "critical_edges_have_raw_evidence": True,
            "not_a_near_duplicate": True,
            "decision": "reject",
            "rationale": (
                "A human independently reviewed the frozen source evidence."
            ),
        }
    return result


def _blank_reviewer():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    return create_assignment(packet, "reviewer", "human-offline-reviewer")


def test_outbound_handoff_is_deterministic_blank_and_blind(tmp_path):
    assignment = _blank_reviewer()
    task_dir = tmp_path / "tasks"
    _write_bundle(task_dir, assignment)

    first, receipt = build_outbound_handoff(
        task_dir,
        git_commit="a" * 40,
    )
    second, _ = build_outbound_handoff(
        task_dir,
        git_commit="a" * 40,
    )

    assert first == second
    assert receipt["role"] == "reviewer"
    assert receipt["case_count"] == len(assignment["cases"])
    with zipfile.ZipFile(__import__("io").BytesIO(first)) as archive:
        handoff = json.loads(archive.read("HANDOFF.json"))
        payload = b"".join(
            archive.read(name) for name in archive.namelist()
        )
    assert handoff["label_fields_prepopulated"] == 0
    assert handoff["other_annotator_labels_included"] is False
    assert b"human-offline-reviewer" in payload
    assert b"human-primary" not in payload


def test_completed_handoff_round_trip_requires_separate_digest(tmp_path):
    blank = _blank_reviewer()
    origin_tasks = tmp_path / "origin"
    _write_bundle(origin_tasks, blank)
    outbound, receipt = build_outbound_handoff(
        origin_tasks,
        git_commit="b" * 40,
    )
    workspace = tmp_path / "reviewer-workspace"
    with zipfile.ZipFile(
        __import__("io").BytesIO(outbound)
    ) as archive:
        archive.extractall(workspace)
    completed = _complete_rejected(blank)
    _, completed_documents = build_case_bundle(completed)
    for name, document in completed_documents.items():
        (workspace / "tasks" / name).write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    returned, seal = seal_completed_handoff(
        workspace,
        observed_git_commit="b" * 40,
    )
    manifest, payloads = verify_returned_handoff(
        returned,
        receipt,
        expected_submission_sha256=seal["submission_sha256"],
    )
    assignment = merge_case_bundle(
        manifest,
        {
            name: json.loads(payload.decode("utf-8"))
            for name, payload in payloads.items()
        },
    )

    assert assignment_progress(assignment)["ready_for_agreement"] is True
    assert assignment["role"] == "reviewer"
    assert seal["send_digest_via_separate_trusted_channel"] is True

    with pytest.raises(ValueError, match="trusted channel"):
        verify_returned_handoff(
            returned,
            receipt,
            expected_submission_sha256="0" * 64,
        )


def test_blank_or_source_tampered_handoff_cannot_be_sealed(tmp_path):
    assignment = _blank_reviewer()
    task_dir = tmp_path / "tasks"
    _write_bundle(task_dir, assignment)
    outbound, _ = build_outbound_handoff(
        task_dir,
        git_commit="c" * 40,
    )
    workspace = tmp_path / "workspace"
    with zipfile.ZipFile(
        __import__("io").BytesIO(outbound)
    ) as archive:
        archive.extractall(workspace)

    with pytest.raises(ValueError, match="incomplete/invalid"):
        seal_completed_handoff(
            workspace,
            observed_git_commit="c" * 40,
        )

    completed = _complete_rejected(assignment)
    _, documents = build_case_bundle(completed)
    first_name = next(iter(documents))
    documents[first_name]["source"]["license"] = "tampered"
    for name, document in documents.items():
        (workspace / "tasks" / name).write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    with pytest.raises(ValueError, match="source context content changed"):
        seal_completed_handoff(
            workspace,
            observed_git_commit="c" * 40,
        )


def test_sealing_rejects_a_different_repository_version(tmp_path):
    assignment = _blank_reviewer()
    task_dir = tmp_path / "tasks"
    _write_bundle(task_dir, assignment)
    outbound, _ = build_outbound_handoff(
        task_dir,
        git_commit="e" * 40,
    )
    workspace = tmp_path / "workspace"
    with zipfile.ZipFile(
        __import__("io").BytesIO(outbound)
    ) as archive:
        archive.extractall(workspace)

    with pytest.raises(ValueError, match="differs from the frozen"):
        seal_completed_handoff(
            workspace,
            observed_git_commit="f" * 40,
        )


def test_outbound_export_rejects_any_prefilled_human_decision(tmp_path):
    assignment = _blank_reviewer()
    assignment["cases"][0]["admission_screen"]["decision"] = "reject"
    task_dir = tmp_path / "tasks"
    _write_bundle(task_dir, assignment)

    with pytest.raises(ValueError, match="entirely blank"):
        build_outbound_handoff(
            task_dir,
            git_commit="d" * 40,
        )
