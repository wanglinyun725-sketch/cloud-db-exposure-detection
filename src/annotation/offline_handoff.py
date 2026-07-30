"""Tamper-evident offline handoff for blind human annotation bundles."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
import zipfile

from src.annotation.task_bundle import (
    assignment_progress,
    load_case_bundle_directory,
    merge_case_bundle,
    negative_assignment_progress,
)


HANDOFF_NAME = "HANDOFF.json"
SUBMISSION_NAME = "SUBMISSION.json"
README_NAME = "README_REVIEWER.md"
TASK_PREFIX = "tasks/"
MAX_ARCHIVE_MEMBERS = 1000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024


def build_outbound_handoff(
    task_dir: str | Path,
    *,
    git_commit: str,
) -> tuple[bytes, dict[str, Any]]:
    """Package one still-blank assignment and return its local receipt."""
    _validate_git_commit(git_commit)
    task_dir = Path(task_dir).resolve()
    assignment = load_case_bundle_directory(task_dir)
    progress = _progress(assignment)
    if progress["counts"]["blank"] != progress["case_count"]:
        raise ValueError(
            "outbound blind handoff requires an entirely blank assignment"
        )
    manifest_bytes, case_payloads = _task_payloads(task_dir)
    assignment_manifest = json.loads(manifest_bytes.decode("utf-8"))
    handoff = {
        "handoff_version": "1.0",
        "purpose": "independent_blind_human_annotation",
        "git_commit": git_commit,
        "assignment_id": assignment.get("assignment_id"),
        "packet_sha256": assignment.get("packet_sha256"),
        "role": assignment.get("role"),
        "annotator_id": assignment.get("annotator_id"),
        "case_count": len(assignment["cases"]),
        "assignment_manifest_sha256": sha256(
            manifest_bytes
        ).hexdigest(),
        "task_files": sorted(case_payloads),
        "label_fields_prepopulated": 0,
        "other_annotator_labels_included": False,
        "submission_sha256_must_use_separate_channel": True,
    }
    handoff_bytes = _json_bytes(handoff)
    archive_files = {
        HANDOFF_NAME: handoff_bytes,
        README_NAME: _reviewer_readme(handoff).encode("utf-8"),
        f"{TASK_PREFIX}assignment_manifest.json": manifest_bytes,
        **{
            f"{TASK_PREFIX}{name}": payload
            for name, payload in case_payloads.items()
        },
    }
    archive = _deterministic_zip(archive_files)
    receipt = {
        "receipt_version": "1.0",
        "keep_private_on_origin_machine": True,
        "handoff_manifest_sha256": sha256(handoff_bytes).hexdigest(),
        "outbound_archive_sha256": sha256(archive).hexdigest(),
        "assignment_id": handoff["assignment_id"],
        "packet_sha256": handoff["packet_sha256"],
        "role": handoff["role"],
        "annotator_id": handoff["annotator_id"],
        "git_commit": git_commit,
        "case_count": handoff["case_count"],
    }
    return archive, receipt


def seal_completed_handoff(
    workspace: str | Path,
    *,
    observed_git_commit: str,
) -> tuple[bytes, dict[str, Any]]:
    """Seal a completed extracted handoff for return to the origin."""
    _validate_git_commit(observed_git_commit)
    workspace = Path(workspace).resolve()
    handoff_bytes = (workspace / HANDOFF_NAME).read_bytes()
    handoff = _json_object(handoff_bytes, HANDOFF_NAME)
    if handoff.get("git_commit") != observed_git_commit:
        raise ValueError(
            "current Git commit differs from the frozen handoff commit"
        )
    task_dir = workspace / "tasks"
    manifest_bytes, case_payloads = _task_payloads(task_dir)
    _validate_static_handoff(handoff, manifest_bytes, case_payloads)
    assignment = load_case_bundle_directory(task_dir)
    _validate_assignment_identity(assignment, handoff)
    progress = _progress(assignment)
    if progress["ready_for_agreement"] is not True:
        raise ValueError(
            "cannot seal an incomplete/invalid human assignment: "
            + repr(progress["counts"])
        )
    task_hashes = {
        name: sha256(payload).hexdigest()
        for name, payload in sorted(case_payloads.items())
    }
    submission = {
        "submission_version": "1.0",
        "handoff_manifest_sha256": sha256(handoff_bytes).hexdigest(),
        "assignment_manifest_sha256": sha256(
            manifest_bytes
        ).hexdigest(),
        "assignment_payload_sha256": _stable_hash(assignment),
        "assignment_id": assignment["assignment_id"],
        "role": assignment["role"],
        "annotator_id": assignment["annotator_id"],
        "case_count": len(assignment["cases"]),
        "all_cases_valid_complete": True,
        "sealing_git_commit": observed_git_commit,
        "task_file_sha256": task_hashes,
    }
    archive_files = {
        HANDOFF_NAME: handoff_bytes,
        SUBMISSION_NAME: _json_bytes(submission),
        f"{TASK_PREFIX}assignment_manifest.json": manifest_bytes,
        **{
            f"{TASK_PREFIX}{name}": payload
            for name, payload in case_payloads.items()
        },
    }
    archive = _deterministic_zip(archive_files)
    return archive, {
        "submission_sha256": sha256(archive).hexdigest(),
        "send_digest_via_separate_trusted_channel": True,
        "assignment_id": assignment["assignment_id"],
        "role": assignment["role"],
        "annotator_id": assignment["annotator_id"],
        "case_count": len(assignment["cases"]),
    }


def verify_returned_handoff(
    archive: bytes,
    receipt: Mapping[str, Any],
    *,
    expected_submission_sha256: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Verify a returned archive and yield its original task layout."""
    _validate_sha256(
        expected_submission_sha256,
        "expected submission SHA-256",
    )
    if sha256(archive).hexdigest() != expected_submission_sha256:
        raise ValueError(
            "returned archive SHA-256 differs from the digest supplied "
            "through the trusted channel"
        )
    files = _read_zip(archive)
    handoff_bytes = files.get(HANDOFF_NAME)
    submission_bytes = files.get(SUBMISSION_NAME)
    if handoff_bytes is None or submission_bytes is None:
        raise ValueError("returned archive lacks handoff/submission manifest")
    if (
        sha256(handoff_bytes).hexdigest()
        != receipt.get("handoff_manifest_sha256")
    ):
        raise ValueError("returned handoff differs from the local receipt")
    handoff = _json_object(handoff_bytes, HANDOFF_NAME)
    submission = _json_object(submission_bytes, SUBMISSION_NAME)
    manifest_member = f"{TASK_PREFIX}assignment_manifest.json"
    manifest_bytes = files.get(manifest_member)
    if manifest_bytes is None:
        raise ValueError("returned archive lacks assignment manifest")
    case_payloads = {
        name.removeprefix(TASK_PREFIX): payload
        for name, payload in files.items()
        if name.startswith(TASK_PREFIX)
        and name != manifest_member
    }
    expected_members = {
        HANDOFF_NAME,
        SUBMISSION_NAME,
        manifest_member,
        *(
            f"{TASK_PREFIX}{name}"
            for name in handoff.get("task_files") or []
        ),
    }
    if set(files) != expected_members:
        raise ValueError("returned archive member set changed")
    _validate_static_handoff(handoff, manifest_bytes, case_payloads)
    if submission.get("handoff_manifest_sha256") != sha256(
        handoff_bytes
    ).hexdigest():
        raise ValueError("submission refers to another handoff")
    expected_task_hashes = {
        name: sha256(payload).hexdigest()
        for name, payload in sorted(case_payloads.items())
    }
    if submission.get("task_file_sha256") != expected_task_hashes:
        raise ValueError("submitted task file hash mismatch")
    if (
        submission.get("assignment_manifest_sha256")
        != sha256(manifest_bytes).hexdigest()
    ):
        raise ValueError("submitted assignment manifest hash mismatch")
    assignment_manifest = _json_object(
        manifest_bytes,
        "assignment_manifest.json",
    )
    documents = {
        name: _json_object(payload, name)
        for name, payload in case_payloads.items()
    }
    assignment = merge_case_bundle(assignment_manifest, documents)
    _validate_assignment_identity(assignment, handoff)
    if submission.get("assignment_payload_sha256") != _stable_hash(
        assignment
    ):
        raise ValueError("submitted assignment payload hash mismatch")
    progress = _progress(assignment)
    if progress["ready_for_agreement"] is not True:
        raise ValueError("returned human assignment is incomplete or invalid")
    if submission.get("all_cases_valid_complete") is not True:
        raise ValueError("submission does not attest complete validation")
    if submission.get("sealing_git_commit") != handoff.get("git_commit"):
        raise ValueError("submission was sealed with another Git commit")
    for field in (
        "assignment_id",
        "packet_sha256",
        "role",
        "annotator_id",
        "git_commit",
    ):
        if receipt.get(field) != handoff.get(field):
            raise ValueError(f"local receipt {field} mismatch")
    return assignment_manifest, case_payloads


def _task_payloads(
    task_dir: Path,
) -> tuple[bytes, dict[str, bytes]]:
    manifest_path = task_dir / "assignment_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"assignment manifest is missing: {manifest_path}")
    manifest_bytes = manifest_path.read_bytes()
    manifest = _json_object(manifest_bytes, manifest_path.name)
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("assignment manifest has no task entries")
    payloads: dict[str, bytes] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("assignment manifest entry is malformed")
        name = _safe_name(entry.get("file"))
        path = task_dir / name
        if not path.is_file():
            raise ValueError(f"assignment task is missing: {path}")
        payloads[name] = path.read_bytes()
    expected = {entry["file"] for entry in entries}
    if set(payloads) != expected:
        raise ValueError("assignment task file set changed")
    return manifest_bytes, payloads


def _validate_static_handoff(
    handoff: Mapping[str, Any],
    manifest_bytes: bytes,
    case_payloads: Mapping[str, bytes],
) -> None:
    if handoff.get("handoff_version") != "1.0":
        raise ValueError("unsupported handoff version")
    if (
        handoff.get("assignment_manifest_sha256")
        != sha256(manifest_bytes).hexdigest()
    ):
        raise ValueError("assignment manifest differs from handoff")
    if set(handoff.get("task_files") or []) != set(case_payloads):
        raise ValueError("handoff task file set changed")
    if handoff.get("label_fields_prepopulated") != 0:
        raise ValueError("handoff claims prepopulated labels")
    if handoff.get("other_annotator_labels_included") is not False:
        raise ValueError("handoff violates blind-review isolation")


def _validate_assignment_identity(
    assignment: Mapping[str, Any],
    handoff: Mapping[str, Any],
) -> None:
    for field in (
        "assignment_id",
        "packet_sha256",
        "role",
        "annotator_id",
    ):
        if assignment.get(field) != handoff.get(field):
            raise ValueError(f"returned assignment {field} changed")
    if len(assignment.get("cases") or []) != handoff.get("case_count"):
        raise ValueError("returned assignment case count changed")


def _progress(assignment: dict[str, Any]) -> dict[str, Any]:
    cases = assignment.get("cases") or []
    if cases and "candidate_id" in cases[0]:
        return negative_assignment_progress(assignment)
    return assignment_progress(assignment)


def _read_zip(payload: bytes) -> dict[str, bytes]:
    stream = BytesIO(payload)
    if not zipfile.is_zipfile(stream):
        raise ValueError("handoff is not a ZIP archive")
    with zipfile.ZipFile(stream) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("handoff archive has too many members")
        if any(info.file_size > MAX_MEMBER_BYTES for info in infos):
            raise ValueError("handoff archive member exceeds size limit")
        if sum(info.file_size for info in infos) > MAX_TOTAL_BYTES:
            raise ValueError("handoff archive exceeds total size limit")
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("handoff archive has duplicate members")
        output = {}
        for raw_name in names:
            name = _safe_archive_name(raw_name)
            if name.endswith("/"):
                raise ValueError("handoff archive must not contain directories")
            output[name] = archive.read(raw_name)
        return output


def _deterministic_zip(files: Mapping[str, bytes]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(
        stream,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name, payload in sorted(files.items()):
            safe_name = _safe_archive_name(name)
            info = zipfile.ZipInfo(
                safe_name,
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)
    return stream.getvalue()


def _reviewer_readme(handoff: Mapping[str, Any]) -> str:
    return f"""# Independent blind annotation handoff

Assignment: `{handoff['assignment_id']}`
Role: `{handoff['role']}`
Annotator: `{handoff['annotator_id']}`
Frozen Git commit: `{handoff['git_commit']}`

1. Clone the repository and check out the exact frozen commit above.
2. Run the local review app against the extracted `tasks` directory.
3. Do not obtain or inspect the other annotator's labels.
4. After every case is human-attested and valid, seal the workspace:

```powershell
python scripts/annotation/manage_offline_handoff.py seal `
  --workspace <this-directory> `
  --output reviewer_completed.zip
```

Send the ZIP normally. Send the printed submission SHA-256 through a separate
trusted channel so the origin can detect transport substitution.
"""


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


def _json_object(payload: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{name} root must be an object")
    return value


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _safe_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid task filename")
    if Path(value).name != value or value in {".", ".."}:
        raise ValueError(f"unsafe task filename: {value}")
    return value


def _safe_archive_name(value: str) -> str:
    normalized = value.replace("\\", "/").strip("/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
    ):
        raise ValueError(f"unsafe archive path: {value}")
    return str(path)


def _validate_git_commit(value: str) -> None:
    if (
        len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("git_commit must be a full lowercase SHA-1")


def _validate_sha256(value: str, label: str) -> None:
    if (
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase hexadecimal")
