"""Label-blind provenance audit for real-source annotation candidates."""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Iterable
from zipfile import BadZipFile, ZipFile


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FINAL_ANNOTATION_STATUSES = {"reviewed", "adjudicated"}
SUPPORTED_PLATFORMS = {"AWS", "AZURE", "GCP"}


def audit_candidate_packet(
    root: Path,
    packet: dict[str, Any],
    *,
    verify_hashes: bool = True,
) -> dict[str, Any]:
    """Audit metadata and immutable artifacts without reading path labels."""
    cases = packet.get("cases")
    if not isinstance(cases, list):
        raise ValueError("candidate packet must contain a cases list")

    hash_cache: dict[str, str] = {}
    case_rows = [
        _audit_case(
            root,
            case,
            verify_hashes=verify_hashes,
            hash_cache=hash_cache,
        )
        for case in cases
    ]
    fingerprints: dict[str, set[str]] = defaultdict(set)
    for row in case_rows:
        if row["runtime_fingerprint"]:
            fingerprints[row["runtime_fingerprint"]].add(
                row["independence_group"]
            )
    collision_groups = {
        group
        for groups in fingerprints.values()
        if len(groups) > 1
        for group in groups
    }

    rows_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        rows_by_group[row["independence_group"]].append(row)

    group_rows = []
    for group_id, rows in sorted(rows_by_group.items()):
        blockers = sorted({
            blocker
            for row in rows
            for blocker in row["blockers"]
        })
        warnings = sorted({
            warning
            for row in rows
            for warning in row["warnings"]
        })
        if group_id in collision_groups:
            warnings.append(
                "runtime_sequence_collides_with_another_independence_group"
            )
        runtime_cases = sum(row["runtime_ready"] for row in rows)
        runtime_instances = sum(row["runtime_instances"] for row in rows)
        provenance_levels = sorted({
            row["provenance_level"] for row in rows
        })
        platforms = sorted({
            platform
            for row in rows
            for platform in row["platforms"]
        })
        source_ids = sorted({row["source_id"] for row in rows})
        metadata_pass = not blockers
        if metadata_pass and runtime_cases:
            admission_class = "runtime_annotation_ready"
        elif metadata_pass:
            admission_class = "static_needs_runtime_or_provider_oracle"
        else:
            admission_class = "blocked_metadata_or_integrity"
        group_rows.append({
            "independence_group": group_id,
            "case_ids": sorted(row["case_id"] for row in rows),
            "source_ids": source_ids,
            "provenance_levels": provenance_levels,
            "platforms": platforms,
            "case_count": len(rows),
            "runtime_case_count": runtime_cases,
            "runtime_instance_count": runtime_instances,
            "admission_class": admission_class,
            "blockers": blockers,
            "warnings": sorted(set(warnings)),
        })

    class_counts = Counter(
        row["admission_class"] for row in group_rows
    )
    ready = [
        row for row in group_rows
        if row["admission_class"] == "runtime_annotation_ready"
    ]
    ready_platform_groups = Counter()
    for row in ready:
        for platform in row["platforms"]:
            ready_platform_groups[platform] += 1
    ready_source_groups = Counter()
    for row in ready:
        for source_id in row["source_ids"]:
            ready_source_groups[source_id] += 1

    return {
        "audit_version": "1.0",
        "label_blind": True,
        "generated_gold_labels": 0,
        "packet_kind": packet.get("packet_kind"),
        "case_count": len(case_rows),
        "independence_group_count": len(group_rows),
        "group_class_counts": dict(sorted(class_counts.items())),
        "runtime_annotation_ready_groups": len(ready),
        "runtime_ready_platform_group_counts": dict(
            sorted(ready_platform_groups.items())
        ),
        "runtime_ready_source_group_counts": dict(
            sorted(ready_source_groups.items())
        ),
        "runtime_ready_source_count": len(ready_source_groups),
        "target_gap": {
            "operational_target_groups": 80,
            "confirmatory_target_groups": 67,
            "runtime_ready_gap_to_operational_target": max(
                0, 80 - len(ready)
            ),
            "runtime_ready_gap_to_confirmatory_target": max(
                0, 67 - len(ready)
            ),
        },
        "integrity": {
            "verified_unique_refs": len(hash_cache),
            "case_blocker_count": sum(
                bool(row["blockers"]) for row in case_rows
            ),
            "group_blocker_count": sum(
                bool(row["blockers"]) for row in group_rows
            ),
            "runtime_fingerprint_collision_group_count": len(
                collision_groups
            ),
        },
        "groups": group_rows,
    }


def _audit_case(
    root: Path,
    case: dict[str, Any],
    *,
    verify_hashes: bool,
    hash_cache: dict[str, str],
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    case_id = _required_text(case.get("case_id"), "case_id", blockers)
    source = case.get("source") or {}
    metadata = case.get("candidate_metadata") or {}
    source_id = _required_text(
        source.get("source_id"),
        "source.source_id",
        blockers,
    )
    _required_text(source.get("upstream_url"), "source.upstream_url", blockers)
    _required_text(
        source.get("version_or_commit"),
        "source.version_or_commit",
        blockers,
    )
    _required_text(source.get("license"), "source.license", blockers)
    provenance_level = _required_text(
        source.get("provenance_level"),
        "source.provenance_level",
        blockers,
    )
    group_id = _required_text(
        metadata.get("independence_group"),
        "candidate_metadata.independence_group",
        blockers,
    )
    if source_id and metadata.get("source_id") not in {None, source_id}:
        blockers.append("candidate_metadata.source_id_mismatch")

    artifacts = source.get("raw_artifacts")
    artifact_hashes: set[str] = set()
    if not isinstance(artifacts, list) or not artifacts:
        blockers.append("source.raw_artifacts_missing")
    else:
        for artifact in artifacts:
            artifact_sha = str(artifact.get("sha256") or "").lower()
            if SHA256_PATTERN.fullmatch(artifact_sha):
                artifact_hashes.add(artifact_sha)
            _audit_ref(
                root,
                artifact.get("raw_ref"),
                artifact.get("sha256"),
                "source.raw_artifact",
                blockers,
                verify_hashes=verify_hashes,
                hash_cache=hash_cache,
            )

    annotation = case.get("annotation") or {}
    if annotation.get("status") in FINAL_ANNOTATION_STATUSES:
        warnings.append("case_already_has_final_human_annotation")
    if any(case.get(field) for field in ("nodes", "edges", "path_labels")):
        blockers.append("candidate_packet_contains_nonempty_gold_fields")
    admission = case.get("admission_screen") or {}
    if admission.get("decision") is not None:
        blockers.append("candidate_packet_contains_admission_decision")

    observations = case.get("observations") or []
    observation_ids = {
        observation.get("observation_id") for observation in observations
    }
    if None in observation_ids:
        blockers.append("observation_id_missing")
    for observation in observations:
        raw_ref = observation.get("raw_ref") or {}
        _audit_ref(
            root,
            raw_ref.get("relative_path"),
            raw_ref.get("sha256"),
            "observation.raw_ref",
            blockers,
            verify_hashes=verify_hashes,
            hash_cache=hash_cache,
        )

    runtime_instances = case.get("runtime_instances") or []
    platforms: set[str] = set()
    runtime_ready = False
    fingerprint_observations = list(observations)
    for instance in runtime_instances:
        platform = str(instance.get("platform") or "").upper()
        if platform not in SUPPORTED_PLATFORMS:
            blockers.append("runtime_instance.platform_invalid")
        else:
            platforms.add(platform)
        refs = instance.get("observation_ids")
        embedded = instance.get("observations")
        if isinstance(refs, list) and refs:
            if not set(refs).issubset(observation_ids):
                blockers.append("runtime_instance.observation_ref_missing")
                continue
            if instance.get("observation_count") != len(refs):
                blockers.append("runtime_instance.observation_count_mismatch")
                continue
            runtime_ready = True
        elif isinstance(embedded, list) and embedded:
            if instance.get("observation_count") != len(embedded):
                blockers.append("runtime_instance.observation_count_mismatch")
                continue
            if any(
                not observation.get("observation_id")
                for observation in embedded
            ):
                blockers.append("runtime_instance.observation_id_missing")
                continue
            for observation in embedded:
                _audit_embedded_observation_ref(
                    root,
                    observation.get("raw_ref") or {},
                    artifact_hashes,
                    blockers,
                    verify_hashes=verify_hashes,
                    hash_cache=hash_cache,
                )
            fingerprint_observations.extend(embedded)
            runtime_ready = True
        else:
            blockers.append("runtime_instance.observations_empty")
    if runtime_instances and not runtime_ready:
        blockers.append("no_valid_runtime_instance")
    if runtime_ready and provenance_level != "B":
        warnings.append("runtime_ready_case_not_marked_provenance_B")

    fingerprint = _runtime_fingerprint(
        fingerprint_observations,
        platforms,
    )
    return {
        "case_id": case_id,
        "independence_group": group_id,
        "source_id": source_id,
        "provenance_level": provenance_level,
        "platforms": sorted(platforms),
        "runtime_instances": len(runtime_instances),
        "runtime_ready": runtime_ready,
        "runtime_fingerprint": fingerprint,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
    }


def _audit_embedded_observation_ref(
    root: Path,
    raw_ref: dict[str, Any],
    artifact_hashes: set[str],
    blockers: list[str],
    *,
    verify_hashes: bool,
    hash_cache: dict[str, str],
) -> None:
    archive_path = raw_ref.get("archive_relative_path")
    member_path = raw_ref.get("member_path")
    if isinstance(archive_path, str) and archive_path and isinstance(
        member_path, str
    ) and member_path:
        archive_sha = str(raw_ref.get("archive_sha256") or "").lower()
        member_sha = str(raw_ref.get("member_sha256") or "").lower()
        if not SHA256_PATTERN.fullmatch(archive_sha):
            blockers.append(
                "runtime_observation.archive_sha256_invalid"
            )
        else:
            _audit_ref(
                root,
                archive_path,
                archive_sha,
                "runtime_observation.archive",
                blockers,
                verify_hashes=verify_hashes,
                hash_cache=hash_cache,
            )
        _audit_ref(
            root,
            f"{archive_path}#{member_path}",
            member_sha,
            "runtime_observation.archive_member",
            blockers,
            verify_hashes=verify_hashes,
            hash_cache=hash_cache,
        )
        if raw_ref.get("record_index") is None:
            blockers.append("runtime_observation.record_index_missing")
        return

    relative_path = raw_ref.get("relative_path")
    expected = str(raw_ref.get("sha256") or "").lower()
    if not isinstance(relative_path, str) or not relative_path:
        blockers.append("runtime_observation.raw_ref_path_missing")
        return
    if not SHA256_PATTERN.fullmatch(expected):
        blockers.append("runtime_observation.raw_ref_sha256_invalid")
        return
    if relative_path.startswith(("doi:", "https://", "http://")):
        archive_sha = str(raw_ref.get("archive_sha256") or "").lower()
        if not SHA256_PATTERN.fullmatch(archive_sha):
            blockers.append(
                "runtime_observation.archive_sha256_invalid"
            )
        elif archive_sha not in artifact_hashes:
            blockers.append(
                "runtime_observation.archive_sha256_not_in_source_artifacts"
            )
        if raw_ref.get("record_index") is None:
            blockers.append("runtime_observation.record_index_missing")
        if not raw_ref.get("upstream_path"):
            blockers.append("runtime_observation.upstream_path_missing")
        return
    _audit_ref(
        root,
        relative_path,
        expected,
        "runtime_observation.raw_ref",
        blockers,
        verify_hashes=verify_hashes,
        hash_cache=hash_cache,
    )


def _audit_ref(
    root: Path,
    raw_ref: Any,
    expected_sha256: Any,
    field: str,
    blockers: list[str],
    *,
    verify_hashes: bool,
    hash_cache: dict[str, str],
) -> None:
    if not isinstance(raw_ref, str) or not raw_ref:
        blockers.append(f"{field}_path_missing")
        return
    if not isinstance(expected_sha256, str) or not SHA256_PATTERN.fullmatch(
        expected_sha256.lower()
    ):
        blockers.append(f"{field}_sha256_invalid")
        return
    try:
        resolved = _resolve_inside_root(root, raw_ref)
    except ValueError:
        blockers.append(f"{field}_path_escapes_root")
        return
    if not resolved["base_path"].is_file():
        blockers.append(f"{field}_file_missing")
        return
    if not verify_hashes:
        return
    try:
        actual = _hash_ref(raw_ref, resolved, hash_cache)
    except (BadZipFile, KeyError, OSError):
        blockers.append(f"{field}_archive_member_unreadable")
        return
    if actual != expected_sha256.lower():
        blockers.append(f"{field}_sha256_mismatch")


def _resolve_inside_root(root: Path, raw_ref: str) -> dict[str, Any]:
    base_ref, separator, member = raw_ref.partition("#")
    root_resolved = root.resolve()
    base_path = (root / base_ref).resolve()
    if root_resolved != base_path and root_resolved not in base_path.parents:
        raise ValueError("reference escapes root")
    return {
        "base_path": base_path,
        "member": member if separator else None,
    }


def _hash_ref(
    raw_ref: str,
    resolved: dict[str, Any],
    cache: dict[str, str],
) -> str:
    if raw_ref in cache:
        return cache[raw_ref]
    digest = sha256()
    member = resolved["member"]
    if member is None:
        with resolved["base_path"].open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    else:
        with ZipFile(resolved["base_path"]) as archive:
            with archive.open(member) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    value = digest.hexdigest()
    cache[raw_ref] = value
    return value


def _runtime_fingerprint(
    observations: Iterable[dict[str, Any]],
    platforms: set[str],
) -> str | None:
    sequence = [
        (
            str(observation.get("schema") or ""),
            str(observation.get("service") or ""),
            str(observation.get("operation") or ""),
            str(observation.get("event_status") or ""),
        )
        for observation in observations
    ]
    if not sequence:
        return None
    material = repr((tuple(sorted(platforms)), tuple(sequence)))
    return sha256(material.encode("utf-8")).hexdigest()


def _required_text(
    value: Any,
    field: str,
    blockers: list[str],
) -> str:
    if not isinstance(value, str) or not value.strip():
        blockers.append(f"{field}_missing")
        return ""
    return value.strip()
