"""Deterministically audit pinned replay artifacts without executing them."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable, Mapping
from zipfile import ZipFile, ZipInfo


MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
TEXT_SUFFIXES = {
    ".bash",
    ".cfg",
    ".conf",
    ".dockerfile",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".tf",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_BASENAMES = {"dockerfile", "makefile"}
BLOCKING_SEVERITIES = {"critical", "high"}


@dataclass(frozen=True)
class SafetyRule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    path_pattern: re.Pattern[str] | None = None


RULES = (
    SafetyRule(
        "RS001",
        "credential material is placed in a container build layer",
        "critical",
        re.compile(
            r"(?i)^\s*(?:ENV|ARG)\s+.*(?:access[_-]?key|"
            r"client[_-]?secret|password|credentials?)"
        ),
        re.compile(r"(?i)(?:^|/)dockerfile$"),
    ),
    SafetyRule(
        "RS002",
        "a command may print credential material to output",
        "critical",
        re.compile(
            r"(?i)\b(?:echo|printf)\b[^\n]{0,240}"
            r"(?:password|secret|access[_-]?key|credentials?)"
        ),
    ),
    SafetyRule(
        "RS003",
        "a long-lived cloud credential or service-principal secret is created",
        "critical",
        re.compile(
            r"(?i)(?:service-accounts\s+keys\s+create|"
            r"create-for-rbac|create-access-key|"
            r"reset-credentials|credential\s+reset)"
        ),
    ),
    SafetyRule(
        "RS004",
        "a public principal, public ACL, or public sharing group is enabled",
        "critical",
        re.compile(
            r"(?i)(?:\ballUsers\b|\ballAuthenticatedUsers\b|"
            r"--group-names?\s+all\b|\bGroup\s*=\s*all\b|"
            r"allow-blob-public-access(?:=|\s+)true|"
            r"\bpublic-read(?:-write)?\b|"
            r"[\"']Principal[\"']\s*:\s*[\"']\*[\"'])"
        ),
    ),
    SafetyRule(
        "RS005",
        "a broad cloud administrator role is granted",
        "critical",
        re.compile(
            r"(?i)(?:roles/(?:owner|editor|"
            r"resourcemanager\.projectIamAdmin)|"
            r"--role(?:=|\s+)[\"']?(?:Owner|Contributor)\b|"
            r"roleDefinitionName[^\n]{0,80}\b(?:Owner|Contributor)\b)"
        ),
    ),
    SafetyRule(
        "RS006",
        "a cloud destructive operation lacks run-ownership proof",
        "high",
        re.compile(
            r"(?i)\b(?:aws|az|gcloud)\b[^\n]{0,240}"
            r"\b(?:delete|destroy|terminate|revoke)\b|"
            r"\bterraform\s+destroy\b"
        ),
    ),
    SafetyRule(
        "RS007",
        "a recursive or forced local deletion is requested",
        "high",
        re.compile(r"(?i)\brm\s+(?=[^\n]*-[^\n]*r)(?=[^\n]*-[^\n]*f)"),
    ),
    SafetyRule(
        "RS008",
        "downloaded content is piped directly to a shell",
        "high",
        re.compile(
            r"(?i)\b(?:curl|wget)\b[^\n|]{0,240}\|\s*"
            r"(?:sudo\s+)?(?:ba)?sh\b"
        ),
    ),
    SafetyRule(
        "RS009",
        "SSH host-key verification is disabled",
        "high",
        re.compile(r"(?i)StrictHostKeyChecking\s+no"),
    ),
    SafetyRule(
        "RS010",
        "a static password or secret assignment is present",
        "high",
        re.compile(
            r"(?i)^\s*(?:ENV\s+|export\s+)?"
            r"[A-Za-z_][A-Za-z0-9_]*(?:pass(?:word)?|secret)"
            r"[A-Za-z0-9_]*\s*(?:=|\s+)\s*\S+"
        ),
    ),
    SafetyRule(
        "RS011",
        "upstream instructions request credentials in build files",
        "high",
        re.compile(
            r"(?i)credentials?\s+(?:should|must|need to)\s+be\s+"
            r"(?:added|placed|stored)[^\n]{0,120}(?:dockerfile|image)"
        ),
    ),
)


def build_replay_safety_audit(
    root: str | Path,
    *,
    acquisition_manifest_path: str | Path,
    source_id: str = "cross_cloud_observability_2026",
    artifact_names: Iterable[str] = ("README.md", "attack_scripts.zip"),
) -> dict[str, Any]:
    """Audit pinned source files without extracting or executing scripts."""
    root = Path(root).resolve()
    manifest_path = _resolve_file(root, acquisition_manifest_path)
    manifest = _read_object(manifest_path)
    source = _select_source(manifest, source_id)
    requested = tuple(artifact_names)
    available = {
        artifact["name"]: artifact
        for artifact in source.get("artifacts") or []
    }
    missing = sorted(set(requested) - set(available))
    if missing:
        raise ValueError(f"artifacts absent from manifest: {missing}")

    findings: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    artifact_bindings = []
    archive_checks = []
    for name in requested:
        artifact = available[name]
        path = _resolve_file(root, artifact["relative_path"])
        binding = _binding(root, path)
        _require_manifest_binding(artifact, binding)
        artifact_bindings.append({
            "name": name,
            **binding,
            "manifest_status": artifact.get("status"),
            "url": artifact.get("url"),
        })
        if path.suffix.casefold() == ".zip":
            check = _scan_zip(name, path, findings, members)
            archive_checks.append(check)
        else:
            data = path.read_bytes()
            _scan_text(
                artifact_name=name,
                member_path=name,
                data=data,
                findings=findings,
                members=members,
            )

    findings.sort(
        key=lambda item: (
            item["artifact_name"],
            item["member_path"],
            item["line_number"],
            item["rule_id"],
        )
    )
    members.sort(
        key=lambda item: (item["artifact_name"], item["member_path"])
    )
    blocking = [
        finding
        for finding in findings
        if finding["severity"] in BLOCKING_SEVERITIES
    ]
    by_rule = Counter(item["rule_id"] for item in findings)
    by_provider = Counter(item["provider"] for item in findings)
    by_severity = Counter(item["severity"] for item in findings)
    affected_members = {
        (item["artifact_name"], item["member_path"])
        for item in findings
    }
    return {
        "audit_version": "1.0.0",
        "audit_kind": "static_replay_supply_safety_audit",
        "source_id": source_id,
        "repository": source.get("repository"),
        "commit": source.get("commit"),
        "status": (
            "direct_execution_blocked_requires_sanitized_wrapper"
            if blocking
            else "static_scan_clear_but_runtime_authorization_required"
        ),
        "bindings": {
            "acquisition_manifest": _binding(root, manifest_path),
            "artifacts": artifact_bindings,
        },
        "policy": {
            "executed_upstream_code": False,
            "extracted_archive_to_filesystem": False,
            "contains_truth_labels": False,
            "contains_expected_outcomes": False,
            "retains_source_line_text": False,
            "retains_possible_secret_values": False,
            "static_scan_is_runtime_safety_proof": False,
            "clean_scan_authorizes_execution": False,
            "blocking_severities": sorted(BLOCKING_SEVERITIES),
        },
        "limits": {
            "max_member_bytes": MAX_MEMBER_BYTES,
            "max_total_uncompressed_bytes": (
                MAX_TOTAL_UNCOMPRESSED_BYTES
            ),
        },
        "summary": {
            "artifact_count": len(artifact_bindings),
            "archive_count": len(archive_checks),
            "archive_member_count": sum(
                item["member_count"] for item in archive_checks
            ),
            "scanned_text_member_count": len(members),
            "affected_text_member_count": len(affected_members),
            "finding_count": len(findings),
            "blocking_finding_count": len(blocking),
            "direct_execution_eligible": not blocking,
            "finding_counts_by_rule": dict(sorted(by_rule.items())),
            "finding_counts_by_severity": dict(
                sorted(by_severity.items())
            ),
            "finding_counts_by_provider": dict(
                sorted(by_provider.items())
            ),
        },
        "rule_catalog": [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "blocks_direct_execution": (
                    rule.severity in BLOCKING_SEVERITIES
                ),
            }
            for rule in RULES
        ],
        "archive_checks": archive_checks,
        "scanned_text_members": members,
        "findings": findings,
        "required_remediation": [
            "replace upstream orchestration with argv-only adapters",
            "use short-lived credentials outside image layers",
            "limit all grants to dedicated test principals and resources",
            "forbid public principals and broad administrator roles",
            "prove every mutable resource was created by the current run",
            "pre-register cleanup and verify post-cleanup inventory",
            "repeat this audit on the exact adapter bytes before execution",
        ],
    }


def _scan_zip(
    artifact_name: str,
    path: Path,
    findings: list[dict[str, Any]],
    members: list[dict[str, Any]],
) -> dict[str, Any]:
    with ZipFile(path) as archive:
        infos = sorted(archive.infolist(), key=lambda item: item.filename)
        total = sum(info.file_size for info in infos)
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ValueError(
                f"archive exceeds uncompressed byte limit: {total}"
            )
        regular_files = 0
        scanned_files = 0
        for info in infos:
            _validate_zip_member(info)
            if info.is_dir():
                continue
            regular_files += 1
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(
                    f"archive member exceeds byte limit: {info.filename}"
                )
            if not _is_text_member(info.filename):
                continue
            scanned_files += 1
            _scan_text(
                artifact_name=artifact_name,
                member_path=info.filename,
                data=archive.read(info),
                findings=findings,
                members=members,
            )
    return {
        "artifact_name": artifact_name,
        "member_count": len(infos),
        "regular_file_count": regular_files,
        "scanned_text_file_count": scanned_files,
        "total_uncompressed_bytes": total,
        "path_traversal_members": 0,
        "encrypted_members": 0,
        "symbolic_link_members": 0,
    }


def _scan_text(
    *,
    artifact_name: str,
    member_path: str,
    data: bytes,
    findings: list[dict[str, Any]],
    members: list[dict[str, Any]],
) -> None:
    if b"\x00" in data:
        return
    text = data.decode("utf-8", errors="replace")
    provider = _provider_from_path(member_path)
    member_findings = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if (
                rule.path_pattern is not None
                and not rule.path_pattern.search(member_path)
            ):
                continue
            if not rule.pattern.search(line):
                continue
            findings.append({
                "artifact_name": artifact_name,
                "member_path": member_path,
                "provider": provider,
                "line_number": line_number,
                "line_sha256": sha256(
                    line.encode("utf-8")
                ).hexdigest(),
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "source_line_retained": False,
            })
            member_findings += 1
    members.append({
        "artifact_name": artifact_name,
        "member_path": member_path,
        "provider": provider,
        "bytes": len(data),
        "sha256": sha256(data).hexdigest(),
        "line_count": len(text.splitlines()),
        "finding_count": member_findings,
    })


def _validate_zip_member(info: ZipInfo) -> None:
    name = info.filename
    normalized = PurePosixPath(name.replace("\\", "/"))
    if (
        name.startswith(("/", "\\"))
        or "\\" in name
        or ".." in normalized.parts
        or (
            normalized.parts
            and re.fullmatch(r"[A-Za-z]:", normalized.parts[0])
        )
    ):
        raise ValueError(f"unsafe archive member path: {name}")
    if info.flag_bits & 0x1:
        raise ValueError(f"encrypted archive member: {name}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode and stat.S_ISLNK(mode):
        raise ValueError(f"symbolic-link archive member: {name}")


def _is_text_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        path.suffix.casefold() in TEXT_SUFFIXES
        or path.name.casefold() in TEXT_BASENAMES
    )


def _provider_from_path(path: str) -> str:
    folded = path.casefold()
    if "aws-attacks" in folded or "/aws/" in folded:
        return "AWS"
    if "azure-attacks" in folded or "/azure/" in folded:
        return "AZURE"
    if "gcp-attacks" in folded or "/gcp/" in folded:
        return "GCP"
    return "CROSS_CLOUD"


def _select_source(
    manifest: Mapping[str, Any],
    source_id: str,
) -> Mapping[str, Any]:
    matches = [
        source
        for source in manifest.get("sources") or []
        if source.get("source_id") == source_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one source {source_id!r}, got {len(matches)}"
        )
    return matches[0]


def _require_manifest_binding(
    artifact: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> None:
    if artifact.get("status") != "verified":
        raise ValueError(
            f"artifact is not verified: {artifact.get('name')}"
        )
    for key in ("bytes", "sha256"):
        if artifact.get(key) != binding.get(key):
            raise ValueError(
                f"artifact {key} mismatch: {artifact.get('name')}"
            )


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _resolve_file(root: Path, value: str | Path) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {value}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _binding(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }
