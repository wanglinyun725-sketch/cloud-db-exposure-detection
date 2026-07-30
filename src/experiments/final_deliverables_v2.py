"""Fail-closed review and final-deliverable binding for Graduate Goal v2."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tarfile
from typing import Any, Mapping
import zipfile


REQUIRED_REVIEW_CHECKS = {
    "method": {
        "react_loop",
        "tool_scope_semantics",
        "four_value_memory",
        "budgeted_discovery",
        "cp_cert_soundness",
        "baseline_parity",
    },
    "statistics": {
        "independence_unit",
        "group_safe_split",
        "confidence_intervals",
        "effect_sizes",
        "power_analysis",
        "holm_correction",
        "safety_endpoint",
        "missing_data_policy",
    },
    "cloud_security": {
        "raw_evidence_traceability",
        "provider_scope_semantics",
        "false_reachable_risk",
        "external_negative_controls",
        "cross_cloud_coverage",
        "threat_model_limits",
    },
}
ALLOWED_REVIEWER_KINDS = {
    "human",
    "model_assisted_human",
    "independent_ai_review",
}
PLACEHOLDER_REVIEWERS = {"", "todo", "tbd", "author", "self", "unknown"}
REQUIRED_ARTIFACT_KINDS = {
    "thesis_pdf",
    "defense_deck",
    "reproduction_bundle",
    "review_stress_tests",
}


def build_review_stress_test_bundle(
    root: str | Path,
    *,
    decision_path: str | Path,
    report_paths: Mapping[str, str | Path],
) -> dict[str, Any]:
    """Validate three independent review reports and bind them to results."""
    root = Path(root).resolve()
    decision_path = _resolve(root, decision_path)
    decision = _read_json(decision_path)
    _require_passing_decision(decision)
    decision_hash = _file_hash(decision_path)
    if set(report_paths) != set(REQUIRED_REVIEW_CHECKS):
        raise ValueError(
            "review reports must be exactly method, statistics, and "
            "cloud_security"
        )

    reports = []
    reviewer_ids = []
    for review_type in sorted(REQUIRED_REVIEW_CHECKS):
        path = _resolve(root, report_paths[review_type])
        report = _read_json(path)
        _validate_review_report(
            root,
            report,
            review_type=review_type,
            decision_sha256=decision_hash,
        )
        reviewer_ids.append(str(report["reviewer_id"]).strip())
        reports.append({
            "review_type": review_type,
            "path": _portable(root, path),
            "sha256": _file_hash(path),
            "reviewer_id": report["reviewer_id"],
            "reviewer_kind": report["reviewer_kind"],
            "verdict": report["verdict"],
            "required_checks": len(REQUIRED_REVIEW_CHECKS[review_type]),
        })
    if len(set(reviewer_ids)) != len(reviewer_ids):
        raise ValueError("the three stress tests require distinct reviewer_id values")

    return {
        "manifest_version": "2.0",
        "status": "complete",
        "confirmatory_decision": {
            "path": _portable(root, decision_path),
            "sha256": decision_hash,
        },
        "review_types": sorted(REQUIRED_REVIEW_CHECKS),
        "reports": reports,
        "all_required_checks_passed": True,
        "unresolved_critical_or_major_findings": 0,
        "reviewer_kind_is_disclosed_not_inferred": True,
    }


def validate_review_stress_test_bundle(
    root: str | Path,
    bundle: Mapping[str, Any],
    *,
    decision_path: str | Path,
) -> None:
    """Revalidate a frozen review bundle and its report hashes."""
    root = Path(root).resolve()
    decision_path = _resolve(root, decision_path)
    if bundle.get("status") != "complete":
        raise ValueError("review stress-test bundle is not complete")
    decision_item = bundle.get("confirmatory_decision")
    if not isinstance(decision_item, Mapping):
        raise ValueError("review bundle has no decision binding")
    decision_hash = _file_hash(decision_path)
    if decision_item.get("sha256") != decision_hash:
        raise ValueError("review bundle is bound to a different decision")
    if bundle.get("all_required_checks_passed") is not True:
        raise ValueError("review bundle contains a failed required check")
    if bundle.get("unresolved_critical_or_major_findings") != 0:
        raise ValueError("review bundle has unresolved critical or major findings")

    reports = bundle.get("reports")
    if not isinstance(reports, list):
        raise ValueError("review bundle reports must be a list")
    by_type = {
        item.get("review_type"): item
        for item in reports
        if isinstance(item, Mapping)
    }
    if set(by_type) != set(REQUIRED_REVIEW_CHECKS):
        raise ValueError("review bundle does not contain all three review types")
    reviewers = []
    for review_type, item in by_type.items():
        path = _resolve(root, str(item.get("path", "")))
        if item.get("sha256") != _file_hash(path):
            raise ValueError(f"{review_type} review hash mismatch")
        report = _read_json(path)
        _validate_review_report(
            root,
            report,
            review_type=review_type,
            decision_sha256=decision_hash,
        )
        reviewers.append(str(report["reviewer_id"]).strip())
    if len(set(reviewers)) != 3:
        raise ValueError("review bundle does not contain three distinct reviewers")


def build_final_deliverables_manifest(
    root: str | Path,
    *,
    decision_path: str | Path,
    thesis_pdf: str | Path,
    defense_deck: str | Path,
    reproduction_bundle: str | Path,
    review_stress_tests: str | Path,
    git_commit: str,
) -> dict[str, Any]:
    """Hash final artifacts only after results and all reviews pass."""
    root = Path(root).resolve()
    decision_path = _resolve(root, decision_path)
    decision = _read_json(decision_path)
    _require_passing_decision(decision)
    if (
        len(git_commit) != 40
        or any(character not in "0123456789abcdef" for character in git_commit)
    ):
        raise ValueError("git_commit must be a full lowercase SHA-1")

    paths = {
        "thesis_pdf": _resolve(root, thesis_pdf),
        "defense_deck": _resolve(root, defense_deck),
        "reproduction_bundle": _resolve(root, reproduction_bundle),
        "review_stress_tests": _resolve(root, review_stress_tests),
    }
    for kind, path in paths.items():
        _validate_artifact_file(kind, path)
    review_bundle = _read_json(paths["review_stress_tests"])
    validate_review_stress_test_bundle(
        root,
        review_bundle,
        decision_path=decision_path,
    )
    artifacts = [
        {
            "kind": kind,
            "path": _portable(root, path),
            "sha256": _file_hash(path),
            "bytes": path.stat().st_size,
        }
        for kind, path in sorted(paths.items())
    ]
    if {item["kind"] for item in artifacts} != REQUIRED_ARTIFACT_KINDS:
        raise AssertionError("internal error: incomplete artifact set")
    return {
        "manifest_version": "2.0",
        "status": "complete",
        "git_commit": git_commit,
        "confirmatory_decision_path": _portable(root, decision_path),
        "confirmatory_decision_sha256": _file_hash(decision_path),
        "claim_allowed": True,
        "artifacts": artifacts,
        "review_gate_passed": True,
        "posthoc_metric_substitution_allowed": False,
    }


def _validate_review_report(
    root: Path,
    report: Mapping[str, Any],
    *,
    review_type: str,
    decision_sha256: str,
) -> None:
    if report.get("review_type") != review_type:
        raise ValueError(f"expected {review_type} review report")
    if report.get("status") != "completed" or report.get("verdict") != "pass":
        raise ValueError(f"{review_type} review is not completed with pass")
    reviewer_id = str(report.get("reviewer_id", "")).strip()
    if reviewer_id.lower() in PLACEHOLDER_REVIEWERS:
        raise ValueError(f"{review_type} review has a placeholder reviewer_id")
    if report.get("reviewer_kind") not in ALLOWED_REVIEWER_KINDS:
        raise ValueError(f"{review_type} review must disclose reviewer_kind")
    if report.get("independent_of_artifact_authorship") is not True:
        raise ValueError(f"{review_type} review is not independent")
    if report.get("confirmatory_decision_sha256") != decision_sha256:
        raise ValueError(f"{review_type} review decision hash mismatch")

    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError(f"{review_type} checks must be a list")
    by_id = {
        item.get("check_id"): item
        for item in checks
        if isinstance(item, Mapping)
    }
    required = REQUIRED_REVIEW_CHECKS[review_type]
    if set(by_id) != required:
        missing = sorted(required - set(by_id))
        extra = sorted(set(by_id) - required)
        raise ValueError(
            f"{review_type} check IDs mismatch; missing={missing}, extra={extra}"
        )
    for check_id, item in by_id.items():
        if item.get("verdict") != "pass":
            raise ValueError(f"{review_type}/{check_id} did not pass")
        evidence = item.get("evidence_paths")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"{review_type}/{check_id} has no evidence")
        for value in evidence:
            path = _resolve(root, str(value))
            if not path.is_file():
                raise ValueError(
                    f"{review_type}/{check_id} evidence is missing: {path}"
                )

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{review_type} findings must be a list")
    unresolved = [
        item
        for item in findings
        if isinstance(item, Mapping)
        and item.get("severity") in {"critical", "major"}
        and item.get("resolution_status") != "resolved"
    ]
    if unresolved:
        raise ValueError(
            f"{review_type} review has unresolved critical/major findings"
        )


def _require_passing_decision(decision: Mapping[str, Any]) -> None:
    if (
        decision.get("claim_allowed") is not True
        or decision.get("overall_status") != "pass"
        or decision.get("posthoc_metric_substitution_allowed") is not False
    ):
        raise ValueError(
            "finalization requires a passing preregistered confirmatory decision"
        )


def _validate_artifact_file(kind: str, path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"required {kind} file is missing: {path}")
    if kind == "thesis_pdf":
        if path.suffix.lower() != ".pdf" or not path.read_bytes().startswith(
            b"%PDF-"
        ):
            raise ValueError("thesis_pdf is not a PDF artifact")
        return
    if kind == "defense_deck":
        if path.suffix.lower() != ".pptx" or not zipfile.is_zipfile(path):
            raise ValueError("defense_deck is not a PPTX artifact")
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
        required = {"[Content_Types].xml", "ppt/presentation.xml"}
        if not required <= names:
            raise ValueError("defense_deck lacks required PPTX parts")
        return
    if kind == "reproduction_bundle":
        names = _archive_names(path)
        required_suffix_groups = [
            {"README.md", "REPRODUCE.md"},
            {"configs/ec_react_main_v2_frozen.yaml"},
            {"scripts/experiments/run_research_pipeline_v2.py"},
            {
                "requirements.txt",
                "pyproject.toml",
                "environment.yml",
                "environment.yaml",
            },
        ]
        normalized = [name.replace("\\", "/").strip("/") for name in names]
        missing = [
            sorted(group)
            for group in required_suffix_groups
            if not any(
                any(name == suffix or name.endswith("/" + suffix) for suffix in group)
                for name in normalized
            )
        ]
        if missing:
            raise ValueError(
                "reproduction_bundle lacks required reproducibility files: "
                + repr(missing)
            )
        return
    if kind == "review_stress_tests":
        _read_json(path)
        return
    raise ValueError(f"unsupported final artifact kind: {kind}")


def _archive_names(path: Path) -> list[str]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            return archive.getnames()
    raise ValueError("reproduction_bundle is not a readable ZIP/TAR archive")


def write_once_json(path: str | Path, value: Mapping[str, Any]) -> None:
    """Write a frozen JSON object without overwriting a different artifact."""
    path = Path(path).resolve()
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    if path.is_file():
        if path.read_bytes() == payload:
            return
        raise RuntimeError(f"refusing to overwrite different artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"required file is missing: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"required file is missing: {path}")
    return sha256(path.read_bytes()).hexdigest()


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


def _portable(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path.resolve())
