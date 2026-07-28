"""Pre-registered quality gate for the runtime human-annotation pilot."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from typing import Any


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def evaluate_pilot_gate(
    release: dict[str, Any],
    pilot_packet: dict[str, Any],
    gate: dict[str, Any],
) -> dict[str, Any]:
    """Return auditable checks; never silently waive a failed threshold."""
    checks: list[dict[str, Any]] = []

    def add(
        check_id: str,
        passed: bool,
        actual: Any,
        criterion: str,
    ) -> None:
        checks.append({
            "check_id": check_id,
            "passed": bool(passed),
            "actual": actual,
            "criterion": criterion,
        })

    expected_packet_hash = _stable_hash(pilot_packet)
    add(
        "packet_hash",
        release.get("packet_sha256") == expected_packet_hash,
        release.get("packet_sha256"),
        f"equals {expected_packet_hash}",
    )
    expected_ids = {
        case["case_id"] for case in pilot_packet["cases"]
    }
    release_cases = release.get("cases") or []
    release_ids = {case.get("case_id") for case in release_cases}
    add(
        "complete_case_set",
        (
            len(release_cases) == gate["required_cases"]
            and release_ids == expected_ids
        ),
        {
            "count": len(release_cases),
            "missing": sorted(expected_ids - release_ids),
            "unexpected": sorted(release_ids - expected_ids),
        },
        f"exactly the {gate['required_cases']} frozen pilot cases",
    )

    agreement = release.get("agreement") or {}
    add(
        "two_human_case_count",
        agreement.get("independent_cases") == gate["required_cases"],
        agreement.get("independent_cases"),
        f"equals {gate['required_cases']}",
    )
    adjudication = release.get("adjudication") or {}
    add(
        "all_disputes_adjudicated",
        (
            adjudication.get("completed")
            == adjudication.get("required")
        ),
        adjudication,
        "completed equals required",
    )

    unresolved = [
        case.get("case_id")
        for case in release_cases
        if case.get("annotation", {}).get("status") == "needs_execution"
    ]
    add(
        "no_unresolved_needs_execution",
        not unresolved,
        unresolved,
        "empty",
    )
    accepted = [
        case
        for case in release_cases
        if case.get("annotation", {}).get("status")
        in {"reviewed", "adjudicated"}
    ]
    accepted_instances = [
        instance
        for case in accepted
        for instance in case.get("runtime_instances") or []
    ]
    accepted_sources = {
        case.get("source", {}).get("source_id") for case in accepted
    } - {None}
    platform_counts = Counter(
        instance.get("platform") for instance in accepted_instances
    )
    add(
        "minimum_accepted_cases",
        len(accepted) >= gate["minimum_accepted_cases"],
        len(accepted),
        f">= {gate['minimum_accepted_cases']}",
    )
    add(
        "minimum_accepted_runtime_instances",
        (
            len(accepted_instances)
            >= gate["minimum_accepted_runtime_instances"]
        ),
        len(accepted_instances),
        f">= {gate['minimum_accepted_runtime_instances']}",
    )
    add(
        "minimum_accepted_source_count",
        (
            len(accepted_sources)
            >= gate["minimum_accepted_source_count"]
        ),
        sorted(accepted_sources),
        f"at least {gate['minimum_accepted_source_count']} sources",
    )
    for platform, minimum in gate[
        "minimum_accepted_platform_instances"
    ].items():
        add(
            f"minimum_accepted_{platform.casefold()}_instances",
            platform_counts[platform] >= minimum,
            platform_counts[platform],
            f">= {minimum}",
        )

    thresholds = gate["agreement_thresholds"]

    def minimum(metric: str, threshold_key: str | None = None) -> None:
        key = threshold_key or metric
        threshold = thresholds[key]
        value = agreement.get(metric)
        add(
            metric,
            isinstance(value, (int, float)) and value >= threshold,
            value,
            f">= {threshold}",
        )

    minimum("admission_exact_agreement")
    admission_kappa = agreement.get("admission_cohen_kappa")
    admission_exact = agreement.get("admission_exact_agreement")
    admission_kappa_pass = (
        admission_kappa >= thresholds[
            "admission_cohen_kappa_if_defined"
        ]
        if isinstance(admission_kappa, (int, float))
        else admission_exact == 1.0
    )
    add(
        "admission_cohen_kappa",
        admission_kappa_pass,
        admission_kappa,
        (
            f">= {thresholds['admission_cohen_kappa_if_defined']} "
            "when defined; otherwise exact agreement must be 1.0"
        ),
    )
    minimum("mean_edge_identity_f1")
    minimum(
        "matched_edge_state_count",
        "minimum_matched_edge_state_count",
    )
    minimum("edge_state_macro_f1_on_matched_edges")
    minimum(
        "matched_path_state_count",
        "minimum_matched_path_state_count",
    )
    path_kappa = agreement.get(
        "path_state_cohen_kappa_on_matched_paths"
    )
    path_accuracy = agreement.get("mean_path_state_accuracy")
    path_kappa_pass = (
        path_kappa >= thresholds[
            "path_state_cohen_kappa_if_defined"
        ]
        if isinstance(path_kappa, (int, float))
        else path_accuracy == 1.0
    )
    add(
        "path_state_cohen_kappa_on_matched_paths",
        path_kappa_pass,
        path_kappa,
        (
            f">= {thresholds['path_state_cohen_kappa_if_defined']} "
            "when defined; otherwise observed agreement must be 1.0"
        ),
    )
    minimum(
        "matched_instance_state_count",
        "minimum_matched_instance_state_count",
    )
    instance_kappa = agreement.get("instance_state_cohen_kappa")
    instance_macro_f1 = agreement.get("instance_state_macro_f1")
    instance_kappa_pass = (
        instance_kappa >= thresholds[
            "instance_state_cohen_kappa_if_defined"
        ]
        if isinstance(instance_kappa, (int, float))
        else instance_macro_f1 == 1.0
    )
    add(
        "instance_state_cohen_kappa",
        instance_kappa_pass,
        instance_kappa,
        (
            f">= {thresholds['instance_state_cohen_kappa_if_defined']} "
            "when defined; otherwise macro-F1 must be 1.0"
        ),
    )
    minimum("instance_state_macro_f1")

    failed = [item["check_id"] for item in checks if not item["passed"]]
    return {
        "pilot_gate_version": "0.1",
        "gate_id": gate["gate_id"],
        "protocol_status": gate["protocol_status"],
        "passes": not failed,
        "failed_checks": failed,
        "summary": {
            "checks": len(checks),
            "passed_checks": len(checks) - len(failed),
            "accepted_cases": len(accepted),
            "accepted_runtime_instances": len(accepted_instances),
            "accepted_source_count": len(accepted_sources),
            "accepted_platform_instance_counts": dict(
                sorted(platform_counts.items())
            ),
        },
        "checks": checks,
        "failure_action": gate["failure_action"],
    }
