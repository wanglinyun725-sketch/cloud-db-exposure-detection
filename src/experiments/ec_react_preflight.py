"""Strict preflight gate for EC-ReAct main experiments."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Mapping

import jsonschema
import yaml

from src.agent.ec_react import PARETO_ACTION_SPACE_ID
from src.annotation.pilot_gate import evaluate_pilot_gate
from src.annotation.workflow import REAL_SCHEMA_PATH
from src.experiments.ec_react_execution import (
    planned_runs_per_instance_for_selection,
    schedule_design_errors,
)
from src.experiments.protocol_freeze_v2 import required_frozen_inputs
from src.graph.path_ontology import (
    load_path_ontology,
    ontology_reference,
    validate_canonical_gold_types,
)
from src.oracle_gold.protocol import validate_oracle_registry


FINAL_STATUSES = {
    "reviewed",
    "adjudicated",
    "needs_execution",
    "rejected",
}
HUMAN_ORIGINS = {"human_reviewed", "human_adjudicated"}
METHOD_FAMILIES = {"llm", "deterministic", "randomized"}


def run_preflight(
    root: str | Path,
    config_path: str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    selected_method_ids: set[str] | None = None,
    selected_model_ids: set[str] | None = None,
    require_model_credentials: bool = True,
) -> dict[str, Any]:
    """Audit data, split, model and fairness prerequisites without running."""
    root = Path(root).resolve()
    config_path = Path(config_path).resolve()
    environment = dict(os.environ if environ is None else environ)
    raw_config = config_path.read_bytes()
    config = yaml.safe_load(raw_config.decode("utf-8"))
    blockers: list[str] = []
    warnings: list[str] = []

    _validate_config_shape(config, blockers)
    _validate_freeze_binding(root, config, blockers)
    methods = config.get("methods") or []
    known_method_ids = {
        item.get("method_id")
        for item in methods
        if isinstance(item, Mapping)
    }
    known_model_ids = {
        item.get("model_id")
        for item in config.get("models") or []
        if isinstance(item, Mapping)
    }
    if selected_method_ids is not None:
        unknown_methods = sorted(selected_method_ids - known_method_ids)
        if unknown_methods:
            blockers.append(
                f"unknown selected methods: {unknown_methods}"
            )
    if selected_model_ids is not None:
        unknown_models = sorted(selected_model_ids - known_model_ids)
        if unknown_models:
            blockers.append(
                f"unknown selected models: {unknown_models}"
            )
    shared = config.get("shared_execution") or {}
    _validate_method_fairness(methods, shared, blockers)
    ontology_summary = _validate_path_ontology_config(
        root,
        config,
        shared,
        blockers,
    )
    prior_summary = _validate_external_action_prior_config(
        root,
        config,
        shared,
        blockers,
    )

    data_config = config.get("data") or {}
    oracle_mode = (
        data_config.get("gold_protocol") == "executable_oracle_v1"
    )
    source_packet_path = _resolve(
        root,
        data_config.get("source_packet"),
    )
    gold_release_path = _resolve(
        root,
        data_config.get("gold_release"),
    )
    split_manifest_path = _resolve(
        root,
        data_config.get("split_manifest"),
    )
    minimum_negative_controls = int(
        data_config.get("minimum_external_negative_controls") or 0
    )
    negative_source_packet_path = _resolve(
        root,
        data_config.get("negative_source_packet"),
    )
    negative_gold_release_path = _resolve(
        root,
        data_config.get("negative_gold_release"),
    )
    pilot_configured = any(
        data_config.get(field)
        for field in (
            "annotation_pilot_packet",
            "annotation_pilot_release",
            "annotation_pilot_gate",
        )
    )
    annotation_pilot_packet_path = _resolve(
        root,
        data_config.get("annotation_pilot_packet"),
    )
    annotation_pilot_release_path = _resolve(
        root,
        data_config.get("annotation_pilot_release"),
    )
    annotation_pilot_gate_path = _resolve(
        root,
        data_config.get("annotation_pilot_gate"),
    )

    source_packet = _read_json_if_present(
        source_packet_path,
        "source packet",
        blockers,
    )
    source_packet_sha = (
        _stable_hash(source_packet)
        if source_packet is not None
        else None
    )
    source_case_count = (
        len(source_packet.get("cases", []))
        if source_packet is not None
        and isinstance(source_packet.get("cases"), list)
        else 0
    )
    source_group_count = (
        len({
            case.get("candidate_metadata", {}).get(
                "independence_group"
            )
            for case in source_packet.get("cases", [])
            if case.get("candidate_metadata", {}).get(
                "independence_group"
            )
        })
        if source_packet is not None
        else 0
    )
    source_runtime_shape = _validate_source_runtime_shape(
        source_packet,
        require_nonempty=(
            data_config.get("require_nonempty_runtime_instances") is True
        ),
        blockers=blockers,
    )
    minimum_finalized = int(
        data_config.get("minimum_finalized_cases") or 0
    )
    minimum_included = int(
        data_config.get("minimum_included_cases") or 0
    )
    minimum_groups = int(
        data_config.get("minimum_independence_groups") or 0
    )
    minimum_runtime = int(
        data_config.get("minimum_runtime_backed_cases") or 0
    )
    if source_packet is not None and source_case_count < minimum_included:
        blockers.append(
            f"source packet has {source_case_count} candidates; "
            f"minimum included target is {minimum_included}"
        )
    if source_packet is not None and source_group_count < minimum_groups:
        blockers.append(
            f"source packet has {source_group_count} independence groups; "
            f"minimum is {minimum_groups}"
        )
    release = _read_json_if_present(
        gold_release_path,
        (
            "executable Oracle registry"
            if oracle_mode
            else "human gold release"
        ),
        blockers,
    )
    split_manifest = _read_json_if_present(
        split_manifest_path,
        "split manifest",
        blockers,
    )
    negative_configured = (not oracle_mode) and (
        minimum_negative_controls > 0
        or bool(data_config.get("negative_source_packet"))
        or bool(data_config.get("negative_gold_release"))
    )
    negative_source_packet = (
        _read_json_if_present(
            negative_source_packet_path,
            "negative-control source packet",
            blockers,
        )
        if negative_configured
        else None
    )
    negative_gold_release = (
        _read_json_if_present(
            negative_gold_release_path,
            "human-screened negative-control release",
            blockers,
        )
        if negative_configured
        else None
    )
    annotation_pilot_packet = (
        _read_json_if_present(
            annotation_pilot_packet_path,
            "human annotation pilot packet",
            blockers,
        )
        if pilot_configured
        else None
    )
    annotation_pilot_release = (
        _read_json_if_present(
            annotation_pilot_release_path,
            "human annotation pilot release",
            blockers,
        )
        if pilot_configured
        else None
    )
    annotation_pilot_gate = (
        _read_json_if_present(
            annotation_pilot_gate_path,
            "human annotation pilot gate",
            blockers,
        )
        if pilot_configured
        else None
    )
    pilot_gate_summary = {
        "configured": pilot_configured,
        "passes": False if pilot_configured else None,
        "failed_checks": [],
    }
    if all(
        value is not None
        for value in (
            annotation_pilot_packet,
            annotation_pilot_release,
            annotation_pilot_gate,
        )
    ):
        try:
            pilot_result = evaluate_pilot_gate(
                annotation_pilot_release,
                annotation_pilot_packet,
                annotation_pilot_gate,
            )
        except (KeyError, TypeError, ValueError) as exc:
            blockers.append(f"human annotation pilot gate is invalid: {exc}")
        else:
            pilot_gate_summary = {
                "configured": True,
                "passes": pilot_result["passes"],
                "failed_checks": pilot_result["failed_checks"],
                "summary": pilot_result["summary"],
            }
            if not pilot_result["passes"]:
                blockers.append(
                    "human annotation pilot gate failed: "
                    + ", ".join(pilot_result["failed_checks"])
                )

    if oracle_mode:
        release_summary, negative_release_summary = (
            _validate_executable_oracle_release(
                root,
                release,
                minimum_groups=minimum_groups,
                minimum_runtime=minimum_runtime,
                minimum_negative_controls=minimum_negative_controls,
                blockers=blockers,
            )
        )
        split_summary = _validate_oracle_splits(
            split_manifest,
            release,
            set(data_config.get("allowed_splits") or []),
            int(data_config.get("minimum_frozen_test_cases") or 0),
            blockers,
        )
    else:
        release_summary = _validate_release(
            release,
            source_packet_sha,
            minimum_finalized,
            minimum_included,
            minimum_groups,
            minimum_runtime,
            ontology_summary.get("reference"),
            blockers,
        )
        split_summary = _validate_splits(
            split_manifest,
            release,
            source_packet_sha,
            set(data_config.get("allowed_splits") or []),
            int(data_config.get("minimum_frozen_test_cases") or 0),
            blockers,
        )
        negative_release_summary = _validate_negative_release(
            negative_gold_release,
            (
                _stable_hash(negative_source_packet)
                if negative_source_packet is not None
                else None
            ),
            minimum_negative_controls,
            blockers,
        )
    model_status = _model_status(
        [
            item
            for item in config.get("models") or []
            if (
                selected_model_ids is None
                or item.get("model_id") in selected_model_ids
            )
        ],
        methods,
        environment,
        blockers,
        require_credentials=require_model_credentials,
    )
    schedule_errors = schedule_design_errors(config)
    blockers.extend(
        f"invalid explicit schedule: {item}"
        for item in schedule_errors
    )

    if (
        config.get("reporting", {}).get(
            "forbid_smoke_as_effectiveness_result"
        )
        is not True
    ):
        blockers.append(
            "reporting must forbid smoke output as an effectiveness result"
        )
    if (
        data_config.get("statistical_unit")
        != "independence_group"
    ):
        blockers.append(
            "statistical_unit must be independence_group"
        )
    statistics = config.get("statistics") or {}
    if int(statistics.get("cluster_bootstrap_resamples") or 0) < 1000:
        warnings.append(
            "cluster bootstrap uses fewer than 1000 resamples"
        )
    if int(statistics.get("paired_permutation_resamples") or 0) < 1000:
        warnings.append(
            "paired permutation test uses fewer than 1000 resamples"
        )

    planned_runs = _planned_runs(
        (
            release_summary["included_runtime_instances"]
            + negative_release_summary["usable_runtime_instances"]
        ),
        methods,
        config.get("models") or [],
        shared,
        config,
        selected_method_ids,
        selected_model_ids,
    )
    planned_runs_at_minimum = _planned_runs(
        (
            minimum_runtime
            if oracle_mode
            else minimum_runtime + minimum_negative_controls
        ),
        methods,
        config.get("models") or [],
        shared,
        config,
        selected_method_ids,
        selected_model_ids,
    )
    return {
        "preflight_version": "0.1",
        "preflight_mode": (
            "execution" if require_model_credentials else "plan_only"
        ),
        "model_credentials_enforced": require_model_credentials,
        "experiment_id": config.get("experiment_id"),
        "config_path": str(config_path),
        "config_sha256": sha256(raw_config).hexdigest(),
        "source_packet_sha256": source_packet_sha,
        "source_candidate_cases": source_case_count,
        "source_independence_groups": source_group_count,
        "source_runtime_data_quality": source_runtime_shape,
        "data": {
            "gold_protocol": data_config.get("gold_protocol"),
            "source_packet": str(source_packet_path),
            "gold_release": str(gold_release_path),
            "split_manifest": str(split_manifest_path),
            "negative_source_packet": (
                str(negative_source_packet_path)
                if negative_configured
                else None
            ),
            "negative_gold_release": (
                str(negative_gold_release_path)
                if negative_configured
                else None
            ),
            "annotation_pilot_packet": (
                str(annotation_pilot_packet_path)
                if pilot_configured
                else None
            ),
            "annotation_pilot_release": (
                str(annotation_pilot_release_path)
                if pilot_configured
                else None
            ),
            "annotation_pilot_gate": (
                str(annotation_pilot_gate_path)
                if pilot_configured
                else None
            ),
        },
        "release_summary": release_summary,
        "path_ontology": ontology_summary,
        "external_action_prior": prior_summary,
        "negative_release_summary": negative_release_summary,
        "annotation_pilot_gate": pilot_gate_summary,
        "split_summary": split_summary,
        "method_count": len(methods),
        "schedule_arm_count": len(config.get("schedule_arms") or []),
        "execution_selection": {
            "method_ids": (
                sorted(selected_method_ids)
                if selected_method_ids is not None
                else None
            ),
            "model_ids": (
                sorted(selected_model_ids)
                if selected_model_ids is not None
                else None
            ),
        },
        "planned_runs_per_runtime_instance": (
            planned_runs_per_instance_for_selection(
                config,
                method_ids=selected_method_ids,
                model_ids=selected_model_ids,
            )
            if not schedule_errors
            else 0
        ),
        "model_status": model_status,
        "planned_runs_if_ready": planned_runs,
        "planned_runs_at_minimum_case_target": (
            planned_runs_at_minimum
        ),
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "ready": not blockers,
        "secrets_in_report": False,
    }


def _validate_executable_oracle_release(
    root: Path,
    registry: dict[str, Any] | None,
    *,
    minimum_groups: int,
    minimum_runtime: int,
    minimum_negative_controls: int,
    blockers: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate Oracle Gold without accepting human-origin compatibility."""
    release_summary = {
        "finalized_cases": 0,
        "included_cases": 0,
        "included_independence_groups": 0,
        "runtime_backed_included_cases": 0,
        "included_runtime_instances": 0,
        "instance_labels": 0,
        "reviewed": 0,
        "adjudicated": 0,
        "needs_execution": 0,
        "rejected": 0,
        "gold_protocol": "executable_oracle_v1",
    }
    negative_summary = {
        "finalized_cases": 0,
        "usable_negative_controls": 0,
        "usable_runtime_instances": 0,
        "reviewed": 0,
        "adjudicated": 0,
        "rejected": 0,
        "embedded_in_oracle_release": True,
    }
    if registry is None:
        return release_summary, negative_summary
    try:
        report = validate_oracle_registry(root, registry)
    except (FileNotFoundError, TypeError, ValueError) as exc:
        blockers.append(f"executable Oracle registry is invalid: {exc}")
        return release_summary, negative_summary

    qualifying_records = [
        item
        for item in registry.get("candidates") or []
        if item.get("counts_toward_oracle_gold") is True
    ]
    runtime_records = [
        item
        for item in qualifying_records
        if item.get("category") == "runtime_telemetry"
    ]
    runtime_instances = 0
    inputs = registry.get("inputs") or {}
    runtime_binding = inputs.get("runtime_packet") or {}
    runtime_path = _resolve(root, runtime_binding.get("path"))
    runtime_packet = _read_json_if_present(
        runtime_path,
        "Oracle-bound runtime packet",
        blockers,
    )
    if runtime_packet is not None:
        cases = {
            str(case.get("case_id")): case
            for case in runtime_packet.get("cases") or []
        }
        for record in runtime_records:
            selected = record.get("selected_oracle_unit") or {}
            case_id = str(selected.get("case_id") or "")
            instance_id = str(
                selected.get("runtime_instance_id") or ""
            )
            case = cases.get(case_id)
            if case is None:
                blockers.append(
                    f"selected Oracle runtime case missing from packet: "
                    f"{case_id}"
                )
                continue
            matching = [
                item
                for item in case.get("runtime_instances") or []
                if str(item.get("instance_id") or "") == instance_id
            ]
            if len(matching) != 1:
                blockers.append(
                    f"selected Oracle runtime instance is not unique in "
                    f"packet: {case_id}/{instance_id}"
                )
                continue
            runtime_instances += 1

    qualifying = report["qualifying_oracle_gold_groups"]
    runtime_groups = len(runtime_records)
    negatives = report["bounded_negative_or_paired_control_groups"]
    release_summary.update({
        "finalized_cases": qualifying,
        "included_cases": qualifying,
        "included_independence_groups": qualifying,
        "runtime_backed_included_cases": runtime_groups,
        "included_runtime_instances": runtime_instances,
        "instance_labels": runtime_instances,
        "oracle_verified": qualifying,
    })
    negative_summary.update({
        "finalized_cases": negatives,
        "usable_negative_controls": negatives,
        "oracle_verified": negatives,
    })
    if qualifying < minimum_groups:
        blockers.append(
            f"executable Oracle registry has {qualifying} qualifying "
            f"independence groups; minimum is {minimum_groups}"
        )
    if runtime_groups < minimum_runtime:
        blockers.append(
            f"executable Oracle registry has {runtime_groups} runtime "
            f"gold groups; minimum is {minimum_runtime}"
        )
    if negatives < minimum_negative_controls:
        blockers.append(
            f"executable Oracle registry has {negatives} bounded negative "
            f"or paired controls; minimum is {minimum_negative_controls}"
        )
    return release_summary, negative_summary


def _validate_oracle_splits(
    manifest: dict[str, Any] | None,
    registry: dict[str, Any] | None,
    allowed_splits: set[str],
    minimum_frozen_test: int,
    blockers: list[str],
) -> dict[str, Any]:
    """Validate group-level splits bound to the complete Oracle registry."""
    summary = {
        "assignments": 0,
        "independence_groups": 0,
        "split_counts": {},
        "runtime_backed_frozen_test_cases": 0,
        "gold_protocol": "executable_oracle_v1",
    }
    if manifest is None or registry is None:
        return summary
    if manifest.get("split_kind") != "executable_oracle_split_v1":
        blockers.append("Oracle split manifest has invalid split_kind")
    if manifest.get("oracle_registry_sha256") != _stable_hash(registry):
        blockers.append("Oracle split manifest registry hash mismatch")
    assignments = manifest.get("assignments")
    if not isinstance(assignments, list):
        blockers.append("Oracle split assignments must be an array")
        return summary
    qualifying = {
        str(item.get("independence_group"))
        for item in registry.get("candidates") or []
        if item.get("counts_toward_oracle_gold") is True
    }
    assigned = [
        str(item.get("independence_group") or "")
        for item in assignments
        if isinstance(item, Mapping)
    ]
    if len(assigned) != len(set(assigned)):
        blockers.append("Oracle split has duplicate independence groups")
    if set(assigned) != qualifying:
        blockers.append(
            "Oracle split group set differs from qualifying Gold"
        )
    split_counts: dict[str, int] = {}
    frozen_test = 0
    for item in assignments:
        if not isinstance(item, Mapping):
            blockers.append("Oracle split assignment must be an object")
            continue
        split = item.get("split")
        if split not in allowed_splits:
            blockers.append(
                f"Oracle split group {item.get('independence_group')} "
                f"has invalid split {split}"
            )
            continue
        split_counts[str(split)] = split_counts.get(str(split), 0) + 1
        if split in {"test", "external_test"}:
            frozen_test += 1
    if frozen_test < minimum_frozen_test:
        blockers.append(
            f"Oracle frozen test has {frozen_test} groups; "
            f"minimum is {minimum_frozen_test}"
        )
    summary.update({
        "assignments": len(assignments),
        "independence_groups": len(set(assigned)),
        "split_counts": dict(sorted(split_counts.items())),
        "runtime_backed_frozen_test_cases": frozen_test,
    })
    return summary


def _validate_negative_release(
    release: dict[str, Any] | None,
    source_packet_sha: str | None,
    minimum_usable: int,
    blockers: list[str],
) -> dict[str, Any]:
    summary = {
        "finalized_cases": 0,
        "usable_negative_controls": 0,
        "usable_runtime_instances": 0,
        "reviewed": 0,
        "adjudicated": 0,
        "rejected": 0,
    }
    if release is None:
        return summary
    if release.get("release_kind") != (
        "human_screened_external_negative_controls"
    ):
        blockers.append("negative-control release has invalid release_kind")
    if release.get("packet_sha256") != source_packet_sha:
        blockers.append(
            "negative-control release packet hash differs from source packet"
        )
    cases = release.get("cases")
    if not isinstance(cases, list):
        blockers.append("negative-control release cases must be an array")
        return summary
    candidate_ids = [item.get("candidate_id") for item in cases]
    case_ids = [item.get("case_id") for item in cases]
    if len(candidate_ids) != len(set(candidate_ids)):
        blockers.append("negative-control release has duplicate candidates")
    if len(case_ids) != len(set(case_ids)):
        blockers.append("negative-control release has duplicate case IDs")
    for case in cases:
        case_id = case.get("case_id")
        if case.get("case_kind") != "external_negative_control":
            blockers.append(f"negative case {case_id} has invalid case_kind")
        _validate_frozen_source_context(case, blockers)
        screening = case.get("screening") or {}
        status = screening.get("status")
        if status not in {"reviewed", "adjudicated", "rejected"}:
            blockers.append(f"negative case {case_id} is not finalized")
        elif status in summary:
            summary[status] += 1
        if screening.get("label_origin") not in HUMAN_ORIGINS:
            blockers.append(
                f"negative case {case_id} lacks reviewed human origin"
            )
        primary = screening.get("primary_annotator")
        reviewer = screening.get("reviewer")
        if (
            not isinstance(primary, str)
            or not isinstance(reviewer, str)
            or primary == reviewer
        ):
            blockers.append(
                f"negative case {case_id} lacks independent screeners"
            )
        usable = all(
            screening.get(field) is True
            for field in (
                "cloud_data_relevant",
                "non_attack_confirmed",
                "usable_as_negative_control",
            )
        )
        if usable and status not in {"reviewed", "adjudicated"}:
            blockers.append(
                f"usable negative case {case_id} has non-admitted status"
            )
        if usable:
            summary["usable_negative_controls"] += 1
            instances = case.get("runtime_instances")
            if not isinstance(instances, list) or len(instances) != 1:
                blockers.append(
                    f"usable negative case {case_id} must have one instance"
                )
            else:
                instance_id = instances[0].get("instance_id")
                if not isinstance(instance_id, str) or not instance_id:
                    blockers.append(
                        f"usable negative case {case_id} has invalid instance"
                    )
                else:
                    summary["usable_runtime_instances"] += 1
    summary["finalized_cases"] = len(cases)
    if summary["usable_negative_controls"] < minimum_usable:
        blockers.append(
            "negative-control release has "
            f"{summary['usable_negative_controls']} usable cases; "
            f"minimum is {minimum_usable}"
        )
    return summary


def _validate_config_shape(
    config: Any,
    blockers: list[str],
) -> None:
    if not isinstance(config, dict):
        blockers.append("config root must be an object")
        return
    for field in (
        "protocol_version",
        "experiment_id",
        "data",
        "shared_execution",
        "methods",
        "statistics",
        "reporting",
    ):
        if field not in config:
            blockers.append(f"config is missing {field}")


def _validate_method_fairness(
    methods: list[dict[str, Any]],
    shared: dict[str, Any],
    blockers: list[str],
) -> None:
    if not methods:
        blockers.append("at least one method is required")
        return
    method_ids = [item.get("method_id") for item in methods]
    if len(method_ids) != len(set(method_ids)):
        blockers.append("method_id values must be unique")
    shared_schema = shared.get("tool_schema_id")
    shared_steps = shared.get("max_steps")
    shared_output_contract = shared.get("output_contract_id")
    shared_path_limit = shared.get("max_path_candidates")
    if not isinstance(shared.get("budget_grid"), list):
        blockers.append("shared budget_grid must be an array")
    if shared.get("task_mode") != "path_discovery":
        blockers.append("shared task_mode must be path_discovery")
    if not isinstance(shared_output_contract, str):
        blockers.append("shared output_contract_id is required")
    if not isinstance(shared_path_limit, int) or shared_path_limit <= 0:
        blockers.append("shared max_path_candidates must be positive")
    if shared.get("hard_budget_enforced") is not True:
        blockers.append("hard_budget_enforced must be true for all methods")
    if shared.get("executable_evidence_tests") is not True:
        blockers.append("executable_evidence_tests must be true")
    if shared.get("pareto_action_space_id") != PARETO_ACTION_SPACE_ID:
        blockers.append(
            "shared pareto_action_space_id must equal "
            f"{PARETO_ACTION_SPACE_ID}"
        )
    if (
        shared.get("external_action_prior_id")
        != "sigma_cloud_operation_prior_v1"
    ):
        blockers.append(
            "shared external_action_prior_id must equal "
            "sigma_cloud_operation_prior_v1"
        )
    provider_scope_declared = any(
        "provider_scope_gate" in method for method in methods
    )
    for method in methods:
        if method.get("family") not in METHOD_FAMILIES:
            blockers.append(
                f"invalid method family for {method.get('method_id')}"
            )
        if method.get("tool_schema_id") != shared_schema:
            blockers.append(
                f"{method.get('method_id')} uses a different tool schema"
            )
        if method.get("max_steps") != shared_steps:
            blockers.append(
                f"{method.get('method_id')} uses a different max_steps"
            )
        if method.get("output_contract_id") != shared_output_contract:
            blockers.append(
                f"{method.get('method_id')} uses a different output contract"
            )
        if method.get("max_path_candidates") != shared_path_limit:
            blockers.append(
                f"{method.get('method_id')} uses a different path limit"
            )
        for component in (
            "pareto_guard",
            "external_rule_prior",
            "four_value_memory",
            "budget_stop",
            *(
                ("provider_scope_gate",)
                if provider_scope_declared
                else ()
            ),
            "evidence_citation_guard",
        ):
            if not isinstance(method.get(component), bool):
                blockers.append(
                    f"{method.get('method_id')} lacks boolean {component}"
                )
        finish_mode = method.get("finish_guard_mode")
        if finish_mode not in {"strict", "record"}:
            blockers.append(
                f"{method.get('method_id')} has invalid finish_guard_mode"
            )
        expected_mode = (
            "strict"
            if method.get("evidence_citation_guard")
            else "record"
        )
        if finish_mode in {"strict", "record"} and finish_mode != expected_mode:
            blockers.append(
                f"{method.get('method_id')} evidence guard disagrees "
                "with finish_guard_mode"
            )
    if "ablate_provider_scope_gate" in method_ids:
        by_id = {item.get("method_id"): item for item in methods}
        full = by_id.get("ec_react_full")
        ablated = by_id["ablate_provider_scope_gate"]
        if full is None:
            blockers.append(
                "ablate_provider_scope_gate requires ec_react_full"
            )
        else:
            compared_fields = (
                "family",
                "tool_schema_id",
                "max_steps",
                "max_path_candidates",
                "output_contract_id",
                "pareto_guard",
                "external_rule_prior",
                "four_value_memory",
                "budget_stop",
                "evidence_citation_guard",
                "finish_guard_mode",
            )
            changed = [
                field for field in compared_fields
                if full.get(field) != ablated.get(field)
            ]
            if changed:
                blockers.append(
                    "ablate_provider_scope_gate changes non-scope fields: "
                    + ", ".join(changed)
                )
            if (
                full.get("provider_scope_gate") is not True
                or ablated.get("provider_scope_gate") is not False
            ):
                blockers.append(
                    "provider scope ablation must change only true to false"
                )


def _validate_release(
    release: dict[str, Any] | None,
    source_packet_sha: str | None,
    minimum_finalized: int,
    minimum_included: int,
    minimum_groups: int,
    minimum_runtime: int,
    expected_ontology: dict[str, str] | None,
    blockers: list[str],
) -> dict[str, Any]:
    summary = {
        "finalized_cases": 0,
        "included_cases": 0,
        "included_independence_groups": 0,
        "runtime_backed_included_cases": 0,
        "included_runtime_instances": 0,
        "instance_labels": 0,
        "reviewed": 0,
        "adjudicated": 0,
        "needs_execution": 0,
        "rejected": 0,
    }
    if release is None:
        return summary
    if release.get("packet_sha256") != source_packet_sha:
        blockers.append(
            "gold release packet hash differs from source packet"
        )
    cases = release.get("cases")
    if not isinstance(cases, list):
        blockers.append("gold release cases must be an array")
        return summary
    case_ids = [case.get("case_id") for case in cases]
    if len(case_ids) != len(set(case_ids)):
        blockers.append("gold release contains duplicate case IDs")
    schema = json.loads(REAL_SCHEMA_PATH.read_text(encoding="utf-8"))
    included_groups: set[str] = set()
    for case in cases:
        try:
            jsonschema.validate(
                case,
                schema,
                format_checker=jsonschema.FormatChecker(),
            )
        except jsonschema.ValidationError as exc:
            blockers.append(
                f"gold case {case.get('case_id')} fails schema: "
                f"{exc.message}"
            )
            continue
        _validate_frozen_source_context(case, blockers)
        if expected_ontology is not None:
            if case.get("path_ontology") != expected_ontology:
                blockers.append(
                    f"gold case {case.get('case_id')} path ontology "
                    "reference differs from frozen config"
                )
            for ontology_error in validate_canonical_gold_types(case):
                blockers.append(
                    f"gold case {case.get('case_id')} {ontology_error}"
                )
        annotation = case["annotation"]
        status = annotation["status"]
        origin = annotation["label_origin"]
        admission = case.get("admission_screen")
        decision = (
            admission.get("decision")
            if isinstance(admission, dict)
            else None
        )
        if status not in FINAL_STATUSES:
            blockers.append(
                f"gold case {case['case_id']} is not finalized"
            )
        if origin not in HUMAN_ORIGINS:
            blockers.append(
                f"gold case {case['case_id']} lacks reviewed human origin"
            )
        expected_statuses = {
            "accept": {"reviewed", "adjudicated"},
            "needs_execution": {"needs_execution"},
            "reject": {"rejected"},
        }
        if decision not in expected_statuses:
            blockers.append(
                f"gold case {case['case_id']} lacks a final admission decision"
            )
        elif status not in expected_statuses[decision]:
            blockers.append(
                f"gold case {case['case_id']} status disagrees with "
                f"admission decision {decision}"
            )
        elif decision == "accept":
            summary["included_cases"] += 1
            runtime_instances = case.get("runtime_instances")
            instance_labels = case.get("instance_labels")
            if not isinstance(runtime_instances, list):
                blockers.append(
                    f"accepted gold case {case['case_id']} lacks "
                    "runtime_instances"
                )
                runtime_instances = []
            if not isinstance(instance_labels, list):
                blockers.append(
                    f"accepted gold case {case['case_id']} lacks "
                    "instance_labels"
                )
                instance_labels = []
            runtime_ids = {
                item.get("instance_id")
                for item in runtime_instances
                if isinstance(item, dict)
            }
            label_ids = {
                item.get("instance_id")
                for item in instance_labels
                if isinstance(item, dict)
            }
            if runtime_ids != label_ids:
                blockers.append(
                    f"accepted gold case {case['case_id']} runtime "
                    "instance/label sets differ"
                )
            for instance in runtime_instances:
                shape_errors, actual_count = _runtime_instance_shape(
                    case, instance
                )
                blockers.extend(
                    f"accepted gold case {case['case_id']} runtime "
                    f"instance {instance.get('instance_id')}: {error}"
                    for error in shape_errors
                )
                if actual_count == 0:
                    blockers.append(
                        f"accepted gold case {case['case_id']} runtime "
                        f"instance {instance.get('instance_id')} has zero "
                        "observations"
                    )
            summary["included_runtime_instances"] += len(
                runtime_instances
            )
            summary["instance_labels"] += len(instance_labels)
            if case["source"]["provenance_level"] in {"A", "B"}:
                summary["runtime_backed_included_cases"] += 1
                if not runtime_instances:
                    blockers.append(
                        f"runtime-backed accepted case {case['case_id']} "
                        "has no frozen runtime instance"
                    )
            group = case.get("candidate_metadata", {}).get(
                "independence_group"
            )
            if not isinstance(group, str) or not group:
                blockers.append(
                    f"accepted gold case {case['case_id']} lacks "
                    "independence_group"
                )
            else:
                included_groups.add(group)
            for section in (
                "nodes",
                "edges",
                "path_labels",
                "tool_tasks",
            ):
                if not case[section]:
                    blockers.append(
                        f"accepted gold case {case['case_id']} has "
                        f"empty {section}"
                    )
        if status in summary:
            summary[status] += 1
    summary["finalized_cases"] = len(cases)
    summary["included_independence_groups"] = len(included_groups)
    if len(cases) < minimum_finalized:
        blockers.append(
            f"gold release has {len(cases)} finalized cases; "
            f"minimum is {minimum_finalized}"
        )
    if summary["included_cases"] < minimum_included:
        blockers.append(
            f"gold release has {summary['included_cases']} included "
            f"accept cases; minimum is {minimum_included}"
        )
    if len(included_groups) < minimum_groups:
        blockers.append(
            f"gold release has {len(included_groups)} included "
            f"independence groups; minimum is {minimum_groups}"
        )
    if summary["runtime_backed_included_cases"] < minimum_runtime:
        blockers.append(
            "gold release has "
            f"{summary['runtime_backed_included_cases']} runtime-backed "
            f"included cases; minimum is {minimum_runtime}"
        )
    return summary


def _validate_source_runtime_shape(
    packet: dict[str, Any] | None,
    *,
    require_nonempty: bool,
    blockers: list[str],
) -> dict[str, Any]:
    summary = {
        "require_nonempty": require_nonempty,
        "runtime_instances": 0,
        "nonempty_runtime_instances": 0,
        "empty_runtime_instances": 0,
        "empty_runtime_instance_ids": [],
        "shape_error_count": 0,
        "shape_errors": [],
    }
    if packet is None:
        return summary
    seen_ids: set[str] = set()
    for case in packet.get("cases", []):
        for instance in case.get("runtime_instances", []):
            summary["runtime_instances"] += 1
            instance_id = instance.get("instance_id")
            errors: list[str] = []
            if not isinstance(instance_id, str) or not instance_id:
                errors.append("missing/invalid instance_id")
            else:
                if instance_id in seen_ids:
                    errors.append("duplicate packet-wide instance_id")
                seen_ids.add(instance_id)
            shape_errors, actual_count = _runtime_instance_shape(
                case, instance
            )
            errors.extend(shape_errors)
            if actual_count == 0:
                summary["empty_runtime_instances"] += 1
                summary["empty_runtime_instance_ids"].append(instance_id)
                if require_nonempty:
                    errors.append(
                        "zero-observation instance is forbidden by config"
                    )
            else:
                summary["nonempty_runtime_instances"] += 1
            summary["shape_errors"].extend(
                {
                    "case_id": case.get("case_id"),
                    "instance_id": instance_id,
                    "error": error,
                }
                for error in errors
            )
    summary["shape_error_count"] = len(summary["shape_errors"])
    if summary["shape_errors"]:
        blockers.append(
            "source packet runtime data quality failed for "
            f"{summary['shape_error_count']} checks"
        )
    return summary


def _runtime_instance_shape(
    case: dict[str, Any],
    instance: dict[str, Any],
) -> tuple[list[str], int]:
    errors: list[str] = []
    nested = instance.get("observations")
    if isinstance(nested, list):
        observations = nested
    else:
        frozen_ids = instance.get("observation_ids")
        if not isinstance(frozen_ids, list):
            observations = []
            errors.append(
                "requires observations or an observation_ids array"
            )
        else:
            by_id = {
                item.get("observation_id"): item
                for item in case.get("observations", [])
                if isinstance(item, dict)
            }
            observations = [
                by_id[item]
                for item in frozen_ids
                if item in by_id
            ]
            if len(observations) != len(frozen_ids):
                errors.append(
                    "observation_ids do not resolve exactly in the case"
                )
    actual_count = len(observations)
    if instance.get("observation_count") != actual_count:
        errors.append(
            "declared observation_count differs from frozen observations"
        )
    observation_ids = [
        item.get("observation_id")
        for item in observations
        if isinstance(item, dict)
    ]
    if (
        len(observation_ids) != actual_count
        or any(
            not isinstance(item, str) or not item
            for item in observation_ids
        )
        or len(observation_ids) != len(set(observation_ids))
    ):
        errors.append(
            "observation IDs are missing, invalid or duplicated"
        )
    if any(
        item.get("path_label") is not None
        or item.get("evidence_state") is not None
        for item in observations
    ):
        errors.append("runtime observations contain evaluator labels")
    return errors, actual_count


def _validate_path_ontology_config(
    root: Path,
    config: dict[str, Any],
    shared: dict[str, Any],
    blockers: list[str],
) -> dict[str, Any]:
    declared = config.get("path_ontology")
    protocol_version = str(config.get("protocol_version") or "")
    required = protocol_version == "0.3"
    if not isinstance(declared, dict):
        if required:
            blockers.append("protocol 0.3 requires a frozen path_ontology")
        return {
            "configured": False,
            "reference": None,
        }
    path = _resolve(root, declared.get("path"))
    if not path.is_file():
        blockers.append(f"path ontology is missing: {path}")
        return {
            "configured": True,
            "path": str(path),
            "reference": None,
        }
    try:
        ontology = load_path_ontology(path)
        reference = ontology_reference(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        blockers.append(f"path ontology is invalid: {exc}")
        return {
            "configured": True,
            "path": str(path),
            "reference": None,
        }
    if declared.get("ontology_id") != reference["ontology_id"]:
        blockers.append("declared path ontology ID differs from file")
    if declared.get("sha256") != reference["sha256"]:
        blockers.append("declared path ontology SHA-256 differs from file")
    if shared.get("path_ontology_id") != reference["ontology_id"]:
        blockers.append("shared execution path ontology ID differs from file")
    if declared.get("require_canonical_gold") is not True:
        blockers.append("path ontology must require canonical human gold")
    if declared.get("require_canonical_agent_output") is not True:
        blockers.append("path ontology must require canonical Agent output")
    if declared.get("primary_match") != "canonical_fine_exact":
        blockers.append("primary path match must be canonical_fine_exact")
    if declared.get("coarse_match_reporting") != "sensitivity_only":
        blockers.append("coarse ontology match must be sensitivity_only")
    return {
        "configured": True,
        "path": str(path),
        "reference": reference,
        "node_types": len(ontology["node_types"]),
        "edge_types": len(ontology["edge_types"]),
        "primary_match": declared.get("primary_match"),
        "coarse_match_reporting": declared.get(
            "coarse_match_reporting"
        ),
    }


def _validate_external_action_prior_config(
    root: Path,
    config: dict[str, Any],
    shared: dict[str, Any],
    blockers: list[str],
) -> dict[str, Any]:
    declared = config.get("external_action_prior")
    required = str(config.get("protocol_version") or "") == "0.3"
    if not isinstance(declared, dict):
        if required:
            blockers.append(
                "protocol 0.3 requires a frozen external_action_prior"
            )
        return {"configured": False, "reference": None}
    path = _resolve(root, declared.get("path"))
    archive_path = _resolve(
        root,
        declared.get("source_archive_path"),
    )
    if not path.is_file():
        blockers.append(f"external action prior is missing: {path}")
        return {
            "configured": True,
            "path": str(path),
            "reference": None,
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        blockers.append(f"external action prior is invalid: {exc}")
        return {
            "configured": True,
            "path": str(path),
            "reference": None,
        }
    prior_sha = sha256(path.read_bytes()).hexdigest()
    if declared.get("prior_id") != payload.get("prior_id"):
        blockers.append("declared external action prior ID differs from file")
    if declared.get("sha256") != prior_sha:
        blockers.append(
            "declared external action prior SHA-256 differs from file"
        )
    if (
        shared.get("external_action_prior_id")
        != payload.get("prior_id")
    ):
        blockers.append(
            "shared external action prior ID differs from file"
        )
    source = payload.get("source") or {}
    if declared.get("source_id") != source.get("source_id"):
        blockers.append("external action prior source ID differs from file")
    if declared.get("source_archive_sha256") != source.get(
        "archive_sha256"
    ):
        blockers.append(
            "external action prior archive hash differs from file"
        )
    archive_sha = None
    if not archive_path.is_file():
        blockers.append(
            f"external action prior source archive is missing: {archive_path}"
        )
    else:
        archive_sha = sha256(archive_path.read_bytes()).hexdigest()
        if archive_sha != declared.get("source_archive_sha256"):
            blockers.append(
                "external action prior source archive SHA-256 mismatch"
            )
    for field, expected in (
        ("label_usage", "none"),
        ("weighting", "none"),
    ):
        if declared.get(field) != expected or payload.get(field) != expected:
            blockers.append(
                f"external action prior {field} must equal {expected}"
            )
    if declared.get("positive_detection_selections_only") is not True:
        blockers.append(
            "external action prior must use positive selections only"
        )
    extraction = payload.get("extraction") or {}
    if extraction.get("filter_subtrees_excluded") is not True:
        blockers.append(
            "external action prior must exclude Sigma filter subtrees"
        )
    return {
        "configured": True,
        "path": str(path),
        "reference": {
            "prior_id": payload.get("prior_id"),
            "version": payload.get("prior_version"),
            "sha256": prior_sha,
            "source_id": source.get("source_id"),
            "source_archive_sha256": archive_sha,
        },
        "rules_total": extraction.get("rules_total"),
        "rules_with_operation_patterns": extraction.get(
            "rules_with_operation_patterns"
        ),
        "patterns": extraction.get("patterns"),
        "label_usage": payload.get("label_usage"),
        "weighting": payload.get("weighting"),
    }


def _validate_splits(
    manifest: dict[str, Any] | None,
    release: dict[str, Any] | None,
    source_packet_sha: str | None,
    allowed_splits: set[str],
    minimum_frozen_test: int,
    blockers: list[str],
) -> dict[str, Any]:
    summary = {
        "assignments": 0,
        "independence_groups": 0,
        "split_counts": {},
        "runtime_backed_frozen_test_cases": 0,
    }
    if manifest is None or release is None:
        return summary
    if manifest.get("packet_sha256") != source_packet_sha:
        blockers.append(
            "split manifest packet hash differs from source packet"
        )
    assignments = manifest.get("assignments")
    if not isinstance(assignments, list):
        blockers.append("split assignments must be an array")
        return summary
    release_ids = {
        case["case_id"] for case in release.get("cases", [])
    }
    split_ids = {
        item.get("case_id") for item in assignments
    }
    if release_ids != split_ids:
        blockers.append(
            "split manifest case set differs from gold release"
        )
    all_groups: set[str] = set()
    analytic_group_splits: dict[str, set[str]] = {}
    split_counts: dict[str, int] = {}
    release_by_id = {
        case["case_id"]: case for case in release.get("cases", [])
    }
    runtime_backed_frozen_test = 0
    for item in assignments:
        group = item.get("independence_group")
        split = item.get("split")
        if not isinstance(group, str) or not group:
            blockers.append(
                f"split case {item.get('case_id')} lacks independence_group"
            )
            continue
        if split not in allowed_splits:
            blockers.append(
                f"split case {item.get('case_id')} has invalid split"
            )
            continue
        all_groups.add(group)
        if split not in {"excluded", "execution_queue"}:
            analytic_group_splits.setdefault(group, set()).add(split)
        split_counts[split] = split_counts.get(split, 0) + 1
        case = release_by_id.get(item.get("case_id"))
        if case is None:
            continue
        decision = case.get("admission_screen", {}).get("decision")
        if decision == "needs_execution" and split != "execution_queue":
            blockers.append(
                f"needs_execution case {case['case_id']} must be queued"
            )
        if decision == "reject" and split != "excluded":
            blockers.append(
                f"rejected case {case['case_id']} must be excluded"
            )
        if (
            decision == "accept"
            and case["source"]["provenance_level"] == "C"
            and split in {"test", "external_test"}
        ):
            blockers.append(
                f"C-level case {case['case_id']} cannot enter {split}"
            )
        if (
            decision == "accept"
            and case["source"]["provenance_level"] in {"A", "B"}
            and split in {"test", "external_test"}
        ):
            runtime_backed_frozen_test += 1
    leaked_groups = sorted(
        group for group, splits in analytic_group_splits.items()
        if len(splits) > 1
    )
    if leaked_groups:
        blockers.append(
            "independence groups cross splits: "
            + ", ".join(leaked_groups)
        )
    if runtime_backed_frozen_test < minimum_frozen_test:
        blockers.append(
            f"frozen test has {runtime_backed_frozen_test} runtime-backed "
            f"accepted cases; minimum is {minimum_frozen_test}"
        )
    summary.update(
        {
            "assignments": len(assignments),
            "independence_groups": len(all_groups),
            "split_counts": dict(sorted(split_counts.items())),
            "runtime_backed_frozen_test_cases": (
                runtime_backed_frozen_test
            ),
        }
    )
    return summary


def _model_status(
    models: list[dict[str, Any]],
    methods: list[dict[str, Any]],
    environment: Mapping[str, str],
    blockers: list[str],
    *,
    require_credentials: bool = True,
) -> list[dict[str, Any]]:
    if not any(method.get("family") == "llm" for method in methods):
        return []
    if not models:
        blockers.append("LLM methods require at least one model")
    output = []
    for model in models:
        api_key_env = model.get("api_key_env")
        model_env = model.get("model_env")
        key_present = bool(environment.get(str(api_key_env), ""))
        key_required = model.get("api_key_required", True) is True
        model_name = (
            environment.get(str(model_env), "")
            or model.get("default_model")
        )
        base_url = (
            model.get("base_url")
            or environment.get(str(model.get("base_url_env")), "")
            or None
        )
        if key_required and not key_present and require_credentials:
            blockers.append(
                f"model {model.get('model_id')} is missing {api_key_env}"
            )
        if not model_name:
            blockers.append(
                f"model {model.get('model_id')} has no frozen model name"
            )
        declared_digest = model.get("frozen_runtime_digest")
        require_digest = model.get("require_runtime_digest") is True
        digest_valid = (
            isinstance(declared_digest, str)
            and len(declared_digest) == 64
            and all(
                character in "0123456789abcdef"
                for character in declared_digest.lower()
            )
        )
        if require_digest and not digest_valid:
            blockers.append(
                f"model {model.get('model_id')} requires a valid frozen "
                "runtime digest"
            )
        exact_version_required = (
            model.get("require_exact_version") is True
        )
        default_model = model.get("default_model")
        if exact_version_required:
            if not isinstance(default_model, str) or not default_model:
                blockers.append(
                    f"model {model.get('model_id')} requires an exact "
                    "default model version"
                )
            elif model_name != default_model:
                blockers.append(
                    f"model {model.get('model_id')} exact version was "
                    f"overridden: expected {default_model}, got {model_name}"
                )
        output.append(
            {
                "model_id": model.get("model_id"),
                "api_key_env": api_key_env,
                "api_key_present": key_present,
                "api_key_required": key_required,
                "credential_enforced": require_credentials,
                "model": model_name,
                "base_url": base_url,
                "require_runtime_digest": require_digest,
                "frozen_runtime_digest": (
                    declared_digest if digest_valid else None
                ),
                "require_exact_version": exact_version_required,
            }
        )
    return output


def _validate_freeze_binding(
    root: Path,
    config: Mapping[str, Any],
    blockers: list[str],
) -> None:
    """Reject drift in every artifact bound by a frozen v2 protocol."""
    status = config.get("freeze_status")
    if status != "FROZEN":
        return
    binding = config.get("freeze_binding")
    if not isinstance(binding, Mapping):
        blockers.append("frozen protocol lacks freeze_binding")
        return
    commit = binding.get("git_commit")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        blockers.append("frozen protocol has invalid git_commit binding")
    inputs = binding.get("inputs")
    if not isinstance(inputs, Mapping):
        blockers.append("frozen protocol lacks input hash bindings")
        return
    if set(inputs) != required_frozen_inputs(config):
        blockers.append("frozen protocol input binding set is incomplete")
        return
    for name, item in inputs.items():
        if not isinstance(item, Mapping):
            blockers.append(f"frozen input binding {name} is invalid")
            continue
        path_value = item.get("path")
        expected = item.get("sha256")
        path = _resolve(root, path_value)
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected
            )
        ):
            blockers.append(
                f"frozen input binding {name} has invalid SHA-256"
            )
            continue
        if not path.is_file():
            blockers.append(f"frozen bound input is missing: {name}={path}")
            continue
        actual = sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            blockers.append(
                f"frozen bound input drifted: {name}; "
                f"expected {expected}, got {actual}"
            )


def _planned_runs(
    cases: int,
    methods: list[dict[str, Any]],
    models: list[dict[str, Any]],
    shared: dict[str, Any],
    config: Mapping[str, Any] | None = None,
    method_ids: set[str] | None = None,
    model_ids: set[str] | None = None,
) -> int:
    if config is not None and config.get("schedule_arms"):
        return cases * planned_runs_per_instance_for_selection(
            config,
            method_ids=method_ids,
            model_ids=model_ids,
        )
    if method_ids is not None:
        methods = [
            item for item in methods
            if item.get("method_id") in method_ids
        ]
    if model_ids is not None:
        models = [
            item for item in models
            if item.get("model_id") in model_ids
        ]
    budgets = len(shared.get("budget_grid") or [])
    llm_repeats = int(shared.get("llm_repeats") or 0)
    deterministic_repeats = int(
        shared.get("deterministic_repeats") or 0
    )
    model_count = len(models)
    total = 0
    for method in methods:
        if method.get("family") == "llm":
            total += (
                cases * budgets * llm_repeats * model_count
            )
        elif method.get("family") == "randomized":
            total += cases * budgets * llm_repeats
        else:
            total += cases * budgets * deterministic_repeats
    return total


def _resolve(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        return root / "__missing_path__"
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def _read_json_if_present(
    path: Path,
    label: str,
    blockers: list[str],
) -> dict[str, Any] | None:
    if not path.is_file():
        blockers.append(f"{label} is missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        blockers.append(f"{label} cannot be read: {exc}")
        return None
    if not isinstance(value, dict):
        blockers.append(f"{label} root must be an object")
        return None
    return value


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _validate_frozen_source_context(
    case: dict[str, Any],
    blockers: list[str],
) -> None:
    fields = case.get("source_context_fields")
    digest = case.get("source_context_sha256")
    if (
        not isinstance(fields, list)
        or not fields
        or "source" not in fields
        or len(fields) != len(set(fields))
    ):
        blockers.append(
            f"gold case {case.get('case_id')} lacks frozen source context"
        )
        return
    if any(field not in case for field in fields):
        blockers.append(
            f"gold case {case.get('case_id')} has missing source context"
        )
        return
    context = {field: case[field] for field in fields}
    if _stable_hash(context) != digest:
        blockers.append(
            f"gold case {case.get('case_id')} source context hash mismatch"
        )
