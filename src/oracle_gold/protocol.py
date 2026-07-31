"""Fail-closed executable Oracle Gold protocol.

The protocol separates immutable candidate material from privileged evaluator
evidence.  Candidate configuration or telemetry is never promoted to a path
verdict merely because it exists.  A usable verdict requires a frozen scope,
all four independent evidence channels, and edge-level evidence bindings.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator


TRUTH_STATES = {
    "Reachable",
    "NotReachableWithinScope",
    "Unknown",
    "Conflict",
}
QUALIFYING_STATES = {"Reachable", "NotReachableWithinScope"}
CHANNELS = (
    "configuration",
    "provider_native_analysis",
    "authorized_active_probe",
    "audit_telemetry",
)
SCOPE_FIELDS = (
    "principals",
    "actions",
    "resources",
    "network_origins",
    "time_window",
)


def build_candidate_registry(
    root: str | Path,
    *,
    runtime_packet_path: str | Path,
    configuration_packet_path: str | Path,
) -> dict[str, Any]:
    """Build a deterministic registry in which every candidate is Unknown."""
    root = Path(root).resolve()
    runtime_path = _resolve_file(root, runtime_packet_path)
    configuration_path = _resolve_file(root, configuration_packet_path)
    schema_path = _resolve_file(
        root,
        "data/real_sources/oracle/"
        "executable_oracle_record_v1.schema.json",
    )
    runtime = _read_object(runtime_path)
    configuration = _read_object(configuration_path)

    records: dict[str, dict[str, Any]] = {}
    for case in runtime.get("cases") or []:
        _add_candidate(
            records,
            case,
            category="runtime_telemetry",
            root=root,
            packet_path=runtime_path,
        )
    for case in configuration.get("cases") or []:
        _add_candidate(
            records,
            case,
            category="configuration",
            root=root,
            packet_path=configuration_path,
        )

    candidates = [records[key] for key in sorted(records)]
    source_ids = sorted({
        source
        for candidate in candidates
        for source in candidate["source_ids"]
    })
    platforms = sorted({
        platform
        for candidate in candidates
        for platform in candidate["platforms"]
    })
    registry = {
        "protocol_version": "1.0.0",
        "registry_kind": "executable_oracle_gold",
        "status": "candidate_registry_no_gold",
        "truth_protocol": {
            "states": [
                "Reachable",
                "NotReachableWithinScope",
                "Unknown",
                "Conflict",
            ],
            "qualifying_states": [
                "Reachable",
                "NotReachableWithinScope",
            ],
            "unknown_is_not_gold": True,
            "conflict_is_not_gold": True,
            "negative_claim_is_scope_bounded": True,
        },
        "separation_policy": {
            "agent_discovery_view_excludes_privileged_oracle": True,
            "oracle_evidence_available_only_to_evaluator": True,
            "same_tool_output_cannot_be_agent_evidence_and_gold": True,
            "configuration_literal_is_runtime_reachability": False,
            "generated_events": 0,
            "generated_labels": 0,
        },
        "inputs": {
            "runtime_packet": _binding(root, runtime_path),
            "configuration_packet": _binding(root, configuration_path),
            "record_schema": _binding(root, schema_path),
        },
        "summary": {
            "candidate_independence_groups": len(candidates),
            "source_count": len(source_ids),
            "sources": source_ids,
            "platforms": platforms,
            "truth_state_counts": {
                "Reachable": 0,
                "NotReachableWithinScope": 0,
                "Unknown": len(candidates),
                "Conflict": 0,
            },
            "qualifying_oracle_gold_groups": 0,
            "bounded_negative_or_paired_control_groups": 0,
        },
        "completion_gate": {
            "minimum_oracle_gold_groups": 30,
            "minimum_bounded_negative_or_paired_controls": 10,
            "oracle_gold_passes": False,
            "negative_control_passes": False,
            "passes": False,
        },
        "candidates": candidates,
    }
    validate_oracle_registry(root, registry)
    return registry


def validate_oracle_registry(
    root: str | Path,
    registry: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate bindings and recompute the fail-closed Oracle Gold gate."""
    root = Path(root).resolve()
    if registry.get("registry_kind") != "executable_oracle_gold":
        raise ValueError("wrong Oracle registry kind")
    policy = registry.get("separation_policy")
    if not isinstance(policy, Mapping):
        raise ValueError("missing separation policy")
    for key in (
        "agent_discovery_view_excludes_privileged_oracle",
        "oracle_evidence_available_only_to_evaluator",
        "same_tool_output_cannot_be_agent_evidence_and_gold",
    ):
        if policy.get(key) is not True:
            raise ValueError(f"Oracle separation policy disabled: {key}")
    if (
        policy.get("generated_events") != 0
        or policy.get("generated_labels") != 0
    ):
        raise ValueError("registry claims generated events or labels")

    inputs = registry.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError("registry lacks input bindings")
    packets: dict[str, dict[str, Any]] = {}
    for category, input_name in (
        ("runtime_telemetry", "runtime_packet"),
        ("configuration", "configuration_packet"),
    ):
        binding = inputs.get(input_name)
        path = _validate_binding(root, binding)
        packets[category] = _read_object(path)
    schema_path = _validate_binding(root, inputs.get("record_schema"))
    schema = _read_object(schema_path)
    schema_validator = Draft202012Validator(schema)

    packet_cases = {
        category: {
            str(case["case_id"]): case
            for case in packet.get("cases") or []
        }
        for category, packet in packets.items()
    }
    candidates = registry.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("Oracle registry has no candidates")

    seen_groups: set[str] = set()
    state_counts = {state: 0 for state in TRUTH_STATES}
    qualifying = 0
    negative_or_control = 0
    errors: list[str] = []
    sources: set[str] = set()
    platforms: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            raise ValueError("candidate must be an object")
        schema_errors = sorted(
            schema_validator.iter_errors(candidate),
            key=lambda error: list(error.absolute_path),
        )
        if schema_errors:
            first = schema_errors[0]
            location = "/".join(str(item) for item in first.absolute_path)
            raise ValueError(
                f"Oracle record schema violation at {location}: "
                f"{first.message}"
            )
        group = str(candidate.get("independence_group") or "")
        if not group or group in seen_groups:
            raise ValueError(f"missing or duplicate independence group: {group}")
        seen_groups.add(group)
        category = str(candidate.get("category") or "")
        if category not in packet_cases:
            raise ValueError(f"unsupported candidate category: {category}")
        _validate_source_case_bindings(
            candidate,
            packet_cases[category],
        )
        sources.update(str(value) for value in candidate.get("source_ids") or [])
        platforms.update(
            str(value) for value in candidate.get("platforms") or []
        )
        state = str(candidate.get("truth_state") or "")
        if state not in TRUTH_STATES:
            raise ValueError(f"invalid truth state for {group}: {state}")
        state_counts[state] += 1
        candidate_errors = _qualification_errors(root, candidate)
        declared_gold = candidate.get("counts_toward_oracle_gold") is True
        should_qualify = state in QUALIFYING_STATES and not candidate_errors
        if declared_gold != should_qualify:
            raise ValueError(
                f"fail-closed gold flag mismatch for {group}: "
                f"{candidate_errors}"
            )
        if should_qualify:
            qualifying += 1
            if (
                state == "NotReachableWithinScope"
                or candidate.get("controlled_counterfactual") is True
            ):
                negative_or_control += 1
        errors.extend(f"{group}: {item}" for item in candidate_errors)

    if set(state_counts) != TRUTH_STATES:
        raise AssertionError("internal truth-state accounting error")
    expected_summary = {
        "candidate_independence_groups": len(candidates),
        "source_count": len(sources),
        "sources": sorted(sources),
        "platforms": sorted(platforms),
        "truth_state_counts": {
            state: state_counts[state]
            for state in (
                "Reachable",
                "NotReachableWithinScope",
                "Unknown",
                "Conflict",
            )
        },
        "qualifying_oracle_gold_groups": qualifying,
        "bounded_negative_or_paired_control_groups": negative_or_control,
    }
    if registry.get("summary") != expected_summary:
        raise ValueError("Oracle registry summary is not reproducible")
    expected_gate = {
        "minimum_oracle_gold_groups": 30,
        "minimum_bounded_negative_or_paired_controls": 10,
        "oracle_gold_passes": qualifying >= 30,
        "negative_control_passes": negative_or_control >= 10,
        "passes": qualifying >= 30 and negative_or_control >= 10,
    }
    if registry.get("completion_gate") != expected_gate:
        raise ValueError("Oracle completion gate is not reproducible")
    return {
        "valid": True,
        "candidate_groups": len(candidates),
        "qualifying_oracle_gold_groups": qualifying,
        "bounded_negative_or_paired_control_groups": negative_or_control,
        "qualification_error_count": len(errors),
        "qualification_errors": errors,
        "completion_gate": expected_gate,
    }


def _add_candidate(
    records: dict[str, dict[str, Any]],
    case: Mapping[str, Any],
    *,
    category: str,
    root: Path,
    packet_path: Path,
) -> None:
    metadata = case.get("candidate_metadata")
    if not isinstance(metadata, Mapping):
        raise ValueError("candidate lacks metadata")
    group = str(metadata.get("independence_group") or "")
    case_id = str(case.get("case_id") or "")
    source = case.get("source")
    if not group or not case_id or not isinstance(source, Mapping):
        raise ValueError("candidate lacks group, id, or source")
    platform_values = {
        str(instance["platform"]).upper()
        for instance in case.get("runtime_instances") or []
    }
    if not platform_values:
        platform_values = {str(metadata.get("platform") or "").upper()}
    if not platform_values or "" in platform_values:
        raise ValueError(f"candidate lacks platform: {case_id}")
    row = records.setdefault(group, {
        "oracle_record_version": "1.0.0",
        "independence_group": group,
        "category": category,
        "case_ids": [],
        "source_ids": [],
        "platforms": [],
        "evidence_stratum": (
            "published_real_cloud_telemetry"
            if category == "runtime_telemetry"
            else "pinned_upstream_configuration"
        ),
        "controlled_counterfactual": False,
        "truth_state": "Unknown",
        "counts_toward_oracle_gold": False,
        "scope": {
            "status": "pending",
            **{field: [] for field in SCOPE_FIELDS},
        },
        "evidence_channels": {
            channel: {
                "status": "pending",
                "outcome": None,
                "evidence": [],
            }
            for channel in CHANNELS
        },
        "critical_edges": [],
        "leakage_control": {
            "agent_view_artifact": None,
            "evaluator_only_artifacts": [],
            "views_are_hash_distinct": None,
            "oracle_outputs_withheld_until_scoring": True,
        },
        "source_case_bindings": [],
        "qualification": {
            "status": "pending",
            "failure_reasons": [
                "truth_state_is_not_qualifying",
                "scope_not_frozen",
                "independent_evidence_channels_incomplete",
                "critical_edges_not_bound",
                "agent_oracle_separation_not_proven",
            ],
        },
    })
    if row["category"] != category:
        raise ValueError(f"group crosses categories: {group}")
    row["case_ids"].append(case_id)
    row["source_ids"].append(str(source.get("source_id") or ""))
    row["platforms"].extend(platform_values)
    row["source_case_bindings"].append({
        "case_id": case_id,
        "packet_path": packet_path.relative_to(root).as_posix(),
        "case_sha256": _stable_hash(case),
    })
    if category == "configuration":
        evidence_id = "configuration-" + sha256(
            group.encode("utf-8")
        ).hexdigest()[:20]
        row["evidence_channels"]["configuration"] = {
            "status": "verified",
            "outcome": "verified_facts",
            "evidence": [{
                "evidence_id": evidence_id,
                "artifact": _binding(root, packet_path),
                "case_id": case_id,
                "case_sha256": _stable_hash(case),
                "evidence_role": (
                    "byte_verified_pinned_upstream_configuration"
                ),
                "does_not_prove": "runtime_reachability",
            }],
        }
    elif case.get("runtime_instances"):
        evidence_id = "telemetry-" + sha256(
            f"{group}:{case_id}".encode("utf-8")
        ).hexdigest()[:20]
        channel = row["evidence_channels"]["audit_telemetry"]
        if channel["status"] == "pending":
            channel["status"] = "artifact_verified"
        channel["evidence"].append({
            "evidence_id": evidence_id,
            "artifact": _binding(root, packet_path),
            "case_id": case_id,
            "case_sha256": _stable_hash(case),
            "evidence_role": "published_real_cloud_audit_telemetry",
            "observation_count": sum(
                len(instance.get("observations") or [])
                for instance in case.get("runtime_instances") or []
            ),
            "semantic_outcome_pending": True,
        })
        channel["evidence"].sort(key=lambda item: item["evidence_id"])
    row["case_ids"] = sorted(set(row["case_ids"]))
    row["source_ids"] = sorted(set(row["source_ids"]))
    row["platforms"] = sorted(set(row["platforms"]))
    row["source_case_bindings"].sort(key=lambda item: item["case_id"])


def _qualification_errors(
    root: Path,
    candidate: Mapping[str, Any],
) -> list[str]:
    state = candidate.get("truth_state")
    if state not in QUALIFYING_STATES:
        return ["truth_state_is_not_qualifying"]
    errors: list[str] = []
    scope = candidate.get("scope")
    if not isinstance(scope, Mapping) or scope.get("status") != "frozen":
        errors.append("scope_not_frozen")
    else:
        for field in SCOPE_FIELDS:
            value = scope.get(field)
            if not isinstance(value, list) or not value:
                errors.append(f"scope_field_empty:{field}")

    evidence_by_id: dict[str, tuple[str, Mapping[str, Any]]] = {}
    channels = candidate.get("evidence_channels")
    if not isinstance(channels, Mapping):
        errors.append("evidence_channels_missing")
    else:
        for channel in CHANNELS:
            entry = channels.get(channel)
            if not isinstance(entry, Mapping) or entry.get("status") != "verified":
                errors.append(f"evidence_channel_not_verified:{channel}")
                continue
            expected = _expected_outcome(state, channel)
            if entry.get("outcome") != expected:
                errors.append(f"evidence_outcome_mismatch:{channel}")
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                errors.append(f"evidence_channel_empty:{channel}")
                continue
            for item in evidence:
                if not isinstance(item, Mapping):
                    errors.append(f"invalid_evidence_item:{channel}")
                    continue
                evidence_id = str(item.get("evidence_id") or "")
                if not evidence_id or evidence_id in evidence_by_id:
                    errors.append(f"duplicate_or_empty_evidence_id:{channel}")
                    continue
                try:
                    _validate_binding(root, item.get("artifact"))
                except (ValueError, FileNotFoundError):
                    errors.append(f"invalid_artifact_binding:{evidence_id}")
                evidence_by_id[evidence_id] = (channel, item)

    edges = candidate.get("critical_edges")
    if not isinstance(edges, list) or not edges:
        errors.append("critical_edges_not_bound")
    else:
        for index, edge in enumerate(edges):
            if not isinstance(edge, Mapping):
                errors.append(f"invalid_critical_edge:{index}")
                continue
            for field in ("src", "edge_type", "dst"):
                if not str(edge.get(field) or ""):
                    errors.append(f"critical_edge_field_empty:{index}:{field}")
            refs = edge.get("evidence_refs")
            if not isinstance(refs, list) or len(set(refs)) < 2:
                errors.append(f"critical_edge_needs_two_evidence_refs:{index}")
                continue
            edge_channels = {
                evidence_by_id[ref][0]
                for ref in refs
                if ref in evidence_by_id
            }
            if len(edge_channels) < 2:
                errors.append(f"critical_edge_not_independent:{index}")
            if any(ref not in evidence_by_id for ref in refs):
                errors.append(f"critical_edge_unknown_evidence_ref:{index}")

    leakage = candidate.get("leakage_control")
    if not isinstance(leakage, Mapping):
        errors.append("leakage_control_missing")
    else:
        if leakage.get("oracle_outputs_withheld_until_scoring") is not True:
            errors.append("oracle_outputs_not_withheld")
        if leakage.get("views_are_hash_distinct") is not True:
            errors.append("agent_and_oracle_views_not_proven_distinct")
        agent_binding = leakage.get("agent_view_artifact")
        oracle_bindings = leakage.get("evaluator_only_artifacts")
        try:
            agent_path = _validate_binding(root, agent_binding)
        except (ValueError, FileNotFoundError):
            errors.append("invalid_agent_view_binding")
            agent_path = None
        if not isinstance(oracle_bindings, list) or not oracle_bindings:
            errors.append("evaluator_only_artifacts_missing")
        else:
            oracle_paths = []
            for binding in oracle_bindings:
                try:
                    oracle_paths.append(_validate_binding(root, binding))
                except (ValueError, FileNotFoundError):
                    errors.append("invalid_evaluator_artifact_binding")
            if agent_path is not None and agent_path in oracle_paths:
                errors.append("agent_view_equals_evaluator_artifact")
    return sorted(set(errors))


def _expected_outcome(state: str, channel: str) -> str:
    if channel == "configuration":
        return "verified_facts"
    if state == "Reachable":
        return {
            "provider_native_analysis": "allows",
            "authorized_active_probe": "allowed",
            "audit_telemetry": "allowed_observed",
        }[channel]
    return {
        "provider_native_analysis": "denies",
        "authorized_active_probe": "denied",
        "audit_telemetry": "denied_observed",
    }[channel]


def _validate_source_case_bindings(
    candidate: Mapping[str, Any],
    packet_cases: Mapping[str, Mapping[str, Any]],
) -> None:
    bindings = candidate.get("source_case_bindings")
    if not isinstance(bindings, list) or not bindings:
        raise ValueError("candidate lacks source case bindings")
    bound_ids = []
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise ValueError("source case binding must be an object")
        case_id = str(binding.get("case_id") or "")
        case = packet_cases.get(case_id)
        if case is None:
            raise ValueError(f"bound case absent from packet: {case_id}")
        if binding.get("case_sha256") != _stable_hash(case):
            raise ValueError(f"source case hash mismatch: {case_id}")
        bound_ids.append(case_id)
    if sorted(bound_ids) != sorted(candidate.get("case_ids") or []):
        raise ValueError("candidate case IDs differ from source bindings")


def _validate_binding(
    root: Path,
    binding: Any,
) -> Path:
    if not isinstance(binding, Mapping):
        raise ValueError("artifact binding must be an object")
    path = _resolve_file(root, str(binding.get("path") or ""))
    data = path.read_bytes()
    if binding.get("sha256") != sha256(data).hexdigest():
        raise ValueError(f"artifact hash mismatch: {path}")
    if binding.get("bytes") != len(data):
        raise ValueError(f"artifact byte count mismatch: {path}")
    return path


def _binding(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
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


def _stable_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
