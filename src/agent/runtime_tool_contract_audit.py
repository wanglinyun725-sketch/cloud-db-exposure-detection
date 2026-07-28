"""Label-free Tool-Use and orchestration audit for every runtime instance."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from src.agent.ec_react import ECReactRunner, ProgressiveTelemetryPolicy
from src.agent.ec_react_langgraph import ECReactLangGraphRunner
from src.agent.unlabeled_runtime_environment import (
    UnlabeledRuntimeInstanceEnvironment,
)


FORBIDDEN_POLICY_FIELDS = {
    "annotation",
    "evidence_state",
    "instance_labels",
    "nodes",
    "edges",
    "path_label",
    "path_labels",
    "source_condition",
}
FORBIDDEN_POLICY_TERMS = {
    "payload_absent",
    "payload_present",
    "source_condition",
}


def _field_names(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        fields.update(str(key) for key in value)
        for item in value.values():
            fields.update(_field_names(item))
    elif isinstance(value, list):
        for item in value:
            fields.update(_field_names(item))
    return fields


def _resource_term(observations: list[dict[str, Any]]) -> str:
    """Choose a deterministic payload token, or a valid guaranteed-miss term."""
    for observation in observations:
        for field in ("request", "response"):
            payload = observation.get(field)
            if payload is None:
                continue
            text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            tokens = re.findall(r"[A-Za-z0-9_.:/-]{3,}", text)
            if tokens:
                return tokens[0]
    return "__contract_probe_no_payload__"


def _probe_tools(
    case: dict[str, Any],
    instance_id: str,
) -> dict[str, Any]:
    environment = UnlabeledRuntimeInstanceEnvironment(
        case, instance_id, budget=None
    )
    observations = environment.audit_observations()
    first = observations[0] if observations else None
    calls = [
        ("summarize_case", {}),
        (
            "search_events",
            (
                {"operation": str(first["operation"])}
                if first
                else {}
            ),
        ),
        (
            "actor_timeline",
            {
                "actor_id": (
                    str(first["actor_id"])
                    if first and first.get("actor_id")
                    else "__contract_probe_missing_actor__"
                )
            },
        ),
        ("resource_search", {"term": _resource_term(observations)}),
    ]
    if first:
        calls.insert(2, (
            "get_event_detail",
            {"observation_id": str(first["observation_id"])},
        ))
    outputs: list[dict[str, Any]] = []
    failures: list[str] = []
    forbidden_fields: set[str] = set()
    forbidden_terms: set[str] = set()
    for tool_name, arguments in calls:
        try:
            output = environment.execute(tool_name, arguments)
            outputs.append(output)
            visible_fields = _field_names(output)
            forbidden_fields.update(
                visible_fields & FORBIDDEN_POLICY_FIELDS
            )
            visible_text = json.dumps(
                output, ensure_ascii=False, sort_keys=True
            ).casefold()
            forbidden_terms.update(
                term
                for term in FORBIDDEN_POLICY_TERMS
                if term in visible_text
            )
        except Exception as exc:  # Audit records exact contract failures.
            failures.append(
                f"{tool_name}: {type(exc).__name__}: {exc}"
            )

    counts = {
        output["receipt"]["tool_name"]: output["receipt"]["result_count"]
        for output in outputs
    }
    expected_positive = {
        "search_events": (
            counts.get("search_events", 0) >= 1
            if first
            else counts.get("search_events", 0) == 0
        ),
        "get_event_detail": (
            counts.get("get_event_detail", 0) == 1
            if first
            else True
        ),
        "actor_timeline": (
            counts.get("actor_timeline", 0) >= 1
            if first and first.get("actor_id")
            else True
        ),
    }
    if not all(expected_positive.values()):
        failures.append(
            "positive-result invariant failed: "
            + json.dumps(expected_positive, sort_keys=True)
        )
    resource_result_count = counts.get("resource_search", 0)
    has_payload = environment.audit_metadata()[
        "has_request_or_response_payload"
    ]
    if has_payload and resource_result_count < 1:
        failures.append(
            "resource_search failed to retrieve a deterministic payload token"
        )
    if forbidden_fields:
        failures.append(
            f"forbidden policy fields visible: {sorted(forbidden_fields)}"
        )
    if forbidden_terms:
        failures.append(
            f"forbidden policy terms visible: {sorted(forbidden_terms)}"
        )
    return {
        "tool_calls": len(outputs),
        "tools_exercised": sorted(counts),
        "failures": failures,
        "result_counts": counts,
        "resource_search_positive": resource_result_count >= 1,
        "trace_receipts": len(environment.export_trace()),
    }


def _policy_leakage(
    case: dict[str, Any],
    instance_id: str,
    public_context: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, list[str]]:
    visible = {
        "public_context": public_context,
        "trace": result["trace"],
    }
    fields = _field_names(visible)
    visible_text = json.dumps(
        visible, ensure_ascii=False, sort_keys=True
    ).casefold()
    candidate_id = (
        case.get("candidate_metadata") or {}
    ).get("candidate_id")
    identifiers = {
        case.get("case_id"),
        candidate_id,
        instance_id,
    }
    return {
        "fields": sorted(fields & FORBIDDEN_POLICY_FIELDS),
        "terms": sorted(
            term
            for term in FORBIDDEN_POLICY_TERMS
            if term in visible_text
        ),
        "identifiers": sorted(
            str(identifier)
            for identifier in identifiers
            if identifier
            and str(identifier).casefold() in visible_text
        ),
    }


def run_runtime_tool_contract_audit(
    root: str | Path,
    packet_path: str | Path,
    *,
    budget: int = 30,
    limit: int | None = None,
) -> dict[str, Any]:
    """Audit all real runtime instances without producing a method score."""
    if budget <= 0:
        raise ValueError("budget must be positive")
    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive or None")
    root = Path(root).resolve()
    packet_path = Path(packet_path)
    if not packet_path.is_absolute():
        packet_path = root / packet_path
    packet_path = packet_path.resolve()
    raw_bytes = packet_path.read_bytes()
    packet = json.loads(raw_bytes.decode("utf-8"))
    selected = [
        (case, instance)
        for case in packet.get("cases", [])
        for instance in case.get("runtime_instances", [])
    ]
    if limit is not None:
        selected = selected[:limit]

    linear_runner = ECReactRunner(ProgressiveTelemetryPolicy())
    graph_runner = ECReactLangGraphRunner(ProgressiveTelemetryPolicy())
    rows = []
    for case, instance in selected:
        instance_id = instance["instance_id"]
        probe = _probe_tools(case, instance_id)
        linear_environment = UnlabeledRuntimeInstanceEnvironment(
            case, instance_id, budget=budget
        )
        graph_environment = UnlabeledRuntimeInstanceEnvironment(
            case, instance_id, budget=budget
        )
        linear = asdict(linear_runner.run(
            linear_environment, linear_environment.public_context
        ))
        graph = asdict(graph_runner.run(
            graph_environment, graph_environment.public_context
        ))
        metadata = linear_environment.audit_metadata()
        leakage = _policy_leakage(
            case,
            instance_id,
            linear_environment.public_context,
            linear,
        )
        rows.append({
            **metadata,
            "tool_contract_valid": not probe["failures"],
            "tool_contract_failures": probe["failures"],
            "tool_calls_exercised": probe["tool_calls"],
            "tools_exercised": probe["tools_exercised"],
            "resource_search_positive": probe[
                "resource_search_positive"
            ],
            "backend_equivalent": linear == graph,
            "policy_leakage": leakage,
            "linear_result_sha256": sha256(json.dumps(
                linear,
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")).hexdigest(),
            "decision": linear["decision"],
            "valid_tool_calls": linear["valid_tool_calls"],
            "query_cost": linear["spent"],
        })

    contract_failures = [
        row["instance_id"]
        for row in rows
        if not row["tool_contract_valid"]
    ]
    backend_mismatches = [
        row["instance_id"]
        for row in rows
        if not row["backend_equivalent"]
    ]
    leakage_failures = [
        row["instance_id"]
        for row in rows
        if any(row["policy_leakage"].values())
    ]
    runtime_sources = Counter(
        row["runtime_evidence_source_id"] for row in rows
    )
    scenario_sources = Counter(row["scenario_source_id"] for row in rows)
    platforms = Counter(row["platform"] for row in rows)
    schemas = Counter(
        schema for row in rows for schema in row["schemas"]
    )
    environment_kinds = Counter(row["environment_kind"] for row in rows)
    payload_capable = sum(
        row["has_request_or_response_payload"] for row in rows
    )
    nonempty_instances = sum(row["observation_count"] > 0 for row in rows)
    resource_positive = sum(
        row["resource_search_positive"] for row in rows
    )
    independence_groups = {
        row["independence_group"] for row in rows
    }
    source_cases = {
        (
            row["runtime_evidence_source_id"],
            row["case_id"],
        )
        for row in rows
    }
    runtime_source_case_counts = Counter(
        source for source, _ in source_cases
    )
    valid = not (
        contract_failures or backend_mismatches or leakage_failures
    )
    return {
        "audit_version": "0.1",
        "purpose": (
            "label-free all-source tool-contract, data-shape, leakage and "
            "linear/LangGraph equivalence validation"
        ),
        "research_effectiveness_result": False,
        "warning": (
            "Pending cases have no human path gold. Passing this audit proves "
            "engineering compatibility only, not attack-path accuracy."
        ),
        "source_packet": str(packet_path.relative_to(root)),
        "source_packet_sha256": sha256(raw_bytes).hexdigest(),
        "packet_version": packet.get("packet_version"),
        "budget_per_backend_run": budget,
        "runtime_instances": len(rows),
        "runtime_cases": len({row["case_id"] for row in rows}),
        "independence_groups": len(independence_groups),
        "runtime_evidence_sources": dict(sorted(runtime_sources.items())),
        "runtime_evidence_source_case_counts": dict(sorted(
            runtime_source_case_counts.items()
        )),
        "scenario_sources": dict(sorted(scenario_sources.items())),
        "platforms": dict(sorted(platforms.items())),
        "environment_kinds": dict(sorted(environment_kinds.items())),
        "schemas": dict(sorted(schemas.items())),
        "data_shape": {
            "nonempty_instances": nonempty_instances,
            "empty_telemetry_instances": len(rows) - nonempty_instances,
            "empty_telemetry_instance_ids": [
                row["instance_id"]
                for row in rows
                if row["observation_count"] == 0
            ],
            "payload_capable_instances": payload_capable,
            "payload_absent_from_normalized_view_instances": (
                len(rows) - payload_capable
            ),
            "resource_search_positive_instances": resource_positive,
            "interpretation": (
                (
                    "Some compact packet instances omit request/response "
                    "payloads; this limits resource_search coverage without "
                    "invalidating the common tool contract. "
                )
                if payload_capable < len(rows)
                else (
                    "Every retained instance exposes source-pinned, "
                    "label-free request/response or resource detail to the "
                    "common resource_search contract. "
                )
            ) + (
                "Empty upstream telemetry is handled as an auditable "
                "abstention input but is not eligible for the frozen main "
                "runtime release."
                if nonempty_instances < len(rows)
                else "All retained runtime instances are non-empty."
            ),
        },
        "tool_calls_exercised": sum(
            row["tool_calls_exercised"] for row in rows
        ),
        "instances_exercising_tool": {
            tool_name: sum(
                tool_name in row["tools_exercised"] for row in rows
            )
            for tool_name in sorted({
                tool_name
                for row in rows
                for tool_name in row["tools_exercised"]
            })
        },
        "tool_contract_failure_count": len(contract_failures),
        "tool_contract_failure_instance_ids": contract_failures,
        "backend_mismatch_count": len(backend_mismatches),
        "backend_mismatch_instance_ids": backend_mismatches,
        "policy_leakage_failure_count": len(leakage_failures),
        "policy_leakage_failure_instance_ids": leakage_failures,
        "audit_valid": valid,
        "descriptive_diagnostics": {
            "decision_counts": dict(sorted(Counter(
                row["decision"] for row in rows
            ).items())),
            "mean_valid_tool_calls": (
                sum(row["valid_tool_calls"] for row in rows) / len(rows)
                if rows else 0.0
            ),
            "mean_query_cost": (
                sum(row["query_cost"] for row in rows) / len(rows)
                if rows else 0.0
            ),
        },
        "rows": rows,
    }
