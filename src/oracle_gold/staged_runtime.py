"""Fail-closed binding of cloud-generated setup outputs.

Cloud identifiers such as Secrets Manager ARNs do not exist before setup.
This module preflights only setup with explicitly deferred placeholders, then
binds allowlisted non-sensitive fields from in-memory JSON responses before it
re-preflights every remaining phase.  Raw setup output and extracted values are
never included in the returned audit report.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence
import re

from src.oracle_gold.runtime_preflight import (
    ExecutionPreflight,
    PHASE_ORDER,
    ResolvedStep,
    mapping_binding_sha256,
    preflight_probe_contract_stage,
    runtime_binding_sha256,
)


_PLACEHOLDER_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
_SECRET_ARN = re.compile(
    r"arn:(?P<partition>aws(?:-cn|-us-gov)?):secretsmanager:"
    r"(?P<region>[a-z]{2}(?:-[a-z0-9]+)+-\d):"
    r"(?P<account>\d{12}):secret:"
    r"pathbench-oracle-(?P<run_id>[a-z0-9][a-z0-9-]{7,31})"
    r"(?:-[12])?-[A-Za-z0-9]{6}"
)
_ALLOWED_VALIDATORS = {"aws_secretsmanager_secret_arn_v1"}
_SENSITIVE_POINTER = re.compile(
    r"(?i)(?:secretstring|secretbinary|password|accesskey|privatekey|"
    r"sessiontoken|credential)"
)


@dataclass(frozen=True)
class InMemorySetupResult:
    """One setup result supplied directly by an executor, never serialized."""

    argv_sha256: str
    exit_code: int
    stdout: bytes
    timed_out: bool = False


def preflight_staged_setup(
    contract: Mapping[str, Any],
    *,
    runtime_values: Mapping[str, str],
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> ExecutionPreflight:
    """Resolve setup while allowing only declared setup outputs to be absent."""
    try:
        bindings = _binding_specs(contract)
    except ValueError as error:
        return _failure_preflight(contract, [str(error)], stage="setup")
    deferred = [item["placeholder"] for item in bindings]
    overlap = sorted(set(deferred) & set(runtime_values))
    if overlap:
        return _failure_preflight(
            contract,
            [f"deferred_placeholder_supplied_before_setup:{name}"
             for name in overlap],
            stage="setup",
        )
    result = preflight_probe_contract_stage(
        contract,
        runtime_values=runtime_values,
        authorization=authorization,
        policy=policy,
        allowed_missing_placeholders=deferred,
        selected_phases=("setup",),
        required_phases=("setup",),
    )
    report = dict(result.audit_report)
    report["stage"] = "setup"
    report["dynamic_binding_plan_valid"] = True
    report["deferred_placeholders_recorded"] = False
    return ExecutionPreflight(
        audit_report=report,
        resolved_steps=result.resolved_steps,
    )


def bind_staged_setup_outputs(
    contract: Mapping[str, Any],
    *,
    setup_preflight: ExecutionPreflight,
    setup_results: Mapping[str, InMemorySetupResult],
    initial_runtime_values: Mapping[str, str],
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> ExecutionPreflight:
    """Bind verified setup outputs and resolve all non-setup phases."""
    blockers: list[str] = []
    try:
        bindings = _binding_specs(contract)
    except ValueError as error:
        return _failure_preflight(contract, [str(error)], stage="post_setup")
    if setup_preflight.audit_report.get("ready_for_execution") is not True:
        blockers.append("setup_preflight_not_ready")
    if setup_preflight.audit_report.get("stage") != "setup":
        blockers.append("wrong_setup_preflight_stage")
    expected_bindings = {
        "contract_binding_sha256": mapping_binding_sha256(contract),
        "authorization_binding_sha256": mapping_binding_sha256(
            authorization
        ),
        "policy_binding_sha256": mapping_binding_sha256(policy),
        "runtime_binding_sha256": runtime_binding_sha256(
            initial_runtime_values
        ),
    }
    for field, expected in expected_bindings.items():
        if (
            expected is None
            or setup_preflight.audit_report.get(field) != expected
        ):
            blockers.append(f"setup_context_binding_mismatch:{field}")
    expected_steps = {
        step.template_path: step for step in setup_preflight.resolved_steps
    }
    if set(setup_results) != set(expected_steps):
        blockers.append("setup_result_step_set_mismatch")

    maximum_stdout = (
        (policy.get("staged_runtime") or {}).get(
            "maximum_setup_stdout_bytes"
        )
    )
    if not isinstance(maximum_stdout, int) or maximum_stdout <= 0:
        blockers.append("maximum_setup_stdout_bytes_invalid")

    parsed: dict[str, Any] = {}
    capture_sources = {
        binding["source_template_path"] for binding in bindings
    }
    step_reports = []
    for path, step in sorted(expected_steps.items()):
        result = setup_results.get(path)
        if not isinstance(result, InMemorySetupResult):
            blockers.append(f"setup_result_missing_or_invalid:{path}")
            continue
        if result.argv_sha256 != step.argv_sha256:
            blockers.append(f"setup_result_argv_digest_mismatch:{path}")
        if result.timed_out:
            blockers.append(f"setup_result_timed_out:{path}")
        if result.exit_code != 0:
            blockers.append(f"setup_result_nonzero_exit:{path}")
        if (
            isinstance(maximum_stdout, int)
            and len(result.stdout) > maximum_stdout
        ):
            blockers.append(f"setup_stdout_exceeds_policy:{path}")
        digest = sha256(result.stdout).hexdigest()
        step_reports.append({
            "template_path": path,
            "argv_sha256": step.argv_sha256,
            "stdout_sha256": digest,
            "stdout_bytes": len(result.stdout),
            "raw_stdout_recorded": False,
        })
        if (
            path in capture_sources
            and result.exit_code == 0
            and not result.timed_out
        ):
            try:
                parsed[path] = json.loads(result.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                blockers.append(f"setup_stdout_not_json:{path}")

    runtime = dict(initial_runtime_values)
    authorization_copy = dict(authorization)
    inventory = authorization.get("run_owned_resource_identifiers")
    if not isinstance(inventory, Sequence) or isinstance(
        inventory, (str, bytes)
    ):
        blockers.append("run_owned_resource_inventory_missing")
        owned = []
    else:
        owned = [str(value) for value in inventory]
    capture_reports = []
    for binding in bindings:
        path = binding["source_template_path"]
        if path not in parsed:
            blockers.append(
                f"binding_source_result_unavailable:{binding['placeholder']}"
            )
            continue
        try:
            value = _json_pointer(parsed[path], binding["json_pointer"])
        except (KeyError, IndexError, TypeError, ValueError):
            blockers.append(
                f"binding_json_pointer_unresolved:{binding['placeholder']}"
            )
            continue
        if not isinstance(value, str) or not value:
            blockers.append(
                f"binding_value_not_nonempty_string:{binding['placeholder']}"
            )
            continue
        validation_error = _validate_bound_value(
            value,
            binding["validator_id"],
            initial_runtime_values,
            authorization,
        )
        if validation_error is not None:
            blockers.append(
                f"binding_value_invalid:{binding['placeholder']}:"
                f"{validation_error}"
            )
            continue
        placeholder = binding["placeholder"]
        runtime[placeholder] = value
        if binding["run_owned"] is True:
            owned.append(value)
        capture_reports.append({
            "placeholder": placeholder,
            "source_template_path": path,
            "json_pointer_sha256": sha256(
                binding["json_pointer"].encode("utf-8")
            ).hexdigest(),
            "validator_id": binding["validator_id"],
            "value_sha256": sha256(value.encode("utf-8")).hexdigest(),
            "value_recorded": False,
            "run_owned": binding["run_owned"],
        })
    authorization_copy["run_owned_resource_identifiers"] = sorted(
        set(owned)
    )

    if blockers:
        return _failure_preflight(
            contract,
            blockers,
            stage="post_setup",
            setup_steps=step_reports,
            captures=capture_reports,
        )
    full = preflight_probe_contract_stage(
        contract,
        runtime_values=runtime,
        authorization=authorization_copy,
        policy=policy,
    )
    if full.audit_report.get("ready_for_execution") is not True:
        return _failure_preflight(
            contract,
            list(full.audit_report.get("blockers") or []),
            stage="post_setup",
            setup_steps=step_reports,
            captures=capture_reports,
        )
    post_steps = tuple(
        step for step in full.resolved_steps if step.phase != "setup"
    )
    report = dict(full.audit_report)
    report.update({
        "stage": "post_setup",
        "ready_for_execution": True,
        "setup_commands_observed": len(step_reports),
        "setup_raw_stdout_recorded": False,
        "bound_values_recorded": False,
        "setup_step_evidence": step_reports,
        "dynamic_binding_evidence": capture_reports,
        "resolved_step_count": len(post_steps),
        "resolved_step_counts_by_phase": _phase_counts(post_steps),
        "resolved_step_digests": _step_digests(post_steps),
        "selected_phases": [
            phase for phase in PHASE_ORDER if phase != "setup"
        ],
    })
    return ExecutionPreflight(
        audit_report=report,
        resolved_steps=post_steps,
    )


def _binding_specs(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    plan = contract.get("runtime_binding_plan")
    if not isinstance(plan, Mapping):
        raise ValueError("runtime_binding_plan_missing")
    if plan.get("plan_version") != "1.0.0":
        raise ValueError("runtime_binding_plan_version_invalid")
    if plan.get("raw_setup_stdout_persistence_forbidden") is not True:
        raise ValueError("raw_setup_stdout_persistence_not_forbidden")
    if plan.get("agent_visibility") != "none":
        raise ValueError("dynamic_binding_visible_to_agent")
    outputs = plan.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        raise ValueError("runtime_binding_outputs_missing")
    setup_paths = {
        path for phase, path, _ in _command_templates(contract)
        if phase == "setup"
    }
    seen = set()
    result = []
    for index, item in enumerate(outputs):
        if not isinstance(item, Mapping):
            raise ValueError(f"runtime_binding_output_invalid:{index}")
        placeholder = item.get("placeholder")
        source = item.get("source_template_path")
        pointer = item.get("json_pointer")
        validator = item.get("validator_id")
        if (
            not isinstance(placeholder, str)
            or not _PLACEHOLDER_NAME.fullmatch(placeholder)
            or not placeholder.startswith("RUN_OWNED_")
        ):
            raise ValueError(f"runtime_binding_placeholder_invalid:{index}")
        if placeholder in seen:
            raise ValueError(f"runtime_binding_placeholder_duplicate:{placeholder}")
        seen.add(placeholder)
        if source not in setup_paths:
            raise ValueError(f"runtime_binding_source_not_setup:{placeholder}")
        if not isinstance(pointer, str) or not pointer.startswith("/"):
            raise ValueError(f"runtime_binding_json_pointer_invalid:{placeholder}")
        if _SENSITIVE_POINTER.search(pointer):
            raise ValueError(
                f"runtime_binding_sensitive_pointer_forbidden:{placeholder}"
            )
        if validator not in _ALLOWED_VALIDATORS:
            raise ValueError(f"runtime_binding_validator_invalid:{placeholder}")
        if item.get("run_owned") is not True:
            raise ValueError(f"dynamic_resource_not_run_owned:{placeholder}")
        if item.get("sensitive") is not False:
            raise ValueError(f"dynamic_binding_may_be_sensitive:{placeholder}")
        result.append(dict(item))
    return result


def _command_templates(
    contract: Mapping[str, Any],
) -> list[tuple[str, str, Sequence[str]]]:
    setup = contract.get("evaluator_setup") or {}
    values = setup.get("command_argv_templates") or []
    return [
        (
            "setup",
            f"evaluator_setup.command_argv_templates[{index}]",
            argv,
        )
        for index, argv in enumerate(values)
        if isinstance(argv, list)
    ]


def _json_pointer(value: Any, pointer: str) -> Any:
    current = value
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                raise TypeError("array pointer is not numeric")
            current = current[int(token)]
        elif isinstance(current, Mapping):
            current = current[token]
        else:
            raise TypeError("pointer traverses a scalar")
    return current


def _validate_bound_value(
    value: str,
    validator_id: str,
    runtime: Mapping[str, str],
    authorization: Mapping[str, Any],
) -> str | None:
    if validator_id == "aws_secretsmanager_secret_arn_v1":
        match = _SECRET_ARN.fullmatch(value)
        if match is None:
            return "secret_arn_format"
        expected = {
            "partition": runtime.get("AWS_PARTITION", "aws"),
            "region": runtime.get("AWS_REGION"),
            "account": str(authorization.get("owner_account_id") or ""),
            "run_id": runtime.get("RUN_ID"),
        }
        for field, expected_value in expected.items():
            if match.group(field) != expected_value:
                return f"secret_arn_{field}_mismatch"
        return None
    return "validator_not_allowlisted"


def _phase_counts(steps: Sequence[ResolvedStep]) -> dict[str, int]:
    return {
        phase: sum(step.phase == phase for step in steps)
        for phase in PHASE_ORDER
        if any(step.phase == phase for step in steps)
    }


def _step_digests(steps: Sequence[ResolvedStep]) -> list[dict[str, Any]]:
    return [{
        "phase": step.phase,
        "template_path": step.template_path,
        "program": step.argv[0],
        "service": step.argv[1] if len(step.argv) > 1 else None,
        "operation": step.argv[2] if len(step.argv) > 2 else None,
        "argv_sha256": step.argv_sha256,
    } for step in steps]


def _failure_preflight(
    contract: Mapping[str, Any],
    blockers: Sequence[str],
    *,
    stage: str,
    setup_steps: Sequence[Mapping[str, Any]] = (),
    captures: Sequence[Mapping[str, Any]] = (),
) -> ExecutionPreflight:
    report = {
        "report_version": "1.0.0",
        "report_kind": "oracle_contract_staged_runtime_preflight",
        "contract_id": contract.get("contract_id"),
        "independence_group": contract.get("independence_group"),
        "platform": contract.get("platform"),
        "stage": stage,
        "ready_for_execution": False,
        "commands_executed": 0,
        "truth_labels_present": False,
        "expected_outcomes_present": False,
        "credential_values_recorded": False,
        "runtime_values_recorded": False,
        "resolved_argv_recorded": False,
        "setup_raw_stdout_recorded": False,
        "bound_values_recorded": False,
        "resolved_step_count": 0,
        "resolved_step_digests": [],
        "setup_step_evidence": list(setup_steps),
        "dynamic_binding_evidence": list(captures),
        "blockers": sorted(set(str(item) for item in blockers)),
    }
    return ExecutionPreflight(audit_report=report, resolved_steps=())
