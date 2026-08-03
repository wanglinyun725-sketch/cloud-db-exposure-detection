from hashlib import sha256
import json
from pathlib import Path

import yaml

from src.oracle_gold.staged_runtime import (
    InMemorySetupResult,
    bind_staged_setup_outputs,
    preflight_staged_setup,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_probe_contracts_v1.json"
)
POLICY = ROOT / "configs" / "oracle_execution_policy_v1.yaml"
OWNER = "123456789012"
GROUP = (
    "stratus_red_team:stratus:"
    "aws.credential-access.secretsmanager-retrieve-secrets"
)


def _contract():
    registry = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    return next(
        item for item in registry["contracts"]
        if item["independence_group"] == GROUP
    )


def _policy():
    return yaml.safe_load(POLICY.read_text(encoding="utf-8"))


def _contexts(tmp_path):
    private_file = tmp_path / "create-secret.json"
    private_file.write_text(
        json.dumps({
            "Name": "pathbench-oracle-a1b2c3d4",
            "SecretString": "non-sensitive-canary",
            "Tags": [{"Key": "pathbench-run", "Value": "a1b2c3d4"}],
        }),
        encoding="utf-8",
    )
    data = private_file.read_bytes()
    runtime = {
        "AWS_REGION": "us-east-1",
        "DEDICATED_PROBE_PRINCIPAL_ARN": (
            f"arn:aws:iam::{OWNER}:role/pathbench-oracle-probe"
        ),
        "EVALUATOR_PRIVATE_CREATE_SECRET_JSON": str(
            private_file.resolve()
        ),
        "RUN_FINISHED_AT": "2026-07-31T10:30:00Z",
        "RUN_ID": "a1b2c3d4",
        "RUN_STARTED_AT": "2026-07-31T10:00:00Z",
        "RUNNER_EGRESS_CIDR": "203.0.113.17/32",
        "RUNNER_EGRESS_IP": "203.0.113.17",
    }
    authorization = {
        "authorization_sentinel": (
            "I_AUTHORIZE_ISOLATED_TEST_RESOURCES_ONLY"
        ),
        "dedicated_scope_attested": True,
        "production_scope": False,
        "no_sensitive_data_attested": True,
        "teardown_plan_verified": True,
        "post_teardown_inventory_plan_verified": True,
        "cost_estimate_approved": True,
        "owner_account_id": OWNER,
        "estimated_cost_usd": 0.05,
        "ttl_hours": 2,
        "resource_tags": {
            "managed-by": "cloud-db-pathbench",
            "purpose": "executable-oracle",
        },
        "run_owned_resource_identifiers": [],
        "evaluator_private_root": str(tmp_path.resolve()),
        "private_inputs": {
            "EVALUATOR_PRIVATE_CREATE_SECRET_JSON": {
                "path": str(private_file.resolve()),
                "sha256": sha256(data).hexdigest(),
                "bytes": len(data),
                "access_control_verified": True,
                "contains_real_secret": False,
            },
        },
    }
    return runtime, authorization


def test_secret_arn_is_bound_from_exact_setup_step_then_fully_repreflighted(
    tmp_path,
):
    contract = _contract()
    runtime, authorization = _contexts(tmp_path)
    setup = preflight_staged_setup(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )

    assert setup.audit_report["ready_for_execution"] is True
    assert setup.audit_report["stage"] == "setup"
    assert setup.audit_report["deferred_placeholder_count"] == 1
    assert len(setup.resolved_steps) == 1
    step = setup.resolved_steps[0]
    arn = (
        "arn:aws:secretsmanager:us-east-1:123456789012:"
        "secret:pathbench-oracle-a1b2c3d4-AbCdEf"
    )
    stdout = json.dumps({
        "ARN": arn,
        "Name": "pathbench-oracle-a1b2c3d4",
        "VersionId": "11111111-1111-4111-8111-111111111111",
    }).encode("utf-8")
    post = bind_staged_setup_outputs(
        contract,
        setup_preflight=setup,
        setup_results={
            step.template_path: InMemorySetupResult(
                argv_sha256=step.argv_sha256,
                exit_code=0,
                stdout=stdout,
            ),
        },
        initial_runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )

    assert post.audit_report["ready_for_execution"] is True
    assert post.audit_report["stage"] == "post_setup"
    assert post.audit_report["setup_commands_observed"] == 1
    assert post.audit_report["resolved_step_count"] == 6
    assert all(step.phase != "setup" for step in post.resolved_steps)
    assert {step.phase for step in post.resolved_steps} == {
        "provider_native_analysis",
        "active_probe",
        "postcondition",
        "audit_telemetry",
        "cleanup",
        "post_cleanup_inventory",
    }
    persisted = json.dumps(post.audit_report, sort_keys=True)
    assert arn not in persisted
    assert stdout.decode("utf-8") not in persisted
    assert str(runtime["EVALUATOR_PRIVATE_CREATE_SECRET_JSON"]) not in persisted
    capture = post.audit_report["dynamic_binding_evidence"][0]
    assert capture["value_recorded"] is False
    assert capture["value_sha256"] == sha256(arn.encode()).hexdigest()


def test_staged_binding_rejects_wrong_account_and_releases_no_probe_steps(
    tmp_path,
):
    contract = _contract()
    runtime, authorization = _contexts(tmp_path)
    setup = preflight_staged_setup(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )
    step = setup.resolved_steps[0]
    wrong_arn = (
        "arn:aws:secretsmanager:us-east-1:210987654321:"
        "secret:pathbench-oracle-a1b2c3d4-AbCdEf"
    )
    post = bind_staged_setup_outputs(
        contract,
        setup_preflight=setup,
        setup_results={
            step.template_path: InMemorySetupResult(
                argv_sha256=step.argv_sha256,
                exit_code=0,
                stdout=json.dumps({"ARN": wrong_arn}).encode(),
            ),
        },
        initial_runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )

    assert post.audit_report["ready_for_execution"] is False
    assert post.resolved_steps == ()
    assert any(
        "secret_arn_account_mismatch" in blocker
        for blocker in post.audit_report["blockers"]
    )
    assert wrong_arn not in json.dumps(post.audit_report)


def test_staged_binding_rejects_step_substitution_and_sensitive_pointer(
    tmp_path,
):
    contract = _contract()
    runtime, authorization = _contexts(tmp_path)
    setup = preflight_staged_setup(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )
    step = setup.resolved_steps[0]
    substituted = bind_staged_setup_outputs(
        contract,
        setup_preflight=setup,
        setup_results={
            step.template_path: InMemorySetupResult(
                argv_sha256="0" * 64,
                exit_code=0,
                stdout=b'{"ARN":"irrelevant"}',
            ),
        },
        initial_runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )
    assert substituted.audit_report["ready_for_execution"] is False
    assert any(
        blocker.startswith("setup_result_argv_digest_mismatch:")
        for blocker in substituted.audit_report["blockers"]
    )

    tampered = json.loads(json.dumps(contract))
    tampered["runtime_binding_plan"]["outputs"][0][
        "json_pointer"
    ] = "/SecretString"
    rejected = preflight_staged_setup(
        tampered,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )
    assert rejected.audit_report["ready_for_execution"] is False
    assert rejected.resolved_steps == ()
    assert any(
        blocker.startswith("runtime_binding_sensitive_pointer_forbidden:")
        for blocker in rejected.audit_report["blockers"]
    )


def test_dynamic_placeholder_cannot_be_injected_before_setup(tmp_path):
    contract = _contract()
    runtime, authorization = _contexts(tmp_path)
    runtime["RUN_OWNED_SECRET_ARN"] = (
        "arn:aws:secretsmanager:us-east-1:123456789012:"
        "secret:pathbench-oracle-a1b2c3d4-AbCdEf"
    )
    setup = preflight_staged_setup(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )

    assert setup.audit_report["ready_for_execution"] is False
    assert setup.resolved_steps == ()
    assert (
        "deferred_placeholder_supplied_before_setup:RUN_OWNED_SECRET_ARN"
        in setup.audit_report["blockers"]
    )


def test_post_setup_cannot_switch_runtime_authorization_or_contract(tmp_path):
    contract = _contract()
    runtime, authorization = _contexts(tmp_path)
    setup = preflight_staged_setup(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )
    step = setup.resolved_steps[0]
    result = {
        step.template_path: InMemorySetupResult(
            argv_sha256=step.argv_sha256,
            exit_code=0,
            stdout=json.dumps({
                "ARN": (
                    "arn:aws:secretsmanager:us-east-1:123456789012:"
                    "secret:pathbench-oracle-a1b2c3d4-AbCdEf"
                ),
            }).encode(),
        ),
    }
    changed_runtime = dict(runtime)
    changed_runtime["RUN_FINISHED_AT"] = "2026-07-31T10:31:00Z"
    rejected_runtime = bind_staged_setup_outputs(
        contract,
        setup_preflight=setup,
        setup_results=result,
        initial_runtime_values=changed_runtime,
        authorization=authorization,
        policy=_policy(),
    )
    assert (
        "setup_context_binding_mismatch:runtime_binding_sha256"
        in rejected_runtime.audit_report["blockers"]
    )
    assert rejected_runtime.resolved_steps == ()

    changed_authorization = dict(authorization)
    changed_authorization["estimated_cost_usd"] = 0.06
    rejected_authorization = bind_staged_setup_outputs(
        contract,
        setup_preflight=setup,
        setup_results=result,
        initial_runtime_values=runtime,
        authorization=changed_authorization,
        policy=_policy(),
    )
    assert (
        "setup_context_binding_mismatch:authorization_binding_sha256"
        in rejected_authorization.audit_report["blockers"]
    )
    assert rejected_authorization.resolved_steps == ()

    changed_contract = json.loads(json.dumps(contract))
    changed_contract["audit_telemetry"]["adapter_id"] = "tampered"
    rejected_contract = bind_staged_setup_outputs(
        changed_contract,
        setup_preflight=setup,
        setup_results=result,
        initial_runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )
    assert (
        "setup_context_binding_mismatch:contract_binding_sha256"
        in rejected_contract.audit_report["blockers"]
    )
    assert rejected_contract.resolved_steps == ()
