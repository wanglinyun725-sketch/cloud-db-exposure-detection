from hashlib import sha256
import json
from pathlib import Path

import yaml

from src.oracle_gold.runtime_preflight import preflight_probe_contract


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_probe_contracts_v1.json"
)
POLICY = ROOT / "configs" / "oracle_execution_policy_v1.yaml"
OWNER = "123456789012"


def _policy():
    return yaml.safe_load(POLICY.read_text(encoding="utf-8"))


def _contract(group):
    registry = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    return next(
        item
        for item in registry["contracts"]
        if item["independence_group"] == group
    )


def _authorization(tmp_path, *, run_owned, private_inputs=None):
    return {
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
        "run_owned_resource_identifiers": list(run_owned),
        "evaluator_private_root": str(tmp_path.resolve()),
        "private_inputs": private_inputs or {},
    }


def test_bounded_secret_contract_resolves_in_memory_without_leaking_value(
    tmp_path,
):
    group = (
        "stratus_red_team:stratus:"
        "aws.credential-access.secretsmanager-retrieve-secrets"
    )
    contract = _contract(group)
    secret_arn = (
        f"arn:aws:secretsmanager:us-east-1:{OWNER}:"
        "secret:pathbench-oracle-a1b2c3d4-AbCdEf"
    )
    private_file = tmp_path / "create-secret.json"
    canary = "pathbench-non-sensitive-canary-value"
    private_file.write_text(
        json.dumps({
            "Name": "pathbench-oracle-a1b2c3d4",
            "SecretString": canary,
            "Tags": [
                {"Key": "pathbench-run", "Value": "a1b2c3d4"},
            ],
        }),
        encoding="utf-8",
    )
    data = private_file.read_bytes()
    private_inputs = {
        "EVALUATOR_PRIVATE_CREATE_SECRET_JSON": {
            "path": str(private_file.resolve()),
            "sha256": sha256(data).hexdigest(),
            "bytes": len(data),
            "access_control_verified": True,
            "contains_real_secret": False,
        },
    }
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
        "RUN_OWNED_SECRET_ARN": secret_arn,
        "RUN_STARTED_AT": "2026-07-31T10:00:00Z",
        "RUNNER_EGRESS_CIDR": "203.0.113.17/32",
        "RUNNER_EGRESS_IP": "203.0.113.17",
    }
    result = preflight_probe_contract(
        contract,
        runtime_values=runtime,
        authorization=_authorization(
            tmp_path,
            run_owned=[secret_arn],
            private_inputs=private_inputs,
        ),
        policy=_policy(),
    )

    assert result.audit_report["ready_for_execution"] is True
    assert result.audit_report["commands_executed"] == 0
    assert result.audit_report["resolved_step_count"] == 7
    assert result.audit_report["blockers"] == []
    assert len(result.resolved_steps) == 7
    persisted = json.dumps(result.audit_report, sort_keys=True)
    assert canary not in persisted
    assert secret_arn not in persisted
    assert str(private_file) not in persisted
    assert result.audit_report["runtime_values_recorded"] is False
    assert result.audit_report["resolved_argv_recorded"] is False


def test_preflight_fails_closed_for_missing_or_tampered_private_input(
    tmp_path,
):
    group = (
        "stratus_red_team:stratus:"
        "aws.credential-access.secretsmanager-retrieve-secrets"
    )
    contract = _contract(group)
    private_file = tmp_path / "create-secret.json"
    private_file.write_text('{"SecretString":"canary"}', encoding="utf-8")
    secret_arn = (
        f"arn:aws:secretsmanager:us-east-1:{OWNER}:"
        "secret:pathbench-oracle-a1b2c3d4-AbCdEf"
    )
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
        "RUN_OWNED_SECRET_ARN": secret_arn,
        "RUN_STARTED_AT": "2026-07-31T10:00:00Z",
        "RUNNER_EGRESS_CIDR": "203.0.113.17/32",
        "RUNNER_EGRESS_IP": "203.0.113.17",
    }
    private_inputs = {
        "EVALUATOR_PRIVATE_CREATE_SECRET_JSON": {
            "path": str(private_file.resolve()),
            "sha256": "0" * 64,
            "bytes": private_file.stat().st_size,
            "access_control_verified": True,
            "contains_real_secret": False,
        },
    }
    result = preflight_probe_contract(
        contract,
        runtime_values=runtime,
        authorization=_authorization(
            tmp_path,
            run_owned=[secret_arn],
            private_inputs=private_inputs,
        ),
        policy=_policy(),
    )

    assert result.audit_report["ready_for_execution"] is False
    assert result.resolved_steps == ()
    assert any(
        blocker.startswith("private_input_sha256_mismatch:")
        for blocker in result.audit_report["blockers"]
    )


def test_account_share_contract_requires_distinct_isolated_accounts(
    tmp_path,
):
    contract = _contract("stratus-technique:T1578.001")
    snapshot_id = "snap-0123456789abcdef0"
    runtime = {
        "AWS_PARTITION": "aws",
        "AWS_REGION": "us-east-1",
        "DEDICATED_PROBE_PRINCIPAL_ARN": (
            f"arn:aws:iam::{OWNER}:role/pathbench-oracle-probe"
        ),
        "ISOLATED_COUNTERPART_ACCOUNT_ID": OWNER,
        "RUN_FINISHED_AT": "2026-07-31T10:30:00Z",
        "RUN_OWNED_SNAPSHOT_ID": snapshot_id,
        "RUN_STARTED_AT": "2026-07-31T10:00:00Z",
        "RUNNER_EGRESS_CIDR": "203.0.113.17/32",
        "RUNNER_EGRESS_IP": "203.0.113.17",
    }
    authorization = _authorization(
        tmp_path,
        run_owned=[snapshot_id],
    )
    authorization["counterpart_account_id"] = OWNER
    result = preflight_probe_contract(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )

    assert result.audit_report["ready_for_execution"] is False
    assert "owner_and_counterpart_accounts_not_distinct" in (
        result.audit_report["blockers"]
    )
    assert result.resolved_steps == ()


def test_policy_cannot_reenable_value_bearing_raw_persistence(tmp_path):
    contract = _contract("stratus-technique:T1578.001")
    policy = _policy()
    policy["evidence_contract"][
        "value_bearing_raw_responses_must_not_be_persisted"
    ] = False
    result = preflight_probe_contract(
        contract,
        runtime_values={},
        authorization=_authorization(tmp_path, run_owned=[]),
        policy=policy,
    )

    assert result.audit_report["ready_for_execution"] is False
    assert (
        "evidence_control_disabled:"
        "value_bearing_raw_responses_must_not_be_persisted"
    ) in result.audit_report["blockers"]
    assert result.resolved_steps == ()


def test_malformed_runtime_json_fails_closed_instead_of_crashing(tmp_path):
    contract = _contract("stratus-technique:T1578.001")
    runtime = {
        "AWS_PARTITION": ["aws"],
        "AWS_REGION": 1,
        "DEDICATED_PROBE_PRINCIPAL_ARN": None,
        "ISOLATED_COUNTERPART_ACCOUNT_ID": {},
        "RUN_FINISHED_AT": False,
        "RUN_OWNED_SNAPSHOT_ID": [],
        "RUN_STARTED_AT": 0,
        "RUNNER_EGRESS_CIDR": object(),
        "RUNNER_EGRESS_IP": 123,
    }
    authorization = _authorization(tmp_path, run_owned=[])
    authorization["counterpart_account_id"] = "210987654321"
    authorization["private_inputs"] = 7
    authorization["run_owned_resource_identifiers"] = 7

    result = preflight_probe_contract(
        contract,
        runtime_values=runtime,
        authorization=authorization,
        policy=_policy(),
    )

    assert result.audit_report["ready_for_execution"] is False
    assert result.audit_report["runtime_binding_sha256"] is None
    assert result.audit_report["private_input_count"] == 0
    assert result.audit_report["run_owned_resource_count"] == 0
    assert result.resolved_steps == ()
    assert any(
        blocker.startswith("runtime_value_not_nonempty_string:")
        for blocker in result.audit_report["blockers"]
    )


def test_ssm_parameter_must_be_explicitly_run_owned_and_match_run_id(
    tmp_path,
):
    group = (
        "stratus_red_team:stratus:"
        "aws.credential-access.ssm-retrieve-securestring-parameters"
    )
    contract = _contract(group)
    runtime = {
        "AWS_PARTITION": "aws",
        "AWS_REGION": "us-east-1",
        "DEDICATED_OWNER_ACCOUNT_ID": OWNER,
        "DEDICATED_PROBE_PRINCIPAL_ARN": (
            f"arn:aws:iam::{OWNER}:role/pathbench-oracle-probe"
        ),
        "EVALUATOR_PRIVATE_PUT_PARAMETER_JSON": str(
            tmp_path / "missing.json"
        ),
        "RUN_FINISHED_AT": "2026-07-31T10:30:00Z",
        "RUN_ID": "a1b2c3d4",
        "RUN_OWNED_PARAMETER_NAME": "/pathbench/other-run/canary",
        "RUN_STARTED_AT": "2026-07-31T10:00:00Z",
        "RUNNER_EGRESS_CIDR": "203.0.113.17/32",
        "RUNNER_EGRESS_IP": "203.0.113.17",
    }
    result = preflight_probe_contract(
        contract,
        runtime_values=runtime,
        authorization=_authorization(
            tmp_path,
            run_owned=["/pathbench/other-run/canary"],
        ),
        policy=_policy(),
    )

    assert result.audit_report["ready_for_execution"] is False
    assert "run_owned_parameter_run_id_mismatch" in (
        result.audit_report["blockers"]
    )
    assert result.resolved_steps == ()
