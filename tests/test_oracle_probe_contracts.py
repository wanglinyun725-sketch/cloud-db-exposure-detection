import json
from pathlib import Path

from src.oracle_gold.probe_contracts import (
    build_probe_contract_registry,
)


ROOT = Path(__file__).resolve().parents[1]
SCOPE = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_scope_candidates_v1.json"
)
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_probe_contracts_v1.json"
)


def _build():
    return build_probe_contract_registry(
        ROOT,
        scope_inventory_path=SCOPE,
    )


def test_committed_probe_contracts_are_reproducible_and_outcome_free():
    built = _build()

    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == built
    assert built["summary"] == {
        "candidate_groups": 40,
        "supported_contracts": 7,
        "unsupported_or_unresolved_groups": 33,
        "platform_counts": {"AWS": 5, "AZURE": 1, "GCP": 1},
    }
    serialized = json.dumps(built, sort_keys=True)
    assert '"truth_state"' not in serialized
    assert '"expected_truth_state": null' in serialized
    assert "Group=all" not in serialized
    assert "--group-names" not in serialized


def test_contracts_use_runtime_placeholders_not_historical_identifiers():
    built = _build()
    serialized = json.dumps(built)

    for historical in (
        "756680937392",
        "118238665043",
        "snap-041993b54a9b3af6f",
        "ami-de1fbCab6ccB03e6D",
        "253.76.43.253",
        "253.19.58.252",
    ):
        assert historical not in serialized
    assert "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}" in serialized
    assert ":ec2:{{AWS_REGION}}::snapshot/" in serialized
    assert ":ec2:{{AWS_REGION}}::image/" in serialized
    aws_contracts = [
        contract for contract in built["contracts"]
        if contract["platform"] == "AWS"
    ]
    assert all(
        contract["safety"]["resource_must_be_created_by_current_run"]
        is True
        and contract["safety"]["public_group_all_forbidden"] is True
        for contract in aws_contracts
    )


def test_probe_and_cleanup_are_exact_inverse_account_grants():
    built = _build()

    account_grant_contracts = [
        contract
        for contract in built["contracts"]
        if "cleanup_argv_template"
        in contract["authorized_active_probe"]
    ]
    assert len(account_grant_contracts) == 2
    for contract in account_grant_contracts:
        probe = contract["authorized_active_probe"]["probe_argv_template"]
        cleanup = contract["authorized_active_probe"][
            "cleanup_argv_template"
        ]
        assert probe[0:3] == cleanup[0:3]
        assert "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}" in " ".join(probe)
        assert "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}" in " ".join(cleanup)
        assert "add" in " ".join(probe).casefold()
        assert "remove" in " ".join(cleanup).casefold()


def test_bounded_secret_reads_never_emit_values_or_enumerate_accounts():
    built = _build()
    bounded = [
        contract
        for contract in built["contracts"]
        if contract["platform"] == "AWS"
        and contract["derivation"].get("upstream_behavior_narrowed")
    ]

    assert len(bounded) == 3
    for contract in bounded:
        assert contract["safety"]["account_wide_enumeration_forbidden"]
        assert contract["safety"]["resource_must_be_created_by_current_run"]
        assert contract["sensitive_response_handling"][
            "cli_query_excludes_sensitive_values"
        ]
        assert contract["sensitive_response_handling"][
            "raw_stdout_persistence_forbidden"
        ]
        probe = contract["authorized_active_probe"][
            "probe_argv_template"
        ]
        assert "--query" in probe
        query = probe[probe.index("--query") + 1]
        assert "SecretString" not in query
        assert "SecretBinary" not in query
        assert "Value:Value" not in query
        assert "--filters" not in probe


def test_cloud_generated_secret_arns_use_hidden_staged_bindings():
    built = _build()
    staged = [
        contract for contract in built["contracts"]
        if "runtime_binding_plan" in contract
    ]

    assert len(staged) == 2
    assert {contract["independence_group"] for contract in staged} == {
        (
            "stratus_red_team:stratus:"
            "aws.credential-access.secretsmanager-retrieve-secrets"
        ),
        (
            "stratus_red_team:stratus:"
            "aws.credential-access.secretsmanager-batch-retrieve-secrets"
        ),
    }
    for contract in staged:
        plan = contract["runtime_binding_plan"]
        assert plan["agent_visibility"] == "none"
        assert plan["raw_setup_stdout_persistence_forbidden"] is True
        assert plan["post_setup_full_repreflight_required"] is True
        assert all(
            output["placeholder"].startswith("RUN_OWNED_SECRET")
            and output["validator_id"]
            == "aws_secretsmanager_secret_arn_v1"
            and output["run_owned"] is True
            and output["sensitive"] is False
            for output in plan["outputs"]
        )


def test_every_contract_binds_pinned_stratus_implementation_bytes():
    built = _build()

    assert built["bindings"]["stratus_archive"]["sha256"] == (
        "fa2ad67871887a55f226f875a9c339b7e12987b83aa5a951631ce9f5036d0480"
    )
    for contract in built["contracts"]:
        upstream = contract["upstream_implementation"]
        if contract["platform"] == "AWS":
            assert upstream["commit"] == (
                "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0"
            )
            assert len(upstream["members"]) == 4
        assert all(
            len(member["sha256"]) == 64 and member["bytes"] > 0
            for member in upstream["members"]
        )


def test_every_contract_has_post_cleanup_inventory_and_explicit_ownership():
    built = _build()

    for contract in built["contracts"]:
        active = contract["authorized_active_probe"]
        assert (
            "post_cleanup_inventory_argv_template" in active
            or "post_cleanup_inventory_argv_templates" in active
        )
        if contract["independence_group"].endswith(
            "ssm-retrieve-securestring-parameters"
        ):
            serialized = json.dumps(contract)
            assert "{{RUN_OWNED_PARAMETER_NAME}}" in serialized
            assert "/pathbench/{{RUN_ID}}/canary" not in serialized


def test_gcpgoat_policy_transition_is_bounded_and_audit_eligible():
    built = _build()
    contract = next(
        item for item in built["contracts"]
        if item["platform"] == "GCP"
    )

    assert contract["independence_group"] == (
        "configuration-lineage:gcpgoat:"
        "gcpgoat_anonymous_bucket_policy_transition"
    )
    assert contract["runtime_scope_template"]["actions"] == [
        "storage.buckets.setIamPolicy",
        "storage.objects.get",
    ]
    assert contract["upstream_implementation"]["commit"] == (
        "44605c4bff4b2da7611dfce78696bb53db6d8c54"
    )
    assert contract["upstream_implementation"]["archive"]["sha256"] == (
        "f8e59451cdf074144cac7fe97f87477296ca88a6c9a605eab72baf82dff85af8"
    )
    assert contract["safety"][
        "random_bucket_name_minimum_entropy_bits"
    ] == 128
    assert contract["safety"][
        "custom_role_has_no_data_read_write_or_delete"
    ] is True
    assert contract["audit_telemetry"][
        "public_object_access_used_as_telemetry"
    ] is False
    required = contract["audit_telemetry"]["required_event_predicates"]
    assert {row["audit_log_type"] for row in required} == {
        "Admin Activity",
        "Data Access",
    }
    serialized = json.dumps(contract)
    assert "{{RUN_OWNED_GCS_BUCKET}}" in serialized
    assert "{{RUN_OWNED_GCS_OBJECT}}" in serialized
    assert "allUsers" in serialized
    assert "roles/storage.admin" not in serialized


def test_azuregoat_blob_pair_is_minimal_anonymous_and_audit_visible():
    built = _build()
    contract = next(
        item for item in built["contracts"]
        if item["platform"] == "AZURE"
    )

    assert contract["independence_group"] == (
        "configuration-lineage:azuregoat:"
        "azuregoat_prod_dev_blob_control_pair"
    )
    upstream = contract["upstream_implementation"]
    assert upstream["commit"] == (
        "b97045952e6df00de735a7f27fd7c4994dcfe8c0"
    )
    assert upstream["archive"]["sha256"] == (
        "ccd24e4f41dfa85f8345fa8f132a6a917811ac05d9350a45f77f8be3500dea2a"
    )
    assert upstream["members"] == [{
        "member_path": (
            "AzureGoat-b97045952e6df00de735a7f27fd7c4994dcfe8c0/"
            "main.tf"
        ),
        "sha256": (
            "2fa47c4d48b423b208b1b3e114fc679374d84b2dcae37f2c9edb42503f755e53"
        ),
        "bytes": 22154,
    }]
    assert contract["derivation"][
        "full_azuregoat_deployment_executed"
    ] is False
    assert contract["derivation"]["upstream_payloads_copied"] is False
    probes = contract["authorized_active_probe"]["probe_argv_templates"]
    assert len(probes) == 4
    for probe in probes:
        assert probe[:2] == ["curl", "--disable"]
        assert "--noproxy" in probe
        assert "--user" not in probe
        assert "--oauth2-bearer" not in probe
        assert not any(
            token.casefold().startswith("authorization:")
            for token in probe
        )
    required = contract["audit_telemetry"][
        "required_event_predicates"
    ]
    assert {row["OperationName"] for row in required} == {
        "ListBlobs",
        "GetBlob",
    }
    assert all(
        row["AuthenticationType"] == "Anonymous" for row in required
    )
    assert contract["audit_telemetry"][
        "absence_of_failed_anonymous_log_is_not_denial_evidence"
    ] is True
    assert contract["safety"][
        "random_storage_account_minimum_entropy_bits"
    ] == 88
