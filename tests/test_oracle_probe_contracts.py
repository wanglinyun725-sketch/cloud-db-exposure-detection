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
        "supported_contracts": 5,
        "unsupported_or_unresolved_groups": 35,
        "platform_counts": {"AWS": 5, "AZURE": 0, "GCP": 0},
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
    assert all(
        contract["safety"]["resource_must_be_created_by_current_run"]
        is True
        and contract["safety"]["public_group_all_forbidden"] is True
        and contract["authorized_active_probe"][
            "dry_run_is_qualifying_runtime_evidence"
        ] is False
        for contract in built["contracts"]
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
        if contract["derivation"].get("upstream_behavior_narrowed")
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


def test_every_contract_binds_pinned_stratus_implementation_bytes():
    built = _build()

    assert built["bindings"]["stratus_archive"]["sha256"] == (
        "fa2ad67871887a55f226f875a9c339b7e12987b83aa5a951631ce9f5036d0480"
    )
    for contract in built["contracts"]:
        upstream = contract["upstream_implementation"]
        assert upstream["commit"] == (
            "52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0"
        )
        assert len(upstream["members"]) == 4
        assert all(
            len(member["sha256"]) == 64 and member["bytes"] > 0
            for member in upstream["members"]
        )
