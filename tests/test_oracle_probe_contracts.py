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
        "supported_contracts": 2,
        "unsupported_or_unresolved_groups": 38,
        "platform_counts": {"AWS": 2, "AZURE": 0, "GCP": 0},
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

    for contract in built["contracts"]:
        probe = contract["authorized_active_probe"]["probe_argv_template"]
        cleanup = contract["authorized_active_probe"][
            "cleanup_argv_template"
        ]
        assert probe[0:3] == cleanup[0:3]
        assert "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}" in " ".join(probe)
        assert "{{ISOLATED_COUNTERPART_ACCOUNT_ID}}" in " ".join(cleanup)
        assert "add" in " ".join(probe).casefold()
        assert "remove" in " ".join(cleanup).casefold()
