from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from src.oracle_gold.evidence_bundle import (
    apply_completed_evidence_bundles,
    build_evidence_bundle_templates,
    derive_truth_state,
    validate_evidence_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
QUEUE = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_execution_queue_v1.json"
)
POLICY = ROOT / "configs" / "oracle_execution_policy_v1.yaml"
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle" / "execution"
    / "oracle_evidence_bundle_templates_v1.json"
)


def _binding(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _scope_digest(scope: dict) -> str:
    payload = json.dumps(
        scope,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _completed_bundle() -> dict:
    collection = build_evidence_bundle_templates(
        ROOT,
        queue_path=QUEUE,
        policy_path=POLICY,
    )
    bundle = deepcopy(collection["templates"][0])
    scope = {
        "status": "frozen",
        "principals": ["test-principal"],
        "actions": ["test:ReadData"],
        "resources": ["test-resource"],
        "network_origins": ["198.51.100.10/32"],
        "time_window": [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:05:00Z",
        ],
    }
    artifact_paths = [
        ROOT / "docs" / "executable_oracle_gold_protocol_v1.md",
        ROOT / "configs" / "oracle_execution_policy_v1.yaml",
        ROOT / "data" / "real_sources" / "oracle"
        / "executable_oracle_record_v1.schema.json",
        ROOT / "data" / "real_sources" / "oracle"
        / "executable_oracle_registry_v1.json",
    ]
    outcomes = {
        "configuration": "verified_facts",
        "provider_native_analysis": "allows",
        "authorized_active_probe": "allowed",
        "audit_telemetry": "allowed_observed",
    }
    digest = _scope_digest(scope)
    channels = {}
    for index, (channel, outcome) in enumerate(outcomes.items()):
        channels[channel] = {
            "status": "verified",
            "outcome": outcome,
            "evidence": [{
                "evidence_id": f"synthetic-test-{channel}",
                "artifact": _binding(artifact_paths[index]),
                "adapter": {
                    "adapter_id": "synthetic-test-only",
                    "adapter_version": "1",
                    "deterministic": True,
                },
                "scope_binding_sha256": digest,
                "observed_at": "2026-01-01T00:01:00Z",
                "wall_clock_seconds": 0.1,
                "command_argv_sha256": "1" * 64,
                "provider_request_ids": [],
            }],
        }
    bundle.update({
        "status": "completed",
        "run": {
            "status": "completed",
            "run_id": "synthetic-unit-test-only",
            "platform": bundle["run"]["platform"],
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:05:00Z",
            "estimated_cost_usd": 0,
            "credential_values_recorded": False,
            "authorization": {
                "dedicated_scope_verified": True,
                "production_scope": False,
                "sentinel_verified": True,
                "no_sensitive_data_attested": True,
                "run_owned_resources_only": True,
            },
            "teardown": {
                "status": "verified_clean",
                "inventory_artifact": _binding(QUEUE),
            },
        },
        "scope": scope,
        "channels": channels,
        "critical_edges": [{
            "src": "test-principal",
            "edge_type": "read",
            "dst": "test-resource",
            "evidence_refs": [
                "synthetic-test-provider_native_analysis",
                "synthetic-test-authorized_active_probe",
            ],
        }],
        "leakage_control": {
            "agent_view_artifact": _binding(
                ROOT / "README.md"
            ),
            "evaluator_only_artifacts": [
                _binding(path) for path in artifact_paths
            ],
            "oracle_outputs_withheld_until_scoring": True,
        },
    })
    return bundle


def test_committed_bundle_templates_are_reproducible_and_label_empty():
    built = build_evidence_bundle_templates(
        ROOT,
        queue_path=QUEUE,
        policy_path=POLICY,
    )

    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == built
    assert built["summary"] == {
        "template_count": 40,
        "platform_counts": {"AWS": 28, "AZURE": 5, "GCP": 7},
    }
    assert all(
        item["status"] == "pending"
        and all(
            entry["outcome"] is None
            for entry in item["channels"].values()
        )
        for item in built["templates"]
    )
    for item in built["templates"]:
        report = validate_evidence_bundle(
            ROOT,
            item,
            queue_path=QUEUE,
            policy_path=POLICY,
            require_completed=False,
        )
        assert report["derived_truth_state"] == "Unknown"


def test_completed_bundle_derives_reachable_without_supplied_label():
    bundle = _completed_bundle()

    report = validate_evidence_bundle(
        ROOT,
        bundle,
        queue_path=QUEUE,
        policy_path=POLICY,
    )

    assert "truth_state" not in bundle
    assert report["derived_truth_state"] == "Reachable"
    assert report["qualifies_by_state"] is True


def test_completed_bundle_is_the_only_input_to_gold_promotion():
    registry = json.loads(
        (
            ROOT / "data" / "real_sources" / "oracle"
            / "executable_oracle_registry_v1.json"
        ).read_text(encoding="utf-8")
    )
    output = apply_completed_evidence_bundles(
        ROOT,
        registry,
        [_completed_bundle()],
        queue_path=QUEUE,
        policy_path=POLICY,
    )

    assert output["summary"]["truth_state_counts"] == {
        "Reachable": 1,
        "NotReachableWithinScope": 0,
        "Unknown": 39,
        "Conflict": 0,
    }
    assert output["summary"]["qualifying_oracle_gold_groups"] == 1
    assert sum(
        item["counts_toward_oracle_gold"] is True
        for item in output["candidates"]
    ) == 1


def test_four_value_derivation_is_fail_closed():
    bundle = _completed_bundle()
    bundle["channels"]["authorized_active_probe"]["status"] = "pending"
    assert derive_truth_state(bundle) == "Unknown"

    bundle = _completed_bundle()
    bundle["channels"]["authorized_active_probe"]["outcome"] = "denied"
    assert derive_truth_state(bundle) == "Conflict"

    bundle = _completed_bundle()
    bundle["channels"]["provider_native_analysis"]["outcome"] = "denies"
    bundle["channels"]["authorized_active_probe"]["outcome"] = "denied"
    bundle["channels"]["audit_telemetry"]["outcome"] = "denied_observed"
    assert derive_truth_state(bundle) == "NotReachableWithinScope"


def test_bundle_rejects_queue_tampering_and_incomplete_teardown():
    bundle = _completed_bundle()
    bundle["task_binding"]["queue"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="queue binding mismatch"):
        validate_evidence_bundle(
            ROOT,
            bundle,
            queue_path=QUEUE,
            policy_path=POLICY,
        )

    bundle = _completed_bundle()
    bundle["run"]["teardown"]["status"] = "pending"
    with pytest.raises(ValueError, match="teardown is not verified clean"):
        validate_evidence_bundle(
            ROOT,
            bundle,
            queue_path=QUEUE,
            policy_path=POLICY,
        )


def test_bundle_schema_forbids_a_hand_written_truth_label():
    bundle = _completed_bundle()
    bundle["truth_state"] = "Reachable"

    with pytest.raises(ValueError, match="schema violation"):
        validate_evidence_bundle(
            ROOT,
            bundle,
            queue_path=QUEUE,
            policy_path=POLICY,
        )


def test_bundle_rejects_scope_mismatch_and_agent_oracle_overlap():
    bundle = _completed_bundle()
    evidence = bundle["channels"]["configuration"]["evidence"][0]
    evidence["scope_binding_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="evidence scope mismatch"):
        validate_evidence_bundle(
            ROOT,
            bundle,
            queue_path=QUEUE,
            policy_path=POLICY,
        )

    bundle = _completed_bundle()
    evaluator = bundle["leakage_control"]["evaluator_only_artifacts"][0]
    bundle["leakage_control"]["agent_view_artifact"] = evaluator
    with pytest.raises(ValueError, match="agent view equals"):
        validate_evidence_bundle(
            ROOT,
            bundle,
            queue_path=QUEUE,
            policy_path=POLICY,
        )
