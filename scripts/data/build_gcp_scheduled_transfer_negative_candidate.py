#!/usr/bin/env python3
"""Build one replicated GCP blocked-path candidate from published telemetry.

The output preserves a provider-deterministic final-edge verdict while leaving
the benchmark gold label null pending semantic/admission audit.  Ten repeated
experiment runs remain instances of one lineage case, not ten benchmark cases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.profile_explicit_denial_candidates import (
    _classify,
    _events,
    _identity,
    _operation,
    _resource,
)


REAL_ROOT = ROOT / "data" / "real_sources"
MANIFEST_PATH = REAL_ROOT / "acquisition_manifest.json"
INVENTORY_PATH = (
    ROOT / "output" / "explicit_denial_candidate_inventory.json"
)
DEFAULT_OUTPUT = (
    REAL_ROOT / "gcp_scheduled_transfer_negative_candidate_v1.json"
)
SOURCE_ID = "cross_cloud_observability_2026"
ATTACK_MEMBER = (
    "attack_scripts/gcp-attacks/attack-scripts/vm-attacks.sh"
)
SCRIPT_FRAGMENTS = (
    'if [ $attack == "scheduled_transfer" ];',
    '--role="roles/storage.objectViewer"',
    '--role="roles/pubsub.publisher"',
    "--service-account=$SERVICE_ACCOUNT",
    "--allow-unauthenticated",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifacts() -> dict[str, dict]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    source = next(
        item
        for item in manifest["sources"]
        if item["source_id"] == SOURCE_ID
    )
    return {
        artifact["name"]: artifact for artifact in source["artifacts"]
    }


def _causal_refs(
    archive: ZipFile,
    member: str,
    *,
    denied_principal: str,
    denied_target: str,
) -> tuple[str, dict[str, list[dict]]]:
    raw = archive.read(member)
    payload = json.loads(raw.decode("utf-8-sig"))
    required = {
        "create_function": (
            "cloudfunctions.googleapis.com::"
            "google.cloud.functions.v2.FunctionService.CreateFunction"
        ),
        "create_scheduler": (
            "cloudscheduler.googleapis.com::"
            "google.cloud.scheduler.v1.CloudScheduler.CreateJob"
        ),
        "act_as_service_account": (
            "iam.googleapis.com::iam.serviceAccounts.actAs"
        ),
        "denied_bucket_list": (
            "storage.googleapis.com::storage.objects.list"
        ),
        "admin_bucket_list_success_control": (
            "storage.googleapis.com::storage.objects.list"
        ),
    }
    found = {key: [] for key in required}
    member_hash = _sha256(raw)
    for provider, event, pointer in _events(payload):
        if provider != "GCP":
            continue
        operation = _operation(provider, event)
        classification, _ = _classify(provider, event)
        principal = _identity(provider, event)
        resource = _resource(provider, event)
        for key, expected_operation in required.items():
            if operation != expected_operation:
                continue
            if (
                key == "denied_bucket_list"
                and (
                    classification != "explicit_denial"
                    or principal != denied_principal
                    or resource != denied_target
                )
            ):
                continue
            if (
                key == "admin_bucket_list_success_control"
                and (
                    classification != "no_explicit_denial"
                    or principal == denied_principal
                    or resource != denied_target
                )
            ):
                continue
            found[key].append(
                {
                    "member": member,
                    "member_sha256": member_hash,
                    "json_pointer": pointer,
                }
            )
    missing = [key for key, refs in found.items() if not refs]
    if missing:
        raise ValueError(f"{member} is missing causal records: {missing}")
    return member_hash, found


def build_candidate() -> dict:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    claims = [
        item
        for item in inventory["data_relevant_denial_candidates"]
        if item["provider"] == "GCP"
        and item["scenario_family"] == "scheduled_transfer"
        and item["operation"].endswith("::storage.objects.list")
    ]
    if len(claims) != 10:
        raise ValueError(
            f"expected 10 scheduled_transfer denial instances, got {len(claims)}"
        )
    if any(
        '"status_code": 7' not in item["reason"]
        or "storage.objects.list" not in item["reason"]
        or item["occurrence_count"] < 1
        for item in claims
    ):
        raise ValueError("scheduled_transfer denial evidence is incomplete")

    artifacts = _artifacts()
    artifact = artifacts["attack_scripts.zip"]
    attack_path = ROOT / artifact["relative_path"]
    with ZipFile(attack_path) as archive:
        raw_script = archive.read(ATTACK_MEMBER)
    script = raw_script.decode("utf-8", errors="replace")
    missing = [
        fragment for fragment in SCRIPT_FRAGMENTS if fragment not in script
    ]
    if missing:
        raise ValueError(f"upstream script fragments changed: {missing}")

    logs_artifact = artifacts["gcp_logs_redacted.zip"]
    logs_path = ROOT / logs_artifact["relative_path"]
    instances = []
    with ZipFile(logs_path) as logs_archive:
        for claim in sorted(
            claims,
            key=lambda item: item["raw_ref"]["member"],
        ):
            member_hash, causal_refs = _causal_refs(
                logs_archive,
                claim["raw_ref"]["member"],
                denied_principal=claim["identity"],
                denied_target=claim["resource"],
            )
            instances.append(
                {
                    "instance_id": Path(
                        claim["raw_ref"]["member"]
                    ).stem,
                    "payload_condition": "y",
                    "principal": claim["identity"],
                    "target": claim["resource"],
                    "operation": claim["operation"],
                    "provider_status_code": 7,
                    "denied_permission": "storage.objects.list",
                    "retry_denial_count": claim["occurrence_count"],
                    "telemetry_archive_sha256": logs_artifact["sha256"],
                    "telemetry_member_sha256": member_hash,
                    "causal_control_refs": causal_refs,
                    "raw_refs": claim["occurrence_refs"],
                    "deterministic_final_edge_state": "Contradicted",
                }
            )

    return {
        "candidate_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_id": "crosscloud:gcp:scheduled_transfer:blocked_bucket_list",
        "source_id": SOURCE_ID,
        "lineage_group": "crosscloud-family:scheduled_transfer",
        "platform": "GCP",
        "status": "provider_oracle_gold_ready_pending_main_release",
        "policy": {
            "generated_events": 0,
            "generated_labels": 0,
            "replicated_runs_are_separate_cases": False,
            "provider_denial_is_deterministic": True,
            "whole_path_gold_requires_semantic_audit": True,
        },
        "upstream_script": {
            "archive_sha256": artifact["sha256"],
            "member": ATTACK_MEMBER,
            "member_sha256": _sha256(raw_script),
            "literal_fragments_verified": list(SCRIPT_FRAGMENTS),
            "notable_configuration": (
                "The script declares one add-iam-policy-binding command "
                "with both objectViewer and pubsub.publisher --role flags, "
                "while the provider CLI contract defines one role per binding."
            ),
        },
        "path_hypothesis": {
            "entry": (
                "scheduled/public Cloud Function executing as the "
                "quickstart service account"
            ),
            "steps": [
                "Cloud Function is created with the quickstart service account",
                "Cloud Scheduler job is created for the function",
                "function code attempts storage.objects.list on the run bucket",
                "GCP explicitly denies storage.objects.list"
            ],
            "data_target": "Google Cloud Storage bucket",
            "deterministic_final_edge_claim": (
                "quickstart service account can list objects in the run bucket"
            ),
            "deterministic_final_edge_state": "Contradicted",
            "provisional_path_state": "NotReachable",
        },
        "provider_oracle_certificate": {
            "oracle": "GCP Cloud Audit Logs",
            "claim": (
                "quickstart service account can execute "
                "storage.objects.list on its run bucket"
            ),
            "verdict": "Contradicted",
            "path_verdict": "NotReachable",
            "gold_tier": "runtime_gold",
            "label_origin": "provider_native_runtime",
            "sufficiency_rule": (
                "Every payload run contains function creation, service-account "
                "actAs, scheduler creation, and one or more code-7 "
                "storage.objects.list denials for the function service account; "
                "the same bucket is successfully listed by a different "
                "project identity in the same run."
            ),
            "sufficient": True,
        },
        "replication": {
            "independent_runs": len(instances),
            "total_denied_attempts": sum(
                instance["retry_denial_count"] for instance in instances
            ),
            "all_runs_same_final_edge_state": True,
            "instances": instances,
        },
        "annotation": {
            "human_gold_label": None,
            "provider_oracle_gold_label": "NotReachable",
            "label_origin": "provider_native_runtime",
            "semantic_contract_status": "deterministic_checks_complete",
            "main_benchmark_release_status": (
                "protocol-v3 pilot integrated; main benchmark remains "
                "pending stratified human audit"
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    candidate = build_candidate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(candidate, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "case_id": candidate["case_id"],
                "status": candidate["status"],
                "independent_runs": candidate["replication"][
                    "independent_runs"
                ],
                "total_denied_attempts": candidate["replication"][
                    "total_denied_attempts"
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
