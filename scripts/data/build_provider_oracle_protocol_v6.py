#!/usr/bin/env python3
"""Build provider-oracle protocol v6 with paired catalogue denials.

V6 preserves v5 and adds three operation-scoped negative cases from one new
Splunk attack-range lineage.  The cases share one independence group.  Each
denied IAM user call has an explicit AccessDenied outcome and a successful
same-account, same-region, same-service, same-operation control call by a
different IAM user.  Verdicts are limited to catalogue enumeration and never
claim that every individual data object is inaccessible.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.data.build_provider_oracle_protocol_v3 import (  # noqa: E402
    _decorate_runtime,
    _public_case,
)
from scripts.data.build_provider_oracle_protocol_v5 import (  # noqa: E402
    build as build_v5,
)


REAL_ROOT = ROOT / "data" / "real_sources"
DENIAL_INDEX = REAL_ROOT / "splunk_denial_expansion_v1.json"
DEFAULT_PUBLIC = REAL_ROOT / "provider_oracle_protocol_v6_public.json"
DEFAULT_GOLD = REAL_ROOT / "provider_oracle_protocol_v6_gold.json"
DEFAULT_SPLITS = REAL_ROOT / "provider_oracle_protocol_v6_splits.json"


def _build_catalogue_negative(
    source_case: dict[str, Any],
    source_observations: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v6:" + source_case["case_id"]
    pair = [
        deepcopy(source_observations[observation_id])
        for observation_id in source_case["observation_ids"]
    ]
    denied = next(
        item for item in pair
        if item["pair_role"] == "denied_principal"
    )
    control = next(
        item for item in pair
        if item["pair_role"] == "same_scope_success_control"
    )
    exact_fields = (
        "account_id",
        "region",
        "service",
        "operation",
        "target_resource",
    )
    if any(denied[field] != control[field] for field in exact_fields):
        raise ValueError(f"{case_id} does not have an exact scope control")
    if denied["event_status"] != "AccessDenied":
        raise ValueError(f"{case_id} lacks an explicit AccessDenied")
    if control["event_status"] != "Success":
        raise ValueError(f"{case_id} lacks a successful control")
    if denied["actor_id"] == control["actor_id"]:
        raise ValueError(f"{case_id} control must use a different principal")

    denied_observation = _decorate_runtime(
        denied,
        case_id=case_id,
        provider_decision="deny",
        target_resource=source_case["target_scope"],
        oracle_kind="AWS CloudTrail service outcome",
    )
    control_observation = _decorate_runtime(
        control,
        case_id=case_id,
        provider_decision="allow_control_different_principal",
        target_resource=source_case["target_scope"],
        oracle_kind="AWS CloudTrail same-scope success control",
    )
    observations = [denied_observation, control_observation]
    case = _public_case(
        case_id=case_id,
        source_id=source_case["source_id"],
        platform="AWS",
        description=(
            "At the denied event time, determine whether the observed IAM "
            f"user could perform {source_case['operation']} against the "
            "exact account/region catalogue scope. Do not infer access to "
            "unobserved individual objects."
        ),
        environment=(
            "pinned Splunk Attack Data AWS attack-range CloudTrail with a "
            "same-scope successful control call by a different IAM user"
        ),
        observations=observations,
    )
    deny_id = denied_observation["observation_id"]
    control_id = control_observation["observation_id"]
    gold = {
        "case_id": case_id,
        "independence_group": source_case["independence_group"],
        "source_id": source_case["source_id"],
        "platform": "AWS",
        "gold_state": "NotReachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "time_scope": denied["timestamp"],
        "path": {
            "path_id": source_case["case_id"] + "-path",
            "nodes": [
                {
                    "node_id": "n-user",
                    "type": "identity",
                    "label": "denied IAM user",
                },
                {
                    "node_id": "n-service",
                    "type": "cloud_service",
                    "label": source_case["service"],
                },
                {
                    "node_id": "n-catalogue",
                    "type": source_case["target_type"],
                    "label": source_case["target_scope"],
                },
            ],
            "edges": [
                {
                    "edge_id": "e-invoke",
                    "source": "n-user",
                    "target": "n-service",
                    "type": "invoke",
                },
                {
                    "edge_id": "e-enumerate",
                    "source": "n-service",
                    "target": "n-catalogue",
                    "type": "enumerate",
                },
            ],
        },
        "support_observation_ids": [deny_id],
        "refute_observation_ids": [deny_id],
        "control_observation_ids": [control_id],
        "edge_evidence": {
            "e-invoke": {
                "support": [deny_id],
                "refute": [],
            },
            "e-enumerate": {
                "support": [],
                "refute": [deny_id],
                "controls": [control_id],
            },
        },
        "negative_certificate": {
            "exact_principal": denied["actor_id"],
            "exact_operation": denied["operation"],
            "exact_resource": source_case["target_scope"],
            "provider_native_decision": "AccessDenied",
            "scope_completeness": "complete",
            "target_existence_control": (
                "a different IAM user successfully called the same service "
                "operation in the same account and region"
            ),
            "contrary_success_by_denied_principal_in_same_state": False,
        },
        "semantic_scope": (
            f"NotReachable means only that {denied['actor_id']} could not "
            f"perform {denied['operation']} on "
            f"{source_case['target_scope']} at {denied['timestamp']}. "
            "It does not prove that no named object could be accessed through "
            "another API or later state."
        ),
    }
    return {"case": case, "observations": observations}, gold


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    public, gold, _ = build_v5()
    index = json.loads(DENIAL_INDEX.read_text(encoding="utf-8"))
    source_observations = {
        item["observation_id"]: item
        for item in index["observations"]
    }
    additions = [
        _build_catalogue_negative(case, source_observations)
        for case in index["cases"]
    ]

    public = deepcopy(public)
    public["protocol_version"] = "6.0-pilot"
    public["warning"] = (
        "Protocol-scale pilot only: eleven provider-runtime cases and five "
        "epistemic controls include three negative catalogue operations from "
        "one shared lineage. The effective sample remains too small for "
        "population-level effectiveness claims."
    )
    public["cases"].extend(pair[0]["case"] for pair in additions)
    public["observations"].extend(
        observation
        for pair in additions
        for observation in pair[0]["observations"]
    )
    public["cases"] = sorted(
        public["cases"], key=lambda item: item["candidate_id"]
    )
    public["observations"] = sorted(
        public["observations"],
        key=lambda item: (
            item["candidate_id"],
            item["observation_id"],
        ),
    )

    gold = deepcopy(gold)
    gold["protocol_version"] = "6.0-pilot"
    gold["provider_oracle_gold_cases"] = 11
    gold["epistemic_control_cases"] = 5
    gold["cases"].extend(pair[1] for pair in additions)
    gold["cases"] = sorted(gold["cases"], key=lambda item: item["case_id"])
    if len(gold["cases"]) != 16:
        raise ValueError("protocol v6 must contain exactly 16 cases")

    splits = {
        "protocol_version": "6.0-pilot",
        "frozen": True,
        "statistical_unit": "independence_group",
        "assignments": [
            {
                "case_id": item["case_id"],
                "independence_group": item["independence_group"],
                "split": "protocol_validation",
            }
            for item in gold["cases"]
        ],
    }
    return public, gold, splits


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-output", type=Path, default=DEFAULT_PUBLIC)
    parser.add_argument("--gold-output", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--split-output", type=Path, default=DEFAULT_SPLITS)
    args = parser.parse_args()
    public, gold, splits = build()
    _write(args.public_output, public)
    _write(args.gold_output, gold)
    _write(args.split_output, splits)
    print(json.dumps({
        "protocol_version": public["protocol_version"],
        "public_cases": len(public["cases"]),
        "public_observations": len(public["observations"]),
        "provider_oracle_gold_cases": gold["provider_oracle_gold_cases"],
        "epistemic_control_cases": gold["epistemic_control_cases"],
        "independence_groups": len({
            item["independence_group"] for item in gold["cases"]
        }),
        "negative_independence_groups": len({
            item["independence_group"] for item in gold["cases"]
            if item["gold_state"] == "NotReachable"
        }),
        "research_effectiveness_result": False,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
