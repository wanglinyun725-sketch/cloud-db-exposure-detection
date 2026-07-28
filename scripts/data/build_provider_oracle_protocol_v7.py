#!/usr/bin/env python3
"""Build provider-oracle protocol v7 with a second denial lineage.

V7 preserves v6 and adds five exact operation-scoped denials from a separate
Splunk Attack Data discovery-sweep artifact.  The five cases share one
independence group.  They contain provider-recorded AccessDenied outcomes but
no same-scope success control, which is disclosed in each certificate.
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
from scripts.data.build_provider_oracle_protocol_v6 import (  # noqa: E402
    build as build_v6,
)


REAL_ROOT = ROOT / "data" / "real_sources"
DENIAL_INDEX = REAL_ROOT / "splunk_accessdenied_discovery_v1.json"
DEFAULT_PUBLIC = REAL_ROOT / "provider_oracle_protocol_v7_public.json"
DEFAULT_GOLD = REAL_ROOT / "provider_oracle_protocol_v7_gold.json"
DEFAULT_SPLITS = REAL_ROOT / "provider_oracle_protocol_v7_splits.json"
HELD_OUT_SOURCES = {
    "splunk_attack_data",
    "splunk_attack_data_2026_expansion",
    "stratus_red_team",
    "azuregoat",
    "gcpgoat",
}


def _build_discovery_negative(
    source_case: dict[str, Any],
    source_observations: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = "oracle-v7:" + source_case["case_id"]
    if len(source_case["observation_ids"]) != 1:
        raise ValueError(f"{case_id} must contain exactly one denial")
    raw_denial = deepcopy(
        source_observations[source_case["observation_ids"][0]]
    )
    if raw_denial["event_status"] != "AccessDenied":
        raise ValueError(f"{case_id} lacks an explicit AccessDenied")
    denial = _decorate_runtime(
        raw_denial,
        case_id=case_id,
        provider_decision="deny",
        target_resource=source_case["target_scope"],
        oracle_kind="AWS CloudTrail service outcome",
    )
    public_case = _public_case(
        case_id=case_id,
        source_id=source_case["source_id"],
        platform="AWS",
        description=(
            "At the recorded event time, determine whether the observed IAM "
            f"user could perform {source_case['operation']} against the exact "
            "account and region catalogue scope. Do not infer access to "
            "unobserved individual data objects."
        ),
        environment=(
            "pinned Splunk Attack Data AWS attack-range CloudTrail "
            "discovery-sweep artifact; no same-scope success control is "
            "available in this artifact"
        ),
        observations=[denial],
    )
    denial_id = denial["observation_id"]
    gold = {
        "case_id": case_id,
        "independence_group": source_case["independence_group"],
        "source_id": source_case["source_id"],
        "platform": "AWS",
        "gold_state": "NotReachable",
        "gold_tier": "runtime_gold",
        "label_origin": "provider_native_runtime",
        "provider_oracle_contract": "provider_oracle_gold_v1",
        "time_scope": denial["timestamp"],
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
        "support_observation_ids": [denial_id],
        "refute_observation_ids": [denial_id],
        "control_observation_ids": [],
        "edge_evidence": {
            "e-invoke": {
                "support": [denial_id],
                "refute": [],
            },
            "e-enumerate": {
                "support": [],
                "refute": [denial_id],
                "controls": [],
            },
        },
        "negative_certificate": {
            "exact_principal": denial["actor_id"],
            "exact_operation": denial["operation"],
            "exact_resource": source_case["target_scope"],
            "provider_native_decision": "AccessDenied",
            "scope_completeness": "complete_for_exact_catalogue_operation",
            "target_existence_control": "not_available",
            "contrary_success_by_denied_principal_in_same_state": False,
        },
        "semantic_scope": (
            f"NotReachable means only that {denial['actor_id']} could not "
            f"perform {denial['operation']} on "
            f"{source_case['target_scope']} at {denial['timestamp']}. "
            "The catalogue endpoint is the target of this verdict; the event "
            "does not prove that every named object was inaccessible through "
            "another API or later state."
        ),
    }
    return {"case": public_case, "observations": [denial]}, gold


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    public, gold, _ = build_v6()
    index = json.loads(DENIAL_INDEX.read_text(encoding="utf-8"))
    source_observations = {
        item["observation_id"]: item
        for item in index["observations"]
    }
    additions = [
        _build_discovery_negative(case, source_observations)
        for case in index["cases"]
    ]

    public = deepcopy(public)
    public["protocol_version"] = "7.0-pilot"
    public["warning"] = (
        "Protocol-scale pilot only: sixteen provider-runtime cases and five "
        "epistemic controls include ten negative operation cases across four "
        "independent lineages. The effective sample remains too small for "
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
    gold["protocol_version"] = "7.0-pilot"
    gold["provider_oracle_gold_cases"] = 16
    gold["epistemic_control_cases"] = 5
    gold["cases"].extend(pair[1] for pair in additions)
    gold["cases"] = sorted(gold["cases"], key=lambda item: item["case_id"])
    if len(gold["cases"]) != 21:
        raise ValueError("protocol v7 must contain exactly 21 cases")

    splits = {
        "protocol_version": "7.0-pilot",
        "frozen": True,
        "statistical_unit": "independence_group",
        "split_strategy": "source_held_out",
        "warning": (
            "Pilot split only. Every source is assigned wholly to one split, "
            "but the held-out set is underpowered and is not the thesis main "
            "test."
        ),
        "held_out_sources": sorted(HELD_OUT_SOURCES),
        "assignments": [
            {
                "case_id": item["case_id"],
                "independence_group": item["independence_group"],
                "source_id": item["source_id"],
                "split": (
                    "source_held_out_test"
                    if item["source_id"] in HELD_OUT_SOURCES
                    else "development"
                ),
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
