#!/usr/bin/env python3
"""Create a blind, label-empty human review packet from the path workbench.

The packet contains provider facts and immutable references but no proposed
path state, nodes, edges, or gold label.  Existing two-human annotation tools
can split it into independent assignments without copying labels between
reviewers.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.graph.path_ontology import ontology_reference  # noqa: E402


WORKBENCH_PATH = (
    ROOT
    / "data"
    / "real_sources"
    / "provider_path_candidate_workbench_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "provider_semantic_review_round1_unlabeled.json"
)


def _raw_ref_text(raw_ref: dict[str, Any]) -> str:
    return (
        f"{raw_ref['archive_relative_path']}::"
        f"{raw_ref['member']}#{raw_ref['json_pointer']}"
    )


def build() -> dict[str, Any]:
    workbench = json.loads(
        WORKBENCH_PATH.read_text(encoding="utf-8")
    )
    cases = []
    for candidate in workbench["candidates"]:
        representative = candidate["representative"]
        support_events = representative["support_events"]
        raw_artifacts = []
        seen_artifacts = set()
        observations = []
        for ordinal, event in enumerate(support_events, start=1):
            raw_ref = event["raw_ref"]
            artifact_key = (
                _raw_ref_text(raw_ref),
                raw_ref["member_sha256"],
            )
            if artifact_key not in seen_artifacts:
                seen_artifacts.add(artifact_key)
                raw_artifacts.append({
                    "raw_ref": artifact_key[0],
                    "sha256": artifact_key[1],
                })
            observations.append({
                "observation_id": (
                    f"{candidate['candidate_id']}:evidence-{ordinal}"
                ),
                "timestamp": event["timestamp"],
                "operation": event["operation"],
                "actor_id": event["identity"],
                "target_resource": event["exact_resource"],
                "target_root": event["target_root"],
                "event_status": "Success",
                "provider_outcome": event["provider_outcome"],
                "raw_ref": deepcopy(raw_ref),
                "path_label": None,
                "evidence_state": None,
            })
        instance_id = candidate["candidate_id"] + ":representative"
        cases.append({
            "case_id": candidate["candidate_id"],
            "source": {
                "source_id": "cross_cloud_observability_2026",
                "upstream_url": (
                    "https://zenodo.org/records/19933893"
                ),
                "version_or_commit": "record-19933893-v2",
                "license": "CC-BY-4.0",
                "provenance_level": "B",
                "raw_artifacts": raw_artifacts,
            },
            "description": (
                "Audit whether the exact provider-success observations form "
                "an admissible cloud-data reachability path. The upstream "
                "attack name and payload condition are not labels."
            ),
            "candidate_metadata": {
                "independence_group": candidate["lineage_group"],
                "platform": candidate["provider"],
                "path_shape_candidate": candidate["path_shape"],
                "scenario_variants": candidate["scenario_variants"],
                "replicate_member_count": candidate[
                    "replicate_member_count"
                ],
                "audit_priority": candidate["audit_priority"],
                "candidate_is_gold": False,
            },
            "oracle_precheck": deepcopy(candidate["oracle_precheck"]),
            "review_questions": deepcopy(candidate["review_questions"]),
            "runtime_instances": [
                {
                    "instance_id": instance_id,
                    "platform": candidate["provider"],
                    "source_schema": (
                        "aws_cloudtrail"
                        if candidate["provider"] == "AWS"
                        else "gcp_audit_log"
                    ),
                    "observation_count": len(observations),
                    "operation_counts": dict(sorted(Counter(
                        item["operation"] for item in observations
                    ).items())),
                    "actor_id": representative["identity"],
                    "principal_class": representative[
                        "principal_class"
                    ],
                    "target_root": representative["target_root"],
                    "observations": observations,
                }
            ],
            "annotation": {
                "status": "pending",
                "label_origin": None,
                "primary_annotator": None,
                "reviewer": None,
                "adjudication": None,
            },
            "path_ontology": ontology_reference(),
            "admission_screen": {
                "external_or_low_privilege_entry_defined": None,
                "multi_step_path_present": None,
                "cloud_data_target_present": None,
                "critical_edges_have_raw_evidence": None,
                "not_a_near_duplicate": None,
                "decision": None,
                "rationale": None,
            },
            "nodes": [],
            "edges": [],
            "path_labels": [],
            "tool_tasks": [],
            "instance_labels": [],
        })

    return {
        "packet_version": "provider-semantic-review-1.0",
        "packet_kind": "provider_runtime_semantic_review_unlabeled",
        "protocol_status": "awaiting_two_independent_humans",
        "schema_ref": (
            "data/real_sources/realpathbench_v2_schema.json"
        ),
        "policy": {
            "generated_cloud_events": 0,
            "generated_human_labels": 0,
            "provider_outcomes_are_facts_not_human_labels": True,
            "path_semantics_are_label_empty": True,
            "two_independent_humans_required": True,
            "third_human_adjudication_for_disputes": True,
            "lineage_group_is_the_statistical_unit": True,
        },
        "source_workbench": {
            "path": str(WORKBENCH_PATH.relative_to(ROOT)).replace(
                "\\", "/"
            ),
            "workbench_version": workbench["workbench_version"],
        },
        "summary": {
            "case_count": len(cases),
            "independence_group_count": len({
                item["candidate_metadata"]["independence_group"]
                for item in cases
            }),
            "platform_counts": dict(sorted(Counter(
                item["candidate_metadata"]["platform"]
                for item in cases
            ).items())),
            "human_gold_cases": 0,
        },
        "cases": sorted(cases, key=lambda item: item["case_id"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    packet = build()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(packet["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
