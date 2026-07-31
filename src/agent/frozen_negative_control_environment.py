"""Frozen Tool-Use environment for human-confirmed reliability controls."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from src.agent.incident_report_environment import (
    IncidentReportToolEnvironment,
)
from src.graph.path_ontology import ontology_reference


class FrozenNegativeControlEnvironment:
    """Expose a reviewed non-attack report with gold kept evaluator-side."""

    def __init__(
        self,
        gold_case: dict[str, Any],
        instance_id: str,
        budget: int | None = None,
    ) -> None:
        if gold_case.get("case_kind") != "external_negative_control":
            raise ValueError("not an external negative-control case")
        screening = gold_case.get("screening") or {}
        if screening.get("status") not in {"reviewed", "adjudicated"}:
            raise ValueError("negative control requires reviewed human screening")
        if screening.get("label_origin") not in {
            "human_reviewed",
            "human_adjudicated",
        }:
            raise ValueError("negative control lacks independent human origin")
        if not all(
            screening.get(field) is True
            for field in (
                "cloud_data_relevant",
                "non_attack_confirmed",
                "usable_as_negative_control",
            )
        ):
            raise ValueError("case is not an admitted negative control")
        instances = {
            item["instance_id"]: item
            for item in gold_case.get("runtime_instances", [])
        }
        if instance_id not in instances:
            raise KeyError(f"unknown negative runtime instance: {instance_id}")
        self._environment = IncidentReportToolEnvironment(gold_case, budget)
        self.public_context = {
            **self._environment.public_context,
            "task": "discover evidence-grounded cloud data attack paths",
        }
        raw_ref = gold_case["raw_ref"]
        self._evaluation_metadata = {
            "case_id": gold_case["case_id"],
            "instance_id": instance_id,
            "independence_group": gold_case["independence_group"],
            "source_id": gold_case["source"]["source_id"],
            "scenario_source_id": gold_case["source"]["source_id"],
            "runtime_evidence_source_id": gold_case["source"]["source_id"],
            "platform": instances[instance_id].get(
                "platform", "unspecified"
            ),
            "provenance_level": "B",
            "path_ontology": ontology_reference(),
            "gold_nodes": [],
            "gold_edges": [],
            "gold_paths": [],
            "gold_instance_label": {
                "instance_id": instance_id,
                "overall_state": "Invalid",
                "path_states": [],
                "evidence_raw_refs": [
                    (
                        f"{raw_ref['member_path']}#record="
                        f"{raw_ref['record_index']}"
                    )
                ],
                "annotator_rationale": screening["final_rationale"],
            },
            "negative_control": True,
        }

    @property
    def spent(self) -> int:
        return self._environment.spent

    @property
    def remaining_budget(self) -> int | None:
        return self._environment.remaining_budget

    @property
    def trace(self):
        return self._environment.trace

    def action_schema(self) -> dict[str, Any]:
        return self._environment.action_schema()

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._environment.execute(tool_name, arguments)

    def export_trace(self) -> list[dict[str, Any]]:
        return self._environment.export_trace()

    def evaluation_metadata(self) -> dict[str, Any]:
        return deepcopy(self._evaluation_metadata)
