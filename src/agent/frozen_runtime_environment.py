"""Leakage-resistant environment for human-labeled runtime instances."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any

from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
)
from src.graph.path_ontology import (
    ontology_reference,
    validate_canonical_gold_types,
)


HUMAN_GOLD_ORIGINS = {"human_reviewed", "human_adjudicated"}
HUMAN_GOLD_STATUSES = {"reviewed", "adjudicated"}


class FrozenRuntimeInstanceEnvironment:
    """Expose one frozen telemetry instance while retaining gold evaluator-side."""

    def __init__(
        self,
        gold_case: dict[str, Any],
        instance_id: str,
        budget: int | None = None,
    ) -> None:
        annotation = gold_case.get("annotation") or {}
        if annotation.get("status") not in HUMAN_GOLD_STATUSES:
            raise ValueError("runtime experiment requires reviewed/adjudicated gold")
        if annotation.get("label_origin") not in HUMAN_GOLD_ORIGINS:
            raise ValueError("runtime experiment requires an independent human origin")
        if (
            (gold_case.get("admission_screen") or {}).get("decision")
            != "accept"
        ):
            raise ValueError("runtime experiment accepts only admitted gold cases")
        if gold_case.get("path_ontology") != ontology_reference():
            raise ValueError("runtime experiment path ontology is missing/stale")
        ontology_errors = validate_canonical_gold_types(gold_case)
        if ontology_errors:
            raise ValueError(
                "runtime experiment has noncanonical gold types: "
                + "; ".join(ontology_errors)
            )

        instances = {
            item["instance_id"]: item
            for item in gold_case.get("runtime_instances", [])
        }
        labels = {
            item["instance_id"]: item
            for item in gold_case.get("instance_labels", [])
        }
        if instance_id not in instances:
            raise KeyError(f"unknown runtime instance: {instance_id}")
        if instance_id not in labels:
            raise ValueError(f"runtime instance lacks human gold: {instance_id}")
        instance = instances[instance_id]
        observations = self._instance_observations(gold_case, instance)
        opaque_case_id = "case-" + sha256(
            instance_id.encode("utf-8")
        ).hexdigest()[:20]
        blinded_observations = []
        for observation in observations:
            item = deepcopy(observation)
            item["candidate_id"] = opaque_case_id
            item["path_label"] = None
            item["evidence_state"] = None
            blinded_observations.append(item)

        source = gold_case["source"]
        case = {
            "candidate_id": opaque_case_id,
            "source_id": source["source_id"],
            "upstream_dataset_id": (
                "opaque-" + sha256(
                    (
                        source["source_id"]
                        + ":"
                        + source["version_or_commit"]
                    ).encode("utf-8")
                ).hexdigest()[:16]
            ),
            "author": "withheld during blind evaluation",
            "published_date": "withheld",
            "description": "Blinded, source-pinned cloud telemetry instance.",
            "environment": "controlled cloud telemetry",
            "observation_ids": [
                item["observation_id"] for item in blinded_observations
            ],
            "annotation_status": "human_gold_hidden",
        }
        self._environment = PublishedTelemetryEnvironment(
            {
                "cases": [case],
                "observations": blinded_observations,
            },
            opaque_case_id,
            budget,
        )
        self.public_context = {
            "instance_handle": opaque_case_id,
            "source_kind": source["source_id"],
            "platform": instance.get("platform", "unspecified"),
            "log_profile": instance.get("log_profile", "unspecified"),
            "task": "discover evidence-grounded cloud data attack paths",
        }
        self._evaluation_metadata = {
            "case_id": gold_case["case_id"],
            "instance_id": instance_id,
            "independence_group": (
                gold_case.get("candidate_metadata") or {}
            ).get("independence_group"),
            "source_id": source["source_id"],
            "scenario_source_id": source["source_id"],
            "runtime_evidence_source_id": (
                instance.get("runtime_source_id")
                or source["source_id"]
            ),
            "platform": instance.get("platform", "unspecified"),
            "provenance_level": source["provenance_level"],
            "path_ontology": ontology_reference(),
            "gold_nodes": deepcopy(gold_case["nodes"]),
            "gold_edges": deepcopy(gold_case["edges"]),
            "gold_paths": deepcopy(gold_case["path_labels"]),
            "gold_instance_label": deepcopy(labels[instance_id]),
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
        """Return hidden human gold only to the experiment evaluator."""
        return deepcopy(self._evaluation_metadata)

    @staticmethod
    def _instance_observations(
        gold_case: dict[str, Any],
        instance: dict[str, Any],
    ) -> list[dict[str, Any]]:
        nested = instance.get("observations")
        if isinstance(nested, list):
            observations = deepcopy(nested)
        else:
            observation_ids = set(instance.get("observation_ids") or [])
            observations = [
                deepcopy(item)
                for item in gold_case.get("observations", [])
                if item.get("observation_id") in observation_ids
            ]
            if {
                item.get("observation_id") for item in observations
            } != observation_ids:
                raise ValueError("runtime instance observation index mismatch")
        if len(observations) != instance.get("observation_count"):
            raise ValueError("runtime instance observation count mismatch")
        if not observations:
            raise ValueError("runtime instance has no observations")
        observation_ids = [item.get("observation_id") for item in observations]
        if (
            any(not isinstance(item, str) or not item for item in observation_ids)
            or len(observation_ids) != len(set(observation_ids))
        ):
            raise ValueError("runtime instance has invalid observation IDs")
        return observations
