"""Blind Tool-Use environment for pending, unlabeled runtime instances.

This environment exists only for engineering and data-contract audits.  It
cannot expose evaluator gold and it must never be used to report research
effectiveness.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any

from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
)


class UnlabeledRuntimeInstanceEnvironment:
    """Expose one real telemetry instance without admitting any gold label."""

    def __init__(
        self,
        pending_case: dict[str, Any],
        instance_id: str,
        budget: int | None = None,
    ) -> None:
        annotation = pending_case.get("annotation") or {}
        if annotation.get("status") != "pending":
            raise ValueError("unlabeled audit requires a pending case")
        if annotation.get("label_origin") is not None:
            raise ValueError("unlabeled audit forbids a label origin")
        for field in ("nodes", "edges", "path_labels", "instance_labels"):
            if pending_case.get(field):
                raise ValueError(
                    f"unlabeled audit forbids non-empty {field}"
                )

        instances = {
            item["instance_id"]: item
            for item in pending_case.get("runtime_instances", [])
        }
        if instance_id not in instances:
            raise KeyError(f"unknown runtime instance: {instance_id}")
        instance = instances[instance_id]
        observations = self._instance_observations(pending_case, instance)

        opaque_case_id = "case-" + sha256(
            instance_id.encode("utf-8")
        ).hexdigest()[:20]
        blinded_observations = []
        for observation in observations:
            item = deepcopy(observation)
            if item.get("path_label") is not None:
                raise ValueError("unlabeled observation contains path_label")
            if item.get("evidence_state") is not None:
                raise ValueError(
                    "unlabeled observation contains evidence_state"
                )
            item["candidate_id"] = opaque_case_id
            item["path_label"] = None
            item["evidence_state"] = None
            blinded_observations.append(item)

        source = pending_case["source"]
        runtime_source_id = (
            instance.get("runtime_source_id") or source["source_id"]
        )
        case = {
            "candidate_id": opaque_case_id,
            "source_id": source["source_id"],
            "upstream_dataset_id": (
                "opaque-"
                + sha256(
                    (
                        runtime_source_id
                        + ":"
                        + source["version_or_commit"]
                    ).encode("utf-8")
                ).hexdigest()[:16]
            ),
            "author": "withheld during blind contract audit",
            "published_date": "withheld",
            "description": "Blinded, source-pinned cloud telemetry instance.",
            "environment": "controlled cloud telemetry",
            "observation_ids": [
                item["observation_id"] for item in blinded_observations
            ],
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
        schemas = sorted({
            item.get("schema") or "unspecified"
            for item in observations
        })
        self._audit_metadata = {
            "case_id": pending_case["case_id"],
            "candidate_id": (
                pending_case.get("candidate_metadata") or {}
            ).get("candidate_id"),
            "instance_id": instance_id,
            "independence_group": (
                pending_case.get("candidate_metadata") or {}
            ).get("independence_group"),
            "scenario_source_id": source["source_id"],
            "runtime_evidence_source_id": runtime_source_id,
            "platform": instance.get("platform", "unspecified"),
            "environment_kind": instance.get(
                "environment_kind", "unspecified"
            ),
            "log_profile": instance.get("log_profile", "unspecified"),
            "observation_count": len(observations),
            "schemas": schemas,
            "has_request_or_response_payload": any(
                item.get("request") is not None
                or item.get("response") is not None
                for item in observations
            ),
        }
        self._observations = observations

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

    def audit_metadata(self) -> dict[str, Any]:
        """Return lineage and shape metadata, never an evaluator label."""
        return deepcopy(self._audit_metadata)

    def audit_observations(self) -> list[dict[str, Any]]:
        """Return source observations only to the deterministic audit."""
        return deepcopy(self._observations)

    @staticmethod
    def _instance_observations(
        pending_case: dict[str, Any],
        instance: dict[str, Any],
    ) -> list[dict[str, Any]]:
        nested = instance.get("observations")
        if isinstance(nested, list):
            observations = deepcopy(nested)
        else:
            observation_ids = set(instance.get("observation_ids") or [])
            observations = [
                deepcopy(item)
                for item in pending_case.get("observations", [])
                if item.get("observation_id") in observation_ids
            ]
            if {
                item.get("observation_id") for item in observations
            } != observation_ids:
                raise ValueError("runtime instance observation index mismatch")
        if len(observations) != instance.get("observation_count"):
            raise ValueError("runtime instance observation count mismatch")
        observation_ids = [item.get("observation_id") for item in observations]
        if (
            any(not isinstance(item, str) or not item for item in observation_ids)
            or len(observation_ids) != len(set(observation_ids))
        ):
            raise ValueError("runtime instance has invalid observation IDs")
        return observations
