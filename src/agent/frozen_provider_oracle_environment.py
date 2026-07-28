"""Leakage-separated environment for provider-oracle protocol v3."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any

from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
)


ALLOWED_GOLD_STATES = {"Reachable", "NotReachable", "Unknown"}
ALLOWED_ORIGINS = {
    "provider_native_runtime",
    "protocol_coverage_control",
}


class FrozenProviderOracleEnvironment:
    """Expose public evidence while retaining state and paths evaluator-side."""

    def __init__(
        self,
        public_packet: dict[str, Any],
        gold_case: dict[str, Any],
        *,
        budget: int | None = None,
    ) -> None:
        case_id = gold_case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("provider-oracle gold requires case_id")
        if gold_case.get("gold_state") not in ALLOWED_GOLD_STATES:
            raise ValueError("provider-oracle gold has invalid state")
        if gold_case.get("label_origin") not in ALLOWED_ORIGINS:
            raise ValueError("provider-oracle gold has invalid origin")
        if (
            gold_case["label_origin"] == "provider_native_runtime"
            and gold_case.get("gold_tier") != "runtime_gold"
        ):
            raise ValueError("provider-native runtime gold must declare its tier")
        if (
            gold_case["label_origin"] == "protocol_coverage_control"
            and (
                gold_case.get("gold_state") != "Unknown"
                or gold_case.get("gold_tier") is not None
            )
        ):
            raise ValueError("coverage controls must be non-gold Unknown cases")

        cases = {
            item["candidate_id"]: item
            for item in public_packet.get("cases", [])
        }
        if case_id not in cases:
            raise KeyError(f"public packet lacks case: {case_id}")
        public_case = deepcopy(cases[case_id])
        observation_ids = set(public_case.get("observation_ids") or [])
        observations = [
            deepcopy(item)
            for item in public_packet.get("observations", [])
            if item.get("candidate_id") == case_id
        ]
        if (
            not observations
            or {item.get("observation_id") for item in observations}
            != observation_ids
        ):
            raise ValueError("provider-oracle public observation index mismatch")
        if any(
            item.get("path_label") is not None
            or item.get("evidence_state") is not None
            for item in observations
        ):
            raise ValueError("agent-visible packet contains hidden labels")

        opaque_id = "oracle-case-" + sha256(
            case_id.encode("utf-8")
        ).hexdigest()[:20]
        public_case["candidate_id"] = opaque_id
        public_case["observation_ids"] = [
            item["observation_id"] for item in observations
        ]
        for item in observations:
            item["candidate_id"] = opaque_id

        self._environment = PublishedTelemetryEnvironment(
            {"cases": [public_case], "observations": observations},
            opaque_id,
            budget,
        )
        self.public_context = {
            "case_handle": opaque_id,
            "platform": public_case.get("platform", gold_case["platform"]),
            "evidence_layers": list(
                public_case.get("evidence_layers") or []
            ),
            "task": public_case["description"],
            "allowed_path_states": [
                "Reachable",
                "NotReachable",
                "Unknown",
            ],
            "unknown_semantics": (
                "Missing, partial, or not-run oracle evidence is Unknown; "
                "absence is never a denial."
            ),
        }
        self._evaluation_metadata = deepcopy(gold_case)
        self._evaluation_metadata["agent_visible_case_handle"] = opaque_id
        self._evaluation_metadata["agent_visible_observation_ids"] = sorted(
            observation_ids
        )

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
        """Return evaluator-only gold after the agent run."""
        return deepcopy(self._evaluation_metadata)
