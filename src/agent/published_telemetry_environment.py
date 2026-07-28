"""Case-scoped Tool-Use environment over pinned, published cloud telemetry.

This module never creates attack paths or evidence labels.  It only exposes
normalized observations from ``pilot_observation_index.json`` through
budgeted, auditable tools.  In particular, ``path_label`` and
``evidence_state`` are never returned to the policy.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from math import ceil
from pathlib import Path
from typing import Any


PUBLIC_CASE_FIELDS = {
    "candidate_id",
    "source_id",
    "upstream_dataset_id",
    "author",
    "published_date",
    "description",
    "environment",
    "mitre_techniques",
}

COMPACT_EVENT_FIELDS = (
    "observation_id",
    "timestamp",
    "evidence_layer",
    "service",
    "operation",
    "actor_type",
    "actor_id",
    "account_id",
    "region",
    "event_status",
    "provider_decision",
    "target_resource",
)

DETAIL_EVENT_FIELDS = COMPACT_EVENT_FIELDS + (
    "schema",
    "oracle_kind",
    "scope_completeness",
    "source_ip",
    "request",
    "response",
    "raw_ref",
)

SEARCH_FILTERS = {
    "service",
    "operation",
    "actor_id",
    "account_id",
    "region",
    "event_status",
    "timestamp_from",
    "timestamp_to",
}


class ToolActionError(ValueError):
    """The requested action violates the deterministic tool contract."""


class ToolBudgetError(RuntimeError):
    """The action is valid but cannot run within the remaining budget."""


@dataclass(frozen=True)
class ToolReceipt:
    call_id: int
    tool_name: str
    arguments: dict[str, Any]
    cost: int
    cumulative_cost: int
    result_count: int
    raw_refs: list[dict[str, Any]]


class PublishedTelemetryEnvironment:
    """A read-only, case-scoped environment for ReAct/Tool-Use experiments."""

    tool_contracts = {
        "summarize_case": {
            "arguments": set(),
            "description": "Return public case metadata and telemetry facets.",
        },
        "search_events": {
            "arguments": SEARCH_FILTERS,
            "description": "Filter case events and return compact observations.",
        },
        "get_event_detail": {
            "arguments": {"observation_id"},
            "description": "Return one normalized event with its raw provenance.",
        },
        "actor_timeline": {
            "arguments": {"actor_id"},
            "description": "Return the ordered activity of one exact actor.",
        },
        "resource_search": {
            "arguments": {"term"},
            "description": "Search request/response payloads for a resource token.",
        },
    }

    def __init__(
        self,
        index: dict[str, Any],
        candidate_id: str,
        budget: int | None = None,
    ) -> None:
        if budget is not None and budget < 0:
            raise ValueError("budget must be non-negative or None")

        cases = {
            case["candidate_id"]: deepcopy(case)
            for case in index.get("cases", [])
        }
        if candidate_id not in cases:
            raise KeyError(f"unknown candidate_id: {candidate_id}")

        self.candidate_id = candidate_id
        self.budget = budget
        self.spent = 0
        self.trace: list[ToolReceipt] = []
        self._case = cases[candidate_id]
        self._events = [
            deepcopy(item)
            for item in index.get("observations", [])
            if item.get("candidate_id") == candidate_id
        ]
        self._event_by_id = {
            item["observation_id"]: item
            for item in self._events
        }
        expected_ids = set(self._case.get("observation_ids", []))
        if expected_ids != set(self._event_by_id):
            raise ValueError(
                f"case observation index mismatch for {candidate_id}"
            )
        for item in self._events:
            if item.get("path_label") is not None:
                raise ValueError("published telemetry index must not contain path labels")
            if item.get("evidence_state") is not None:
                raise ValueError("published telemetry index must not contain evidence labels")

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        candidate_id: str,
        budget: int | None = None,
    ) -> "PublishedTelemetryEnvironment":
        index = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(index, candidate_id, budget)

    @property
    def remaining_budget(self) -> int | None:
        if self.budget is None:
            return None
        return self.budget - self.spent

    def action_schema(self) -> dict[str, Any]:
        """Return the action space without revealing any case observation."""
        return {
            name: {
                "arguments": sorted(contract["arguments"]),
                "description": contract["description"],
            }
            for name, contract in self.tool_contracts.items()
        }

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Validate, execute and record one tool action."""
        arguments = dict(arguments or {})
        self._guard_action(tool_name, arguments)

        if tool_name == "summarize_case":
            result = self._summarize_case()
        elif tool_name == "search_events":
            result = self._search_events(arguments)
        elif tool_name == "get_event_detail":
            result = self._get_event_detail(arguments["observation_id"])
        elif tool_name == "actor_timeline":
            result = self._actor_timeline(arguments["actor_id"])
        elif tool_name == "resource_search":
            result = self._resource_search(arguments["term"])
        else:  # pragma: no cover - _guard_action handles this.
            raise ToolActionError(f"unknown tool: {tool_name}")

        rows = result.get("events", [])
        result_count = len(rows) if isinstance(rows, list) else 0
        cost = self._cost(tool_name, result_count)
        if self.budget is not None and self.spent + cost > self.budget:
            raise ToolBudgetError(
                f"tool action exceeds remaining budget ({self.remaining_budget})"
            )

        self.spent += cost
        raw_refs = self._unique_raw_refs(rows)
        receipt = ToolReceipt(
            call_id=len(self.trace) + 1,
            tool_name=tool_name,
            arguments=deepcopy(arguments),
            cost=cost,
            cumulative_cost=self.spent,
            result_count=result_count,
            raw_refs=raw_refs,
        )
        self.trace.append(receipt)
        return {
            "tool_result": result,
            "receipt": asdict(receipt),
            "remaining_budget": self.remaining_budget,
        }

    def export_trace(self) -> list[dict[str, Any]]:
        return [asdict(receipt) for receipt in self.trace]

    def _guard_action(self, tool_name: str, arguments: dict[str, Any]) -> None:
        if tool_name not in self.tool_contracts:
            raise ToolActionError(f"unknown tool: {tool_name}")
        if not isinstance(arguments, dict):
            raise ToolActionError("arguments must be an object")

        allowed = self.tool_contracts[tool_name]["arguments"]
        unknown = set(arguments) - allowed
        if unknown:
            raise ToolActionError(
                f"unsupported arguments for {tool_name}: {sorted(unknown)}"
            )

        required = {
            "get_event_detail": {"observation_id"},
            "actor_timeline": {"actor_id"},
            "resource_search": {"term"},
        }.get(tool_name, set())
        missing = required - set(arguments)
        if missing:
            raise ToolActionError(
                f"missing arguments for {tool_name}: {sorted(missing)}"
            )

        for name, value in arguments.items():
            if name in {"timestamp_from", "timestamp_to"}:
                if not isinstance(value, (int, float)):
                    raise ToolActionError(f"{name} must be a numeric timestamp")
            elif not isinstance(value, str) or not value.strip():
                raise ToolActionError(f"{name} must be a non-empty string")

    def _summarize_case(self) -> dict[str, Any]:
        metadata = {
            field: deepcopy(self._case[field])
            for field in PUBLIC_CASE_FIELDS
            if field in self._case
        }
        operation_counts: dict[str, int] = {}
        service_counts: dict[str, int] = {}
        for event in self._events:
            operation = event.get("operation") or "unknown"
            service = event.get("service") or "unknown"
            operation_counts[operation] = operation_counts.get(operation, 0) + 1
            service_counts[service] = service_counts.get(service, 0) + 1
        return {
            "case": metadata,
            "observation_count": len(self._events),
            "operation_counts": operation_counts,
            "service_counts": service_counts,
            "events": [],
        }

    def _search_events(self, arguments: dict[str, Any]) -> dict[str, Any]:
        events = self._events
        for field in SEARCH_FILTERS - {"timestamp_from", "timestamp_to"}:
            if field in arguments:
                needle = arguments[field].casefold()
                events = [
                    item
                    for item in events
                    if str(item.get(field, "")).casefold() == needle
                ]
        if "timestamp_from" in arguments:
            events = [
                item for item in events
                if self._timestamp_millis(item.get("timestamp")) is not None
                and self._timestamp_millis(item.get("timestamp"))
                >= self._timestamp_millis(arguments["timestamp_from"])
            ]
        if "timestamp_to" in arguments:
            events = [
                item for item in events
                if self._timestamp_millis(item.get("timestamp")) is not None
                and self._timestamp_millis(item.get("timestamp"))
                <= self._timestamp_millis(arguments["timestamp_to"])
            ]
        return {
            "filters": deepcopy(arguments),
            "events": [
                self._project(item, COMPACT_EVENT_FIELDS, include_raw_ref=True)
                for item in self._sort_events(events)
            ],
            "empty_result_semantics": "Unknown; absence is not contradiction.",
        }

    def _get_event_detail(self, observation_id: str) -> dict[str, Any]:
        if observation_id not in self._event_by_id:
            raise ToolActionError(
                "observation_id is not present in the current case"
            )
        event = self._project(
            self._event_by_id[observation_id],
            DETAIL_EVENT_FIELDS,
            include_raw_ref=False,
        )
        return {"events": [event]}

    def _actor_timeline(self, actor_id: str) -> dict[str, Any]:
        events = [
            item for item in self._events
            if str(item.get("actor_id", "")).casefold() == actor_id.casefold()
        ]
        return {
            "actor_id": actor_id,
            "events": [
                self._project(item, COMPACT_EVENT_FIELDS, include_raw_ref=True)
                for item in self._sort_events(events)
            ],
            "empty_result_semantics": "Unknown; absence is not contradiction.",
        }

    def _resource_search(self, term: str) -> dict[str, Any]:
        needle = term.casefold()
        matches = []
        for item in self._events:
            matched_fields = [
                field
                for field in ("request", "response")
                if needle in str(item.get(field, "")).casefold()
            ]
            if matched_fields:
                event = self._project(
                    item,
                    COMPACT_EVENT_FIELDS,
                    include_raw_ref=True,
                )
                event["matched_fields"] = matched_fields
                matches.append(event)
        return {
            "term": term,
            "events": self._sort_events(matches),
            "empty_result_semantics": "Unknown; absence is not contradiction.",
        }

    @staticmethod
    def _cost(tool_name: str, result_count: int) -> int:
        base = {
            "summarize_case": 1,
            "search_events": 1,
            "get_event_detail": 2,
            "actor_timeline": 2,
            "resource_search": 2,
        }[tool_name]
        if tool_name in {"search_events", "actor_timeline", "resource_search"}:
            return base + ceil(result_count / 5)
        return base

    @staticmethod
    def _project(
        item: dict[str, Any],
        fields: tuple[str, ...],
        *,
        include_raw_ref: bool,
    ) -> dict[str, Any]:
        projected = {
            field: deepcopy(item.get(field))
            for field in fields
            if field in item
        }
        if include_raw_ref:
            projected["raw_ref"] = deepcopy(item["raw_ref"])
        return projected

    @staticmethod
    def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            events,
            key=lambda item: (
                PublishedTelemetryEnvironment._timestamp_millis(
                    item.get("timestamp")
                ) is None,
                PublishedTelemetryEnvironment._timestamp_millis(
                    item.get("timestamp")
                ) or 0,
                item.get("observation_id", ""),
            ),
        )

    @staticmethod
    def _timestamp_millis(value: Any) -> float | None:
        """Normalize numeric/ISO timestamps for comparison, preserving source data."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            numeric = float(value)
            return numeric * 1000 if abs(numeric) < 100_000_000_000 else numeric
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                numeric = float(text)
                return numeric * 1000 if abs(numeric) < 100_000_000_000 else numeric
            except ValueError:
                pass
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.timestamp() * 1000
            except ValueError:
                return None
        return None

    @staticmethod
    def _unique_raw_refs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for event in events:
            raw_ref = event.get("raw_ref")
            if not isinstance(raw_ref, dict):
                continue
            key = (
                raw_ref.get("sha256"),
                raw_ref.get("record_index"),
                raw_ref.get("upstream_path"),
            )
            if key not in seen:
                seen.add(key)
                refs.append(deepcopy(raw_ref))
        return refs
