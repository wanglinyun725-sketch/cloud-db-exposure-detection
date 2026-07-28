"""Non-LLM baseline policies using the same tools and path output contract."""
from __future__ import annotations

import random
import re
from typing import Any


class FixedOrderPathPolicy:
    """Query operations in a fixed lexical order and emit observable paths."""

    def __init__(self, max_path_candidates: int = 5) -> None:
        self.max_path_candidates = max_path_candidates

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        executed = _executed(view)
        if not executed:
            return _tool("summarize_case", {}, "Reveal telemetry facets.")
        pending_event = _pending_event(executed, view)
        if pending_event is not None:
            return _submit_event_path(view, pending_event)
        operations = _operation_counts(executed)
        searched = {
            item["proposal"].get("arguments", {}).get("operation")
            for item in view["history"]
            if item["status"] == "tool_executed"
            and item["proposal"].get("tool_name") == "search_events"
        }
        remaining = sorted(set(operations) - searched)
        if (
            remaining
            and view["submitted_path_candidates"]
            < self.max_path_candidates
        ):
            return _tool(
                "search_events",
                {"operation": remaining[0]},
                "Run the next fixed-order operation query.",
            )
        return _finish("Fixed-order search is complete.")


class RandomToolPathPolicy(FixedOrderPathPolicy):
    """Seeded random-operation baseline with identical output schema."""

    def __init__(
        self,
        seed: int,
        max_path_candidates: int = 5,
    ) -> None:
        super().__init__(max_path_candidates)
        self.seed = seed

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        executed = _executed(view)
        if not executed:
            return _tool("summarize_case", {}, "Reveal telemetry facets.")
        pending_event = _pending_event(executed, view)
        if pending_event is not None:
            return _submit_event_path(view, pending_event)
        operations = _operation_counts(executed)
        searched = {
            item["proposal"].get("arguments", {}).get("operation")
            for item in view["history"]
            if item["status"] == "tool_executed"
            and item["proposal"].get("tool_name") == "search_events"
        }
        remaining = sorted(set(operations) - searched)
        if (
            remaining
            and view["submitted_path_candidates"]
            < self.max_path_candidates
        ):
            # Recompute from immutable state so backend scheduling cannot alter
            # the seeded choice.
            chooser = random.Random(
                f"{self.seed}:{','.join(sorted(searched - {None}))}"
            )
            operation = chooser.choice(remaining)
            return _tool(
                "search_events",
                {"operation": operation},
                "Run a seeded random operation query.",
            )
        return _finish("Seeded random search is complete.")


class FullQueryPathPolicy:
    """Retrieve the whole case once, then emit paths from rendered rows only."""

    def __init__(self, max_path_candidates: int = 5) -> None:
        self.max_path_candidates = max_path_candidates

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        executed = _executed(view)
        full_query = next(
            (
                item for item in executed
                if item["proposal"].get("tool_name") == "search_events"
                and item["proposal"].get("arguments") == {}
            ),
            None,
        )
        if full_query is None:
            return _tool(
                "search_events",
                {},
                "Retrieve the full case under the shared hard budget.",
            )
        events = full_query["observation"].get("events") or []
        index = view["submitted_path_candidates"]
        if index < min(len(events), self.max_path_candidates):
            return _submit_event_path(view, events[index])
        return _finish("Full-query baseline candidate set is complete.")


class ProviderAwarePathPolicy:
    """Deterministic EC-ReAct control that preserves allow/deny/Unknown.

    This is a transparent protocol-validation policy, not a learned model. It
    uses the same public tools and proposal schema as the LLM methods.
    """

    DATA_OPERATIONS = {
        "CopyObject",
        "DescribeClusters",
        "DescribeDBInstances",
        "DescribeParameters",
        "GetObject",
        "GetSecretValue",
        "ListBuckets",
        "ListDomainNames",
        "ListObjects",
        "ListSecrets",
        "ListTables",
        "ModifySnapshotAttribute",
        "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        "storage.objects.get",
        "storage.objects.list",
    }
    DENIAL_STATUSES = {
        "Code:7",
        "Code:16",
        "AccessDenied",
        "Client.InvalidAMIAttributeItemValue",
        "Denied",
        "KMS.KMSInvalidStateException",
    }

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        executed = _executed(view)
        full_query = next(
            (
                item for item in executed
                if item["proposal"].get("tool_name") == "search_events"
                and item["proposal"].get("arguments") == {}
            ),
            None,
        )
        if full_query is None:
            return _tool(
                "search_events",
                {},
                "Inspect the complete frozen evidence episode once.",
            )
        if view["submitted_path_candidates"]:
            return _finish("The decisive provider-state edge was submitted.")
        events = full_query["observation"].get("events") or []
        denial = next(
            (
                event for event in events
                if event.get("event_status") in self.DENIAL_STATUSES
                and event.get("operation") in self.DATA_OPERATIONS
            ),
            None,
        )
        if denial is not None:
            return _submit_state_path(
                view,
                denial,
                claimed_state="NotReachable",
                polarity="refute",
            )
        successful = next(
            (
                event for event in reversed(events)
                if event.get("operation") in self.DATA_OPERATIONS
                and event.get("event_status")
                in {"Success", "SuccessOrUnspecified"}
            ),
            None,
        )
        if successful is not None:
            return _submit_state_path(
                view,
                successful,
                claimed_state="Reachable",
                polarity="support",
            )
        return {
            "kind": "finish",
            "thought": (
                "No complete-scope runtime allow or explicit denial is "
                "visible, so absence cannot resolve the path."
            ),
            "decision": "no_verified_path",
            "hypothesis": "The runtime path state remains Unknown.",
        }


def _executed(view: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item for item in view["history"]
        if item["status"] == "tool_executed"
    ]


def _operation_counts(executed: list[dict[str, Any]]) -> dict[str, int]:
    for item in executed:
        counts = item["observation"].get("operation_counts")
        if isinstance(counts, dict):
            return counts
    return {}


def _pending_event(
    executed: list[dict[str, Any]],
    view: dict[str, Any],
) -> dict[str, Any] | None:
    searched = [
        item for item in executed
        if item["proposal"].get("tool_name") == "search_events"
        and (item["observation"].get("events") or [])
    ]
    if len(searched) <= view["submitted_path_candidates"]:
        return None
    events = searched[-1]["observation"].get("events") or []
    return events[0] if events else None


def _tool(
    tool_name: str,
    arguments: dict[str, Any],
    thought: str,
) -> dict[str, Any]:
    return {
        "kind": "tool",
        "thought": thought,
        "tool_name": tool_name,
        "arguments": arguments,
    }


def _finish(hypothesis: str) -> dict[str, Any]:
    return {
        "kind": "finish",
        "thought": "Stop under the shared output contract.",
        "decision": "search_complete",
        "hypothesis": hypothesis,
    }


def _submit_event_path(
    view: dict[str, Any],
    event: dict[str, Any],
) -> dict[str, Any]:
    observation_id = event["observation_id"]
    citations = [
        item
        for item in view["visible_evidence_ledger"]
        if item["observation_id"] == observation_id
    ]
    if not citations:
        return _finish("No citable rendered event remains.")
    citation = min(citations, key=lambda item: item["call_id"])
    rank = view["submitted_path_candidates"] + 1
    operation = str(event.get("operation") or "unknown_operation")
    slug = re.sub(r"[^a-z0-9]+", "-", operation.casefold()).strip("-")
    slug = slug or "operation"
    return {
        "kind": "submit_path",
        "thought": "Convert one rendered event into the baseline path schema.",
        "hypothesis": (
            "A directly rendered operation may represent one cloud transition."
        ),
        "path_candidate": {
            "path_id": f"baseline-{rank}-{slug}",
            "nodes": [
                {
                    "node_id": f"identity-{rank}",
                    "type": "identity",
                    "label": str(event.get("actor_id") or "unknown identity"),
                },
                {
                    "node_id": f"service-{rank}",
                    "type": "cloud_service",
                    "label": str(event.get("service") or "unknown service"),
                },
            ],
            "edges": [
                {
                    "edge_id": f"edge-{rank}",
                    "source": f"identity-{rank}",
                    "target": f"service-{rank}",
                    "type": "observed_operation",
                }
            ],
            "evidence_assignments": [
                {
                    "observation_id": observation_id,
                    "call_id": citation["call_id"],
                    "polarity": "support",
                    "edge_ids": [f"edge-{rank}"],
                    "test": {
                        "field": "operation",
                        "operator": "eq",
                        "value": operation,
                    },
                }
            ],
        },
    }


def _submit_state_path(
    view: dict[str, Any],
    event: dict[str, Any],
    *,
    claimed_state: str,
    polarity: str,
) -> dict[str, Any]:
    observation_id = event["observation_id"]
    citations = [
        item
        for item in view["visible_evidence_ledger"]
        if item["observation_id"] == observation_id
    ]
    if not citations:
        return _finish("The decisive provider observation is not citable.")
    citation = min(citations, key=lambda item: item["call_id"])
    operation = str(event.get("operation") or "unknown_operation")
    actor_type = (
        "workload_identity"
        if "serviceaccount" in str(event.get("actor_type", "")).casefold()
        or "service-account" in str(event.get("actor_id", "")).casefold()
        else "identity"
    )
    if operation == "ModifySnapshotAttribute":
        edge_type = "grant_permission"
    elif operation == "CopyObject":
        edge_type = "write_data"
    elif operation in {
        "GetObject",
        "GetSecretValue",
        "google.cloud.secretmanager.v1."
        "SecretManagerService.AccessSecretVersion",
        "storage.objects.get",
    }:
        edge_type = "read_data"
    else:
        edge_type = "enumerate"
    target_type = (
        "secret_store"
        if "Secret" in operation or "secretmanager" in operation
        else (
            "data_object"
            if edge_type in {
                "read_data",
                "write_data",
                "grant_permission",
            }
            else "object_storage"
        )
    )
    return {
        "kind": "submit_path",
        "thought": (
            "Use the provider outcome on the exact data operation without "
            "turning missing evidence into denial."
        ),
        "hypothesis": (
            f"The exact provider outcome makes this edge {claimed_state}."
        ),
        "path_candidate": {
            "path_id": "provider-aware-decisive-edge",
            "claimed_state": claimed_state,
            "nodes": [
                {
                    "node_id": "observed-principal",
                    "type": actor_type,
                    "label": str(event.get("actor_id") or "observed principal"),
                },
                {
                    "node_id": "observed-target",
                    "type": target_type,
                    "label": str(
                        event.get("target_resource")
                        or event.get("service")
                        or "observed data target"
                    ),
                },
            ],
            "edges": [
                {
                    "edge_id": "decisive-edge",
                    "source": "observed-principal",
                    "target": "observed-target",
                    "type": edge_type,
                }
            ],
            "evidence_assignments": [
                {
                    "observation_id": observation_id,
                    "call_id": citation["call_id"],
                    "polarity": polarity,
                    "edge_ids": ["decisive-edge"],
                    "test": {
                        "field": "event_status",
                        "operator": "eq",
                        "value": event["event_status"],
                    },
                }
            ],
        },
    }
