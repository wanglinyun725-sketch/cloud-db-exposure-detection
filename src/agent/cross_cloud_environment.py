"""Leakage-resistant Tool-Use environment for cross-cloud telemetry episodes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any
import zipfile

from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
)


class CrossCloudTelemetryEnvironment:
    """Expose one DOI-published episode without its attack/condition labels."""

    def __init__(
        self,
        root: str | Path,
        episode_index: dict[str, Any],
        episode_id: str,
        budget: int | None = None,
    ) -> None:
        self._root = Path(root)
        episodes = {
            item["episode_id"]: item
            for item in episode_index.get("episodes", [])
        }
        if episode_id not in episodes:
            raise KeyError(f"unknown episode_id: {episode_id}")
        episode = episodes[episode_id]
        self._evaluation_metadata = {
            "episode_id": episode_id,
            "candidate_id": episode["candidate_id"],
            "independence_group": episode["independence_group"],
            "attack": episode["attack"],
            "source_condition": episode["source_condition"],
            "run_id": episode["run_id"],
            "raw_ref": dict(episode["raw_ref"]),
        }
        opaque_id = "episode-" + hashlib.sha256(
            episode_id.encode("utf-8")
        ).hexdigest()[:16]
        observations = self._load_observations(episode, opaque_id)
        blinding_token = _scenario_token(
            opaque_id,
            episode["attack"],
        )
        case = {
            "candidate_id": opaque_id,
            "source_id": "cross_cloud_observability_2026",
            "upstream_dataset_id": "10.5281/zenodo.19933893",
            "author": "Dhooghe et al.",
            "published_date": "2026-04-30",
            "description": (
                f"Redacted {episode['platform']} cloud audit telemetry episode."
            ),
            "environment": "controlled cloud subscription",
            "observation_ids": [
                item["observation_id"] for item in observations
            ],
            "annotation_status": "source_condition_hidden",
        }
        self._environment = PublishedTelemetryEnvironment(
            {
                "cases": [case],
                "observations": observations,
            },
            opaque_id,
            budget,
        )
        self.public_context = {
            "episode_handle": opaque_id,
            "platform": episode["platform"],
            "log_profile": episode["log_profile"],
            "source": "DOI-published redacted cloud telemetry",
            "scenario_literal_blinding": "deterministic_v1",
        }
        self._evaluation_metadata["policy_blinding"] = {
            "version": "deterministic_v1",
            "sensitive_term_sha256": hashlib.sha256(
                episode["attack"].casefold().encode("utf-8")
            ).hexdigest(),
            "replacement_token": blinding_token,
        }

    @classmethod
    def from_file(
        cls,
        root: str | Path,
        index_path: str | Path,
        episode_id: str,
        budget: int | None = None,
    ) -> "CrossCloudTelemetryEnvironment":
        index = json.loads(Path(index_path).read_text(encoding="utf-8"))
        return cls(root, index, episode_id, budget)

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
        """Return hidden labels to the experiment runner, never to the policy."""
        return dict(self._evaluation_metadata)

    def _load_observations(
        self,
        episode: dict[str, Any],
        opaque_id: str,
    ) -> list[dict[str, Any]]:
        raw_ref = episode["raw_ref"]
        archive_path = self._root / raw_ref["archive_relative_path"]
        with zipfile.ZipFile(archive_path) as archive:
            raw_bytes = archive.read(raw_ref["member_path"])
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if digest != raw_ref["member_sha256"]:
            raise ValueError(
                f"member hash mismatch for {raw_ref['member_path']}"
            )
        records = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(records, list):
            raise ValueError("episode member must contain a JSON array")
        return [
            self._normalize_event(
                episode["platform"],
                opaque_id,
                record,
                record_index,
                raw_ref,
                episode["attack"],
            )
            for record_index, record in enumerate(records)
        ]

    @staticmethod
    def _normalize_event(
        platform: str,
        opaque_id: str,
        record: dict[str, Any],
        record_index: int,
        raw_ref: dict[str, Any],
        scenario_literal: str,
    ) -> dict[str, Any]:
        observation_id = "obs-" + hashlib.sha256(
            (
                f"{opaque_id}:{raw_ref['member_sha256']}:{record_index}"
            ).encode("utf-8")
        ).hexdigest()[:24]
        if platform == "AWS":
            identity = record.get("userIdentity") or {}
            resources = record.get("resources") or []
            actor_id = (
                identity.get("arn")
                or identity.get("principalId")
                or identity.get("userName")
                or identity.get("invokedBy")
                or identity.get("type")
            )
            resource = json.dumps(resources, ensure_ascii=False, sort_keys=True)
            normalized = {
                "schema": "aws_cloudtrail",
                "timestamp": record.get("eventTime"),
                "service": record.get("eventSource"),
                "operation": record.get("eventName"),
                "actor_type": identity.get("type"),
                "actor_id": actor_id,
                "source_ip": record.get("sourceIPAddress"),
                "account_id": (
                    identity.get("accountId")
                    or record.get("recipientAccountId")
                ),
                "region": record.get("awsRegion"),
                "event_status": (
                    "Error"
                    if record.get("errorCode") or record.get("errorMessage")
                    else "SuccessOrUnspecified"
                ),
                "request": json.dumps(
                    record.get("requestParameters"),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "response": json.dumps(
                    record.get("responseElements"),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "resource": resource,
            }
        elif platform == "AZURE":
            operation = record.get("operationName") or {}
            provider = record.get("resourceProviderName") or {}
            status = record.get("status") or {}
            authorization = record.get("authorization") or {}
            normalized = {
                "schema": "azure_activity",
                "timestamp": (
                    record.get("eventTimestamp")
                    or record.get("submissionTimestamp")
                ),
                "service": _value(provider),
                "operation": _value(operation),
                "actor_type": (
                    (record.get("claims") or {}).get("idtyp")
                    or "unknown"
                ),
                "actor_id": record.get("caller"),
                "source_ip": record.get("callerIpAddress"),
                "account_id": record.get("subscriptionId"),
                "region": (
                    (record.get("properties") or {}).get("resourceLocation")
                    or record.get("resourceRegion")
                ),
                "event_status": _value(status),
                "request": json.dumps(
                    {
                        "authorization": authorization,
                        "properties": record.get("properties"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "response": json.dumps(
                    {
                        "subStatus": record.get("subStatus"),
                        "description": record.get("description"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "resource": (
                    record.get("resourceId")
                    or authorization.get("scope")
                ),
            }
        else:
            payload = record.get("protoPayload") or {}
            authentication = payload.get("authenticationInfo") or {}
            request_metadata = payload.get("requestMetadata") or {}
            status = payload.get("status") or {}
            resource = (
                payload.get("resourceName")
                or json.dumps(
                    record.get("resource"),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            normalized = {
                "schema": "gcp_audit_log",
                "timestamp": (
                    record.get("timestamp")
                    or record.get("receiveTimestamp")
                ),
                "service": payload.get("serviceName"),
                "operation": payload.get("methodName"),
                "actor_type": (
                    str(authentication.get("principalSubject", "")).split(
                        ":", 1
                    )[0]
                    or "unknown"
                ),
                "actor_id": (
                    authentication.get("principalEmail")
                    or authentication.get("principalSubject")
                ),
                "source_ip": request_metadata.get("callerIp"),
                "account_id": (
                    (record.get("resource") or {}).get("labels", {}).get(
                        "project_id"
                    )
                ),
                "region": (
                    (record.get("resource") or {}).get("labels", {}).get(
                        "location"
                    )
                ),
                "event_status": (
                    f"Code:{status.get('code')}"
                    if status.get("code") is not None
                    else "SuccessOrUnspecified"
                ),
                "request": json.dumps(
                    payload.get("request"),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "response": json.dumps(
                    payload.get("response"),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "resource": resource,
            }
        normalized.update(
            {
                "observation_id": observation_id,
                "candidate_id": opaque_id,
                "raw_ref": {
                    "relative_path": "doi:10.5281/zenodo.19933893",
                    "sha256": raw_ref["member_sha256"],
                    "record_index": record_index,
                    "upstream_path": (
                        "member-" + raw_ref["member_sha256"][:16]
                    ),
                    "archive_sha256": raw_ref["archive_sha256"],
                },
                "path_label": None,
                "evidence_state": None,
            }
        )
        normalized["request"] = (
            normalized["request"] + "\nresource=" + str(normalized.pop("resource"))
        )
        replacement = _scenario_token(opaque_id, scenario_literal)
        normalized = {
            key: _replace_literal(value, scenario_literal, replacement)
            for key, value in normalized.items()
        }
        return normalized


def _value(value: Any) -> str | None:
    if isinstance(value, dict):
        return value.get("value") or value.get("localizedValue")
    return str(value) if value is not None else None


def _scenario_token(opaque_id: str, scenario_literal: str) -> str:
    digest = hashlib.sha256(
        f"{opaque_id}:{scenario_literal.casefold()}".encode("utf-8")
    ).hexdigest()[:16]
    return f"opaque-resource-{digest}"


def _replace_literal(
    value: Any,
    sensitive_literal: str,
    replacement: str,
) -> Any:
    """Blind source scenario names without altering evaluator-side raw bytes."""
    if not sensitive_literal:
        return value
    if isinstance(value, str):
        return re.sub(
            re.escape(sensitive_literal),
            replacement,
            value,
            flags=re.IGNORECASE,
        )
    if isinstance(value, list):
        return [
            _replace_literal(item, sensitive_literal, replacement)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _replace_literal(item, sensitive_literal, replacement)
            for key, item in value.items()
        }
    return value
