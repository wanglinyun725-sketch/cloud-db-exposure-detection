"""Tool-Use adapter for DOI-published real cloud incident reports."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from src.agent.published_telemetry_environment import (
    PublishedTelemetryEnvironment,
)


class IncidentReportToolEnvironment:
    """Expose one report incrementally while hiding human screening fields.

    The adapter does not presume that the report is a negative control.  Its
    reviewed screening state is available only through ``evaluation_metadata``.
    """

    def __init__(
        self,
        case: dict[str, Any],
        budget: int | None = None,
    ) -> None:
        candidate_id = case["candidate_id"]
        opaque_id = "incident-" + hashlib.sha256(
            candidate_id.encode("utf-8")
        ).hexdigest()[:16]
        raw_ref = case["raw_ref"]
        observation_id = "obs-" + hashlib.sha256(
            (
                f"{candidate_id}:{raw_ref['record_sha256']}"
            ).encode("utf-8")
        ).hexdigest()[:24]
        service_hint = case.get("service_hint") or "published_report"
        observation = {
            "observation_id": observation_id,
            "candidate_id": opaque_id,
            "schema": "published_cloud_incident_report",
            "timestamp": case.get("year"),
            "service": case["vendor"],
            "operation": service_hint,
            "actor_type": "cloud_provider",
            "actor_id": case["vendor"],
            "source_ip": None,
            "account_id": None,
            "region": None,
            "event_status": "PublishedIncidentReport",
            "request": case["report_text"],
            "response": "",
            "raw_ref": {
                "relative_path": raw_ref["archive_relative_path"],
                "sha256": raw_ref["archive_sha256"],
                "record_index": raw_ref["record_index"],
                "upstream_path": raw_ref["member_path"],
                "record_sha256": raw_ref["record_sha256"],
            },
            "path_label": None,
            "evidence_state": None,
        }
        index = {
            "cases": [
                {
                    "candidate_id": opaque_id,
                    "source_id": case["source"]["source_id"],
                    "upstream_dataset_id": case["source"]["doi"],
                    "author": "Chu et al.",
                    "published_date": "2024-10-29",
                    "description": (
                        f"DOI-published {case['vendor']} cloud incident report."
                    ),
                    "environment": "production incident report archive",
                    "observation_ids": [observation_id],
                    "annotation_status": "screening_hidden",
                }
            ],
            "observations": [observation],
        }
        self._environment = PublishedTelemetryEnvironment(
            index,
            opaque_id,
            budget,
        )
        self.public_context = {
            "report_handle": opaque_id,
            "vendor": case["vendor"],
            "year": case.get("year"),
            "source": "DOI-published cloud incident report",
        }
        self._evaluation_metadata = {
            "candidate_id": candidate_id,
            "raw_ref": dict(raw_ref),
            "screening": dict(case["screening"]),
            "data_relevance_facets": list(
                case["data_relevance_facets"]
            ),
            "security_term_hits": list(case["security_term_hits"]),
        }

    @classmethod
    def from_file(
        cls,
        packet_path: str | Path,
        candidate_id: str,
        budget: int | None = None,
    ) -> "IncidentReportToolEnvironment":
        packet = json.loads(Path(packet_path).read_text(encoding="utf-8"))
        cases = {
            item["candidate_id"]: item
            for item in packet.get("cases", [])
        }
        if candidate_id not in cases:
            raise KeyError(f"unknown incident candidate: {candidate_id}")
        return cls(cases[candidate_id], budget)

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
        return {
            **self._evaluation_metadata,
            "screening": dict(self._evaluation_metadata["screening"]),
        }
