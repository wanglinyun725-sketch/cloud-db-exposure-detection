"""Evidence-constrained ReAct loop with deterministic Tool-Use guards."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from math import ceil
import os
import re
from typing import Any, Protocol
import urllib.request

from src.agent.published_telemetry_environment import (
    ToolActionError,
    ToolBudgetError,
)
from src.agent.path_proposal import (
    compact_evidence_ledger,
    evaluate_path_finish_proposal,
    path_proposal_schema,
    record_visible_observations,
)
from src.agent.sigma_semantic_prior import SIGMA_SEMANTIC_PRIOR


ALLOWED_DECISIONS = {
    "candidate_evidence_found",
    "no_candidate_evidence",
    "abstain",
}

PARETO_ACTION_SPACE_ID = "cross_tool_visible_sigma_v0.3"


class ReActPolicy(Protocol):
    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        """Return one structured Thought+Action or Thought+Finish proposal."""


@dataclass(frozen=True)
class ActionCandidate:
    tool_name: str
    arguments: dict[str, Any]
    external_rule_gain: int
    coverage_gain: int
    estimated_cost: int
    evidence_resolution_gain: int = 0


@dataclass
class ReActTraceStep:
    step: int
    thought: str
    proposal: dict[str, Any]
    status: str
    observation: dict[str, Any] | None = None
    error: str | None = None
    cumulative_cost: int = 0


@dataclass
class ECReactResult:
    decision: str
    hypothesis: str
    stop_reason: str
    steps: int
    valid_tool_calls: int
    invalid_actions: int
    spent: int
    evidence_observation_ids: list[str] = field(default_factory=list)
    evidence_raw_refs: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    path_candidates: list[dict[str, Any]] = field(default_factory=list)
    verified_path_candidates: list[dict[str, Any]] = field(default_factory=list)
    path_verdict: dict[str, Any] | None = None
    certificate: dict[str, Any] | None = None
    certificate_audit: dict[str, Any] | None = None
    certificate_scope: str | None = None
    verification_errors: list[str] = field(default_factory=list)


class ECReactRunner:
    """Run a policy while retaining authority in deterministic guards."""

    def __init__(
        self,
        policy: ReActPolicy,
        *,
        max_steps: int = 12,
        max_invalid_actions: int = 3,
        task_mode: str = "candidate_evidence",
        finish_guard_mode: str = "strict",
        pareto_guard: bool = True,
        external_rule_prior: bool = True,
        four_value_memory: bool = True,
        budget_stop: bool = True,
        provider_scope_gate: bool = True,
        max_path_candidates: int = 5,
    ) -> None:
        if max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if task_mode not in {"candidate_evidence", "path_discovery"}:
            raise ValueError(
                "task_mode must be candidate_evidence or path_discovery"
            )
        if finish_guard_mode not in {"strict", "record"}:
            raise ValueError("finish_guard_mode must be strict or record")
        if max_path_candidates <= 0:
            raise ValueError("max_path_candidates must be positive")
        self.policy = policy
        self.max_steps = max_steps
        self.max_invalid_actions = max_invalid_actions
        self.task_mode = task_mode
        self.finish_guard_mode = finish_guard_mode
        self.pareto_guard = pareto_guard
        self.external_rule_prior = external_rule_prior
        self.four_value_memory = four_value_memory
        self.budget_stop = budget_stop
        self.provider_scope_gate = provider_scope_gate
        self.max_path_candidates = max_path_candidates

    def run(
        self,
        environment: Any,
        public_context: dict[str, Any],
    ) -> ECReactResult:
        history: list[ReActTraceStep] = []
        action_keys: set[str] = set()
        observed_ids: set[str] = set()
        raw_refs_by_id: dict[str, dict[str, Any]] = {}
        evidence_ledger: dict[str, list[dict[str, Any]]] = {}
        operation_counts: dict[str, int] = {}
        service_counts: dict[str, int] = {}
        observation_count = 0
        invalid_actions = 0
        path_candidates: list[dict[str, Any]] = []

        for step_number in range(1, self.max_steps + 1):
            proposal: dict[str, Any] = {}
            candidates = pareto_action_candidates(
                operation_counts,
                action_keys,
                (
                    environment.remaining_budget
                    if self.budget_stop
                    else None
                ),
                service_counts=service_counts,
                visible_events=_visible_event_map(evidence_ledger),
                observation_count=observation_count,
                platform=public_context.get("platform"),
                use_external_rule_prior=self.external_rule_prior,
                apply_pareto=self.pareto_guard,
            )
            view = {
                "public_context": public_context,
                "tool_contracts": environment.action_schema(),
                "remaining_budget": environment.remaining_budget,
                "pareto_actions": [asdict(item) for item in candidates],
                "observed_evidence_ids": sorted(observed_ids),
                "visible_evidence_ledger": compact_evidence_ledger(
                    evidence_ledger
                ),
                "task_mode": self.task_mode,
                "method_components": {
                    "pareto_guard": self.pareto_guard,
                    "external_rule_prior": self.external_rule_prior,
                    "four_value_memory": self.four_value_memory,
                    "budget_stop": self.budget_stop,
                    "provider_scope_gate": self.provider_scope_gate,
                    "finish_guard_mode": self.finish_guard_mode,
                },
                "path_candidate_limit": self.max_path_candidates,
                "submitted_path_candidates": len(path_candidates),
                "four_value_claim_memory": (
                    self._claim_memory(path_candidates)
                    if self.four_value_memory
                    else []
                ),
                "finish_contract": (
                    path_proposal_schema()
                    if self.task_mode == "path_discovery"
                    else None
                ),
                "history": [
                    {
                        "step": item.step,
                        "thought": item.thought,
                        "proposal": item.proposal,
                        "status": item.status,
                        "observation": item.observation,
                        "error": item.error,
                    }
                    for item in history
                ],
                "instruction": (
                    self._instruction()
                ),
            }
            try:
                try:
                    proposal = self.policy.propose(view)
                except Exception as exc:
                    raise ToolActionError(
                        f"policy error: {type(exc).__name__}: {exc}"
                    ) from exc
                thought, kind = self._guard_proposal(proposal)
                if kind == "submit_path":
                    if self.task_mode != "path_discovery":
                        raise ToolActionError(
                            "submit_path is available only in path_discovery"
                        )
                    report = self._submit_path_candidate(
                        proposal,
                        evidence_ledger,
                        raw_refs_by_id,
                        path_candidates,
                    )
                    history.append(
                        ReActTraceStep(
                            step=step_number,
                            thought=thought,
                            proposal=proposal,
                            status=(
                                "path_candidate_accepted"
                                if report["verified"]
                                else "path_candidate_recorded"
                            ),
                            observation=self._compact_path_report(report),
                            cumulative_cost=environment.spent,
                        )
                    )
                    if len(path_candidates) >= self.max_path_candidates:
                        result = self._path_collection_result(
                            path_candidates,
                            raw_refs_by_id,
                            history,
                            environment.spent,
                            invalid_actions,
                            "path_candidate_limit",
                            "Path candidate limit reached.",
                        )
                        result.trace = [asdict(item) for item in history]
                        result.steps = len(history)
                        return result
                    continue
                if kind == "finish":
                    if self.task_mode == "path_discovery":
                        result = self._guard_path_finish(
                            proposal,
                            evidence_ledger,
                            raw_refs_by_id,
                            history,
                            environment.spent,
                            invalid_actions,
                            path_candidates,
                        )
                    else:
                        result = self._guard_finish(
                            proposal,
                            observed_ids,
                            raw_refs_by_id,
                            history,
                            environment.spent,
                            invalid_actions,
                        )
                    history.append(
                        ReActTraceStep(
                            step=step_number,
                            thought=thought,
                            proposal=proposal,
                            status="finished",
                            cumulative_cost=environment.spent,
                        )
                    )
                    result.trace = [asdict(item) for item in history]
                    result.steps = len(history)
                    return result

                tool_name = proposal["tool_name"]
                arguments = dict(proposal.get("arguments") or {})
                action_key = _action_key(tool_name, arguments)
                if action_key in action_keys:
                    raise ToolActionError("duplicate tool action")
                self._guard_tool_action(
                    tool_name,
                    arguments,
                    candidates,
                    operation_counts,
                    service_counts,
                    _visible_event_map(evidence_ledger),
                    observation_count,
                    environment.remaining_budget,
                )

                tool_output = environment.execute(tool_name, arguments)
                action_keys.add(action_key)
                compact_observation = _compact_tool_output(tool_output)
                record_visible_observations(
                    evidence_ledger,
                    tool_output,
                    compact_observation,
                )
                visible_ids = {
                    event.get("observation_id")
                    for event in compact_observation.get("events", [])
                    if event.get("observation_id")
                }
                for event in tool_output["tool_result"].get("events", []):
                    observation_id = event.get("observation_id")
                    if observation_id in visible_ids:
                        observed_ids.add(observation_id)
                        if isinstance(event.get("raw_ref"), dict):
                            raw_refs_by_id[observation_id] = event["raw_ref"]
                if tool_name == "summarize_case":
                    operation_counts = dict(
                        tool_output["tool_result"].get(
                            "operation_counts",
                            {},
                        )
                    )
                    service_counts = dict(
                        tool_output["tool_result"].get(
                            "service_counts",
                            {},
                        )
                    )
                    observation_count = int(
                        tool_output["tool_result"].get(
                            "observation_count",
                            0,
                        )
                    )
                history.append(
                    ReActTraceStep(
                        step=step_number,
                        thought=thought,
                        proposal=proposal,
                        status="tool_executed",
                        observation=compact_observation,
                        cumulative_cost=environment.spent,
                    )
                )
            except (
                KeyError,
                TypeError,
                ValueError,
                ToolActionError,
                ToolBudgetError,
            ) as exc:
                invalid_actions += 1
                history.append(
                    ReActTraceStep(
                        step=step_number,
                        thought=(
                            str(proposal.get("thought", ""))
                            if isinstance(proposal, dict)
                            else ""
                        ),
                        proposal=(
                            proposal
                            if isinstance(proposal, dict)
                            else {}
                        ),
                        status="action_rejected",
                        error=f"{type(exc).__name__}: {exc}",
                        cumulative_cost=environment.spent,
                    )
                )
                if invalid_actions >= self.max_invalid_actions:
                    return self._abstain(
                        history,
                        environment.spent,
                        invalid_actions,
                        "invalid_action_limit",
                        path_candidates,
                    )

        return self._abstain(
            history,
            environment.spent,
            invalid_actions,
            "max_steps",
            path_candidates,
        )

    def _instruction(self) -> str:
        if self.task_mode == "path_discovery":
            return (
                "Choose one tool action or follow finish_contract. A proposed "
                "path may be submitted with kind=submit_path and is not "
                "accepted until deterministic CP-Cert verification. Submit "
                "up to path_candidate_limit candidates, then finish. "
                "Cite only observation/call pairs in visible_evidence_ledger. "
                "Empty search results mean Unknown, not contradiction."
            )
        return (
            "Choose one tool action or finish. Empty search results mean "
            "Unknown, not contradiction."
        )

    @staticmethod
    def _guard_proposal(
        proposal: dict[str, Any],
    ) -> tuple[str, str]:
        if not isinstance(proposal, dict):
            raise ToolActionError("policy proposal must be an object")
        thought = proposal.get("thought")
        if not isinstance(thought, str) or not thought.strip():
            raise ToolActionError("proposal requires a non-empty thought")
        kind = proposal.get("kind")
        if kind not in {"tool", "submit_path", "finish"}:
            raise ToolActionError("kind must be tool, submit_path, or finish")
        if kind == "tool":
            if not isinstance(proposal.get("tool_name"), str):
                raise ToolActionError("tool proposal requires tool_name")
            arguments = proposal.get("arguments", {})
            if not isinstance(arguments, dict):
                raise ToolActionError("tool arguments must be an object")
        return thought.strip(), kind

    @staticmethod
    def _guard_finish(
        proposal: dict[str, Any],
        observed_ids: set[str],
        raw_refs_by_id: dict[str, dict[str, Any]],
        history: list[ReActTraceStep],
        spent: int,
        invalid_actions: int,
    ) -> ECReactResult:
        decision = proposal.get("decision")
        if decision not in ALLOWED_DECISIONS:
            raise ToolActionError(f"invalid decision: {decision}")
        hypothesis = proposal.get("hypothesis")
        if not isinstance(hypothesis, str) or not hypothesis.strip():
            raise ToolActionError("finish requires a non-empty hypothesis")
        evidence_ids = proposal.get("evidence_observation_ids", [])
        if not isinstance(evidence_ids, list) or not all(
            isinstance(item, str) for item in evidence_ids
        ):
            raise ToolActionError("evidence_observation_ids must be strings")
        hallucinated = set(evidence_ids) - observed_ids
        if hallucinated:
            raise ToolActionError(
                f"finish cites unobserved evidence: {sorted(hallucinated)}"
            )
        if decision == "candidate_evidence_found" and not evidence_ids:
            raise ToolActionError(
                "positive decision requires at least one observed evidence ID"
            )
        raw_refs = [
            raw_refs_by_id[item]
            for item in evidence_ids
            if item in raw_refs_by_id
        ]
        return ECReactResult(
            decision=decision,
            hypothesis=hypothesis.strip(),
            stop_reason="policy_finish_guard_passed",
            steps=len(history),
            valid_tool_calls=sum(
                item.status == "tool_executed" for item in history
            ),
            invalid_actions=invalid_actions,
            spent=spent,
            evidence_observation_ids=list(dict.fromkeys(evidence_ids)),
            evidence_raw_refs=raw_refs,
        )

    def _guard_path_finish(
        self,
        proposal: dict[str, Any],
        evidence_ledger: dict[str, list[dict[str, Any]]],
        raw_refs_by_id: dict[str, dict[str, Any]],
        history: list[ReActTraceStep],
        spent: int,
        invalid_actions: int,
        path_candidates: list[dict[str, Any]],
    ) -> ECReactResult:
        if (
            proposal.get("decision")
            in {"search_complete", "no_verified_path", "abstain"}
            and not (
                isinstance(proposal.get("hypothesis"), str)
                and proposal["hypothesis"].strip()
            )
            and isinstance(proposal.get("thought"), str)
            and proposal["thought"].strip()
        ):
            proposal["hypothesis"] = proposal["thought"].strip()
            proposal.setdefault("protocol_normalizations", []).append(
                "hypothesis_from_thought"
            )
        evaluated = evaluate_path_finish_proposal(
            proposal,
            evidence_ledger,
            raw_refs_by_id,
            provider_scope_gate=self.provider_scope_gate,
        )
        report = evaluated["report"]
        if report is not None:
            self._append_path_report(path_candidates, report)
            if not report["verified"] and self.finish_guard_mode == "strict":
                summary = "; ".join(
                    report.get("errors")
                    or ["unknown verification failure"]
                )
                raise ToolActionError(
                    f"path verification failed: {summary}"
                )
        if path_candidates:
            return self._path_collection_result(
                path_candidates,
                raw_refs_by_id,
                history,
                spent,
                invalid_actions,
                evaluated["stop_reason"],
                evaluated["hypothesis"],
            )
        return ECReactResult(
            decision=evaluated["decision"],
            hypothesis=evaluated["hypothesis"],
            stop_reason=evaluated["stop_reason"],
            steps=len(history),
            valid_tool_calls=sum(
                item.status == "tool_executed" for item in history
            ),
            invalid_actions=invalid_actions,
            spent=spent,
        )

    def _submit_path_candidate(
        self,
        proposal: dict[str, Any],
        evidence_ledger: dict[str, list[dict[str, Any]]],
        raw_refs_by_id: dict[str, dict[str, Any]],
        path_candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        evaluated = evaluate_path_finish_proposal(
            {
                "decision": "path_found",
                "hypothesis": proposal.get("hypothesis"),
                "path_candidate": proposal.get("path_candidate"),
            },
            evidence_ledger,
            raw_refs_by_id,
            provider_scope_gate=self.provider_scope_gate,
        )
        report = evaluated["report"]
        self._append_path_report(path_candidates, report)
        if not report["verified"] and self.finish_guard_mode == "strict":
            summary = "; ".join(
                report.get("errors") or ["unknown verification failure"]
            )
            raise ToolActionError(f"path verification failed: {summary}")
        return report

    @staticmethod
    def _append_path_report(
        path_candidates: list[dict[str, Any]],
        report: dict[str, Any],
    ) -> None:
        normalized = report.get("normalized_path") or {}
        identity = json.dumps(
            {
                "path_id": normalized.get("path_id"),
                "nodes": normalized.get("nodes"),
                "edges": normalized.get("edges"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for existing in path_candidates:
            existing_path = existing.get("normalized_path") or {}
            existing_identity = json.dumps(
                {
                    "path_id": existing_path.get("path_id"),
                    "nodes": existing_path.get("nodes"),
                    "edges": existing_path.get("edges"),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if existing.get("verified") and identity == existing_identity:
                raise ToolActionError(
                    "duplicate already-certified path candidate"
                )
        path_candidates.append(report)

    @staticmethod
    def _claim_memory(
        path_candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            {
                "path_id": (
                    (item.get("normalized_path") or {}).get("path_id")
                ),
                "state": (item.get("verdict") or {}).get("state"),
                "claim_states": (
                    (item.get("verdict") or {}).get("claim_states") or {}
                ),
                "verified": bool(item.get("verified")),
                "errors": list(item.get("errors") or []),
            }
            for item in path_candidates
        ]

    @staticmethod
    def _compact_path_report(report: dict[str, Any]) -> dict[str, Any]:
        return {
            "path_id": (
                (report.get("normalized_path") or {}).get("path_id")
            ),
            "verified": bool(report.get("verified")),
            "verdict": report.get("verdict"),
            "errors": list(report.get("errors") or []),
            "certificate_id": (
                (report.get("certificate") or {}).get("certificate_id")
            ),
            "certificate_scope": report.get("certificate_scope"),
        }

    @staticmethod
    def _path_collection_result(
        path_candidates: list[dict[str, Any]],
        raw_refs_by_id: dict[str, dict[str, Any]],
        history: list[ReActTraceStep],
        spent: int,
        invalid_actions: int,
        stop_reason: str,
        hypothesis: str,
    ) -> ECReactResult:
        verified = [
            item for item in path_candidates if item.get("verified")
        ]
        evidence_ids = list(dict.fromkeys(
            assignment["observation_id"]
            for report in path_candidates
            for assignment in (
                (report.get("normalized_path") or {}).get(
                    "evidence_assignments",
                    [],
                )
            )
            if assignment.get("observation_id")
        ))
        last = path_candidates[-1]
        last_certified = verified[-1] if verified else last
        errors = list(dict.fromkeys(
            error
            for report in path_candidates
            for error in (report.get("errors") or [])
        ))
        return ECReactResult(
            decision=(
                "evidence_certified_paths"
                if verified
                else "unverified_paths_proposed"
            ),
            hypothesis=hypothesis,
            stop_reason=stop_reason,
            steps=len(history),
            valid_tool_calls=sum(
                item.status == "tool_executed" for item in history
            ),
            invalid_actions=invalid_actions,
            spent=spent,
            evidence_observation_ids=evidence_ids,
            evidence_raw_refs=[
                raw_refs_by_id[item]
                for item in evidence_ids
                if item in raw_refs_by_id
            ],
            path_candidates=list(path_candidates),
            verified_path_candidates=list(verified),
            path_verdict=last.get("verdict"),
            certificate=last_certified.get("certificate"),
            certificate_audit=last_certified.get("certificate_audit"),
            certificate_scope=last_certified.get("certificate_scope"),
            verification_errors=errors,
        )

    def _guard_tool_action(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        pareto_candidates: list[ActionCandidate],
        operation_counts: dict[str, int],
        service_counts: dict[str, int],
        visible_events: dict[str, dict[str, Any]],
        observation_count: int,
        remaining_budget: int | None,
    ) -> None:
        if self.pareto_guard and _is_rankable_action(
            tool_name,
            arguments,
            operation_counts,
            service_counts,
            visible_events,
        ):
            if _action_key(tool_name, arguments) not in {
                _action_key(item.tool_name, item.arguments)
                for item in pareto_candidates
            }:
                raise ToolActionError(
                    "ranked action is outside the current Pareto frontier"
                )
        if self.budget_stop and remaining_budget is not None:
            estimated = _minimum_action_cost(
                tool_name,
                arguments,
                operation_counts,
                service_counts,
                observation_count,
            )
            if estimated > remaining_budget:
                raise ToolActionError(
                    f"estimated action cost {estimated} exceeds remaining "
                    f"budget {remaining_budget}"
                )

    @staticmethod
    def _abstain(
        history: list[ReActTraceStep],
        spent: int,
        invalid_actions: int,
        stop_reason: str,
        path_candidates: list[dict[str, Any]] | None = None,
    ) -> ECReactResult:
        return ECReactResult(
            decision="abstain",
            hypothesis="The guarded investigation did not reach a valid finish.",
            stop_reason=stop_reason,
            steps=len(history),
            valid_tool_calls=sum(
                item.status == "tool_executed" for item in history
            ),
            invalid_actions=invalid_actions,
            spent=spent,
            trace=[asdict(item) for item in history],
            path_candidates=list(path_candidates or []),
            verified_path_candidates=[
                item
                for item in (path_candidates or [])
                if item.get("verified")
            ],
            verification_errors=(
                list((path_candidates or [])[-1].get("errors") or [])
                if path_candidates
                else []
            ),
        )


def pareto_action_candidates(
    operation_counts: dict[str, int],
    executed_action_keys: set[str] | None = None,
    remaining_budget: int | None = None,
    *,
    service_counts: dict[str, int] | None = None,
    visible_events: dict[str, dict[str, Any]] | None = None,
    observation_count: int = 0,
    platform: str | None = None,
    use_external_rule_prior: bool = True,
    apply_pareto: bool = True,
) -> list[ActionCandidate]:
    """Return budget-feasible actions, optionally filtered to the frontier."""
    executed_action_keys = executed_action_keys or set()
    service_counts = service_counts or {}
    visible_events = visible_events or {}
    candidates: dict[str, ActionCandidate] = {}

    def add(candidate: ActionCandidate) -> None:
        key = _action_key(candidate.tool_name, candidate.arguments)
        if key in executed_action_keys:
            return
        if (
            remaining_budget is not None
            and candidate.estimated_cost > remaining_budget
        ):
            return
        candidates[key] = candidate

    if not operation_counts and not service_counts:
        add(ActionCandidate(
            tool_name="summarize_case",
            arguments={},
            external_rule_gain=0,
            coverage_gain=1,
            estimated_cost=1,
            evidence_resolution_gain=1,
        ))

    for operation, count in operation_counts.items():
        add(ActionCandidate(
            tool_name="search_events",
            arguments={"operation": operation},
            external_rule_gain=_external_rule_score(
                operation,
                platform,
            ) if use_external_rule_prior else 0,
            coverage_gain=min(int(count), 20),
            estimated_cost=1 + ceil(int(count) / 5),
            evidence_resolution_gain=1,
        ))
    for service, count in service_counts.items():
        add(ActionCandidate(
            tool_name="search_events",
            arguments={"service": service},
            external_rule_gain=0,
            coverage_gain=min(int(count), 20),
            estimated_cost=1 + ceil(int(count) / 5),
            evidence_resolution_gain=1,
        ))

    actor_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for observation_id, event in visible_events.items():
        add(ActionCandidate(
            tool_name="get_event_detail",
            arguments={"observation_id": observation_id},
            external_rule_gain=(
                _external_rule_score(
                    str(event.get("operation") or ""),
                    platform,
                )
                if use_external_rule_prior
                else 0
            ),
            coverage_gain=1,
            estimated_cost=2,
            evidence_resolution_gain=4,
        ))
        actor_id = event.get("actor_id")
        if isinstance(actor_id, str) and actor_id.strip():
            actor_counts[actor_id] = actor_counts.get(actor_id, 0) + 1
        status = event.get("event_status")
        if isinstance(status, str) and status.strip():
            status_counts[status] = status_counts.get(status, 0) + 1
        for term in _visible_resource_terms(event):
            add(ActionCandidate(
                tool_name="resource_search",
                arguments={"term": term},
                external_rule_gain=0,
                coverage_gain=2,
                estimated_cost=_unknown_result_cost(
                    "resource_search",
                    observation_count,
                ),
                evidence_resolution_gain=3,
            ))
    for actor_id, count in actor_counts.items():
        add(ActionCandidate(
            tool_name="actor_timeline",
            arguments={"actor_id": actor_id},
            external_rule_gain=0,
            coverage_gain=min(count, 20),
            estimated_cost=_unknown_result_cost(
                "actor_timeline",
                observation_count,
            ),
            evidence_resolution_gain=2,
        ))
    for status, count in status_counts.items():
        add(ActionCandidate(
            tool_name="search_events",
            arguments={"event_status": status},
            external_rule_gain=0,
            coverage_gain=min(count, 20),
            estimated_cost=_unknown_result_cost(
                "search_events",
                observation_count,
            ),
            evidence_resolution_gain=1,
        ))

    all_candidates = list(candidates.values())
    selected = (
        [
            candidate
            for candidate in all_candidates
            if not any(
                _dominates(other, candidate)
                for other in all_candidates
                if other != candidate
            )
        ]
        if apply_pareto
        else all_candidates
    )
    return sorted(
        selected,
        key=lambda item: (
            -item.external_rule_gain,
            -item.evidence_resolution_gain,
            -item.coverage_gain,
            item.estimated_cost,
            _action_key(item.tool_name, item.arguments),
        ),
    )


def _visible_event_map(
    evidence_ledger: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    visible = {}
    for observation_id, accesses in evidence_ledger.items():
        if not accesses:
            continue
        latest = max(accesses, key=lambda item: item.get("call_id", 0))
        event = latest.get("visible_event")
        if isinstance(event, dict):
            visible[observation_id] = dict(event)
    return visible


def _visible_resource_terms(event: dict[str, Any]) -> list[str]:
    text = " ".join(
        str(event.get(field) or "")
        for field in ("request", "response")
    )
    if not text.strip():
        return []
    tokens = {
        match.group(0).strip("\"'[]{}(),")
        for match in re.finditer(
            r"[A-Za-z0-9][A-Za-z0-9._:/@-]{5,159}",
            text,
        )
    }
    excluded = {
        "resource",
        "request",
        "response",
        "success",
        "unknown",
    }
    useful = [
        token for token in tokens
        if token.casefold() not in excluded
        and not token.casefold().startswith(("https://", "http://"))
    ]
    return sorted(
        useful,
        key=lambda token: (
            -len(token),
            token.casefold(),
        ),
    )[:2]


def _is_rankable_action(
    tool_name: str,
    arguments: dict[str, Any],
    operation_counts: dict[str, int],
    service_counts: dict[str, int],
    visible_events: dict[str, dict[str, Any]],
) -> bool:
    if tool_name == "summarize_case" and not arguments:
        return not operation_counts and not service_counts
    if tool_name == "get_event_detail":
        return (
            set(arguments) == {"observation_id"}
            and arguments.get("observation_id") in visible_events
        )
    if tool_name == "actor_timeline":
        visible_actors = {
            event.get("actor_id") for event in visible_events.values()
        }
        return (
            set(arguments) == {"actor_id"}
            and arguments.get("actor_id") in visible_actors
        )
    if tool_name == "resource_search":
        terms = {
            term
            for event in visible_events.values()
            for term in _visible_resource_terms(event)
        }
        return (
            set(arguments) == {"term"}
            and arguments.get("term") in terms
        )
    if tool_name != "search_events" or len(arguments) != 1:
        return False
    if "operation" in arguments:
        return arguments["operation"] in operation_counts
    if "service" in arguments:
        return arguments["service"] in service_counts
    if "event_status" in arguments:
        return arguments["event_status"] in {
            event.get("event_status") for event in visible_events.values()
        }
    return False


def _unknown_result_cost(tool_name: str, observation_count: int) -> int:
    base = 2 if tool_name in {"actor_timeline", "resource_search"} else 1
    return base + ceil(max(0, observation_count) / 5)


def _dominates(left: ActionCandidate, right: ActionCandidate) -> bool:
    no_worse = (
        left.external_rule_gain >= right.external_rule_gain
        and left.coverage_gain >= right.coverage_gain
        and left.evidence_resolution_gain
        >= right.evidence_resolution_gain
        and left.estimated_cost <= right.estimated_cost
    )
    strictly_better = (
        left.external_rule_gain > right.external_rule_gain
        or left.coverage_gain > right.coverage_gain
        or left.evidence_resolution_gain
        > right.evidence_resolution_gain
        or left.estimated_cost < right.estimated_cost
    )
    return no_worse and strictly_better


def _external_rule_score(
    operation: str,
    platform: str | None = None,
) -> int:
    return SIGMA_SEMANTIC_PRIOR.score(operation, platform)


def _minimum_action_cost(
    tool_name: str,
    arguments: dict[str, Any],
    operation_counts: dict[str, int],
    service_counts: dict[str, int] | None = None,
    observation_count: int = 0,
) -> int:
    service_counts = service_counts or {}
    if tool_name == "summarize_case":
        return 1
    if tool_name == "get_event_detail":
        return 2
    if tool_name == "search_events":
        operation = arguments.get("operation")
        if (
            isinstance(operation, str)
            and operation in operation_counts
            and set(arguments) == {"operation"}
        ):
            return 1 + ceil(int(operation_counts[operation]) / 5)
        service = arguments.get("service")
        if (
            isinstance(service, str)
            and service in service_counts
            and set(arguments) == {"service"}
        ):
            return 1 + ceil(int(service_counts[service]) / 5)
        if set(arguments) == {"event_status"}:
            return _unknown_result_cost(
                "search_events",
                observation_count,
            )
        return 1
    if tool_name in {"actor_timeline", "resource_search"}:
        return _unknown_result_cost(tool_name, observation_count)
    return 1


def _action_key(tool_name: str, arguments: dict[str, Any]) -> str:
    return json.dumps(
        [tool_name, arguments],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _compact_tool_output(output: dict[str, Any]) -> dict[str, Any]:
    result = output["tool_result"]
    events = result.get("events", [])
    return {
        "tool": output["receipt"]["tool_name"],
        "call_id": output["receipt"]["call_id"],
        "cost": output["receipt"]["cost"],
        "result_count": output["receipt"]["result_count"],
        "operation_counts": result.get("operation_counts"),
        "service_counts": result.get("service_counts"),
        "events": [
            {
                key: _compact_policy_value(event.get(key))
                for key in (
                    "observation_id",
                    "timestamp",
                    "service",
                    "operation",
                    "actor_type",
                    "actor_id",
                    "account_id",
                    "region",
                    "event_status",
                    "provider_decision",
                    "oracle_kind",
                    "scope_completeness",
                    "target_resource",
                    "schema",
                    "source_ip",
                    "request",
                    "response",
                )
                if key in event
            }
            for event in events[:12]
        ],
        "results_truncated_in_policy_view": len(events) > 12,
        "remaining_budget": output["remaining_budget"],
    }


def _compact_policy_value(value: Any, max_characters: int = 1600) -> Any:
    """Bound prompt size while preserving exactly what validators can inspect."""
    if not isinstance(value, str) or len(value) <= max_characters:
        return value
    return value[:max_characters] + "…[truncated]"


class ProgressiveTelemetryPolicy:
    """Offline deterministic policy for protocol smoke tests and baseline use."""

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        history = view["history"]
        if not history:
            return {
                "kind": "tool",
                "thought": "First reveal aggregate telemetry facets.",
                "tool_name": "summarize_case",
                "arguments": {},
            }
        executed = [
            item for item in history
            if item["status"] == "tool_executed"
        ]
        if len(executed) == 1 and view["pareto_actions"]:
            action = view["pareto_actions"][0]
            return {
                "kind": "tool",
                "thought": (
                    "Inspect a non-dominated operation with high evidence "
                    "gain relative to query cost."
                ),
                "tool_name": action["tool_name"],
                "arguments": action["arguments"],
            }
        if executed:
            last_events = executed[-1]["observation"].get("events") or []
            if last_events and executed[-1]["observation"]["tool"] != "get_event_detail":
                return {
                    "kind": "tool",
                    "thought": "Inspect the most recent compact event in detail.",
                    "tool_name": "get_event_detail",
                    "arguments": {
                        "observation_id": last_events[0]["observation_id"]
                    },
                }
            observed_ids = view["observed_evidence_ids"]
            if observed_ids:
                latest_operation = (
                    last_events[0].get("operation")
                    if last_events
                    else "queried cloud operation"
                )
                return {
                    "kind": "finish",
                    "thought": "Return an evidence candidate without overstating path validity.",
                    "decision": "candidate_evidence_found",
                    "hypothesis": (
                        f"Observed {latest_operation}; human/path verification "
                        "is still required."
                    ),
                    "evidence_observation_ids": [observed_ids[0]],
                }
        return {
            "kind": "finish",
            "thought": "No observable candidate was retrieved within the protocol.",
            "decision": "abstain",
            "hypothesis": "Insufficient queried evidence.",
            "evidence_observation_ids": [],
        }


class OpenAICompatibleReActPolicy:
    """Structured ReAct policy for OpenAI-compatible chat endpoints."""

    def __init__(self, client: Any, model: str) -> None:
        self.client = client
        self.model = model

    @classmethod
    def from_env(cls) -> "OpenAICompatibleReActPolicy":
        from openai import OpenAI

        api_key = (
            os.getenv("OPENAI_API_KEY")
            or os.getenv("DASHSCOPE_API_KEY")
        )
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY or DASHSCOPE_API_KEY is required"
            )
        base_url = os.getenv("OPENAI_BASE_URL")
        model = os.getenv("LLM_MODEL", "qwen-plus")
        client = OpenAI(
            api_key=api_key,
            **({"base_url": base_url} if base_url else {}),
        )
        return cls(client, model)

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        if view.get("task_mode") == "path_discovery":
            finish_instruction = (
                "Use kind=submit_path with thought/hypothesis/path_candidate "
                "to add one ranked candidate, then continue investigating. "
                "For kind=finish, follow finish_contract. Deterministic "
                "verification, not your wording, determines acceptance. Cite "
                "each observation together with the call that exposed it."
            )
        else:
            finish_instruction = (
                "For kind=finish use thought/decision/hypothesis/"
                "evidence_observation_ids."
            )
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an evidence-constrained cloud investigation "
                        "agent. Return exactly one JSON object. Never cite an "
                        "observation ID that is not in observed_evidence_ids. "
                        "An empty result is Unknown, not contradiction. "
                        "Use kind=tool with thought/tool_name/arguments. "
                        + finish_instruction
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        view,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
        )
        content = response.choices[0].message.content or ""
        return _parse_json_object(content)


class OllamaNativeReActPolicy:
    """Structured ReAct policy for a local Ollama native chat endpoint.

    Ollama's native ``think=false`` option is used deliberately.  Some
    reasoning models spend the whole output budget in a separate reasoning
    field through the OpenAI-compatible endpoint and return an empty content
    string.  Native JSON mode keeps the experiment's action channel bounded
    and machine-parseable without changing the shared ReAct view or guards.
    """

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 120.0,
        keep_alive: str = "30m",
        num_predict: int = 512,
        num_ctx: int = 4096,
        seed: int | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("Ollama model must be non-empty")
        if timeout_seconds <= 0:
            raise ValueError("Ollama timeout must be positive")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.keep_alive = keep_alive
        self.num_predict = num_predict
        self.num_ctx = num_ctx
        self.seed = seed

    def propose(self, view: dict[str, Any]) -> dict[str, Any]:
        model_view = _compact_ollama_view(view)
        pareto_actions = view.get("pareto_actions")
        allowed_kinds = (
            ["submit_path", "finish"]
            if isinstance(pareto_actions, list) and not pareto_actions
            else ["tool", "submit_path", "finish"]
        )
        exact_tool_names = sorted({
            str(item["tool_name"])
            for item in (pareto_actions or [])
            if isinstance(item, dict) and item.get("tool_name")
        })
        exact_arguments = []
        for item in pareto_actions or []:
            if not isinstance(item, dict):
                continue
            arguments = item.get("arguments")
            if not isinstance(arguments, dict):
                continue
            exact_arguments.append({
                "type": "object",
                "properties": {
                    str(key): {"const": value}
                    for key, value in arguments.items()
                },
                "required": sorted(str(key) for key in arguments),
                "additionalProperties": False,
            })
        tool_name_schema: dict[str, Any] = {"type": "string"}
        if exact_tool_names:
            tool_name_schema["enum"] = exact_tool_names
        arguments_schema: dict[str, Any] = {"type": "object"}
        if exact_arguments:
            arguments_schema = {"anyOf": exact_arguments}
        ontology = path_proposal_schema()["path_ontology"]
        node_type_ids = [
            item["id"] for item in ontology["node_types"]
        ]
        edge_type_ids = [
            item["id"] for item in ontology["edge_types"]
        ]
        method_components = view.get("method_components") or {}
        provider_scope_gate = method_components.get(
            "provider_scope_gate",
            True,
        )
        decisive_provider_evidence: dict[str, str] = {}
        decisive_provider_events: dict[str, dict[str, Any]] = {}
        visible_provider_decisions: list[str] = []
        if method_components.get("external_rule_prior"):
            for item in model_view.get("history") or []:
                observation = (
                    item.get("observation")
                    if isinstance(item, dict)
                    else None
                )
                if not isinstance(observation, dict):
                    continue
                for event in observation.get("events") or []:
                    if not isinstance(event, dict):
                        continue
                    observation_id = event.get("observation_id")
                    provider_decision = event.get("provider_decision")
                    if isinstance(provider_decision, str):
                        visible_provider_decisions.append(provider_decision)
                    if (
                        isinstance(observation_id, str)
                        and provider_decision in {"allow", "deny"}
                        and (
                            not provider_scope_gate
                            or _provider_scope_is_decisive(event)
                        )
                    ):
                        decisive_provider_evidence[observation_id] = (
                            provider_decision
                        )
                        decisive_provider_events[observation_id] = {
                            "call_id": observation.get("call_id"),
                            "event": dict(event),
                        }
        decisive_decisions = set(decisive_provider_evidence.values())
        allowed_claimed_states = ["Reachable", "NotReachable"]
        allowed_polarities = ["support", "refute"]
        if decisive_decisions == {"allow"}:
            allowed_claimed_states = ["Reachable"]
            allowed_polarities = ["support"]
        elif decisive_decisions == {"deny"}:
            allowed_claimed_states = ["NotReachable"]
            allowed_polarities = ["refute"]
        control_only_evidence = (
            bool(visible_provider_decisions)
            and not decisive_provider_evidence
        )
        allowed_finish_decisions = [
            "path_found",
            "search_complete",
            "no_verified_path",
            "abstain",
        ]
        if (
            control_only_evidence
            and isinstance(pareto_actions, list)
            and not pareto_actions
        ):
            allowed_kinds = ["finish"]
            allowed_finish_decisions = ["no_verified_path", "abstain"]
            model_view["allowed_next_kinds"] = ["finish"]
            model_view["tool_contracts"] = []
            model_view["provider_evidence_state"] = (
                "control_only; runtime reachability remains Unknown"
            )
        observation_id_schema: dict[str, Any] = {"type": "string"}
        if decisive_provider_evidence:
            observation_id_schema["enum"] = sorted(
                decisive_provider_evidence
            )
        evidence_assignment_item_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "observation_id": observation_id_schema,
                "call_id": {"type": "integer"},
                "polarity": {
                    "type": "string",
                    "enum": allowed_polarities,
                },
                "edge_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "test": {
                    "type": "object",
                    "properties": {
                        "field": {"type": "string"},
                        "operator": {
                            "type": "string",
                            "enum": ["eq", "contains", "exists"],
                        },
                        "value": {
                            "anyOf": [
                                {"type": "string"},
                                {"type": "number"},
                                {"type": "boolean"},
                                {"type": "null"},
                            ],
                        },
                    },
                    "required": ["field", "operator", "value"],
                },
            },
            "required": [
                "observation_id",
                "call_id",
                "polarity",
                "edge_ids",
                "test",
            ],
        }
        if decisive_provider_events:
            assignment_variants = []
            for observation_id in sorted(decisive_provider_events):
                provider_decision = decisive_provider_evidence[
                    observation_id
                ]
                event_context = decisive_provider_events[observation_id]
                event = event_context["event"]
                test_variants = []
                for field_name in (
                    "provider_decision",
                    "scope_completeness",
                    "oracle_kind",
                    "event_status",
                    "timestamp",
                    "operation",
                    "target_resource",
                ):
                    if field_name not in event:
                        continue
                    field_value = event[field_name]
                    if not isinstance(
                        field_value,
                        (str, int, float, bool, type(None)),
                    ):
                        continue
                    test_variants.append({
                        "type": "object",
                        "properties": {
                            "field": {"const": field_name},
                            "operator": {"const": "eq"},
                            "value": {"const": field_value},
                        },
                        "required": ["field", "operator", "value"],
                        "additionalProperties": False,
                    })
                assignment_variants.append({
                    "type": "object",
                    "properties": {
                        "observation_id": {"const": observation_id},
                        "call_id": {
                            "const": event_context["call_id"],
                        },
                        "polarity": {
                            "const": (
                                "support"
                                if provider_decision == "allow"
                                else "refute"
                            ),
                        },
                        "edge_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        },
                        "test": {"anyOf": test_variants},
                    },
                    "required": [
                        "observation_id",
                        "call_id",
                        "polarity",
                        "edge_ids",
                        "test",
                    ],
                    "additionalProperties": False,
                })
            evidence_assignment_item_schema = {
                "anyOf": assignment_variants,
            }
        rule_prior_instruction = (
            " Apply this provider-time rule: compare event timestamps with "
            "the exact task time. A later success cannot overwrite an earlier "
            "provider denial. When the exact-time event has a non-Success "
            "provider status and only a later success follows, claim "
            "NotReachable, cite the exact-time event as refute, and treat the "
            "later event only as a control. A provider allow or deny is "
            "decisive only when scope_completeness is complete or begins with "
            "complete_for_; incomplete, unknown, and control_only observations "
            "leave the requested end-to-end claim Unknown. Use these canonical "
            "mappings when "
            "visible evidence supports them: IAMUser->identity, service "
            "endpoint->cloud_service, bucket/blob target->object_storage or "
            "data_object, list/describe->enumerate, Get/read->read_data, "
            "Put/Copy->write_data, and API call->invoke."
            if method_components.get("external_rule_prior")
            else ""
        )
        if view.get("task_mode") == "path_discovery":
            finish_instruction = (
                "Use kind=submit_path with thought, hypothesis, and a "
                "path_candidate that exactly follows finish_contract. Cite "
                "each observation with the call that exposed it. Use "
                "claimed_state=Reachable or NotReachable only when supported "
                "by visible provider evidence. Unknown is not a path_candidate "
                "state: express it with kind=finish and "
                "decision=no_verified_path or abstain. For kind=finish, follow "
                "finish_contract. Every edge source and target must "
                "equal a listed node_id. An ordered path must have exactly "
                "len(nodes)-1 edges; two edges require three ordered nodes."
            )
        else:
            finish_instruction = (
                "For kind=finish use thought, decision, hypothesis, and "
                "evidence_observation_ids."
            )
        required_output_fields = ["kind", "thought"]
        if allowed_kinds == ["finish"]:
            required_output_fields.extend(["decision", "hypothesis"])
        payload = {
            "model": self.model,
            "stream": False,
            "think": False,
            "format": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": allowed_kinds,
                    },
                    "thought": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 240,
                    },
                    "tool_name": tool_name_schema,
                    "arguments": arguments_schema,
                    "decision": {
                        "type": "string",
                        "enum": allowed_finish_decisions,
                    },
                    "hypothesis": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 320,
                    },
                    "path_candidate": {
                        "type": "object",
                        "properties": {
                            "path_id": {"type": "string"},
                            "claimed_state": {
                                "type": "string",
                                "enum": allowed_claimed_states,
                            },
                            "nodes": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "node_id": {"type": "string"},
                                        "type": {
                                            "type": "string",
                                            "enum": node_type_ids,
                                        },
                                        "label": {"type": "string"},
                                    },
                                    "required": [
                                        "node_id",
                                        "type",
                                        "label",
                                    ],
                                },
                            },
                            "edges": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "edge_id": {"type": "string"},
                                        "source": {"type": "string"},
                                        "target": {"type": "string"},
                                        "type": {
                                            "type": "string",
                                            "enum": edge_type_ids,
                                        },
                                    },
                                    "required": [
                                        "edge_id",
                                        "source",
                                        "target",
                                        "type",
                                    ],
                                },
                            },
                            "evidence_assignments": {
                                "type": "array",
                                "items": evidence_assignment_item_schema,
                            },
                        },
                        "required": [
                            "path_id",
                            "claimed_state",
                            "nodes",
                            "edges",
                            "evidence_assignments",
                        ],
                    },
                },
                "required": required_output_fields,
                "additionalProperties": False,
            },
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": 0,
                "num_predict": self.num_predict,
                "num_ctx": self.num_ctx,
            },
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an evidence-constrained cloud investigation "
                        "agent. Return exactly one JSON object. Every action "
                        "must include a non-empty thought string. Never cite an "
                        "observation ID that is not in observed_evidence_ids. "
                        "An empty result is Unknown, not contradiction. Use "
                        "kind=tool with thought, tool_name, and arguments. "
                        "When observed_evidence_ids is empty and a tool is "
                        "available, do not finish: choose one valid tool, "
                        "preferably from pareto_actions. Keep thought under "
                        "25 words. When pareto_actions is non-empty, copy one "
                        "listed tool_name and arguments exactly. Do not repeat "
                        "an action that history marks rejected. When "
                        "pareto_actions is empty, never choose kind=tool; "
                        "submit a minimal path or finish using only visible "
                        "evidence. Obey allowed_next_kinds in the user JSON. "
                        "A NotReachable result is a refuted candidate path: "
                        "use kind=submit_path or decision=path_found with "
                        "claimed_state=NotReachable and refute evidence, not "
                        "decision=no_verified_path. Use no_verified_path only "
                        "for Unknown, including configuration-only "
                        "provider_decision=not_run evidence. Inspect an "
                        "observation's scope_completeness before treating its "
                        "provider outcome as end-to-end path evidence. Inspect an "
                        "explicit provider denial before treating a later "
                        "success as decisive for an earlier time-scoped claim. "
                        "Once evidence is sufficient, submit one minimal path "
                        "whose every edge endpoint is a listed node_id; use "
                        "exactly one fewer edge than nodes. "
                        "without explanatory prose outside the JSON fields. "
                        + rule_prior_instruction
                        + " "
                        + finish_instruction
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        model_view,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
        }
        if allowed_kinds == ["finish"]:
            for field_name in ("tool_name", "arguments", "path_candidate"):
                payload["format"]["properties"].pop(field_name, None)
        if self.seed is not None:
            payload["options"]["seed"] = self.seed
        request = urllib.request.Request(
            self.base_url + "/api/chat",
            data=json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(
            request,
            timeout=self.timeout_seconds,
        ) as response:
            result = json.loads(response.read().decode("utf-8"))
        message = result.get("message") or {}
        content = message.get("content") or ""
        if not content.strip():
            raise ValueError("Ollama returned an empty action content")
        return _parse_json_object(content)


def _provider_scope_is_decisive(event: dict[str, Any]) -> bool:
    """Return whether a provider outcome covers the exact investigated claim.

    Older protocol fixtures may not render this field, so absence preserves
    legacy behavior. Once scope is explicit, only complete evidence is allowed
    to constrain the end-to-end path state.
    """
    scope = event.get("scope_completeness")
    if not isinstance(scope, str):
        return True
    normalized = scope.strip().lower()
    return normalized == "complete" or normalized.startswith("complete_for_")


def _compact_ollama_view(view: dict[str, Any]) -> dict[str, Any]:
    """Keep the shared semantics while shortening repeated ontology prose."""
    compact = json.loads(json.dumps(view, ensure_ascii=False))
    pareto_actions = compact.get("pareto_actions")
    if isinstance(pareto_actions, list):
        if pareto_actions:
            compact["allowed_next_kinds"] = [
                "tool",
                "submit_path",
                "finish",
            ]
        else:
            compact["allowed_next_kinds"] = ["submit_path", "finish"]
            compact["tool_contracts"] = []
    contract = compact.get("finish_contract")
    if isinstance(contract, dict):
        ontology = contract.get("path_ontology")
        if isinstance(ontology, dict):
            for field in ("node_types", "edge_types"):
                values = ontology.get(field)
                if isinstance(values, list):
                    ontology[field] = [
                        item.get("id") if isinstance(item, dict) else item
                        for item in values
                    ]
    return compact


def _parse_json_object(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("LLM response must be a JSON object")
    return parsed
