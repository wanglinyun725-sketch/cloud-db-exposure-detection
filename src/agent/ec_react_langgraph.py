"""LangGraph orchestration backend for the framework-agnostic EC-ReAct core."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, TypedDict

from src.agent.ec_react import (
    ALLOWED_DECISIONS,
    ECReactRunner,
    ECReactResult,
    ReActTraceStep,
    _action_key,
    _compact_tool_output,
    _visible_event_map,
    pareto_action_candidates,
)
from src.agent.path_proposal import (
    compact_evidence_ledger,
    evaluate_path_finish_proposal,
    path_proposal_schema,
    record_visible_observations,
)
from src.agent.published_telemetry_environment import (
    ToolActionError,
    ToolBudgetError,
)

try:
    from langgraph.graph import END, StateGraph

    HAS_LANGGRAPH = True
except ImportError:  # pragma: no cover - exercised only in minimal installs.
    END = None
    StateGraph = None
    HAS_LANGGRAPH = False


class ECReactGraphState(TypedDict, total=False):
    public_context: dict[str, Any]
    history: list[dict[str, Any]]
    action_keys: list[str]
    observed_ids: list[str]
    raw_refs_by_id: dict[str, dict[str, Any]]
    evidence_ledger: dict[str, list[dict[str, Any]]]
    operation_counts: dict[str, int]
    service_counts: dict[str, int]
    observation_count: int
    path_candidates: list[dict[str, Any]]
    invalid_actions: int
    step_number: int
    proposal: dict[str, Any]
    proposal_error: str | None
    final_result: dict[str, Any] | None


class ECReactLangGraphRunner:
    """Execute plan→guard/tool→belief-update→route as LangGraph nodes."""

    def __init__(
        self,
        policy: Any,
        *,
        max_steps: int = 12,
        max_invalid_actions: int = 3,
        checkpointer: Any | None = None,
        task_mode: str = "candidate_evidence",
        finish_guard_mode: str = "strict",
        pareto_guard: bool = True,
        external_rule_prior: bool = True,
        four_value_memory: bool = True,
        budget_stop: bool = True,
        max_path_candidates: int = 5,
    ) -> None:
        if not HAS_LANGGRAPH:
            raise RuntimeError(
                "LangGraph is not installed; install requirements.txt"
            )
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
        self.checkpointer = checkpointer
        self.task_mode = task_mode
        self.finish_guard_mode = finish_guard_mode
        self.pareto_guard = pareto_guard
        self.external_rule_prior = external_rule_prior
        self.four_value_memory = four_value_memory
        self.budget_stop = budget_stop
        self.max_path_candidates = max_path_candidates
        self._environment: Any | None = None
        self._compiled = self._build_graph().compile(
            checkpointer=checkpointer
        )

    def _build_graph(self):
        graph = StateGraph(ECReactGraphState)
        graph.add_node("plan", self._plan_node)
        graph.add_node("guard_tool_update", self._guard_tool_update_node)
        graph.set_entry_point("plan")
        graph.add_edge("plan", "guard_tool_update")
        graph.add_conditional_edges(
            "guard_tool_update",
            self._route,
            {
                "continue": "plan",
                "end": END,
            },
        )
        return graph

    def run(
        self,
        environment: Any,
        public_context: dict[str, Any],
        *,
        config: dict[str, Any] | None = None,
    ) -> ECReactResult:
        self._environment = environment
        initial: ECReactGraphState = {
            "public_context": dict(public_context),
            "history": [],
            "action_keys": [],
            "observed_ids": [],
            "raw_refs_by_id": {},
            "evidence_ledger": {},
            "operation_counts": {},
            "service_counts": {},
            "observation_count": 0,
            "path_candidates": [],
            "invalid_actions": 0,
            "step_number": 0,
            "proposal": {},
            "proposal_error": None,
            "final_result": None,
        }
        final = self._compiled.invoke(initial, config=config)
        payload = dict(final["final_result"])
        return ECReactResult(**payload)

    def _plan_node(
        self,
        state: ECReactGraphState,
    ) -> ECReactGraphState:
        candidates = pareto_action_candidates(
            state.get("operation_counts", {}),
            set(state.get("action_keys", [])),
            (
                self._environment.remaining_budget
                if self.budget_stop
                else None
            ),
            service_counts=state.get("service_counts", {}),
            visible_events=_visible_event_map(
                state.get("evidence_ledger", {})
            ),
            observation_count=state.get("observation_count", 0),
            platform=state["public_context"].get("platform"),
            use_external_rule_prior=self.external_rule_prior,
            apply_pareto=self.pareto_guard,
        )
        view = {
            "public_context": state["public_context"],
            "tool_contracts": self._environment.action_schema(),
            "remaining_budget": self._environment.remaining_budget,
            "pareto_actions": [asdict(item) for item in candidates],
            "observed_evidence_ids": sorted(
                state.get("observed_ids", [])
            ),
            "visible_evidence_ledger": compact_evidence_ledger(
                state.get("evidence_ledger", {})
            ),
            "task_mode": self.task_mode,
            "method_components": {
                "pareto_guard": self.pareto_guard,
                "external_rule_prior": self.external_rule_prior,
                "four_value_memory": self.four_value_memory,
                "budget_stop": self.budget_stop,
                "finish_guard_mode": self.finish_guard_mode,
            },
            "path_candidate_limit": self.max_path_candidates,
            "submitted_path_candidates": len(
                state.get("path_candidates", [])
            ),
            "four_value_claim_memory": (
                ECReactRunner._claim_memory(
                    state.get("path_candidates", [])
                )
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
                    "step": item["step"],
                    "thought": item["thought"],
                    "proposal": item["proposal"],
                    "status": item["status"],
                    "observation": item.get("observation"),
                    "error": item.get("error"),
                }
                for item in state.get("history", [])
            ],
            "instruction": self._instruction(),
        }
        proposal_error = None
        try:
            proposal = self.policy.propose(view)
        except Exception as exc:  # Policy output is still guarded downstream.
            proposal = {}
            proposal_error = (
                f"policy error: {type(exc).__name__}: {exc}"
            )
        return {
            **state,
            "step_number": state.get("step_number", 0) + 1,
            "proposal": proposal,
            "proposal_error": proposal_error,
        }

    def _guard_tool_update_node(
        self,
        state: ECReactGraphState,
    ) -> ECReactGraphState:
        history = list(state.get("history", []))
        action_keys = list(state.get("action_keys", []))
        observed_ids = set(state.get("observed_ids", []))
        raw_refs_by_id = dict(state.get("raw_refs_by_id", {}))
        evidence_ledger = {
            key: list(value)
            for key, value in state.get("evidence_ledger", {}).items()
        }
        operation_counts = dict(state.get("operation_counts", {}))
        service_counts = dict(state.get("service_counts", {}))
        observation_count = int(state.get("observation_count", 0))
        path_candidates = list(state.get("path_candidates", []))
        invalid_actions = state.get("invalid_actions", 0)
        proposal = state.get("proposal", {})
        step_number = state["step_number"]

        try:
            if state.get("proposal_error"):
                raise ToolActionError(state["proposal_error"])
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
                    asdict(
                        ReActTraceStep(
                            step=step_number,
                            thought=thought,
                            proposal=proposal,
                            status=(
                                "path_candidate_accepted"
                                if report["verified"]
                                else "path_candidate_recorded"
                            ),
                            observation=ECReactRunner._compact_path_report(
                                report
                            ),
                            cumulative_cost=self._environment.spent,
                        )
                    )
                )
                final_result = None
                if len(path_candidates) >= self.max_path_candidates:
                    final_result = self._path_collection_result(
                        path_candidates,
                        raw_refs_by_id,
                        history,
                        invalid_actions,
                        "path_candidate_limit",
                        "Path candidate limit reached.",
                    )
                    final_result["steps"] = len(history)
                    final_result["trace"] = history
                return {
                    **state,
                    "history": history,
                    "raw_refs_by_id": raw_refs_by_id,
                    "evidence_ledger": evidence_ledger,
                    "path_candidates": path_candidates,
                    "invalid_actions": invalid_actions,
                    "final_result": final_result,
                }
            if kind == "finish":
                if self.task_mode == "path_discovery":
                    final_result = self._path_finish_result(
                        proposal,
                        history,
                        evidence_ledger,
                        raw_refs_by_id,
                        invalid_actions,
                        path_candidates,
                    )
                else:
                    final_result = self._finish_result(
                        proposal,
                        history,
                        observed_ids,
                        raw_refs_by_id,
                        invalid_actions,
                    )
                history.append(
                    asdict(
                        ReActTraceStep(
                            step=step_number,
                            thought=thought,
                            proposal=proposal,
                            status="finished",
                            cumulative_cost=self._environment.spent,
                        )
                    )
                )
                final_result["steps"] = len(history)
                final_result["trace"] = history
                return {
                    **state,
                    "history": history,
                    "path_candidates": path_candidates,
                    "final_result": final_result,
                }

            tool_name = proposal["tool_name"]
            arguments = dict(proposal.get("arguments") or {})
            action_key = _action_key(tool_name, arguments)
            if action_key in action_keys:
                raise ToolActionError("duplicate tool action")
            candidates = pareto_action_candidates(
                operation_counts,
                set(action_keys),
                (
                    self._environment.remaining_budget
                    if self.budget_stop
                    else None
                ),
                service_counts=service_counts,
                visible_events=_visible_event_map(evidence_ledger),
                observation_count=observation_count,
                platform=state["public_context"].get("platform"),
                use_external_rule_prior=self.external_rule_prior,
                apply_pareto=self.pareto_guard,
            )
            ECReactRunner._guard_tool_action(
                self,
                tool_name,
                arguments,
                candidates,
                operation_counts,
                service_counts,
                _visible_event_map(evidence_ledger),
                observation_count,
                self._environment.remaining_budget,
            )
            output = self._environment.execute(tool_name, arguments)
            action_keys.append(action_key)
            compact_observation = _compact_tool_output(output)
            record_visible_observations(
                evidence_ledger,
                output,
                compact_observation,
            )
            visible_ids = {
                event.get("observation_id")
                for event in compact_observation.get("events", [])
                if event.get("observation_id")
            }
            for event in output["tool_result"].get("events", []):
                observation_id = event.get("observation_id")
                if observation_id in visible_ids:
                    observed_ids.add(observation_id)
                    if isinstance(event.get("raw_ref"), dict):
                        raw_refs_by_id[observation_id] = event["raw_ref"]
            if tool_name == "summarize_case":
                operation_counts = dict(
                    output["tool_result"].get("operation_counts", {})
                )
                service_counts = dict(
                    output["tool_result"].get("service_counts", {})
                )
                observation_count = int(
                    output["tool_result"].get("observation_count", 0)
                )
            history.append(
                asdict(
                    ReActTraceStep(
                        step=step_number,
                        thought=thought,
                        proposal=proposal,
                        status="tool_executed",
                        observation=compact_observation,
                        cumulative_cost=self._environment.spent,
                    )
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
                asdict(
                    ReActTraceStep(
                        step=step_number,
                        thought=(
                            str(proposal.get("thought", ""))
                            if isinstance(proposal, dict)
                            else ""
                        ),
                        proposal=proposal if isinstance(proposal, dict) else {},
                        status="action_rejected",
                        error=f"{type(exc).__name__}: {exc}",
                        cumulative_cost=self._environment.spent,
                    )
                )
            )

        final_result = None
        if invalid_actions >= self.max_invalid_actions:
            final_result = self._abstain_result(
                history,
                invalid_actions,
                "invalid_action_limit",
                path_candidates,
            )
        elif step_number >= self.max_steps:
            final_result = self._abstain_result(
                history,
                invalid_actions,
                "max_steps",
                path_candidates,
            )
        return {
            **state,
            "history": history,
            "action_keys": action_keys,
            "observed_ids": sorted(observed_ids),
            "raw_refs_by_id": raw_refs_by_id,
            "evidence_ledger": evidence_ledger,
            "operation_counts": operation_counts,
            "service_counts": service_counts,
            "observation_count": observation_count,
            "path_candidates": path_candidates,
            "invalid_actions": invalid_actions,
            "final_result": final_result,
        }

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
            if not isinstance(proposal.get("arguments", {}), dict):
                raise ToolActionError("tool arguments must be an object")
        return thought.strip(), kind

    def _finish_result(
        self,
        proposal: dict[str, Any],
        history: list[dict[str, Any]],
        observed_ids: set[str],
        raw_refs_by_id: dict[str, dict[str, Any]],
        invalid_actions: int,
    ) -> dict[str, Any]:
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
        return {
            "decision": decision,
            "hypothesis": hypothesis.strip(),
            "stop_reason": "policy_finish_guard_passed",
            "steps": len(history),
            "valid_tool_calls": sum(
                item["status"] == "tool_executed" for item in history
            ),
            "invalid_actions": invalid_actions,
            "spent": self._environment.spent,
            "evidence_observation_ids": list(dict.fromkeys(evidence_ids)),
            "evidence_raw_refs": [
                raw_refs_by_id[item]
                for item in evidence_ids
                if item in raw_refs_by_id
            ],
            "trace": [],
        }

    def _path_finish_result(
        self,
        proposal: dict[str, Any],
        history: list[dict[str, Any]],
        evidence_ledger: dict[str, list[dict[str, Any]]],
        raw_refs_by_id: dict[str, dict[str, Any]],
        invalid_actions: int,
        path_candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
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
        )
        report = evaluated["report"]
        if report is not None:
            ECReactRunner._append_path_report(path_candidates, report)
            if (
                not report["verified"]
                and self.finish_guard_mode == "strict"
            ):
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
                invalid_actions,
                evaluated["stop_reason"],
                evaluated["hypothesis"],
            )
        return {
            "decision": evaluated["decision"],
            "hypothesis": evaluated["hypothesis"],
            "stop_reason": evaluated["stop_reason"],
            "steps": len(history),
            "valid_tool_calls": sum(
                item["status"] == "tool_executed" for item in history
            ),
            "invalid_actions": invalid_actions,
            "spent": self._environment.spent,
            "trace": [],
        }

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
        )
        report = evaluated["report"]
        ECReactRunner._append_path_report(path_candidates, report)
        if not report["verified"] and self.finish_guard_mode == "strict":
            summary = "; ".join(
                report.get("errors") or ["unknown verification failure"]
            )
            raise ToolActionError(f"path verification failed: {summary}")
        return report

    def _path_collection_result(
        self,
        path_candidates: list[dict[str, Any]],
        raw_refs_by_id: dict[str, dict[str, Any]],
        history: list[dict[str, Any]],
        invalid_actions: int,
        stop_reason: str,
        hypothesis: str,
    ) -> dict[str, Any]:
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
        return {
            "decision": (
                "evidence_certified_paths"
                if verified
                else "unverified_paths_proposed"
            ),
            "hypothesis": hypothesis,
            "stop_reason": stop_reason,
            "steps": len(history),
            "valid_tool_calls": sum(
                item["status"] == "tool_executed" for item in history
            ),
            "invalid_actions": invalid_actions,
            "spent": self._environment.spent,
            "evidence_observation_ids": evidence_ids,
            "evidence_raw_refs": [
                raw_refs_by_id[item]
                for item in evidence_ids
                if item in raw_refs_by_id
            ],
            "trace": [],
            "path_candidates": list(path_candidates),
            "verified_path_candidates": list(verified),
            "path_verdict": last.get("verdict"),
            "certificate": last_certified.get("certificate"),
            "certificate_audit": last_certified.get(
                "certificate_audit"
            ),
            "certificate_scope": last_certified.get("certificate_scope"),
            "verification_errors": errors,
        }

    def _abstain_result(
        self,
        history: list[dict[str, Any]],
        invalid_actions: int,
        stop_reason: str,
        path_candidates: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "decision": "abstain",
            "hypothesis": (
                "The guarded investigation did not reach a valid finish."
            ),
            "stop_reason": stop_reason,
            "steps": len(history),
            "valid_tool_calls": sum(
                item["status"] == "tool_executed" for item in history
            ),
            "invalid_actions": invalid_actions,
            "spent": self._environment.spent,
            "evidence_observation_ids": [],
            "evidence_raw_refs": [],
            "trace": history,
            "path_candidates": list(path_candidates or []),
            "verified_path_candidates": [
                item
                for item in (path_candidates or [])
                if item.get("verified")
            ],
            "verification_errors": (
                list((path_candidates or [])[-1].get("errors") or [])
                if path_candidates
                else []
            ),
        }

    @staticmethod
    def _route(state: ECReactGraphState) -> str:
        return "end" if state.get("final_result") is not None else "continue"
