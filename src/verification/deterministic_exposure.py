"""Deterministic, layered exposure verdicts for frozen cloud configurations.

This module does not infer labels from prose.  It combines two independently
auditable layers:

* configuration semantics from a provider-native analyzer; and
* runtime semantics from an authorized active probe.

An absent analyzer finding is deliberately treated as Unknown.  A negative
verdict requires an explicit deny result over a complete query scope.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Iterable, Sequence


class EvidenceState(str, Enum):
    UNKNOWN = "Unknown"
    SUPPORTED = "Supported"
    CONTRADICTED = "Contradicted"
    CONFLICT = "Conflict"

    @classmethod
    def from_bits(cls, support: bool, refute: bool) -> "EvidenceState":
        if support and refute:
            return cls.CONFLICT
        if support:
            return cls.SUPPORTED
        if refute:
            return cls.CONTRADICTED
        return cls.UNKNOWN


ANALYZER_RESULTS = {"allow", "deny", "not_found", "not_run", "error"}
PROBE_RESULTS = {"success", "access_denied", "not_run", "error"}
SCOPE_LEVELS = {"complete", "partial", "unknown"}


@dataclass(frozen=True)
class AnalyzerObservation:
    """One provider-native policy/reachability analyzer result."""

    observation_id: str
    result: str
    scope: str
    raw_ref: str
    provider: str
    tool: str

    def __post_init__(self) -> None:
        if self.result not in ANALYZER_RESULTS:
            raise ValueError(f"unsupported analyzer result: {self.result}")
        if self.scope not in SCOPE_LEVELS:
            raise ValueError(f"unsupported analyzer scope: {self.scope}")
        if not self.observation_id or not self.raw_ref:
            raise ValueError("analyzer observations require id and raw_ref")


@dataclass(frozen=True)
class ProbeObservation:
    """One authorized active probe against an isolated lab deployment."""

    observation_id: str
    result: str
    scope: str
    raw_ref: str
    audit_ref: str | None = None

    def __post_init__(self) -> None:
        if self.result not in PROBE_RESULTS:
            raise ValueError(f"unsupported probe result: {self.result}")
        if self.scope not in SCOPE_LEVELS:
            raise ValueError(f"unsupported probe scope: {self.scope}")
        if not self.observation_id or not self.raw_ref:
            raise ValueError("probe observations require id and raw_ref")


@dataclass(frozen=True)
class LayerVerdict:
    state: str
    support_refs: tuple[str, ...]
    refute_refs: tuple[str, ...]
    ignored_refs: tuple[str, ...]
    semantics: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ExposureVerdict:
    claim_id: str
    configuration: LayerVerdict
    runtime: LayerVerdict
    strongest_gold_tier: str | None

    def to_dict(self) -> dict:
        return {
            "claim_id": self.claim_id,
            "configuration": self.configuration.to_dict(),
            "runtime": self.runtime.to_dict(),
            "strongest_gold_tier": self.strongest_gold_tier,
        }


@dataclass(frozen=True)
class PathExposureVerdict:
    path_id: str
    configuration_state: str
    runtime_state: str
    claim_verdicts: tuple[ExposureVerdict, ...]
    strongest_gold_tier: str | None

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "configuration_state": self.configuration_state,
            "runtime_state": self.runtime_state,
            "claim_verdicts": [
                verdict.to_dict() for verdict in self.claim_verdicts
            ],
            "strongest_gold_tier": self.strongest_gold_tier,
        }


def evaluate_exposure_claim(
    claim_id: str,
    *,
    frozen_config_refs: Sequence[str],
    analyzer_observations: Iterable[AnalyzerObservation] = (),
    probe_observations: Iterable[ProbeObservation] = (),
) -> ExposureVerdict:
    """Evaluate one reachability claim without treating silence as denial.

    Frozen configuration is mandatory provenance, but its mere presence is not
    evidence that a permission is allowed or denied.  Configuration support or
    refutation requires an explicit provider-native result with complete scope.
    Runtime support requires a successful probe and its matching audit record.
    Runtime refutation requires an explicit access-denied probe with complete
    scope; the error response itself is the primary raw evidence.
    """
    if not claim_id.strip():
        raise ValueError("claim_id must be non-empty")
    if not frozen_config_refs or any(not ref for ref in frozen_config_refs):
        raise ValueError("at least one frozen configuration reference is required")

    analyzer_support: list[str] = []
    analyzer_refute: list[str] = []
    analyzer_ignored: list[str] = []
    for observation in analyzer_observations:
        if observation.scope != "complete":
            analyzer_ignored.append(observation.raw_ref)
        elif observation.result == "allow":
            analyzer_support.append(observation.raw_ref)
        elif observation.result == "deny":
            analyzer_refute.append(observation.raw_ref)
        else:
            analyzer_ignored.append(observation.raw_ref)

    runtime_support: list[str] = []
    runtime_refute: list[str] = []
    runtime_ignored: list[str] = []
    for observation in probe_observations:
        if observation.scope != "complete":
            runtime_ignored.append(observation.raw_ref)
        elif observation.result == "success" and observation.audit_ref:
            runtime_support.extend((observation.raw_ref, observation.audit_ref))
        elif observation.result == "access_denied":
            runtime_refute.append(observation.raw_ref)
            if observation.audit_ref:
                runtime_refute.append(observation.audit_ref)
        else:
            runtime_ignored.append(observation.raw_ref)

    config_state = EvidenceState.from_bits(
        bool(analyzer_support),
        bool(analyzer_refute),
    )
    runtime_state = EvidenceState.from_bits(
        bool(runtime_support),
        bool(runtime_refute),
    )
    if runtime_state in {
        EvidenceState.SUPPORTED,
        EvidenceState.CONTRADICTED,
    }:
        gold_tier = "runtime_gold"
    elif config_state in {
        EvidenceState.SUPPORTED,
        EvidenceState.CONTRADICTED,
    }:
        gold_tier = "configuration_gold"
    else:
        gold_tier = None

    return ExposureVerdict(
        claim_id=claim_id,
        configuration=LayerVerdict(
            state=config_state.value,
            support_refs=tuple(sorted(set(analyzer_support))),
            refute_refs=tuple(sorted(set(analyzer_refute))),
            ignored_refs=tuple(sorted(set(analyzer_ignored))),
            semantics=(
                "complete-scope provider-native allow/deny only; "
                "not_found, partial scope, and tool errors remain Unknown"
            ),
        ),
        runtime=LayerVerdict(
            state=runtime_state.value,
            support_refs=tuple(sorted(set(runtime_support))),
            refute_refs=tuple(sorted(set(runtime_refute))),
            ignored_refs=tuple(sorted(set(runtime_ignored))),
            semantics=(
                "success requires a matching audit record; explicit "
                "complete-scope access_denied supports a negative verdict"
            ),
        ),
        strongest_gold_tier=gold_tier,
    )


def evaluate_exposure_path(
    path_id: str,
    claim_verdicts: Iterable[ExposureVerdict],
) -> PathExposureVerdict:
    """Conservatively aggregate mandatory claims into a path verdict."""
    claims = tuple(claim_verdicts)
    if not claims:
        raise ValueError("a path requires at least one claim verdict")
    return PathExposureVerdict(
        path_id=path_id,
        configuration_state=_aggregate_required_claims(
            verdict.configuration.state for verdict in claims
        ),
        runtime_state=_aggregate_required_claims(
            verdict.runtime.state for verdict in claims
        ),
        claim_verdicts=claims,
        strongest_gold_tier=_path_gold_tier(claims),
    )


def _aggregate_required_claims(states: Iterable[str]) -> str:
    values = tuple(states)
    if "Conflict" in values:
        return "Conflict"
    if "Contradicted" in values:
        return "NotReachable"
    if "Unknown" in values:
        return "Unknown"
    return "Reachable"


def _path_gold_tier(claims: Sequence[ExposureVerdict]) -> str | None:
    runtime_states = {claim.runtime.state for claim in claims}
    if runtime_states <= {"Supported"}:
        return "runtime_gold"
    if "Contradicted" in runtime_states and not (
        runtime_states & {"Conflict"}
    ):
        return "runtime_gold"

    config_states = {claim.configuration.state for claim in claims}
    if config_states <= {"Supported"}:
        return "configuration_gold"
    if "Contradicted" in config_states and not (
        config_states & {"Conflict"}
    ):
        return "configuration_gold"
    return None
