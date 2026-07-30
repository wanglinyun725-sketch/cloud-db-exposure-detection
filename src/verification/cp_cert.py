"""Conflict-preserving path verification and minimal evidence certificates.

CP-Cert deliberately separates two questions:

1. What is the four-valued state of every required path premise?
2. What is the smallest auditable set of evidence that proves the verdict?

Evidence is never averaged.  Independent support and refutation bits are
joined monotonically, so adding contrary evidence changes ``Supported`` or
``Refuted`` into ``Conflict`` instead of erasing either side.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
from itertools import combinations
import json
from math import log
from typing import Iterable, Mapping, Sequence


class FourValue(str, Enum):
    """Belnap-style evidence state represented by support/refutation bits."""

    UNKNOWN = "Unknown"
    SUPPORTED = "Supported"
    REFUTED = "Contradicted"
    CONFLICT = "Conflict"

    @classmethod
    def from_bits(cls, support: bool, refute: bool) -> "FourValue":
        if support and refute:
            return cls.CONFLICT
        if support:
            return cls.SUPPORTED
        if refute:
            return cls.REFUTED
        return cls.UNKNOWN

    @property
    def support_bit(self) -> bool:
        return self in {FourValue.SUPPORTED, FourValue.CONFLICT}

    @property
    def refute_bit(self) -> bool:
        return self in {FourValue.REFUTED, FourValue.CONFLICT}

    def join(self, other: "FourValue") -> "FourValue":
        """Monotone information join; neither side of a conflict is lost."""
        return FourValue.from_bits(
            self.support_bit or other.support_bit,
            self.refute_bit or other.refute_bit,
        )


@dataclass(frozen=True)
class EvidenceItem:
    """One immutable, source-grounded support or refutation observation."""

    evidence_id: str
    polarity: str
    claim_ids: tuple[str, ...]
    raw_ref: str
    cost: float = 1.0
    source: str = "unknown"

    def __post_init__(self) -> None:
        if self.polarity not in {"support", "refute"}:
            raise ValueError("polarity must be 'support' or 'refute'")
        if not self.evidence_id.strip():
            raise ValueError("evidence_id must be non-empty")
        if not self.claim_ids or any(not item.strip() for item in self.claim_ids):
            raise ValueError("claim_ids must contain non-empty claim identifiers")
        if not self.raw_ref.strip():
            raise ValueError("raw_ref is required for an auditable certificate")
        if self.cost < 0:
            raise ValueError("cost must be non-negative")


@dataclass(frozen=True)
class PathVerdict:
    path_id: str
    state: str
    claim_states: dict[str, str]
    unknown_claims: tuple[str, ...]
    refuted_claims: tuple[str, ...]
    conflict_claims: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Certificate:
    """A machine-checkable positive or negative evidence certificate."""

    certificate_id: str
    kind: str
    method: str
    evidence_ids: tuple[str, ...]
    raw_refs: tuple[str, ...]
    total_cost: float
    covered_requirements: tuple[str, ...]
    required_requirements: tuple[str, ...]
    sufficient: bool
    irreducible: bool
    optimal: bool
    approximation_bound: float | None
    semantics: str

    def to_dict(self) -> dict:
        return asdict(self)


def fuse_claims(
    evidence: Iterable[EvidenceItem],
    claim_ids: Iterable[str] | None = None,
) -> dict[str, FourValue]:
    """Fuse evidence into four values without collapsing contradictions."""
    items = tuple(evidence)
    requested = set(claim_ids or ())
    if not requested:
        requested = {
            claim_id
            for item in items
            for claim_id in item.claim_ids
        }
    bits = {claim_id: [False, False] for claim_id in requested}
    for item in items:
        for claim_id in set(item.claim_ids).intersection(requested):
            bits[claim_id][0 if item.polarity == "support" else 1] = True
    return {
        claim_id: FourValue.from_bits(*bits[claim_id])
        for claim_id in sorted(requested)
    }


def verify_path_claims(
    path_id: str,
    premise_ids: Sequence[str],
    evidence: Iterable[EvidenceItem],
) -> PathVerdict:
    """Verify a path using conservative, conflict-preserving semantics.

    ``Valid`` requires support-only evidence for every premise.  Any explicit
    conflict is reported as ``Conflict``.  A refutation without conflict makes
    the path ``Invalid``; otherwise missing evidence yields ``Insufficient``.
    """
    premises = tuple(dict.fromkeys(premise_ids))
    if not premises:
        raise ValueError("a path must have at least one required premise")
    states = fuse_claims(evidence, premises)
    conflicts = tuple(
        claim_id
        for claim_id in premises
        if states[claim_id] == FourValue.CONFLICT
    )
    refuted = tuple(
        claim_id
        for claim_id in premises
        if states[claim_id] == FourValue.REFUTED
    )
    unknown = tuple(
        claim_id
        for claim_id in premises
        if states[claim_id] == FourValue.UNKNOWN
    )
    if conflicts:
        state = "Conflict"
    elif refuted:
        state = "Invalid"
    elif unknown:
        state = "Insufficient"
    else:
        state = "Valid"
    return PathVerdict(
        path_id=path_id,
        state=state,
        claim_states={key: states[key].value for key in premises},
        unknown_claims=unknown,
        refuted_claims=refuted,
        conflict_claims=conflicts,
    )


def build_positive_certificate(
    path_id: str,
    premise_ids: Sequence[str],
    evidence: Iterable[EvidenceItem],
    method: str = "exact",
    exact_item_limit: int = 24,
) -> Certificate:
    """Find evidence covering every premise of a conflict-free valid path."""
    premises = tuple(dict.fromkeys(premise_ids))
    items = tuple(evidence)
    verdict = verify_path_claims(path_id, premises, items)
    if verdict.state != "Valid":
        raise ValueError(
            f"positive certificate requires a Valid path, got {verdict.state}"
        )
    support_items = tuple(item for item in items if item.polarity == "support")
    coverage = {
        item.evidence_id: set(item.claim_ids).intersection(premises)
        for item in support_items
    }
    return _build_cover_certificate(
        kind="positive",
        requirements=premises,
        items=support_items,
        coverage=coverage,
        method=method,
        exact_item_limit=exact_item_limit,
        semantics=(
            f"selected support evidence covers every hard premise of path {path_id}"
        ),
    )


def build_negative_certificate(
    paths: Mapping[str, Sequence[str]],
    evidence: Iterable[EvidenceItem],
    method: str = "exact",
    exact_item_limit: int = 24,
) -> Certificate:
    """Find a minimum-cost refutation set hitting every candidate path.

    The certificate proves that none of the supplied candidates is currently a
    conflict-free valid path.  It does not claim that an unenumerated path is
    impossible, nor does Unknown evidence count as a refutation.
    """
    normalized_paths = {
        str(path_id): tuple(dict.fromkeys(premises))
        for path_id, premises in paths.items()
    }
    if not normalized_paths:
        raise ValueError("at least one candidate path is required")
    if any(not premises for premises in normalized_paths.values()):
        raise ValueError("every candidate path needs at least one premise")
    items = tuple(item for item in evidence if item.polarity == "refute")
    coverage = {
        item.evidence_id: {
            path_id
            for path_id, premises in normalized_paths.items()
            if set(item.claim_ids).intersection(premises)
        }
        for item in items
    }
    return _build_cover_certificate(
        kind="negative",
        requirements=tuple(normalized_paths),
        items=items,
        coverage=coverage,
        method=method,
        exact_item_limit=exact_item_limit,
        semantics=(
            "selected refutation evidence intersects every enumerated candidate "
            "path; Unknown observations never count as blockers"
        ),
    )


def verify_certificate(
    certificate: Certificate,
    evidence: Iterable[EvidenceItem],
    coverage: Mapping[str, Iterable[str]],
    *,
    oracle_item_limit: int = 18,
) -> dict:
    """Recompute structure, sufficiency, minimality and traceability."""
    if oracle_item_limit < 0:
        raise ValueError("oracle_item_limit must be non-negative")
    item_index = _index_items(evidence)
    selected = tuple(certificate.evidence_ids)
    selected_ids_unique = len(selected) == len(set(selected))
    claimed_requirements = set(certificate.required_requirements)
    expected_requirements: set[str] = set()
    for values in coverage.values():
        expected_requirements.update(values)
    requirements_nonempty = bool(expected_requirements)
    normalized_coverage = {
        evidence_id: set(values).intersection(expected_requirements)
        for evidence_id, values in coverage.items()
    }
    unknown_evidence_ids = tuple(
        evidence_id for evidence_id in selected if evidence_id not in item_index
    )
    covered = _covered_by(selected, normalized_coverage)
    sufficient = (
        selected_ids_unique
        and not unknown_evidence_ids
        and expected_requirements.issubset(covered)
    )
    deletion_failures = []
    for evidence_id in selected:
        reduced = tuple(item for item in selected if item != evidence_id)
        if expected_requirements.issubset(
            _covered_by(reduced, normalized_coverage)
        ):
            deletion_failures.append(evidence_id)
    raw_refs_complete = (
        not unknown_evidence_ids
        and all(item_index[evidence_id].raw_ref.strip() for evidence_id in selected)
    )
    recomputed_cost = sum(
        item_index[evidence_id].cost
        for evidence_id in selected
        if evidence_id in item_index
    )
    expected_raw_refs = tuple(
        item_index[evidence_id].raw_ref
        for evidence_id in selected
        if evidence_id in item_index
    )
    cost_matches = abs(
        recomputed_cost - certificate.total_cost
    ) <= 1e-9
    required_requirements_match = (
        claimed_requirements == expected_requirements
        and len(certificate.required_requirements)
        == len(claimed_requirements)
    )
    covered_requirements_match = (
        tuple(sorted(covered))
        == tuple(sorted(certificate.covered_requirements))
    )
    raw_refs_match = certificate.raw_refs == expected_raw_refs
    expected_certificate_id = _certificate_id(
        kind=certificate.kind,
        method=certificate.method,
        evidence_ids=selected,
        requirements=certificate.required_requirements,
        total_cost=certificate.total_cost,
    )
    certificate_id_matches = (
        certificate.certificate_id == expected_certificate_id
    )
    irreducible = sufficient and not deletion_failures
    certificate_claims_match = (
        certificate.sufficient == sufficient
        and certificate.irreducible == irreducible
    )
    kind_and_method_valid = (
        certificate.kind in {"positive", "negative"}
        and certificate.method in {"exact", "greedy"}
    )
    available_items = tuple(item_index.values())
    polarity_matches_kind = all(
        item.polarity
        == ("support" if certificate.kind == "positive" else "refute")
        for item in available_items
    ) if certificate.kind in {"positive", "negative"} else False
    expected_approximation_bound = (
        1.0 + log(max(len(expected_requirements), 1))
    )
    method_claims_valid = (
        certificate.optimal is True
        and certificate.approximation_bound is None
        if certificate.method == "exact"
        else (
            certificate.optimal is False
            and certificate.approximation_bound is not None
            and abs(
                certificate.approximation_bound
                - expected_approximation_bound
            )
            <= 1e-9
        )
        if certificate.method == "greedy"
        else False
    )
    oracle_minimum_cost = None
    optimality_verified = None
    approximation_bound_satisfied = None
    if (
        expected_requirements
        and len(available_items) <= oracle_item_limit
    ):
        oracle_minimum_cost = brute_force_minimum_cost(
            tuple(sorted(expected_requirements)),
            available_items,
            {
                evidence_id: set(values)
                for evidence_id, values in normalized_coverage.items()
            },
        )
        optimality_verified = abs(
            certificate.total_cost - oracle_minimum_cost
        ) <= 1e-9
        if certificate.approximation_bound is not None:
            approximation_bound_satisfied = (
                certificate.total_cost
                <= certificate.approximation_bound
                * oracle_minimum_cost
                + 1e-9
            )
    optimality_claim_valid = (
        optimality_verified is not False
        if certificate.optimal
        else (
            certificate.method == "greedy"
            and approximation_bound_satisfied is not False
        )
    )
    valid = all((
        requirements_nonempty,
        sufficient,
        irreducible,
        raw_refs_complete,
        raw_refs_match,
        cost_matches,
        required_requirements_match,
        covered_requirements_match,
        certificate_id_matches,
        certificate_claims_match,
        kind_and_method_valid,
        polarity_matches_kind,
        method_claims_valid,
        optimality_claim_valid,
    ))
    return {
        "valid": valid,
        "requirements_nonempty": requirements_nonempty,
        "sufficient": sufficient,
        "irreducible": irreducible,
        "raw_refs_complete": raw_refs_complete,
        "raw_refs_match": raw_refs_match,
        "selected_ids_unique": selected_ids_unique,
        "required_requirements_match": required_requirements_match,
        "covered_requirements_match": covered_requirements_match,
        "certificate_id_matches": certificate_id_matches,
        "certificate_claims_match": certificate_claims_match,
        "kind_and_method_valid": kind_and_method_valid,
        "polarity_matches_kind": polarity_matches_kind,
        "method_claims_valid": method_claims_valid,
        "unknown_evidence_ids": list(unknown_evidence_ids),
        "redundant_evidence_ids": deletion_failures,
        "covered_requirements": sorted(covered),
        "missing_requirements": sorted(expected_requirements - covered),
        "recomputed_cost": recomputed_cost,
        "cost_matches": cost_matches,
        "oracle_minimum_cost": oracle_minimum_cost,
        "optimality_verified": optimality_verified,
        "approximation_bound_satisfied": approximation_bound_satisfied,
        "optimality_claim_valid": optimality_claim_valid,
    }


def _build_cover_certificate(
    *,
    kind: str,
    requirements: Sequence[str],
    items: Sequence[EvidenceItem],
    coverage: Mapping[str, set[str]],
    method: str,
    exact_item_limit: int,
    semantics: str,
) -> Certificate:
    universe = tuple(dict.fromkeys(requirements))
    item_index = _index_items(items)
    useful = tuple(
        item
        for item in items
        if coverage.get(item.evidence_id)
    )
    possible = _covered_by(
        (item.evidence_id for item in useful),
        coverage,
    )
    missing = set(universe) - possible
    if missing:
        raise ValueError(
            "no sufficient certificate; uncovered requirements: "
            + ", ".join(sorted(missing))
        )
    if method not in {"exact", "greedy", "auto"}:
        raise ValueError("method must be exact, greedy, or auto")
    resolved_method = method
    if method == "auto":
        resolved_method = "exact" if len(useful) <= exact_item_limit else "greedy"
    if resolved_method == "exact" and len(useful) > exact_item_limit:
        raise ValueError(
            f"exact solver received {len(useful)} useful items; "
            f"limit is {exact_item_limit}"
        )
    if resolved_method == "exact":
        selected = _exact_weighted_cover(universe, useful, coverage)
        optimal = True
        approximation_bound = None
    else:
        selected = _greedy_weighted_cover(universe, useful, coverage)
        optimal = False
        approximation_bound = 1.0 + log(max(len(universe), 1))
    selected = _remove_redundancy(selected, universe, coverage, item_index)
    covered = _covered_by(selected, coverage)
    total_cost = sum(item_index[evidence_id].cost for evidence_id in selected)
    raw_refs = tuple(item_index[evidence_id].raw_ref for evidence_id in selected)
    certificate_id = _certificate_id(
        kind=kind,
        method=resolved_method,
        evidence_ids=selected,
        requirements=universe,
        total_cost=total_cost,
    )
    irreducible = all(
        not set(universe).issubset(
            _covered_by(
                tuple(item for item in selected if item != evidence_id),
                coverage,
            )
        )
        for evidence_id in selected
    )
    return Certificate(
        certificate_id=certificate_id,
        kind=kind,
        method=resolved_method,
        evidence_ids=selected,
        raw_refs=raw_refs,
        total_cost=total_cost,
        covered_requirements=tuple(sorted(covered)),
        required_requirements=universe,
        sufficient=set(universe).issubset(covered),
        irreducible=irreducible,
        optimal=optimal,
        approximation_bound=approximation_bound,
        semantics=semantics,
    )


def _certificate_id(
    *,
    kind: str,
    method: str,
    evidence_ids: Sequence[str],
    requirements: Sequence[str],
    total_cost: float,
) -> str:
    payload = {
        "kind": kind,
        "method": method,
        "evidence_ids": tuple(evidence_ids),
        "requirements": tuple(requirements),
        "total_cost": total_cost,
    }
    return "cp-" + sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:20]


def _index_items(items: Iterable[EvidenceItem]) -> dict[str, EvidenceItem]:
    index: dict[str, EvidenceItem] = {}
    for item in items:
        if item.evidence_id in index:
            raise ValueError(f"duplicate evidence_id: {item.evidence_id}")
        index[item.evidence_id] = item
    return index


def _covered_by(
    evidence_ids: Iterable[str],
    coverage: Mapping[str, Iterable[str]],
) -> set[str]:
    covered: set[str] = set()
    for evidence_id in evidence_ids:
        covered.update(coverage.get(evidence_id, ()))
    return covered


def _exact_weighted_cover(
    requirements: Sequence[str],
    items: Sequence[EvidenceItem],
    coverage: Mapping[str, set[str]],
) -> tuple[str, ...]:
    """Exact branch-and-bound weighted set cover for small case graphs."""
    universe = frozenset(requirements)
    item_index = _index_items(items)
    by_requirement = {
        requirement: tuple(
            sorted(
                (
                    item.evidence_id
                    for item in items
                    if requirement in coverage.get(item.evidence_id, set())
                ),
                key=lambda evidence_id: (
                    item_index[evidence_id].cost,
                    evidence_id,
                ),
            )
        )
        for requirement in universe
    }
    best_ids: tuple[str, ...] | None = None
    best_key: tuple[float, int, tuple[str, ...]] | None = None
    best_seen_cost: dict[frozenset[str], float] = {}

    def search(
        uncovered: frozenset[str],
        selected: tuple[str, ...],
        current_cost: float,
    ) -> None:
        nonlocal best_ids, best_key
        if not uncovered:
            normalized = tuple(sorted(selected))
            key = (current_cost, len(normalized), normalized)
            if best_key is None or key < best_key:
                best_ids = normalized
                best_key = key
            return
        if best_key is not None and current_cost > best_key[0] + 1e-12:
            return
        previous = best_seen_cost.get(uncovered)
        if previous is not None and current_cost > previous + 1e-12:
            return
        best_seen_cost[uncovered] = min(previous, current_cost) if previous is not None else current_cost

        requirement = min(
            uncovered,
            key=lambda value: (len(by_requirement[value]), value),
        )
        for evidence_id in by_requirement[requirement]:
            new_uncovered = uncovered - frozenset(coverage[evidence_id])
            search(
                new_uncovered,
                (*selected, evidence_id),
                current_cost + item_index[evidence_id].cost,
            )

    search(universe, (), 0.0)
    if best_ids is None:
        raise ValueError("no exact cover exists")
    return best_ids


def _greedy_weighted_cover(
    requirements: Sequence[str],
    items: Sequence[EvidenceItem],
    coverage: Mapping[str, set[str]],
) -> tuple[str, ...]:
    universe = set(requirements)
    item_index = _index_items(items)
    uncovered = set(universe)
    selected: list[str] = []
    while uncovered:
        candidates = []
        for item in items:
            new = coverage.get(item.evidence_id, set()).intersection(uncovered)
            if not new:
                continue
            denominator = item.cost if item.cost > 0 else 1e-12
            candidates.append(
                (
                    len(new) / denominator,
                    len(new),
                    -item.cost,
                    item.evidence_id,
                )
            )
        if not candidates:
            raise ValueError("no greedy cover exists")
        evidence_id = max(candidates)[3]
        selected.append(evidence_id)
        uncovered -= coverage[evidence_id]
    return tuple(selected)


def _remove_redundancy(
    selected: Sequence[str],
    requirements: Sequence[str],
    coverage: Mapping[str, set[str]],
    item_index: Mapping[str, EvidenceItem],
) -> tuple[str, ...]:
    required = set(requirements)
    kept = list(dict.fromkeys(selected))
    # Prefer dropping expensive evidence when two items became redundant.
    for evidence_id in sorted(
        tuple(kept),
        key=lambda value: (-item_index[value].cost, value),
    ):
        reduced = [value for value in kept if value != evidence_id]
        if required.issubset(_covered_by(reduced, coverage)):
            kept = reduced
    return tuple(sorted(kept))


def brute_force_minimum_cost(
    requirements: Sequence[str],
    evidence: Sequence[EvidenceItem],
    coverage: Mapping[str, set[str]],
) -> float:
    """Small-fixture oracle used to independently audit the exact solver."""
    universe = set(requirements)
    best = float("inf")
    # Do not return at the first cardinality: weights, not size, are primary.
    for size in range(len(evidence) + 1):
        for subset in combinations(evidence, size):
            ids = tuple(item.evidence_id for item in subset)
            if universe.issubset(_covered_by(ids, coverage)):
                best = min(best, sum(item.cost for item in subset))
    if best == float("inf"):
        raise ValueError("no cover exists")
    return best
