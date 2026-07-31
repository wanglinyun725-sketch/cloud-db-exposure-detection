"""Dependency-free sensitivity power analysis for the frozen main study.

The main inferential unit is an independent attack/configuration lineage.
Repeated seeds, events, paths, and cases inside a lineage never increase N.
"""
from __future__ import annotations

from math import comb
from statistics import NormalDist


def normal_paired_power(
    n_groups: int,
    effect_dz: float,
    *,
    alpha: float = 0.05,
    sided: int = 2,
) -> float:
    """Normal-approximation power for a paired standardized mean effect.

    This is a sensitivity calculation, not a promise that edge-F1
    differences are normally distributed. The frozen analysis will use a
    paired randomization test and cluster bootstrap confidence intervals.
    """
    if n_groups < 2:
        raise ValueError("n_groups must be at least two")
    if effect_dz < 0:
        raise ValueError("effect_dz must be non-negative")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between zero and one")
    if sided not in {1, 2}:
        raise ValueError("sided must be one or two")

    normal = NormalDist()
    shift = effect_dz * (n_groups ** 0.5)
    if sided == 1:
        critical = normal.inv_cdf(1 - alpha)
        return normal.cdf(shift - critical)
    critical = normal.inv_cdf(1 - alpha / 2)
    upper = normal.cdf(shift - critical)
    lower = normal.cdf(-shift - critical)
    return upper + lower


def exact_sign_power(
    n_groups: int,
    discordance_rate: float,
    treatment_win_share: float,
    *,
    alpha: float = 0.05,
    sided: int = 2,
) -> float:
    """Unconditional power of an exact paired sign test.

    Each independent group is a tie with probability ``1-discordance_rate``.
    Conditional on a non-tie, the treatment wins with probability
    ``treatment_win_share``. This prevents ties from being silently removed
    when planning the total number of lineages.
    """
    if n_groups < 1:
        raise ValueError("n_groups must be positive")
    if not 0 <= discordance_rate <= 1:
        raise ValueError("discordance_rate must be in [0, 1]")
    if not 0.5 <= treatment_win_share <= 1:
        raise ValueError("treatment_win_share must be in [0.5, 1]")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between zero and one")
    if sided not in {1, 2}:
        raise ValueError("sided must be one or two")

    power = 0.0
    for discordant in range(n_groups + 1):
        p_discordant = _binomial_pmf(
            discordant,
            n_groups,
            discordance_rate,
        )
        critical = _sign_test_critical_wins(
            discordant,
            alpha=alpha,
            sided=sided,
        )
        if critical is None:
            continue
        conditional_rejection = sum(
            _binomial_pmf(wins, discordant, treatment_win_share)
            for wins in range(critical, discordant + 1)
        )
        power += p_discordant * conditional_rejection
    return min(1.0, max(0.0, power))


def minimum_groups_for_normal_power(
    effect_dz: float,
    *,
    target_power: float = 0.8,
    alpha: float = 0.05,
    sided: int = 2,
    max_groups: int = 500,
) -> int | None:
    """Return the first N meeting a paired normal sensitivity target."""
    _validate_target_power(target_power)
    for n_groups in range(2, max_groups + 1):
        if normal_paired_power(
            n_groups,
            effect_dz,
            alpha=alpha,
            sided=sided,
        ) >= target_power:
            return n_groups
    return None


def minimum_detectable_normal_effect(
    n_groups: int,
    *,
    target_power: float = 0.8,
    alpha: float = 0.05,
    sided: int = 2,
    max_effect_dz: float = 10.0,
) -> float | None:
    """Return the smallest paired dz detectable at the requested power.

    This prospective sensitivity quantity depends only on N, alpha and the
    target power. It deliberately does not plug the observed effect back into
    a post-hoc power calculation.
    """
    if n_groups < 2:
        return None
    _validate_target_power(target_power)
    if max_effect_dz <= 0:
        raise ValueError("max_effect_dz must be positive")
    if normal_paired_power(
        n_groups,
        0.0,
        alpha=alpha,
        sided=sided,
    ) >= target_power:
        return 0.0
    if normal_paired_power(
        n_groups,
        max_effect_dz,
        alpha=alpha,
        sided=sided,
    ) < target_power:
        return None
    low = 0.0
    high = max_effect_dz
    for _ in range(80):
        midpoint = (low + high) / 2
        if normal_paired_power(
            n_groups,
            midpoint,
            alpha=alpha,
            sided=sided,
        ) >= target_power:
            high = midpoint
        else:
            low = midpoint
    return high


def minimum_groups_for_sign_power(
    discordance_rate: float,
    treatment_win_share: float,
    *,
    target_power: float = 0.8,
    alpha: float = 0.05,
    sided: int = 2,
    max_groups: int = 500,
) -> int | None:
    """Return the first total-lineage N meeting an exact-sign target."""
    _validate_target_power(target_power)
    for n_groups in range(1, max_groups + 1):
        if exact_sign_power(
            n_groups,
            discordance_rate,
            treatment_win_share,
            alpha=alpha,
            sided=sided,
        ) >= target_power:
            return n_groups
    return None


def _sign_test_critical_wins(
    discordant: int,
    *,
    alpha: float,
    sided: int,
) -> int | None:
    """Smallest treatment-win count significant under the null p=0.5."""
    if discordant == 0:
        return None
    for wins in range(discordant // 2 + 1, discordant + 1):
        upper_tail = sum(
            _binomial_pmf(value, discordant, 0.5)
            for value in range(wins, discordant + 1)
        )
        p_value = upper_tail if sided == 1 else min(1.0, 2 * upper_tail)
        if p_value <= alpha:
            return wins
    return None


def _binomial_pmf(successes: int, trials: int, probability: float) -> float:
    if successes < 0 or successes > trials:
        return 0.0
    if probability == 0:
        return 1.0 if successes == 0 else 0.0
    if probability == 1:
        return 1.0 if successes == trials else 0.0
    return (
        comb(trials, successes)
        * probability ** successes
        * (1 - probability) ** (trials - successes)
    )


def _validate_target_power(target_power: float) -> None:
    if not 0 < target_power < 1:
        raise ValueError("target_power must be between zero and one")
