from __future__ import annotations

import pytest

from src.experiments.power_analysis import (
    exact_sign_power,
    minimum_detectable_normal_effect,
    minimum_groups_for_normal_power,
    minimum_groups_for_sign_power,
    normal_paired_power,
)


def test_normal_power_increases_with_n_and_effect() -> None:
    small = normal_paired_power(30, 0.35)
    larger_n = normal_paired_power(60, 0.35)
    larger_effect = normal_paired_power(30, 0.65)
    assert 0 < small < larger_n < 1
    assert small < larger_effect < 1


def test_exact_sign_power_keeps_ties_in_total_n() -> None:
    no_discordance = exact_sign_power(40, 0.0, 0.9)
    moderate = exact_sign_power(40, 0.5, 0.75)
    more_information = exact_sign_power(40, 0.8, 0.75)
    assert no_discordance == 0.0
    assert 0 < moderate < more_information < 1


def test_minimum_sample_size_meets_target() -> None:
    normal_n = minimum_groups_for_normal_power(0.5)
    sign_n = minimum_groups_for_sign_power(0.5, 0.75)
    assert normal_n is not None
    assert sign_n is not None
    assert normal_paired_power(normal_n, 0.5) >= 0.8
    assert exact_sign_power(sign_n, 0.5, 0.75) >= 0.8
    if normal_n > 2:
        assert normal_paired_power(normal_n - 1, 0.5) < 0.8
    if sign_n > 1:
        assert exact_sign_power(sign_n - 1, 0.5, 0.75) < 0.8


def test_minimum_detectable_effect_is_prospective_and_shrinks_with_n() -> None:
    effect_15 = minimum_detectable_normal_effect(15)
    effect_30 = minimum_detectable_normal_effect(30)

    assert effect_15 is not None
    assert effect_30 is not None
    assert effect_30 < effect_15
    assert normal_paired_power(30, effect_30) >= 0.8
    assert normal_paired_power(30, effect_30 - 1e-5) < 0.8
    assert minimum_detectable_normal_effect(1) is None


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ((1, 0.5), "n_groups"),
        ((30, -0.1), "effect_dz"),
    ],
)
def test_normal_power_rejects_invalid_inputs(
    args: tuple[int, float],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        normal_paired_power(*args)


def test_exact_sign_power_rejects_invalid_probability() -> None:
    with pytest.raises(ValueError, match="discordance_rate"):
        exact_sign_power(30, 1.1, 0.8)
    with pytest.raises(ValueError, match="treatment_win_share"):
        exact_sign_power(30, 0.5, 0.4)
