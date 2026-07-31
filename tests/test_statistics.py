import unittest

from scripts.experiments.run_statistical_tests import (
    apply_holm_correction,
    bootstrap_confidence_interval,
    paired_sign_flip_test,
)
from scripts.experiments.run_source_robustness import heterogeneity_permutation_test


class StatisticalMethodTests(unittest.TestCase):
    def test_bootstrap_uses_observed_values(self):
        result = bootstrap_confidence_interval([0.0, 0.0, 1.0, 1.0], n_bootstrap=1000)

        self.assertEqual(4, result["n"])
        self.assertEqual(0.5, result["mean"])
        self.assertLessEqual(result["ci_lower"], result["mean"])
        self.assertGreaterEqual(result["ci_upper"], result["mean"])

    def test_paired_test_reports_observed_difference(self):
        baseline = [0.0, 0.1, 0.0, 0.2, 0.1, 0.0]
        treatment = [0.8, 0.9, 1.0, 0.9, 0.8, 1.0]
        result = paired_sign_flip_test(
            baseline,
            treatment,
            n_permutations=5000,
        )

        self.assertEqual(6, result["n_pairs"])
        self.assertAlmostEqual(
            sum(t - b for b, t in zip(baseline, treatment)) / 6,
            result["mean_difference"],
        )
        self.assertLess(result["p_value"], 0.05)

    def test_holm_adjustment_is_monotonic(self):
        results = {
            "a": {"p_value": 0.001},
            "b": {"p_value": 0.01},
            "c": {"p_value": 0.04},
        }
        apply_holm_correction(results)

        adjusted = [
            results[key]["p_value_adjusted"]
            for key in ("a", "b", "c")
        ]
        self.assertEqual(sorted(adjusted), adjusted)

    def test_heterogeneity_test_detects_opposite_source_gains(self):
        result = heterogeneity_permutation_test(
            [0.8, 0.9, 1.0, 0.7, 0.9],
            [-0.8, -0.9, -1.0, -0.7, -0.9],
            n_permutations=5000,
        )

        self.assertGreater(result["source_difference_in_gain"], 1.0)
        self.assertLess(result["p_value"], 0.05)


if __name__ == "__main__":
    unittest.main()
