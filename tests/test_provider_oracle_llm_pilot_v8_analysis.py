import unittest

from scripts.experiments.analyze_provider_oracle_llm_pilot_v8 import (
    _collapse_groups,
    _exact_mcnemar,
    _paired_counts,
)


def _row(method, group, gold, semantic, abstain, false_reachable=False):
    return {
        "method_id": method,
        "independence_group": group,
        "score": {
            "provider_oracle_gold": gold,
            "semantically_correct_state": semantic,
            "correct_abstention": abstain,
            "false_reachable": false_reachable,
        },
    }


class ProviderOracleLLMV8AnalysisTests(unittest.TestCase):
    def test_repeats_and_cases_collapse_to_one_strict_group(self):
        rows = [
            _row("m", "g", True, True, False),
            _row("m", "g", False, False, True),
            _row("m", "g", False, False, False, True),
        ]

        collapsed = _collapse_groups(rows)

        self.assertEqual(1, len(collapsed["m"]))
        self.assertFalse(collapsed["m"]["g"]["protocol_correct"])
        self.assertTrue(collapsed["m"]["g"]["false_reachable"])
        self.assertEqual(3, collapsed["m"]["g"]["run_count"])

    def test_paired_counts_use_only_common_independence_groups(self):
        primary = {
            "g1": {"protocol_correct": True},
            "g2": {"protocol_correct": False},
            "g3": {"protocol_correct": True},
        }
        comparator = {
            "g1": {"protocol_correct": False},
            "g2": {"protocol_correct": True},
            "g4": {"protocol_correct": False},
        }

        result = _paired_counts(primary, comparator)

        self.assertEqual(2, result["paired_independence_groups"])
        self.assertEqual(1, result["primary_wins"])
        self.assertEqual(1, result["comparator_wins"])
        self.assertEqual(0, result["ties"])
        self.assertEqual(1.0, result["p_exact_mcnemar"])

    def test_exact_mcnemar_is_conservative_for_tiny_pilot(self):
        self.assertEqual(1.0, _exact_mcnemar(1, 0))
        self.assertEqual(0.125, _exact_mcnemar(4, 0))
        self.assertEqual(1.0, _exact_mcnemar(0, 0))


if __name__ == "__main__":
    unittest.main()
