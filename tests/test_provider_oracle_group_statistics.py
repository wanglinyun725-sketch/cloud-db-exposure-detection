import unittest

from scripts.experiments.run_provider_oracle_protocol_v3 import summarize


def _row(
    group: str,
    case_id: str,
    *,
    correct: bool,
    repeat: int = 0,
) -> dict:
    return {
        "method_id": "method",
        "budget": 4,
        "case_id": case_id,
        "repeat": repeat,
        "independence_group": group,
        "score": {
            "provider_oracle_gold": True,
            "epistemic_control": False,
            "gold_state": "Reachable",
            "state_correct": correct,
            "semantically_correct_state": correct,
            "correct_rejection": False,
            "correct_abstention": False,
            "false_reachable": False,
            "query_cost": 2,
            "gold_path_edge_f1": 1.0 if correct else 0.0,
        },
    }


class ProviderOracleGroupStatisticsTests(unittest.TestCase):
    def test_duplicate_cases_do_not_inflate_independent_accuracy(self):
        rows = [
            _row("group-a", "a-1", correct=True),
            _row("group-a", "a-2", correct=True),
            _row("group-b", "b-1", correct=False),
        ]

        summary = summarize(rows)[0]

        self.assertEqual(2, summary["effective_provider_gold_groups"])
        self.assertEqual(0.5, summary["provider_gold_state_accuracy"])
        self.assertAlmostEqual(
            2 / 3,
            summary["diagnostic_case_run_metrics"][
                "provider_gold_state_accuracy"
            ],
        )

    def test_one_failed_repeat_fails_the_lineage(self):
        rows = [
            _row("group-a", "a", correct=True, repeat=0),
            _row("group-a", "a", correct=False, repeat=1),
        ]

        summary = summarize(rows)[0]

        self.assertEqual(0.0, summary["provider_gold_state_accuracy"])
        low, high = summary["provider_gold_state_accuracy_ci95"]
        self.assertEqual(0.0, low)
        self.assertGreater(high, 0.0)


if __name__ == "__main__":
    unittest.main()
