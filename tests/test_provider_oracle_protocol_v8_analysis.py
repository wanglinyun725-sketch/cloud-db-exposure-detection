import json
from pathlib import Path
import unittest

from scripts.experiments.analyze_provider_oracle_protocol_v8 import (
    analyze,
)
from scripts.experiments.run_provider_oracle_protocol_v3 import run


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "provider_oracle_protocol_v8.json"


class ProviderOracleProtocolV8AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run(CONFIG)
        cls.analysis = analyze(cls.report)

    def test_analysis_uses_independence_groups_not_runs(self):
        self.assertEqual(600, self.analysis["run_records"])
        self.assertEqual(16, self.analysis["independence_groups"])
        self.assertTrue(self.analysis["pseudo_replication_guard"])
        self.assertFalse(
            self.analysis["research_effectiveness_result"]
        )

    def test_provider_reference_is_correct_but_not_overclaimed(self):
        summaries = {
            (item["method_id"], item["budget"]): item
            for item in self.analysis["summaries"]
        }
        reference = summaries[("provider_aware_cp_cert", 2)]
        self.assertEqual(1.0, reference[
            "protocol_correct_group_rate"
        ])
        self.assertEqual(0.0, reference[
            "unsafe_false_reachable_group_rate"
        ])
        self.assertLess(
            reference["protocol_correct_group_rate_ci95"][0],
            0.82,
        )
        full_query = summaries[("full_query", 2)]
        self.assertLess(
            full_query["protocol_correct_group_rate"],
            reference["protocol_correct_group_rate"],
        )

    def test_exact_comparisons_are_paired_and_holm_corrected(self):
        self.assertEqual(9, len(self.analysis["paired_comparisons"]))
        for item in self.analysis["paired_comparisons"]:
            self.assertEqual(16, item["paired_independence_groups"])
            self.assertGreaterEqual(
                item["p_holm_all_budget_baseline_comparisons"],
                item["p_exact_mcnemar"],
            )

    def test_new_cases_have_no_reference_failures(self):
        diagnostics = [
            item for item in self.analysis["new_case_diagnostics"]
            if item["method_id"] == "provider_aware_cp_cert"
        ]
        self.assertEqual(12, len(diagnostics))
        self.assertTrue(all(
            item["strict_semantic_or_abstention_correct"]
            for item in diagnostics
        ))
        self.assertTrue(all(
            item["false_reachable_runs"] == 0
            for item in diagnostics
        ))


if __name__ == "__main__":
    unittest.main()
