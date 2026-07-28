import unittest

from scripts.experiments.audit_research_readiness import build_audit


class ResearchReadinessAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = build_audit()

    def test_zero_human_gold_cannot_be_scored_as_excellent(self):
        self.assertEqual(
            0, self.audit["dataset"]["human_finalized_gold_cases"]
        )
        self.assertFalse(self.audit["excellent_now"])
        self.assertFalse(
            self.audit["excellent_hard_gates"][
                "human_gold_effectiveness_results_exist"
            ]
        )

    def test_engineering_audits_are_not_effectiveness_results(self):
        self.assertFalse(
            self.audit["method"][
                "protocol_research_effectiveness_result"
            ]
        )
        self.assertFalse(
            self.audit["method"]["pareto_research_effectiveness_result"]
        )
        self.assertFalse(
            self.audit["method"][
                "all_source_runtime_research_effectiveness_result"
            ]
        )
        self.assertFalse(
            self.audit["method"][
                "unlabeled_main_research_effectiveness_result"
            ]
        )
        self.assertTrue(
            self.audit["method"]["all_source_runtime_contract_valid"]
        )
        self.assertTrue(
            self.audit["method"]["unlabeled_main_dry_run_valid"]
        )
        self.assertTrue(
            self.audit["excellent_hard_gates"][
                "non_llm_main_execution_contract_valid"
            ]
        )
        self.assertEqual(
            91,
            self.audit["method"]["unlabeled_main_runtime_instances"],
        )
        self.assertEqual(
            1911,
            self.audit["method"]["unlabeled_main_scheduled_runs"],
        )
        self.assertEqual(
            1911,
            self.audit["method"]["unlabeled_main_completed_runs"],
        )
        self.assertEqual(
            0,
            self.audit["method"][
                "unlabeled_main_backend_mismatch_count"
            ],
        )
        self.assertEqual(
            0,
            self.audit["method"][
                "unlabeled_main_budget_violation_count"
            ],
        )
        self.assertEqual(
            0,
            self.audit["method"][
                "unlabeled_main_execution_failure_count"
            ],
        )
        self.assertEqual(
            0,
            self.audit["method"][
                "all_source_tool_contract_failure_count"
            ],
        )
        self.assertEqual(
            91,
            self.audit["method"]["runtime_payload_capable_instances"],
        )
        self.assertEqual(
            0,
            self.audit["method"]["runtime_payload_limited_instances"],
        )
        self.assertEqual(
            [
                "scenario_source_id",
                "runtime_evidence_source_id",
                "platform",
                "split",
            ],
            self.audit["method"]["required_reporting_slices"],
        )
        self.assertEqual(
            5,
            self.audit["method"]["source_heterogeneity"][
                "minimum_independence_groups_per_source"
            ],
        )

    def test_real_candidate_and_runtime_counts_are_current(self):
        self.assertEqual(150, self.audit["dataset"]["candidate_cases"])
        self.assertEqual(113, self.audit["dataset"]["independence_groups"])
        self.assertEqual(91, self.audit["dataset"]["runtime_instances"])
        self.assertEqual(
            {
                "cross_cloud_observability_2026": 36,
                "otrf_security_datasets": 1,
                "splunk_attack_data": 9,
                "stratus_red_team": 11,
            },
            self.audit["dataset"]["runtime_source_case_counts"],
        )
        self.assertEqual(35, self.audit["runtime_pilot"][
            "runtime_instance_count"
        ])


if __name__ == "__main__":
    unittest.main()
