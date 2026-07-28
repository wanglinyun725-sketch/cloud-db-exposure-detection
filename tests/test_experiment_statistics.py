import unittest

from src.experiments.statistics import analyze_frozen_runs


def _config():
    return {
        "methods": [
            {"method_id": "ec_react_full", "family": "llm"},
            {"method_id": "vanilla_react", "family": "llm"},
        ],
        "statistics": {
            "cluster_bootstrap_resamples": 200,
            "paired_permutation_resamples": 500,
            "confidence_level": 0.95,
        },
        "reporting": {
            "primary_metrics": [
                "exact_path_match",
                "mean_query_cost",
            ]
        },
    }


def _records():
    rows = []
    instance_groups = [
        ("g1-a", "g1"),
        ("g1-b", "g1"),
        ("g2-a", "g2"),
        ("g3-a", "g3"),
    ]
    for method in ("ec_react_full", "vanilla_react"):
        for instance_id, group in instance_groups:
            for repeat in range(2):
                full = method == "ec_react_full"
                run_id = f"{method}-{instance_id}-{repeat}"
                rows.append({
                    "run_id": run_id,
                    "schedule_id": "schedule-" + run_id,
                    "research_effectiveness_result": True,
                    "human_gold_used_for_scoring_only": True,
                    "config_sha256": "a" * 64,
                    "method_id": method,
                    "model_id": "model-a",
                    "budget": 10,
                    "split": "test",
                    "independence_group": group,
                    "case_id": "case-" + instance_id,
                    "instance_id": instance_id,
                    "score": {
                        "exact_path_match": full,
                        "query_cost": 2 if full else 5,
                    },
                })
    return rows


def _source_records():
    rows = []
    for source, platform in (
        ("source-a", "AWS"),
        ("source-b", "AZURE"),
    ):
        for index in range(6):
            group = f"{source}-g{index}"
            instance_id = f"{group}-i"
            for method in ("ec_react_full", "vanilla_react"):
                positive_gain = source == "source-a"
                exact = (
                    positive_gain
                    if method == "ec_react_full"
                    else not positive_gain
                )
                query_cost = (
                    2
                    if exact
                    else 5
                )
                run_id = f"{method}-{instance_id}"
                rows.append({
                    "run_id": run_id,
                    "schedule_id": "schedule-" + run_id,
                    "research_effectiveness_result": True,
                    "human_gold_used_for_scoring_only": True,
                    "config_sha256": "b" * 64,
                    "method_id": method,
                    "model_id": "model-a",
                    "budget": 10,
                    "split": "test",
                    "source_id": source,
                    "scenario_source_id": source,
                    "runtime_evidence_source_id": source,
                    "platform": platform,
                    "independence_group": group,
                    "case_id": "case-" + group,
                    "instance_id": instance_id,
                    "score": {
                        "exact_path_match": exact,
                        "query_cost": query_cost,
                    },
                })
    return rows


class ExperimentStatisticsTests(unittest.TestCase):
    def test_repeats_and_instances_are_collapsed_before_group_inference(self):
        report = analyze_frozen_runs(_records(), _config())

        self.assertEqual(16, report["run_records"])
        self.assertEqual(4, report["unique_runtime_instances"])
        self.assertEqual(3, report["unique_independence_groups"])
        self.assertTrue(report["pseudo_replication_guard"])
        self.assertTrue(all(
            item["independence_groups"] == 3
            for item in report["summaries"]
        ))
        comparisons = {
            item["metric"]: item
            for item in report["paired_comparisons"]
        }
        self.assertEqual(1.0, comparisons["exact_path_match"]["favorable_effect"])
        self.assertEqual(3.0, comparisons["mean_query_cost"]["favorable_effect"])
        self.assertTrue(all(
            item["paired_independence_groups"] == 3
            for item in comparisons.values()
        ))
        self.assertTrue(all(
            0 <= item["p_value"] <= item["p_holm"] <= 1
            for item in comparisons.values()
        ))

    def test_duplicate_run_record_is_rejected(self):
        records = _records()
        records.append(dict(records[0]))

        with self.assertRaisesRegex(ValueError, "run_id"):
            analyze_frozen_runs(records, _config())

    def test_ontology_sensitivity_is_summarized_not_hypothesis_tested(self):
        config = _config()
        config["reporting"]["secondary_metrics"] = [
            "coarse_exact_path_match",
        ]
        records = _records()
        for record in records:
            record["score"]["coarse_exact_path_match"] = True

        report = analyze_frozen_runs(records, config)

        self.assertIn(
            "coarse_exact_path_match",
            {item["metric"] for item in report["summaries"]},
        )
        self.assertNotIn(
            "coarse_exact_path_match",
            {item["metric"] for item in report["paired_comparisons"]},
        )
        self.assertFalse(
            report["secondary_metrics_used_for_hypothesis_tests"]
        )

    def test_source_slices_and_gain_heterogeneity_are_machine_reported(self):
        config = _config()
        config["reporting"]["primary_metrics"] = [
            "exact_path_match",
            "mean_query_cost",
        ]
        config["reporting"]["required_slices"] = [
            "scenario_source_id",
            "runtime_evidence_source_id",
            "platform",
            "split",
        ]
        config["statistics"]["source_heterogeneity"] = {
            "dimensions": [
                "scenario_source_id",
                "runtime_evidence_source_id",
            ],
            "baseline_method_id": "vanilla_react",
            "minimum_independence_groups_per_source": 5,
            "permutation_resamples": 2000,
        }

        report = analyze_frozen_runs(_source_records(), config)

        self.assertEqual(
            set(config["reporting"]["required_slices"]),
            {
                item["slice_dimension"]
                for item in report["slice_summaries"]
            },
        )
        gains = report["source_heterogeneity"][
            "source_gain_summaries"
        ]
        scenario_gains = {
            item["source"]: item["mean_favorable_gain"]
            for item in gains
            if (
                item["source_dimension"] == "scenario_source_id"
                and item["metric"] == "exact_path_match"
            )
        }
        self.assertEqual(
            {"source-a": 1.0, "source-b": -1.0},
            scenario_gains,
        )
        tests = report["source_heterogeneity"][
            "heterogeneity_tests"
        ]
        cost_gains = {
            item["source"]: item["mean_favorable_gain"]
            for item in gains
            if (
                item["source_dimension"] == "scenario_source_id"
                and item["metric"] == "mean_query_cost"
            )
        }
        self.assertEqual(
            {"source-a": 3.0, "source-b": -3.0},
            cost_gains,
        )
        self.assertEqual(4, len(tests))
        self.assertTrue(all(
            item["difference_in_mean_gain"] > 0
            and item["p_holm"] < 0.05
            for item in tests
        ))

    def test_required_slice_cannot_be_silently_missing(self):
        config = _config()
        config["reporting"]["required_slices"] = ["platform"]
        with self.assertRaisesRegex(ValueError, "required slice"):
            analyze_frozen_runs(_records(), config)


if __name__ == "__main__":
    unittest.main()
