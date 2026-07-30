import json
import unittest
from pathlib import Path

from scripts.data.audit_deterministic_config_sources import audit_sources
from src.verification.deterministic_exposure import (
    AnalyzerObservation,
    ProbeObservation,
    evaluate_exposure_claim,
    evaluate_exposure_path,
)


ROOT = Path(__file__).resolve().parents[1]


class DeterministicExposureTests(unittest.TestCase):
    def test_absent_analyzer_finding_is_unknown_not_negative(self):
        verdict = evaluate_exposure_claim(
            "anonymous-can-list",
            frozen_config_refs=("sha256:config",),
            analyzer_observations=(
                AnalyzerObservation(
                    observation_id="a1",
                    result="not_found",
                    scope="complete",
                    raw_ref="sha256:analyzer",
                    provider="AWS",
                    tool="Access Analyzer",
                ),
            ),
        )

        self.assertEqual("Unknown", verdict.configuration.state)
        self.assertIsNone(verdict.strongest_gold_tier)
        self.assertEqual(
            ("sha256:analyzer",),
            verdict.configuration.ignored_refs,
        )

    def test_explicit_complete_scope_deny_is_configuration_gold(self):
        verdict = evaluate_exposure_claim(
            "anonymous-can-list",
            frozen_config_refs=("sha256:config",),
            analyzer_observations=(
                AnalyzerObservation(
                    observation_id="a1",
                    result="deny",
                    scope="complete",
                    raw_ref="sha256:deny",
                    provider="GCP",
                    tool="testIamPermissions",
                ),
            ),
        )

        self.assertEqual("Contradicted", verdict.configuration.state)
        self.assertEqual("configuration_gold", verdict.strongest_gold_tier)

    def test_success_requires_matching_audit_record_for_runtime_gold(self):
        without_audit = evaluate_exposure_claim(
            "principal-can-read",
            frozen_config_refs=("sha256:config",),
            probe_observations=(
                ProbeObservation(
                    observation_id="p1",
                    result="success",
                    scope="complete",
                    raw_ref="sha256:response",
                ),
            ),
        )
        with_audit = evaluate_exposure_claim(
            "principal-can-read",
            frozen_config_refs=("sha256:config",),
            probe_observations=(
                ProbeObservation(
                    observation_id="p1",
                    result="success",
                    scope="complete",
                    raw_ref="sha256:response",
                    audit_ref="sha256:audit-event",
                ),
            ),
        )

        self.assertEqual("Unknown", without_audit.runtime.state)
        self.assertEqual("Supported", with_audit.runtime.state)
        self.assertEqual("runtime_gold", with_audit.strongest_gold_tier)

    def test_conflicting_oracle_results_are_preserved(self):
        verdict = evaluate_exposure_claim(
            "principal-can-read",
            frozen_config_refs=("sha256:config",),
            analyzer_observations=(
                AnalyzerObservation(
                    observation_id="allow",
                    result="allow",
                    scope="complete",
                    raw_ref="sha256:allow",
                    provider="Azure",
                    tool="RBAC",
                ),
                AnalyzerObservation(
                    observation_id="deny",
                    result="deny",
                    scope="complete",
                    raw_ref="sha256:deny",
                    provider="Azure",
                    tool="Defender",
                ),
            ),
        )

        self.assertEqual("Conflict", verdict.configuration.state)
        self.assertIsNone(verdict.strongest_gold_tier)

    def test_one_explicitly_denied_mandatory_edge_blocks_path(self):
        supported = evaluate_exposure_claim(
            "entry",
            frozen_config_refs=("sha256:config",),
            analyzer_observations=(
                AnalyzerObservation(
                    observation_id="allow",
                    result="allow",
                    scope="complete",
                    raw_ref="sha256:allow",
                    provider="AWS",
                    tool="Access Analyzer",
                ),
            ),
        )
        denied = evaluate_exposure_claim(
            "data-read",
            frozen_config_refs=("sha256:config",),
            analyzer_observations=(
                AnalyzerObservation(
                    observation_id="deny",
                    result="deny",
                    scope="complete",
                    raw_ref="sha256:deny",
                    provider="AWS",
                    tool="Access Analyzer",
                ),
            ),
        )

        path = evaluate_exposure_path("p1", (supported, denied))
        self.assertEqual("NotReachable", path.configuration_state)
        self.assertEqual("configuration_gold", path.strongest_gold_tier)

    def test_frozen_source_references_are_real_but_candidates_stay_unlabeled(self):
        report = audit_sources()
        candidates = json.loads(
            (
                ROOT
                / "data"
                / "real_sources"
                / "deterministic_config_candidates_v1.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(7, report["summary"]["frozen_sources"])
        self.assertEqual(10, report["summary"]["candidate_cases"])
        self.assertEqual(0, report["summary"]["runtime_gold_cases"])
        self.assertEqual(0, report["summary"]["configuration_gold_cases"])
        self.assertTrue(
            all(case["gold_label"] is None for case in candidates["cases"])
        )
        self.assertTrue(
            all(case["label_origin"] is None for case in candidates["cases"])
        )


if __name__ == "__main__":
    unittest.main()
