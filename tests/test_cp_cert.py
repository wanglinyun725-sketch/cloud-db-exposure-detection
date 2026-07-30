from dataclasses import replace
from itertools import product
import random
import unittest

from src.verification.cp_cert import (
    Certificate,
    EvidenceItem,
    FourValue,
    brute_force_minimum_cost,
    build_negative_certificate,
    build_positive_certificate,
    fuse_claims,
    verify_certificate,
    verify_path_claims,
)


def item(evidence_id, polarity, claims, cost=1.0):
    return EvidenceItem(
        evidence_id=evidence_id,
        polarity=polarity,
        claim_ids=tuple(claims),
        raw_ref=f"sha256:fixture/{evidence_id}",
        cost=cost,
        source="verification_fixture",
    )


class FourValuedVerificationTests(unittest.TestCase):
    def test_all_four_states_are_distinct(self):
        evidence = [
            item("s1", "support", ["supported"]),
            item("s2", "support", ["conflict"]),
            item("r1", "refute", ["refuted"]),
            item("r2", "refute", ["conflict"]),
        ]
        states = fuse_claims(
            evidence,
            ["unknown", "supported", "refuted", "conflict"],
        )

        self.assertEqual(FourValue.UNKNOWN, states["unknown"])
        self.assertEqual(FourValue.SUPPORTED, states["supported"])
        self.assertEqual(FourValue.REFUTED, states["refuted"])
        self.assertEqual(FourValue.CONFLICT, states["conflict"])

    def test_information_join_preserves_conflict(self):
        self.assertEqual(
            FourValue.CONFLICT,
            FourValue.SUPPORTED.join(FourValue.REFUTED),
        )
        self.assertEqual(
            FourValue.CONFLICT,
            FourValue.CONFLICT.join(FourValue.SUPPORTED),
        )

    def test_information_join_obeys_semilattice_laws_exhaustively(self):
        values = tuple(FourValue)
        for left, right, third in product(values, repeat=3):
            self.assertEqual(left.join(right), right.join(left))
            self.assertEqual(left.join(left), left)
            self.assertEqual(
                left.join(right).join(third),
                left.join(right.join(third)),
            )
            self.assertEqual(left, left.join(FourValue.UNKNOWN))

    def test_path_verdict_does_not_treat_unknown_as_refutation(self):
        verdict = verify_path_claims(
            "p1",
            ["entry", "permission"],
            [item("s1", "support", ["entry"])],
        )

        self.assertEqual("Insufficient", verdict.state)
        self.assertEqual(("permission",), verdict.unknown_claims)
        self.assertEqual((), verdict.refuted_claims)

    def test_conflict_has_precedence_and_remains_auditable(self):
        verdict = verify_path_claims(
            "p1",
            ["entry", "permission"],
            [
                item("s1", "support", ["entry", "permission"]),
                item("r1", "refute", ["permission"]),
            ],
        )

        self.assertEqual("Conflict", verdict.state)
        self.assertEqual(("permission",), verdict.conflict_claims)


class CertificateTests(unittest.TestCase):
    def test_exact_positive_certificate_uses_shared_evidence(self):
        evidence = [
            item("shared", "support", ["entry", "reach"], cost=2),
            item("entry", "support", ["entry"], cost=1.5),
            item("reach", "support", ["reach"], cost=1.5),
            item("permission", "support", ["permission"], cost=1),
        ]

        certificate = build_positive_certificate(
            "p1",
            ["entry", "reach", "permission"],
            evidence,
        )

        self.assertEqual(("permission", "shared"), certificate.evidence_ids)
        self.assertEqual(3, certificate.total_cost)
        self.assertTrue(certificate.sufficient)
        self.assertTrue(certificate.irreducible)
        self.assertTrue(certificate.optimal)

    def test_positive_certificate_rejects_conflicted_path(self):
        evidence = [
            item("s1", "support", ["permission"]),
            item("r1", "refute", ["permission"]),
        ]

        with self.assertRaisesRegex(ValueError, "Conflict"):
            build_positive_certificate("p1", ["permission"], evidence)

    def test_exact_negative_certificate_matches_independent_oracle(self):
        paths = {
            "p1": ["a", "b"],
            "p2": ["b", "c"],
            "p3": ["d"],
        }
        evidence = [
            item("r-a", "refute", ["a"], cost=1),
            item("r-b", "refute", ["b"], cost=1.7),
            item("r-cd", "refute", ["c", "d"], cost=2),
            item("r-d", "refute", ["d"], cost=1.2),
        ]
        coverage = {
            evidence_item.evidence_id: {
                path_id
                for path_id, claims in paths.items()
                if set(evidence_item.claim_ids).intersection(claims)
            }
            for evidence_item in evidence
        }

        certificate = build_negative_certificate(paths, evidence, method="exact")
        oracle_cost = brute_force_minimum_cost(
            tuple(paths),
            evidence,
            coverage,
        )

        self.assertEqual(oracle_cost, certificate.total_cost)
        self.assertEqual(("r-b", "r-d"), certificate.evidence_ids)
        self.assertTrue(certificate.sufficient)
        self.assertTrue(certificate.irreducible)

        audit = verify_certificate(certificate, evidence, coverage)
        self.assertTrue(audit["sufficient"])
        self.assertTrue(audit["irreducible"])
        self.assertTrue(audit["raw_refs_complete"])
        self.assertTrue(audit["cost_matches"])
        self.assertTrue(audit["certificate_id_matches"])
        self.assertTrue(audit["required_requirements_match"])
        self.assertTrue(audit["optimality_verified"])
        self.assertTrue(audit["valid"])

    def test_unknown_evidence_cannot_create_negative_certificate(self):
        paths = {"p1": ["a"], "p2": ["b"]}
        only_partial_refutation = [
            item("r-a", "refute", ["a"]),
            item("s-b", "support", ["b"]),
        ]

        with self.assertRaisesRegex(ValueError, "p2"):
            build_negative_certificate(paths, only_partial_refutation)

    def test_greedy_certificate_reports_bound_and_passes_deletion_test(self):
        paths = {
            "p1": ["a"],
            "p2": ["b"],
            "p3": ["c"],
            "p4": ["d"],
        }
        evidence = [
            item("r-ab", "refute", ["a", "b"], cost=1),
            item("r-cd", "refute", ["c", "d"], cost=1),
            item("r-all-expensive", "refute", ["a", "b", "c", "d"], cost=3),
        ]
        certificate = build_negative_certificate(
            paths,
            evidence,
            method="greedy",
        )

        self.assertFalse(certificate.optimal)
        self.assertIsNotNone(certificate.approximation_bound)
        self.assertTrue(certificate.sufficient)
        self.assertTrue(certificate.irreducible)
        self.assertEqual(("r-ab", "r-cd"), certificate.evidence_ids)

    def test_evidence_without_raw_reference_is_forbidden(self):
        with self.assertRaisesRegex(ValueError, "raw_ref"):
            EvidenceItem(
                evidence_id="bad",
                polarity="support",
                claim_ids=("entry",),
                raw_ref="",
            )

    def test_verifier_rejects_tampered_identity_refs_and_requirements(self):
        evidence = [
            item("s-entry", "support", ["entry"], cost=1),
            item("s-reach", "support", ["reach"], cost=1),
        ]
        coverage = {
            value.evidence_id: set(value.claim_ids)
            for value in evidence
        }
        certificate = build_positive_certificate(
            "p1",
            ["entry", "reach"],
            evidence,
        )

        tampered = (
            replace(certificate, certificate_id="cp-tampered"),
            replace(certificate, raw_refs=("sha256:wrong",)),
            replace(certificate, required_requirements=("entry",)),
            replace(certificate, sufficient=False),
        )
        audits = [
            verify_certificate(value, evidence, coverage)
            for value in tampered
        ]

        self.assertTrue(all(not audit["valid"] for audit in audits))
        self.assertFalse(audits[0]["certificate_id_matches"])
        self.assertFalse(audits[1]["raw_refs_match"])
        self.assertFalse(audits[2]["required_requirements_match"])
        self.assertFalse(audits[3]["certificate_claims_match"])

    def test_structural_validity_is_separate_from_oracle_coverage(self):
        evidence = [
            item(
                f"s-{index}",
                "support",
                [f"r-{index}"],
                cost=1,
            )
            for index in range(19)
        ]
        requirements = [f"r-{index}" for index in range(19)]
        coverage = {
            value.evidence_id: set(value.claim_ids)
            for value in evidence
        }
        certificate = build_positive_certificate(
            "large",
            requirements,
            evidence,
        )

        audit = verify_certificate(certificate, evidence, coverage)

        self.assertTrue(audit["valid"])
        self.assertIsNone(audit["optimality_verified"])
        self.assertTrue(audit["optimality_claim_valid"])

    def test_empty_requirement_certificate_is_never_valid(self):
        certificate = Certificate(
            certificate_id="cp-empty",
            kind="positive",
            method="exact",
            evidence_ids=(),
            raw_refs=(),
            total_cost=0,
            covered_requirements=(),
            required_requirements=(),
            sufficient=True,
            irreducible=True,
            optimal=True,
            approximation_bound=None,
            semantics="empty",
        )

        audit = verify_certificate(certificate, [], {})

        self.assertFalse(audit["requirements_nonempty"])
        self.assertFalse(audit["valid"])

    def test_exact_and_greedy_properties_hold_on_deterministic_small_covers(self):
        rng = random.Random(20260730)
        for fixture_index in range(80):
            requirements = [f"r{index}" for index in range(5)]
            paths = {
                f"p{index}": [requirement]
                for index, requirement in enumerate(requirements)
            }
            evidence = [
                item(
                    f"singleton-{fixture_index}-{index}",
                    "refute",
                    [requirement],
                    cost=round(rng.uniform(0.5, 3.0), 3),
                )
                for index, requirement in enumerate(requirements)
            ]
            for extra_index in range(5):
                claims = [
                    requirement
                    for requirement in requirements
                    if rng.random() < 0.5
                ] or [rng.choice(requirements)]
                evidence.append(item(
                    f"shared-{fixture_index}-{extra_index}",
                    "refute",
                    claims,
                    cost=round(rng.uniform(0.5, 4.0), 3),
                ))
            coverage = {
                value.evidence_id: {
                    path_id
                    for path_id, premises in paths.items()
                    if set(value.claim_ids).intersection(premises)
                }
                for value in evidence
            }

            exact = build_negative_certificate(
                paths,
                evidence,
                method="exact",
            )
            greedy = build_negative_certificate(
                paths,
                evidence,
                method="greedy",
            )
            oracle = brute_force_minimum_cost(
                tuple(paths),
                evidence,
                coverage,
            )
            exact_audit = verify_certificate(exact, evidence, coverage)
            greedy_audit = verify_certificate(greedy, evidence, coverage)

            self.assertAlmostEqual(oracle, exact.total_cost)
            self.assertTrue(exact_audit["valid"])
            self.assertTrue(exact_audit["optimality_verified"])
            self.assertTrue(greedy_audit["valid"])
            self.assertTrue(
                greedy_audit["approximation_bound_satisfied"]
            )


if __name__ == "__main__":
    unittest.main()
