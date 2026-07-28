import unittest

from src.verification.cp_cert import (
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


if __name__ == "__main__":
    unittest.main()
