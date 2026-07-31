from hashlib import sha256
import json
from pathlib import Path
import unittest

from scripts.data.build_sigma_cloud_operation_prior import build_prior
from src.agent.ec_react import pareto_action_candidates
from src.agent.sigma_semantic_prior import (
    DEFAULT_PRIOR_PATH,
    SIGMA_SEMANTIC_PRIOR,
)


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = (
    ROOT
    / "data"
    / "real_sources"
    / "raw"
    / "sigmahq"
    / "sigma-r2026-07-01.zip"
)


class SigmaSemanticPriorTests(unittest.TestCase):
    def test_pinned_archive_rebuilds_frozen_prior_exactly(self):
        frozen = json.loads(
            DEFAULT_PRIOR_PATH.read_text(encoding="utf-8")
        )
        digest = sha256(ARCHIVE.read_bytes()).hexdigest()

        self.assertEqual(
            frozen["source"]["archive_sha256"],
            digest,
        )
        self.assertEqual(frozen, build_prior(ARCHIVE))
        self.assertEqual("none", frozen["weighting"])
        self.assertEqual("none", frozen["label_usage"])
        self.assertTrue(
            frozen["extraction"]["filter_subtrees_excluded"]
        )
        self.assertGreater(
            frozen["extraction"]["excluded_filter_subtrees"],
            0,
        )

    def test_rule_support_is_platform_scoped_and_unweighted(self):
        aws_rules = SIGMA_SEMANTIC_PRIOR.matching_rule_ids(
            "DeleteBucket",
            "AWS",
        )

        self.assertTrue(aws_rules)
        self.assertEqual(
            len(aws_rules),
            SIGMA_SEMANTIC_PRIOR.score("DeleteBucket", "AWS"),
        )
        self.assertEqual(
            0,
            SIGMA_SEMANTIC_PRIOR.score("DeleteBucket", "GCP"),
        )
        self.assertEqual(
            0,
            SIGMA_SEMANTIC_PRIOR.score(
                "DefinitelyNotACloudOperation",
                "AWS",
            ),
        )

    def test_action_gain_is_distinct_sigma_rule_count(self):
        candidates = pareto_action_candidates(
            {"DeleteBucket": 10, "ListThings": 10},
            platform="AWS",
            apply_pareto=False,
        )
        by_operation = {
            item.arguments["operation"]: item
            for item in candidates
        }

        self.assertEqual(
            SIGMA_SEMANTIC_PRIOR.score("DeleteBucket", "AWS"),
            by_operation["DeleteBucket"].external_rule_gain,
        )
        self.assertEqual(
            0,
            by_operation["ListThings"].external_rule_gain,
        )


if __name__ == "__main__":
    unittest.main()
