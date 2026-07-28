import unittest

from src.graph.path_ontology import (
    canonicalize_type,
    coarse_type,
    load_path_ontology,
    ontology_reference,
    validate_canonical_gold_types,
)


class PathOntologyTests(unittest.TestCase):
    def test_ontology_is_hash_frozen_and_aliases_are_explicit(self):
        ontology = load_path_ontology()
        reference = ontology_reference()

        self.assertEqual("cloud_data_path_v1", reference["ontology_id"])
        self.assertRegex(reference["sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(len(ontology["node_types"]), 10)
        self.assertGreater(len(ontology["edge_types"]), 20)
        self.assertEqual(
            "database",
            canonicalize_type("DB", "node", allow_alias=True),
        )
        self.assertIsNone(
            canonicalize_type("DB", "node", allow_alias=False)
        )
        self.assertEqual(
            "access_data",
            canonicalize_type("data_access", "edge", allow_alias=True),
        )

    def test_coarse_families_are_secondary_not_fine_type_merges(self):
        self.assertEqual("data_target", coarse_type("database", "node"))
        self.assertEqual("data_target", coarse_type("object_storage", "node"))
        self.assertNotEqual(
            canonicalize_type("database", "node", allow_alias=True),
            canonicalize_type(
                "object_storage",
                "node",
                allow_alias=True,
            ),
        )

    def test_human_gold_requires_canonical_ids(self):
        errors = validate_canonical_gold_types({
            "nodes": [
                {"type": "Identity"},
                {"type": "database"},
            ],
            "edges": [{"type": "data_access"}],
        })

        self.assertEqual(2, len(errors))
        self.assertIn("use identity", errors[0])
        self.assertIn("use access_data", errors[1])


if __name__ == "__main__":
    unittest.main()
