from pathlib import Path
import unittest

from src.agent.runtime_tool_contract_audit import (
    run_runtime_tool_contract_audit,
)


ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT
    / "data"
    / "real_sources"
    / "annotation"
    / "expanded_full_pool_v0_5_unlabeled.json"
)


class RuntimeToolContractAuditTests(unittest.TestCase):
    def test_label_free_audit_is_not_an_effectiveness_result(self):
        result = run_runtime_tool_contract_audit(
            ROOT, PACKET, budget=30, limit=1
        )
        self.assertTrue(result["audit_valid"])
        self.assertFalse(result["research_effectiveness_result"])
        self.assertEqual(5, result["tool_calls_exercised"])
        self.assertEqual(0, result["tool_contract_failure_count"])
        self.assertEqual(0, result["backend_mismatch_count"])
        self.assertEqual(0, result["policy_leakage_failure_count"])


if __name__ == "__main__":
    unittest.main()
