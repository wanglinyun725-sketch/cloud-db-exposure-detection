import unittest

from src.verification.provider_oracles import (
    OracleClaim,
    build_aws_simulate_principal_policy_command,
    parse_aws_simulate_principal_policy,
    parse_azure_defender_attack_paths,
    parse_gcp_test_iam_permissions,
)


class ProviderOracleTests(unittest.TestCase):
    def test_aws_command_is_exact_and_argv_safe(self):
        claim = OracleClaim(
            query_id="q1",
            provider="AWS",
            principal="arn:aws:iam::123456789012:role/lab",
            action="dynamodb:Scan",
            resource="arn:aws:dynamodb:us-east-1:123456789012:table/blog-users",
        )

        command = build_aws_simulate_principal_policy_command(claim)
        self.assertIsInstance(command, list)
        self.assertIn(claim.action, command)
        self.assertIn(claim.resource, command)
        self.assertNotIn("shell=True", command)

    def test_aws_missing_context_downgrades_allow_to_partial_scope(self):
        claim = OracleClaim(
            query_id="q1",
            provider="AWS",
            principal="arn:aws:iam::123456789012:role/lab",
            action="dynamodb:Scan",
            resource="arn:aws:dynamodb:us-east-1:123456789012:table/blog-users",
        )
        observation = parse_aws_simulate_principal_policy(
            claim,
            {
                "EvaluationResults": [
                    {
                        "EvalActionName": claim.action,
                        "EvalResourceName": claim.resource,
                        "EvalDecision": "allowed",
                        "MissingContextValues": ["aws:SourceVpce"],
                    }
                ]
            },
            raw_ref="sha256:aws",
            policy_scope_complete=True,
        )

        self.assertEqual("allow", observation.result)
        self.assertEqual("partial", observation.scope)

    def test_gcp_test_permissions_can_prove_allow_and_deny_for_caller(self):
        claim = OracleClaim(
            query_id="q1",
            provider="GCP",
            principal="allUsers",
            action="storage.objects.list",
            resource="//storage.googleapis.com/dev-bucket",
        )
        denied = parse_gcp_test_iam_permissions(
            claim,
            {"permissions": ["storage.buckets.get"]},
            raw_ref="sha256:t0",
            authenticated_principal="allUsers",
        )
        allowed = parse_gcp_test_iam_permissions(
            claim,
            {"permissions": ["storage.objects.list"]},
            raw_ref="sha256:t1",
            authenticated_principal="allUsers",
        )

        self.assertEqual(("deny", "complete"), (denied.result, denied.scope))
        self.assertEqual(("allow", "complete"), (allowed.result, allowed.scope))

    def test_gcp_result_for_different_caller_is_not_reused(self):
        claim = OracleClaim(
            query_id="q1",
            provider="GCP",
            principal="allUsers",
            action="storage.objects.list",
            resource="//storage.googleapis.com/dev-bucket",
        )
        observation = parse_gcp_test_iam_permissions(
            claim,
            {"permissions": ["storage.objects.list"]},
            raw_ref="sha256:user",
            authenticated_principal="user:student@example.com",
        )

        self.assertEqual("error", observation.result)
        self.assertEqual("unknown", observation.scope)

    def test_azure_unmatched_attack_path_is_unknown_not_deny(self):
        claim = OracleClaim(
            query_id="q1",
            provider="Azure",
            principal="internet",
            action="read",
            resource="cosmos-account",
        )
        observation = parse_azure_defender_attack_paths(
            claim,
            {"data": []},
            raw_ref="sha256:azure",
        )

        self.assertEqual("not_found", observation.result)
        self.assertEqual("unknown", observation.scope)


if __name__ == "__main__":
    unittest.main()
