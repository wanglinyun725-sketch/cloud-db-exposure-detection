"""Normalize provider-native authorization results into exposure evidence.

The parsers are intentionally narrow.  If a provider response cannot be tied
to the exact requested action/resource, it returns ``not_found`` or partial
scope rather than inventing a negative result.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from src.verification.deterministic_exposure import AnalyzerObservation


@dataclass(frozen=True)
class OracleClaim:
    query_id: str
    provider: str
    principal: str
    action: str
    resource: str

    def __post_init__(self) -> None:
        values = (
            self.query_id,
            self.provider,
            self.principal,
            self.action,
            self.resource,
        )
        if any(not value.strip() for value in values):
            raise ValueError("oracle claim fields must be non-empty")


def build_aws_simulate_principal_policy_command(
    claim: OracleClaim,
) -> list[str]:
    """Build an argv-safe AWS IAM simulation command for one exact claim."""
    if claim.provider.casefold() != "aws":
        raise ValueError("AWS command requires provider='AWS'")
    return [
        "aws",
        "iam",
        "simulate-principal-policy",
        "--policy-source-arn",
        claim.principal,
        "--action-names",
        claim.action,
        "--resource-arns",
        claim.resource,
        "--no-paginate",
        "--output",
        "json",
    ]


def parse_aws_simulate_principal_policy(
    claim: OracleClaim,
    payload: Mapping[str, Any],
    *,
    raw_ref: str,
    policy_scope_complete: bool,
) -> AnalyzerObservation:
    """Parse one exact AWS IAM simulator result.

    ``policy_scope_complete`` must be asserted only when all relevant policy
    families and required condition context were included.  The AWS simulator
    itself can differ from the live environment, so this produces
    configuration evidence, never runtime evidence.
    """
    matches = []
    for item in payload.get("EvaluationResults", []):
        if (
            item.get("EvalActionName") == claim.action
            and item.get("EvalResourceName") == claim.resource
        ):
            matches.append(item)
    if len(matches) != 1:
        return AnalyzerObservation(
            observation_id=claim.query_id,
            result="not_found",
            scope="unknown",
            raw_ref=raw_ref,
            provider="AWS",
            tool="IAM SimulatePrincipalPolicy",
        )

    match = matches[0]
    missing_context = match.get("MissingContextValues") or []
    scope = (
        "complete"
        if policy_scope_complete and not missing_context
        else "partial"
    )
    decision = match.get("EvalDecision")
    result_map = {
        "allowed": "allow",
        "explicitDeny": "deny",
        "implicitDeny": "deny",
    }
    result = result_map.get(decision, "error")
    return AnalyzerObservation(
        observation_id=claim.query_id,
        result=result,
        scope=scope,
        raw_ref=raw_ref,
        provider="AWS",
        tool="IAM SimulatePrincipalPolicy",
    )


def parse_gcp_test_iam_permissions(
    claim: OracleClaim,
    payload: Mapping[str, Any],
    *,
    raw_ref: str,
    authenticated_principal: str,
) -> AnalyzerObservation:
    """Parse a GCP testIamPermissions response for the current caller.

    The API returns the subset of requested permissions held by the caller.
    Therefore an absent exact permission is an explicit deny only when the
    claim principal is the authenticated caller and the response is complete.
    """
    if claim.provider.casefold() != "gcp":
        raise ValueError("GCP parser requires provider='GCP'")
    if claim.principal != authenticated_principal:
        return AnalyzerObservation(
            observation_id=claim.query_id,
            result="error",
            scope="unknown",
            raw_ref=raw_ref,
            provider="GCP",
            tool="testIamPermissions",
        )
    permissions = payload.get("permissions")
    if permissions is None:
        permissions = []
    if not isinstance(permissions, Sequence) or isinstance(
        permissions,
        (str, bytes),
    ):
        return AnalyzerObservation(
            observation_id=claim.query_id,
            result="error",
            scope="unknown",
            raw_ref=raw_ref,
            provider="GCP",
            tool="testIamPermissions",
        )
    return AnalyzerObservation(
        observation_id=claim.query_id,
        result=("allow" if claim.action in permissions else "deny"),
        scope="complete",
        raw_ref=raw_ref,
        provider="GCP",
        tool="testIamPermissions",
    )


def parse_azure_defender_attack_paths(
    claim: OracleClaim,
    payload: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    raw_ref: str,
) -> AnalyzerObservation:
    """Parse exact entry/target IDs from Azure Defender attack paths.

    Defender's result supports a discovered externally driven attack path.
    An empty or unmatched response remains ``not_found``/Unknown because the
    API is not a proof that no other path exists.
    """
    if claim.provider.casefold() != "azure":
        raise ValueError("Azure parser requires provider='Azure'")
    records: Sequence[Mapping[str, Any]]
    if isinstance(payload, Mapping):
        value = payload.get("data", payload.get("value", []))
        records = value if isinstance(value, Sequence) else []
    else:
        records = payload

    matched = False
    for record in records:
        properties = record.get("properties", {})
        entry = properties.get(
            "entryPointEntityInternalID",
            properties.get("entryPointEntityInternalId"),
        )
        target = properties.get(
            "targetEntityInternalID",
            properties.get("targetEntityInternalId"),
        )
        if entry == claim.principal and target == claim.resource:
            matched = True
            break
    return AnalyzerObservation(
        observation_id=claim.query_id,
        result=("allow" if matched else "not_found"),
        scope=("complete" if matched else "unknown"),
        raw_ref=raw_ref,
        provider="Azure",
        tool="Defender for Cloud attack-path API",
    )
