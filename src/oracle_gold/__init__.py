"""Executable, evidence-bound ground-truth protocol."""

from .protocol import (
    build_candidate_registry,
    refresh_registry_derived_fields,
    validate_oracle_registry,
)
from .evidence_bundle import (
    apply_completed_evidence_bundles,
    build_evidence_bundle_templates,
    derive_truth_state,
    validate_evidence_bundle,
)
from .scope_candidates import build_scope_candidate_inventory
from .probe_contracts import build_probe_contract_registry
from .replay_safety import build_replay_safety_audit
from .replay_supply import build_replay_supply_inventory
from .runtime_preflight import preflight_probe_contract
from .staged_runtime import (
    InMemorySetupResult,
    bind_staged_setup_outputs,
    preflight_staged_setup,
)

__all__ = [
    "apply_completed_evidence_bundles",
    "build_candidate_registry",
    "build_evidence_bundle_templates",
    "build_scope_candidate_inventory",
    "build_probe_contract_registry",
    "build_replay_safety_audit",
    "build_replay_supply_inventory",
    "preflight_probe_contract",
    "preflight_staged_setup",
    "bind_staged_setup_outputs",
    "InMemorySetupResult",
    "derive_truth_state",
    "refresh_registry_derived_fields",
    "validate_evidence_bundle",
    "validate_oracle_registry",
]
