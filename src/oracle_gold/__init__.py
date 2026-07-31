"""Executable, evidence-bound ground-truth protocol."""

from .protocol import (
    build_candidate_registry,
    validate_oracle_registry,
)

__all__ = [
    "build_candidate_registry",
    "validate_oracle_registry",
]
