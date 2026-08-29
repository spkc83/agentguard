"""Compatibility exports for the canonical :mod:`agentguard.testing` generator."""

from agentguard.testing.synthetic import (
    CreditApplicationSchema,
    SyntheticCreditGenerator,
    is_synthetic_approval,
)

__all__ = [
    "CreditApplicationSchema",
    "SyntheticCreditGenerator",
    "is_synthetic_approval",
]
