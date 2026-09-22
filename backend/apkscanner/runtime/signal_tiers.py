"""Compatibility imports for the former runtime-owned verdict helpers.

Verdict policy is a core-domain concern. Keep this module so downstream users do
not need a flag-day import migration.
"""

from ..core.verdicts import (
    SignalTier,
    finding_signal_tier,
    valid_static_refutation_gate,
    valid_static_support_gate,
)

__all__ = [
    "SignalTier",
    "finding_signal_tier",
    "valid_static_refutation_gate",
    "valid_static_support_gate",
]
