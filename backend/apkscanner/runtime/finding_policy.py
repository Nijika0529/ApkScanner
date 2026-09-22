"""Compatibility facade for core finding policy.

New code should import :mod:`apkscanner.core.finding_policy`. The runtime path is
retained for integrations that predate the dependency-boundary cleanup.
"""

from ..core.finding_policy import (
    EVIDENCE_BACKED_FINDING_STATUSES,
    FindingVerdictProjection,
    build_static_refutation_gate,
    evidence_backed_signal_tier,
    evidence_backed_signal_tiers,
    partition_findings,
    project_findings,
    static_evidence_is_usable,
    static_refutation_is_evidence_backed,
)

__all__ = [
    "EVIDENCE_BACKED_FINDING_STATUSES",
    "FindingVerdictProjection",
    "build_static_refutation_gate",
    "evidence_backed_signal_tier",
    "evidence_backed_signal_tiers",
    "partition_findings",
    "project_findings",
    "static_evidence_is_usable",
    "static_refutation_is_evidence_backed",
]
