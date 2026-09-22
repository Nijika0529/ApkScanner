"""Compatibility facade for core signal projections."""

from ..core.signal_projection import (
    evidence_supports_runtime_observation,
    project_runtime_observation_gap,
)

__all__ = [
    "evidence_supports_runtime_observation",
    "project_runtime_observation_gap",
]
