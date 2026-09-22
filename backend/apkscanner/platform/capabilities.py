"""Compatibility facade for runtime capability registration."""

from ..runtime.capabilities import (
    CapabilityAdapter,
    CapabilityInvocation,
    CapabilityManifest,
    CapabilityRegistry,
    CapabilityResult,
)

__all__ = [
    "CapabilityAdapter",
    "CapabilityInvocation",
    "CapabilityManifest",
    "CapabilityRegistry",
    "CapabilityResult",
]
