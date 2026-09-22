"""Compatibility facade for content-addressed artifact infrastructure."""

from ..infrastructure.artifacts import ArtifactStore, ArtifactTooLargeError

__all__ = ["ArtifactStore", "ArtifactTooLargeError"]
