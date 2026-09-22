from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ArtifactWriter(Protocol):
    """Minimum content-addressed storage contract needed by the domain."""

    def put_json(self, category: str, value: Any) -> tuple[str, Path]: ...

    def put_bytes(
        self,
        category: str,
        content: bytes,
        *,
        suffix: str = ".bin",
    ) -> tuple[str, Path]: ...


class CommandResultView(Protocol):
    """Read-only command receipt accepted by EvidenceRecorder."""

    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    canceled: bool
