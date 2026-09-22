from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.models import EntryPoint
    from ..infrastructure.tools import TimeBudget
    from .device import AdbDeviceAdapter


@dataclass(slots=True)
class LiveProofContext:
    """Public task-scoped contract shared by proof producers and the runtime."""

    token: str
    scan_id: str
    task_id: str
    package_name: str
    workspace: Path
    entries: list[EntryPoint]
    default_entry_id: str
    hypotheses: list[dict[str, Any]]
    budget: TimeBudget
    evidence_summaries: list[dict[str, Any]]
    cancel_event: threading.Event
    round_index: int
    device: AdbDeviceAdapter | None = None
    adb_policy: str = "scoped"
    container_workspace: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    responses: dict[str, dict[str, Any]] = field(default_factory=dict)
    proof_strategies: dict[str, dict[str, Any]] = field(default_factory=dict)
    executed_semantic_strategies: dict[str, dict[str, Any]] = field(default_factory=dict)
    proven_semantic_strategies: dict[str, dict[str, Any]] = field(default_factory=dict)
