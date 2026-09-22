from __future__ import annotations

from typing import Protocol


class ReconciliationTarget(Protocol):
    def _reconcile_legacy_direct_reachability_findings(self) -> None: ...

    def _reconcile_unproven_dynamic_findings(self) -> None: ...

    def _recover_interrupted_runtime_records(self) -> None: ...


class StartupReconciler:
    """Idempotent data repair, deliberately separate from schema migration."""

    def __init__(self, target: ReconciliationTarget):
        self.target = target

    def reconcile(self) -> None:
        self.target._reconcile_legacy_direct_reachability_findings()
        self.target._reconcile_unproven_dynamic_findings()
        self.target._recover_interrupted_runtime_records()
