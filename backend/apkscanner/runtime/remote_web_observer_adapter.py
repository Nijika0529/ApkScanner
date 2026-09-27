from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from .remote_observer_backend import (
    RemoteActionReceipt,
    RemoteDeployment,
    RemoteObserverBackend,
)
from .web_exploit_observer import WebExperiment, WebExploitObserver


@dataclass(frozen=True, slots=True)
class RemoteWebObserverSession:
    deployment: RemoteDeployment
    attack_url: str
    control_url: str
    quiet_url: str


class RemoteWebObserverAdapter:
    """Expose local WebExploitObserver pages over a verified HTTPS SSH tunnel.

    The HTTP handler and Evidence persistence stay local, so there is no
    remote event importer and no second source of truth for client callbacks.
    """

    def __init__(self, observer: WebExploitObserver, backend: RemoteObserverBackend):
        self.observer = observer
        self.backend = backend
        self._lock = RLock()
        self._owners: dict[str, str] = {}

    def deploy(self, experiment: WebExperiment, *, task_id: str) -> RemoteWebObserverSession:
        if self.observer.get(experiment.experiment_id, task_id=task_id) is not experiment:
            raise ValueError("Web experiment does not belong to this observer")
        remaining = int((experiment.deadline - datetime.now(UTC)).total_seconds())
        deployment = self.backend.deploy(
            experiment.experiment_id,
            experiment.nonce,
            experiment.phase_nonces,
            remaining,
        )
        with self._lock:
            self._owners[experiment.experiment_id] = task_id
        return RemoteWebObserverSession(
            deployment=deployment,
            attack_url=self.observer.url(
                experiment, base_url=deployment.base_url, phase="attack",
            ),
            control_url=self.observer.url(
                experiment, base_url=deployment.base_url, phase="control",
            ),
            quiet_url=self.observer.url(
                experiment, base_url=deployment.base_url, phase="quiet",
            ),
        )

    def events(self, experiment_id: str, *, task_id: str) -> list[dict[str, Any]]:
        self.observer.get(experiment_id, task_id=task_id)
        return self.observer.events(experiment_id, task_id=task_id)

    def health(self, experiment_id: str, *, task_id: str) -> bool:
        self._require_owner(experiment_id, task_id)
        return self.backend.health(experiment_id)

    def revoke(self, experiment_id: str, *, task_id: str) -> bool:
        self._require_owner(experiment_id, task_id)
        return self.backend.revoke(experiment_id)

    def receipts(
        self, experiment_id: str, *, task_id: str,
    ) -> tuple[RemoteActionReceipt, ...]:
        self._require_owner(experiment_id, task_id)
        return self.backend.receipts(experiment_id)

    def _require_owner(self, experiment_id: str, task_id: str) -> None:
        with self._lock:
            if self._owners.get(experiment_id) != task_id:
                raise ValueError("remote Web experiment does not belong to this task")
