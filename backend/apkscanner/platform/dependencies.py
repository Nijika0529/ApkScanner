from __future__ import annotations

from collections.abc import Generator
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import update
from sqlalchemy.orm import Session

from ..core.db import Database
from ..core.enums import TaskStatus
from ..core.models import InvestigationTask, Scan
from ..infrastructure.artifacts import ArtifactStore
from ..runtime.capabilities import CapabilityRegistry
from ..runtime.orchestrator import ScanOrchestrator
from ..runtime.supervisor import SupervisorService


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_store(request: Request) -> ArtifactStore:
    return request.app.state.store


def get_orchestrator(request: Request) -> ScanOrchestrator:
    return request.app.state.orchestrator


def get_capability_registry(request: Request) -> CapabilityRegistry:
    return request.app.state.capability_registry


def get_supervisor(request: Request) -> SupervisorService:
    return request.app.state.supervisor


def get_session(database: Database = Depends(get_database)) -> Generator[Session, None, None]:
    with database.session_factory() as session:
        yield session


def require_scan(session: Session, scan_id: str) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


def require_active_task(session: Session, task_id: str) -> InvestigationTask:
    task = session.get(InvestigationTask, task_id)
    if task is None or task.status == TaskStatus.DELETED.value:
        raise HTTPException(404, "Task not found")
    return task


def transition_task(
    session: Session,
    task_id: str,
    *,
    expected_status: str,
    values: dict[str, Any],
) -> bool:
    result = session.execute(
        update(InvestigationTask)
        .where(
            InvestigationTask.id == task_id,
            InvestigationTask.status == expected_status,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1
