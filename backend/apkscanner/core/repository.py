from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from .models import EntryPoint, Scan, ScanEvent


def add_event(
    session: Session,
    scan_id: str,
    event_type: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> ScanEvent:
    event = ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        message=message,
        data=data or {},
    )
    session.add(event)
    return event


def now() -> datetime:
    return datetime.now(UTC)


def invalidate_scan_materialized_summary(
    session: Session,
    scan_id: str,
    *,
    reason: str,
) -> None:
    """Mark final-scan derived counts and seal stale after a material Finding mutation."""

    scan = session.get(Scan, scan_id)
    if scan is None:
        return
    stats = dict(scan.stats) if isinstance(scan.stats, dict) else {}
    for key in (
        "finding_count",
        "signal_count",
        "entry_disposition_counts",
        "entry_disposition_coverage_rate",
        "unresolved_entry_disposition_count",
    ):
        stats.pop(key, None)
    invalidated_at = now().isoformat()
    seal = stats.get("seal")
    if isinstance(seal, dict):
        stats["seal"] = {
            **seal,
            "current": False,
            "invalidated_at": invalidated_at,
            "invalidated_reason": reason,
        }
    stats["materialized_summary"] = {
        "schema_version": "1.0",
        "current": False,
        "invalidated_at": invalidated_at,
        "reason": reason,
    }
    scan.stats = stats
    for entry in session.scalars(
        select(EntryPoint).where(EntryPoint.scan_id == scan_id)
    ):
        entry.disposition = None


def scalars(session: Session, statement: Select) -> list[Any]:
    return list(session.scalars(statement).all())


def by_scan(model, scan_id: str, *order_by) -> Select:  # noqa: ANN001, ANN202
    statement = select(model).where(model.scan_id == scan_id)
    if order_by:
        statement = statement.order_by(*order_by)
    return statement


def terminal_task_statuses() -> set[str]:
    return {
        "blocked_device",
        "completed",
        "not_reproduced",
        "inconclusive",
        "failed",
        "canceled",
        "deleted",
    }


def all_terminal(statuses: Iterable[str]) -> bool:
    values = list(statuses)
    return bool(values) and all(item in terminal_task_statuses() for item in values)
