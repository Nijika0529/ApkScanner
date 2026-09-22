from __future__ import annotations

import multiprocessing
import os
from pathlib import Path

import pytest
from apkscanner.core.config import Settings
from apkscanner.core.db import Database
from apkscanner.core.migrations import MIGRATION_TABLE_NAME
from sqlalchemy import text


def _concurrent_create_all_worker(
    database_url: str,
    data_dir: str,
    ready_queue,  # noqa: ANN001
    start_event,  # noqa: ANN001
    result_queue,  # noqa: ANN001
) -> None:
    settings = Settings(
        data_dir=Path(data_dir),
        database_url=database_url,
        sqlite_synchronous="OFF",
        tool_timeout_seconds=30,
    )
    settings.ensure_directories()
    ready_queue.put(os.getpid())
    if not start_event.wait(timeout=30):
        result_queue.put("start barrier timed out")
        return

    database = Database(settings)
    try:
        database.create_all()
    except Exception as exc:  # pragma: no cover - surfaced in the parent assertion
        result_queue.put(f"{type(exc).__name__}: {exc}")
    else:
        result_queue.put(None)
    finally:
        database.engine.dispose()


def test_schema_migrations_are_versioned_and_idempotent(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()

    with database.engine.connect() as connection:
        first = list(
            connection.execute(
                text(
                    f"SELECT revision, checksum, applied_at FROM {MIGRATION_TABLE_NAME} "
                    "ORDER BY revision"
                )
            )
        )

    assert [row.revision for row in first] == [
        "20260921_01_entry_point_disposition",
        "20260921_02_finding_identity_guard",
    ]
    assert all(row.checksum.startswith("sha256:") for row in first)

    database.create_all()
    with database.engine.connect() as connection:
        second = list(
            connection.execute(
                text(
                    f"SELECT revision, checksum, applied_at FROM {MIGRATION_TABLE_NAME} "
                    "ORDER BY revision"
                )
            )
        )
    assert second == first


def test_applied_migration_checksum_drift_is_rejected(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.engine.begin() as connection:
        connection.execute(
            text(
                f"UPDATE {MIGRATION_TABLE_NAME} SET checksum = 'rewritten' "
                "WHERE revision = '20260921_01_entry_point_disposition'"
            )
        )

    with pytest.raises(RuntimeError, match="applied schema migration was modified"):
        database.create_all()


@pytest.mark.skipif(os.name != "posix", reason="SQLite startup lock uses POSIX flock")
def test_concurrent_first_start_serializes_schema_migration(settings) -> None:  # noqa: ANN001
    context = multiprocessing.get_context("spawn")
    ready_queue = context.Queue()
    result_queue = context.Queue()
    start_event = context.Event()
    workers = [
        context.Process(
            target=_concurrent_create_all_worker,
            args=(
                settings.database_url,
                str(settings.data_dir),
                ready_queue,
                start_event,
                result_queue,
            ),
        )
        for _ in range(2)
    ]

    try:
        for worker in workers:
            worker.start()
        for _worker in workers:
            ready_queue.get(timeout=30)
        start_event.set()
        for worker in workers:
            worker.join(timeout=30)
        assert not [worker.pid for worker in workers if worker.is_alive()]
        assert [result_queue.get(timeout=5) for _worker in workers] == [None, None]
        assert [worker.exitcode for worker in workers] == [0, 0]
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=5)

    database = Database(settings)
    try:
        with database.engine.connect() as connection:
            revisions = connection.execute(
                text(
                    f"SELECT revision FROM {MIGRATION_TABLE_NAME} "
                    "ORDER BY revision"
                )
            ).scalars()
            assert list(revisions) == [
                "20260921_01_entry_point_disposition",
                "20260921_02_finding_identity_guard",
            ]
    finally:
        database.engine.dispose()
