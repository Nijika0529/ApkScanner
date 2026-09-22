from __future__ import annotations

import pytest
from apkscanner.core.db import Database
from apkscanner.core.migrations import MIGRATION_TABLE_NAME
from sqlalchemy import text


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
