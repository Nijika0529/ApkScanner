from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Column, Engine, MetaData, String, Table, Text, inspect, select

MIGRATION_TABLE_NAME = "apkscanner_schema_migrations"

_metadata = MetaData()
_migration_table = Table(
    MIGRATION_TABLE_NAME,
    _metadata,
    Column("revision", String(64), primary_key=True),
    Column("description", Text, nullable=False),
    Column("checksum", String(128), nullable=False),
    Column("applied_at", String(40), nullable=False),
)


@dataclass(frozen=True, slots=True)
class SchemaMigration:
    """An immutable, append-only schema revision."""

    revision: str
    description: str
    checksum: str
    upgrade: Callable[[], None]
    is_current: Callable[[], bool] | None = None


class SchemaMigrator:
    """Small versioned migration ledger for in-place appliance upgrades."""

    def __init__(self, engine: Engine, migrations: Iterable[SchemaMigration]):
        self.engine = engine
        self.migrations = tuple(migrations)
        revisions = [migration.revision for migration in self.migrations]
        if len(revisions) != len(set(revisions)):
            raise ValueError("schema migration revisions must be unique")

    def migrate(self) -> None:
        _metadata.create_all(self.engine)
        applied = self._applied()
        for migration in self.migrations:
            recorded = applied.get(migration.revision)
            if recorded is not None:
                self._validate_checksum(migration, recorded)
                if migration.is_current is not None and not migration.is_current():
                    migration.upgrade()
                    self._validate_state(migration)
                continue
            migration.upgrade()
            self._validate_state(migration)
            with self.engine.begin() as connection:
                connection.execute(
                    _migration_table.insert().values(
                        revision=migration.revision,
                        description=migration.description,
                        checksum=migration.checksum,
                        applied_at=datetime.now(UTC).isoformat(),
                    )
                )
            applied[migration.revision] = migration.checksum

    def validate_current(self) -> list[str]:
        """Return missing migration facts; raise on a rewritten applied revision."""

        if not inspect(self.engine).has_table(MIGRATION_TABLE_NAME):
            return [MIGRATION_TABLE_NAME]
        applied = self._applied()
        missing: list[str] = []
        for migration in self.migrations:
            recorded = applied.get(migration.revision)
            if recorded is None:
                missing.append(f"migration:{migration.revision}")
            else:
                self._validate_checksum(migration, recorded)
                if migration.is_current is not None and not migration.is_current():
                    missing.append(f"migration-state:{migration.revision}")
        return missing

    def applied_revisions(self) -> tuple[str, ...]:
        if not inspect(self.engine).has_table(MIGRATION_TABLE_NAME):
            return ()
        return tuple(self._applied())

    def _applied(self) -> dict[str, str]:
        with self.engine.connect() as connection:
            return {
                str(revision): str(checksum)
                for revision, checksum in connection.execute(
                    select(_migration_table.c.revision, _migration_table.c.checksum).order_by(
                        _migration_table.c.revision
                    )
                )
            }

    @staticmethod
    def _validate_checksum(migration: SchemaMigration, recorded: str) -> None:
        if recorded != migration.checksum:
            raise RuntimeError(
                "applied schema migration was modified: "
                f"{migration.revision} (database={recorded}, code={migration.checksum})"
            )

    @staticmethod
    def _validate_state(migration: SchemaMigration) -> None:
        if migration.is_current is not None and not migration.is_current():
            raise RuntimeError(
                "schema migration completed without establishing its invariant: "
                f"{migration.revision}"
            )
