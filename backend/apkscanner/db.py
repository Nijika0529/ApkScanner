from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import Settings
from .permissions import create_private_file, ensure_private_file


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, settings: Settings):
        url = make_url(settings.database_url)
        sqlite = url.get_backend_name() == "sqlite"
        self._sqlite_read_only = sqlite and url.query.get("mode") == "ro"
        self._sqlite_path = self._sqlite_database_path(url) if sqlite else None
        if self._sqlite_path is not None:
            if url.query.get("mode") in {"ro", "rw"}:
                ensure_private_file(self._sqlite_path)
            else:
                create_private_file(self._sqlite_path)
        connect_args = {"check_same_thread": False} if sqlite else {}
        engine_options = {"connect_args": connect_args}
        if sqlite and url.database in {None, "", ":memory:"}:
            engine_options["poolclass"] = StaticPool
        self.engine = create_engine(settings.database_url, **engine_options)
        if sqlite:
            event.listen(self.engine, "connect", self._configure_sqlite)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False, class_=Session)

    def _configure_sqlite(self, dbapi_connection, _connection_record) -> None:  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA busy_timeout=10000")
        if not self._sqlite_read_only:
            cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
        self._harden_sqlite_files()

    @staticmethod
    def _sqlite_database_path(url) -> Path | None:  # noqa: ANN001
        database = url.database
        if (
            not database
            or database in {":memory:", "file::memory:"}
            or url.query.get("mode") == "memory"
        ):
            return None
        if database.startswith("file:") and url.query.get("uri") == "true":
            database = database.removeprefix("file:")
        return Path(database).expanduser().absolute()

    def _harden_sqlite_files(self) -> None:
        if self._sqlite_path is None:
            return
        for path in (
            self._sqlite_path,
            Path(f"{self._sqlite_path}-wal"),
            Path(f"{self._sqlite_path}-shm"),
            Path(f"{self._sqlite_path}-journal"),
        ):
            ensure_private_file(path)

    def create_all(self) -> None:
        from . import models  # noqa: F401

        Base.metadata.create_all(self.engine)
        if not self._sqlite_read_only:
            self._reconcile_legacy_direct_reachability_findings()
        self._harden_sqlite_files()

    def _reconcile_legacy_direct_reachability_findings(self) -> None:
        """Reopen only findings auto-closed by the former direct-edge policy."""

        from .enums import FindingStatus
        from .models import Finding

        with self.session_factory() as session:
            findings = list(
                session.scalars(
                    select(Finding).where(
                        Finding.status == FindingStatus.FALSE_POSITIVE.value,
                        Finding.review_note.is_(None),
                    )
                )
            )
            changed = False
            for finding in findings:
                metadata = dict(finding.metadata_json or {})
                legacy = metadata.pop("closed_by_static_reachability", None)
                if not isinstance(legacy, dict):
                    continue
                finding.status = FindingStatus.CANDIDATE.value
                metadata["direct_reachability_assessment"] = {
                    "status": "blocked",
                    "scope": "ordinary_app_direct_invocation_only",
                    "indirect_chain_paths_evaluated": False,
                    "threat_model": legacy.get(
                        "threat_model",
                        "ordinary_app_uid",
                    ),
                    "entry_decisions": legacy.get("entry_decisions", []),
                }
                metadata["legacy_status_reconciliation"] = {
                    "previous_status": FindingStatus.FALSE_POSITIVE.value,
                    "reason": (
                        "blocked direct invocation does not refute indirect "
                        "cross-component chains"
                    ),
                }
                finding.metadata_json = metadata
                changed = True
            if changed:
                session.commit()

    def session(self) -> Generator[Session, None, None]:
        with self.session_factory() as session:
            yield session
