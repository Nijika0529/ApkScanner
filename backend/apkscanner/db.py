from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, select, text, update
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
            self._reconcile_duplicate_findings()
            self._ensure_runtime_schema_guards()
            self._recover_interrupted_runtime_records()
        self._harden_sqlite_files()

    def _reconcile_duplicate_findings(self) -> None:
        """Merge legacy duplicates before installing the database uniqueness guard."""

        from .models import (
            Finding,
            SecurityHypothesis,
            VulnerabilityCase,
            VulnerabilityOccurrence,
            VulnerabilityPattern,
        )

        status_rank = {
            "candidate": 0,
            "inconclusive": 1,
            "not_reproduced": 2,
            "supported_static": 3,
            "accepted": 4,
            "reproduced_blackbox": 5,
            "refuted_static": 2,
            "false_positive": 2,
        }
        with self.session_factory() as session:
            findings = list(
                session.scalars(
                    select(Finding).order_by(Finding.scan_id, Finding.dedupe_key, Finding.created_at)
                )
            )
            canonical_by_key: dict[tuple[str, str], Finding] = {}
            changed = False
            for duplicate in findings:
                key = (duplicate.scan_id, duplicate.dedupe_key)
                canonical = canonical_by_key.get(key)
                if canonical is None:
                    canonical_by_key[key] = duplicate
                    continue
                changed = True
                if status_rank.get(duplicate.status, 0) > status_rank.get(canonical.status, 0):
                    canonical.status = duplicate.status
                    canonical.severity = duplicate.severity
                    canonical.confidence = duplicate.confidence
                canonical.entry_point_ids = list(
                    dict.fromkeys(
                        [*(canonical.entry_point_ids or []), *(duplicate.entry_point_ids or [])]
                    )
                )
                canonical.evidence_ids = list(
                    dict.fromkeys(
                        [*(canonical.evidence_ids or []), *(duplicate.evidence_ids or [])]
                    )
                )
                locations = [*(canonical.locations or []), *(duplicate.locations or [])]
                canonical.locations = list(
                    {
                        str(item): item
                        for item in locations
                        if isinstance(item, dict)
                    }.values()
                )
                metadata = dict(canonical.metadata_json or {})
                legacy_ids = metadata.get("legacy_duplicate_finding_ids")
                if not isinstance(legacy_ids, list):
                    legacy_ids = []
                duplicate_legacy_ids = (duplicate.metadata_json or {}).get(
                    "legacy_duplicate_finding_ids"
                )
                if not isinstance(duplicate_legacy_ids, list):
                    duplicate_legacy_ids = []
                metadata["legacy_duplicate_finding_ids"] = list(
                    dict.fromkeys(
                        [
                            *legacy_ids,
                            duplicate.id,
                            *duplicate_legacy_ids,
                        ]
                    )
                )
                canonical.metadata_json = metadata
                for model, field in (
                    (SecurityHypothesis, SecurityHypothesis.final_finding_id),
                    (VulnerabilityCase, VulnerabilityCase.source_finding_id),
                    (VulnerabilityOccurrence, VulnerabilityOccurrence.finding_id),
                    (VulnerabilityPattern, VulnerabilityPattern.source_finding_id),
                ):
                    session.execute(
                        update(model)
                        .where(field == duplicate.id)
                        .values({field.key: canonical.id})
                    )
                session.delete(duplicate)
            if changed:
                session.commit()

    def _ensure_runtime_schema_guards(self) -> None:
        """Install guards that ``create_all`` cannot add to an existing database."""

        inspector = inspect(self.engine)
        protected = any(
            set(item.get("column_names") or []) == {"scan_id", "dedupe_key"}
            for item in inspector.get_unique_constraints("findings")
        ) or any(
            bool(item.get("unique"))
            and set(item.get("column_names") or []) == {"scan_id", "dedupe_key"}
            for item in inspector.get_indexes("findings")
        )
        if protected:
            return
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_scan_dedupe "
                    "ON findings (scan_id, dedupe_key)"
                )
            )

    def _recover_interrupted_runtime_records(self) -> None:
        """Close stale CAS/runtime states left behind by an unclean service exit."""

        from datetime import UTC, datetime

        from .models import (
            AgentSessionRecord,
            AgentTurnRecord,
            ProofAttempt,
            ScanContainerRecord,
            SecurityHypothesis,
        )

        recovered_at = datetime.now(UTC)
        with self.session_factory() as session:
            stale_attempts = list(
                session.scalars(select(ProofAttempt).where(ProofAttempt.status == "executing"))
            )
            for attempt in stale_attempts:
                attempt.status = "inconclusive"
                attempt.error = "recovered after an interrupted platform process"
                attempt.completed_at = recovered_at
                hypothesis = session.get(SecurityHypothesis, attempt.hypothesis_id)
                if hypothesis is not None and hypothesis.status == "executing":
                    hypothesis.status = "inconclusive"
            session.execute(
                update(AgentTurnRecord)
                .where(AgentTurnRecord.status == "running")
                .values(
                    status="interrupted",
                    error="recovered after an interrupted platform process",
                    completed_at=recovered_at,
                )
            )
            session.execute(
                update(AgentSessionRecord)
                .where(AgentSessionRecord.status == "active")
                .values(status="interrupted", completed_at=recovered_at)
            )
            session.execute(
                update(ScanContainerRecord)
                .where(ScanContainerRecord.status.in_({"prepared", "running"}))
                .values(status="interrupted", completed_at=recovered_at)
            )
            session.commit()

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
