from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

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

        if self._sqlite_read_only:
            self._validate_read_only_schema()
        else:
            Base.metadata.create_all(self.engine)
            self._ensure_runtime_schema_columns()
            self._reconcile_legacy_direct_reachability_findings()
            self._reconcile_duplicate_findings()
            self._reconcile_unproven_dynamic_findings()
            self._ensure_runtime_schema_guards()
            self._recover_interrupted_runtime_records()
        self._harden_sqlite_files()

    def _validate_read_only_schema(self) -> None:
        """Fail clearly when a legacy database needs a writable migration first."""

        inspector = inspect(self.engine)
        missing: list[str] = []
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                missing.append(table.name)
                continue
            actual_columns = {str(item["name"]) for item in inspector.get_columns(table.name)}
            missing.extend(
                f"{table.name}.{column.name}"
                for column in table.columns
                if column.name not in actual_columns
            )
        if inspector.has_table("findings") and not self._findings_unique_guard_exists(
            inspector
        ):
            missing.append("findings.unique(scan_id,dedupe_key)")
        if missing:
            preview = ", ".join(missing[:10])
            suffix = " ..." if len(missing) > 10 else ""
            raise RuntimeError(
                "read-only database schema is outdated; reopen it writable and run "
                f"create_all() before read-only use (missing: {preview}{suffix})"
            )

    def _ensure_runtime_schema_columns(self) -> None:
        """Add columns and indexes that ``create_all`` cannot retrofit onto old tables."""

        inspector = inspect(self.engine)
        if not inspector.has_table("entry_points"):
            return
        columns = {str(item["name"]) for item in inspector.get_columns("entry_points")}
        if "disposition" not in columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE entry_points ADD COLUMN disposition VARCHAR(64)")
                )

        inspector = inspect(self.engine)
        disposition_indexed = any(
            list(item.get("column_names") or []) == ["disposition"]
            for item in inspector.get_indexes("entry_points")
        )
        if not disposition_indexed:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_entry_points_disposition "
                        "ON entry_points (disposition)"
                    )
                )

    def _reconcile_duplicate_findings(self) -> None:
        """Merge legacy duplicates before installing the database uniqueness guard."""

        import hashlib
        import json

        from ..runtime.finding_policy import (
            evidence_backed_signal_tier,
            static_refutation_is_evidence_backed,
        )
        from .enums import FINDING_STATUS_RANK
        from .models import (
            AdaptiveVerificationCheckpoint,
            DynamicExperimentCapsule,
            Evidence,
            Finding,
            IndexedArtifact,
            InvestigationTask,
            OperatorSession,
            RuntimeObservation,
            Scan,
            SecurityHypothesis,
            VulnerabilityCase,
            VulnerabilityOccurrence,
            VulnerabilityPattern,
        )
        from .proof_receipts import (
            attributable_harm_attempts,
            attributable_refutation_attempts,
        )
        from .repository import invalidate_scan_materialized_summary

        status_rank = FINDING_STATUS_RANK

        def merge_json_lists(*values: Any) -> list[Any]:
            merged: list[Any] = []
            seen: set[str] = set()
            for value in values:
                if not isinstance(value, list):
                    continue
                for item in value:
                    key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
                    if key in seen:
                        continue
                    seen.add(key)
                    merged.append(item)
            return merged

        def string_list(value: Any) -> list[str]:
            return [
                item
                for item in value
                if isinstance(item, str) and item
            ] if isinstance(value, list) else []

        def replace_json_finding_refs(
            value: Any,
            *,
            duplicate_id: str,
            canonical_id: str,
        ) -> Any:
            if isinstance(value, list):
                replaced = [
                    replace_json_finding_refs(
                        item,
                        duplicate_id=duplicate_id,
                        canonical_id=canonical_id,
                    )
                    for item in value
                ]
                return merge_json_lists(replaced)
            if not isinstance(value, dict):
                return value
            result: dict[str, Any] = {}
            for key, item in value.items():
                if key == "merged_finding_map" and isinstance(item, dict):
                    result[key] = {
                        canonical_id if map_key == duplicate_id else map_key: (
                            canonical_id if map_value == duplicate_id else map_value
                        )
                        for map_key, map_value in item.items()
                    }
                elif key == "finding_id" or key.endswith("_finding_id"):
                    result[key] = canonical_id if item == duplicate_id else item
                elif (
                    key == "finding_ids"
                    or key.endswith("_finding_ids")
                    or key == "missing_candidate_assessments"
                ):
                    result[key] = (
                        list(
                            dict.fromkeys(
                                canonical_id if member == duplicate_id else member
                                for member in item
                                if isinstance(member, str) and member
                            )
                        )
                        if isinstance(item, list)
                        else item
                    )
                else:
                    result[key] = replace_json_finding_refs(
                        item,
                        duplicate_id=duplicate_id,
                        canonical_id=canonical_id,
                    )
            return result

        def effective_status_rank(session: Session, finding: Finding) -> tuple[int, int]:
            if (
                finding.status in {"false_positive", "accepted"}
                and isinstance(finding.review_note, str)
                and finding.review_note.strip()
            ):
                return max(status_rank.values()) + 1, 1
            tier = evidence_backed_signal_tier(session, finding)
            if finding.status in {
                "accepted",
                "reproduced_blackbox",
            } and not attributable_harm_attempts(session, finding):
                return (
                    {
                        "raw_candidate": status_rank["candidate"],
                        "static_chain": status_rank["supported_static"],
                        "runtime_oracle_gap": status_rank[
                            "runtime_observed_unverified"
                        ],
                    }[tier],
                    0,
                )
            if finding.status == "not_reproduced":
                rank = (
                    status_rank["false_positive"]
                    if attributable_refutation_attempts(session, finding)
                    else status_rank["candidate"]
                )
                return rank, 0
            if finding.status == "refuted_static":
                return (
                    status_rank["refuted_static"]
                    if static_refutation_is_evidence_backed(session, finding)
                    else status_rank["candidate"],
                    0,
                )
            if finding.status in {
                "supported_static",
                "static_path_supported",
                "runtime_observed_unverified",
                "oracle_gap",
            } and tier == "raw_candidate":
                return status_rank["candidate"], 0
            manual_closure = int(
                finding.status in {"false_positive", "accepted"}
                and bool(finding.review_note)
            )
            return status_rank.get(finding.status, 0), manual_closure

        with self.session_factory() as session:
            findings = list(
                session.scalars(
                    select(Finding).order_by(
                        Finding.scan_id, Finding.dedupe_key, Finding.created_at
                    )
                )
            )
            evidence_ids_by_scan: dict[str, set[str]] = {}
            for evidence_id, evidence_scan_id in session.execute(
                select(Evidence.id, Evidence.scan_id)
            ):
                evidence_ids_by_scan.setdefault(evidence_scan_id, set()).add(evidence_id)
            canonical_by_key: dict[tuple[str, str], Finding] = {}
            changed = False
            affected_scan_ids: set[str] = set()
            for duplicate in findings:
                key = (duplicate.scan_id, duplicate.dedupe_key)
                canonical = canonical_by_key.get(key)
                if canonical is None:
                    canonical_by_key[key] = duplicate
                    continue
                changed = True
                affected_scan_ids.add(duplicate.scan_id)
                canonical_rank = effective_status_rank(session, canonical)
                duplicate_rank = effective_status_rank(session, duplicate)
                duplicate_preferred = duplicate_rank >= canonical_rank
                canonical_metadata = (
                    dict(canonical.metadata_json)
                    if isinstance(canonical.metadata_json, dict)
                    else {}
                )
                duplicate_metadata = (
                    dict(duplicate.metadata_json)
                    if isinstance(duplicate.metadata_json, dict)
                    else {}
                )
                discarded = canonical if duplicate_preferred else duplicate
                discarded_metadata = (
                    canonical_metadata if duplicate_preferred else duplicate_metadata
                )
                discarded_occurrence = {
                    "record_id": discarded.id,
                    "title": discarded.title,
                    "description": discarded.description,
                    "remediation": discarded.remediation,
                    "status": discarded.status,
                    "review_note": discarded.review_note,
                    "created_at": discarded.created_at.isoformat(),
                    "evidence_ids": string_list(discarded.evidence_ids),
                    "metadata_sha256": hashlib.sha256(
                        json.dumps(
                            discarded_metadata,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            default=str,
                        ).encode()
                    ).hexdigest(),
                }
                harm_attempts = [
                    *attributable_harm_attempts(session, canonical),
                    *attributable_harm_attempts(session, duplicate),
                ]
                refutation_attempts = [
                    *attributable_refutation_attempts(session, canonical),
                    *attributable_refutation_attempts(session, duplicate),
                ]
                if duplicate_preferred:
                    canonical.status = duplicate.status
                    canonical.severity = duplicate.severity
                    canonical.confidence = duplicate.confidence
                    canonical.source = duplicate.source
                    canonical.rule_id = duplicate.rule_id
                    canonical.title = duplicate.title
                    canonical.description = duplicate.description
                    canonical.remediation = duplicate.remediation
                    canonical.masvs = duplicate.masvs
                    canonical.cwe = duplicate.cwe
                    canonical.review_note = duplicate.review_note
                canonical.entry_point_ids = list(
                    dict.fromkeys(
                        [
                            *string_list(canonical.entry_point_ids),
                            *string_list(duplicate.entry_point_ids),
                        ]
                    )
                )
                valid_scan_evidence_ids = evidence_ids_by_scan.get(canonical.scan_id, set())
                canonical.evidence_ids = [
                    evidence_id
                    for evidence_id in dict.fromkeys(
                        [
                            *string_list(canonical.evidence_ids),
                            *string_list(duplicate.evidence_ids),
                        ]
                    )
                    if evidence_id in valid_scan_evidence_ids
                ]
                locations = [
                    *(canonical.locations if isinstance(canonical.locations, list) else []),
                    *(duplicate.locations if isinstance(duplicate.locations, list) else []),
                ]
                canonical.locations = list(
                    {str(item): item for item in locations if isinstance(item, dict)}.values()
                )
                metadata = (
                    {**canonical_metadata, **duplicate_metadata}
                    if duplicate_preferred
                    else {**duplicate_metadata, **canonical_metadata}
                )
                legacy_ids = string_list(metadata.get("legacy_duplicate_finding_ids"))
                duplicate_legacy_ids = string_list(
                    duplicate_metadata.get("legacy_duplicate_finding_ids")
                )
                metadata["legacy_duplicate_finding_ids"] = list(
                    dict.fromkeys(
                        [
                            *legacy_ids,
                            duplicate.id,
                            *duplicate_legacy_ids,
                        ]
                    )
                )
                metadata["legacy_duplicate_occurrences"] = merge_json_lists(
                    canonical_metadata.get("legacy_duplicate_occurrences"),
                    duplicate_metadata.get("legacy_duplicate_occurrences"),
                    [discarded_occurrence],
                )
                for list_key in (
                    "adaptive_verification_history",
                    "coverage_gaps",
                    "merged_occurrences",
                ):
                    canonical_values = canonical_metadata.get(list_key)
                    duplicate_values = duplicate_metadata.get(list_key)
                    if isinstance(canonical_values, list) or isinstance(
                        duplicate_values, list
                    ):
                        metadata[list_key] = merge_json_lists(
                            canonical_values,
                            duplicate_values,
                        )
                metadata["harm_demonstrated"] = bool(harm_attempts)
                metadata["proof_attempt_ids"] = list(
                    dict.fromkeys(attempt.id for attempt in harm_attempts)
                )
                metadata["refutation_attempt_ids"] = list(
                    dict.fromkeys(attempt.id for attempt in refutation_attempts)
                )
                metadata["release_gate_eligible"] = any(
                    payload.get("release_gate_eligible") is True
                    for payload in (canonical_metadata, duplicate_metadata)
                )
                if canonical.status == "runtime_observed_unverified":
                    metadata["signal_tier"] = "runtime_oracle_gap"
                    metadata["proof_gap_code"] = "missing_platform_harm_oracle"
                    existing_oracle_gap = metadata.get("oracle_gap")
                    metadata["oracle_gap"] = {
                        **(
                            dict(existing_oracle_gap)
                            if isinstance(existing_oracle_gap, dict)
                            else {}
                        ),
                        "schema_version": "1.0",
                        "status": "open",
                        "runtime_observed": True,
                    }
                    metadata.pop("platform_static_support_gate", None)
                    metadata.pop("chain_receipt", None)
                elif canonical.status in {"accepted", "reproduced_blackbox"}:
                    metadata.pop("signal_tier", None)
                    metadata.pop("proof_gap_code", None)
                    metadata.pop("oracle_gap", None)
                elif canonical.status in {
                    "false_positive",
                    "refuted_static",
                    "not_reproduced",
                }:
                    metadata.pop("signal_tier", None)
                    metadata.pop("proof_gap_code", None)
                    metadata.pop("oracle_gap", None)
                    metadata.pop("platform_static_support_gate", None)
                    metadata.pop("chain_receipt", None)
                if metadata["harm_demonstrated"]:
                    proof_backlog = metadata.get("proof_backlog")
                    metadata["proof_backlog"] = {
                        **(
                            dict(proof_backlog)
                            if isinstance(proof_backlog, dict)
                            else {}
                        ),
                        "status": "verified",
                    }
                elif isinstance(metadata.get("proof_backlog"), dict):
                    metadata["proof_backlog"] = {
                        **dict(metadata["proof_backlog"]),
                        "status": "proof_required",
                    }
                canonical.metadata_json = metadata
                for model, field in (
                    (SecurityHypothesis, SecurityHypothesis.final_finding_id),
                    (VulnerabilityCase, VulnerabilityCase.source_finding_id),
                    (VulnerabilityOccurrence, VulnerabilityOccurrence.finding_id),
                    (VulnerabilityPattern, VulnerabilityPattern.source_finding_id),
                ):
                    session.execute(
                        update(model).where(field == duplicate.id).values({field.key: canonical.id})
                    )
                for model in (
                    RuntimeObservation,
                    DynamicExperimentCapsule,
                    IndexedArtifact,
                ):
                    session.execute(
                        update(model)
                        .where(model.finding_id == duplicate.id)
                        .values(finding_id=canonical.id)
                    )
                duplicate_checkpoints = list(
                    session.scalars(
                        select(AdaptiveVerificationCheckpoint).where(
                            AdaptiveVerificationCheckpoint.finding_id == duplicate.id
                        )
                    )
                )
                for checkpoint in duplicate_checkpoints:
                    assessment_json = (
                        dict(checkpoint.assessment_json)
                        if isinstance(checkpoint.assessment_json, dict)
                        else {}
                    )
                    if assessment_json.get("finding_id") == duplicate.id:
                        assessment_json["finding_id"] = canonical.id
                    if assessment_json.get("duplicate_of_finding_id") == duplicate.id:
                        assessment_json["duplicate_of_finding_id"] = canonical.id
                    checkpoint.assessment_json = assessment_json
                    existing_checkpoint = session.scalar(
                        select(AdaptiveVerificationCheckpoint).where(
                            AdaptiveVerificationCheckpoint.task_id == checkpoint.task_id,
                            AdaptiveVerificationCheckpoint.finding_id == canonical.id,
                        )
                    )
                    if existing_checkpoint is None:
                        checkpoint.finding_id = canonical.id
                        continue
                    existing_assessment = (
                        dict(existing_checkpoint.assessment_json)
                        if isinstance(existing_checkpoint.assessment_json, dict)
                        else {}
                    )
                    existing_checkpoint.assessment_json = replace_json_finding_refs(
                        existing_assessment,
                        duplicate_id=duplicate.id,
                        canonical_id=canonical.id,
                    )
                    if checkpoint.updated_at >= existing_checkpoint.updated_at:
                        for field_name in (
                            "batch_index",
                            "audit_id",
                            "response_evidence_id",
                            "thread_id",
                            "turn_id",
                            "assessment_json",
                            "environment_json",
                        ):
                            setattr(
                                existing_checkpoint,
                                field_name,
                                getattr(checkpoint, field_name),
                            )
                        existing_assessment = (
                            dict(existing_checkpoint.assessment_json)
                            if isinstance(existing_checkpoint.assessment_json, dict)
                            else {}
                        )
                        if existing_assessment.get("finding_id") == duplicate.id:
                            existing_assessment["finding_id"] = canonical.id
                        if (
                            existing_assessment.get("duplicate_of_finding_id")
                            == duplicate.id
                        ):
                            existing_assessment["duplicate_of_finding_id"] = canonical.id
                        existing_checkpoint.assessment_json = existing_assessment
                    session.delete(checkpoint)
                for task in session.scalars(
                    select(InvestigationTask).where(
                        InvestigationTask.scan_id == canonical.scan_id
                    )
                ):
                    task.preconditions = replace_json_finding_refs(
                        task.preconditions,
                        duplicate_id=duplicate.id,
                        canonical_id=canonical.id,
                    )
                    task.result = replace_json_finding_refs(
                        task.result,
                        duplicate_id=duplicate.id,
                        canonical_id=canonical.id,
                    )
                for operator_session in session.scalars(select(OperatorSession)):
                    operator_session.scope_json = replace_json_finding_refs(
                        operator_session.scope_json,
                        duplicate_id=duplicate.id,
                        canonical_id=canonical.id,
                    )
                    operator_session.result_json = replace_json_finding_refs(
                        operator_session.result_json,
                        duplicate_id=duplicate.id,
                        canonical_id=canonical.id,
                    )
                scan = session.get(Scan, canonical.scan_id)
                if scan is not None:
                    scan.stats = replace_json_finding_refs(
                        scan.stats,
                        duplicate_id=duplicate.id,
                        canonical_id=canonical.id,
                    )
                session.flush()
                session.delete(duplicate)
            if changed:
                for scan_id in affected_scan_ids:
                    invalidate_scan_materialized_summary(
                        session,
                        scan_id,
                        reason="startup_duplicate_finding_reconciliation",
                    )
                session.commit()

    @staticmethod
    def _attributable_harm_attempts(
        session: Session,
        finding: Any,
        _metadata: dict[str, Any],
    ) -> list[Any]:
        """Resolve harm receipts without trusting a stale cross-hypothesis proof ID."""

        from .proof_receipts import attributable_harm_attempts

        return attributable_harm_attempts(session, finding)

    def _ensure_runtime_schema_guards(self) -> None:
        """Install guards that ``create_all`` cannot add to an existing database."""

        inspector = inspect(self.engine)
        if self._findings_unique_guard_exists(inspector):
            return
        reserved_name = "uq_findings_scan_dedupe"
        named_objects = [
            *inspector.get_unique_constraints("findings"),
            *inspector.get_indexes("findings"),
        ]
        conflict = next(
            (
                item
                for item in named_objects
                if item.get("name") == reserved_name
            ),
            None,
        )
        if conflict is not None:
            raise RuntimeError(
                "database schema guard conflict: uq_findings_scan_dedupe exists but is not "
                "a unique guard over findings(scan_id, dedupe_key); repair the legacy index "
                "and retry the writable migration"
            )
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX uq_findings_scan_dedupe "
                    "ON findings (scan_id, dedupe_key)"
                )
            )
        if not self._findings_unique_guard_exists(inspect(self.engine)):
            raise RuntimeError(
                "database schema migration did not install the required unique guard over "
                "findings(scan_id, dedupe_key)"
            )

    @staticmethod
    def _findings_unique_guard_exists(inspector: Any) -> bool:
        expected = {"scan_id", "dedupe_key"}
        return any(
            set(item.get("column_names") or []) == expected
            for item in inspector.get_unique_constraints("findings")
        ) or any(
            bool(item.get("unique"))
            and set(item.get("column_names") or []) == expected
            for item in inspector.get_indexes("findings")
        )

    def _recover_interrupted_runtime_records(self) -> None:
        """Close stale CAS/runtime states left behind by an unclean service exit."""

        from datetime import UTC, datetime

        from .models import (
            AgentSessionRecord,
            AgentTurnRecord,
            OperatorSession,
            OperatorTurn,
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
            session.execute(
                update(OperatorTurn)
                .where(OperatorTurn.status.in_({"queued", "running"}))
                .values(
                    status="interrupted",
                    error="recovered after an interrupted platform process",
                    completed_at=recovered_at,
                )
            )
            session.execute(
                update(OperatorSession)
                .where(OperatorSession.status == "running")
                .values(
                    status="interrupted",
                    error="recovered after an interrupted platform process",
                    completed_at=recovered_at,
                )
            )
            session.commit()

    def _reconcile_legacy_direct_reachability_findings(self) -> None:
        """Reopen only findings auto-closed by the former direct-edge policy."""

        from .enums import FindingStatus
        from .models import Finding
        from .repository import invalidate_scan_materialized_summary

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
            affected_scan_ids: set[str] = set()
            for finding in findings:
                metadata = (
                    dict(finding.metadata_json)
                    if isinstance(finding.metadata_json, dict)
                    else {}
                )
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
                        "blocked direct invocation does not refute indirect cross-component chains"
                    ),
                }
                finding.metadata_json = metadata
                changed = True
                affected_scan_ids.add(finding.scan_id)
            if changed:
                for scan_id in affected_scan_ids:
                    invalidate_scan_materialized_summary(
                        session,
                        scan_id,
                        reason="startup_legacy_reachability_reconciliation",
                    )
                session.commit()

    def _reconcile_unproven_dynamic_findings(self) -> None:
        """Repair crash-boundary drift between platform proof receipts and Finding state."""

        from ..runtime.finding_policy import (
            evidence_backed_signal_tier,
            static_refutation_is_evidence_backed,
        )
        from .enums import FindingStatus
        from .models import Evidence, Finding, InvestigationTask, SecurityHypothesis
        from .proof_receipts import (
            attributable_refutation_attempts,
            evidence_backed_harm_attempts,
        )
        from .repository import invalidate_scan_materialized_summary

        with self.session_factory() as session:
            findings = list(
                session.scalars(select(Finding).order_by(Finding.created_at))
            )
            changed = False
            affected_scan_ids: set[str] = set()
            for finding in findings:
                metadata = (
                    dict(finding.metadata_json)
                    if isinstance(finding.metadata_json, dict)
                    else {}
                )
                attempts = self._attributable_harm_attempts(session, finding, metadata)
                if attempts:
                    for hypothesis_id in {
                        attempt.hypothesis_id for attempt in attempts
                    }:
                        hypothesis = session.get(SecurityHypothesis, hypothesis_id)
                        if (
                            hypothesis is not None
                            and hypothesis.scan_id == finding.scan_id
                            and hypothesis.final_finding_id is None
                        ):
                            hypothesis.final_finding_id = finding.id
                            changed = True
                            affected_scan_ids.add(finding.scan_id)
                    proof_ids = [attempt.id for attempt in attempts]
                    proof_evidence_ids = [
                        evidence_id
                        for attempt in attempts
                        for evidence_id in (
                            attempt.evidence_ids
                            if isinstance(attempt.evidence_ids, list)
                            else []
                        )
                        if isinstance(evidence_id, str) and evidence_id
                    ]
                    release_gate_eligible = any(
                        (
                            attempt.oracle
                            if isinstance(attempt.oracle, dict)
                            else {}
                        ).get("release_gate_eligible")
                        is True
                        for attempt in attempts
                    )
                    previous_status = finding.status
                    if finding.status not in {
                        FindingStatus.ACCEPTED.value,
                        FindingStatus.FALSE_POSITIVE.value,
                    }:
                        finding.status = FindingStatus.REPRODUCED_BLACKBOX.value
                    raw_finding_evidence_ids = (
                        [
                            evidence_id
                            for evidence_id in finding.evidence_ids
                            if isinstance(evidence_id, str) and evidence_id
                        ]
                        if isinstance(finding.evidence_ids, list)
                        else []
                    )
                    valid_evidence_ids = set(
                        session.scalars(
                            select(Evidence.id).where(Evidence.scan_id == finding.scan_id)
                        )
                    )
                    repaired_evidence_ids = [
                        evidence_id
                        for evidence_id in dict.fromkeys(
                            [*raw_finding_evidence_ids, *proof_evidence_ids]
                        )
                        if isinstance(evidence_id, str)
                        and evidence_id in valid_evidence_ids
                    ]
                    if (
                        metadata.get("proof_attempt_ids") != proof_ids
                        or metadata.get("harm_demonstrated") is not True
                        or metadata.get("release_gate_eligible")
                        is not release_gate_eligible
                        or finding.status != previous_status
                        or finding.evidence_ids != repaired_evidence_ids
                    ):
                        metadata["proof_attempt_ids"] = proof_ids
                        metadata["harm_demonstrated"] = True
                        metadata["release_gate_eligible"] = release_gate_eligible
                        metadata["proof_backlog"] = {
                            **(
                                dict(metadata.get("proof_backlog"))
                                if isinstance(metadata.get("proof_backlog"), dict)
                                else {}
                            ),
                            "status": "verified",
                        }
                        if finding.status == FindingStatus.REPRODUCED_BLACKBOX.value:
                            metadata.pop("signal_tier", None)
                            metadata.pop("proof_gap_code", None)
                            metadata.pop("oracle_gap", None)
                            metadata["verdict_reconciliation"] = {
                                "schema_version": "1.0",
                                "previous_status": previous_status,
                                "reason": (
                                    "Recovered an attributable evidence-backed platform harm "
                                    "receipt after an interrupted Finding update."
                                ),
                            }
                        finding.evidence_ids = repaired_evidence_ids
                        finding.metadata_json = metadata
                        changed = True
                        affected_scan_ids.add(finding.scan_id)
                    continue
                if finding.status == FindingStatus.NOT_REPRODUCED.value:
                    refuting_attempts = attributable_refutation_attempts(
                        session,
                        finding,
                    )
                    if refuting_attempts:
                        refutation_ids = [attempt.id for attempt in refuting_attempts]
                        refutation_evidence_ids = list(
                            dict.fromkeys(
                                evidence_id
                                for attempt in refuting_attempts
                                for evidence_id in attempt.evidence_ids
                                if isinstance(evidence_id, str) and evidence_id
                            )
                        )
                        valid_evidence_ids = set(
                            session.scalars(
                                select(Evidence.id).where(
                                    Evidence.scan_id == finding.scan_id
                                )
                            )
                        )
                        repaired_evidence_ids = list(
                            dict.fromkeys(
                                [
                                    *(
                                        [
                                            evidence_id
                                            for evidence_id in finding.evidence_ids
                                            if isinstance(evidence_id, str) and evidence_id
                                        ]
                                        if isinstance(finding.evidence_ids, list)
                                        else []
                                    ),
                                    *refutation_evidence_ids,
                                ]
                            )
                        )
                        repaired_evidence_ids = [
                            evidence_id
                            for evidence_id in repaired_evidence_ids
                            if isinstance(evidence_id, str)
                            and evidence_id in valid_evidence_ids
                        ]
                        if (
                            metadata.get("refutation_attempt_ids") != refutation_ids
                            or finding.evidence_ids != repaired_evidence_ids
                            or metadata.get("harm_demonstrated") is not False
                        ):
                            metadata["refutation_attempt_ids"] = refutation_ids
                            metadata["harm_demonstrated"] = False
                            metadata["proof_backlog"] = {
                                **(
                                    dict(metadata.get("proof_backlog"))
                                    if isinstance(metadata.get("proof_backlog"), dict)
                                    else {}
                                ),
                                "status": "refuted",
                            }
                            finding.evidence_ids = repaired_evidence_ids
                            finding.metadata_json = metadata
                            changed = True
                            affected_scan_ids.add(finding.scan_id)
                        continue
                    finding.status = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                    tier = evidence_backed_signal_tier(session, finding)
                    if tier != "runtime_oracle_gap":
                        finding.status = FindingStatus.SUPPORTED_STATIC.value
                        tier = evidence_backed_signal_tier(session, finding)
                    if tier == "runtime_oracle_gap":
                        finding.status = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                        metadata["signal_tier"] = "runtime_oracle_gap"
                        metadata["proof_gap_code"] = "missing_platform_harm_oracle"
                        metadata["oracle_gap"] = {
                            "schema_version": "1.0",
                            "status": "open",
                            "runtime_observed": True,
                        }
                        backlog_status = "oracle_gap"
                    elif tier == "static_chain":
                        finding.status = FindingStatus.SUPPORTED_STATIC.value
                        metadata["signal_tier"] = "static_chain"
                        metadata.pop("proof_gap_code", None)
                        metadata.pop("oracle_gap", None)
                        backlog_status = "proof_required"
                    else:
                        finding.status = FindingStatus.INCONCLUSIVE.value
                        metadata.pop("signal_tier", None)
                        metadata.pop("proof_gap_code", None)
                        metadata.pop("oracle_gap", None)
                        metadata.pop("platform_static_support_gate", None)
                        metadata.pop("chain_receipt", None)
                        backlog_status = "proof_required"
                    metadata["refutation_attempt_ids"] = []
                    metadata["harm_demonstrated"] = False
                    metadata["proof_backlog"] = {
                        **(
                            dict(metadata.get("proof_backlog"))
                            if isinstance(metadata.get("proof_backlog"), dict)
                            else {}
                        ),
                        "status": backlog_status,
                    }
                    metadata["negative_verdict_reconciliation"] = {
                        "schema_version": "1.0",
                        "previous_status": FindingStatus.NOT_REPRODUCED.value,
                        "reason": (
                            "Legacy not_reproduced verdict had no attributable "
                            "evidence-backed platform Oracle refutation receipt."
                        ),
                    }
                    finding.metadata_json = metadata
                    changed = True
                    affected_scan_ids.add(finding.scan_id)
                    continue
                if finding.status == FindingStatus.REFUTED_STATIC.value:
                    if static_refutation_is_evidence_backed(session, finding):
                        continue
                    reported_gate = metadata.pop(
                        "platform_static_refutation_gate",
                        None,
                    )
                    finding.status = FindingStatus.INCONCLUSIVE.value
                    metadata["harm_demonstrated"] = False
                    metadata["proof_backlog"] = {
                        **(
                            dict(metadata.get("proof_backlog"))
                            if isinstance(metadata.get("proof_backlog"), dict)
                            else {}
                        ),
                        "status": "proof_required",
                    }
                    metadata["static_refutation_reconciliation"] = {
                        "schema_version": "1.0",
                        "previous_status": FindingStatus.REFUTED_STATIC.value,
                        "reason": (
                            "Legacy refuted_static verdict had no complete platform static-"
                            "refutation receipt backed by usable same-scan Evidence."
                        ),
                        **(
                            {"reported_gate": reported_gate}
                            if isinstance(reported_gate, dict)
                            else {}
                        ),
                    }
                    finding.metadata_json = metadata
                    changed = True
                    affected_scan_ids.add(finding.scan_id)
                    continue
                if finding.status != FindingStatus.REPRODUCED_BLACKBOX.value:
                    continue
                finding.status = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                tier = evidence_backed_signal_tier(session, finding)
                if tier != "runtime_oracle_gap":
                    finding.status = FindingStatus.SUPPORTED_STATIC.value
                    tier = evidence_backed_signal_tier(session, finding)
                if tier == "runtime_oracle_gap":
                    finding.status = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                    metadata["signal_tier"] = "runtime_oracle_gap"
                    metadata["proof_gap_code"] = "missing_platform_harm_oracle"
                    metadata["oracle_gap"] = {
                        **(
                            dict(metadata.get("oracle_gap"))
                            if isinstance(metadata.get("oracle_gap"), dict)
                            else {}
                        ),
                        "schema_version": "1.0",
                        "status": "open",
                        "runtime_observed": True,
                    }
                    backlog_status = "oracle_gap"
                elif tier == "static_chain":
                    finding.status = FindingStatus.SUPPORTED_STATIC.value
                    metadata["signal_tier"] = "static_chain"
                    metadata.pop("proof_gap_code", None)
                    metadata.pop("oracle_gap", None)
                    backlog_status = "proof_required"
                else:
                    finding.status = FindingStatus.CANDIDATE.value
                    metadata.pop("signal_tier", None)
                    metadata.pop("proof_gap_code", None)
                    metadata.pop("oracle_gap", None)
                    metadata.pop("platform_static_support_gate", None)
                    metadata.pop("chain_receipt", None)
                    backlog_status = "proof_required"
                metadata.update(
                    {
                        "harm_demonstrated": False,
                        "release_gate_eligible": False,
                        "proof_attempt_ids": [],
                        "proof_backlog": {
                            **(
                                dict(metadata.get("proof_backlog"))
                                if isinstance(metadata.get("proof_backlog"), dict)
                                else {}
                            ),
                            "status": backlog_status,
                        },
                        "verdict_reconciliation": {
                            "schema_version": "1.0",
                            "reason": (
                                "Legacy reproduced verdict had no attributable platform "
                                "ProofAttempt with harm_demonstrated=true."
                            ),
                        },
                    }
                )
                finding.metadata_json = metadata
                changed = True
                affected_scan_ids.add(finding.scan_id)
            orphan_hypotheses = list(
                session.scalars(
                    select(SecurityHypothesis).where(
                        SecurityHypothesis.final_finding_id.is_(None)
                    )
                )
            )
            for hypothesis in orphan_hypotheses:
                attempts = evidence_backed_harm_attempts(
                    session,
                    scan_id=hypothesis.scan_id,
                    task_id=hypothesis.task_id,
                    hypothesis_ids={hypothesis.id},
                )
                if not attempts:
                    continue
                task = session.get(InvestigationTask, hypothesis.task_id)
                task_result = (
                    task.result
                    if task is not None and isinstance(task.result, dict)
                    else {}
                )
                severity = task_result.get("platform_severity") or task_result.get(
                    "severity_proposal"
                )
                if severity not in {"info", "low", "medium", "high", "critical"}:
                    severity = "high"
                proof_evidence_ids = list(
                    dict.fromkeys(
                        evidence_id
                        for attempt in attempts
                        for evidence_id in (
                            attempt.evidence_ids
                            if isinstance(attempt.evidence_ids, list)
                            else []
                        )
                        if isinstance(evidence_id, str) and evidence_id
                    )
                )
                recovered = Finding(
                    scan_id=hypothesis.scan_id,
                    dedupe_key=f"recovered-proof:{hypothesis.id}",
                    rule_id="PLATFORM-PROOF-RECOVERY",
                    source="platform",
                    title=f"已复现：{hypothesis.claim[:220]}",
                    description=(
                        "平台在进程中断前已持久化可归因的危害 ProofAttempt；"
                        "本记录由启动恢复流程重新物化。"
                    ),
                    remediation="根据已证明的攻击路径补充调用者校验、输入约束和敏感操作授权。",
                    masvs="MASVS-PLATFORM",
                    severity=severity,
                    confidence="high",
                    status=FindingStatus.REPRODUCED_BLACKBOX.value,
                    entry_point_ids=[
                        entry_point_id
                        for entry_point_id in (
                            hypothesis.entry_point_ids
                            if isinstance(hypothesis.entry_point_ids, list)
                            else []
                        )
                        if isinstance(entry_point_id, str) and entry_point_id
                    ],
                    evidence_ids=proof_evidence_ids,
                    metadata_json={
                        "hypothesis_id": hypothesis.id,
                        "task_id": hypothesis.task_id,
                        "proof_attempt_ids": [attempt.id for attempt in attempts],
                        "harm_demonstrated": True,
                        "release_gate_eligible": any(
                            (
                                attempt.oracle
                                if isinstance(attempt.oracle, dict)
                                else {}
                            ).get("release_gate_eligible")
                            is True
                            for attempt in attempts
                        ),
                        "proof_backlog": {"status": "verified"},
                        "verdict_reconciliation": {
                            "schema_version": "1.0",
                            "reason": (
                                "Recovered a platform proof committed before an interrupted "
                                "Finding materialization."
                            ),
                        },
                    },
                )
                session.add(recovered)
                session.flush()
                hypothesis.final_finding_id = recovered.id
                changed = True
                affected_scan_ids.add(hypothesis.scan_id)
            if changed:
                for scan_id in affected_scan_ids:
                    invalidate_scan_materialized_summary(
                        session,
                        scan_id,
                        reason="startup_finding_proof_reconciliation",
                    )
                session.commit()

    def session(self) -> Generator[Session, None, None]:
        with self.session_factory() as session:
            yield session
