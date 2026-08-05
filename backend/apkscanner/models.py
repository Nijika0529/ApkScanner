from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    filename: Mapped[str] = mapped_column(String(512))
    artifact_sha256: Mapped[str] = mapped_column(String(64), index=True)
    artifact_path: Mapped[str] = mapped_column(Text)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    min_sdk: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_sdk: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signing: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    preliminary_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    entries: Mapped[list[EntryPoint]] = relationship(back_populates="scan", cascade="all, delete")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete")
    tasks: Mapped[list[InvestigationTask]] = relationship(
        back_populates="scan", cascade="all, delete"
    )
    coverage: Mapped[list[CoverageItem]] = relationship(
        back_populates="scan", cascade="all, delete"
    )
    events: Mapped[list[ScanEvent]] = relationship(back_populates="scan", cascade="all, delete")
    security_hypotheses: Mapped[list[SecurityHypothesis]] = relationship(
        back_populates="scan", cascade="all, delete"
    )
    benchmark_evaluations: Mapped[list[BenchmarkEvaluation]] = relationship(
        back_populates="scan", cascade="all, delete"
    )
    security_snapshot: Mapped[SecuritySnapshot | None] = relationship(
        back_populates="scan", cascade="all, delete", uselist=False
    )


class AdbDeviceRecord(Base):
    """Persistent operator-managed membership of the runtime ADB pool."""

    __tablename__ = "adb_devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    serial: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="ready", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    api_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    android_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ApplicationRecord(Base):
    """Stable application identity independent from any one uploaded APK."""

    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    package_name: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ApplicationRelease(Base):
    """Identity and analysis-profile snapshot for one scan in an app version line."""

    __tablename__ = "application_releases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    signer_digest: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    identity_status: Mapped[str] = mapped_column(String(32), default="unverified", index=True)
    version_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    artifact_sha256: Mapped[str] = mapped_column(String(64), index=True)
    snapshot_hash: Mapped[str] = mapped_column(String(64), index=True)
    analysis_profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VulnerabilityCase(Base):
    """Human-maintained vulnerability identity spanning application releases."""

    __tablename__ = "vulnerability_cases"
    __table_args__ = (
        UniqueConstraint("application_id", "case_key", name="uq_vulnerability_case_key"),
        UniqueConstraint(
            "application_id",
            "fingerprint_version",
            "fingerprint",
            name="uq_vulnerability_case_fingerprint",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    case_key: Mapped[str] = mapped_column(String(128), index=True)
    fingerprint_version: Mapped[str] = mapped_column(String(32), default="case-v1")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    identity_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    title: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str] = mapped_column(Text, default="")
    harm: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    masvs: Mapped[str] = mapped_column(String(128), default="MASVS-PLATFORM")
    minimum_proof: Mapped[str] = mapped_column(String(32), default="dynamic")
    lifecycle: Mapped[str] = mapped_column(String(32), default="active", index=True)
    source_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class VulnerabilityOccurrence(Base):
    """One case's machine observation on one concrete APK scan."""

    __tablename__ = "vulnerability_occurrences"
    __table_args__ = (
        UniqueConstraint("case_id", "scan_id", name="uq_vulnerability_occurrence_scan"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerability_cases.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    analysis_status: Mapped[str] = mapped_column(String(32), default="inconclusive", index=True)
    proof_level: Mapped[str] = mapped_column(String(32), default="none")
    match_quality: Mapped[str] = mapped_column(String(32), default="strong")
    match_reason: Mapped[str] = mapped_column(Text, default="")
    observed_identity_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class EntryPoint(Base):
    __tablename__ = "entry_points"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    kind: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(1024))
    owner_component: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    exported: Mapped[bool] = mapped_column(Boolean, default=False)
    exported_reason: Mapped[str] = mapped_column(String(256), default="explicit_false")
    permission: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    permission_protection: Mapped[str | None] = mapped_column(String(128), nullable=True)
    intent_filters: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    deep_links: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    code_anchors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="entries")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "dedupe_key", name="uq_findings_scan_dedupe"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    dedupe_key: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(256), index=True)
    source: Mapped[str] = mapped_column(String(128), default="builtin")
    title: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default="")
    masvs: Mapped[str] = mapped_column(String(128), index=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="candidate", index=True)
    entry_point_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    locations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")


class InvestigationTask(Base):
    __tablename__ = "investigation_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    task_type: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    target_entry_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    hypotheses: Mapped[list[str]] = mapped_column(JSON, default=list)
    preconditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    allowed_side_effects: Mapped[list[str]] = mapped_column(JSON, default=list)
    device_profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    thread_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    turn_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="tasks")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    kind: Mapped[str] = mapped_column(String(64), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    path: Mapped[str] = mapped_column(Text)
    command: Mapped[list[str]] = mapped_column(JSON, default=list)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityHypothesis(Base):
    __tablename__ = "security_hypotheses"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_security_hypothesis_scan_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"), index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(128), index=True)
    claim: Mapped[str] = mapped_column(Text)
    attacker_model: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    preconditions: Mapped[list[str]] = mapped_column(JSON, default=list)
    impact: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="candidate", index=True)
    confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    source_role: Mapped[str] = mapped_column(String(64), default="platform_seed")
    entry_point_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    support_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    refute_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    proof_obligations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    final_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="security_hypotheses")
    arguments: Mapped[list[HypothesisArgument]] = relationship(
        back_populates="hypothesis",
        cascade="all, delete",
        order_by="HypothesisArgument.created_at",
    )
    proof_attempts: Mapped[list[ProofAttempt]] = relationship(
        back_populates="hypothesis",
        cascade="all, delete",
        order_by="ProofAttempt.created_at",
    )


class HypothesisArgument(Base):
    __tablename__ = "hypothesis_arguments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"), index=True
    )
    hypothesis_id: Mapped[str] = mapped_column(
        ForeignKey("security_hypotheses.id", ondelete="CASCADE"), index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    role: Mapped[str] = mapped_column(String(32), index=True)
    position: Mapped[str] = mapped_column(String(32), index=True)
    phase: Mapped[str] = mapped_column(String(64), index=True)
    backend: Mapped[str] = mapped_column(String(32), default="platform")
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    hypothesis: Mapped[SecurityHypothesis] = relationship(back_populates="arguments")


class ProofAttempt(Base):
    __tablename__ = "proof_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"), index=True
    )
    hypothesis_id: Mapped[str] = mapped_column(
        ForeignKey("security_hypotheses.id", ondelete="CASCADE"), index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    test_case_id: Mapped[str] = mapped_column(String(128), index=True)
    prover: Mapped[str] = mapped_column(String(128), default="android_entry_probe")
    status: Mapped[str] = mapped_column(String(32), default="planned", index=True)
    plan: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    oracle: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    harm_demonstrated: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    hypothesis: Mapped[SecurityHypothesis] = relationship(back_populates="proof_attempts")


class SecuritySnapshot(Base):
    """Content-addressed security facts for one application version."""

    __tablename__ = "security_snapshots"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_security_snapshot_scan"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    package_name: Mapped[str] = mapped_column(String(512), index=True)
    signer_digest: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    version_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    snapshot_hash: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="security_snapshot")


class VersionDiff(Base):
    """Semantic security delta between two same-identity application scans."""

    __tablename__ = "version_diffs"
    __table_args__ = (
        UniqueConstraint(
            "baseline_scan_id",
            "target_scan_id",
            name="uq_version_diff_scan_pair",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    baseline_scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    target_scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    status: Mapped[str] = mapped_column(String(32), default="completed", index=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    entry_mapping: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    deltas: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    replay_candidates: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VulnerabilityPattern(Base):
    """Reusable, package-independent pattern distilled from a proven finding."""

    __tablename__ = "vulnerability_patterns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="validated", index=True)
    source_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    vulnerability_class: Mapped[str] = mapped_column(String(256), index=True)
    title: Mapped[str] = mapped_column(String(1024))
    attacker_model: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    entry_signature: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    code_signature: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    missing_guards: Mapped[list[str]] = mapped_column(JSON, default=list)
    exclusion_conditions: Mapped[list[str]] = mapped_column(JSON, default=list)
    proof_recipe: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class PatternMatch(Base):
    """A non-finding candidate produced by deterministic pattern search."""

    __tablename__ = "pattern_matches"
    __table_args__ = (
        UniqueConstraint(
            "pattern_id",
            "scan_id",
            "entry_point_id",
            name="uq_pattern_match_target",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    pattern_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerability_patterns.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    entry_point_id: Mapped[str] = mapped_column(
        ForeignKey("entry_points.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="candidate_match", index=True)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BenchmarkEvaluation(Base):
    __tablename__ = "benchmark_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    name: Mapped[str] = mapped_column(String(256))
    artifact_sha256: Mapped[str] = mapped_column(String(64), index=True)
    investigator_backend: Mapped[str] = mapped_column(String(32), default="none")
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ground_truth: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="benchmark_evaluations")


class InvestigationBrief(Base):
    """A first-class contract for non-standard or app-internal investigations."""

    __tablename__ = "investigation_briefs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    name: Mapped[str] = mapped_column(String(256))
    objective: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    attacker_model: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    preconditions: Mapped[list[str]] = mapped_column(JSON, default=list)
    plan: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evaluation_contract: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CoverageItem(Base):
    __tablename__ = "coverage_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    control_id: Mapped[str] = mapped_column(String(256), index=True)
    domain: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="not_tested")
    stages: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    gap_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    entry_point_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    scan: Mapped[Scan] = relationship(back_populates="coverage")


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="events")


class AgentRuntimeEventRecord(Base):
    """Idempotency ledger for live and spool-recovered Agent runtime events."""

    __tablename__ = "agent_runtime_event_records"
    __table_args__ = (
        UniqueConstraint("record_key", name="uq_agent_runtime_event_record_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
    )
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"),
        index=True,
    )
    session_id: Mapped[str] = mapped_column(String(512), index=True)
    protocol_stream_id: Mapped[str] = mapped_column(String(64), index=True)
    worker_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    record_key: Mapped[str] = mapped_column(String(768), unique=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    delivery_source: Mapped[str] = mapped_column(String(32), default="live", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanContainerRecord(Base):
    """Durable lifecycle record for a scan-scoped worker container/workspace."""

    __tablename__ = "scan_container_records"
    __table_args__ = (
        UniqueConstraint("container_key", name="uq_scan_container_record_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    container_key: Mapped[str] = mapped_column(String(768), unique=True)
    isolation: Mapped[str] = mapped_column(String(32), default="docker")
    workspace_path: Mapped[str] = mapped_column(Text, default="")
    container_name: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="prepared", index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AgentSessionRecord(Base):
    """Stable Agent session identity independent from verbose runtime events."""

    __tablename__ = "agent_session_records"
    __table_args__ = (
        UniqueConstraint("session_key", name="uq_agent_session_record_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"), index=True
    )
    container_record_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_container_records.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_key: Mapped[str] = mapped_column(String(768), unique=True)
    role: Mapped[str] = mapped_column(String(64), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    backend: Mapped[str] = mapped_column(String(32), default="codex")
    provider: Mapped[str | None] = mapped_column(String(256), nullable=True)
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    thread_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AgentTurnRecord(Base):
    """One auditable provider turn; the audit ID is its idempotency key."""

    __tablename__ = "agent_turn_records"
    __table_args__ = (UniqueConstraint("audit_id", name="uq_agent_turn_audit_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"), index=True
    )
    session_record_id: Mapped[str] = mapped_column(
        ForeignKey("agent_session_records.id", ondelete="CASCADE"), index=True
    )
    audit_id: Mapped[str] = mapped_column(String(36), unique=True)
    phase: Mapped[str] = mapped_column(String(64), index=True)
    round_index: Mapped[int] = mapped_column(Integer, default=0)
    turn_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    request_evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    response_evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    usage_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AdaptiveVerificationCheckpoint(Base):
    """Per-candidate checkpoint so one failed batch never discards completed judgments."""

    __tablename__ = "adaptive_verification_checkpoints"
    __table_args__ = (
        UniqueConstraint("task_id", "finding_id", name="uq_adaptive_checkpoint_candidate"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    batch_index: Mapped[int] = mapped_column(Integer)
    audit_id: Mapped[str] = mapped_column(String(36), index=True)
    response_evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    thread_id: Mapped[str] = mapped_column(String(512), default="")
    turn_id: Mapped[str] = mapped_column(String(512), default="")
    assessment_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    environment_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class RuntimeObservation(Base):
    """Normalized runtime fact emitted by ADB, a PoC, WebView, socket, or callback sink."""

    __tablename__ = "runtime_observations"
    __table_args__ = (
        UniqueConstraint("observation_key", name="uq_runtime_observation_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    observation_key: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(64), default="platform", index=True)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    environment: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ValidationFixture(Base):
    """Operator-provided account/session/canary state for repeatable dynamic tests."""

    __tablename__ = "validation_fixtures"
    __table_args__ = (
        UniqueConstraint("scan_id", "name", name="uq_validation_fixture_scan_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(128))
    fixture_type: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    setup_instructions: Mapped[list[str]] = mapped_column(JSON, default=list)
    cleanup_instructions: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CampaignRun(Base):
    """Persistent supervisor campaign with an explicit goal and execution budget."""

    __tablename__ = "campaign_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(256), index=True)
    goal: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    plan_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    max_parallel_scans: Mapped[int] = mapped_column(Integer, default=1)
    total_budget_seconds: Mapped[int] = mapped_column(Integer, default=86_400)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CampaignEntryRecord(Base):
    """Persistent DAG node controlled by the supervisor reconciliation loop."""

    __tablename__ = "campaign_entry_records"
    __table_args__ = (
        UniqueConstraint("campaign_id", "entry_key", name="uq_campaign_entry_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaign_runs.id", ondelete="CASCADE"), index=True
    )
    entry_key: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    depends_on: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    launched_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    capability_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    input_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
