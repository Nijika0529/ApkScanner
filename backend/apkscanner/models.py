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
