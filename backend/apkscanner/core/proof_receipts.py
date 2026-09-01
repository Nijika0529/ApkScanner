from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Evidence, Finding, ProofAttempt, SecurityHypothesis


def _allowed_hypothesis_ids(session: Session, finding: Finding) -> set[str]:
    """Return hypotheses that are actually attached to this finding in the same scan."""

    metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
    metadata_hypothesis_id = metadata.get("hypothesis_id")
    conditions = [SecurityHypothesis.final_finding_id == finding.id]
    if isinstance(metadata_hypothesis_id, str) and metadata_hypothesis_id:
        conditions.append(SecurityHypothesis.id == metadata_hypothesis_id)
    hypotheses = session.scalars(
        select(SecurityHypothesis).where(
            SecurityHypothesis.scan_id == finding.scan_id,
            or_(*conditions),
        )
    )
    return {
        hypothesis.id
        for hypothesis in hypotheses
        if hypothesis.final_finding_id in {None, finding.id}
    }


def _attributable_attempts(
    session: Session,
    finding: Finding,
    *,
    metadata_key: str,
    qualifies: Callable[[ProofAttempt], bool],
) -> list[ProofAttempt]:
    metadata = (
        dict(finding.metadata_json)
        if isinstance(finding.metadata_json, dict)
        else {}
    )
    raw_declared_ids = metadata.get(metadata_key, [])
    if not isinstance(raw_declared_ids, list):
        raw_declared_ids = []
    declared_ids = [
        value
        for value in raw_declared_ids
        if isinstance(value, str) and value
    ]
    allowed_hypothesis_ids = _allowed_hypothesis_ids(session, finding)
    if not allowed_hypothesis_ids:
        return []
    base = select(ProofAttempt).where(ProofAttempt.scan_id == finding.scan_id)

    attempts: list[ProofAttempt] = []
    if declared_ids:
        attempts = [
            attempt
            for attempt in session.scalars(
                base.where(
                    ProofAttempt.id.in_(declared_ids),
                    ProofAttempt.hypothesis_id.in_(allowed_hypothesis_ids),
                ).order_by(ProofAttempt.created_at)
            )
            if qualifies(attempt)
        ]
    if not attempts:
        attempts = list(
            session.scalars(
                base.where(
                    ProofAttempt.hypothesis_id.in_(allowed_hypothesis_ids)
                ).order_by(ProofAttempt.created_at)
            )
        )
    return [attempt for attempt in attempts if qualifies(attempt)]


def attributable_harm_attempts(
    session: Session,
    finding: Finding,
) -> list[ProofAttempt]:
    """Return same-scan harm receipts bound to this finding's hypotheses."""

    attempts = _attributable_attempts(
        session,
        finding,
        metadata_key="proof_attempt_ids",
        qualifies=lambda attempt: (
            attempt.status == "proven" and attempt.harm_demonstrated is True
        ),
    )
    return _evidence_backed_attempts_for_scan(session, finding.scan_id, attempts)


def attributable_harm_attempts_by_finding(
    session: Session,
    findings: Iterable[Finding],
) -> dict[str, list[ProofAttempt]]:
    """Bulk form of ``attributable_harm_attempts`` for list/report endpoints."""

    items = list(findings)
    result: dict[str, list[ProofAttempt]] = {finding.id: [] for finding in items}
    findings_by_scan: dict[str, list[Finding]] = defaultdict(list)
    for finding in items:
        findings_by_scan[finding.scan_id].append(finding)
    for scan_id, scan_findings in findings_by_scan.items():
        finding_ids = {finding.id for finding in scan_findings}
        metadata_hypothesis_by_finding = {
            finding.id: metadata_hypothesis_id
            for finding in scan_findings
            if isinstance(finding.metadata_json, dict)
            and isinstance(
                metadata_hypothesis_id := finding.metadata_json.get("hypothesis_id"),
                str,
            )
            and metadata_hypothesis_id
        }
        metadata_hypothesis_ids = set(metadata_hypothesis_by_finding.values())
        conditions = [SecurityHypothesis.final_finding_id.in_(finding_ids)]
        if metadata_hypothesis_ids:
            conditions.append(SecurityHypothesis.id.in_(metadata_hypothesis_ids))
        hypotheses = list(
            session.scalars(
                select(SecurityHypothesis).where(
                    SecurityHypothesis.scan_id == scan_id,
                    or_(*conditions),
                )
            )
        )
        hypotheses_by_id = {hypothesis.id: hypothesis for hypothesis in hypotheses}
        hypothesis_ids_by_finding: dict[str, set[str]] = defaultdict(set)
        for hypothesis in hypotheses:
            if hypothesis.final_finding_id in finding_ids:
                hypothesis_ids_by_finding[hypothesis.final_finding_id].add(hypothesis.id)
        for finding_id, hypothesis_id in metadata_hypothesis_by_finding.items():
            hypothesis = hypotheses_by_id.get(hypothesis_id)
            if hypothesis is not None and hypothesis.final_finding_id in {None, finding_id}:
                hypothesis_ids_by_finding[finding_id].add(hypothesis_id)
        all_hypothesis_ids = {
            hypothesis_id
            for hypothesis_ids in hypothesis_ids_by_finding.values()
            for hypothesis_id in hypothesis_ids
        }
        attempts = evidence_backed_harm_attempts(
            session,
            scan_id=scan_id,
            hypothesis_ids=all_hypothesis_ids,
        )
        attempts_by_hypothesis: dict[str, list[ProofAttempt]] = defaultdict(list)
        for attempt in attempts:
            attempts_by_hypothesis[attempt.hypothesis_id].append(attempt)
        for finding in scan_findings:
            result[finding.id] = [
                attempt
                for hypothesis_id in hypothesis_ids_by_finding.get(finding.id, set())
                for attempt in attempts_by_hypothesis.get(hypothesis_id, [])
            ]
            result[finding.id].sort(key=lambda attempt: attempt.created_at)
    return result


def _evidence_backed_attempts_for_scan(
    session: Session,
    scan_id: str,
    attempts: list[ProofAttempt],
) -> list[ProofAttempt]:
    evidence_ids = {
        evidence_id
        for attempt in attempts
        for evidence_id in (
            attempt.evidence_ids if isinstance(attempt.evidence_ids, list) else []
        )
        if isinstance(evidence_id, str) and evidence_id
    }
    if not evidence_ids:
        return []
    valid_evidence_ids = set(
        session.scalars(
            select(Evidence.id).where(
                Evidence.scan_id == scan_id,
                Evidence.id.in_(evidence_ids),
            )
        )
    )
    return [
        attempt
        for attempt in attempts
        if isinstance(attempt.evidence_ids, list)
        and bool(attempt.evidence_ids)
        and all(
            isinstance(evidence_id, str)
            and bool(evidence_id)
            and evidence_id in valid_evidence_ids
            for evidence_id in attempt.evidence_ids
        )
    ]


def evidence_backed_harm_attempts(
    session: Session,
    *,
    scan_id: str,
    task_id: str | None = None,
    hypothesis_ids: set[str] | None = None,
) -> list[ProofAttempt]:
    """Return proven harm attempts whose complete evidence receipt exists in the scan."""

    query = select(ProofAttempt).where(
        ProofAttempt.scan_id == scan_id,
        ProofAttempt.status == "proven",
        ProofAttempt.harm_demonstrated.is_(True),
    )
    if task_id is not None:
        query = query.where(ProofAttempt.task_id == task_id)
    if hypothesis_ids is not None:
        if not hypothesis_ids:
            return []
        query = query.where(ProofAttempt.hypothesis_id.in_(hypothesis_ids))
    attempts = list(session.scalars(query.order_by(ProofAttempt.created_at)))
    return _evidence_backed_attempts_for_scan(session, scan_id, attempts)


def attributable_refutation_attempts(
    session: Session,
    finding: Finding,
) -> list[ProofAttempt]:
    """Return same-scan, evidence-backed platform Oracle refutations for this finding."""

    attempts = _attributable_attempts(
        session,
        finding,
        metadata_key="refutation_attempt_ids",
        qualifies=lambda attempt: (
            attempt.status == "refuted"
            and attempt.harm_demonstrated is False
            and bool(attempt.evidence_ids)
            and (
                attempt.oracle if isinstance(attempt.oracle, dict) else {}
            ).get("oracle_refuted")
            is True
            and (
                attempt.oracle if isinstance(attempt.oracle, dict) else {}
            ).get("execution_demonstrated")
            is True
            and (
                attempt.oracle if isinstance(attempt.oracle, dict) else {}
            ).get("dynamic_verdict_eligible")
            is True
        ),
    )
    return _evidence_backed_attempts_for_scan(session, finding.scan_id, attempts)
