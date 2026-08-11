from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .enums import FindingStatus
from .models import Evidence, Finding, ProofAttempt

EVIDENCE_BACKED_FINDING_STATUSES = {
    FindingStatus.REPRODUCED_BLACKBOX.value,
    FindingStatus.ACCEPTED.value,
}


def partition_findings(
    session: Session,
    findings: Iterable[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Split proven vulnerabilities from static or otherwise unproven signals."""
    items = list(findings)
    referenced_ids = {
        evidence_id
        for finding in items
        for evidence_id in finding.evidence_ids
        if isinstance(evidence_id, str) and evidence_id
    }
    valid_evidence = (
        {
            (evidence_id, scan_id)
            for evidence_id, scan_id in session.execute(
                select(Evidence.id, Evidence.scan_id).where(
                    Evidence.id.in_(referenced_ids)
                )
            )
        }
        if referenced_ids
        else set()
    )
    declared_proof_ids = {
        proof_id
        for finding in items
        for proof_id in (finding.metadata_json or {}).get("proof_attempt_ids", [])
        if isinstance(proof_id, str) and proof_id
    }
    valid_proof_ids = (
        set(
            session.scalars(
                select(ProofAttempt.id).where(
                    ProofAttempt.id.in_(declared_proof_ids),
                    ProofAttempt.harm_demonstrated.is_(True),
                )
            )
        )
        if declared_proof_ids
        else set()
    )

    confirmed: list[Finding] = []
    signals: list[Finding] = []
    for finding in items:
        # Cross-task consolidation keeps source rows and their evidence for audit, but only the
        # canonical record is a user-facing vulnerability or signal.
        if isinstance(
            (finding.metadata_json or {}).get("merged_into_finding_id"),
            str,
        ):
            continue
        evidence_ids = {
            value
            for value in finding.evidence_ids
            if isinstance(value, str) and value
        }
        proof_attempt_ids = {
            value
            for value in (finding.metadata_json or {}).get("proof_attempt_ids", [])
            if isinstance(value, str) and value
        }
        proof_backed = bool(proof_attempt_ids & valid_proof_ids)
        is_confirmed = (
            finding.status in EVIDENCE_BACKED_FINDING_STATUSES
            and (finding.metadata_json or {}).get("harm_demonstrated") is True
            and (
                finding.status != FindingStatus.REPRODUCED_BLACKBOX.value
                or proof_backed
            )
            and bool(evidence_ids)
            and all(
                (evidence_id, finding.scan_id) in valid_evidence
                for evidence_id in evidence_ids
            )
        )
        (confirmed if is_confirmed else signals).append(finding)
    return confirmed, signals
