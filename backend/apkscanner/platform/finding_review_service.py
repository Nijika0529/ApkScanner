from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.enums import FindingStatus
from ..core.models import Evidence, Finding
from ..core.proof_receipts import attributable_harm_attempts
from ..core.repository import invalidate_scan_materialized_summary
from ..core.verdicts import decide_human_review


def apply_finding_review(
    session: Session,
    finding: Finding,
    *,
    status: str,
    note: str,
) -> Finding:
    """Apply a human disposition while preserving platform proof invariants."""

    harm_attempts = attributable_harm_attempts(session, finding)
    decide_human_review(
        current_status=finding.status,
        requested_status=status,
        has_harm_proof=bool(harm_attempts),
    )

    if status == FindingStatus.ACCEPTED.value:
        proof_attempt_ids = list(dict.fromkeys(attempt.id for attempt in harm_attempts))
        proof_evidence_ids = list(
            dict.fromkeys(
                evidence_id
                for attempt in harm_attempts
                for evidence_id in (
                    attempt.evidence_ids
                    if isinstance(attempt.evidence_ids, list)
                    else []
                )
                if isinstance(evidence_id, str) and evidence_id
            )
        )
        current_evidence_ids = (
            finding.evidence_ids if isinstance(finding.evidence_ids, list) else []
        )
        candidate_evidence_ids = list(
            dict.fromkeys(
                evidence_id
                for evidence_id in [*current_evidence_ids, *proof_evidence_ids]
                if isinstance(evidence_id, str) and evidence_id
            )
        )
        valid_evidence_ids = set(
            session.scalars(
                select(Evidence.id).where(
                    Evidence.scan_id == finding.scan_id,
                    Evidence.id.in_(candidate_evidence_ids),
                )
            )
        )
        finding.evidence_ids = [
            evidence_id
            for evidence_id in candidate_evidence_ids
            if evidence_id in valid_evidence_ids
        ]
        metadata = (
            dict(finding.metadata_json)
            if isinstance(finding.metadata_json, dict)
            else {}
        )
        metadata["harm_demonstrated"] = True
        metadata["proof_attempt_ids"] = proof_attempt_ids
        metadata["release_gate_eligible"] = any(
            isinstance(attempt.oracle, dict)
            and attempt.oracle.get("release_gate_eligible") is True
            for attempt in harm_attempts
        )
        metadata["proof_backlog"] = {
            **(
                dict(metadata.get("proof_backlog"))
                if isinstance(metadata.get("proof_backlog"), dict)
                else {}
            ),
            "status": "verified",
        }
        metadata.pop("signal_tier", None)
        metadata.pop("proof_gap_code", None)
        metadata.pop("oracle_gap", None)
        finding.metadata_json = metadata

    metadata = (
        dict(finding.metadata_json)
        if isinstance(finding.metadata_json, dict)
        else {}
    )
    report = metadata.get("report")
    if isinstance(report, dict):
        report = dict(report)
        verification = report.get("verification")
        verification = dict(verification) if isinstance(verification, dict) else {}
        if status == FindingStatus.ACCEPTED.value:
            report["kind"] = "finding"
            verification["status"] = "confirmed"
            verification["missing_proof"] = None
            verification["next_step"] = None
            verification["evidence_ids"] = list(finding.evidence_ids or [])
            verification["proof_attempt_ids"] = list(
                metadata.get("proof_attempt_ids") or []
            )
        elif status == FindingStatus.FALSE_POSITIVE.value:
            report["kind"] = "pending_risk"
            verification["status"] = "refuted"
            verification["missing_proof"] = None
            verification["next_step"] = None
        else:
            report["kind"] = "pending_risk"
            verification["status"] = "pending"
        report["verification"] = verification
        metadata["report"] = report
        finding.metadata_json = metadata

    finding.status = status
    finding.review_note = note
    invalidate_scan_materialized_summary(
        session,
        finding.scan_id,
        reason="finding_human_review_changed",
    )
    session.commit()
    session.refresh(finding)
    return finding
