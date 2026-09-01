from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.enums import FindingStatus
from ..core.models import Evidence, Finding, RuntimeObservation
from ..core.proof_receipts import attributable_harm_attempts_by_finding
from .signal_projection import evidence_supports_runtime_observation
from .signal_tiers import SignalTier, finding_signal_tier, valid_static_refutation_gate

EVIDENCE_BACKED_FINDING_STATUSES = {
    FindingStatus.REPRODUCED_BLACKBOX.value,
    FindingStatus.ACCEPTED.value,
}

_UNUSABLE_STATIC_STATUSES = {
    "failed",
    "no_output",
    "output_unusable",
    "partial_timeout",
    "timed_out",
    "timeout",
    "tool_failed",
    "unavailable",
}


def static_evidence_is_usable(
    *,
    kind: object,
    metadata: object,
    exit_code: object = None,
) -> bool:
    """Reject explicit static-tool failures while retaining legacy evidence compatibility."""

    if not isinstance(kind, str) or not kind.startswith("static."):
        return False
    details = metadata if isinstance(metadata, dict) else {}
    explicit = details.get("static_output_usable")
    if explicit is not None:
        return explicit is True
    output_usable = details.get("output_usable")
    if output_usable is True:
        return True
    if output_usable is False:
        return False
    status = str(
        details.get("static_tool_status") or details.get("status") or ""
    ).strip().lower()
    if status in _UNUSABLE_STATIC_STATUSES:
        return False
    timed_out = details.get("static_tool_timed_out", details.get("timed_out"))
    if timed_out is True and output_usable is not True:
        return False
    return not (isinstance(exit_code, int) and exit_code != 0)


def _substantive_refutation_text(value: object, *, minimum: int = 12) -> bool:
    if not isinstance(value, str):
        return False
    normalized = " ".join(value.strip().split())
    return len(normalized) >= minimum and len(
        {character.lower() for character in normalized if character.isalnum()}
    ) >= 3


def build_static_refutation_gate(
    *,
    evidence_by_id: Mapping[str, Evidence | Mapping[str, Any]],
    evidence_ids: Iterable[object],
    counterevidence: object,
    blocked_edge: object,
) -> dict[str, Any]:
    """Build a platform-owned receipt for a concrete, evidence-backed static closure."""

    def evidence_fields(record: Evidence | Mapping[str, Any]) -> tuple[object, object, object]:
        if isinstance(record, Evidence):
            return record.kind, record.metadata_json, record.exit_code
        return (
            record.get("kind"),
            record.get("metadata", record.get("metadata_json")),
            record.get("exit_code"),
        )

    cited_ids = list(
        dict.fromkeys(
            value for value in evidence_ids if isinstance(value, str) and value
        )
    )
    static_evidence_ids: list[str] = []
    for evidence_id in cited_ids:
        record = evidence_by_id.get(evidence_id)
        if record is None:
            continue
        kind, metadata, exit_code = evidence_fields(record)
        if static_evidence_is_usable(
            kind=kind,
            metadata=metadata,
            exit_code=exit_code,
        ):
            static_evidence_ids.append(evidence_id)
    concrete_counterevidence = (
        [value for value in counterevidence if _substantive_refutation_text(value)]
        if isinstance(counterevidence, list)
        else []
    )
    normalized_blocked_edge = (
        " ".join(blocked_edge.strip().split())
        if _substantive_refutation_text(blocked_edge)
        else ""
    )
    suppression_reasons: list[str] = []
    if not static_evidence_ids:
        suppression_reasons.append("missing_usable_static_evidence")
    if not concrete_counterevidence:
        suppression_reasons.append("missing_concrete_counterevidence")
    if not normalized_blocked_edge:
        suppression_reasons.append("missing_guard_or_unreachable_edge")
    return {
        "schema_version": "1.0",
        "eligible": not suppression_reasons,
        "static_evidence_ids": static_evidence_ids,
        "counterevidence": concrete_counterevidence,
        "blocked_edge": normalized_blocked_edge,
        "suppression_reasons": suppression_reasons,
    }


def static_refutation_is_evidence_backed(
    session: Session,
    finding: Finding,
) -> bool:
    """Revalidate a persisted static-refutation receipt against same-scan Evidence."""

    metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
    if not valid_static_refutation_gate(metadata):
        return False
    gate = metadata["platform_static_refutation_gate"]
    gate_ids = {
        value
        for value in gate["static_evidence_ids"]
        if isinstance(value, str) and value
    }
    finding_ids = {
        value
        for value in (
            finding.evidence_ids if isinstance(finding.evidence_ids, list) else []
        )
        if isinstance(value, str) and value
    }
    if not gate_ids or not gate_ids.issubset(finding_ids):
        return False
    evidence_by_id = {
        evidence.id: evidence
        for evidence in session.scalars(
            select(Evidence).where(
                Evidence.scan_id == finding.scan_id,
                Evidence.id.in_(gate_ids),
            )
        )
    }
    return gate_ids == set(evidence_by_id) and all(
        static_evidence_is_usable(
            kind=evidence.kind,
            metadata=evidence.metadata_json,
            exit_code=evidence.exit_code,
        )
        for evidence in evidence_by_id.values()
    )


def evidence_backed_signal_tier(session: Session, finding: Finding) -> SignalTier:
    """Return the public tier, validating static gate references against stored evidence."""

    return evidence_backed_signal_tiers(session, [finding])[finding.id]


def evidence_backed_signal_tiers(
    session: Session,
    findings: Iterable[Finding],
) -> dict[str, SignalTier]:
    """Bulk public-tier projection with a bounded number of evidence queries per scan."""

    items = list(findings)
    result: dict[str, SignalTier] = {
        finding.id: finding_signal_tier(finding.status, finding.metadata_json)
        for finding in items
    }
    findings_by_scan: dict[str, list[Finding]] = defaultdict(list)
    for finding in items:
        findings_by_scan[finding.scan_id].append(finding)
    for scan_id, scan_findings in findings_by_scan.items():
        finding_by_id = {finding.id: finding for finding in scan_findings}
        runtime_findings = [
            finding
            for finding in scan_findings
            if result[finding.id] == "runtime_oracle_gap"
        ]
        runtime_ids = {finding.id for finding in runtime_findings}
        observations = (
            list(
                session.scalars(
                    select(RuntimeObservation).where(
                        RuntimeObservation.scan_id == scan_id,
                        RuntimeObservation.finding_id.in_(runtime_ids),
                    )
                )
            )
            if runtime_ids
            else []
        )
        runtime_evidence_ids_by_finding: dict[str, set[str]] = defaultdict(set)
        for observation in observations:
            runtime_evidence_ids_by_finding[observation.finding_id].update(
                evidence_id
                for evidence_id in (
                    observation.evidence_ids
                    if isinstance(observation.evidence_ids, list)
                    else []
                )
                if isinstance(evidence_id, str) and evidence_id
            )

        static_gate_ids_by_finding: dict[str, set[str]] = {}
        for finding in scan_findings:
            if result[finding.id] != "static_chain":
                continue
            metadata = (
                finding.metadata_json
                if isinstance(finding.metadata_json, dict)
                else {}
            )
            gate = metadata.get("platform_static_support_gate")
            gate = gate if isinstance(gate, dict) else {}
            raw_gate_ids = gate.get("static_evidence_ids")
            static_gate_ids_by_finding[finding.id] = (
                {
                    value
                    for value in raw_gate_ids
                    if isinstance(value, str) and value
                }
                if isinstance(raw_gate_ids, list)
                else set()
            )
        all_evidence_ids = {
            evidence_id
            for evidence_ids in [
                *runtime_evidence_ids_by_finding.values(),
                *static_gate_ids_by_finding.values(),
            ]
            for evidence_id in evidence_ids
        }
        evidence_by_id = {
            evidence.id: evidence
            for evidence in (
                session.scalars(
                    select(Evidence).where(
                        Evidence.scan_id == scan_id,
                        Evidence.id.in_(all_evidence_ids),
                    )
                )
                if all_evidence_ids
                else []
            )
        }
        for finding in runtime_findings:
            result[finding.id] = (
                "runtime_oracle_gap"
                if any(
                    evidence_supports_runtime_observation(evidence_by_id[evidence_id])
                    for evidence_id in runtime_evidence_ids_by_finding.get(
                        finding.id, set()
                    )
                    if evidence_id in evidence_by_id
                )
                else "raw_candidate"
            )
        for finding_id, gate_ids in static_gate_ids_by_finding.items():
            finding = finding_by_id[finding_id]
            finding_ids = {
                value
                for value in (
                    finding.evidence_ids
                    if isinstance(finding.evidence_ids, list)
                    else []
                )
                if isinstance(value, str) and value
            }
            result[finding_id] = (
                "static_chain"
                if gate_ids
                and gate_ids.issubset(finding_ids)
                and all(
                    evidence_id in evidence_by_id
                    and static_evidence_is_usable(
                        kind=evidence_by_id[evidence_id].kind,
                        metadata=evidence_by_id[evidence_id].metadata_json,
                        exit_code=evidence_by_id[evidence_id].exit_code,
                    )
                    for evidence_id in gate_ids
                )
                else "raw_candidate"
            )
    return result


def partition_findings(
    session: Session,
    findings: Iterable[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Split proven vulnerabilities from static or otherwise unproven signals."""
    items = list(findings)
    referenced_ids = {
        evidence_id
        for finding in items
        for evidence_id in (
            finding.evidence_ids if isinstance(finding.evidence_ids, list) else []
        )
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
    confirmed: list[Finding] = []
    signals: list[Finding] = []
    proof_candidates = [
        finding
        for finding in items
        if finding.status in EVIDENCE_BACKED_FINDING_STATUSES
        and isinstance(finding.metadata_json, dict)
        and finding.metadata_json.get("harm_demonstrated") is True
    ]
    harm_attempts_by_finding = attributable_harm_attempts_by_finding(
        session,
        proof_candidates,
    )
    for finding in items:
        metadata = (
            finding.metadata_json
            if isinstance(finding.metadata_json, dict)
            else {}
        )
        # Cross-task consolidation keeps source rows and their evidence for audit, but only the
        # canonical record is a user-facing vulnerability or signal.
        if isinstance(metadata.get("merged_into_finding_id"), str):
            continue
        evidence_ids = {
            value
            for value in (
                finding.evidence_ids if isinstance(finding.evidence_ids, list) else []
            )
            if isinstance(value, str) and value
        }
        evidence_backed = bool(evidence_ids) and all(
            (evidence_id, finding.scan_id) in valid_evidence
            for evidence_id in evidence_ids
        )
        proof_backed = (
            bool(harm_attempts_by_finding.get(finding.id))
            if finding.status in EVIDENCE_BACKED_FINDING_STATUSES
            and metadata.get("harm_demonstrated") is True
            and evidence_backed
            else False
        )
        is_confirmed = (
            finding.status in EVIDENCE_BACKED_FINDING_STATUSES
            and metadata.get("harm_demonstrated") is True
            and proof_backed
            and evidence_backed
        )
        (confirmed if is_confirmed else signals).append(finding)
    return confirmed, signals
