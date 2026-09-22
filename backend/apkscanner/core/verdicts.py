from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .enums import FindingStatus

SignalTier = Literal["runtime_oracle_gap", "static_chain", "raw_candidate"]

_CLOSED_STATUSES = frozenset(
    {
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.REFUTED_STATIC.value,
        FindingStatus.NOT_REPRODUCED.value,
    }
)
_RUNTIME_GAP_STATUSES = frozenset(
    {
        FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
        "oracle_gap",
    }
)
_STATIC_GATE_FIELDS = frozenset(
    {
        "source",
        "control",
        "sink",
        "reachable_path",
        "boundary",
        "security_impact",
        "missing_control",
    }
)


class VerdictTransitionError(ValueError):
    """Raised when a requested state change would violate proof invariants."""


@dataclass(frozen=True, slots=True)
class VerdictDecision:
    """Platform-owned result of resolving a requested Finding transition."""

    requested_status: str
    applied_status: str
    override_reason: str | None = None

    @property
    def overridden(self) -> bool:
        return self.requested_status != self.applied_status


def valid_static_support_gate(metadata: dict[str, Any] | None) -> bool:
    """Accept only a current, complete platform gate receipt as static support."""

    payload = metadata if isinstance(metadata, dict) else {}
    gate = payload.get("platform_static_support_gate")
    if not isinstance(gate, dict):
        return False
    required_fields = gate.get("required_fields")
    static_evidence_ids = gate.get("static_evidence_ids")
    suppression_reasons = gate.get("suppression_reasons")
    normalized_required_fields = (
        {
            value
            for value in required_fields
            if isinstance(value, str) and value
        }
        if isinstance(required_fields, list)
        else set()
    )
    return (
        gate.get("schema_version") == "1.0"
        and gate.get("eligible") is True
        and _STATIC_GATE_FIELDS.issubset(normalized_required_fields)
        and isinstance(static_evidence_ids, list)
        and any(isinstance(value, str) and value for value in static_evidence_ids)
        and isinstance(suppression_reasons, list)
        and not suppression_reasons
    )


def valid_static_refutation_gate(metadata: dict[str, Any] | None) -> bool:
    """Validate the durable shape of a platform static-refutation receipt."""

    payload = metadata if isinstance(metadata, dict) else {}
    gate = payload.get("platform_static_refutation_gate")
    if not isinstance(gate, dict):
        return False
    static_evidence_ids = gate.get("static_evidence_ids")
    counterevidence = gate.get("counterevidence")
    blocked_edge = gate.get("blocked_edge")
    suppression_reasons = gate.get("suppression_reasons")

    def substantive(value: object) -> bool:
        if not isinstance(value, str):
            return False
        normalized = " ".join(value.strip().split())
        return len(normalized) >= 12 and len(
            {character.lower() for character in normalized if character.isalnum()}
        ) >= 3

    return (
        gate.get("schema_version") == "1.0"
        and gate.get("eligible") is True
        and isinstance(static_evidence_ids, list)
        and any(isinstance(value, str) and value for value in static_evidence_ids)
        and isinstance(counterevidence, list)
        and any(substantive(value) for value in counterevidence)
        and substantive(blocked_edge)
        and isinstance(suppression_reasons, list)
        and not suppression_reasons
    )


def finding_signal_tier(status: str, metadata: dict[str, Any] | None) -> SignalTier:
    """Classify a non-confirmed record from durable platform facts."""

    if status in _CLOSED_STATUSES:
        return "raw_candidate"
    if status in _RUNTIME_GAP_STATUSES:
        return "runtime_oracle_gap"

    payload = metadata if isinstance(metadata, dict) else {}
    adaptive = payload.get("adaptive_verification")
    adaptive = adaptive if isinstance(adaptive, dict) else {}
    runtime_observed = (
        payload.get("runtime_observed") is True
        or adaptive.get("runtime_observed") is True
    )
    model_verdict = adaptive.get("model_verdict")
    override_reason = adaptive.get("verdict_override_reason") or payload.get(
        "verdict_override_reason"
    )
    if (
        runtime_observed
        and payload.get("harm_demonstrated") is not True
        and (model_verdict == FindingStatus.REPRODUCED_BLACKBOX.value or bool(override_reason))
    ):
        return "runtime_oracle_gap"

    if status in {"static_path_supported", FindingStatus.SUPPORTED_STATIC.value} and (
        valid_static_support_gate(payload)
    ):
        return "static_chain"
    return "raw_candidate"


def decide_human_review(
    *,
    current_status: str,
    requested_status: str,
    has_harm_proof: bool,
) -> VerdictDecision:
    """Resolve a human review without allowing it to fabricate or erase proof."""

    if requested_status == FindingStatus.ACCEPTED.value and not has_harm_proof:
        raise VerdictTransitionError(
            "Only a proof-backed confirmed finding can be accepted; static candidates "
            "and unverified signals must remain pending or be marked false positive."
        )
    if requested_status == FindingStatus.CANDIDATE.value and has_harm_proof:
        raise VerdictTransitionError(
            "A platform-proven finding cannot be downgraded to candidate; use an "
            "explicit false-positive review to override it."
        )
    return VerdictDecision(
        requested_status=requested_status,
        applied_status=requested_status,
    )


def decide_operator_verdict(
    *,
    current_status: str,
    requested_status: str,
    has_harm_proof: bool,
    has_refutation_proof: bool,
    runtime_observed: bool,
    existing_signal_tier: SignalTier,
    preserve_human_closure: bool,
    static_support_eligible: bool,
    static_refutation_eligible: bool,
) -> VerdictDecision:
    """Resolve an Operator proposal against platform-owned proof facts.

    This is deliberately pure. Operator, API, recovery, and future automation all
    consume the same transition policy instead of maintaining subtly different
    status ladders.
    """

    applied = requested_status
    reason: str | None = None
    if preserve_human_closure:
        applied = current_status
        reason = (
            "A human disposition can only be replaced by an explicit human review. "
            "The Operator evidence was retained for that review."
        )
    elif requested_status == "unchanged" and current_status == FindingStatus.ACCEPTED.value:
        applied = current_status
    elif has_harm_proof:
        applied = FindingStatus.REPRODUCED_BLACKBOX.value
        if requested_status != applied:
            reason = "An attributable platform harm receipt prevents an Operator downgrade."
    elif requested_status == "unchanged":
        applied = current_status
    elif requested_status == FindingStatus.REPRODUCED_BLACKBOX.value:
        if runtime_observed or existing_signal_tier == "runtime_oracle_gap":
            applied = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
            reason = (
                "Runtime behavior was observed, but no attributable platform harm "
                "ProofAttempt exists."
            )
        else:
            applied = FindingStatus.INCONCLUSIVE.value
            reason = (
                "Operator evidence did not include an attributable platform harm "
                "ProofAttempt or a platform runtime observation."
            )
    elif requested_status == FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value:
        if not runtime_observed and existing_signal_tier != "runtime_oracle_gap":
            applied = FindingStatus.INCONCLUSIVE.value
            reason = "No platform runtime-observation receipt was attributable to the finding."
    elif requested_status == FindingStatus.NOT_REPRODUCED.value:
        if not has_refutation_proof:
            applied = (
                FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                if runtime_observed or existing_signal_tier == "runtime_oracle_gap"
                else FindingStatus.INCONCLUSIVE.value
            )
            reason = (
                "A negative Operator verdict requires an attributable platform Oracle "
                "refutation receipt."
            )
    elif requested_status == FindingStatus.SUPPORTED_STATIC.value:
        if existing_signal_tier == "runtime_oracle_gap":
            applied = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
            reason = "A static Operator assessment cannot erase an existing runtime Oracle gap."
        elif not static_support_eligible:
            applied = current_status
            reason = "Static support requires the platform's complete static-chain gate receipt."
    elif requested_status == FindingStatus.REFUTED_STATIC.value:
        if runtime_observed or existing_signal_tier == "runtime_oracle_gap":
            applied = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
            reason = (
                "A model-only static refutation cannot close an existing runtime observation; "
                "an attributable platform Oracle refutation is required."
            )
        elif not static_refutation_eligible:
            applied = FindingStatus.INCONCLUSIVE.value
            reason = (
                "Static refutation requires attributable usable static Evidence, concrete "
                "counterevidence, and an exact guard or blocked edge."
            )
    elif (
        requested_status == FindingStatus.INCONCLUSIVE.value
        and existing_signal_tier == "runtime_oracle_gap"
    ):
        applied = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
        reason = "An inconclusive Operator turn cannot erase an existing runtime Oracle gap."

    return VerdictDecision(
        requested_status=requested_status,
        applied_status=applied,
        override_reason=reason,
    )


def normalize_signal_metadata(
    metadata: dict[str, Any] | None,
    *,
    status: str,
    runtime_observed: bool = False,
    operator_session_id: str | None = None,
) -> dict[str, Any]:
    """Project status-dependent signal metadata from one canonical implementation."""

    normalized = dict(metadata) if isinstance(metadata, dict) else {}
    if status == FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value:
        normalized["signal_tier"] = "runtime_oracle_gap"
        normalized["proof_gap_code"] = "missing_platform_harm_oracle"
        normalized["oracle_gap"] = {
            **(
                dict(normalized.get("oracle_gap"))
                if isinstance(normalized.get("oracle_gap"), dict)
                else {}
            ),
            "schema_version": "1.0",
            "status": "open",
            "runtime_observed": runtime_observed,
            **(
                {"operator_session_id": operator_session_id}
                if operator_session_id is not None
                else {}
            ),
        }
    elif status == FindingStatus.SUPPORTED_STATIC.value:
        normalized["signal_tier"] = "static_chain"
        normalized.pop("proof_gap_code", None)
        normalized.pop("oracle_gap", None)
    else:
        normalized.pop("signal_tier", None)
        normalized.pop("proof_gap_code", None)
        normalized.pop("oracle_gap", None)
    return normalized
