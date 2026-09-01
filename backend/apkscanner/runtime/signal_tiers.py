from __future__ import annotations

from typing import Any, Literal

SignalTier = Literal["runtime_oracle_gap", "static_chain", "raw_candidate"]

_CLOSED_STATUSES = frozenset(
    {"false_positive", "refuted_static", "not_reproduced"}
)
_RUNTIME_GAP_STATUSES = frozenset(
    {"runtime_observed_unverified", "oracle_gap"}
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
    """Classify a non-confirmed finding without rewriting historical audit records."""

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
        and (model_verdict == "reproduced_blackbox" or bool(override_reason))
    ):
        return "runtime_oracle_gap"

    if status in {"static_path_supported", "supported_static"} and valid_static_support_gate(
        payload
    ):
        return "static_chain"
    return "raw_candidate"
