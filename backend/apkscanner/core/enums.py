from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    INTAKE = "intake"
    STATIC_RUNNING = "static_running"
    STATIC_COMPLETE = "static_complete"
    INVESTIGATING = "investigating"
    PRELIMINARY_READY = "preliminary_ready"
    FINAL = "final"
    FAILED = "failed"


class EntryPointKind(StrEnum):
    ACTIVITY = "activity"
    ACTIVITY_ALIAS = "activity_alias"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"
    DEEP_LINK = "deep_link"
    STATIC_SURFACE = "static_surface"


class TaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELED = "canceled"
    AWAITING_DEVICE = "awaiting_device"
    BLOCKED_DEVICE = "blocked_device"
    COMPLETED = "completed"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    DELETED = "deleted"


class TaskType(StrEnum):
    COMPONENT = "component"
    DEEP_LINK = "deep_link"
    STATIC_REVIEW = "static_review"
    ADAPTIVE_VERIFICATION = "adaptive_verification"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    SUPPORTED_STATIC = "supported_static"
    REFUTED_STATIC = "refuted_static"
    REPRODUCED_BLACKBOX = "reproduced_blackbox"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class HypothesisStatus(StrEnum):
    CANDIDATE = "candidate"
    CHALLENGED = "challenged"
    ACCEPTED_FOR_PROOF = "accepted_for_proof"
    PROOF_PLANNED = "proof_planned"
    EXECUTING = "executing"
    PROVEN = "proven"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class ProofAttemptStatus(StrEnum):
    PLANNED = "planned"
    EXECUTING = "executing"
    PROVEN = "proven"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class CoverageStatus(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"
    TOOL_FAILED = "tool_failed"
    DEGRADED = "degraded"


class EntryDisposition(StrEnum):
    """Mandatory per-entry disposition after scan completion.

    Every entry point must resolve to exactly one of these states,
    replacing the previous ad-hoc "was it investigated?" ambiguity.
    """

    UNINVESTIGATED = "uninvestigated"
    STATICALLY_UNREACHABLE = "statically_unreachable"
    PERMISSION_PROTECTED = "permission_protected"
    CALLER_IDENTITY_PROTECTED = "caller_identity_protected"
    ATTACK_CHAIN_CANDIDATE = "attack_chain_candidate"
    STATICALLY_SUPPORTED = "statically_supported"
    DYNAMICALLY_NOT_REPRODUCED = "dynamically_not_reproduced"
    DYNAMICALLY_REFUTED = "dynamically_refuted"
    REPRODUCED_BLACKBOX = "reproduced_blackbox"
    CAPABILITY_GAP = "capability_gap"
