from __future__ import annotations

from ..core.enums import FindingStatus
from ..core.models import Evidence, Finding

_RUNTIME_OBSERVATION_FLAGS = (
    "request_observed",
    "probe_success",
    "poc_success",
    "platform_observed_poc_effect",
    "dynamic_experiment_execution_demonstrated",
    "runtime_package_observed",
    "runtime_crash_observed",
)


def _ordered_ids(*groups: list[str]) -> list[str]:
    return list(
        dict.fromkeys(
            value
            for group in groups
            for value in group
            if isinstance(value, str) and value
        )
    )


def evidence_supports_runtime_observation(evidence: Evidence) -> bool:
    """Accept only platform-issued execution/callback facts as runtime observations."""

    if not (
        evidence.kind.startswith("blackbox.")
        or evidence.kind.startswith("dynamic_experiment.")
    ):
        return False
    metadata = (
        evidence.metadata_json if isinstance(evidence.metadata_json, dict) else {}
    )
    return any(metadata.get(key) is True for key in _RUNTIME_OBSERVATION_FLAGS)


def project_runtime_observation_gap(
    finding: Finding,
    *,
    observation_id: str,
    evidence_ids: list[str],
    task_id: str,
    observation_kind: str,
) -> bool:
    """Project a durable runtime fact without turning it into a proven vulnerability."""

    if finding.status in {
        FindingStatus.ACCEPTED.value,
        FindingStatus.REPRODUCED_BLACKBOX.value,
        FindingStatus.FALSE_POSITIVE.value,
    }:
        return False
    metadata = (
        dict(finding.metadata_json)
        if isinstance(finding.metadata_json, dict)
        else {}
    )
    previous_status = finding.status
    observation_ids = metadata.get("runtime_observation_ids")
    observation_ids = observation_ids if isinstance(observation_ids, list) else []
    observation_evidence_ids = metadata.get("runtime_observation_evidence_ids")
    observation_evidence_ids = (
        observation_evidence_ids
        if isinstance(observation_evidence_ids, list)
        else []
    )
    finding.status = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
    finding.evidence_ids = _ordered_ids(
        finding.evidence_ids if isinstance(finding.evidence_ids, list) else [],
        evidence_ids,
    )
    metadata["signal_tier"] = "runtime_oracle_gap"
    if previous_status in {
        FindingStatus.REFUTED_STATIC.value,
        FindingStatus.NOT_REPRODUCED.value,
    }:
        metadata["previous_closure"] = {
            "status": previous_status,
            "reopened_by_runtime_observation_id": observation_id,
        }
    metadata["runtime_observed"] = True
    metadata["runtime_observation_ids"] = _ordered_ids(
        observation_ids,
        [observation_id],
    )
    metadata["runtime_observation_evidence_ids"] = _ordered_ids(
        observation_evidence_ids,
        evidence_ids,
    )
    metadata["proof_gap_code"] = "missing_platform_harm_oracle"
    metadata["oracle_gap"] = {
        **(
            dict(metadata.get("oracle_gap"))
            if isinstance(metadata.get("oracle_gap"), dict)
            else {}
        ),
        "schema_version": "1.0",
        "status": "open",
        "reason": "runtime_observation_without_harm_oracle",
        "runtime_observed": True,
        "observation_id": observation_id,
        "observation_kind": observation_kind,
        "task_id": task_id,
    }
    proof_backlog = metadata.get("proof_backlog")
    metadata["proof_backlog"] = {
        **(dict(proof_backlog) if isinstance(proof_backlog, dict) else {}),
        "status": "oracle_gap",
        "reason": "runtime_observation_without_harm_oracle",
    }
    finding.metadata_json = metadata
    return True
