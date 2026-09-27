from __future__ import annotations

from typing import Any

from ..core.schemas import AgentInvestigationResult


def agent_progress_state(
    result: AgentInvestigationResult,
    *,
    evidence_summaries: list[dict[str, Any]],
    proven_hypotheses: dict[str, list[str]],
) -> dict[str, Any]:
    """Return the platform-visible facts used by no-progress convergence."""

    requested_tests: list[dict[str, Any]] = []
    for request in result.requested_tests:
        payload = request.model_dump(mode="json")
        payload.pop("rationale", None)
        requested_tests.append(payload)

    assessments = [
        {
            "hypothesis_id": assessment.hypothesis_id,
            "verdict": assessment.verdict,
            "evidence_ids": sorted(assessment.evidence_ids),
            "source": assessment.source,
            "control": assessment.control,
            "sink": assessment.sink,
            "reachable_path": assessment.reachable_path,
            "boundary": assessment.boundary,
            "security_impact": assessment.security_impact,
            "missing_control": assessment.missing_control,
            "has_counterevidence": bool(assessment.counterevidence),
            "has_proof_gaps": bool(assessment.proof_gaps),
        }
        for assessment in result.hypothesis_assessments
    ]
    assessments.sort(key=lambda item: (item["hypothesis_id"], item["verdict"]))
    return {
        "result": result.result,
        "evidence_ids": sorted(
            {
                *result.evidence_ids,
                *(str(item["id"]) for item in evidence_summaries if item.get("id")),
            }
        ),
        "proven_hypotheses": {
            hypothesis_id: sorted(evidence_ids)
            for hypothesis_id, evidence_ids in sorted(proven_hypotheses.items())
        },
        "requested_tests": requested_tests,
        "assessments": assessments,
    }
