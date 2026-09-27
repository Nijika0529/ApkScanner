from __future__ import annotations

from dataclasses import replace

import pytest
from apkscanner.core.db import Database
from apkscanner.core.investigation_loop import (
    InvestigationLoopState,
    LoopDirective,
    LoopStopReason,
    decide_investigation_loop,
)
from apkscanner.core.models import InvestigationTask, Scan
from apkscanner.core.schemas import AgentInvestigationResult, AgentRequestedTest
from apkscanner.runtime.investigation_loop import agent_progress_state
from apkscanner.runtime.task_execution_state import TaskExecutionStateMixin


def _running_state() -> InvestigationLoopState:
    return InvestigationLoopState(
        has_result=True,
        has_pending_action=True,
        proof_complete=False,
        executor_ready=True,
        budget_expired=False,
        no_progress_rounds=0,
        no_progress_limit=3,
    )


def test_loop_executes_only_when_platform_preconditions_hold() -> None:
    decision = decide_investigation_loop(_running_state())

    assert decision.directive == LoopDirective.EXECUTE
    assert decision.reason is None


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"proof_complete": True}, LoopStopReason.PROOF_COMPLETE),
        ({"has_result": False}, LoopStopReason.RESULT_UNAVAILABLE),
        ({"has_pending_action": False}, LoopStopReason.NO_PENDING_ACTION),
        ({"executor_ready": False}, LoopStopReason.EXECUTOR_UNAVAILABLE),
        ({"budget_expired": True}, LoopStopReason.BUDGET_EXHAUSTED),
        ({"no_progress_rounds": 3}, LoopStopReason.NO_PROGRESS),
    ],
)
def test_loop_has_an_explicit_stop_reason(change, reason) -> None:  # noqa: ANN001
    decision = decide_investigation_loop(replace(_running_state(), **change))

    assert decision.directive == LoopDirective.STOP
    assert decision.reason == reason


def test_progress_state_ignores_model_wording_but_tracks_platform_actions() -> None:
    request = AgentRequestedTest(
        hypothesis_id="00000000-0000-0000-0000-000000000001",
        entry_point_id="00000000-0000-0000-0000-000000000002",
        rationale="第一种说明",
    )
    first = AgentInvestigationResult(
        summary="第一次模型说明。",
        result="supported_static",
        hypotheses_tested=[request.hypothesis_id],
        test_cases=[],
        evidence_ids=["evidence-1"],
        severity_proposal="medium",
        confidence="medium",
        coverage_gaps=[],
        followups=[],
        requested_tests=[request],
    )
    reworded = first.model_copy(
        update={
            "summary": "只是换一种中文说法。",
            "requested_tests": [request.model_copy(update={"rationale": "第二种说明"})],
        }
    )

    first_state = agent_progress_state(
        first,
        evidence_summaries=[{"id": "evidence-1"}],
        proven_hypotheses={},
    )
    reworded_state = agent_progress_state(
        reworded,
        evidence_summaries=[{"id": "evidence-1"}],
        proven_hypotheses={},
    )

    assert first_state == reworded_state
    changed_request = request.model_copy(update={"extras": {"mode": "alternate"}})
    changed = first.model_copy(update={"requested_tests": [changed_request]})
    assert agent_progress_state(
        changed,
        evidence_summaries=[{"id": "evidence-1"}],
        proven_hypotheses={},
    ) != first_state


def test_new_attempt_starts_a_fresh_loop_projection(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="loop.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "loop.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            attempts=2,
            result={
                "investigation_loop": {
                    "attempt": 1,
                    "status": "closed",
                    "decision": "stop",
                    "termination_reason": "budget_exhausted",
                    "started_at": "old-attempt",
                }
            },
        )
        session.add_all([scan, task])
        session.commit()
        scan_id = scan.id
        task_id = task.id

    state_writer = TaskExecutionStateMixin()
    state_writer.database = database
    state_writer._set_task_investigation_loop(
        scan_id,
        task_id,
        phase="plan",
        round_index=0,
        no_progress_rounds=0,
        budget_remaining_seconds=60,
    )

    with database.session_factory() as session:
        loop = session.get(InvestigationTask, task_id).result["investigation_loop"]
    assert loop["attempt"] == 2
    assert loop["status"] == "running"
    assert loop["started_at"] != "old-attempt"
    assert "decision" not in loop
    assert "termination_reason" not in loop
