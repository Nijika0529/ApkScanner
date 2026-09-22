from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.enums import FindingStatus, ScanStatus, TaskStatus
from ..core.models import Evidence, InvestigationTask, Scan
from ..core.repository import add_event, now
from ..core.schemas import (
    InvestigationTaskOut,
    ScanAgentControl,
    ScanDetail,
    ScanExecutionControl,
    ScanRerunResult,
    TaskAgentControl,
    TaskDeleteResult,
    TaskReanalysisRequest,
)
from ..runtime.agent_audit import AGENT_AUDIT_KINDS
from ..runtime.orchestrator import ScanOrchestrator
from .dependencies import (
    get_orchestrator,
    get_session,
    require_active_task,
    require_scan,
    transition_task,
)

router = APIRouter()


@router.patch("/scans/{scan_id}/agent-control", response_model=ScanDetail)
def update_scan_agent_control(
    scan_id: str,
    control: ScanAgentControl,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    current_backend = str(
        (scan.stats.get("agent_control") or {}).get("backend")
        or scan.stats.get("investigator")
        or "configured"
    )
    requested_backend = control.backend or current_backend
    if control.enabled and requested_backend == "none":
        requested_backend = orchestrator.resolve_investigator()
    try:
        backend = orchestrator.resolve_investigator(requested_backend)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if control.enabled and backend == "none":
        raise HTTPException(422, "An enabled AI control requires codex")

    scan.stats = {
        **scan.stats,
        "investigator": backend,
        "agent_control": {
            "enabled": bool(control.enabled),
            "backend": backend,
            "updated_at": now().isoformat(),
        },
    }
    add_event(
        session,
        scan.id,
        "exploration.control.updated",
        "扫描级 AI 总开关已更新",
        {
            "source": "platform",
            "enabled": bool(control.enabled),
            "backend": backend,
            "scope": "scan",
        },
    )
    session.commit()
    session.refresh(scan)
    return scan


@router.patch("/scans/{scan_id}/execution-control", response_model=ScanDetail)
async def update_scan_execution_control(
    scan_id: str,
    control: ScanExecutionControl,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status in {ScanStatus.FINAL.value, ScanStatus.FAILED.value}:
        raise HTTPException(409, "A finished scan cannot be paused, resumed, or stopped")

    current = scan.stats.get("execution_control")
    current_state = (
        str(current.get("state") or "running") if isinstance(current, dict) else "running"
    )
    next_state = {
        "pause": "paused",
        "resume": "running",
        "stop": "stopping",
    }[control.action]
    if current_state == "stopping" and control.action != "stop":
        raise HTTPException(409, "Scan termination is already in progress")

    changed_at = now()
    scan.stats = {
        **dict(scan.stats or {}),
        "execution_control": {
            "state": next_state,
            "action": control.action,
            "updated_at": changed_at.isoformat(),
        },
    }
    event_type = {
        "pause": "scan.execution.paused",
        "resume": "scan.execution.resumed",
        "stop": "scan.execution.stop_requested",
    }[control.action]
    message = {
        "pause": "扫描任务调度已暂停；正在运行的任务会完成，等待任务不会继续领取",
        "resume": "扫描任务调度已恢复",
        "stop": "用户已请求结束扫描；未完成任务正在停止",
    }[control.action]
    add_event(
        session,
        scan.id,
        event_type,
        message,
        {
            "source": "platform",
            "previous_state": current_state,
            "state": next_state,
        },
    )
    session.commit()

    if control.action == "stop":
        orchestrator.stop_scan_tasks(scan.id)
    elif control.action == "resume":
        background = asyncio.create_task(
            orchestrator.ensure_scan_running(scan.id),
            name=f"resume-execution-{scan.id}",
        )
        request.app.state.background_tasks.add(background)
        background.add_done_callback(request.app.state.background_tasks.discard)

    session.expire_all()
    return require_scan(session, scan.id)


@router.patch("/tasks/{task_id}/agent-control", response_model=InvestigationTaskOut)
def update_task_agent_control(
    task_id: str,
    control: TaskAgentControl,
    session: Session = Depends(get_session),
) -> InvestigationTask:
    task = require_active_task(session, task_id)
    if task.status in {
        TaskStatus.RUNNING.value,
        TaskStatus.CANCEL_REQUESTED.value,
    }:
        raise HTTPException(409, "A running task keeps the AI control resolved at its start")
    task.preconditions = {
        **dict(task.preconditions or {}),
        "agent_enabled": bool(control.enabled),
    }
    add_event(
        session,
        task.scan_id,
        "exploration.control.updated",
        "任务级 AI 开关已更新",
        {
            "task_id": task.id,
            "source": "platform",
            "enabled": bool(control.enabled),
            "scope": "task",
        },
    )
    session.commit()
    session.refresh(task)
    return task


def _reset_task_for_manual_rerun(
    session: Session,
    task: InvestigationTask,
    *,
    reason: str,
) -> None:
    previous_status = task.status
    requested_at = now()
    task.status = TaskStatus.QUEUED.value
    task.error = None
    task.result = {
        "manual_rerun": {
            "requested_at": requested_at.isoformat(),
            "previous_status": previous_status,
            "reason": reason,
        }
    }
    task.thread_id = None
    task.turn_id = None
    task.started_at = None
    task.completed_at = None
    add_event(
        session,
        task.scan_id,
        "exploration.rerun.requested",
        "入口探索已重新排队；静态产物将被复用",
        {
            "task_id": task.id,
            "source": "platform",
            "previous_status": previous_status,
            "attempts_completed": task.attempts,
            "reason": reason,
        },
    )


def _reset_timed_out_task_for_continuation(
    session: Session,
    task: InvestigationTask,
) -> None:
    previous_result = dict(task.result or {})
    previous_continuation = dict(previous_result.get("manual_continuation") or {})
    continuation_number = int(previous_continuation.get("continuation_number") or 0) + 1
    requested_at = now()
    prior_result = {
        key: previous_result[key]
        for key in (
            "result",
            "summary",
            "confidence",
            "severity_proposal",
            "platform_severity",
            "coverage_gaps",
            "platform_context",
        )
        if key in previous_result
    }
    task.status = TaskStatus.QUEUED.value
    task.error = None
    task.result = {
        "manual_continuation": {
            "requested_at": requested_at.isoformat(),
            "previous_status": TaskStatus.TIMED_OUT.value,
            "previous_attempt": task.attempts,
            "previous_thread_id": task.thread_id,
            "previous_turn_id": task.turn_id,
            "continuation_number": continuation_number,
            "reuse_task_evidence": True,
            "prior_result": prior_result,
        }
    }
    task.thread_id = None
    task.turn_id = None
    task.started_at = None
    task.completed_at = None
    add_event(
        session,
        task.scan_id,
        "exploration.continuation.requested",
        f"超时任务已进入第 {continuation_number} 次深度续跑队列",
        {
            "task_id": task.id,
            "source": "platform",
            "previous_attempt": task.attempts,
            "continuation_number": continuation_number,
            "reuse_static_artifacts": True,
            "reuse_task_evidence": True,
        },
    )


def _create_independent_reanalysis(
    session: Session,
    task: InvestigationTask,
) -> InvestigationTask:
    requested_at = now()
    original_preconditions = dict(task.preconditions or {})
    for history_key in ("version_replays", "prior_findings", "history", "continuation"):
        original_preconditions.pop(history_key, None)
    independent = InvestigationTask(
        scan_id=task.scan_id,
        task_type=task.task_type,
        status=TaskStatus.QUEUED.value,
        priority=task.priority,
        target_entry_ids=list(task.target_entry_ids),
        hypotheses=list(task.hypotheses),
        preconditions={
            **original_preconditions,
            "context_policy": {
                "mode": "independent",
                "reuse_static_artifacts": True,
                "reuse_task_evidence": False,
                "reuse_agent_thread": False,
                "reuse_version_replays": False,
            },
        },
        allowed_side_effects=list(task.allowed_side_effects),
        device_profile=dict(task.device_profile or {}),
        result={
            "independent_reanalysis": {
                "requested_at": requested_at.isoformat(),
                "origin_task_id": task.id,
                "context_mode": "independent",
                "reuse_static_artifacts": True,
                "reuse_task_evidence": False,
                "reuse_agent_thread": False,
                "reuse_version_replays": False,
            }
        },
    )
    session.add(independent)
    session.flush()
    add_event(
        session,
        task.scan_id,
        "exploration.independent.requested",
        "已创建不读取原任务上下文的独立复核任务",
        {
            "task_id": independent.id,
            "origin_task_id": task.id,
            "source": "platform",
            "reuse_static_artifacts": True,
            "reuse_task_evidence": False,
            "reuse_agent_thread": False,
            "reuse_version_replays": False,
        },
    )
    return independent


def _task_needs_supplemental_rerun(task: InvestigationTask) -> bool:
    if task.status in {
        TaskStatus.BLOCKED_DEVICE.value,
        TaskStatus.INCONCLUSIVE.value,
        TaskStatus.TIMED_OUT.value,
        TaskStatus.FAILED.value,
    }:
        return True
    return (
        task.status == TaskStatus.COMPLETED.value
        and str((task.result or {}).get("result")) == FindingStatus.INCONCLUSIVE.value
    )


def _resume_scan(session: Session, scan: Scan) -> None:
    scan.status = ScanStatus.INVESTIGATING.value
    scan.error = None
    scan.completed_at = None
    scan.stats = {
        **dict(scan.stats or {}),
        "execution_control": {
            "state": "running",
            "action": "resume",
            "updated_at": now().isoformat(),
            "source": "manual_rerun",
        },
    }


@router.post("/tasks/{task_id}/retry", response_model=InvestigationTaskOut, status_code=202)
async def retry_task(
    task_id: str,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationTask:
    task = require_active_task(session, task_id)
    if task.status in {
        TaskStatus.QUEUED.value,
        TaskStatus.AWAITING_DEVICE.value,
        TaskStatus.RUNNING.value,
        TaskStatus.CANCEL_REQUESTED.value,
    }:
        raise HTTPException(409, "Task is already queued or running")
    if task.attempts >= orchestrator.settings.task_max_attempts:
        raise HTTPException(
            409,
            "Task retry budget is exhausted; use the explicit rerun action after reviewing side effects",
        )
    scan = session.get(Scan, task.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    _reset_task_for_manual_rerun(
        session,
        task,
        reason="用户请求重新执行该入口的设备验证与 AI 分析",
    )
    _resume_scan(session, scan)
    session.commit()
    background = asyncio.create_task(orchestrator.submit(task.scan_id), name=f"retry-{task.id}")
    request.app.state.background_tasks.add(background)
    background.add_done_callback(request.app.state.background_tasks.discard)
    return task


@router.post("/tasks/{task_id}/rerun", response_model=InvestigationTaskOut, status_code=202)
async def rerun_task(
    task_id: str,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationTask:
    task = require_active_task(session, task_id)
    if task.status in {
        TaskStatus.QUEUED.value,
        TaskStatus.AWAITING_DEVICE.value,
        TaskStatus.RUNNING.value,
        TaskStatus.CANCEL_REQUESTED.value,
    }:
        raise HTTPException(409, "Task is already queued or running")
    scan = session.get(Scan, task.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    _reset_task_for_manual_rerun(
        session,
        task,
        reason="用户显式请求重新执行该入口，已确认可能产生新的设备与模型调用",
    )
    _resume_scan(session, scan)
    session.commit()
    background = asyncio.create_task(orchestrator.submit(task.scan_id), name=f"rerun-{task.id}")
    request.app.state.background_tasks.add(background)
    background.add_done_callback(request.app.state.background_tasks.discard)
    return task


@router.post(
    "/tasks/{task_id}/reanalyses",
    response_model=InvestigationTaskOut,
    status_code=202,
)
async def create_task_reanalysis(
    task_id: str,
    control: TaskReanalysisRequest,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationTask:
    task = require_active_task(session, task_id)
    if task.status in {
        TaskStatus.QUEUED.value,
        TaskStatus.AWAITING_DEVICE.value,
        TaskStatus.RUNNING.value,
        TaskStatus.CANCEL_REQUESTED.value,
    }:
        raise HTTPException(409, "Task is already queued or running")
    scan = session.get(Scan, task.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if control.context_mode == "independent":
        queued_task = _create_independent_reanalysis(session, task)
    elif task.status == TaskStatus.TIMED_OUT.value:
        _reset_timed_out_task_for_continuation(session, task)
        queued_task = task
    else:
        _reset_task_for_manual_rerun(
            session,
            task,
            reason="用户请求沿用该入口定义重新分析",
        )
        queued_task = task
    _resume_scan(session, scan)
    session.commit()
    background = asyncio.create_task(
        orchestrator.submit(task.scan_id),
        name=f"reanalysis-{queued_task.id}",
    )
    request.app.state.background_tasks.add(background)
    background.add_done_callback(request.app.state.background_tasks.discard)
    return queued_task


@router.post("/tasks/{task_id}/continue", response_model=InvestigationTaskOut, status_code=202)
async def continue_timed_out_task(
    task_id: str,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationTask:
    task = require_active_task(session, task_id)
    if task.status != TaskStatus.TIMED_OUT.value:
        raise HTTPException(409, "Only a timed-out task can continue from prior evidence")
    scan = session.get(Scan, task.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    _reset_timed_out_task_for_continuation(session, task)
    _resume_scan(session, scan)
    session.commit()
    background = asyncio.create_task(
        orchestrator.submit(task.scan_id),
        name=f"continue-{task.id}",
    )
    request.app.state.background_tasks.add(background)
    background.add_done_callback(request.app.state.background_tasks.discard)
    return task


@router.post(
    "/scans/{scan_id}/rerun-incomplete",
    response_model=ScanRerunResult,
    status_code=202,
)
async def rerun_incomplete_tasks(
    scan_id: str,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> ScanRerunResult:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status not in {ScanStatus.FINAL.value, ScanStatus.FAILED.value}:
        raise HTTPException(409, "Wait for the current scan run to finish before supplementing it")
    tasks = list(
        session.scalars(
            select(InvestigationTask)
            .where(InvestigationTask.scan_id == scan_id)
            .order_by(InvestigationTask.priority.desc(), InvestigationTask.created_at)
        )
    )
    selected = [task for task in tasks if _task_needs_supplemental_rerun(task)]
    if not selected:
        raise HTTPException(409, "No incomplete or device-blocked tasks need a supplemental rerun")
    for task in selected:
        _reset_task_for_manual_rerun(
            session,
            task,
            reason="能力恢复后的全局补扫",
        )
    _resume_scan(session, scan)
    add_event(
        session,
        scan.id,
        "exploration.rerun.batch_requested",
        f"已将 {len(selected)} 个信息不全的入口任务加入补扫队列",
        {
            "source": "platform",
            "task_ids": [task.id for task in selected],
            "count": len(selected),
            "reuse_static_artifacts": True,
        },
    )
    session.commit()
    background = asyncio.create_task(orchestrator.submit(scan.id), name=f"rerun-{scan.id}")
    request.app.state.background_tasks.add(background)
    background.add_done_callback(request.app.state.background_tasks.discard)
    return ScanRerunResult(
        scan_id=scan.id,
        queued_task_ids=[task.id for task in selected],
        queued_count=len(selected),
    )


@router.post(
    "/tasks/{task_id}/cancel",
    response_model=InvestigationTaskOut,
    status_code=202,
)
def cancel_task(
    task_id: str,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationTask:
    task = require_active_task(session, task_id)
    if task.status == TaskStatus.CANCEL_REQUESTED.value:
        raise HTTPException(409, "Task cancellation is already pending")
    if task.status not in {
        TaskStatus.QUEUED.value,
        TaskStatus.AWAITING_DEVICE.value,
        TaskStatus.RUNNING.value,
    }:
        raise HTTPException(409, "Only a queued or running task can be cancelled")

    requested_at = now()
    previous_status = task.status
    runtime_active = previous_status in {
        TaskStatus.AWAITING_DEVICE.value,
        TaskStatus.RUNNING.value,
    }
    cancellation_result = {
        **dict(task.result or {}),
        "cancellation": {
            "requested": True,
            "acknowledged": not runtime_active,
            "requested_at": requested_at.isoformat(),
        },
    }
    if runtime_active:
        next_status = TaskStatus.CANCEL_REQUESTED.value
        next_error = (
            "正在从云真机队列取消任务"
            if previous_status == TaskStatus.AWAITING_DEVICE.value
            else "正在停止当前分析"
        )
        transition_values = {
            "status": next_status,
            "error": next_error,
            "result": cancellation_result,
        }
        message = (
            "用户已请求取消等待云真机的入口探索任务"
            if previous_status == TaskStatus.AWAITING_DEVICE.value
            else "用户已请求停止正在运行的入口探索任务"
        )
    else:
        # A queued task may already have a registered runtime immediately before
        # it enters the device scheduler. Signalling is harmless when no runtime exists.
        next_status = TaskStatus.CANCELED.value
        transition_values = {
            "status": next_status,
            "error": "用户在任务执行前取消了分析",
            "completed_at": requested_at,
            "result": cancellation_result,
        }
        message = "用户已取消等待中的入口探索任务"
    if not transition_task(
        session,
        task_id,
        expected_status=previous_status,
        values=transition_values,
    ):
        session.rollback()
        current = require_active_task(session, task_id)
        raise HTTPException(
            409,
            f"Task state changed to {current.status!r} before cancellation could be applied",
        )
    add_event(
        session,
        task.scan_id,
        "task.cancel_requested",
        message,
        {
            "task_id": task.id,
            "status": next_status,
            "requested_at": requested_at.isoformat(),
        },
    )
    add_event(
        session,
        task.scan_id,
        "exploration.cancel_requested",
        message,
        {
            "task_id": task.id,
            "source": "platform",
            "status": next_status,
        },
    )
    session.commit()
    if not orchestrator.request_task_cancellation(task_id):
        session.expire_all()
        current = require_active_task(session, task_id)
        if current.status == TaskStatus.CANCEL_REQUESTED.value:
            completed_at = now()
            acknowledged_result = {
                **dict(current.result or {}),
                "cancellation": {
                    **dict((current.result or {}).get("cancellation") or {}),
                    "acknowledged": True,
                    "completed_at": completed_at.isoformat(),
                },
            }
            if transition_task(
                session,
                task_id,
                expected_status=TaskStatus.CANCEL_REQUESTED.value,
                values={
                    "status": TaskStatus.CANCELED.value,
                    "error": "分析运行时已经退出，停止请求已确认",
                    "completed_at": completed_at,
                    "result": acknowledged_result,
                },
            ):
                add_event(
                    session,
                    current.scan_id,
                    "task.cancelled",
                    "分析运行时已经退出，停止请求已确认",
                    {"task_id": current.id, "status": TaskStatus.CANCELED.value},
                )
                session.commit()
            else:
                session.rollback()
    session.expire_all()
    return require_active_task(session, task_id)


@router.delete("/tasks/{task_id}", response_model=TaskDeleteResult)
def delete_task(
    task_id: str,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> TaskDeleteResult:
    task = require_active_task(session, task_id)
    if task.status not in {
        TaskStatus.BLOCKED_DEVICE.value,
        TaskStatus.COMPLETED.value,
        TaskStatus.NOT_REPRODUCED.value,
        TaskStatus.INCONCLUSIVE.value,
        TaskStatus.TIMED_OUT.value,
        TaskStatus.FAILED.value,
        TaskStatus.CANCELED.value,
        TaskStatus.CANCEL_REQUESTED.value,
    }:
        raise HTTPException(409, "Only a terminal or stopping task can be deleted")

    stopping_runtime = task.status == TaskStatus.CANCEL_REQUESTED.value
    if stopping_runtime:
        orchestrator.request_task_cancellation(task_id)

    audit_artifacts = list(
        session.scalars(
            select(Evidence).where(
                Evidence.task_id == task_id,
                Evidence.kind.in_(AGENT_AUDIT_KINDS),
            )
        )
    )
    deleted_at = now()
    task.status = TaskStatus.DELETED.value
    task.error = None
    task.result = {
        **dict(task.result or {}),
        "deletion": {
            "soft_deleted": True,
            "deleted_at": deleted_at.isoformat(),
            "runtime_stop_pending": stopping_runtime,
            "reason": (
                "Execution row hidden while evidence, hypotheses, proof attempts, and AI audit "
                "lineage remain preserved."
            ),
        },
    }
    add_event(
        session,
        task.scan_id,
        "task.deleted",
        "任务已从执行列表移除，验证链与 AI 审计继续保留",
        {
            "task_id": task.id,
            "soft_deleted": True,
            "audit_artifacts_preserved": len(audit_artifacts),
        },
    )
    session.commit()
    return TaskDeleteResult(
        id=task_id,
        audit_artifacts_preserved=len(audit_artifacts),
    )
