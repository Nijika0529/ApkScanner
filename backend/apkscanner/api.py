from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from sqlalchemy import case, desc, select, update
from sqlalchemy.orm import Session, selectinload

from . import __version__
from .agent_audit import AGENT_AUDIT_KINDS, build_agent_audits
from .artifacts import ArtifactStore, ArtifactTooLargeError
from .benchmark import BenchmarkEvaluator
from .db import Database
from .enums import FindingStatus, ScanStatus, TaskStatus
from .finding_policy import partition_findings
from .models import (
    BenchmarkEvaluation,
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    Scan,
    ScanEvent,
    SecurityHypothesis,
)
from .orchestrator import ScanOrchestrator
from .reports import ReportBuilder
from .repository import add_event, now
from .schemas import (
    AgentAuditOut,
    AgentProofReplay,
    BenchmarkEvaluationOut,
    BenchmarkSpec,
    Capability,
    CoverageItemOut,
    EntryPointOut,
    EventOut,
    EvidenceOut,
    FindingOut,
    FindingReview,
    HealthResponse,
    InvestigationTaskOut,
    ScanAgentControl,
    ScanDeleteResult,
    ScanDetail,
    ScanRerunResult,
    ScanSummary,
    SecurityHypothesisOut,
    TaskAgentControl,
    TaskDeleteResult,
)

router = APIRouter(prefix="/api/v1")
reports = ReportBuilder()


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_store(request: Request) -> ArtifactStore:
    return request.app.state.store


def get_orchestrator(request: Request) -> ScanOrchestrator:
    return request.app.state.orchestrator


@router.post("/internal/tasks/{task_id}/proof-replay")
def execute_live_proof_replay(
    task_id: str,
    replay: AgentProofReplay,
    x_apkscanner_proof_token: str = Header(default=""),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        return orchestrator.execute_live_proof_replay(
            task_id,
            x_apkscanner_proof_token,
            replay,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (TimeoutError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


def get_session(database: Database = Depends(get_database)):
    with database.session_factory() as session:
        yield session


def require_scan(session: Session, scan_id: str) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


def require_active_task(session: Session, task_id: str) -> InvestigationTask:
    task = session.get(InvestigationTask, task_id)
    if task is None or task.status == TaskStatus.DELETED.value:
        raise HTTPException(404, "Task not found")
    return task


def _transition_task(
    session: Session,
    task_id: str,
    *,
    expected_status: str,
    values: dict[str, Any],
) -> bool:
    result = session.execute(
        update(InvestigationTask)
        .where(
            InvestigationTask.id == task_id,
            InvestigationTask.status == expected_status,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


@router.get("/health", response_model=HealthResponse)
def health(orchestrator: ScanOrchestrator = Depends(get_orchestrator)) -> HealthResponse:
    tool_versions = {
        name: orchestrator.runner.version(name)
        for name in ("aapt2", "apksigner", "apktool", "apkanalyzer", "jadx", "adb")
    }
    capabilities = [
        Capability(name=name, available=version is not None, version=version)
        for name, version in tool_versions.items()
    ]
    codex = orchestrator.codex.capability(deep=False)
    capabilities.append(
        Capability(
            name="codex",
            available=bool(codex.get("available")),
            version=codex.get("version"),
            detail=codex.get("detail"),
        )
    )
    opencode = orchestrator.opencode.capability(deep=False)
    capabilities.append(
        Capability(
            name="opencode_deepseek",
            available=bool(opencode.get("available")),
            version=opencode.get("version"),
            detail=opencode.get("detail"),
        )
    )
    device = orchestrator.device.capability(non_blocking=True)
    capabilities.append(
        Capability(
            name="remote_android_device",
            available=bool(device.get("available")),
            version=device.get("android_version"),
            detail=device.get("detail"),
        )
    )
    mobsf = orchestrator.mobsf.capability()
    capabilities.append(
        Capability(
            name="mobsf",
            available=bool(mobsf.get("available")),
            detail=mobsf.get("detail"),
        )
    )
    poc_builder = orchestrator.poc_builder.capability()
    capabilities.append(
        Capability(
            name="agent_poc_builder",
            available=bool(poc_builder.get("available")),
            detail=poc_builder.get("detail"),
        )
    )
    return HealthResponse(
        version=__version__,
        max_upload_bytes=orchestrator.settings.max_upload_bytes,
        default_investigator=orchestrator.resolve_investigator(),
        enabled_investigators=[
            name
            for name in ("codex", "opencode")
            if orchestrator.settings.investigator_enabled(name)
        ],
        capabilities=capabilities,
    )


@router.post("/scans", response_model=ScanSummary, status_code=202)
async def create_scan(
    request: Request,
    apk: UploadFile = File(...),
    investigator: str = Form("configured"),
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> Scan:
    try:
        resolved_investigator = orchestrator.resolve_investigator(investigator)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    filename = Path(apk.filename or "upload.apk").name
    if not filename.lower().endswith(".apk"):
        raise HTTPException(415, "Only a single installable .apk is supported in v1")
    try:
        sha256, artifact_path, size = await store.save_upload(apk)
    except ArtifactTooLargeError as exc:
        raise HTTPException(413, str(exc)) from exc
    scan = Scan(
        status=ScanStatus.QUEUED.value,
        filename=filename,
        artifact_sha256=sha256,
        artifact_path=str(artifact_path),
        stats={
            "upload_bytes": size,
            "investigator": resolved_investigator,
            "agent_control": {
                "enabled": resolved_investigator != "none",
                "backend": resolved_investigator,
            },
        },
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    task = asyncio.create_task(orchestrator.submit(scan.id), name=f"scan-{scan.id}")
    request.app.state.background_tasks.add(task)
    task.add_done_callback(request.app.state.background_tasks.discard)
    return scan


@router.get("/scans", response_model=list[ScanSummary])
def list_scans(
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> list[Scan]:
    return list(session.scalars(select(Scan).order_by(desc(Scan.created_at)).limit(limit)))


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@router.delete("/scans/{scan_id}", response_model=ScanDeleteResult)
def delete_scan(
    scan_id: str,
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
) -> ScanDeleteResult:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status not in {ScanStatus.FINAL.value, ScanStatus.FAILED.value}:
        raise HTTPException(409, "A running or queued scan cannot be deleted")

    artifact = (scan.artifact_path, scan.artifact_sha256)
    evidence = list(
        session.execute(
            select(Evidence.path, Evidence.sha256).where(Evidence.scan_id == scan_id)
        )
    )
    evidence_by_path = {str(path): str(sha256) for path, sha256 in evidence}
    shared_evidence_paths: set[str] = set()
    evidence_paths = list(evidence_by_path)
    for start in range(0, len(evidence_paths), 500):
        chunk = evidence_paths[start : start + 500]
        shared_evidence_paths.update(
            str(path)
            for path in session.scalars(
                select(Evidence.path).where(
                    Evidence.scan_id != scan_id,
                    Evidence.path.in_(chunk),
                )
            )
        )
    artifact_is_shared = (
        session.scalar(
            select(Scan.id)
            .where(
                Scan.id != scan_id,
                Scan.artifact_path == scan.artifact_path,
            )
            .limit(1)
        )
        is not None
    )

    session.delete(scan)
    session.commit()

    removed = 0
    warnings: list[str] = []
    if not artifact_is_shared:
        try:
            removed += int(
                store.delete_content_addressed("artifacts", artifact[0], artifact[1])
            )
        except (OSError, ValueError) as exc:
            warnings.append(f"APK artifact cleanup failed: {exc}")
    for path, sha256 in evidence_by_path.items():
        if path in shared_evidence_paths:
            continue
        try:
            removed += int(store.delete_content_addressed("evidence", path, sha256))
        except (OSError, ValueError) as exc:
            warnings.append(f"Evidence cleanup failed for {Path(path).name}: {exc}")
    try:
        removed += int(store.delete_scan_workspace(scan_id))
    except (OSError, ValueError) as exc:
        warnings.append(f"Workspace cleanup failed: {exc}")
    return ScanDeleteResult(
        id=scan_id,
        files_removed=removed,
        cleanup_warnings=warnings,
    )


@router.get("/scans/{scan_id}/entries", response_model=list[EntryPointOut])
def list_entries(scan_id: str, session: Session = Depends(get_session)) -> list[EntryPoint]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(EntryPoint)
            .where(EntryPoint.scan_id == scan_id)
            .order_by(EntryPoint.kind, EntryPoint.name)
        )
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(scan_id: str, session: Session = Depends(get_session)) -> list[Finding]:
    require_scan(session, scan_id)
    findings = list(
        session.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(
                case(
                    (Finding.severity == "critical", 0),
                    (Finding.severity == "high", 1),
                    (Finding.severity == "medium", 2),
                    (Finding.severity == "low", 3),
                    else_=4,
                ),
                Finding.created_at,
            )
        )
    )
    confirmed, _signals = partition_findings(session, findings)
    return confirmed


@router.get("/scans/{scan_id}/signals", response_model=list[FindingOut])
def list_finding_signals(
    scan_id: str,
    session: Session = Depends(get_session),
) -> list[Finding]:
    require_scan(session, scan_id)
    findings = list(
        session.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(
                case(
                    (Finding.severity == "critical", 0),
                    (Finding.severity == "high", 1),
                    (Finding.severity == "medium", 2),
                    (Finding.severity == "low", 3),
                    else_=4,
                ),
                Finding.created_at,
            )
        )
    )
    _confirmed, signals = partition_findings(session, findings)
    return signals


@router.get("/scans/{scan_id}/tasks", response_model=list[InvestigationTaskOut])
def list_tasks(scan_id: str, session: Session = Depends(get_session)) -> list[InvestigationTask]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(InvestigationTask)
            .where(
                InvestigationTask.scan_id == scan_id,
                InvestigationTask.status != TaskStatus.DELETED.value,
            )
            .order_by(InvestigationTask.priority.desc(), InvestigationTask.created_at)
        )
    )


@router.get(
    "/scans/{scan_id}/hypotheses",
    response_model=list[SecurityHypothesisOut],
)
def list_security_hypotheses(
    scan_id: str,
    session: Session = Depends(get_session),
) -> list[SecurityHypothesis]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(SecurityHypothesis)
            .where(SecurityHypothesis.scan_id == scan_id)
            .options(
                selectinload(SecurityHypothesis.arguments),
                selectinload(SecurityHypothesis.proof_attempts),
            )
            .order_by(SecurityHypothesis.created_at)
        )
    )


@router.post(
    "/scans/{scan_id}/evaluations",
    response_model=BenchmarkEvaluationOut,
)
def evaluate_scan_against_ground_truth(
    scan_id: str,
    spec: BenchmarkSpec,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> BenchmarkEvaluation:
    if session.get(Scan, scan_id) is None:
        raise HTTPException(404, "Scan not found")
    try:
        return BenchmarkEvaluator(
            orchestrator.settings,
            orchestrator.database,
        ).evaluate(scan_id, spec)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get(
    "/scans/{scan_id}/evaluations",
    response_model=list[BenchmarkEvaluationOut],
)
def list_benchmark_evaluations(
    scan_id: str,
    session: Session = Depends(get_session),
) -> list[BenchmarkEvaluation]:
    if session.get(Scan, scan_id) is None:
        raise HTTPException(404, "Scan not found")
    return list(
        session.scalars(
            select(BenchmarkEvaluation)
            .where(BenchmarkEvaluation.scan_id == scan_id)
            .order_by(BenchmarkEvaluation.created_at.desc())
        )
    )


@router.get("/scans/{scan_id}/agent-audits", response_model=list[AgentAuditOut])
def list_agent_audits(
    scan_id: str,
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
) -> list[dict[str, Any]]:
    if session.get(Scan, scan_id) is None:
        raise HTTPException(404, "Scan not found")
    return build_agent_audits(session, store, scan_id)


@router.get("/scans/{scan_id}/coverage", response_model=list[CoverageItemOut])
def list_coverage(scan_id: str, session: Session = Depends(get_session)) -> list[CoverageItem]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(CoverageItem)
            .where(CoverageItem.scan_id == scan_id)
            .order_by(CoverageItem.domain, CoverageItem.control_id)
        )
    )


@router.get("/scans/{scan_id}/events", response_model=list[EventOut])
def list_events(
    scan_id: str,
    after: int = Query(0, ge=0),
    session: Session = Depends(get_session),
) -> list[ScanEvent]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id, ScanEvent.id > after)
            .order_by(ScanEvent.id)
        )
    )


@router.get("/scans/{scan_id}/events/stream")
async def stream_events(
    scan_id: str,
    request: Request,
    database: Database = Depends(get_database),
) -> StreamingResponse:
    with database.session_factory() as session:
        if session.get(Scan, scan_id) is None:
            raise HTTPException(404, "Scan not found")
    last_event_id = request.headers.get("last-event-id", "")
    initial_cursor = int(last_event_id) if last_event_id.isdigit() else 0

    async def generate():  # noqa: ANN202
        cursor = initial_cursor
        while not await request.is_disconnected():
            with database.session_factory() as session:
                events = list(
                    session.scalars(
                        select(ScanEvent)
                        .where(ScanEvent.scan_id == scan_id, ScanEvent.id > cursor)
                        .order_by(ScanEvent.id)
                    )
                )
                scan = session.get(Scan, scan_id)
            for event in events:
                cursor = event.id
                payload = EventOut.model_validate(event).model_dump(mode="json")
                stream_event = (
                    "exploration.update"
                    if event.event_type.startswith("exploration.")
                    else event.event_type
                )
                yield f"id: {event.id}\nevent: {stream_event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            if scan is None or (
                scan.status in {ScanStatus.FINAL.value, ScanStatus.FAILED.value}
                and not events
            ):
                yield "event: end\ndata: {}\n\n"
                break
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.post("/findings/{finding_id}/review", response_model=FindingOut)
def review_finding(
    finding_id: str,
    review: FindingReview,
    session: Session = Depends(get_session),
) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    finding.status = review.status
    finding.review_note = review.note
    session.commit()
    session.refresh(finding)
    return finding


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
        raise HTTPException(422, "An enabled AI control requires codex or opencode")

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
    if not _transition_task(
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
            if _transition_task(
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


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: str, session: Session = Depends(get_session)) -> Evidence:
    evidence = session.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(404, "Evidence not found")
    return evidence


@router.get("/evidence/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
) -> FileResponse:
    evidence = session.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(404, "Evidence not found")
    try:
        path = store.verify_content_addressed(
            "evidence", evidence.path, evidence.sha256
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(409, f"Evidence integrity check failed: {exc}") from exc
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@router.get("/scans/{scan_id}/report/{report_format}")
def export_report(
    scan_id: str,
    report_format: str,
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
):  # noqa: ANN201
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    report = reports.build(
        session,
        scan,
        agent_audits=build_agent_audits(session, store, scan_id),
    )
    if report_format == "json":
        return JSONResponse(report)
    if report_format == "sarif":
        return JSONResponse(reports.sarif(report), media_type="application/sarif+json")
    if report_format == "html":
        return HTMLResponse(reports.html(report))
    raise HTTPException(404, "Supported report formats: json, sarif, html")
