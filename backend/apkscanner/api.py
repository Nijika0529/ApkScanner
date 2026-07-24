from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from sqlalchemy import case, desc, select, update
from sqlalchemy.orm import Session

from . import __version__
from .agent_audit import AGENT_AUDIT_KINDS, build_agent_audits
from .artifacts import ArtifactStore, ArtifactTooLargeError
from .db import Database
from .enums import ScanStatus, TaskStatus
from .models import CoverageItem, EntryPoint, Evidence, Finding, InvestigationTask, Scan, ScanEvent
from .orchestrator import ScanOrchestrator
from .reports import ReportBuilder
from .repository import add_event, now
from .schemas import (
    AgentAuditOut,
    Capability,
    CoverageItemOut,
    EntryPointOut,
    EventOut,
    EvidenceOut,
    FindingOut,
    FindingReview,
    HealthResponse,
    InvestigationTaskOut,
    ScanDeleteResult,
    ScanDetail,
    ScanSummary,
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


def get_session(database: Database = Depends(get_database)):
    with database.session_factory() as session:
        yield session


@router.get("/health", response_model=HealthResponse)
def health(orchestrator: ScanOrchestrator = Depends(get_orchestrator)) -> HealthResponse:
    tool_versions = {
        name: orchestrator.runner.version(name)
        for name in ("aapt2", "apksigner", "apktool", "apkanalyzer", "jadx", "adb", "frida")
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
    device = orchestrator.device.capability()
    capabilities.append(
        Capability(
            name="remote_android_device",
            available=bool(device.get("available")),
            version=device.get("android_version"),
            detail=device.get("detail"),
        )
    )
    frida = orchestrator.frida.capability(deep=False)
    capabilities.append(
        Capability(
            name="frida_device",
            available=bool(frida.get("available")),
            version=frida.get("version"),
            detail=frida.get("detail"),
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
    auth = orchestrator.device.auth_capability()
    capabilities.append(
        Capability(
            name="authenticated_replay",
            available=bool(auth.get("available")),
            detail=auth.get("detail"),
        )
    )
    return HealthResponse(
        version=__version__,
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
    return list(
        session.scalars(
            select(EntryPoint)
            .where(EntryPoint.scan_id == scan_id)
            .order_by(EntryPoint.kind, EntryPoint.name)
        )
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(scan_id: str, session: Session = Depends(get_session)) -> list[Finding]:
    return list(
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


@router.get("/scans/{scan_id}/tasks", response_model=list[InvestigationTaskOut])
def list_tasks(scan_id: str, session: Session = Depends(get_session)) -> list[InvestigationTask]:
    return list(
        session.scalars(
            select(InvestigationTask)
            .where(InvestigationTask.scan_id == scan_id)
            .order_by(InvestigationTask.priority.desc(), InvestigationTask.created_at)
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
    async def generate():  # noqa: ANN202
        cursor = 0
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
            if scan and scan.status in {ScanStatus.FINAL.value, ScanStatus.FAILED.value} and not events:
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


@router.post("/tasks/{task_id}/retry", response_model=InvestigationTaskOut, status_code=202)
async def retry_task(
    task_id: str,
    request: Request,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationTask:
    task = session.get(InvestigationTask, task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    if task.status in {
        TaskStatus.QUEUED.value,
        TaskStatus.RUNNING.value,
        TaskStatus.CANCEL_REQUESTED.value,
    }:
        raise HTTPException(409, "Task is already queued or running")
    if task.attempts >= orchestrator.settings.task_max_attempts:
        raise HTTPException(409, "Task retry budget is exhausted")
    task.status = TaskStatus.QUEUED.value
    task.error = None
    task.result = {}
    task.started_at = None
    task.completed_at = None
    scan = session.get(Scan, task.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    scan.status = ScanStatus.INVESTIGATING.value
    scan.completed_at = None
    session.commit()
    background = asyncio.create_task(orchestrator.submit(task.scan_id), name=f"retry-{task.id}")
    request.app.state.background_tasks.add(background)
    background.add_done_callback(request.app.state.background_tasks.discard)
    return task


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
    task = session.get(InvestigationTask, task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    if task.status == TaskStatus.CANCEL_REQUESTED.value:
        raise HTTPException(409, "Task cancellation is already pending")
    if task.status not in {
        TaskStatus.QUEUED.value,
        TaskStatus.AWAITING_DEVICE.value,
        TaskStatus.RUNNING.value,
    }:
        raise HTTPException(409, "Only a queued or running task can be cancelled")

    requested_at = now()
    task.result = {
        **dict(task.result or {}),
        "cancellation": {
            "requested": True,
            "acknowledged": task.status != TaskStatus.RUNNING.value,
            "requested_at": requested_at.isoformat(),
        },
    }
    if task.status == TaskStatus.RUNNING.value:
        task.status = TaskStatus.CANCEL_REQUESTED.value
        task.error = "正在停止当前 AI 分析"
        should_signal = True
        message = "用户已请求停止正在运行的 AI 分析"
    else:
        should_signal = False
        task.status = TaskStatus.CANCELED.value
        task.error = "用户在任务执行前取消了分析"
        task.completed_at = requested_at
        message = "用户已取消等待中的入口探索任务"
    add_event(
        session,
        task.scan_id,
        "task.cancel_requested",
        message,
        {
            "task_id": task.id,
            "status": task.status,
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
            "status": task.status,
        },
    )
    session.commit()
    if should_signal and not orchestrator.request_task_cancellation(task_id):
        session.refresh(task)
        if task.status == TaskStatus.CANCEL_REQUESTED.value:
            task.status = TaskStatus.CANCELED.value
            task.error = "分析运行时已经退出，停止请求已确认"
            task.completed_at = now()
            task.result = {
                **dict(task.result or {}),
                "cancellation": {
                    **dict((task.result or {}).get("cancellation") or {}),
                    "acknowledged": True,
                    "completed_at": task.completed_at.isoformat(),
                },
            }
            add_event(
                session,
                task.scan_id,
                "task.cancelled",
                "分析运行时已经退出，停止请求已确认",
                {"task_id": task.id, "status": TaskStatus.CANCELED.value},
            )
            session.commit()
    session.refresh(task)
    return task


@router.delete("/tasks/{task_id}", response_model=TaskDeleteResult)
def delete_task(
    task_id: str,
    session: Session = Depends(get_session),
) -> TaskDeleteResult:
    task = session.get(InvestigationTask, task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    if task.status not in {
        TaskStatus.BLOCKED_DEVICE.value,
        TaskStatus.COMPLETED.value,
        TaskStatus.NOT_REPRODUCED.value,
        TaskStatus.INCONCLUSIVE.value,
        TaskStatus.TIMED_OUT.value,
        TaskStatus.FAILED.value,
        TaskStatus.CANCELED.value,
    }:
        raise HTTPException(409, "Only a terminal task can be deleted")

    audit_artifacts = list(
        session.scalars(
            select(Evidence).where(
                Evidence.task_id == task_id,
                Evidence.kind.in_(AGENT_AUDIT_KINDS),
            )
        )
    )
    # Evidence and findings are scan-level security records. Detach them from the
    # execution row before deleting the task so AI audits remain available.
    session.execute(
        update(Evidence).where(Evidence.task_id == task_id).values(task_id=None)
    )
    session.delete(task)
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
