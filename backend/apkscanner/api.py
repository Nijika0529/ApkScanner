from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any, Literal

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
from sqlalchemy import case, desc, or_, select, update
from sqlalchemy.orm import Session, selectinload

from . import __version__
from .agent_audit import AGENT_AUDIT_KINDS, build_agent_audits
from .artifacts import ArtifactStore, ArtifactTooLargeError
from .benchmark import BenchmarkEvaluator
from .capabilities import CapabilityInvocation, CapabilityRegistry
from .db import Database
from .enums import FindingStatus, ScanStatus, TaskStatus
from .finding_policy import partition_findings
from .models import (
    AdaptiveVerificationCheckpoint,
    AgentSessionRecord,
    AgentTurnRecord,
    ApplicationRecord,
    ApplicationRelease,
    BenchmarkEvaluation,
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationBrief,
    InvestigationTask,
    PatternMatch,
    RuntimeObservation,
    Scan,
    ScanContainerRecord,
    ScanEvent,
    SecurityHypothesis,
    SecuritySnapshot,
    ValidationFixture,
    VersionDiff,
    VulnerabilityCase,
    VulnerabilityOccurrence,
    VulnerabilityPattern,
)
from .orchestrator import ScanOrchestrator
from .reports import ReportBuilder
from .repository import add_event, now
from .schemas import (
    AdbDeviceConnectRequest,
    AdbDeviceOut,
    AgentAuditOut,
    AgentProofReplay,
    AgentRuntimeObservation,
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
    InvestigationBriefCreate,
    InvestigationBriefEvaluation,
    InvestigationBriefOut,
    InvestigationTaskOut,
    PatternMatchOut,
    RegressionCaseCreate,
    ScanAgentControl,
    ScanDeleteResult,
    ScanDetail,
    ScanRerunResult,
    ScanSummary,
    SecurityHypothesisOut,
    SecuritySnapshotOut,
    TaskAgentControl,
    TaskDeleteResult,
    TaskReanalysisRequest,
    ValidationFixtureCreate,
    ValidationFixtureOut,
    VersionDiffOut,
    VulnerabilityCaseOut,
    VulnerabilityOccurrenceOut,
    VulnerabilityPatternOut,
)
from .supervisor import CampaignAppendRequest, CampaignPlan, SupervisorService

router = APIRouter(prefix="/api/v1")
reports = ReportBuilder()


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_store(request: Request) -> ArtifactStore:
    return request.app.state.store


def get_orchestrator(request: Request) -> ScanOrchestrator:
    return request.app.state.orchestrator


def get_capability_registry(request: Request) -> CapabilityRegistry:
    return request.app.state.capability_registry


def get_supervisor(request: Request) -> SupervisorService:
    return request.app.state.supervisor


def get_session(database: Database = Depends(get_database)):
    with database.session_factory() as session:
        yield session


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


@router.post("/internal/tasks/{task_id}/observations", status_code=201)
def record_live_runtime_observation(
    task_id: str,
    observation: AgentRuntimeObservation,
    x_apkscanner_proof_token: str = Header(default=""),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        return orchestrator.record_live_runtime_observation(
            task_id,
            x_apkscanner_proof_token,
            observation,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (TimeoutError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/capabilities/catalog")
def capability_catalog(
    registry: CapabilityRegistry = Depends(get_capability_registry),
) -> list[dict[str, Any]]:
    return registry.catalog()


@router.get("/scans/{scan_id}/agent-runtime")
def scan_agent_runtime(
    scan_id: str,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    if session.get(Scan, scan_id) is None:
        raise HTTPException(404, "scan not found")
    containers = list(
        session.scalars(
            select(ScanContainerRecord)
            .where(ScanContainerRecord.scan_id == scan_id)
            .order_by(ScanContainerRecord.started_at)
        )
    )
    sessions = list(
        session.scalars(
            select(AgentSessionRecord)
            .where(AgentSessionRecord.scan_id == scan_id)
            .order_by(AgentSessionRecord.started_at)
        )
    )
    turns = list(
        session.scalars(
            select(AgentTurnRecord)
            .where(AgentTurnRecord.scan_id == scan_id)
            .order_by(AgentTurnRecord.started_at)
        )
    )
    checkpoints = list(
        session.scalars(
            select(AdaptiveVerificationCheckpoint)
            .where(AdaptiveVerificationCheckpoint.scan_id == scan_id)
            .order_by(AdaptiveVerificationCheckpoint.created_at)
        )
    )
    return {
        "schema_version": "1.0",
        "containers": [
            {
                "id": item.id,
                "task_id": item.task_id,
                "container_key": item.container_key,
                "isolation": item.isolation,
                "workspace_path": item.workspace_path,
                "container_name": item.container_name,
                "status": item.status,
                "started_at": item.started_at.isoformat(),
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
            }
            for item in containers
        ],
        "sessions": [
            {
                "id": item.id,
                "task_id": item.task_id,
                "container_record_id": item.container_record_id,
                "role": item.role,
                "attempt": item.attempt,
                "backend": item.backend,
                "provider": item.provider,
                "model": item.model,
                "thread_id": item.thread_id,
                "status": item.status,
                "started_at": item.started_at.isoformat(),
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
            }
            for item in sessions
        ],
        "turns": [
            {
                "id": item.id,
                "task_id": item.task_id,
                "session_record_id": item.session_record_id,
                "audit_id": item.audit_id,
                "phase": item.phase,
                "round_index": item.round_index,
                "turn_id": item.turn_id,
                "status": item.status,
                "request_evidence_id": item.request_evidence_id,
                "response_evidence_id": item.response_evidence_id,
                "usage": item.usage_json,
                "error": item.error,
                "started_at": item.started_at.isoformat(),
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
            }
            for item in turns
        ],
        "adaptive_checkpoints": [
            {
                "id": item.id,
                "task_id": item.task_id,
                "finding_id": item.finding_id,
                "batch_index": item.batch_index,
                "audit_id": item.audit_id,
                "response_evidence_id": item.response_evidence_id,
                "thread_id": item.thread_id,
                "turn_id": item.turn_id,
                "updated_at": item.updated_at.isoformat(),
            }
            for item in checkpoints
        ],
    }


@router.get("/scans/{scan_id}/runtime-observations")
def list_runtime_observations(
    scan_id: str,
    task_id: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    statement = (
        select(RuntimeObservation)
        .where(RuntimeObservation.scan_id == scan_id)
        .order_by(RuntimeObservation.created_at)
    )
    if task_id is not None:
        statement = statement.where(RuntimeObservation.task_id == task_id)
    return [
        {
            "id": item.id,
            "task_id": item.task_id,
            "finding_id": item.finding_id,
            "observation_key": item.observation_key,
            "kind": item.kind,
            "source": item.source,
            "evidence_ids": item.evidence_ids,
            "payload": item.payload,
            "environment": item.environment,
            "created_at": item.created_at.isoformat(),
        }
        for item in session.scalars(statement)
    ]


@router.post("/capabilities/reload")
def reload_capabilities(
    registry: CapabilityRegistry = Depends(get_capability_registry),
) -> dict[str, Any]:
    try:
        registry.reload()
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"capabilities": registry.catalog()}


@router.post("/capabilities/{capability_id}/invoke")
def invoke_capability(
    capability_id: str,
    invocation: CapabilityInvocation,
    registry: CapabilityRegistry = Depends(get_capability_registry),
) -> dict[str, Any]:
    try:
        return registry.invoke(capability_id, invocation.input).model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(404, "Capability not found") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/supervisor/snapshot")
def supervisor_snapshot(
    supervisor: SupervisorService = Depends(get_supervisor),
) -> dict[str, Any]:
    return supervisor.snapshot()


@router.post("/supervisor/campaigns/validate")
def validate_campaign(
    plan: CampaignPlan,
    supervisor: SupervisorService = Depends(get_supervisor),
) -> dict[str, Any]:
    return supervisor.validate_plan(plan)


@router.post("/supervisor/campaigns/launch", status_code=202)
async def launch_campaign(
    plan: CampaignPlan,
    request: Request,
    supervisor: SupervisorService = Depends(get_supervisor),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        result = supervisor.launch(plan)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    for scan_id in result["scan_ids"]:
        task = asyncio.create_task(
            orchestrator.submit(scan_id),
            name=f"campaign-scan-{scan_id}",
        )
        request.app.state.background_tasks.add(task)
        task.add_done_callback(request.app.state.background_tasks.discard)
    return result


@router.get("/supervisor/campaigns")
def list_campaigns(
    supervisor: SupervisorService = Depends(get_supervisor),
) -> list[dict[str, Any]]:
    return supervisor.list_campaigns()


@router.get("/supervisor/campaigns/{campaign_id}")
def get_campaign(
    campaign_id: str,
    supervisor: SupervisorService = Depends(get_supervisor),
) -> dict[str, Any]:
    try:
        return supervisor.get_campaign(campaign_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


def _schedule_campaign_scans(
    request: Request,
    orchestrator: ScanOrchestrator,
    scan_ids: list[str],
) -> None:
    for scan_id in scan_ids:
        task = asyncio.create_task(
            orchestrator.submit(scan_id),
            name=f"campaign-scan-{scan_id}",
        )
        request.app.state.background_tasks.add(task)
        task.add_done_callback(request.app.state.background_tasks.discard)


@router.post("/supervisor/campaigns/{campaign_id}/cancel")
def cancel_campaign(
    campaign_id: str,
    supervisor: SupervisorService = Depends(get_supervisor),
) -> dict[str, Any]:
    try:
        return supervisor.cancel(campaign_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/supervisor/campaigns/{campaign_id}/continue", status_code=202)
def continue_campaign(
    campaign_id: str,
    request: Request,
    supervisor: SupervisorService = Depends(get_supervisor),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        result = supervisor.continue_campaign(campaign_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    _schedule_campaign_scans(request, orchestrator, result["scan_ids"])
    return result


@router.post("/supervisor/campaigns/{campaign_id}/entries", status_code=202)
def append_campaign_entries(
    campaign_id: str,
    payload: CampaignAppendRequest,
    request: Request,
    supervisor: SupervisorService = Depends(get_supervisor),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        result = supervisor.append_entries(campaign_id, payload)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    _schedule_campaign_scans(request, orchestrator, result["scan_ids"])
    return result


@router.get("/investigation-briefs", response_model=list[InvestigationBriefOut])
def list_investigation_briefs(
    scan_id: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[InvestigationBrief]:
    statement = select(InvestigationBrief).order_by(desc(InvestigationBrief.created_at))
    if scan_id is not None:
        statement = statement.where(InvestigationBrief.scan_id == scan_id)
    return list(session.scalars(statement))


@router.get("/validation-fixtures", response_model=list[ValidationFixtureOut])
def list_validation_fixtures(
    scan_id: str = Query(...),
    task_id: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[ValidationFixture]:
    statement = (
        select(ValidationFixture)
        .where(ValidationFixture.scan_id == scan_id)
        .order_by(ValidationFixture.created_at)
    )
    if task_id is not None:
        statement = statement.where(
            or_(ValidationFixture.task_id.is_(None), ValidationFixture.task_id == task_id)
        )
    return list(session.scalars(statement))


@router.post(
    "/validation-fixtures",
    response_model=ValidationFixtureOut,
    status_code=201,
)
def create_validation_fixture(
    payload: ValidationFixtureCreate,
    session: Session = Depends(get_session),
) -> ValidationFixture:
    if session.get(Scan, payload.scan_id) is None:
        raise HTTPException(404, "scan not found")
    if payload.task_id is not None:
        task = session.get(InvestigationTask, payload.task_id)
        if task is None or task.scan_id != payload.scan_id:
            raise HTTPException(409, "fixture task is outside the selected scan")
    existing = session.scalar(
        select(ValidationFixture).where(
            ValidationFixture.scan_id == payload.scan_id,
            ValidationFixture.name == payload.name,
        )
    )
    if existing is not None:
        raise HTTPException(409, "fixture name already exists in this scan")
    fixture = ValidationFixture(
        scan_id=payload.scan_id,
        task_id=payload.task_id,
        name=payload.name,
        fixture_type=payload.fixture_type,
        payload=payload.payload,
        setup_instructions=list(payload.setup_instructions),
        cleanup_instructions=list(payload.cleanup_instructions),
    )
    session.add(fixture)
    session.commit()
    session.refresh(fixture)
    return fixture


@router.delete("/validation-fixtures/{fixture_id}", status_code=204)
def delete_validation_fixture(
    fixture_id: str,
    session: Session = Depends(get_session),
) -> None:
    fixture = session.get(ValidationFixture, fixture_id)
    if fixture is None:
        raise HTTPException(404, "validation fixture not found")
    session.delete(fixture)
    session.commit()


@router.post(
    "/investigation-briefs",
    response_model=InvestigationBriefOut,
    status_code=201,
)
def create_investigation_brief(
    payload: InvestigationBriefCreate,
    session: Session = Depends(get_session),
) -> InvestigationBrief:
    try:
        plan = CampaignPlan.model_validate(payload.plan)
    except ValueError as exc:
        raise HTTPException(422, f"Invalid entry plan: {exc}") from exc
    if payload.scan_id is not None and session.get(Scan, payload.scan_id) is None:
        raise HTTPException(404, "Scan not found")
    brief = InvestigationBrief(
        scan_id=payload.scan_id,
        name=payload.name,
        objective=payload.objective,
        status="draft",
        scope=payload.scope,
        attacker_model=payload.attacker_model,
        preconditions=list(payload.preconditions),
        plan=plan.model_dump(mode="json"),
        evaluation_contract=payload.evaluation_contract.model_dump(mode="json"),
        result={},
    )
    session.add(brief)
    session.flush()
    if brief.scan_id:
        add_event(
            session,
            brief.scan_id,
            "investigation.brief.created",
            "已创建带评判契约的特殊调查入口",
            {"brief_id": brief.id, "name": brief.name},
        )
    session.commit()
    session.refresh(brief)
    return brief


@router.post("/investigation-briefs/{brief_id}/validate")
def validate_investigation_brief(
    brief_id: str,
    session: Session = Depends(get_session),
    supervisor: SupervisorService = Depends(get_supervisor),
) -> dict[str, Any]:
    brief = session.get(InvestigationBrief, brief_id)
    if brief is None:
        raise HTTPException(404, "Investigation brief not found")
    plan = CampaignPlan.model_validate(brief.plan)
    validation = supervisor.validate_plan(plan)
    brief.status = "validated" if validation["valid"] else "draft"
    brief.result = {**dict(brief.result or {}), "validation": validation}
    session.commit()
    return {
        **validation,
        "brief_id": brief.id,
        "evaluation_contract": brief.evaluation_contract,
    }


@router.post(
    "/investigation-briefs/{brief_id}/launch",
    response_model=InvestigationBriefOut,
    status_code=202,
)
async def launch_investigation_brief(
    brief_id: str,
    request: Request,
    session: Session = Depends(get_session),
    supervisor: SupervisorService = Depends(get_supervisor),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> InvestigationBrief:
    brief = session.get(InvestigationBrief, brief_id)
    if brief is None:
        raise HTTPException(404, "Investigation brief not found")
    if brief.status == "running":
        raise HTTPException(409, "Investigation brief is already running")
    plan = CampaignPlan.model_validate(brief.plan)
    validation = supervisor.validate_plan(plan)
    if not validation["valid"]:
        raise HTTPException(409, "Investigation brief has unavailable or invalid entries")
    result = supervisor.launch(plan)
    brief.status = "running" if result["scan_ids"] else "completed"
    brief.result = {
        "launch": result,
        "evaluation_contract": brief.evaluation_contract,
        "verdict": "pending" if result["scan_ids"] else "requires_evaluation",
    }
    if brief.scan_id:
        add_event(
            session,
            brief.scan_id,
            "investigation.brief.launched",
            "特殊调查入口已交给监督控制面执行",
            {"brief_id": brief.id, "generated_scan_ids": result["scan_ids"]},
        )
    session.commit()
    for scan_id in result["scan_ids"]:
        task = asyncio.create_task(
            orchestrator.submit(scan_id),
            name=f"brief-scan-{scan_id}",
        )
        request.app.state.background_tasks.add(task)
        task.add_done_callback(request.app.state.background_tasks.discard)
    session.refresh(brief)
    return brief


@router.post(
    "/investigation-briefs/{brief_id}/evaluate",
    response_model=InvestigationBriefOut,
)
def evaluate_investigation_brief(
    brief_id: str,
    payload: InvestigationBriefEvaluation,
    session: Session = Depends(get_session),
) -> InvestigationBrief:
    brief = session.get(InvestigationBrief, brief_id)
    if brief is None:
        raise HTTPException(404, "Investigation brief not found")
    contract = dict(brief.evaluation_contract or {})
    expected_criteria = set(contract.get("success_criteria") or [])
    submitted = {item.criterion: item for item in payload.criteria}
    if set(submitted) != expected_criteria:
        raise HTTPException(422, "Every success criterion must be evaluated exactly once")
    evidence_ids = {
        evidence_id
        for item in payload.criteria
        for evidence_id in item.evidence_ids
    }
    evidence = list(
        session.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids)))
    ) if evidence_ids else []
    if len(evidence) != len(evidence_ids):
        raise HTTPException(422, "Evaluation references unknown Evidence IDs")
    launch = dict((brief.result or {}).get("launch") or {})
    allowed_scan_ids = set(launch.get("scan_ids") or [])
    if brief.scan_id:
        allowed_scan_ids.add(brief.scan_id)
    if any(item.scan_id not in allowed_scan_ids for item in evidence):
        raise HTTPException(422, "Evaluation Evidence is outside the brief scope")
    observed_kinds = {item.kind for item in evidence}
    required_kinds = set(contract.get("required_evidence_kinds") or [])
    missing_kinds = sorted(required_kinds - observed_kinds)
    if payload.verdict == "passed" and (
        missing_kinds or not all(item.passed for item in payload.criteria)
    ):
        raise HTTPException(
            409,
            "A passed verdict requires every criterion and every required Evidence kind",
        )
    brief.status = "completed"
    brief.result = {
        **dict(brief.result or {}),
        "verdict": payload.verdict,
        "evaluation": {
            **payload.model_dump(mode="json"),
            "evidence_ids": sorted(evidence_ids),
            "observed_evidence_kinds": sorted(observed_kinds),
            "missing_evidence_kinds": missing_kinds,
            "evaluated_at": now().isoformat(),
        },
    }
    if brief.scan_id:
        add_event(
            session,
            brief.scan_id,
            "investigation.brief.evaluated",
            f"特殊调查已按 Evaluation Contract 完成：{payload.verdict}",
            {"brief_id": brief.id, "verdict": payload.verdict},
        )
    session.commit()
    session.refresh(brief)
    return brief


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


@router.get("/devices", response_model=list[AdbDeviceOut])
def list_adb_devices(
    probe: bool = Query(default=False),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> list[dict[str, Any]]:
    return orchestrator.list_adb_devices(probe=probe)


@router.post("/devices", response_model=AdbDeviceOut, status_code=201)
def connect_adb_device(
    control: AdbDeviceConnectRequest,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        return orchestrator.connect_adb_device(
            control.serial,
            label=control.label,
            connect=control.connect,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/devices/{serial}/drain", response_model=AdbDeviceOut)
def drain_adb_device(
    serial: str,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        return orchestrator.drain_adb_device(serial)
    except KeyError as exc:
        raise HTTPException(404, "ADB device not found") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/devices/{serial}/reconnect", response_model=AdbDeviceOut)
def reconnect_adb_device(
    serial: str,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        return orchestrator.reconnect_adb_device(serial)
    except KeyError as exc:
        raise HTTPException(404, "ADB device not found") from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.delete("/devices/{serial}")
def remove_adb_device(
    serial: str,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    try:
        orchestrator.remove_adb_device(serial)
    except KeyError as exc:
        raise HTTPException(404, "ADB device not found") from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"serial": serial, "deleted": True}


@router.get("/health", response_model=HealthResponse)
def health(orchestrator: ScanOrchestrator = Depends(get_orchestrator)) -> HealthResponse:
    tool_versions = {
        name: orchestrator.runner.version(name)
        for name in ("aapt2", "apksigner", "apktool", "jadx", "adb")
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
    device = orchestrator.device_pool.capability(non_blocking=True)
    capabilities.append(
        Capability(
            name="remote_android_device",
            available=bool(device.get("available")),
            busy=bool(device.get("busy")),
            version=device.get("android_version"),
            detail=device.get("detail"),
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
            for name in ("codex",)
            if orchestrator.settings.investigator_enabled(name)
        ],
        capabilities=capabilities,
    )


@router.post("/scans", response_model=ScanSummary, status_code=202)
async def create_scan(
    request: Request,
    apk: UploadFile = File(...),
    investigator: str = Form("configured"),
    baseline_scan_id: str | None = Form(default=None),
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> Scan:
    try:
        resolved_investigator = orchestrator.resolve_investigator(investigator)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    baseline: Scan | None = None
    if baseline_scan_id:
        baseline = session.get(Scan, baseline_scan_id)
        if baseline is None:
            raise HTTPException(404, "Baseline scan not found")
        if baseline.status != ScanStatus.FINAL.value:
            raise HTTPException(409, "Baseline scan must be final")
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
            "version_baseline": (
                {
                    "scan_id": baseline.id,
                    "selection": "explicit",
                    "artifact_sha256": baseline.artifact_sha256,
                }
                if baseline is not None
                else None
            ),
        },
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    task = asyncio.create_task(orchestrator.submit(scan.id), name=f"scan-{scan.id}")
    request.app.state.background_tasks.add(task)
    task.add_done_callback(request.app.state.background_tasks.discard)
    return scan


@router.post(
    "/scans/{scan_id}/fresh-run",
    response_model=ScanSummary,
    status_code=202,
)
async def create_fresh_scan_run(
    scan_id: str,
    request: Request,
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> Scan:
    source = require_scan(session, scan_id)
    if source.status not in {ScanStatus.FINAL.value, ScanStatus.FAILED.value}:
        raise HTTPException(409, "Wait for the current scan run to finish before starting a fresh run")
    try:
        artifact_path = store.verify_content_addressed(
            "artifacts",
            source.artifact_path,
            source.artifact_sha256,
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(409, f"The original APK artifact is unavailable: {exc}") from exc

    source_stats = dict(source.stats or {})
    source_control = source_stats.get("agent_control")
    if not isinstance(source_control, dict):
        source_control = {}
    requested_backend = str(
        source_control.get("backend")
        or source_stats.get("investigator")
        or "configured"
    )
    try:
        resolved_backend = orchestrator.resolve_investigator(requested_backend)
    except ValueError:
        resolved_backend = orchestrator.resolve_investigator()
    agent_enabled = bool(source_control.get("enabled", resolved_backend != "none"))
    investigator = resolved_backend if agent_enabled else "none"
    fresh_run = Scan(
        status=ScanStatus.QUEUED.value,
        filename=source.filename,
        artifact_sha256=source.artifact_sha256,
        artifact_path=str(artifact_path),
        stats={
            "upload_bytes": artifact_path.stat().st_size,
            "investigator": investigator,
            "agent_control": {
                "enabled": investigator != "none",
                "backend": resolved_backend,
            },
            "fresh_run": {
                "source_scan_id": source.id,
                "mode": "isolated",
                "reuse_apk_only": True,
                "inherit_tasks": False,
                "inherit_findings": False,
                "inherit_evidence": False,
                "inherit_agent_sessions": False,
                "inherit_version_replays": False,
                "inherit_pattern_matches": False,
            },
        },
    )
    session.add(fresh_run)
    session.flush()
    add_event(
        session,
        fresh_run.id,
        "scan.fresh_run.created",
        "已基于原始 APK 创建独立全新扫描；未继承旧任务、结论、证据或 Agent 会话",
        {
            "source_scan_id": source.id,
            "artifact_sha256": source.artifact_sha256,
            "reuse_apk_only": True,
        },
    )
    add_event(
        session,
        source.id,
        "scan.fresh_run.spawned",
        "已从该扫描创建一个不继承历史结果的全新扫描",
        {"fresh_scan_id": fresh_run.id},
    )
    session.commit()
    session.refresh(fresh_run)

    task = asyncio.create_task(
        orchestrator.submit(fresh_run.id),
        name=f"fresh-scan-{fresh_run.id}",
    )
    request.app.state.background_tasks.add(task)
    task.add_done_callback(request.app.state.background_tasks.discard)
    return fresh_run


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


@router.get("/scans/{scan_id}/artifact-graph")
def get_scan_artifact_graph(
    scan_id: str,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    scan = require_scan(session, scan_id)
    workspace = (scan.stats or {}).get("workspace")
    if not isinstance(workspace, str):
        raise HTTPException(409, "Product bundle analysis has not completed")
    graph_path = Path(workspace) / "artifact_graph.json"
    if not graph_path.is_file():
        raise HTTPException(404, "Artifact graph is unavailable")
    try:
        payload = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(409, "Artifact graph could not be read") from exc
    return payload


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


@router.get(
    "/scans/{scan_id}/security-snapshot",
    response_model=SecuritySnapshotOut,
)
def get_security_snapshot(
    scan_id: str,
    session: Session = Depends(get_session),
) -> SecuritySnapshot:
    require_scan(session, scan_id)
    snapshot = session.scalar(
        select(SecuritySnapshot).where(SecuritySnapshot.scan_id == scan_id)
    )
    if snapshot is None:
        raise HTTPException(404, "Security snapshot is not available")
    return snapshot


@router.get(
    "/scans/{scan_id}/version-diff",
    response_model=VersionDiffOut,
)
def get_version_diff(
    scan_id: str,
    session: Session = Depends(get_session),
) -> VersionDiff:
    require_scan(session, scan_id)
    diff = session.scalar(
        select(VersionDiff)
        .where(VersionDiff.target_scan_id == scan_id)
        .order_by(desc(VersionDiff.created_at))
    )
    if diff is None:
        raise HTTPException(404, "No same-signer baseline version is available")
    return diff


@router.post(
    "/findings/{finding_id}/regression-case",
    response_model=VulnerabilityCaseOut,
    status_code=201,
)
def create_regression_case(
    finding_id: str,
    payload: RegressionCaseCreate,
    session: Session = Depends(get_session),
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> VulnerabilityCase:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    scan = session.get(Scan, finding.scan_id)
    snapshot = session.scalar(
        select(SecuritySnapshot).where(SecuritySnapshot.scan_id == finding.scan_id)
    )
    if scan is None or snapshot is None:
        raise HTTPException(409, "The source scan has no security snapshot")
    release = session.scalar(
        select(ApplicationRelease).where(ApplicationRelease.scan_id == scan.id)
    )
    if release is None:
        release = orchestrator.security_evolution.ensure_application_release(
            session,
            scan=scan,
            snapshot=snapshot,
        )
    stable_by_entry = {
        str(item.get("entry_id")): str(item.get("stable_key"))
        for item in (snapshot.payload or {}).get("entries", [])
        if isinstance(item, dict) and item.get("entry_id") and item.get("stable_key")
    }
    identity = {
        "namespace": "apkscanner-regression-case",
        "version": "case-v1",
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "entry_stable_keys": sorted(
            stable_by_entry[item]
            for item in finding.entry_point_ids
            if item in stable_by_entry
        ),
        "title": " ".join(finding.title.lower().split()),
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    duplicate = session.scalar(
        select(VulnerabilityCase).where(
            VulnerabilityCase.application_id == release.application_id,
            (
                (VulnerabilityCase.case_key == payload.case_key)
                | (VulnerabilityCase.fingerprint == fingerprint)
            ),
        )
    )
    if duplicate is not None:
        raise HTTPException(409, "A regression case with this key or identity already exists")
    case_record = VulnerabilityCase(
        application_id=release.application_id,
        case_key=payload.case_key,
        fingerprint_version="case-v1",
        fingerprint=fingerprint,
        identity_json=identity,
        title=finding.title,
        description=finding.description,
        harm=payload.harm,
        severity=finding.severity,
        cwe=finding.cwe,
        masvs=finding.masvs,
        minimum_proof=payload.minimum_proof,
        lifecycle="active",
        source_scan_id=scan.id,
        source_finding_id=finding.id,
    )
    session.add(case_record)
    session.flush()
    proof_level = (
        "dynamic"
        if finding.status == FindingStatus.REPRODUCED_BLACKBOX.value
        else "static"
        if finding.status == FindingStatus.SUPPORTED_STATIC.value
        else "none"
    )
    session.add(
        VulnerabilityOccurrence(
            case_id=case_record.id,
            scan_id=scan.id,
            finding_id=finding.id,
            analysis_status=finding.status,
            proof_level=proof_level,
            match_quality="strong",
            match_reason="explicitly promoted from the source finding by the operator",
            observed_identity_json={
                **identity,
                "snapshot_hash": snapshot.snapshot_hash,
            },
        )
    )
    add_event(
        session,
        scan.id,
        "version.regression_case.created",
        "已将 Finding 提升为跨版本稳定漏洞案例",
        {"case_id": case_record.id, "case_key": case_record.case_key},
    )
    session.commit()
    session.refresh(case_record)
    return case_record


@router.get(
    "/applications/{application_id}/regression-cases",
    response_model=list[VulnerabilityCaseOut],
)
def list_regression_cases(
    application_id: str,
    session: Session = Depends(get_session),
) -> list[VulnerabilityCase]:
    if session.get(ApplicationRecord, application_id) is None:
        raise HTTPException(404, "Application not found")
    return list(
        session.scalars(
            select(VulnerabilityCase)
            .where(VulnerabilityCase.application_id == application_id)
            .order_by(VulnerabilityCase.created_at)
        )
    )


@router.get(
    "/scans/{scan_id}/regression-occurrences",
    response_model=list[VulnerabilityOccurrenceOut],
)
def list_regression_occurrences(
    scan_id: str,
    session: Session = Depends(get_session),
) -> list[VulnerabilityOccurrence]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(VulnerabilityOccurrence)
            .where(VulnerabilityOccurrence.scan_id == scan_id)
            .order_by(VulnerabilityOccurrence.created_at)
        )
    )


@router.get(
    "/scans/{scan_id}/pattern-matches",
    response_model=list[PatternMatchOut],
)
def list_pattern_matches(
    scan_id: str,
    session: Session = Depends(get_session),
) -> list[PatternMatch]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(PatternMatch)
            .where(PatternMatch.scan_id == scan_id)
            .order_by(PatternMatch.score.desc(), PatternMatch.created_at)
        )
    )


@router.get("/patterns", response_model=list[VulnerabilityPatternOut])
def list_vulnerability_patterns(
    session: Session = Depends(get_session),
) -> list[VulnerabilityPattern]:
    return list(
        session.scalars(
            select(VulnerabilityPattern).order_by(
                VulnerabilityPattern.updated_at.desc()
            )
        )
    )


@router.get(
    "/patterns/{pattern_id}",
    response_model=VulnerabilityPatternOut,
)
def get_vulnerability_pattern(
    pattern_id: str,
    session: Session = Depends(get_session),
) -> VulnerabilityPattern:
    pattern = session.get(VulnerabilityPattern, pattern_id)
    if pattern is None:
        raise HTTPException(404, "Vulnerability pattern not found")
    return pattern


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
    include_artifacts: bool = Query(default=True),
    audit_id: str | None = Query(default=None, min_length=1, max_length=128),
    session: Session = Depends(get_session),
    store: ArtifactStore = Depends(get_store),
) -> list[dict[str, Any]]:
    if session.get(Scan, scan_id) is None:
        raise HTTPException(404, "Scan not found")
    return build_agent_audits(
        session,
        store,
        scan_id,
        include_artifacts=include_artifacts,
        audit_id=audit_id,
    )


@router.get("/scans/{scan_id}/coverage", response_model=list[CoverageItemOut])
def list_coverage(scan_id: str, session: Session = Depends(get_session)) -> list[CoverageItem]:
    require_scan(session, scan_id)
    return list(
        session.scalars(
            select(CoverageItem)
            .where(
                CoverageItem.scan_id == scan_id,
                CoverageItem.control_id != "ENGINE-MOBSF",
            )
            .order_by(CoverageItem.domain, CoverageItem.control_id)
        )
    )


@router.get("/scans/{scan_id}/events", response_model=list[EventOut])
def list_events(
    scan_id: str,
    after: int = Query(0, ge=0),
    limit: int = Query(300, ge=1, le=2_000),
    detail: Literal["summary", "full"] = Query("full"),
    session: Session = Depends(get_session),
) -> list[ScanEvent]:
    require_scan(session, scan_id)
    statement = select(ScanEvent).where(ScanEvent.scan_id == scan_id)
    if detail == "summary":
        statement = statement.where(_console_summary_event_filter())
    if after:
        return list(
            session.scalars(
                statement.where(ScanEvent.id > after)
                .order_by(ScanEvent.id)
                .limit(limit)
            )
        )
    latest = list(
        session.scalars(statement.order_by(ScanEvent.id.desc()).limit(limit))
    )
    latest.reverse()
    return latest


@router.get("/scans/{scan_id}/events/stream")
async def stream_events(
    scan_id: str,
    request: Request,
    database: Database = Depends(get_database),
    after: int = Query(0, ge=0),
    detail: Literal["summary", "full"] = Query("full"),
) -> StreamingResponse:
    with database.session_factory() as session:
        if session.get(Scan, scan_id) is None:
            raise HTTPException(404, "Scan not found")
    last_event_id = request.headers.get("last-event-id", "")
    initial_cursor = (
        int(last_event_id)
        if last_event_id.isdigit()
        else after
        if isinstance(after, int)
        else 0
    )

    async def generate():  # noqa: ANN202
        cursor = initial_cursor
        while not await request.is_disconnected():
            with database.session_factory() as session:
                statement = select(ScanEvent).where(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.id > cursor,
                )
                if detail == "summary":
                    statement = statement.where(_console_summary_event_filter())
                events = list(
                    session.scalars(
                        statement.order_by(ScanEvent.id).limit(200)
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


_SUMMARY_MODEL_EVENTS = {
    "exploration.model.cancelled",
    "exploration.model.completed",
    "exploration.model.dispatched",
    "exploration.model.failed",
    "exploration.model.output.validated",
}


def _console_summary_event_filter():  # noqa: ANN202
    """Exclude high-rate runtime telemetry from the interactive console stream."""
    return (
        or_(
            ~ScanEvent.event_type.like("exploration.model.%"),
            ScanEvent.event_type.in_(_SUMMARY_MODEL_EVENTS),
        )
        & (ScanEvent.event_type != "exploration.evidence.created")
    )


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
