from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse

from ..core.models import IndexedArtifact, OperatorSession, OperatorTurn
from ..core.operator_schemas import (
    IndexedArtifactOut,
    OperatorSessionCreate,
    OperatorSessionOut,
    OperatorTurnCreate,
    OperatorTurnOut,
)
from .operator_service import PlatformOperatorService

router = APIRouter()


def get_platform_operator(request: Request) -> PlatformOperatorService:
    return request.app.state.platform_operator


def _operator_session_out(
    operator_session: OperatorSession,
    turns: list[OperatorTurn],
) -> OperatorSessionOut:
    payload = OperatorSessionOut.model_validate(operator_session).model_dump()
    payload["turns"] = [OperatorTurnOut.model_validate(turn).model_dump() for turn in turns]
    return OperatorSessionOut.model_validate(payload)


def _schedule_operator_turn(
    request: Request,
    service: PlatformOperatorService,
    session_id: str,
    turn_id: str,
) -> None:
    task = asyncio.create_task(
        asyncio.to_thread(service.run_turn, session_id, turn_id),
        name=f"platform-operator-{session_id}-{turn_id}",
    )
    request.app.state.background_tasks.add(task)
    task.add_done_callback(request.app.state.background_tasks.discard)


@router.get("/operator/sessions", response_model=list[OperatorSessionOut])
def list_operator_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> list[OperatorSessionOut]:
    result: list[OperatorSessionOut] = []
    for operator_session in service.list_sessions(limit=limit):
        current, turns = service.get_session(operator_session.id)
        result.append(_operator_session_out(current, turns))
    return result


@router.post("/operator/sessions", status_code=202, response_model=OperatorSessionOut)
async def create_operator_session(
    payload: OperatorSessionCreate,
    request: Request,
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> OperatorSessionOut:
    try:
        session_id, turn_id = service.create_session(payload)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    _schedule_operator_turn(request, service, session_id, turn_id)
    operator_session, turns = service.get_session(session_id)
    return _operator_session_out(operator_session, turns)


@router.post(
    "/supervisor/operator-dispatch",
    status_code=202,
    response_model=OperatorSessionOut,
)
async def supervisor_dispatch_operator(
    payload: OperatorSessionCreate,
    request: Request,
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> OperatorSessionOut:
    """Stable dispatch API for a future autonomous Supervisor Agent."""

    return await create_operator_session(payload, request, service)


@router.get("/operator/sessions/{session_id}", response_model=OperatorSessionOut)
def get_operator_session(
    session_id: str,
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> OperatorSessionOut:
    try:
        operator_session, turns = service.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(404, "Operator session not found") from exc
    return _operator_session_out(operator_session, turns)


@router.post(
    "/operator/sessions/{session_id}/turns",
    status_code=202,
    response_model=OperatorSessionOut,
)
async def continue_operator_session(
    session_id: str,
    payload: OperatorTurnCreate,
    request: Request,
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> OperatorSessionOut:
    try:
        turn_id = service.add_turn(session_id, payload.instruction, payload.device_mode)
    except KeyError as exc:
        raise HTTPException(404, "Operator session not found") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    _schedule_operator_turn(request, service, session_id, turn_id)
    operator_session, turns = service.get_session(session_id)
    return _operator_session_out(operator_session, turns)


@router.post("/operator/sessions/{session_id}/cancel")
def cancel_operator_session(
    session_id: str,
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> dict[str, Any]:
    if not service.cancel(session_id):
        raise HTTPException(404, "Operator session not found")
    return {"session_id": session_id, "cancel_requested": True}


@router.get("/operator/artifacts", response_model=list[IndexedArtifactOut])
def list_operator_artifacts(
    scan_id: str | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    operator_session_id: str | None = Query(default=None),
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> list[IndexedArtifact]:
    return service.list_artifacts(
        scan_id=scan_id,
        finding_id=finding_id,
        operator_session_id=operator_session_id,
    )


@router.get("/operator/artifacts/{artifact_id}/download")
def download_operator_artifact(
    artifact_id: str,
    service: PlatformOperatorService = Depends(get_platform_operator),
) -> FileResponse:
    try:
        path = service.artifact_path(artifact_id)
    except KeyError as exc:
        raise HTTPException(404, "Artifact not found") from exc
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")
