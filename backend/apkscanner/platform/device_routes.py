from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..core.schemas import AdbDeviceConnectRequest, AdbDeviceOut
from ..runtime.orchestrator import ScanOrchestrator

router = APIRouter()


def get_orchestrator(request: Request) -> ScanOrchestrator:
    return request.app.state.orchestrator


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
