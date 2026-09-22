from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..core.schemas import AdbDeviceConnectRequest, AdbDeviceOut
from ..runtime.device_registry import DeviceRegistry

router = APIRouter()


def get_device_registry(request: Request) -> DeviceRegistry:
    return request.app.state.orchestrator.device_registry


@router.get("/devices", response_model=list[AdbDeviceOut])
def list_adb_devices(
    probe: bool = Query(default=False),
    registry: DeviceRegistry = Depends(get_device_registry),
) -> list[dict[str, Any]]:
    return registry.list_devices(probe=probe)


@router.post("/devices", response_model=AdbDeviceOut, status_code=201)
def connect_adb_device(
    control: AdbDeviceConnectRequest,
    registry: DeviceRegistry = Depends(get_device_registry),
) -> dict[str, Any]:
    try:
        return registry.connect(
            control.serial,
            label=control.label,
            connect=control.connect,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/devices/{serial}/drain", response_model=AdbDeviceOut)
def drain_adb_device(
    serial: str,
    registry: DeviceRegistry = Depends(get_device_registry),
) -> dict[str, Any]:
    try:
        return registry.drain(serial)
    except KeyError as exc:
        raise HTTPException(404, "ADB device not found") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/devices/{serial}/reconnect", response_model=AdbDeviceOut)
def reconnect_adb_device(
    serial: str,
    registry: DeviceRegistry = Depends(get_device_registry),
) -> dict[str, Any]:
    try:
        return registry.reconnect(serial)
    except KeyError as exc:
        raise HTTPException(404, "ADB device not found") from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.delete("/devices/{serial}")
def remove_adb_device(
    serial: str,
    registry: DeviceRegistry = Depends(get_device_registry),
) -> dict[str, Any]:
    try:
        registry.remove(serial)
    except KeyError as exc:
        raise HTTPException(404, "ADB device not found") from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"serial": serial, "deleted": True}
