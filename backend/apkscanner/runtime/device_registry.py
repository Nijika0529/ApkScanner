from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select

from ..core.config import Settings
from ..core.db import Database
from ..core.enums import ScanStatus
from ..core.models import AdbDeviceRecord, Scan
from ..core.repository import add_event, now
from ..infrastructure.tools import ToolRunner
from .device import AdbDeviceAdapter, AdbDevicePool


class DeviceRegistry:
    """Own persisted ADB devices and synchronize them with the runtime pool."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        runner: ToolRunner,
        pool: AdbDevicePool,
    ) -> None:
        self.settings = settings
        self.database = database
        self.runner = runner
        self.pool = pool

    @classmethod
    def bootstrap(
        cls,
        *,
        settings: Settings,
        database: Database,
        runner: ToolRunner,
    ) -> DeviceRegistry:
        configured_serials = settings.configured_adb_serials
        with database.session_factory() as session:
            records = {item.serial: item for item in session.scalars(select(AdbDeviceRecord))}
            for serial in configured_serials:
                if serial not in records:
                    record = AdbDeviceRecord(
                        serial=serial,
                        label="environment bootstrap",
                        state="ready",
                        enabled=True,
                        metadata_json={"source": "environment"},
                    )
                    session.add(record)
                    records[serial] = record
            session.commit()
            enabled_records = [item for item in records.values() if item.enabled]

        pool = AdbDevicePool(
            [
                AdbDeviceAdapter(settings, runner, serial=item.serial)
                for item in enabled_records
            ]
        )
        for item in enabled_records:
            if item.state == "draining":
                pool.drain(item.serial)
            elif item.state == "unavailable":
                # Persisted devices that disappeared must not inflate task
                # admission until a probe or reconnect succeeds.
                pool.mark_unavailable(item.serial)
        return cls(settings=settings, database=database, runner=runner, pool=pool)

    @staticmethod
    def validate_serial(serial: str) -> str:
        serial = serial.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}", serial):
            raise ValueError("ADB serial contains unsupported characters")
        return serial

    def list_devices(self, *, probe: bool = False) -> list[dict[str, Any]]:
        pool_state = self.pool.snapshot()
        active = dict(pool_state.get("active") or {})
        draining = set(pool_state.get("draining") or [])
        adapters = {str(item.serial): item for item in self.pool.adapters}
        with self.database.session_factory() as session:
            records = list(
                session.scalars(select(AdbDeviceRecord).order_by(AdbDeviceRecord.created_at))
            )
            output: list[dict[str, Any]] = []
            changed = False
            for record in records:
                adapter = adapters.get(record.serial)
                capability: dict[str, Any] = {}
                if adapter is not None:
                    capability = adapter.capability(
                        non_blocking=(not probe or record.serial in active)
                    )
                    if probe and not capability.get("busy") and capability.get("available"):
                        api_text = str(capability.get("api_level") or "")
                        record.api_level = int(api_text) if api_text.isdigit() else None
                        record.android_version = (
                            str(capability.get("android_version") or "") or None
                        )
                        record.last_error = None
                        record.last_seen_at = now()
                        record.state = "draining" if record.serial in draining else "ready"
                        changed = True
                        self.pool.mark_available(record.serial)
                    elif probe and not capability.get("busy"):
                        record.last_error = str(
                            capability.get("detail") or "ADB device is unavailable"
                        )[:4000]
                        record.state = "unavailable"
                        changed = True
                        self.pool.mark_unavailable(record.serial)
                verdict_metadata = self.settings.verdict_metadata(record.api_level)
                verdict_metadata.update(
                    {
                        key: capability[key]
                        for key in verdict_metadata
                        if capability.get(key) is not None
                    }
                )
                if capability and not capability.get("available"):
                    verdict_metadata.update(
                        {
                            "android16_verdict_eligible": False,
                            "dynamic_verdict_eligible": False,
                            "release_gate_eligible": False,
                            "compatibility_smoke_only": False,
                            "verdict_scope": "unavailable",
                        }
                    )
                output.append(
                    {
                        "id": record.id,
                        "serial": record.serial,
                        "label": record.label,
                        "state": (
                            "draining"
                            if record.serial in draining
                            else "busy"
                            if record.serial in active
                            else record.state
                        ),
                        "enabled": record.enabled,
                        "api_level": record.api_level,
                        "android_version": record.android_version,
                        "available": bool(capability.get("available")),
                        **verdict_metadata,
                        "busy": record.serial in active,
                        "active_task_id": active.get(record.serial),
                        "last_error": record.last_error,
                        "last_seen_at": record.last_seen_at,
                        "created_at": record.created_at,
                        "updated_at": record.updated_at,
                    }
                )
            if changed:
                session.commit()
            return output

    def connect(
        self,
        serial: str,
        *,
        label: str | None = None,
        connect: bool = True,
    ) -> dict[str, Any]:
        serial = self.validate_serial(serial)
        if self.pool.is_active(serial):
            raise RuntimeError("Device is active; wait for the owning task before reconnecting it")
        if not self.runner.available("adb"):
            raise RuntimeError("adb is not installed on the host")
        if connect and ":" in serial:
            result = self.runner.run(["adb", "connect", serial], timeout=30)
            combined = f"{result.stdout}\n{result.stderr}".strip().lower()
            if result.exit_code != 0 or "failed" in combined or "unable" in combined:
                raise RuntimeError(combined or "adb connect failed")
        adapter = AdbDeviceAdapter(self.settings, self.runner, serial=serial)
        capability = adapter.capability(non_blocking=False)
        if not capability.get("available"):
            raise RuntimeError(str(capability.get("detail") or "ADB device is unavailable"))
        api_text = str(capability.get("api_level") or "")
        api_level = int(api_text) if api_text.isdigit() else None
        if api_level is None:
            raise RuntimeError("Could not determine the Android API level")
        verdict_metadata = self.settings.verdict_metadata(api_level)
        if not verdict_metadata["dynamic_verdict_eligible"]:
            raise RuntimeError(
                "The selected validation profile does not permit this Android API "
                "to issue a scoped dynamic verdict"
            )
        with self.database.session_factory() as session:
            record = session.scalar(
                select(AdbDeviceRecord).where(AdbDeviceRecord.serial == serial)
            )
            if record is None:
                record = AdbDeviceRecord(serial=serial)
                session.add(record)
            record.label = label.strip() if label and label.strip() else record.label
            record.enabled = True
            record.state = "ready"
            record.api_level = api_level
            record.android_version = str(capability.get("android_version") or "") or None
            record.last_error = None
            record.last_seen_at = now()
            record.metadata_json = {
                **dict(record.metadata_json or {}),
                "source": "runtime_api",
                **verdict_metadata,
            }
            session.commit()
            record_id = record.id
        self.pool.add(adapter)
        self.pool.restore(serial)
        self.pool.wake_waiters()
        self._record_pool_event(
            "device.pool.connected",
            "运行时 ADB 设备已加入探索队列",
            {"serial": serial, "api_level": api_level, **verdict_metadata},
        )
        return next(item for item in self.list_devices() if item["id"] == record_id)

    def drain(self, serial: str) -> dict[str, Any]:
        serial = self.validate_serial(serial)
        if not self.pool.drain(serial):
            raise KeyError(serial)
        with self.database.session_factory() as session:
            record = session.scalar(
                select(AdbDeviceRecord).where(AdbDeviceRecord.serial == serial)
            )
            if record is None:
                raise KeyError(serial)
            record.state = "draining"
            session.commit()
            record_id = record.id
        self._record_pool_event(
            "device.pool.draining",
            "ADB 设备已停止接收新任务，等待当前 lease 释放",
            {"serial": serial, "active": self.pool.is_active(serial)},
        )
        return next(item for item in self.list_devices() if item["id"] == record_id)

    def reconnect(self, serial: str) -> dict[str, Any]:
        serial = self.validate_serial(serial)
        if self.pool.is_active(serial):
            raise RuntimeError("Device is active; drain it and wait for the task to release it")
        if ":" in serial:
            result = self.runner.run(["adb", "connect", serial], timeout=30)
            if result.exit_code != 0:
                raise RuntimeError(result.stderr.strip() or "adb reconnect failed")
        return self.connect(serial, connect=False)

    def remove(self, serial: str) -> None:
        serial = self.validate_serial(serial)
        if self.pool.is_active(serial):
            raise RuntimeError("Device is active; drain it and wait for the task to release it")
        # A persisted device may be absent from the current pool after a restart.
        # The database record remains the management source of truth.
        self.pool.remove(serial)
        with self.database.session_factory() as session:
            record = session.scalar(
                select(AdbDeviceRecord).where(AdbDeviceRecord.serial == serial)
            )
            if record is None:
                raise KeyError(serial)
            session.delete(record)
            session.commit()
        self._record_pool_event(
            "device.pool.removed",
            "ADB 设备已从运行时队列移除",
            {"serial": serial},
        )

    def _record_pool_event(
        self,
        event_type: str,
        message: str,
        data: dict[str, Any],
    ) -> None:
        with self.database.session_factory() as session:
            scan_ids = list(
                session.scalars(
                    select(Scan.id).where(
                        Scan.status.in_(
                            {
                                ScanStatus.INVESTIGATING.value,
                                ScanStatus.PRELIMINARY_READY.value,
                            }
                        )
                    )
                )
            )
            for scan_id in scan_ids:
                add_event(
                    session,
                    scan_id,
                    event_type,
                    message,
                    {**data, "source": "platform"},
                )
            if scan_ids:
                session.commit()
