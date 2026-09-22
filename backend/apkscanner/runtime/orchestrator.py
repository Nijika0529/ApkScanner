from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import shutil
import threading
import time
import uuid
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager, suppress
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import desc, select, update

from ..analysis.asc_xrefs import (
    AscXrefExtractor,
    build_asc_queries,
    evidence_summary,
    relevance_filter,
)
from ..analysis.manifest import parse_manifest
from ..analysis.rules import BuiltinRuleEngine
from ..analysis.security_design import build_android_threat_model, finding_identity
from ..analysis.static_analysis import CODE_INDEX_CONTEXT_VERSION, ApkInspector
from ..analysis.target_profiles import (
    active_profile_id,
    investigation_group,
    target_review_surfaces,
)
from ..core.config import Settings
from ..core.db import Database
from ..core.enums import (
    CoverageStatus,
    EntryPointKind,
    FindingStatus,
    HypothesisStatus,
    ScanStatus,
    TaskStatus,
    TaskType,
)
from ..core.evidence import EvidenceRecorder
from ..core.finding_policy import (
    build_static_refutation_gate,
    evidence_backed_signal_tier,
    static_evidence_is_usable,
)
from ..core.models import (
    AdbDeviceRecord,
    AgentRuntimeEventRecord,
    AgentSessionRecord,
    AgentTurnRecord,
    CoverageItem,
    DynamicExperimentCapsule,
    DynamicExperimentReceipt,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    ScanContainerRecord,
    SecurityHypothesis,
    ValidationFixture,
)
from ..core.proof_receipts import (
    evidence_backed_harm_attempts,
)
from ..core.repository import add_event, now
from ..core.schemas import (
    AGENT_RESULT_JSON_SCHEMA,
    AgentInvestigationResult,
    AgentOracleSpec,
    AgentRequestedTest,
)
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.tools import CommandResult, TimeBudget, ToolRunner
from .adaptive_verification import AdaptiveVerificationMixin
from .adb_gateway import (
    validate_dynamic_experiment_adb_template,
)
from .agent_events import AgentCancelledError, AgentRuntimeEvent
from .agent_prompt import (
    developer_instructions,
    investigation_prompt,
)
from .attacker_templates import attacker_template_catalog, materialize_attacker_templates
from .codex_runner import CodexInvestigator, CodexRunResult
from .concurrency import ResizableSemaphore
from .device import AdbDeviceAdapter, AdbDevicePool, DeviceLeaseCancelledError
from .dynamic_experiments import DynamicExperimentService
from .finalization import ScanFinalizer
from .finding_reports import (
    build_finding_report,
    render_finding_description,
    render_finding_remediation,
)
from .live_proof import LiveProofContext
from .live_proof_gateway import LiveProofGatewayMixin
from .planner import InvestigationPlanner
from .poc import PocBuilder, PocBuildResult
from .proof_recipes import ProofRecipe, bind_proof_recipe, proof_recipe_from_plan
from .runtime_artifacts import RuntimeArtifactService
from .runtime_contracts import task_gateway_environment
from .security_pipeline import HypothesisLedger
from .versioning import SecurityEvolutionService

# Temporary import compatibility for integrations written before LiveProofContext
# became a public runtime contract.
_LiveProofContext = LiveProofContext


class ScanOrchestrator(LiveProofGatewayMixin, AdaptiveVerificationMixin):
    def __init__(self, settings: Settings, database: Database, store: ArtifactStore):
        self.settings = settings
        self.database = database
        self.store = store
        self.runner = ToolRunner(
            settings.tool_timeout_seconds,
            executable_overrides={"adb": settings.host_adb_executable},
        )
        self.inspector = ApkInspector(settings, self.runner)
        self.asc = AscXrefExtractor(settings, self.runner)
        self.rules = BuiltinRuleEngine()
        self.evidence = EvidenceRecorder(store)
        self.hypothesis_ledger = HypothesisLedger(database)
        configured_serials = settings.configured_adb_serials
        with self.database.session_factory() as session:
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
        self.devices = [
            AdbDeviceAdapter(settings, self.runner, serial=item.serial) for item in enabled_records
        ]
        # Compatibility handle for integrations that customize the first
        # adapter. Scheduling always goes through the mutable pool below.
        self.device = self.devices[0] if self.devices else AdbDeviceAdapter(settings, self.runner)
        self.device_pool = AdbDevicePool(self.devices)
        for item in enabled_records:
            if item.state == "draining":
                self.device_pool.drain(item.serial)
            elif item.state == "unavailable":
                # A record from a previous session whose phone is gone must not
                # inflate device-bound concurrency until a probe/reconnect succeeds.
                self.device_pool.mark_unavailable(item.serial)
        self.poc_builder = PocBuilder(settings, self.runner, store)
        self.dynamic_experiments = DynamicExperimentService(
            database,
            self.evidence,
            self.device_pool,
        )
        self.runtime_artifacts = RuntimeArtifactService(
            settings,
            database,
            store,
            self.inspector,
            self.evidence,
            self.device_pool,
        )
        self.security_evolution = SecurityEvolutionService()
        self.codex = CodexInvestigator(settings)
        self.investigators = {"codex": self.codex}
        self._running: set[str] = set()
        self._resubmit_requested: set[str] = set()
        self._running_lock = asyncio.Lock()
        self._task_cancellations: dict[str, threading.Event] = {}
        self._live_proof_contexts: dict[str, LiveProofContext] = {}
        self._live_proof_lock = threading.Lock()
        self._live_proof_server: ThreadingHTTPServer | None = None
        self._live_proof_server_thread: threading.Thread | None = None
        self._live_proof_base_url: str | None = None
        self._task_cancellations_lock = threading.Lock()
        self._shutting_down = threading.Event()
        self._analysis_slots = ResizableSemaphore(settings.agent_analysis_slots)
        self._admission_targets: dict[str, int] = {}
        self._admission_lock = threading.Lock()
        self._build_slots = threading.BoundedSemaphore(settings.poc_build_slots)
        self.finalizer = ScanFinalizer(
            settings=settings,
            database=database,
            evidence=self.evidence,
            device_pool=self.device_pool,
            resolve_task_investigator=self.resolve_task_investigator,
        )

    @staticmethod
    def _validate_adb_serial(serial: str) -> str:
        serial = serial.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}", serial):
            raise ValueError("ADB serial contains unsupported characters")
        return serial

    def list_adb_devices(self, *, probe: bool = False) -> list[dict[str, Any]]:
        pool = self.device_pool.snapshot()
        active = dict(pool.get("active") or {})
        draining = set(pool.get("draining") or [])
        adapters = {str(item.serial): item for item in self.device_pool.adapters}
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
                        # A successful probe returns the phone to the assignable set
                        # so device-bound concurrency follows connected devices.
                        self.device_pool.mark_available(record.serial)
                    elif probe and not capability.get("busy"):
                        record.last_error = str(
                            capability.get("detail") or "ADB device is unavailable"
                        )[:4000]
                        record.state = "unavailable"
                        changed = True
                        self.device_pool.mark_unavailable(record.serial)
                verdict_metadata = self.settings.verdict_metadata(record.api_level)
                verdict_metadata.update(
                    {
                        key: capability[key]
                        for key in verdict_metadata
                        if capability.get(key) is not None
                    }
                )
                if capability and not capability.get("available"):
                    verdict_metadata["android16_verdict_eligible"] = False
                    verdict_metadata["dynamic_verdict_eligible"] = False
                    verdict_metadata["release_gate_eligible"] = False
                    verdict_metadata["compatibility_smoke_only"] = False
                    verdict_metadata["verdict_scope"] = "unavailable"
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

    def connect_adb_device(
        self,
        serial: str,
        *,
        label: str | None = None,
        connect: bool = True,
    ) -> dict[str, Any]:
        serial = self._validate_adb_serial(serial)
        if self.device_pool.is_active(serial):
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
            record = session.scalar(select(AdbDeviceRecord).where(AdbDeviceRecord.serial == serial))
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
        self.device_pool.add(adapter)
        self.device_pool.restore(serial)
        self.device_pool.wake_waiters()
        self._record_device_pool_event(
            "device.pool.connected",
            "运行时 ADB 设备已加入探索队列",
            {
                "serial": serial,
                "api_level": api_level,
                **verdict_metadata,
            },
        )
        return next(item for item in self.list_adb_devices() if item["id"] == record_id)

    def drain_adb_device(self, serial: str) -> dict[str, Any]:
        serial = self._validate_adb_serial(serial)
        if not self.device_pool.drain(serial):
            raise KeyError(serial)
        with self.database.session_factory() as session:
            record = session.scalar(select(AdbDeviceRecord).where(AdbDeviceRecord.serial == serial))
            if record is None:
                raise KeyError(serial)
            record.state = "draining"
            session.commit()
            record_id = record.id
        self._record_device_pool_event(
            "device.pool.draining",
            "ADB 设备已停止接收新任务，等待当前 lease 释放",
            {"serial": serial, "active": self.device_pool.is_active(serial)},
        )
        return next(item for item in self.list_adb_devices() if item["id"] == record_id)

    def reconnect_adb_device(self, serial: str) -> dict[str, Any]:
        serial = self._validate_adb_serial(serial)
        if self.device_pool.is_active(serial):
            raise RuntimeError("Device is active; drain it and wait for the task to release it")
        if ":" in serial:
            result = self.runner.run(["adb", "connect", serial], timeout=30)
            if result.exit_code != 0:
                raise RuntimeError(result.stderr.strip() or "adb reconnect failed")
        return self.connect_adb_device(serial, connect=False)

    def remove_adb_device(self, serial: str) -> None:
        serial = self._validate_adb_serial(serial)
        if self.device_pool.is_active(serial):
            raise RuntimeError("Device is active; drain it and wait for the task to release it")
        # Best-effort removal from the runtime pool: a device may be persisted in
        # the database from a previous bootstrap but absent from the current
        # runtime pool (e.g. the server was restarted with different
        # APKSCANNER_ADB_SERIALS).  The database record is the source of truth,
        # so deleting it below is what actually removes the device.
        self.device_pool.remove(serial)
        with self.database.session_factory() as session:
            record = session.scalar(select(AdbDeviceRecord).where(AdbDeviceRecord.serial == serial))
            if record is None:
                raise KeyError(serial)
            session.delete(record)
            session.commit()
        self._record_device_pool_event(
            "device.pool.removed",
            "ADB 设备已从运行时队列移除",
            {"serial": serial},
        )

    def _record_device_pool_event(
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

    def resolve_investigator(self, requested: str = "configured") -> str:
        backend = (
            self.settings.investigator_backend
            if requested.strip().lower() == "configured"
            else requested.strip().lower()
        )
        if backend not in {*self.investigators, "none"}:
            raise ValueError("investigator must be configured, codex, or none")
        return backend

    def resolve_task_investigator(
        self,
        scan: Scan,
        task: InvestigationTask,
    ) -> str:
        control = scan.stats.get("agent_control")
        if not isinstance(control, dict):
            control = {}
        backend = self.resolve_investigator(
            str(control.get("backend") or scan.stats.get("investigator", "configured"))
        )
        master_enabled = bool(control.get("enabled", backend != "none"))
        task_override = (task.preconditions or {}).get("agent_enabled")
        task_enabled = task_override if isinstance(task_override, bool) else True
        return backend if master_enabled and task_enabled else "none"

    def _record_exploration_event(
        self,
        scan_id: str,
        task_id: str,
        event_type: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        normalized_type = (
            event_type if event_type.startswith("exploration.") else f"exploration.{event_type}"
        )
        with self.database.session_factory() as session:
            add_event(
                session,
                scan_id,
                normalized_type,
                message,
                {
                    "task_id": task_id,
                    **(data or {}),
                },
            )
            session.commit()

    def _record_agent_runtime_event(
        self,
        scan_id: str,
        task_id: str,
        event: AgentRuntimeEvent,
        *,
        phase: str,
        round_index: int,
        agent_backend: str,
    ) -> bool:
        """Project one protocol event once, even after spool recovery or reconnect."""

        record_key = event.protocol_record_key
        stream_id = event.protocol_stream_id
        session_id = event.session_id
        normalized_type = (
            event.event_type
            if event.event_type.startswith("exploration.")
            else f"exploration.{event.event_type}"
        )
        event_data = {
            "task_id": task_id,
            "source": "sdk",
            "phase": phase,
            "round_index": round_index,
            "agent_backend": agent_backend,
            "session_id": session_id,
            "protocol_stream_id": stream_id,
            "worker_sequence": event.worker_sequence,
            "delivery_source": event.delivery_source,
            **event.data,
        }
        with self.database.session_factory() as session:
            if record_key and stream_id and session_id:
                existing = session.scalar(
                    select(AgentRuntimeEventRecord.id).where(
                        AgentRuntimeEventRecord.record_key == record_key
                    )
                )
                if existing is not None:
                    return False
                session.add(
                    AgentRuntimeEventRecord(
                        scan_id=scan_id,
                        task_id=task_id,
                        session_id=session_id,
                        protocol_stream_id=stream_id,
                        worker_sequence=event.worker_sequence,
                        record_key=record_key,
                        event_type=event.event_type,
                        message=event.message,
                        data=event.data,
                        delivery_source=event.delivery_source,
                    )
                )
            add_event(
                session,
                scan_id,
                normalized_type,
                event.message,
                event_data,
            )
            session.commit()
        return True

    async def submit(self, scan_id: str) -> None:
        if self._shutting_down.is_set():
            return
        async with self._running_lock:
            if scan_id in self._running:
                self._resubmit_requested.add(scan_id)
                return
            self._running.add(scan_id)
        try:
            while True:
                async with self._running_lock:
                    self._resubmit_requested.discard(scan_id)
                await asyncio.to_thread(self._run_sync, scan_id)
                async with self._running_lock:
                    if scan_id in self._resubmit_requested:
                        continue
                    self._running.discard(scan_id)
                    return
        finally:
            async with self._running_lock:
                self._running.discard(scan_id)
                self._resubmit_requested.discard(scan_id)

    async def ensure_scan_running(self, scan_id: str) -> None:
        """Resume a persisted scan without requesting a duplicate pass."""
        async with self._running_lock:
            if scan_id in self._running:
                return
        await self.submit(scan_id)

    def shutdown(self) -> None:
        """Cancel active orchestration and terminate owned subprocess groups."""
        self._shutting_down.set()
        with self._task_cancellations_lock:
            cancellations = list(self._task_cancellations.values())
        for cancellation in cancellations:
            cancellation.set()
        proof_server = self._live_proof_server
        if proof_server is not None:
            proof_server.shutdown()
            proof_server.server_close()
        self.codex.shutdown()
        self.runner.shutdown()

    def recover_interrupted_device_tasks(self) -> None:
        """Normalize transient single-device states after a control-plane restart."""
        recovered_at = now()
        with self.database.session_factory() as session:
            tasks = list(
                session.scalars(
                    select(InvestigationTask)
                    .join(Scan, Scan.id == InvestigationTask.scan_id)
                    .where(
                        Scan.status.in_(
                            {
                                ScanStatus.QUEUED.value,
                                ScanStatus.STATIC_RUNNING.value,
                                ScanStatus.STATIC_COMPLETE.value,
                                ScanStatus.INVESTIGATING.value,
                                ScanStatus.PRELIMINARY_READY.value,
                            }
                        ),
                        InvestigationTask.status.in_(
                            {
                                TaskStatus.AWAITING_DEVICE.value,
                                TaskStatus.RUNNING.value,
                                TaskStatus.CANCEL_REQUESTED.value,
                            }
                        ),
                    )
                )
            )
            for task in tasks:
                previous_status = task.status
                if previous_status == TaskStatus.AWAITING_DEVICE.value:
                    task.status = TaskStatus.QUEUED.value
                    task.error = "服务重启后已重新进入云真机队列"
                    queue_data = dict((task.result or {}).get("device_queue") or {})
                    task.result = {
                        **dict(task.result or {}),
                        "device_queue": {
                            **queue_data,
                            "recovered_at": recovered_at.isoformat(),
                        },
                    }
                    event_type = "task.device_requeued"
                    message = "服务重启，等待云真机的任务已安全重新入队"
                elif previous_status == TaskStatus.CANCEL_REQUESTED.value:
                    task.status = TaskStatus.CANCELED.value
                    task.error = "服务重启时确认了停止请求"
                    task.completed_at = recovered_at
                    task.result = {
                        **dict(task.result or {}),
                        "cancellation": {
                            **dict((task.result or {}).get("cancellation") or {}),
                            "acknowledged": True,
                            "completed_at": recovered_at.isoformat(),
                            "recovered_after_restart": True,
                        },
                    }
                    event_type = "task.cancelled"
                    message = "服务重启后确认任务已停止"
                else:
                    queue_data = dict((task.result or {}).get("device_queue") or {})
                    device_session_active = bool(
                        queue_data.get("acquired_at") and not queue_data.get("released_at")
                    )
                    if not device_session_active:
                        task.status = TaskStatus.QUEUED.value
                        task.error = "服务重启中断了 Agent/平台计算阶段，任务已安全重新排队"
                        task.started_at = None
                        task.completed_at = None
                        task.result = {
                            **dict(task.result or {}),
                            "worker_recovery": {
                                "requeued_at": recovered_at.isoformat(),
                                "reason": "interrupted_outside_device_session",
                            },
                        }
                        event_type = "task.worker_requeued"
                        message = "服务重启发生在设备租约之外，入口探索任务已安全重新排队"
                        add_event(
                            session,
                            task.scan_id,
                            event_type,
                            message,
                            {
                                "task_id": task.id,
                                "previous_status": previous_status,
                                "status": task.status,
                            },
                        )
                        continue
                    prior_gaps = (task.result or {}).get("coverage_gaps")
                    if not isinstance(prior_gaps, list):
                        prior_gaps = []
                    task.status = TaskStatus.INCONCLUSIVE.value
                    task.error = "控制面在设备会话中重启；为避免重复副作用，需要人工重试"
                    task.completed_at = recovered_at
                    task.result = {
                        **dict(task.result or {}),
                        "device_queue": {
                            **queue_data,
                            "interrupted_at": recovered_at.isoformat(),
                        },
                        "coverage_gaps": [
                            *prior_gaps,
                            "Device session was interrupted by a control-plane restart.",
                        ],
                    }
                    coverage = list(
                        session.scalars(
                            select(CoverageItem).where(
                                CoverageItem.scan_id == task.scan_id,
                                CoverageItem.entry_point_id.in_(task.target_entry_ids),
                            )
                        )
                    )
                    for item in coverage:
                        item.status = "partial"
                        item.gap_reason = "控制面在云真机会话中重启，需要人工重试该入口。"
                        item.stages = {
                            **item.stages,
                            "deterministic_dynamic": "interrupted",
                            "agent": "interrupted",
                        }
                    event_type = "task.device_interrupted"
                    message = "设备会话因服务重启中断，任务已标记为证据不足"
                add_event(
                    session,
                    task.scan_id,
                    event_type,
                    message,
                    {
                        "task_id": task.id,
                        "previous_status": previous_status,
                        "status": task.status,
                    },
                )
            session.commit()

    def _ensure_scan_container_record(self, scan_id: str) -> None:
        if not self.settings.codex_enabled or self.settings.codex_isolation != "docker":
            return
        container_key = f"{scan_id}:scan-container"
        with self.database.session_factory() as session:
            record = session.scalar(
                select(ScanContainerRecord).where(
                    ScanContainerRecord.container_key == container_key
                )
            )
            if record is None:
                record = ScanContainerRecord(
                    scan_id=scan_id,
                    container_key=container_key,
                    isolation="docker",
                    status="prepared",
                    metadata_json={"session_workspaces": {}},
                )
                session.add(record)
            else:
                record.status = "prepared"
                record.completed_at = None
            session.commit()

    def _close_scan_container_record(self, scan_id: str) -> None:
        with self.database.session_factory() as session:
            record = session.scalar(
                select(ScanContainerRecord).where(
                    ScanContainerRecord.container_key == f"{scan_id}:scan-container"
                )
            )
            if record is None:
                return
            scan = session.get(Scan, scan_id)
            record.status = "failed" if scan is not None and scan.status == "failed" else "closed"
            record.completed_at = now()
            session.execute(
                update(AgentSessionRecord)
                .where(
                    AgentSessionRecord.scan_id == scan_id,
                    AgentSessionRecord.status.in_({"active", "idle"}),
                )
                .values(status=record.status, completed_at=record.completed_at)
            )
            session.commit()

    def _run_sync(self, scan_id: str) -> None:
        self._ensure_scan_container_record(scan_id)
        try:
            self._run_static(scan_id)
            task_outcome = self._run_tasks(scan_id)
            if task_outcome == "shutdown":
                return
            execution_state = self._wait_for_scan_execution(scan_id)
            if execution_state == "shutdown":
                return
            if execution_state not in {"stopping", "stopped"}:
                self._run_adaptive_verifier(scan_id)
            if self._shutting_down.is_set():
                return
            self._finish(scan_id)
        except Exception as exc:
            with self.database.session_factory() as session:
                scan = session.get(Scan, scan_id)
                if scan:
                    failed_at = now()
                    scan.status = ScanStatus.FAILED.value
                    scan.error = str(exc)
                    scan.completed_at = failed_at
                    interrupted = list(
                        session.scalars(
                            select(InvestigationTask).where(
                                InvestigationTask.scan_id == scan_id,
                                InvestigationTask.status.in_(
                                    {
                                        TaskStatus.QUEUED.value,
                                        TaskStatus.AWAITING_DEVICE.value,
                                        TaskStatus.RUNNING.value,
                                        TaskStatus.CANCEL_REQUESTED.value,
                                    }
                                ),
                            )
                        )
                    )
                    for task in interrupted:
                        cancellation_requested = task.status == TaskStatus.CANCEL_REQUESTED.value
                        task.status = (
                            TaskStatus.CANCELED.value
                            if cancellation_requested
                            else TaskStatus.FAILED.value
                        )
                        task.error = (
                            "停止请求在扫描异常退出时已确认"
                            if cancellation_requested
                            else f"scan execution failed: {exc}"
                        )
                        task.completed_at = failed_at
                        task.result = {
                            **dict(task.result or {}),
                            "scan_failure": {
                                "error": str(exc),
                                "failed_at": failed_at.isoformat(),
                            },
                        }
                    add_event(session, scan_id, "scan.failed", "Scan failed", {"error": str(exc)})
                    session.commit()
        finally:
            self.codex.close_scan(scan_id)
            self._close_scan_container_record(scan_id)

    def _run_static(self, scan_id: str) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise LookupError(f"unknown scan {scan_id}")
            if scan.status in {
                ScanStatus.STATIC_COMPLETE.value,
                ScanStatus.PRELIMINARY_READY.value,
                ScanStatus.INVESTIGATING.value,
                ScanStatus.FINAL.value,
            }:
                return
            scan.status = ScanStatus.STATIC_RUNNING.value
            add_event(session, scan_id, "static.started", "Static analysis started")
            session.commit()

        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            created_at = scan.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            preliminary_deadline = created_at + timedelta(
                seconds=self.settings.preliminary_after_seconds
            )
            preliminary_remaining = max(
                1, int((preliminary_deadline - datetime.now(UTC)).total_seconds())
            )
            preliminary_budget = TimeBudget.from_seconds(preliminary_remaining)
            phase_labels = {
                "static_cache": "静态缓存恢复",
                "static_cache_publish": "静态缓存发布",
                "decompilation": "APK 解包与反编译",
                "code_index": "组件代码索引",
                "android_attack_chains": "Android 攻击链索引",
                "native_analysis": "Native/JNI 资产分析",
                "embedded_artifacts": "内嵌 APK 与插件链",
                "rule_evaluation": "静态规则评估",
                "target_profile": "目标审计 Profile 规划",
                "asc_xrefs": "ASC 字节码交叉引用",
            }
            static_phase_started: dict[str, float] = {}

            def record_static_phase(
                phase: str,
                status: str,
                details: dict[str, Any] | None = None,
            ) -> None:
                label = phase_labels.get(phase, phase)
                payload = dict(details or {})
                if status == "started":
                    static_phase_started[phase] = time.monotonic()
                elif phase in static_phase_started and "elapsed_seconds" not in payload:
                    payload["elapsed_seconds"] = round(
                        time.monotonic() - static_phase_started[phase],
                        3,
                    )
                payload.update({"phase": phase, "status": status})
                scan.stats = {
                    **dict(scan.stats or {}),
                    "static_progress": {
                        "phase": phase,
                        "label": label,
                        "status": status,
                        **(
                            {"elapsed_seconds": payload["elapsed_seconds"]}
                            if payload.get("elapsed_seconds") is not None
                            else {}
                        ),
                    },
                }
                add_event(
                    session,
                    scan.id,
                    f"static.phase.{status}",
                    f"{label}{'开始' if status == 'started' else '完成'}",
                    payload,
                )
                session.commit()

            result = self.inspector.inspect(
                Path(scan.artifact_path),
                scan.id,
                preliminary_budget,
                _progress=record_static_phase,
            )
            record_static_phase("rule_evaluation", "started")
            findings, coverage = self.rules.evaluate(result)
            record_static_phase(
                "rule_evaluation",
                "completed",
                {"finding_count": len(findings)},
            )
            record_static_phase("target_profile", "started")
            static_review_surfaces = self.rules.static_review_surfaces(
                result.manifest,
                findings,
            )
            static_review_surfaces.extend(self.rules.embedded_artifact_review_surfaces(result))
            static_review_surfaces.extend(target_review_surfaces(result))
            for surface in static_review_surfaces:
                if surface.investigation_group is None:
                    surface.investigation_group = investigation_group(
                        package_name=result.manifest.package_name,
                        name=surface.name,
                        owner_component=surface.name,
                        static_family=surface.family,
                        artifact=surface.artifact,
                    )
            record_static_phase(
                "target_profile",
                "completed",
                {
                    "profile": active_profile_id(result.manifest.package_name),
                    "surface_count": len(static_review_surfaces),
                },
            )
            for surface in static_review_surfaces:
                self.inspector.add_static_surface_to_code_index(
                    result,
                    surface_name=surface.name,
                    locations=surface.locations,
                    attack_chains=surface.attack_chains,
                    package_name=(
                        str(surface.artifact.get("package_name"))
                        if surface.artifact and surface.artifact.get("package_name")
                        else None
                    ),
                )
                for finding in findings:
                    if (
                        finding.rule_id in surface.rule_ids
                        and surface.name not in finding.entry_names
                    ):
                        finding.entry_names.append(surface.name)
            if static_review_surfaces:
                self.inspector.persist_code_index(result)
            scan.package_name = result.manifest.package_name
            scan.version_name = result.manifest.version_name
            scan.version_code = result.manifest.version_code
            scan.min_sdk = result.manifest.min_sdk
            scan.target_sdk = result.manifest.target_sdk
            scan.signing = result.signing
            scan.tool_versions = result.tool_versions
            scan.stats = {
                **scan.stats,
                **result.file_inventory,
                "workspace": str(result.workspace),
                "static_finding_count": len(findings),
                "attack_chain_inventory": {
                    "total": len(result.attack_chains),
                    "review_required": sum(
                        item.get("review_required") is not False for item in result.attack_chains
                    ),
                    "families": dict(
                        Counter(
                            str(item.get("family") or "unknown") for item in result.attack_chains
                        )
                    ),
                    "kinds": dict(
                        Counter(
                            str(item.get("chain_kind") or "unknown")
                            for item in result.attack_chains
                        )
                    ),
                    "engine_versions": sorted(
                        {
                            str(item.get("engine_version"))
                            for item in result.attack_chains
                            if item.get("engine_version")
                        }
                    ),
                },
                "preliminary_deadline": preliminary_deadline.isoformat(),
                "target_audit_profile": active_profile_id(result.manifest.package_name),
                "decompilation": {
                    key: value
                    for key, value in result.decompilation.items()
                    if key != "failed_classes"
                },
            }
            entries: list[EntryPoint] = []
            for parsed in result.manifest.entries:
                code_context = result.code_index.get(
                    parsed.owner_component or parsed.name,
                    {},
                )
                public_anchors = [
                    {key: value for key, value in anchor.items() if key != "content"}
                    for anchor in code_context.get("anchors", [])
                    if isinstance(anchor, dict)
                ]
                profile_group = investigation_group(
                    package_name=result.manifest.package_name,
                    name=parsed.name,
                    owner_component=parsed.owner_component,
                )
                entry = EntryPoint(
                    scan_id=scan.id,
                    kind=parsed.kind,
                    name=parsed.name,
                    owner_component=parsed.owner_component,
                    exported=parsed.exported,
                    exported_reason=parsed.exported_reason,
                    permission=parsed.permission,
                    permission_protection=parsed.permission_protection,
                    intent_filters=parsed.intent_filters,
                    deep_links=parsed.deep_links,
                    code_anchors=public_anchors,
                    metadata_json={
                        **parsed.metadata,
                        **(
                            {"investigation_group": profile_group}
                            if profile_group is not None
                            else {}
                        ),
                        "decompilation": {
                            "status": code_context.get("status", "source_not_found"),
                            "target_in_jadx_failure_list": bool(
                                code_context.get("target_in_jadx_failure_list")
                            ),
                            "target_source_has_decompiler_errors": bool(
                                code_context.get("target_source_has_decompiler_errors")
                            ),
                            "global_status": code_context.get(
                                "global_decompilation_status",
                                result.decompilation.get("status"),
                            ),
                        },
                    },
                )
                session.add(entry)
                entries.append(entry)
            for surface in static_review_surfaces:
                code_context = result.code_index.get(surface.name, {})
                public_anchors = [
                    {key: value for key, value in anchor.items() if key != "content"}
                    for anchor in code_context.get("anchors", [])
                    if isinstance(anchor, dict)
                ]
                entry = EntryPoint(
                    scan_id=scan.id,
                    kind=EntryPointKind.STATIC_SURFACE.value,
                    name=surface.name,
                    owner_component=surface.name,
                    exported=False,
                    exported_reason="static_semantic_seed",
                    permission=None,
                    permission_protection=None,
                    intent_filters=[],
                    deep_links=[],
                    code_anchors=public_anchors,
                    metadata_json={
                        "effective_enabled": True,
                        "direct_invocation_applicable": False,
                        "static_review_family": surface.family,
                        "static_review_title": surface.title,
                        "static_review_severity": surface.severity,
                        "static_review_priority": surface.priority,
                        "static_review_rule_ids": surface.rule_ids,
                        "static_review_hypotheses": surface.hypotheses,
                        "static_review_locations": surface.locations,
                        "static_review_attack_chains": surface.attack_chains,
                        "static_review_artifact": surface.artifact,
                        "static_review_rollup": surface.rollup,
                        **(
                            {"static_review_site": surface.site}
                            if surface.site is not None
                            else {}
                        ),
                        **(
                            {"static_review_parent_surface": surface.parent_surface}
                            if surface.parent_surface
                            else {}
                        ),
                        **(
                            {"investigation_group": surface.investigation_group}
                            if surface.investigation_group is not None
                            else {}
                        ),
                        "decompilation": {
                            "status": code_context.get(
                                "status",
                                "source_not_found",
                            ),
                            "global_status": code_context.get(
                                "global_decompilation_status",
                                result.decompilation.get("status"),
                            ),
                        },
                    },
                )
                session.add(entry)
                entries.append(entry)
            session.flush()
            threat_model = build_android_threat_model(scan, entries)
            scan.stats = {
                **scan.stats,
                "threat_model": threat_model,
            }
            entry_ids_by_name: dict[str, list[str]] = defaultdict(list)
            for entry in entries:
                entry_ids_by_name[entry.name].append(entry.id)
            persisted_findings: list[Finding] = []
            for draft in findings:
                entry_ids = [
                    entry_id
                    for name in draft.entry_names
                    for entry_id in entry_ids_by_name.get(name, [])
                ]
                identity = finding_identity(
                    scan=scan,
                    rule_id=draft.rule_id,
                    category="static_signal",
                    entry_names=[
                        *draft.entry_names,
                        *[
                            str(location[key])
                            for location in draft.locations
                            for key in ("component", "path")
                            if location.get(key)
                        ],
                    ],
                    claim=draft.title,
                )
                persisted_finding = Finding(
                    scan_id=scan.id,
                    dedupe_key=draft.dedupe_key,
                    rule_id=draft.rule_id,
                    source=draft.source,
                    title=draft.title,
                    description=draft.description,
                    remediation=draft.remediation,
                    masvs=draft.masvs,
                    cwe=draft.cwe,
                    severity=draft.severity,
                    confidence=draft.confidence,
                    status=FindingStatus.CANDIDATE.value,
                    entry_point_ids=entry_ids,
                    locations=draft.locations,
                    metadata_json={**draft.metadata, "identity": identity},
                )
                session.add(persisted_finding)
                persisted_findings.append(persisted_finding)
            for item in coverage:
                session.add(
                    CoverageItem(
                        scan_id=scan.id,
                        control_id=item.control_id,
                        domain=item.domain,
                        title=item.title,
                        status=item.status,
                        stages=item.stages,
                        gap_reason=item.gap_reason,
                    )
                )
            entry_coverage: dict[str, CoverageItem] = {}
            for entry in entries:
                coverage_item = CoverageItem(
                    scan_id=scan.id,
                    control_id=f"ENTRY-{entry.id}",
                    domain="MASVS-PLATFORM",
                    title=f"Entry point: {entry.name}",
                    status=CoverageStatus.PARTIAL.value,
                    stages={
                        "static": "completed",
                        "deterministic_dynamic": "pending",
                        "agent": "pending",
                        "blackbox": "pending",
                    },
                    gap_reason="Dynamic and semantic investigation pending.",
                    entry_point_id=entry.id,
                )
                session.add(coverage_item)
                entry_coverage[entry.id] = coverage_item
            for tool, payload in result.tool_results.items():
                decompilation = (
                    {
                        key: value
                        for key, value in dict(payload.get("decompilation") or {}).items()
                        if key != "failed_classes"
                    }
                    if tool == "jadx"
                    else {}
                )
                timed_out = payload.get("timed_out") is True
                exit_code = payload.get("exit_code")
                output_usable = (
                    decompilation.get("output_usable") is True
                    if tool == "jadx"
                    else exit_code == 0 and not timed_out
                )
                tool_status = (
                    str(decompilation.get("status") or "unknown")
                    if tool == "jadx"
                    else "timed_out"
                    if timed_out
                    else "succeeded"
                    if exit_code == 0
                    else "tool_failed"
                )
                metadata = {
                    **decompilation,
                    "static_output_usable": output_usable,
                    "static_tool_status": tool_status,
                    "static_tool_timed_out": timed_out,
                    "static_tool_exit_code": exit_code,
                }
                self.evidence.json(
                    session,
                    scan_id=scan.id,
                    task_id=None,
                    kind=f"static.{tool}",
                    value=payload,
                    summary=self._static_tool_evidence_summary(tool, payload),
                    metadata=metadata,
                )
            self._run_asc_xrefs(
                session,
                scan,
                entries,
                preliminary_budget,
                progress=record_static_phase,
            )
            planner = InvestigationPlanner(
                android_version=self.settings.device_android_version,
                android_api=self.settings.device_android_api,
                adb_configured=self.device_pool.configured,
                device_reset_policy=self.settings.device_reset_policy,
                max_standalone_chain_sites=self.settings.max_standalone_chain_sites,
            )
            investigation_plan = planner.plan_with_decisions(scan.id, entries)
            tasks = investigation_plan.tasks
            static_closures = investigation_plan.static_closures
            coalescing_decisions = investigation_plan.coalescing_decisions
            closures_by_entry = {closure.entry_point_id: closure for closure in static_closures}
            for entry_id, closure in closures_by_entry.items():
                coverage_item = entry_coverage[entry_id]
                coverage_item.status = CoverageStatus.COVERED.value
                coverage_item.stages = {
                    "static": "completed",
                    "deterministic_dynamic": "not_applicable",
                    "agent": "not_applicable",
                    "blackbox": "not_applicable",
                    "indirect_chain": "retained_for_scan_wide_seed_exploration",
                }
                coverage_item.gap_reason = closure.reason
            for finding in persisted_findings:
                self._annotate_direct_reachability(
                    finding,
                    closures_by_entry,
                )
            session.add_all(tasks)
            session.flush()
            security_snapshot = self.security_evolution.build_snapshot(
                session,
                scan=scan,
                entries=entries,
                code_index=result.code_index,
            )
            fresh_run = (scan.stats or {}).get("fresh_run")
            isolated_fresh_run = isinstance(fresh_run, dict) and fresh_run.get("mode") == "isolated"
            if isolated_fresh_run:
                version_diff = None
                pattern_matches = []
                add_event(
                    session,
                    scan.id,
                    "planning.fresh_run.isolated",
                    "本轮为独立全新扫描，已禁用历史 PoC 回放与 Finding 模式卡注入",
                    {
                        "source_scan_id": fresh_run.get("source_scan_id"),
                        "reuse_apk_only": True,
                    },
                )
            else:
                version_diff = self.security_evolution.build_version_diff(
                    session,
                    scan=scan,
                    snapshot=security_snapshot,
                )
                pattern_matches = self.security_evolution.apply_diff_and_patterns(
                    session,
                    scan=scan,
                    entries=entries,
                    tasks=tasks,
                    diff=version_diff,
                )
            for replay_task in (task for task in tasks if task.task_type == "version_replay"):
                for entry_id in replay_task.target_entry_ids:
                    coverage_item = entry_coverage.get(entry_id)
                    if coverage_item is None:
                        continue
                    coverage_item.status = CoverageStatus.PARTIAL.value
                    coverage_item.stages = {
                        **dict(coverage_item.stages or {}),
                        "deterministic_dynamic": "pending",
                        "agent": "pending",
                        "blackbox": "pending",
                        "version_replay": "pending",
                        "indirect_chain": ("retained_for_scan_wide_seed_exploration"),
                    }
                    coverage_item.gap_reason = (
                        "普通应用直接入口已静态阻断；历史漏洞 PoC 仍需在"
                        "当前版本回放，以验证修复并防止回归。"
                    )
            self.security_evolution.record_static_events(
                session,
                scan_id=scan.id,
                snapshot=security_snapshot,
                diff=version_diff,
                pattern_matches=pattern_matches,
            )
            if static_closures:
                add_event(
                    session,
                    scan.id,
                    "planning.static_closed",
                    f"{len(static_closures)} 个入口的普通应用直接调用路径已静态判定为阻断",
                    {
                        "count": len(static_closures),
                        "threat_model": "ordinary_app_uid",
                        "scope": "direct_invocation_only",
                        "indirect_chain_targets_retained": True,
                        "decisions": [closure.as_dict() for closure in static_closures[:200]],
                        "truncated": len(static_closures) > 200,
                    },
                )
            if coalescing_decisions:
                avoided_task_count = sum(
                    int(item.get("avoided_task_count") or 0) for item in coalescing_decisions
                )
                add_event(
                    session,
                    scan.id,
                    "planning.tasks.coalesced",
                    f"同一攻击链的入口变体已归并，避免 {avoided_task_count} 个重复调查任务",
                    {
                        "profile": active_profile_id(result.manifest.package_name),
                        "group_count": len(coalescing_decisions),
                        "avoided_task_count": avoided_task_count,
                        "decisions": coalescing_decisions,
                    },
                )
            scan.status = ScanStatus.PRELIMINARY_READY.value
            scan.preliminary_at = now()
            dispatched_entry_ids = {
                entry_id for task in tasks for entry_id in task.target_entry_ids
            }
            scan.stats = {
                **scan.stats,
                "entry_point_count": len(entries),
                "task_count": len(tasks),
                "planning_raw_task_count": len(tasks)
                + sum(int(item.get("avoided_task_count") or 0) for item in coalescing_decisions),
                "coalesced_task_count": sum(
                    int(item.get("avoided_task_count") or 0) for item in coalescing_decisions
                ),
                "coalescing_group_count": len(coalescing_decisions),
                "static_closed_entry_count": len(static_closures),
                "agent_dispatched_entry_count": len(dispatched_entry_ids),
                "security_snapshot_hash": security_snapshot.snapshot_hash,
                "version_diff_id": version_diff.id if version_diff else None,
                "version_replay_candidate_count": (
                    len(version_diff.replay_candidates) if version_diff else 0
                ),
                "pattern_match_count": len(pattern_matches),
                "chain_site_count": investigation_plan.chain_site_total,
                "chain_site_dispatched_count": investigation_plan.chain_site_dispatched,
                "chain_site_merged_into_component_count": (
                    investigation_plan.chain_site_merged_into_component
                ),
                "chain_site_deferred_count": investigation_plan.chain_site_deferred,
            }
            if scan.preliminary_at > preliminary_deadline:
                late_by = int((scan.preliminary_at - preliminary_deadline).total_seconds())
                scan.stats = {**scan.stats, "preliminary_sla_late_seconds": late_by}
                add_event(
                    session,
                    scan.id,
                    "scan.preliminary_sla_missed",
                    "Preliminary-report deadline was missed",
                    {"late_seconds": late_by},
                )
            add_event(
                session,
                scan.id,
                "static.completed",
                "Static analysis and attack-surface planning completed",
                {
                    "entries": len(entries),
                    "findings": len(findings),
                    "tasks": len(tasks),
                    "static_closed_entries": len(static_closures),
                },
            )
            add_event(
                session,
                scan.id,
                "scan.preliminary_ready",
                "Preliminary report is ready; investigations may continue",
            )
            session.commit()

    def _run_tasks(self, scan_id: str) -> str:
        adb_concurrency = self.device_pool.capacity
        initial_concurrency = self._current_investigation_concurrency()
        self._apply_investigation_admission(scan_id, initial_concurrency)
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            scan.stats = {
                **dict(scan.stats or {}),
                "execution_policy": {
                    "concurrency_policy": "device_bound_phase_admission",
                    "concurrency_basis": (
                        "device_pool_capacity" if adb_concurrency else "analysis_slots"
                    ),
                    "investigation_concurrency_at_start": initial_concurrency,
                    "adb_concurrency": adb_concurrency,
                    "analysis_slots": self.settings.agent_analysis_slots,
                    "effective_analysis_slots": self._analysis_slots.limit,
                    "max_investigation_concurrency": (
                        self.settings.max_investigation_concurrency
                    ),
                    "build_slots": self.settings.poc_build_slots,
                    "device_slots": adb_concurrency,
                    "device_ownership": "dynamic_execution_phase",
                    "agent_workspace_scope": "task_attempt",
                },
            }
            add_event(
                session,
                scan_id,
                "investigation.pool.started",
                (
                    f"设备绑定探索池已启动：{adb_concurrency} 台 ADB 设备对应 "
                    f"{initial_concurrency} 路并发调查任务"
                    if adb_concurrency
                    else "资源感知探索池已启动：先运行无设备分析，设备接入后执行证明"
                ),
                {
                    "concurrency_policy": "device_bound_phase_admission",
                    "investigation_concurrency": initial_concurrency,
                    "adb_concurrency": adb_concurrency,
                    "analysis_slots": self.settings.agent_analysis_slots,
                    "build_slots": self.settings.poc_build_slots,
                    "device_serials": list(self.device_pool.serials),
                    "device_ownership": "dynamic_execution_phase",
                },
            )
            session.commit()
            task_count = len(
                list(
                    session.scalars(
                        select(InvestigationTask.id).where(
                            InvestigationTask.scan_id == scan_id,
                            InvestigationTask.status == TaskStatus.QUEUED.value,
                            InvestigationTask.task_type != TaskType.ADAPTIVE_VERIFICATION.value,
                        )
                    )
                )
            )
        futures: set[Future[None]] = set()
        with ThreadPoolExecutor(
            # The executor is only a thread container. Admission follows the live
            # device pool; build and device stages acquire their own
            # process-wide resource tokens.
            max_workers=max(1, task_count),
            thread_name_prefix="investigation",
        ) as executor:
            try:
                while True:
                    if self._shutting_down.is_set():
                        return "shutdown"
                    execution_state = self._scan_execution_state(scan_id)
                    if execution_state in {"stopping", "stopped"}:
                        self.stop_scan_tasks(scan_id)
                    elif execution_state == "running":
                        desired_concurrency = self._current_investigation_concurrency()
                        self._apply_investigation_admission(scan_id, desired_concurrency)
                        while len(futures) < desired_concurrency:
                            if not self._has_queued_tasks(scan_id):
                                break
                            claimed = self._claim_next_task(scan_id)
                            if claimed is None:
                                break
                            task_id, timeout_seconds = claimed
                            futures.add(
                                executor.submit(
                                    self._run_claimed_task,
                                    scan_id,
                                    task_id,
                                    timeout_seconds,
                                )
                            )
                    if not futures:
                        if execution_state in {"stopping", "stopped"}:
                            return execution_state
                        if not self._has_queued_tasks(scan_id):
                            return "completed"
                        # A paused scan intentionally keeps its queued rows untouched.
                        # Polling lets pause/resume survive service restarts without an
                        # in-memory-only control object.
                        self._shutting_down.wait(0.5)
                        continue
                    completed, futures = wait(
                        futures,
                        timeout=0.5,
                        return_when=FIRST_COMPLETED,
                    )
                    for future in completed:
                        future.result()
            finally:
                self._release_investigation_admission(scan_id)

    @staticmethod
    def _execution_state_from_stats(stats: dict[str, Any] | None) -> str:
        control = (stats or {}).get("execution_control")
        state = str(control.get("state") or "running") if isinstance(control, dict) else "running"
        return state if state in {"running", "paused", "stopping", "stopped"} else "running"

    def _scan_execution_state(self, scan_id: str) -> str:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return "stopping"
            return self._execution_state_from_stats(dict(scan.stats or {}))

    def _wait_for_scan_execution(self, scan_id: str) -> str:
        while True:
            if self._shutting_down.is_set():
                return "shutdown"
            state = self._scan_execution_state(scan_id)
            if state != "paused":
                return state
            self._shutting_down.wait(0.5)

    def _current_investigation_concurrency(self) -> int:
        """Admit one concurrent investigation task per connected ADB device.

        The pool capacity is re-read on every admission decision, so plugging an
        extra device mid-scan widens the pool without a restart.  The result stays
        bounded by the global Codex worker-session budget and by
        ``max_investigation_concurrency``; with no device attached the analysis
        slots keep desktop-only scans pipelined.  Device execution itself stays
        leased per device, so a task never shares a phone.
        """
        device_capacity = self.device_pool.capacity
        if device_capacity > 0:
            return max(
                1,
                min(
                    device_capacity,
                    self.settings.max_investigation_concurrency,
                    self.settings.codex_max_sessions,
                ),
            )
        return max(
            1,
            min(
                self.settings.agent_analysis_slots,
                self.settings.codex_max_sessions_per_scan,
            ),
        )

    def _publish_analysis_limit(self, widest: int) -> int:
        """Size the process-wide analysis token to the current admission target.

        The token bounds concurrent Agent investigations across all scans.  It must
        equal the device-bound target when tasks are admitted: an
        ``agent_analysis_slots`` floor here let one phone run several concurrent
        investigations, which is exactly the over-subscription this bound exists to
        prevent.  ``agent_analysis_slots`` only sizes the idle/desktop-only pool.
        """

        if widest > 0:
            return self._analysis_slots.set_limit(widest)
        return self._analysis_slots.set_limit(max(1, self.settings.agent_analysis_slots))

    def _apply_investigation_admission(self, scan_id: str, desired: int) -> int:
        """Publish one admission decision to the shared analysis and session pools.

        The analysis token is process-wide, so it follows the widest target among
        the scans currently admitting tasks; the per-scan Codex session ceiling is
        published per scan.
        """
        with self._admission_lock:
            self._admission_targets[scan_id] = desired
            widest = max(self._admission_targets.values())
        analysis_limit = self._publish_analysis_limit(widest)
        self.codex.set_scan_session_limit(
            scan_id,
            max(desired, self.settings.codex_max_sessions_per_scan),
        )
        return analysis_limit

    def _release_investigation_admission(self, scan_id: str) -> None:
        """Drop a finished scan from the shared pools and shrink the token again."""
        with self._admission_lock:
            self._admission_targets.pop(scan_id, None)
            widest = max(self._admission_targets.values(), default=0)
        self._publish_analysis_limit(widest)
        self.codex.set_scan_session_limit(scan_id, None)

    @staticmethod
    def _default_execution_dag() -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "nodes": {
                "seed_analysis": {
                    "status": "pending",
                    "depends_on": [],
                    "resources": ["analysis"],
                },
                "adversarial_review": {
                    "status": "optional",
                    "depends_on": ["seed_analysis"],
                    "resources": ["analysis"],
                },
                "rescue_review": {
                    "status": "optional",
                    "depends_on": ["seed_analysis"],
                    "resources": ["analysis"],
                },
                "poc_build": {
                    "status": "pending",
                    "depends_on": ["seed_analysis"],
                    "resources": ["build"],
                },
                "device_execution": {
                    "status": "pending",
                    "depends_on": ["poc_build"],
                    "resources": ["device"],
                },
                "adaptive_analysis": {
                    "status": "optional",
                    "depends_on": ["device_execution"],
                    "resources": ["analysis"],
                },
                "impact_evaluation": {
                    "status": "pending",
                    "depends_on": ["device_execution", "adaptive_analysis"],
                    "resources": ["platform"],
                },
                "final_synthesis": {
                    "status": "pending",
                    "depends_on": ["impact_evaluation"],
                    "resources": ["analysis"],
                },
            },
        }

    @classmethod
    def _ensure_task_execution_dag(cls, task: InvestigationTask) -> dict[str, Any]:
        result = dict(task.result or {})
        dag = result.get("execution_dag")
        if not isinstance(dag, dict) or not isinstance(dag.get("nodes"), dict):
            dag = cls._default_execution_dag()
            result["execution_dag"] = dag
            task.result = result
        return dag

    def _set_task_stage(
        self,
        scan_id: str,
        task_id: str,
        stage: str,
        status: str,
        **metadata: Any,
    ) -> None:
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None or task.scan_id != scan_id:
                return
            dag = deepcopy(self._ensure_task_execution_dag(task))
            nodes = dag["nodes"]
            node = dict(nodes.get(stage) or {})
            node["status"] = status
            if status == "running" and not node.get("started_at"):
                node["started_at"] = now().isoformat()
            if status in {"completed", "failed", "skipped", "inconclusive"}:
                node["completed_at"] = now().isoformat()
            if metadata:
                node["metadata"] = {**dict(node.get("metadata") or {}), **metadata}
            nodes[stage] = node
            dag["current_stage"] = stage
            dag["updated_at"] = now().isoformat()
            task.result = {**dict(task.result or {}), "execution_dag": dag}
            add_event(
                session,
                scan_id,
                "task.stage.updated",
                f"任务阶段 {stage} 更新为 {status}",
                {
                    "task_id": task_id,
                    "stage": stage,
                    "status": status,
                    "resources": node.get("resources", []),
                    **metadata,
                },
            )
            session.commit()

    @staticmethod
    def _scheduler_score(task: InvestigationTask) -> tuple[int, dict[str, int]]:
        text = " ".join(str(value).lower() for value in task.hypotheses or [])
        risk_terms = {
            "token",
            "credential",
            "account",
            "payment",
            "privilege",
            "binder",
            "webview",
            "javascript",
            "file",
        }
        risk = min(18, 3 * sum(term in text for term in risk_terms))
        proof_ready = 20 if (task.preconditions or {}).get("version_replays") else 0
        coalesced = int(bool((task.preconditions or {}).get("coalescing"))) * 4
        created_at = task.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        age_seconds = max(0.0, (now() - created_at).total_seconds())
        aging = min(20, int(age_seconds // 300))
        entry_cost = min(12, max(0, len(task.target_entry_ids or []) - 1))
        breakdown = {
            "base_priority": int(task.priority),
            "risk": risk,
            "proof_readiness": proof_ready,
            "coalescing_value": coalesced,
            "aging": aging,
            "entry_cost": -entry_cost,
        }
        return sum(breakdown.values()), breakdown

    @staticmethod
    def _agent_progress_signature(
        result: AgentInvestigationResult,
        *,
        evidence_summaries: list[dict[str, Any]],
        proven_hypotheses: dict[str, list[str]],
    ) -> str:
        """Hash platform-visible progress, excluding free-form model wording."""

        requested_tests = [
            {
                "hypothesis_id": request.hypothesis_id,
                "entry_point_id": request.entry_point_id,
                "state": request.state,
                "operation": request.operation,
                "extras": request.extras,
                "binder_transaction_code": request.binder_transaction_code,
                "binder_interface_descriptor": request.binder_interface_descriptor,
                "binder_reply_type": request.binder_reply_type,
                "binder_script": (
                    [item.model_dump(mode="json") for item in request.binder_script]
                    if request.binder_script
                    else None
                ),
                "poc": request.poc.model_dump(mode="json") if request.poc else None,
                "oracle": request.oracle.model_dump(mode="json"),
            }
            for request in result.requested_tests
        ]
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
        payload = {
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
            "assessments": sorted(
                assessments,
                key=lambda item: (item["hypothesis_id"], item["verdict"]),
            ),
        }
        return hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def _has_queued_tasks(self, scan_id: str) -> bool:
        with self.database.session_factory() as session:
            return (
                session.scalar(
                    select(InvestigationTask.id)
                    .where(
                        InvestigationTask.scan_id == scan_id,
                        InvestigationTask.status == TaskStatus.QUEUED.value,
                        InvestigationTask.task_type != TaskType.ADAPTIVE_VERIFICATION.value,
                    )
                    .limit(1)
                )
                is not None
            )

    def _run_claimed_task(
        self,
        scan_id: str,
        task_id: str,
        timeout_seconds: int | None,
    ) -> None:
        try:
            self._run_task(scan_id, task_id, timeout_seconds)
        except Exception as exc:
            self._mark_task_worker_failed(scan_id, task_id, exc)

    def _claim_next_task(self, scan_id: str) -> tuple[str, int] | None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            if self._execution_state_from_stats(dict(scan.stats or {})) != "running":
                return None
            queued_tasks = list(
                session.scalars(
                    select(InvestigationTask)
                    .where(
                        InvestigationTask.scan_id == scan_id,
                        InvestigationTask.status == TaskStatus.QUEUED.value,
                        InvestigationTask.task_type != TaskType.ADAPTIVE_VERIFICATION.value,
                    )
                    .order_by(InvestigationTask.created_at)
                )
            )
            scored_tasks = [
                (self._scheduler_score(candidate), candidate) for candidate in queued_tasks
            ]
            task = (
                max(
                    scored_tasks,
                    key=lambda item: (item[0][0], -item[1].created_at.timestamp()),
                )[1]
                if scored_tasks
                else None
            )
            if task is None:
                return None
            score, score_breakdown = self._scheduler_score(task)
            self._ensure_task_execution_dag(task)
            task.result = {
                **dict(task.result or {}),
                "scheduler": {
                    "schema_version": "1.0",
                    "score": score,
                    "score_breakdown": score_breakdown,
                    "admitted_at": now().isoformat(),
                    "policy": "risk_proof_readiness_cost_aging",
                },
            }
            created_at = scan.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            scan_deadline = created_at + timedelta(seconds=self.settings.scan_deadline_seconds)
            task_result = dict(task.result or {})
            manual_dispatch = bool(
                task_result.get("manual_rerun") or task_result.get("manual_continuation")
            )
            remaining = (
                self.settings.task_timeout_seconds
                if manual_dispatch
                else int((scan_deadline - datetime.now(UTC)).total_seconds())
            )
            if remaining <= 0:
                pending_tasks = list(
                    session.scalars(
                        select(InvestigationTask).where(
                            InvestigationTask.scan_id == scan_id,
                            InvestigationTask.status == TaskStatus.QUEUED.value,
                            InvestigationTask.task_type != TaskType.ADAPTIVE_VERIFICATION.value,
                        )
                    )
                )
                for pending in pending_tasks:
                    pending.status = TaskStatus.TIMED_OUT.value
                    pending.error = "whole-scan deadline exhausted before task dispatch"
                    pending.completed_at = now()
                add_event(
                    session,
                    scan_id,
                    "scan.deadline_exhausted",
                    "Whole-scan deadline exhausted; remaining tasks were not dispatched",
                    {"remaining_tasks": len(pending_tasks)},
                )
                session.commit()
                return None
            # Claim before handing work to the executor so the dispatcher cannot
            # submit the same row more than once.
            task.status = TaskStatus.RUNNING.value
            task.started_at = now()
            session.commit()
            return task.id, min(self.settings.task_timeout_seconds, remaining)

    def _mark_task_worker_failed(
        self,
        scan_id: str,
        task_id: str,
        error: Exception,
    ) -> None:
        failed_at = now()
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None:
                return
            if task.status == TaskStatus.CANCEL_REQUESTED.value:
                task.status = TaskStatus.CANCELED.value
                task.error = "停止请求在任务异常退出时已确认"
            elif task.status not in {
                TaskStatus.CANCELED.value,
                TaskStatus.COMPLETED.value,
                TaskStatus.NOT_REPRODUCED.value,
                TaskStatus.INCONCLUSIVE.value,
                TaskStatus.TIMED_OUT.value,
                TaskStatus.FAILED.value,
                TaskStatus.DELETED.value,
            }:
                task.status = TaskStatus.FAILED.value
                task.error = f"investigation worker failed: {error}"
            else:
                return
            task.completed_at = failed_at
            task.result = {
                **dict(task.result or {}),
                "worker_failure": {
                    "error": str(error),
                    "failed_at": failed_at.isoformat(),
                },
            }
            add_event(
                session,
                scan_id,
                "task.failed",
                "并发入口探索 worker 异常退出",
                {"task_id": task_id, "error": str(error)[:2000]},
            )
            session.commit()

    def request_task_cancellation(self, task_id: str) -> bool:
        with self._task_cancellations_lock:
            event = self._task_cancellations.get(task_id)
            if event is None:
                return False
            event.set()
            self.device_pool.wake_waiters()
            return True

    def run_dynamic_experiment(
        self,
        capsule_id: str,
        *,
        preferred_serial: str | None = None,
    ) -> DynamicExperimentCapsule:
        """Run or resume a standalone Capsule and close its bound Proof when terminal."""

        capsule = self.dynamic_experiments.run(
            capsule_id,
            preferred_serial=preferred_serial,
        )
        self._reconcile_dynamic_experiment_proof(capsule)
        return capsule

    def cancel_dynamic_experiment(self, capsule_id: str) -> DynamicExperimentCapsule:
        capsule = self.dynamic_experiments.cancel(capsule_id)
        self._reconcile_dynamic_experiment_proof(capsule)
        return capsule

    def _reconcile_dynamic_experiment_proof(
        self,
        capsule: DynamicExperimentCapsule,
    ) -> None:
        if capsule.status not in {"completed", "canceled", "failed"}:
            return
        proof_attempt_id = (capsule.impact_contract or {}).get("proof_attempt_id")
        if not isinstance(proof_attempt_id, str):
            return
        with self.database.session_factory() as session:
            receipts = list(
                session.scalars(
                    select(DynamicExperimentReceipt)
                    .where(DynamicExperimentReceipt.capsule_id == capsule.id)
                    .order_by(
                        DynamicExperimentReceipt.started_at,
                        DynamicExperimentReceipt.attempt,
                    )
                )
            )
            evidence_ids = list(
                dict.fromkeys(
                    evidence_id for receipt in receipts for evidence_id in receipt.evidence_ids
                )
            )
            evidence_by_id = {
                item.id: item
                for item in session.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids)))
            }
            summaries = [
                self._evidence_summary(evidence_by_id[evidence_id])
                for evidence_id in evidence_ids
                if evidence_id in evidence_by_id
            ]
        self.hypothesis_ledger.complete_proof(
            proof_attempt_id,
            summaries,
            error=(capsule.error if capsule.status in {"canceled", "failed"} else None),
        )

    def stop_scan_tasks(self, scan_id: str) -> dict[str, int]:
        """Stop every unfinished task while preserving completed evidence."""
        requested_at = now()
        requested: list[tuple[str, str]] = []
        active_statuses = {
            TaskStatus.QUEUED.value,
            TaskStatus.AWAITING_DEVICE.value,
            TaskStatus.RUNNING.value,
        }
        with self.database.session_factory() as session:
            tasks = list(
                session.scalars(
                    select(InvestigationTask).where(
                        InvestigationTask.scan_id == scan_id,
                        InvestigationTask.status.in_(active_statuses),
                    )
                )
            )
            for task in tasks:
                previous_status = task.status
                result = {
                    **dict(task.result or {}),
                    "cancellation": {
                        **dict((task.result or {}).get("cancellation") or {}),
                        "requested": True,
                        "acknowledged": False,
                        "requested_at": requested_at.isoformat(),
                        "scope": "scan",
                    },
                }
                transition = session.execute(
                    update(InvestigationTask)
                    .where(
                        InvestigationTask.id == task.id,
                        InvestigationTask.status == previous_status,
                    )
                    .values(
                        status=TaskStatus.CANCEL_REQUESTED.value,
                        error=(
                            "扫描已结束，正在退出云真机队列"
                            if previous_status == TaskStatus.AWAITING_DEVICE.value
                            else "扫描已结束，正在停止当前分析"
                            if previous_status == TaskStatus.RUNNING.value
                            else "扫描已结束，等待任务已取消"
                        ),
                        result=result,
                    )
                    .execution_options(synchronize_session=False)
                )
                if transition.rowcount:
                    requested.append((task.id, previous_status))
            if requested:
                add_event(
                    session,
                    scan_id,
                    "scan.execution.tasks_stopping",
                    f"正在停止 {len(requested)} 个未完成任务",
                    {
                        "source": "platform",
                        "task_ids": [task_id for task_id, _status in requested],
                        "status_counts": dict(Counter(status for _task_id, status in requested)),
                    },
                )
            session.commit()

        signalled = 0
        acknowledged = 0
        for task_id, _previous_status in requested:
            if self.request_task_cancellation(task_id):
                signalled += 1
                continue
            # The dispatcher may have claimed the row immediately before the stop
            # request but not registered its runtime yet. Marking it cancelled now
            # prevents that late worker from starting any work.
            self._mark_task_canceled(scan_id, task_id)
            acknowledged += 1
        self.device_pool.wake_waiters()
        return {
            "requested": len(requested),
            "signalled": signalled,
            "acknowledged": acknowledged,
        }

    def _device_queue_priority(self, scan_id: str, task_id: str) -> int | None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            task = session.get(InvestigationTask, task_id)
            if (
                scan is None
                or task is None
                or task.status
                not in {
                    TaskStatus.RUNNING.value,
                    TaskStatus.AWAITING_DEVICE.value,
                }
                or not self.device_pool.configured
                or not scan.package_name
                or not self.device_pool.package_safe(scan.package_name)
            ):
                return None
            return int(task.priority)

    def _mark_task_awaiting_device(
        self,
        scan_id: str,
        task_id: str,
        position: int,
    ) -> None:
        requested_at = now()
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None or task.status != TaskStatus.RUNNING.value:
                return
            previous_queue = dict((task.result or {}).get("device_queue") or {})
            history = list(previous_queue.pop("history", []) or [])
            if previous_queue.get("requested_at"):
                history.append(previous_queue)
            task.status = TaskStatus.AWAITING_DEVICE.value
            task_result = {
                **dict(task.result or {}),
                "device_queue": {
                    "history": history,
                    "serial": None,
                    "candidate_serials": list(self.device_pool.serials),
                    "position_at_enqueue": position,
                    "requested_at": requested_at.isoformat(),
                },
            }
            task.result = task_result
            dag = deepcopy(self._ensure_task_execution_dag(task))
            device_node = dict(dag["nodes"]["device_execution"])
            device_node.update(
                {
                    "status": "waiting_resource",
                    "waiting_since": requested_at.isoformat(),
                    "metadata": {"queue_position": position},
                }
            )
            dag["nodes"]["device_execution"] = device_node
            dag["current_stage"] = "device_execution"
            task.result = {**dict(task.result or {}), "execution_dag": dag}
            add_event(
                session,
                scan_id,
                "task.awaiting_device",
                f"任务正在等待可用真机，当前排队位置 {position}",
                {
                    "task_id": task_id,
                    "status": TaskStatus.AWAITING_DEVICE.value,
                    "queue_position": position,
                    "priority": task.priority,
                    "device_serials": list(self.device_pool.serials),
                },
            )
            add_event(
                session,
                scan_id,
                "exploration.device.queued",
                "入口探索已进入云真机队列",
                {
                    "task_id": task_id,
                    "source": "platform",
                    "queue_position": position,
                    "priority": task.priority,
                    "device_serials": list(self.device_pool.serials),
                },
            )
            session.commit()

    def _record_device_acquired(
        self,
        scan_id: str,
        task_id: str,
        waited_seconds: float,
        device_serial: str | None,
    ) -> None:
        acquired_at = now()
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None or task.status not in {
                TaskStatus.RUNNING.value,
                TaskStatus.AWAITING_DEVICE.value,
            }:
                return
            queue_data = dict((task.result or {}).get("device_queue") or {})
            task.result = {
                **dict(task.result or {}),
                "device_queue": {
                    **queue_data,
                    "serial": device_serial,
                    "acquired_at": acquired_at.isoformat(),
                    "wait_seconds": round(waited_seconds, 3),
                },
            }
            task.status = TaskStatus.RUNNING.value
            dag = deepcopy(self._ensure_task_execution_dag(task))
            device_node = dict(dag["nodes"]["device_execution"])
            device_node.update(
                {
                    "status": "running",
                    "started_at": acquired_at.isoformat(),
                    "metadata": {
                        "serial": device_serial,
                        "wait_seconds": round(waited_seconds, 3),
                    },
                }
            )
            dag["nodes"]["device_execution"] = device_node
            dag["current_stage"] = "device_execution"
            task.result = {**dict(task.result or {}), "execution_dag": dag}
            add_event(
                session,
                scan_id,
                "task.device_acquired",
                f"任务已独占云真机，等待 {waited_seconds:.1f} 秒",
                {
                    "task_id": task_id,
                    "device_serial": device_serial,
                    "wait_seconds": round(waited_seconds, 3),
                },
            )
            add_event(
                session,
                scan_id,
                "exploration.device.acquired",
                "已获取云真机独占租约",
                {
                    "task_id": task_id,
                    "source": "platform",
                    "device_serial": device_serial,
                    "wait_seconds": round(waited_seconds, 3),
                },
            )
            session.commit()

    def _record_device_released(
        self,
        scan_id: str,
        task_id: str,
        held_seconds: float,
        device_serial: str | None,
    ) -> None:
        released_at = now()
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None:
                return
            queue_data = dict((task.result or {}).get("device_queue") or {})
            task.result = {
                **dict(task.result or {}),
                "device_queue": {
                    **queue_data,
                    "released_at": released_at.isoformat(),
                    "held_seconds": round(held_seconds, 3),
                },
            }
            dag = deepcopy(self._ensure_task_execution_dag(task))
            device_node = dict(dag["nodes"]["device_execution"])
            device_node.update(
                {
                    "status": "completed",
                    "completed_at": released_at.isoformat(),
                    "metadata": {
                        **dict(device_node.get("metadata") or {}),
                        "serial": device_serial,
                        "held_seconds": round(held_seconds, 3),
                    },
                }
            )
            dag["nodes"]["device_execution"] = device_node
            task.result = {**dict(task.result or {}), "execution_dag": dag}
            add_event(
                session,
                scan_id,
                "task.device_released",
                "云真机清理完成，独占租约已释放",
                {
                    "task_id": task_id,
                    "device_serial": device_serial,
                    "held_seconds": round(held_seconds, 3),
                },
            )
            add_event(
                session,
                scan_id,
                "exploration.device.released",
                "云真机已释放给下一个等待任务",
                {
                    "task_id": task_id,
                    "source": "platform",
                    "device_serial": device_serial,
                    "held_seconds": round(held_seconds, 3),
                },
            )
            session.commit()

    @contextmanager
    def _task_device_session(
        self,
        scan_id: str,
        task_id: str,
        *,
        priority: int,
        cancel_event: threading.Event,
        preferred_serial: str | None = None,
    ):  # noqa: ANN201
        try:
            with self.device_pool.task_lease(
                task_id,
                priority=priority,
                cancel_event=cancel_event,
                preferred_serial=preferred_serial,
                on_queued=lambda position: self._mark_task_awaiting_device(
                    scan_id, task_id, position
                ),
                on_acquired=lambda waited, adapter: self._record_device_acquired(
                    scan_id,
                    task_id,
                    waited,
                    adapter.serial,
                ),
                on_released=lambda held, adapter: self._record_device_released(
                    scan_id,
                    task_id,
                    held,
                    adapter.serial,
                ),
            ) as lease:
                self._raise_if_cancelled(cancel_event)
                yield lease
                self._raise_if_cancelled(cancel_event)
        except DeviceLeaseCancelledError as exc:
            raise AgentCancelledError(str(exc)) from exc

    def _run_task(
        self,
        scan_id: str,
        task_id: str,
        timeout_seconds: int | None = None,
    ) -> None:
        cancel_event = threading.Event()
        with self._task_cancellations_lock:
            self._task_cancellations[task_id] = cancel_event
        try:
            self._raise_if_cancelled(cancel_event)
            self._run_task_impl(
                scan_id,
                task_id,
                timeout_seconds,
                cancel_event=cancel_event,
            )
        except AgentCancelledError:
            self._mark_task_canceled(scan_id, task_id)
        finally:
            self.codex.close_task(scan_id, task_id)
            with self._task_cancellations_lock:
                if self._task_cancellations.get(task_id) is cancel_event:
                    self._task_cancellations.pop(task_id, None)

    def _run_task_impl(
        self,
        scan_id: str,
        task_id: str,
        timeout_seconds: int | None = None,
        *,
        cancel_event: threading.Event,
    ) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            task = session.get(InvestigationTask, task_id)
            assert scan is not None and task is not None
            if task.scan_id != scan.id:
                raise ValueError("investigation task does not belong to the selected scan")
            if task.status not in {
                TaskStatus.QUEUED.value,
                TaskStatus.RUNNING.value,
            }:
                return
            scan_entries = list(
                session.scalars(
                    select(EntryPoint).where(
                        EntryPoint.scan_id == scan.id,
                    )
                )
            )
            entries_by_id = {entry.id: entry for entry in scan_entries}
            entries = [
                entries_by_id[entry_id]
                for entry_id in task.target_entry_ids
                if entry_id in entries_by_id
            ]
            loaded_entry_ids = {entry.id for entry in entries}
            expected_entry_ids = set(task.target_entry_ids)
            if not expected_entry_ids or loaded_entry_ids != expected_entry_ids:
                transition = session.execute(
                    update(InvestigationTask)
                    .where(
                        InvestigationTask.id == task_id,
                        InvestigationTask.scan_id == scan_id,
                        InvestigationTask.status.in_(
                            [TaskStatus.QUEUED.value, TaskStatus.RUNNING.value]
                        ),
                    )
                    .values(
                        status=TaskStatus.FAILED.value,
                        error=(
                            "Investigation task references missing entry points or "
                            "entry points outside its scan"
                        ),
                        completed_at=now(),
                    )
                    .execution_options(synchronize_session=False)
                )
                if transition.rowcount == 1:
                    add_event(
                        session,
                        scan_id,
                        "task.failed",
                        "Investigation stopped because its entry-point references are invalid",
                        {
                            "task_id": task.id,
                            "expected_entry_point_ids": sorted(expected_entry_ids),
                            "loaded_entry_point_ids": sorted(loaded_entry_ids),
                        },
                    )
                    session.commit()
                else:
                    session.rollback()
                return
            persisted_task_result = dict(task.result or {})
            continuation_context = dict(persisted_task_result.get("manual_continuation") or {})
            independent_context = dict(persisted_task_result.get("independent_reanalysis") or {})
            manual_dispatch = bool(
                persisted_task_result.get("manual_rerun")
                or persisted_task_result.get("manual_continuation")
                or independent_context
            )
            agent_backend = self.resolve_task_investigator(scan, task)
            task.status = TaskStatus.RUNNING.value
            dag = deepcopy(self._ensure_task_execution_dag(task))
            seed_node = dict(dag["nodes"]["seed_analysis"])
            seed_node.update(
                {
                    "status": "running",
                    "started_at": seed_node.get("started_at") or now().isoformat(),
                }
            )
            dag["nodes"]["seed_analysis"] = seed_node
            dag["current_stage"] = "seed_analysis"
            task.result = {**dict(task.result or {}), "execution_dag": dag}
            task.attempts += 1
            task.started_at = task.started_at or now()
            scan.status = ScanStatus.INVESTIGATING.value
            add_event(
                session,
                scan_id,
                "task.started",
                f"Investigation started for {len(entries)} entry point(s)",
                {"task_id": task.id, "agent_backend": agent_backend},
            )
            add_event(
                session,
                scan_id,
                "exploration.started",
                (
                    f"AI 探索任务已启动：{len(entries)} 个入口"
                    if agent_backend != "none"
                    else f"确定性入口验证任务已启动：{len(entries)} 个入口"
                ),
                {
                    "task_id": task.id,
                    "source": "platform",
                    "run_id": f"{task.id}:attempt:{task.attempts}",
                    "agent_backend": agent_backend,
                    "model": (self.settings.codex_model if agent_backend == "codex" else None),
                    "entry_point_ids": list(task.target_entry_ids),
                    "hypotheses": list(task.hypotheses),
                    "continuation_number": continuation_context.get("continuation_number"),
                    "reusing_task_evidence": bool(continuation_context),
                    "context_mode": ("independent" if independent_context else "continue"),
                    "origin_task_id": independent_context.get("origin_task_id"),
                    "investigation_concurrency": self._current_investigation_concurrency(),
                    "concurrency_policy": "resource_aware_phase_admission",
                },
            )
            session.commit()

        self.hypothesis_ledger.ensure_task_hypotheses(task)
        hypothesis_context = self.hypothesis_ledger.task_context(task_id)
        hypothesis_ids = {item["id"] for item in hypothesis_context}
        self._raise_if_cancelled(cancel_event)
        task_budget_seconds = (
            self.settings.task_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        budget = TimeBudget.from_seconds(task_budget_seconds)
        scan_deadline: float | None = None
        if not manual_dispatch:
            scan_created_at = scan.created_at
            if scan_created_at.tzinfo is None:
                scan_created_at = scan_created_at.replace(tzinfo=UTC)
            hard_remaining = max(
                0.0,
                (
                    scan_created_at
                    + timedelta(seconds=self.settings.scan_deadline_seconds)
                    - datetime.now(UTC)
                ).total_seconds(),
            )
            scan_deadline = TimeBudget.from_seconds(hard_remaining).deadline
            budget = TimeBudget(deadline=min(budget.deadline, scan_deadline))
        evidence_summaries = self._evidence_summaries_for_run(
            scan_id,
            task_id=task_id,
            include_task_evidence=bool(continuation_context),
        )
        if continuation_context:
            self._record_exploration_event(
                scan_id,
                task_id,
                "exploration.continuation.context_loaded",
                "已装载历次静态、设备和 AI Evidence，继续深度探索",
                {
                    "source": "platform",
                    "continuation_number": continuation_context.get("continuation_number"),
                    "prior_evidence_count": len(evidence_summaries),
                    "new_budget_seconds": task_budget_seconds,
                },
            )
        target_code_context = self._target_code_context(scan_id, entries)
        target_xrefs = self._target_xrefs_context(scan_id, entries)
        scope_plan = InvestigationPlanner(
            android_version=self.settings.device_android_version,
            android_api=self.settings.device_android_api,
            adb_configured=self.device_pool.configured,
            device_reset_policy=self.settings.device_reset_policy,
        ).plan_with_decisions(scan_id, scan_entries)
        static_closures_by_entry = {
            closure.entry_point_id: closure for closure in scope_plan.static_closures
        }
        statically_closed_entry_ids = set(static_closures_by_entry)
        testable_entries = [
            entry
            for entry in scan_entries
            if entry.id not in statically_closed_entry_ids
            and entry.kind != EntryPointKind.STATIC_SURFACE.value
        ]
        seed_entry_ids = set(task.target_entry_ids)
        direct_test_entry_ids = {
            entry.id for entry in testable_entries if entry.id in seed_entry_ids
        }
        entry_scope = {
            "policy": "seed_entry_with_scan_wide_chain_exploration",
            "seed_entry_point_ids": list(task.target_entry_ids),
            "direct_test_entry_point_ids": sorted(direct_test_entry_ids),
            "catalog": [
                {
                    "id": entry.id,
                    "kind": entry.kind,
                    "name": entry.name,
                    "owner_component": entry.owner_component,
                    "exported": entry.exported,
                    "permission": entry.permission,
                    "permission_protection": entry.permission_protection,
                    "direct_test_allowed": entry.id in direct_test_entry_ids,
                    "direct_reachability": (
                        "not_applicable"
                        if entry.kind == EntryPointKind.STATIC_SURFACE.value
                        else "blocked"
                        if entry.id in statically_closed_entry_ids
                        else "testable"
                    ),
                    "direct_reachability_decision": (
                        static_closures_by_entry[entry.id].as_dict()
                        if entry.id in static_closures_by_entry
                        else None
                    ),
                    "indirect_chain_target_allowed": True,
                    "assigned_seed": entry.id in set(task.target_entry_ids),
                }
                for entry in scan_entries
                if entry.id in seed_entry_ids
            ],
        }
        coverage_gaps: list[str] = []
        stages: dict[str, Any] = {
            "device_attempted": False,
            "blackbox_attempted": False,
        }
        device_capability = self.device_pool.capability(non_blocking=True)
        task_device: AdbDeviceAdapter | None = None
        device_lease_owned = False
        device_lease_acquired = False
        device_session = None
        target_installed = False
        sticky_device_serial: str | None = None
        prepared_device_serials: set[str] = set()
        task_gateway_token = secrets.token_urlsafe(48)

        def acquire_dynamic_device() -> dict[str, Any]:
            nonlocal device_session, task_device, device_lease_owned
            nonlocal device_lease_acquired, sticky_device_serial, budget
            if device_session is not None:
                return {
                    "device": task_device,
                    "wait_seconds": 0.0,
                    "serial": task_device.serial if task_device else None,
                }
            device_session = self._task_device_session(
                scan_id,
                task_id,
                priority=int(task.priority),
                cancel_event=cancel_event,
                preferred_serial=sticky_device_serial,
            )
            lease_metadata = device_session.__enter__()
            task_device = lease_metadata["device"]
            device_lease_owned = True
            device_lease_acquired = True
            acquired_serial = str(task_device.serial or "")
            if sticky_device_serial is None:
                sticky_device_serial = acquired_serial
            elif acquired_serial != sticky_device_serial:
                coverage_gaps.append(
                    "The preferred Android device became unavailable; a later dynamic batch "
                    f"moved from {sticky_device_serial} to {acquired_serial} and re-preparation "
                    "was required."
                )
                sticky_device_serial = acquired_serial
            budget = budget.extend(
                float(lease_metadata["wait_seconds"]),
                maximum_deadline=scan_deadline,
            )
            return lease_metadata

        def release_dynamic_device(*, cleanup_target: bool = False) -> None:
            nonlocal device_session, device_lease_owned, target_installed
            if device_session is None:
                return
            if cleanup_target and target_installed and task_device is not None and package_name:
                cleanup = task_device.cleanup(package_name)
                self._record_commands(scan_id, task_id, cleanup, None)
                target_installed = False
            final_device_session = device_session
            device_session = None
            final_device_session.__exit__(None, None, None)
            device_lease_owned = False

        def current_device_capability() -> dict[str, Any]:
            capability = dict(device_capability)
            if task_device is not None and device_lease_owned:
                capability.update(task_device.capability(non_blocking=False))
            if device_lease_owned:
                capability.update(
                    {
                        "available": True,
                        "busy": False,
                        "lease_owned_by_current_task": True,
                        "active_task_id": task_id,
                        "serial": task_device.serial if task_device else None,
                        "detail": (
                            "当前任务已独占设备；本任务申请的测试会在该 lease 内"
                            "直接串行执行，无需重新排队。"
                        ),
                    }
                )
            elif device_lease_acquired:
                capability.update(
                    {
                        "available": True,
                        "busy": False,
                        "lease_owned_by_current_task": False,
                        "lease_completed_by_current_task": True,
                        "active_task_id": None,
                        "serial": sticky_device_serial,
                        "detail": "当前任务的独占设备会话已完成并释放。",
                    }
                )
            return capability

        def prepare_dynamic_target() -> bool:
            nonlocal target_installed
            if task_device is None or not device_lease_owned or not package_name:
                return False
            serial = str(task_device.serial or "")
            if serial in prepared_device_serials:
                return True
            stages["device_attempted"] = True
            prepare_commands = task_device.prepare(Path(scan.artifact_path), package_name, budget)
            self._record_commands(scan_id, task_id, prepare_commands, evidence_summaries)
            target_installed = target_installed or any(
                kind == "device.install" and result.exit_code == 0
                for kind, result, _metadata in prepare_commands
            )
            critical = {
                kind: result
                for kind, result, _metadata in prepare_commands
                if kind in {"device.health", "device.install", "device.clear"}
                and result.exit_code != 0
            }
            if critical:
                failures = ", ".join(
                    f"{kind}=exit {result.exit_code}" for kind, result in critical.items()
                )
                coverage_gaps.append(f"Device preparation failed: {failures}")
                return False
            prepared_device_serials.add(serial)
            return True

        agent_result = None
        agent_error = None
        agent_capability_gap = False
        agent_failures: list[dict[str, str]] = []
        executed_agent_tests: list[dict[str, Any]] = []
        agent_round_history: list[dict[str, Any]] = []
        debate_context: dict[str, Any] = {}
        rescue_context: dict[str, Any] = {}
        rescue_gate: dict[str, Any] = {}
        phase_counts: dict[str, int] = {}
        phase_usage_seconds: dict[str, float] = defaultdict(float)
        agent_runtime_workspaces: dict[str, Path] = {}
        last_progress_signature: str | None = None
        agent_no_progress_rounds = 0
        single_pass_phases = {
            "adversarial_review",
            "rescue_review",
            "rescue_exploration",
            "final_evaluation",
        }
        debate_policy: dict[str, Any] = {
            "mode": "single_pass",
            "max_critic_rounds": 1,
            "max_rescue_reviews": 1,
            "max_rescue_explorations": 1,
            "max_final_evaluations": 1,
            "critic_and_rescue_are_mutually_exclusive": False,
        }
        package_name = scan.package_name
        investigator = self.investigators.get(agent_backend)
        agent_enabled = self.settings.investigator_enabled(agent_backend)

        def phase_budget(phase: str) -> tuple[str, int]:
            if phase in {"static_only", "test_planning"}:
                return "primary_analysis", self.settings.agent_initial_phase_seconds
            if phase == "exploration_round":
                # A rejected plan must not leave its corrective turn with only
                # the few seconds remaining from primary analysis.
                return "adaptive_analysis", self.settings.agent_exploration_phase_seconds
            if phase == "adversarial_review":
                return "critic", self.settings.agent_critic_phase_seconds
            if phase in {"rescue_review", "rescue_exploration"}:
                return "rescue", self.settings.agent_rescue_phase_seconds
            return "final_synthesis", self.settings.agent_final_phase_seconds

        def invoke_agent(
            *,
            phase: str,
            timeout_cap: int | None = None,
            executed_tests: list[dict[str, Any]] | None = None,
            candidate_under_review: dict[str, Any] | None = None,
            round_index: int = 0,
            blind_rescue: bool = False,
        ):  # noqa: ANN202
            nonlocal agent_capability_gap, last_progress_signature, agent_no_progress_rounds
            audit_id: str | None = None
            runtime_events: list[dict[str, Any]] = []
            phase_bucket, phase_limit_seconds = phase_budget(phase)
            stage = {
                "static_only": "seed_analysis",
                "test_planning": "seed_analysis",
                "adversarial_review": "adversarial_review",
                "rescue_review": "rescue_review",
                "rescue_exploration": "rescue_review",
                "exploration_round": "adaptive_analysis",
                "final_evaluation": "final_synthesis",
                "recovery_evaluation": "final_synthesis",
            }.get(phase, "seed_analysis")
            self._raise_if_cancelled(cancel_event)
            if phase in single_pass_phases and phase_counts.get(phase, 0) >= 1:
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "debate.phase.skipped",
                    "单向辩论策略阻止了重复阶段",
                    {
                        "source": "platform",
                        "phase": phase,
                        "round_index": round_index,
                        "maximum_runs": 1,
                    },
                )
                return None, f"{phase} is limited to one run per task"
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
            if investigator is None:
                agent_capability_gap = True
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "inconclusive",
                    phase=phase,
                    reason="investigator_unavailable",
                )
                return None, "AI investigation is disabled for this scan"
            if not agent_enabled:
                agent_capability_gap = True
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "inconclusive",
                    phase=phase,
                    reason="investigator_disabled",
                )
                return None, f"{agent_backend} investigation is disabled"

            def dispatch_remaining() -> int:
                remaining_seconds = budget.remaining()
                phase_remaining = max(
                    0,
                    int(phase_limit_seconds - phase_usage_seconds.get(phase_bucket, 0.0)),
                )
                remaining_seconds = min(remaining_seconds, phase_remaining)
                if timeout_cap is not None:
                    remaining_seconds = min(remaining_seconds, timeout_cap)
                return remaining_seconds

            remaining = dispatch_remaining()
            if remaining <= 0:
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "inconclusive",
                    phase=phase,
                    reason="phase_budget_exhausted",
                )
                return None, "task time budget exhausted before AI dispatch"
            capability = investigator.capability(deep=True)
            self._raise_if_cancelled(cancel_event)
            if not capability.get("available"):
                agent_capability_gap = True
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "inconclusive",
                    phase=phase,
                    reason="capability_unavailable",
                )
                return None, capability.get("detail", f"{agent_backend} capability probe failed")
            remaining = dispatch_remaining()
            if remaining <= 0:
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "inconclusive",
                    phase=phase,
                    reason="phase_budget_exhausted",
                )
                return None, "task time budget exhausted during AI capability probe"
            self._set_task_stage(
                scan_id,
                task_id,
                stage,
                "running",
                phase=phase,
                round_index=round_index,
            )
            try:
                task_threat_model = deepcopy((scan.stats or {}).get("threat_model"))
                if isinstance(task_threat_model, dict):
                    attack_surface = task_threat_model.get("attack_surface")
                    if isinstance(attack_surface, dict):
                        seed_names = {entry.name for entry in entries} | {
                            entry.owner_component for entry in entries if entry.owner_component
                        }
                        representatives = attack_surface.get("representative_entries")
                        if isinstance(representatives, list):
                            attack_surface["representative_entries"] = [
                                item
                                for item in representatives
                                if isinstance(item, dict) and item.get("name") in seed_names
                            ]
                critic_turn = phase == "adversarial_review"
                critic_evidence_ids = (
                    self._candidate_evidence_ids(candidate_under_review) if critic_turn else set()
                )
                dispatch_evidence = (
                    [
                        item
                        for item in evidence_summaries
                        if str(item.get("id")) in critic_evidence_ids
                    ]
                    if critic_turn
                    else evidence_summaries
                )
                dispatch_code_context = target_code_context
                gateway_available = bool(
                    not critic_turn
                    and phase not in {"rescue_review", "final_evaluation"}
                    and self.settings.codex_isolation == "docker"
                    and device_lease_owned
                    and task_device is not None
                )
                poc_builder_capability = self.poc_builder.capability()
                ephemeral_app_harness = bool(
                    poc_builder_capability.get("available")
                    and poc_builder_capability.get("source_build_available")
                )
                platform_context = {
                    "phase": phase,
                    "round_index": round_index,
                    "output_language": "zh-CN",
                    "validation_fixtures": self._validation_fixture_context(scan_id, task_id),
                    "device": current_device_capability(),
                    "poc_builder": poc_builder_capability,
                    "coverage_gaps": ([] if blind_rescue or critic_turn else coverage_gaps),
                    "target_code_context": dispatch_code_context,
                    "target_xrefs": target_xrefs,
                    "entry_scope": entry_scope,
                    "executed_agent_tests": ([] if critic_turn else executed_tests or []),
                    "agent_round_history": (
                        [] if blind_rescue or critic_turn else deepcopy(agent_round_history)
                    ),
                    "further_test_rounds_available": (phase != "final_evaluation"),
                    "exploration_policy": {
                        "mode": "agent_directed",
                        "count_limits": False,
                        "termination": [
                            "agent_reports_no_material_followup",
                            "all_hypotheses_proven",
                            "task_cancelled",
                            "task_lifecycle_deadline",
                        ],
                    },
                    "proof_capabilities": {
                        "schema_version": "1.0",
                        "ephemeral_app_harness": ephemeral_app_harness,
                        "ephemeral_app_harness_unavailable_reason": (
                            None
                            if ephemeral_app_harness
                            else "the platform PoC source-build toolchain is unavailable"
                        ),
                        "operations": ["binder_transact", "binder_script"],
                        "binder_primitive_writes": [
                            "string",
                            "integer",
                            "long",
                            "boolean",
                            "bytes_base64",
                        ],
                        "binder_primitive_reads": [
                            "string",
                            "integer",
                            "long",
                            "boolean",
                            "bytes_base64",
                        ],
                        "binder_reply_match_modes": [
                            "exact",
                            "contains",
                            "regex",
                            "sha256",
                            "non_empty_diagnostic_only",
                        ],
                        "impact_oracles": [
                            "provider_rows",
                            "binder_reply",
                            "target_uid_log_contains",
                            "target_file_sha256",
                            "ui_text",
                            "process_crash",
                        ],
                        "poc_log_is_auxiliary_only": True,
                        "runtime_observation_intake": {
                            "available": gateway_available,
                            "url_env": "APKSCANNER_OBSERVATION_URL",
                            "token_env": "APKSCANNER_OBSERVATION_TOKEN",
                            "supported_sources": [
                                "webview_callback",
                                "network_callback",
                                "localhost_client",
                                "unix_socket_client",
                                "ssh_remote",
                                "agent",
                            ],
                            "policy": "observation_is_evidence_not_an_automatic_verdict",
                        },
                    },
                    "continuation": continuation_context or None,
                    "context_policy": (
                        {
                            "mode": "independent",
                            "origin_task_id": independent_context.get("origin_task_id"),
                            "static_artifacts_reused": True,
                            "task_evidence_reused": False,
                            "agent_thread_reused": False,
                            "version_replays_reused": False,
                        }
                        if independent_context
                        else {
                            "mode": "continue",
                            "task_evidence_reused": bool(continuation_context),
                        }
                    ),
                    "threat_model": task_threat_model,
                    "security_hypotheses": self.hypothesis_ledger.task_context(task_id),
                    "platform_proven_hypotheses": (
                        self.hypothesis_ledger.task_proven_hypotheses(task_id)
                    ),
                    "hypothesis_progress": (
                        self.hypothesis_ledger.task_hypothesis_progress(task_id)
                    ),
                    "candidate_under_review": (None if blind_rescue else candidate_under_review),
                    "critic_scope": (
                        {
                            "mode": "candidate_and_cited_evidence_only",
                            "evidence_ids": sorted(critic_evidence_ids),
                            "bounded_source_recheck_allowed": True,
                        }
                        if critic_turn
                        else None
                    ),
                    "debate": None if blind_rescue else debate_context or None,
                    "rescue": None if blind_rescue else rescue_context or None,
                    "debate_policy": {
                        **debate_policy,
                        "phase_counts": dict(phase_counts),
                    },
                    "blind_rescue": (
                        {
                            "mode": "independent_negative_closure_review",
                            "prior_model_conclusion_withheld": True,
                        }
                        if blind_rescue
                        else None
                    ),
                    "proof_replay": {
                        "available": gateway_available,
                        "command": "apkscanner-proof <proof-replay.json>",
                        "mode": (
                            "task_scoped_docker_gateway"
                            if gateway_available
                            else "unavailable_without_device_lease"
                        ),
                    },
                    "adb_gateway": {
                        "available": gateway_available,
                        "command": "adb <allowed-arguments>",
                        "mode": (
                            "task_scoped_fixed_serial"
                            if gateway_available
                            else "unavailable_without_device_lease"
                        ),
                    },
                }
                agent_workspace = self._materialize_agent_evidence(
                    scan_id,
                    task_id,
                    task.attempts,
                    dispatch_evidence,
                    platform_context=platform_context,
                )
                agent_runtime_workspace = agent_workspace
                prepare_workspace = getattr(
                    investigator,
                    "prepare_session_workspace",
                    None,
                )
                if callable(prepare_workspace):
                    agent_runtime_workspace = prepare_workspace(
                        scan=scan,
                        task=task,
                        workspace=agent_workspace,
                        phase=phase,
                    )
                runtime_role = (
                    "critic"
                    if phase == "adversarial_review"
                    else "rescue"
                    if phase == "rescue_review"
                    else "rescue_explorer"
                    if phase == "rescue_exploration"
                    else "primary"
                )
                agent_runtime_workspaces[runtime_role] = agent_runtime_workspace
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "context.loaded",
                    "静态结果、入口信息与现有证据已装载",
                    {
                        "source": "platform",
                        "phase": phase,
                        "round_index": round_index,
                        "evidence_count": len(evidence_summaries),
                        "target_code_statuses": [
                            item.get("status") for item in target_code_context.get("components", [])
                        ],
                        "executed_test_count": len(executed_tests or []),
                        "agent_backend": agent_backend,
                    },
                )
                audit_id = self._record_agent_request(
                    scan=scan,
                    task=task,
                    entries=entries,
                    evidence=dispatch_evidence,
                    platform_context=platform_context,
                    backend=agent_backend,
                    phase=phase,
                    capability=capability,
                    runtime_workspace=agent_runtime_workspace,
                )
                proof_token: str | None = None
                gateway_environment: dict[str, str] | None = None
                if gateway_available:
                    endpoint = self.ensure_live_proof_endpoint()
                    port = urlsplit(endpoint).port
                    if port is None:
                        raise RuntimeError("internal Agent gateway has no TCP port")
                    proof_token = task_gateway_token
                    self.register_live_proof_context(
                        LiveProofContext(
                            token=proof_token,
                            scan_id=scan_id,
                            task_id=task_id,
                            package_name=package_name or "",
                            workspace=agent_runtime_workspace,
                            entries=entries,
                            default_entry_id=entries[0].id,
                            hypotheses=hypothesis_context,
                            budget=budget,
                            evidence_summaries=evidence_summaries,
                            cancel_event=cancel_event,
                            round_index=round_index,
                            device=task_device,
                        )
                    )
                    docker_base = f"http://apkscanner-host:{port}"
                    gateway_environment = task_gateway_environment(
                        task_id=task_id,
                        base_url=docker_base,
                        token=proof_token,
                        proof_replay=True,
                    )

                def on_runtime_event(event: AgentRuntimeEvent) -> None:
                    if not self._record_agent_runtime_event(
                        scan_id,
                        task_id,
                        event,
                        phase=phase,
                        round_index=round_index,
                        agent_backend=agent_backend,
                    ):
                        return
                    record = {
                        "schema_version": "1.0",
                        "sequence": len(runtime_events) + 1,
                        "dedupe_key": event.dedupe_key,
                        "event_type": event.event_type,
                        "message": event.message,
                        "data": event.data,
                        "session_id": event.session_id,
                        "protocol_stream_id": event.protocol_stream_id,
                        "worker_sequence": event.worker_sequence,
                        "delivery_source": event.delivery_source,
                        "created_at": datetime.now(UTC).isoformat(),
                    }
                    runtime_events.append(record)

                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "model.dispatched",
                    f"任务已下发到 {agent_backend} SDK",
                    {
                        "source": "platform",
                        "phase": phase,
                        "round_index": round_index,
                        "agent_backend": agent_backend,
                    },
                )
                remaining = dispatch_remaining()
                if remaining <= 0:
                    raise TimeoutError(
                        "task time budget exhausted while preparing the AI audit context"
                    )
                investigation_kwargs = {
                    "scan": scan,
                    "task": task,
                    "entries": entries,
                    "workspace": agent_workspace,
                    "evidence": dispatch_evidence,
                    "platform_context": platform_context,
                    "timeout_seconds": remaining,
                    "event_callback": on_runtime_event,
                    "cancel_event": cancel_event,
                    "gateway_environment": gateway_environment,
                }
                acquired_analysis_slot = False
                agent_call_started_at: float | None = None
                try:
                    while not acquired_analysis_slot:
                        self._raise_if_cancelled(cancel_event)
                        if dispatch_remaining() <= 0:
                            raise TimeoutError(
                                "phase budget exhausted while waiting for an analysis slot"
                            )
                        acquired_analysis_slot = self._analysis_slots.acquire(timeout=0.5)
                    call_timeout = dispatch_remaining()
                    if call_timeout <= 0:
                        raise TimeoutError("phase budget exhausted before the AI call started")
                    investigation_kwargs["timeout_seconds"] = call_timeout
                    agent_call_started_at = time.monotonic()
                    result = investigator.investigate(**investigation_kwargs)
                finally:
                    if agent_call_started_at is not None:
                        phase_usage_seconds[phase_bucket] += max(
                            0.0, time.monotonic() - agent_call_started_at
                        )
                    if acquired_analysis_slot:
                        self._analysis_slots.release()
                    if proof_token is not None:
                        self.unregister_live_proof_context(task_id, proof_token)
                self._raise_if_cancelled(cancel_event)
                self._record_agent_response(
                    scan_id=scan_id,
                    task_id=task_id,
                    audit_id=audit_id,
                    backend=agent_backend,
                    phase=phase,
                    attempt=task.attempts,
                    result=result,
                )
                rejected_requested_tests = self._rejected_requested_tests(result.result)
                normalization_repairs = self._normalization_repairs(result.result)
                argument_payload = result.result.model_dump(mode="json")
                if rejected_requested_tests or normalization_repairs:
                    argument_payload["platform_model_validation"] = {
                        "rejected_requested_tests": rejected_requested_tests,
                        "normalization_repairs": normalization_repairs,
                    }
                role = (
                    "critic"
                    if phase == "adversarial_review"
                    else "rescuer"
                    if phase == "rescue_review"
                    else "hunter"
                    if phase in {"static_only", "test_planning"}
                    else "advocate"
                )
                self.hypothesis_ledger.record_argument(
                    task_id=task_id,
                    role=role,
                    phase=phase,
                    backend=agent_backend,
                    model=self.settings.codex_model,
                    payload=argument_payload,
                    allowed_evidence_ids={
                        str(item["id"])
                        for item in dispatch_evidence
                        if isinstance(item.get("id"), str)
                    },
                )
                self._record_agent_runtime_events(
                    scan_id=scan_id,
                    task_id=task_id,
                    audit_id=audit_id,
                    backend=agent_backend,
                    phase=phase,
                    attempt=task.attempts,
                    events=runtime_events,
                )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "model.completed",
                    f"{agent_backend} SDK 已返回本轮结构化结果",
                    {
                        "source": "platform",
                        "phase": phase,
                        "round_index": round_index,
                        "agent_backend": agent_backend,
                        "thread_id": result.thread_id,
                        "turn_id": result.turn_id,
                        "requested_test_count": len(result.result.requested_tests),
                        "rejected_requested_test_count": len(rejected_requested_tests),
                        "normalization_repair_count": len(normalization_repairs),
                        "phase_budget_bucket": phase_bucket,
                        "phase_budget_consumed_seconds": round(
                            phase_usage_seconds.get(phase_bucket, 0.0), 3
                        ),
                        "phase_budget_remaining_seconds": dispatch_remaining(),
                    },
                )
                for hypothesis in result.result.hypotheses_tested[:12]:
                    self._record_exploration_event(
                        scan_id,
                        task_id,
                        "hypothesis.recorded",
                        "AI 已记录一项被验证的安全假设",
                        {
                            "source": "model",
                            "phase": phase,
                            "round_index": round_index,
                            "agent_backend": agent_backend,
                            "hypothesis": hypothesis,
                        },
                    )
                for request in result.result.requested_tests:
                    self._record_exploration_event(
                        scan_id,
                        task_id,
                        "action.proposed",
                        "AI 申请执行一项受控入口测试",
                        {
                            "source": "model",
                            "phase": phase,
                            "round_index": round_index,
                            "agent_backend": agent_backend,
                            "entry_point_id": request.entry_point_id,
                            "state": request.state,
                            "rationale_summary": request.rationale,
                            "poc_package": (request.poc.package_name if request.poc else None),
                            "poc_project_path": (request.poc.project_path if request.poc else None),
                            "execution_mode": (
                                "dynamic_experiment"
                                if request.experiment is not None
                                else "android_poc"
                            ),
                            "experiment_step_count": (
                                len(request.experiment.steps)
                                if request.experiment is not None
                                else 0
                            ),
                        },
                    )
                agent_round_history.append(
                    {
                        "phase": phase,
                        "round_index": round_index,
                        "thread_id": result.thread_id,
                        "turn_id": result.turn_id,
                        "model_result": result.result.model_dump(mode="json"),
                        "model_validation": {
                            "rejected_requested_tests": rejected_requested_tests,
                            "normalization_repairs": normalization_repairs,
                        },
                        "test_validation": None,
                    }
                )
                progress_signature = self._agent_progress_signature(
                    result.result,
                    evidence_summaries=evidence_summaries,
                    proven_hypotheses=(self.hypothesis_ledger.task_proven_hypotheses(task_id)),
                )
                if progress_signature == last_progress_signature:
                    agent_no_progress_rounds += 1
                else:
                    agent_no_progress_rounds = 0
                    last_progress_signature = progress_signature
                agent_round_history[-1]["progress"] = {
                    "signature": progress_signature,
                    "consecutive_no_progress_rounds": agent_no_progress_rounds,
                }
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "completed",
                    phase=phase,
                    round_index=round_index,
                    no_progress_rounds=agent_no_progress_rounds,
                )
                return result, None
            except AgentCancelledError as exc:
                if audit_id is not None and runtime_events:
                    self._record_agent_runtime_events(
                        scan_id=scan_id,
                        task_id=task_id,
                        audit_id=audit_id,
                        backend=agent_backend,
                        phase=phase,
                        attempt=task.attempts,
                        events=runtime_events,
                    )
                if audit_id is not None:
                    self._record_agent_cancellation(
                        scan_id=scan_id,
                        task_id=task_id,
                        audit_id=audit_id,
                        backend=agent_backend,
                        phase=phase,
                        attempt=task.attempts,
                        error=exc,
                    )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "model.cancelled",
                    f"{agent_backend} SDK 本轮调用已由用户停止",
                    {
                        "source": "platform",
                        "phase": phase,
                        "round_index": round_index,
                        "agent_backend": agent_backend,
                    },
                )
                raise
            except Exception as exc:
                self._set_task_stage(
                    scan_id,
                    task_id,
                    stage,
                    "failed",
                    phase=phase,
                    round_index=round_index,
                    error=str(exc)[:1000],
                )
                agent_failures.append(
                    {
                        "phase": phase,
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:2000],
                    }
                )
                if audit_id is not None and runtime_events:
                    self._record_agent_runtime_events(
                        scan_id=scan_id,
                        task_id=task_id,
                        audit_id=audit_id,
                        backend=agent_backend,
                        phase=phase,
                        attempt=task.attempts,
                        events=runtime_events,
                    )
                if audit_id is not None:
                    self._record_agent_error(
                        scan_id=scan_id,
                        task_id=task_id,
                        audit_id=audit_id,
                        backend=agent_backend,
                        phase=phase,
                        attempt=task.attempts,
                        error=exc,
                    )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "model.failed",
                    f"{agent_backend} SDK 本轮调用失败",
                    {
                        "source": "platform",
                        "phase": phase,
                        "round_index": round_index,
                        "agent_backend": agent_backend,
                        "error": str(exc)[:2000],
                    },
                )
                return None, str(exc)

        def run_negative_rescue(current_result, *, round_index: int):  # noqa: ANN202
            """Review only material negatives plus a deterministic quality sample."""

            nonlocal rescue_context
            if (
                current_result is None
                or not self._needs_rescue_review(current_result.result)
                or self.hypothesis_ledger.task_all_hypotheses_proven(task_id)
            ):
                return current_result
            rescue_decision = self._rescue_decision(
                task,
                current_result.result,
                target_code_context=target_code_context,
            )
            if not rescue_decision["triggered"]:
                rescue_gate.update(
                    {
                        "triggered": False,
                        "passed": True,
                        "outcome": "risk_gate_skipped",
                        "policy": rescue_decision,
                    }
                )
                self._set_task_stage(
                    scan_id,
                    task_id,
                    "rescue_review",
                    "skipped",
                    reasons=rescue_decision["reasons"],
                )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "rescue.skipped",
                    "负面结论未命中高风险救援条件，本次不执行盲审",
                    {
                        "source": "platform",
                        "round_index": round_index,
                        **rescue_decision,
                    },
                )
                return current_result

            rescue_gate.update(
                {
                    "triggered": True,
                    "passed": False,
                    "candidate_turn_id": current_result.turn_id,
                    "candidate_result": current_result.result.result,
                    "mode": "blind_independent_review",
                    "policy": rescue_decision,
                }
            )
            debate_policy["outcome"] = "rescue_started"
            self._record_exploration_event(
                scan_id,
                task_id,
                "rescue.started",
                "负面结论进入盲审救援，上一轮模型结论已从救援上下文中移除",
                {
                    "source": "platform",
                    "round_index": round_index,
                    "candidate_turn_id": current_result.turn_id,
                    "candidate_result": current_result.result.result,
                    "prior_model_conclusion_withheld": True,
                },
            )
            review_result, review_error = invoke_agent(
                phase="rescue_review",
                executed_tests=executed_agent_tests,
                round_index=round_index,
                blind_rescue=True,
            )
            if review_result is None:
                rescue_gate.update(
                    {
                        "outcome": "review_unavailable",
                        "error": review_error,
                    }
                )
                debate_policy["outcome"] = rescue_gate["outcome"]
                coverage_gaps.append(
                    "Blind rescue review was unavailable; the model negative was not accepted: "
                    f"{review_error}"
                )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "rescue.failed",
                    "盲审救援不可用，平台未接受原模型的负面关闭结论",
                    {
                        "source": "platform",
                        "round_index": round_index,
                        "error": review_error,
                    },
                )
                return current_result

            rescue_gate.update(
                {
                    "review_thread_id": review_result.thread_id,
                    "review_turn_id": review_result.turn_id,
                    "review_result": review_result.result.result,
                }
            )
            if self._needs_rescue_review(review_result.result):
                rescue_gate.update(
                    {
                        "passed": True,
                        "outcome": "independent_closure_confirmed",
                    }
                )
                debate_policy["outcome"] = rescue_gate["outcome"]
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "rescue.closed",
                    "独立盲审未发现替代攻击链，并为负面结论提供了逐假设关闭依据",
                    {
                        "source": "platform",
                        "round_index": round_index,
                        "review_turn_id": review_result.turn_id,
                    },
                )
                return review_result

            rescue_context = {
                "strategy": review_result.result.model_dump(mode="json"),
                "review_thread_id": review_result.thread_id,
                "review_turn_id": review_result.turn_id,
                "prior_model_conclusion_withheld_during_review": True,
            }
            self._record_exploration_event(
                scan_id,
                task_id,
                "rescue.lead_found",
                "独立救援发现替代攻击链，已交给工具 Agent 继续验证",
                {
                    "source": "platform",
                    "round_index": round_index,
                    "review_turn_id": review_result.turn_id,
                    "followups": review_result.result.followups[:12],
                },
            )
            exploration_result, exploration_error = invoke_agent(
                phase="rescue_exploration",
                executed_tests=executed_agent_tests,
                round_index=round_index + 1,
            )
            if exploration_result is None:
                rescue_gate.update(
                    {
                        "outcome": "lead_verification_unavailable",
                        "error": exploration_error,
                    }
                )
                debate_policy["outcome"] = rescue_gate["outcome"]
                coverage_gaps.append(
                    "Rescue found an alternate exploit lead, but tool verification was unavailable; "
                    f"the prior negative was not accepted: {exploration_error}"
                )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "rescue.failed",
                    "救援已发现替代攻击链，但工具验证不可用，原负面结论未被接受",
                    {
                        "source": "platform",
                        "round_index": round_index + 1,
                        "error": exploration_error,
                    },
                )
                return current_result

            current_result = exploration_result
            rescue_gate.update(
                {
                    "passed": True,
                    "exploration_thread_id": exploration_result.thread_id,
                    "exploration_turn_id": exploration_result.turn_id,
                    "exploration_result": exploration_result.result.result,
                    "outcome": (
                        "lead_closed_after_tool_exploration"
                        if self._needs_rescue_review(exploration_result.result)
                        else "negative_closure_reopened"
                    ),
                }
            )
            debate_policy["outcome"] = rescue_gate["outcome"]
            self._record_exploration_event(
                scan_id,
                task_id,
                "rescue.completed",
                (
                    "替代攻击链经工具探索后关闭"
                    if self._needs_rescue_review(exploration_result.result)
                    else "原负面结论已被救援推翻，任务恢复为风险验证"
                ),
                {
                    "source": "platform",
                    "round_index": round_index + 1,
                    "exploration_turn_id": exploration_result.turn_id,
                    "result": exploration_result.result.result,
                    "platform_proof": (
                        self.hypothesis_ledger.task_proof_result(task_id) is not None
                    ),
                },
            )

            return current_result

        # A busy non-blocking snapshot remains eligible for the device queue, but
        # an explicit unavailable result should degrade directly to static AI.
        device_ready = bool(
            task.task_type != TaskType.STATIC_REVIEW.value
            and self.device_pool.configured
            and package_name
            and self.device_pool.package_safe(package_name)
            and (device_capability.get("available") or device_capability.get("busy"))
        )
        prebuilt_plans: dict[str, dict[str, Any]] = {}
        if device_ready:
            # Static reasoning and the first PoC build happen before a scarce
            # device is leased. Later adaptive rounds may still rebuild after a
            # concrete runtime failure, but the normal path enters the queue
            # with an executable ProofSpec.
            agent_result, agent_error = invoke_agent(
                phase="test_planning",
                executed_tests=executed_agent_tests,
                round_index=0,
            )
            if agent_result is not None:
                model_rejections = self._rejected_requested_tests(agent_result.result)
                submitted_tests = [
                    item.model_dump(mode="json") for item in agent_result.result.requested_tests
                ]
                submitted_tests.extend(
                    rejection["request"]
                    for rejection in model_rejections
                    if isinstance(rejection.get("request"), dict)
                )
                requested, platform_request_gaps = self._validate_requested_tests(
                    agent_result.result.requested_tests,
                    testable_entries,
                    hypothesis_ids=hypothesis_ids,
                    permission_profile=self.settings.agent_permission_profile,
                )
                request_gaps = [
                    *self._rejected_requested_test_gaps(model_rejections),
                    *platform_request_gaps,
                ]
                poc_artifacts: dict[str, PocBuildResult] = {}
                validated_request_count = len(requested)
                if requested:
                    materialized_workspace = (
                        self.settings.data_dir
                        / "workspaces"
                        / scan_id
                        / "agent_context"
                        / task_id
                        / f"attempt-{task.attempts}"
                    )
                    poc_workspace = agent_runtime_workspaces.get("primary", materialized_workspace)
                    requested, poc_artifacts, poc_build_gaps = self._build_requested_pocs(
                        scan_id=scan_id,
                        task_id=task_id,
                        workspace=poc_workspace,
                        requests=requested,
                        evidence_summaries=evidence_summaries,
                        cancel_event=cancel_event,
                    )
                    request_gaps.extend(poc_build_gaps)
                else:
                    self._set_task_stage(
                        scan_id,
                        task_id,
                        "poc_build",
                        "skipped",
                        reason="no_accepted_proof_request",
                    )
                prebuilt_plans[agent_result.turn_id] = {
                    "model_rejections": model_rejections,
                    "submitted_tests": submitted_tests,
                    "requested": requested,
                    "request_gaps": request_gaps,
                    "poc_artifacts": poc_artifacts,
                }
                prebuilt_plans[agent_result.turn_id]["validated_request_count"] = (
                    validated_request_count
                )
            else:
                self._set_task_stage(
                    scan_id,
                    task_id,
                    "poc_build",
                    "inconclusive",
                    reason="test_planning_unavailable",
                )
        if not device_ready:
            self._set_task_stage(
                scan_id,
                task_id,
                "poc_build",
                "skipped",
                reason="static_or_device_unavailable_path",
            )
            self._set_task_stage(
                scan_id,
                task_id,
                "device_execution",
                "skipped",
                reason="static_or_device_unavailable_path",
            )
            agent_result, agent_error = invoke_agent(
                phase="static_only",
            )
            agent_result = run_negative_rescue(agent_result, round_index=0)
        else:
            try:
                acquire_dynamic_device()
            except Exception as exc:
                coverage_gaps.append(
                    "Dynamic device lease failed before execution "
                    f"({type(exc).__name__}); retained the static-only path."
                )
                self._set_task_stage(
                    scan_id,
                    task_id,
                    "device_execution",
                    "skipped",
                    reason="device_lease_failed",
                )
                agent_result, agent_error = invoke_agent(phase="static_only")
                agent_result = run_negative_rescue(agent_result, round_index=0)
                device_session = None
                task_device = None
            if device_session is not None:
                prepared = False
                target_installed = False
                try:
                    if prepare_dynamic_target():
                        prepared = True
                        for entry in entries:
                            if budget.expired:
                                break
                            probe = task_device.probe(
                                entry, package_name, state="guest", budget=budget
                            )
                            stages["blackbox_attempted"] = True
                            self._record_commands(
                                scan_id, task_id, probe.commands, evidence_summaries
                            )

                        replay_candidates = list(
                            (task.preconditions or {}).get("version_replays", [])
                        )
                        if replay_candidates and not budget.expired:
                            replay_results, replay_gaps = self._execute_version_replays(
                                scan_id=scan_id,
                                task_id=task_id,
                                package_name=package_name,
                                attempt=task.attempts,
                                replay_candidates=replay_candidates,
                                entries=entries,
                                hypothesis_context=hypothesis_context,
                                hypothesis_ids=hypothesis_ids,
                                budget=budget,
                                evidence_summaries=evidence_summaries,
                                cancel_event=cancel_event,
                                device=task_device,
                            )
                            executed_agent_tests.extend(replay_results)
                            coverage_gaps.extend(replay_gaps)

                    replay_proof_terminal = self.hypothesis_ledger.task_all_hypotheses_proven(
                        task_id
                    )
                    initial_executed_test_count = len(executed_agent_tests)
                    if replay_proof_terminal and agent_result is None:
                        release_dynamic_device()
                        agent_result, agent_error = invoke_agent(
                            phase="final_evaluation",
                            executed_tests=executed_agent_tests,
                            round_index=0,
                        )
                    if (
                        agent_result is not None
                        and self._needs_adversarial_review(agent_result.result)
                        and not self._has_requested_test_work(agent_result.result)
                        and not self.hypothesis_ledger.task_all_hypotheses_proven(task_id)
                        and not budget.expired
                    ):
                        release_dynamic_device()
                        candidate_payload = agent_result.result.model_dump(mode="json")
                        critic_result, critic_error = invoke_agent(
                            phase="adversarial_review",
                            candidate_under_review=candidate_payload,
                            round_index=0,
                        )
                        proof_after_critic = self.hypothesis_ledger.task_proof_result(task_id)
                        proof_terminal_after_critic = (
                            self.hypothesis_ledger.task_all_hypotheses_proven(task_id)
                        )
                        if critic_result is not None and not proof_terminal_after_critic:
                            critic_payload = critic_result.result.model_dump(mode="json")
                            material_objections = list(critic_payload.get("review_objections", []))
                            critic_requested_test_count = len(
                                critic_result.result.requested_tests
                            ) + len(self._rejected_requested_tests(critic_result.result))
                            if critic_requested_test_count:
                                coverage_gaps.append(
                                    "Critic proposed device tests, but Critic is evidence-only; "
                                    "the proposals were not scheduled."
                                )
                            if material_objections:
                                debate_context = {
                                    "candidate": candidate_payload,
                                    "critic": critic_payload,
                                    "critic_thread_id": critic_result.thread_id,
                                    "critic_turn_id": critic_result.turn_id,
                                }
                                debate_policy["outcome"] = "critic_objections_require_one_arbiter"
                                merged_result = agent_result.result.model_copy(
                                    update={
                                        "coverage_gaps": list(
                                            dict.fromkeys(
                                                [
                                                    *agent_result.result.coverage_gaps,
                                                    *critic_result.result.coverage_gaps,
                                                ]
                                            )
                                        ),
                                    }
                                )
                                agent_result.result = merged_result
                                self._record_exploration_event(
                                    scan_id,
                                    task_id,
                                    "debate.objections_recorded",
                                    "Critic 提出实质异议，任务仅进入一次最终裁决",
                                    {
                                        "source": "platform",
                                        "candidate_result": candidate_payload.get("result"),
                                        "critic_result": critic_payload.get("result"),
                                        "critic_objection_count": len(material_objections),
                                        "critic_test_proposals_ignored": (
                                            critic_requested_test_count
                                        ),
                                    },
                                )
                            else:
                                debate_policy["outcome"] = "candidate_kept_without_arbiter"
                                self._record_exploration_event(
                                    scan_id,
                                    task_id,
                                    "debate.closed_no_objection",
                                    "Critic 未提出实质异议，保留候选结论并停止辩论",
                                    {
                                        "source": "platform",
                                        "candidate_result": candidate_payload.get("result"),
                                        "critic_result": critic_payload.get("result"),
                                        "critic_objection_count": 0,
                                        "critic_test_proposals_ignored": (
                                            critic_requested_test_count
                                        ),
                                    },
                                )
                        elif critic_result is not None:
                            debate_policy["outcome"] = "platform_proof_stopped_debate"
                            self._record_exploration_event(
                                scan_id,
                                task_id,
                                "debate.discarded_platform_proven",
                                "平台动态证明已形成，Critic 意见仅保留审计且不参与裁决",
                                {
                                    "source": "platform",
                                    "critic_thread_id": critic_result.thread_id,
                                    "critic_turn_id": critic_result.turn_id,
                                    "proof_result": proof_after_critic[0],
                                    "proof_evidence_ids": proof_after_critic[1],
                                },
                            )
                        elif critic_error:
                            debate_policy["outcome"] = "critic_unavailable"
                            coverage_gaps.append(
                                f"Adversarial review was unavailable: {critic_error}"
                            )
                    elif (
                        agent_result is not None
                        and self._needs_adversarial_review(agent_result.result)
                        and not self._has_requested_test_work(agent_result.result)
                        and not self.hypothesis_ledger.task_all_hypotheses_proven(task_id)
                        and budget.expired
                    ):
                        coverage_gaps.append(
                            "Adversarial review could not start because the parent task "
                            "lifecycle had already ended."
                        )
                    completed_rounds = 0
                    while (
                        agent_result
                        and self._has_requested_test_work(agent_result.result)
                        and not self.hypothesis_ledger.task_all_hypotheses_proven(task_id)
                        and prepared
                        and not budget.expired
                        and agent_no_progress_rounds < self.settings.agent_no_progress_limit
                    ):
                        planning_result = agent_result
                        planning_turn_id = planning_result.turn_id
                        prebuilt = prebuilt_plans.pop(planning_turn_id, None)
                        if prebuilt is not None:
                            model_rejections = prebuilt["model_rejections"]
                            submitted_tests = prebuilt["submitted_tests"]
                            requested = prebuilt["requested"]
                            request_gaps = prebuilt["request_gaps"]
                            poc_artifacts = prebuilt["poc_artifacts"]
                        else:
                            model_rejections = self._rejected_requested_tests(
                                planning_result.result
                            )
                            submitted_tests = [
                                item.model_dump(mode="json")
                                for item in planning_result.result.requested_tests
                            ]
                            submitted_tests.extend(
                                rejection["request"]
                                for rejection in model_rejections
                                if isinstance(rejection.get("request"), dict)
                            )
                            requested, platform_request_gaps = self._validate_requested_tests(
                                planning_result.result.requested_tests,
                                testable_entries,
                                hypothesis_ids=hypothesis_ids,
                                permission_profile=self.settings.agent_permission_profile,
                            )
                            request_gaps = [
                                *self._rejected_requested_test_gaps(model_rejections),
                                *platform_request_gaps,
                            ]
                            poc_artifacts: dict[str, PocBuildResult] = {}
                            if requested:
                                materialized_workspace = (
                                    self.settings.data_dir
                                    / "workspaces"
                                    / scan_id
                                    / "agent_context"
                                    / task_id
                                    / f"attempt-{task.attempts}"
                                )
                                poc_workspace = agent_runtime_workspaces.get(
                                    "primary", materialized_workspace
                                )
                                requested, poc_artifacts, poc_build_gaps = (
                                    self._build_requested_pocs(
                                        scan_id=scan_id,
                                        task_id=task_id,
                                        workspace=poc_workspace,
                                        requests=requested,
                                        evidence_summaries=evidence_summaries,
                                        cancel_event=cancel_event,
                                    )
                                )
                                request_gaps.extend(poc_build_gaps)
                        coverage_gaps.extend(request_gaps)
                        for accepted in requested:
                            self._record_exploration_event(
                                scan_id,
                                task_id,
                                "action.accepted",
                                "平台已接受 AI 申请的受控入口测试",
                                {
                                    "source": "platform",
                                    "round_index": completed_rounds,
                                    "entry_point_id": accepted.entry_point_id,
                                    "state": accepted.state,
                                    "rationale_summary": accepted.rationale,
                                    "poc_package": (
                                        accepted.poc.package_name if accepted.poc else None
                                    ),
                                },
                            )
                        if request_gaps or len(requested) < len(submitted_tests):
                            self._record_exploration_event(
                                scan_id,
                                task_id,
                                "action.rejected",
                                "部分 AI 测试申请被平台边界策略拒绝",
                                {
                                    "source": "platform",
                                    "round_index": completed_rounds,
                                    "submitted_count": len(submitted_tests),
                                    "accepted_count": len(requested),
                                    "gaps": request_gaps,
                                },
                            )

                        execution_gaps: list[str] = []
                        executed_this_round: list[dict[str, Any]] = []
                        if requested and not budget.expired:
                            if not device_lease_owned:
                                acquire_dynamic_device()
                                prepared = prepare_dynamic_target()
                            if prepared and task_device is not None:
                                (
                                    executed_this_round,
                                    execution_gaps,
                                ) = self._execute_requested_tests(
                                    scan_id=scan_id,
                                    task_id=task_id,
                                    package_name=package_name,
                                    entries=testable_entries,
                                    requests=requested,
                                    budget=budget,
                                    evidence_summaries=evidence_summaries,
                                    round_index=completed_rounds + 1,
                                    poc_artifacts=poc_artifacts,
                                    device=task_device,
                                )
                                executed_agent_tests.extend(executed_this_round)
                                coverage_gaps.extend(execution_gaps)
                            else:
                                execution_gaps.append(
                                    "The dynamic batch could not prepare its assigned device."
                                )
                                coverage_gaps.extend(execution_gaps)
                            release_dynamic_device()
                        elif requested:
                            execution_gaps.append(
                                "Task budget expired before accepted AI-requested tests ran."
                            )
                            coverage_gaps.extend(execution_gaps)

                        self._record_agent_test_validation(
                            task_id=task_id,
                            turn_id=planning_turn_id,
                            submitted=submitted_tests,
                            accepted=[item.model_dump(mode="json") for item in requested],
                            executed=executed_this_round,
                            gaps=[*request_gaps, *execution_gaps],
                            model_rejected=model_rejections,
                        )
                        for round_handoff in reversed(agent_round_history):
                            if round_handoff.get("turn_id") == planning_turn_id:
                                round_handoff["test_validation"] = {
                                    "submitted": submitted_tests,
                                    "accepted": [
                                        item.model_dump(mode="json") for item in requested
                                    ],
                                    "executed": executed_this_round,
                                    "gaps": [*request_gaps, *execution_gaps],
                                    "model_rejected": model_rejections,
                                }
                                break
                        completed_rounds += 1
                        if self.hypothesis_ledger.task_all_hypotheses_proven(task_id):
                            proof_progress = self.hypothesis_ledger.task_hypothesis_progress(
                                task_id
                            )
                            self._record_exploration_event(
                                scan_id,
                                task_id,
                                "exploration.proof_terminal",
                                "所有漏洞假设均已获得平台危害回执，停止追加探索并进入最终结论",
                                {
                                    "source": "platform",
                                    "round_index": completed_rounds,
                                    "proven_hypothesis_ids": proof_progress[
                                        "proven_hypothesis_ids"
                                    ],
                                },
                            )
                            break
                        if budget.expired:
                            break
                        # Model analysis and any next-round PoC build run without
                        # occupying a scarce device. The next accepted dynamic
                        # batch reacquires the same serial when it is available.
                        release_dynamic_device()
                        next_result, next_error = invoke_agent(
                            phase="exploration_round",
                            executed_tests=executed_agent_tests,
                            round_index=completed_rounds,
                        )
                        if next_result is None:
                            coverage_gaps.append(
                                "Adaptive AI exploration round failed; retained prior result: "
                                f"{next_error}"
                            )
                            break
                        agent_result = next_result
                        agent_error = None

                    if agent_no_progress_rounds >= self.settings.agent_no_progress_limit:
                        coverage_gaps.append(
                            "Dynamic exploration stopped after repeated rounds produced no new "
                            "Evidence, proof state, materially changed test, or hypothesis update."
                        )
                        self._record_exploration_event(
                            scan_id,
                            task_id,
                            "exploration.no_progress_stopped",
                            "连续多轮未产生新的证据或假设进展，动态探索阶段已收尾",
                            {
                                "source": "platform",
                                "consecutive_rounds": agent_no_progress_rounds,
                                "limit": self.settings.agent_no_progress_limit,
                            },
                        )

                    if (
                        (len(executed_agent_tests) > initial_executed_test_count or debate_context)
                        and not replay_proof_terminal
                        and not budget.expired
                    ):
                        release_dynamic_device()
                        final_result, final_error = invoke_agent(
                            phase="final_evaluation",
                            executed_tests=executed_agent_tests,
                            round_index=completed_rounds,
                        )
                        if final_result is not None:
                            agent_result = final_result
                            agent_error = None
                            if debate_context:
                                debate_policy["outcome"] = "arbiter_completed"
                            if self._has_requested_test_work(final_result.result):
                                coverage_gaps.append(
                                    "Final evaluation requested additional tests, but final turns "
                                    "cannot schedule new device actions."
                                )
                        else:
                            if debate_context:
                                debate_policy["outcome"] = "arbiter_unavailable"
                            coverage_gaps.append(
                                "Final AI evaluation failed; retained the latest exploration result: "
                                f"{final_error}"
                            )
                    elif (
                        len(executed_agent_tests) > initial_executed_test_count or debate_context
                    ) and budget.expired:
                        coverage_gaps.append(
                            "Final AI evaluation could not start because the parent task "
                            "lifecycle had already ended; retained the latest validated result."
                        )
                    release_dynamic_device()
                    agent_result = run_negative_rescue(
                        agent_result,
                        round_index=completed_rounds + 1,
                    )
                except AgentCancelledError:
                    raise
                except Exception as exc:
                    coverage_gaps.append(f"Dynamic investigation failed safely: {exc}")
                    if agent_result is None:
                        agent_result, agent_error = invoke_agent(
                            phase="recovery_evaluation",
                        )
                finally:
                    release_dynamic_device()

        self._raise_if_cancelled(cancel_event)
        self._set_task_stage(
            scan_id,
            task_id,
            "impact_evaluation",
            "running",
            proven_hypothesis_count=len(self.hypothesis_ledger.task_proven_hypotheses(task_id)),
        )
        if (
            agent_result is not None
            and self._needs_rescue_review(agent_result.result)
            and rescue_gate.get("triggered")
            and not rescue_gate.get("passed")
        ):
            agent_error = (
                "negative conclusion withheld because the mandatory blind rescue gate "
                "did not complete"
            )
            agent_result = None
        validated_payload: dict[str, Any] | None = None
        validated_result_value: str | None = None
        debate_policy["phase_counts"] = dict(phase_counts)
        if agent_result is None:
            agent_result = self._platform_proof_fallback_result(
                task_id,
                agent_error=agent_error,
            )
        if agent_result:
            raw_payload = agent_result.result.model_dump(mode="json")
            validation_input = deepcopy(raw_payload)
            critic_payload = (
                debate_context.get("critic")
                if isinstance(debate_context, dict)
                else None
            )
            if isinstance(critic_payload, dict):
                critic_objections = critic_payload.get("review_objections", [])
                validation_input["review_objections"] = (
                    [
                        dict(item)
                        for item in critic_objections
                        if isinstance(item, dict)
                    ]
                    if isinstance(critic_objections, list)
                    else []
                )
            validated_payload, validated_result_value = self._validated_agent_payload(
                validation_input, evidence_summaries
            )
            validated_payload = self._validated_hypothesis_payload(
                validated_payload,
                hypothesis_context,
            )
            validated_result_value = str(validated_payload["result"])
            validated_payload["coverage_gaps"] = list(
                dict.fromkeys(
                    [
                        *validated_payload.get("coverage_gaps", []),
                        *coverage_gaps,
                    ]
                )
            )
            if rescue_gate:
                validated_payload["negative_closure_rescue"] = deepcopy(rescue_gate)
            validated_payload["debate_policy"] = deepcopy(debate_policy)
            proven_hypotheses = self.hypothesis_ledger.task_proven_hypotheses(task_id)
            if proven_hypotheses:
                proof_status = FindingStatus.REPRODUCED_BLACKBOX.value
                if validated_result_value != proof_status:
                    validated_payload["coverage_gaps"] = list(
                        dict.fromkeys(
                            [
                                *validated_payload.get("coverage_gaps", []),
                                (
                                    "The platform Prover overrode the model conclusion because a "
                                    "concrete harm Oracle succeeded."
                                ),
                            ]
                        )
                    )
                validated_payload = self._apply_platform_proof_overrides(
                    validated_payload,
                    proven_hypotheses=proven_hypotheses,
                    proven_severity=self.hypothesis_ledger.task_proven_severity(task_id),
                    agent_round_history=agent_round_history,
                    debate_context=debate_context,
                )
                validated_result_value = proof_status
            self._record_agent_validation(
                task_id=task_id,
                turn_id=agent_result.turn_id,
                raw_payload=raw_payload,
                validated_payload=validated_payload,
            )

        self._set_task_stage(
            scan_id,
            task_id,
            "impact_evaluation",
            "completed" if agent_result is not None else "inconclusive",
            result=validated_result_value,
            proven_hypothesis_count=len(self.hypothesis_ledger.task_proven_hypotheses(task_id)),
        )
        self._set_task_stage(
            scan_id,
            task_id,
            "final_synthesis",
            "completed" if agent_result is not None else "inconclusive",
            result=validated_result_value,
        )

        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            scan = session.get(Scan, scan_id)
            assert task is not None and scan is not None
            existing_result = dict(task.result or {})
            terminal_values: dict[str, Any] = {
                "completed_at": now(),
            }
            if agent_result:
                assert validated_payload is not None
                assert validated_result_value is not None
                payload = validated_payload
                result_value = validated_result_value
                terminal_values.update(
                    {
                        "thread_id": agent_result.thread_id,
                        "turn_id": agent_result.turn_id,
                        "result": {
                            **existing_result,
                            **payload,
                            "result": result_value,
                            "agent_backend": agent_backend,
                            "usage": agent_result.usage,
                            "platform_context": {
                                "device": current_device_capability(),
                                "executed_agent_tests": executed_agent_tests,
                                "agent_round_history": agent_round_history,
                                "agent_failures": deepcopy(agent_failures),
                                "hypothesis_progress": (
                                    self.hypothesis_ledger.task_hypothesis_progress(task_id)
                                ),
                            },
                        },
                        "status": (
                            TaskStatus.NOT_REPRODUCED.value
                            if result_value == FindingStatus.NOT_REPRODUCED.value
                            else TaskStatus.COMPLETED.value
                        ),
                    },
                )
            elif budget.expired:
                terminal_values.update(
                    {
                        "status": TaskStatus.TIMED_OUT.value,
                        "error": agent_error or "task time budget exhausted",
                        "result": {
                            **existing_result,
                            "deterministic_evidence": evidence_summaries,
                            "coverage_gaps": coverage_gaps,
                            "agent_backend": agent_backend,
                            "negative_closure_rescue": deepcopy(rescue_gate),
                            "debate_policy": deepcopy(debate_policy),
                            "hypothesis_progress": (
                                self.hypothesis_ledger.task_hypothesis_progress(task_id)
                            ),
                        },
                    },
                )
            elif agent_failures:
                terminal_values.update(
                    {
                        "status": TaskStatus.FAILED.value,
                        "error": agent_error or agent_failures[-1]["error"],
                        "result": {
                            **existing_result,
                            "deterministic_evidence": evidence_summaries,
                            "coverage_gaps": coverage_gaps,
                            "failure_category": "agent_structured_output_or_runtime",
                            "agent_failures": deepcopy(agent_failures),
                            "agent_backend": agent_backend,
                            "device": current_device_capability(),
                            "negative_closure_rescue": deepcopy(rescue_gate),
                            "debate_policy": deepcopy(debate_policy),
                            "hypothesis_progress": (
                                self.hypothesis_ledger.task_hypothesis_progress(task_id)
                            ),
                        },
                    },
                )
            elif stages["device_attempted"]:
                terminal_values.update(
                    {
                        "status": TaskStatus.INCONCLUSIVE.value,
                        "error": agent_error,
                        "result": {
                            **existing_result,
                            "deterministic_evidence": evidence_summaries,
                            "coverage_gaps": [
                                *coverage_gaps,
                                (
                                    f"{agent_backend} semantic investigation was "
                                    "disabled or unavailable."
                                ),
                            ],
                            "agent_backend": agent_backend,
                            "failure_category": (
                                "agent_unavailable"
                                if agent_capability_gap
                                else "evidence_inconclusive"
                            ),
                            "capability_gap": agent_capability_gap,
                            "negative_closure_rescue": deepcopy(rescue_gate),
                            "debate_policy": deepcopy(debate_policy),
                            "hypothesis_progress": (
                                self.hypothesis_ledger.task_hypothesis_progress(task_id)
                            ),
                        },
                    },
                )
            elif task.task_type != TaskType.STATIC_REVIEW.value:
                terminal_values.update(
                    {
                        "status": TaskStatus.BLOCKED_DEVICE.value,
                        "error": agent_error or str(device_capability.get("detail")),
                        "result": {
                            **existing_result,
                            "coverage_gaps": coverage_gaps,
                            "failure_category": "device_unavailable",
                            "device": current_device_capability(),
                            "static_agent_attempted": agent_enabled,
                            "agent_backend": agent_backend,
                            "negative_closure_rescue": deepcopy(rescue_gate),
                            "debate_policy": deepcopy(debate_policy),
                            "hypothesis_progress": (
                                self.hypothesis_ledger.task_hypothesis_progress(task_id)
                            ),
                        },
                    },
                )
            else:
                terminal_values.update(
                    {
                        "status": TaskStatus.INCONCLUSIVE.value,
                        "error": agent_error or "static semantic investigation is unavailable",
                        "result": {
                            **existing_result,
                            "deterministic_evidence": evidence_summaries,
                            "coverage_gaps": coverage_gaps,
                            "failure_category": "agent_unavailable",
                            "agent_backend": agent_backend,
                            "negative_closure_rescue": deepcopy(rescue_gate),
                            "debate_policy": deepcopy(debate_policy),
                            "hypothesis_progress": (
                                self.hypothesis_ledger.task_hypothesis_progress(task_id)
                            ),
                        },
                    },
                )

            transition = session.execute(
                update(InvestigationTask)
                .where(
                    InvestigationTask.id == task_id,
                    InvestigationTask.status == TaskStatus.RUNNING.value,
                )
                .values(**terminal_values)
                .execution_options(synchronize_session=False)
            )
            if transition.rowcount != 1:
                session.rollback()
                current_status = session.scalar(
                    select(InvestigationTask.status).where(InvestigationTask.id == task_id)
                )
                if current_status in {
                    TaskStatus.CANCEL_REQUESTED.value,
                    TaskStatus.DELETED.value,
                }:
                    raise AgentCancelledError("task cancellation won the terminal-state transition")
                return

            # The conditional update is the task's terminal-state linearization
            # point. All terminal findings, coverage, and events are written in
            # the same transaction only after that transition succeeds.
            session.refresh(task)
            if agent_result:
                self.hypothesis_ledger.finalize(
                    task_id=task_id,
                    payload=payload,
                    result_value=result_value,
                    backend=agent_backend,
                    model=self.settings.codex_model,
                    session=session,
                )
                add_event(
                    session,
                    scan_id,
                    "exploration.conclusion.recorded",
                    f"平台已确认 AI 结论：{result_value}",
                    {
                        "task_id": task.id,
                        "source": "platform",
                        "agent_backend": agent_backend,
                        "thread_id": agent_result.thread_id,
                        "turn_id": agent_result.turn_id,
                        "result": result_value,
                        "confidence": payload.get("confidence"),
                        "evidence_ids": payload.get("evidence_ids", []),
                    },
                )
                self._supersede_prior_agent_findings(session, task, result_value, agent_backend)
                self._persist_agent_finding(
                    session,
                    scan,
                    task,
                    entries,
                    result_value,
                    agent_backend,
                )
                self._consolidate_findings(session, scan_id=scan_id)
            self._update_entry_coverage(
                session,
                scan_id,
                task,
                stages=stages,
                agent_completed=agent_result is not None,
                coverage_gaps=coverage_gaps,
            )
            add_event(
                session,
                scan_id,
                "task.completed",
                f"Investigation finished with status {task.status}",
                {
                    "task_id": task.id,
                    "status": task.status,
                    "agent_backend": agent_backend,
                },
            )
            add_event(
                session,
                scan_id,
                "exploration.completed",
                f"入口探索任务结束：{task.status}",
                {
                    "task_id": task.id,
                    "source": "platform",
                    "status": task.status,
                    "agent_backend": agent_backend,
                    "evidence_count": len(evidence_summaries),
                },
            )
            session.commit()

    def _platform_proof_fallback_result(
        self,
        task_id: str,
        *,
        agent_error: str | None,
    ) -> CodexRunResult | None:
        """Keep an immutable platform proof terminal when model finalization fails."""

        proven_hypotheses = self.hypothesis_ledger.task_proven_hypotheses(task_id)
        if not proven_hypotheses:
            return None
        evidence_ids = list(
            dict.fromkeys(
                evidence_id
                for hypothesis_evidence in proven_hypotheses.values()
                for evidence_id in hypothesis_evidence
            )
        )
        result = AgentInvestigationResult(
            summary=(
                "平台已通过普通应用身份、关联执行与危害 Oracle 完成动态证明；"
                "模型最终结构化结论不可用时，保留不可变的平台证明终态。"
            ),
            result=FindingStatus.REPRODUCED_BLACKBOX.value,
            hypotheses_tested=list(proven_hypotheses),
            hypothesis_assessments=[],
            review_objections=[],
            objection_resolutions=[],
            test_cases=[],
            evidence_ids=evidence_ids,
            severity_proposal=(self.hypothesis_ledger.task_proven_severity(task_id) or "medium"),
            confidence="high",
            coverage_gaps=(
                [f"Model finalization failed after platform proof: {agent_error}"]
                if agent_error
                else []
            ),
            followups=[],
            requested_tests=[],
        )
        return CodexRunResult(
            thread_id="platform-proof-fallback",
            turn_id="platform-proof-fallback",
            result=result,
            usage={"source": "platform_proof_fallback"},
        )

    @staticmethod
    def _raise_if_cancelled(cancel_event: threading.Event) -> None:
        if cancel_event.is_set():
            raise AgentCancelledError("investigation was cancelled by the user")

    @staticmethod
    def _annotate_direct_reachability(
        finding: Finding,
        closures_by_entry: dict[str, Any],
    ) -> bool:
        """Record a blocked direct edge without closing indirect vulnerability chains."""

        linked_entries = set(finding.entry_point_ids)
        if not linked_entries or not linked_entries <= set(closures_by_entry):
            return False
        finding.metadata_json = {
            **finding.metadata_json,
            "direct_reachability_assessment": {
                "status": "blocked",
                "scope": "ordinary_app_direct_invocation_only",
                "indirect_chain_paths_evaluated": False,
                "threat_model": "ordinary_app_uid",
                "entry_decisions": [
                    closures_by_entry[entry_id].as_dict() for entry_id in sorted(linked_entries)
                ],
            },
        }
        return True

    def _mark_task_canceled(self, scan_id: str, task_id: str) -> None:
        with self.database.session_factory() as session:
            for _attempt in range(3):
                task = session.get(InvestigationTask, task_id)
                if task is None:
                    return
                observed_status = task.status
                completed_at = now()
                existing_cancellation = dict((task.result or {}).get("cancellation") or {})
                if observed_status == TaskStatus.DELETED.value:
                    cancellation_result = {
                        **dict(task.result or {}),
                        "cancellation": {
                            **existing_cancellation,
                            "requested": True,
                            "acknowledged": True,
                            "completed_at": completed_at.isoformat(),
                        },
                    }
                    transition_values = {"result": cancellation_result}
                elif observed_status in {
                    TaskStatus.QUEUED.value,
                    TaskStatus.RUNNING.value,
                    TaskStatus.AWAITING_DEVICE.value,
                    TaskStatus.CANCEL_REQUESTED.value,
                }:
                    cancellation_result = {
                        **dict(task.result or {}),
                        "cancellation": {
                            **existing_cancellation,
                            "requested": True,
                            "acknowledged": True,
                            "completed_at": completed_at.isoformat(),
                        },
                    }
                    transition_values = {
                        "status": TaskStatus.CANCELED.value,
                        "error": "用户已停止本次分析",
                        "completed_at": completed_at,
                        "result": cancellation_result,
                    }
                elif (
                    observed_status == TaskStatus.CANCELED.value
                    and existing_cancellation.get("requested") is True
                    and "completed_at" not in existing_cancellation
                ):
                    cancellation_result = {
                        **dict(task.result or {}),
                        "cancellation": {
                            **existing_cancellation,
                            "acknowledged": True,
                            "completed_at": completed_at.isoformat(),
                        },
                    }
                    transition_values = {"result": cancellation_result}
                else:
                    # A completion/failure transition that won before cancellation
                    # is already authoritative and must never be overwritten.
                    return

                transition = session.execute(
                    update(InvestigationTask)
                    .where(
                        InvestigationTask.id == task_id,
                        InvestigationTask.status == observed_status,
                    )
                    .values(**transition_values)
                    .execution_options(synchronize_session=False)
                )
                if transition.rowcount == 1:
                    session.refresh(task)
                    break
                session.rollback()
            else:
                return

            if observed_status == TaskStatus.DELETED.value:
                coverage = list(
                    session.scalars(
                        select(CoverageItem).where(
                            CoverageItem.scan_id == scan_id,
                            CoverageItem.entry_point_id.in_(task.target_entry_ids),
                        )
                    )
                )
                for item in coverage:
                    item.status = "partial"
                    item.gap_reason = "入口探索由用户主动停止并从任务列表删除，未形成最终判断。"
                    item.stages = {
                        **item.stages,
                        "agent": "cancelled",
                    }
                add_event(
                    session,
                    scan_id,
                    "task.cancelled_after_deletion",
                    "已删除任务的后台运行时完成停止确认",
                    {
                        "task_id": task_id,
                        "status": TaskStatus.DELETED.value,
                        "hidden": True,
                    },
                )
                session.commit()
                return
            coverage = list(
                session.scalars(
                    select(CoverageItem).where(
                        CoverageItem.scan_id == scan_id,
                        CoverageItem.entry_point_id.in_(task.target_entry_ids),
                    )
                )
            )
            for item in coverage:
                item.status = "partial"
                item.gap_reason = "入口探索由用户主动停止，未形成最终判断。"
                item.stages = {
                    **item.stages,
                    "agent": "cancelled",
                }
            add_event(
                session,
                scan_id,
                "task.cancelled",
                "用户已停止入口探索任务",
                {"task_id": task_id, "status": TaskStatus.CANCELED.value},
            )
            add_event(
                session,
                scan_id,
                "exploration.cancelled",
                "AI 分析已停止，未生成新的最终结论",
                {
                    "task_id": task_id,
                    "source": "platform",
                    "status": TaskStatus.CANCELED.value,
                },
            )
            session.commit()

    @staticmethod
    def _needs_adversarial_review(result: Any) -> bool:
        """Spend a critic turn only on a material positive claim."""

        return str(getattr(result, "result", FindingStatus.REFUTED_STATIC.value)) in {
            FindingStatus.SUPPORTED_STATIC.value,
            FindingStatus.REPRODUCED_BLACKBOX.value,
        } and (
            str(getattr(result, "severity_proposal", "info")) != "info"
            or str(getattr(result, "confidence", "low")) == "high"
        )

    @staticmethod
    def _needs_rescue_review(result: Any) -> bool:
        """Return whether a result is a negative eligible for the rescue policy."""

        return str(getattr(result, "result", FindingStatus.REFUTED_STATIC.value)) in {
            FindingStatus.REFUTED_STATIC.value,
            FindingStatus.NOT_REPRODUCED.value,
        }

    def _rescue_decision(
        self,
        task: InvestigationTask,
        result: Any,
        *,
        target_code_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Gate expensive blind rescue by risk, uncertainty, and sampled quality audit."""

        reasons: list[str] = []
        if int(task.priority) >= 95:
            reasons.append("high_priority_entry")
        text = " ".join(
            [
                *(str(value).lower() for value in task.hypotheses or []),
                str(getattr(result, "summary", "")).lower(),
            ]
        )
        complex_terms = {
            "binder",
            "webview",
            "javascript",
            "pendingintent",
            "nested intent",
            "uri grant",
            "native",
            "plugin",
            "classloader",
            "socket",
            "token",
            "credential",
            "payment",
            "account",
        }
        matched_terms = sorted(term for term in complex_terms if term in text)
        if matched_terms:
            reasons.append("complex_boundary:" + ",".join(matched_terms[:5]))
        if list(getattr(result, "coverage_gaps", []) or []):
            reasons.append("coverage_gap")
        components = target_code_context.get("components", [])
        # The code index emits source_available / partial_source_available /
        # smali_fallback / target_decompilation_failed / source_not_found.  The old
        # {"complete", "available"} vocabulary never matched, so every task with a
        # resolved component was classified partial and forced through blind rescue.
        if any(
            isinstance(component, dict)
            and str(component.get("status") or "")
            not in {
                "source_available",
                "smali_fallback",
                "static_signal_source_available",
            }
            for component in components
        ):
            reasons.append("partial_static_context")
        digest = hashlib.sha256(task.id.encode()).digest()
        sample_value = int.from_bytes(digest[:8], "big") / float(2**64)
        sampled = sample_value < self.settings.rescue_audit_sample_rate
        if sampled:
            reasons.append("quality_audit_sample")
        return {
            "schema_version": "1.0",
            "triggered": bool(reasons),
            "reasons": reasons,
            "sampled": sampled,
            "sample_rate": self.settings.rescue_audit_sample_rate,
        }

    @staticmethod
    def _candidate_evidence_ids(
        candidate: dict[str, Any] | None,
    ) -> set[str]:
        """Limit Critic input to evidence the candidate actually relied on."""

        if not isinstance(candidate, dict):
            return set()
        evidence_ids: set[str] = set()

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "evidence_ids" and isinstance(item, list):
                        evidence_ids.update(
                            evidence_id for evidence_id in item if isinstance(evidence_id, str)
                        )
                    elif key in {
                        "hypothesis_assessments",
                        "test_cases",
                        "platform_proof_overrides",
                    }:
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(candidate)
        return evidence_ids

    @staticmethod
    def _requested_test_signature(request: AgentRequestedTest) -> str:
        payload = request.model_dump(mode="json")
        # Rationale is audit prose, not part of the device action identity.
        # Keep the hypothesis in the signature so one physical input is not
        # silently attributed to a different proof obligation.
        payload.pop("rationale", None)
        return json.dumps(payload, sort_keys=True)

    @staticmethod
    def _rejected_requested_tests(result: Any) -> list[dict[str, Any]]:
        rejected = getattr(result, "rejected_requested_tests", [])
        if not isinstance(rejected, list):
            return []
        return deepcopy([item for item in rejected if isinstance(item, dict)])

    @staticmethod
    def _normalization_repairs(result: Any) -> list[dict[str, Any]]:
        repairs = getattr(result, "normalization_repairs", [])
        if not isinstance(repairs, list):
            return []
        return deepcopy([item for item in repairs if isinstance(item, dict)])

    @classmethod
    def _has_requested_test_work(cls, result: Any) -> bool:
        return bool(getattr(result, "requested_tests", []) or cls._rejected_requested_tests(result))

    @staticmethod
    def _rejected_requested_test_gaps(
        rejected: list[dict[str, Any]],
    ) -> list[str]:
        gaps: list[str] = []
        for fallback_index, item in enumerate(rejected):
            index = item.get("index", fallback_index)
            errors = item.get("errors")
            if not isinstance(errors, list) or not errors:
                gaps.append(f"requested_tests[{index}] failed model schema validation.")
                continue
            for error in errors:
                if not isinstance(error, dict):
                    continue
                location = str(error.get("location") or "<request>")
                message = str(error.get("message") or "invalid request")
                error_type = str(error.get("type") or "validation_error")
                gaps.append(
                    f"requested_tests[{index}] schema validation failed at "
                    f"{location}: {message} ({error_type})"
                )
        return gaps

    @staticmethod
    def _validate_requested_tests(
        requests: list[AgentRequestedTest],
        entries: list[EntryPoint],
        *,
        hypothesis_ids: set[str] | None = None,
        permission_profile: str = "personal_lab",
    ) -> tuple[list[AgentRequestedTest], list[str]]:
        entries_by_id = {entry.id: entry for entry in entries}
        accepted: list[AgentRequestedTest] = []
        gaps: list[str] = []
        seen: set[str] = set()
        for request in requests:
            entry = entries_by_id.get(request.entry_point_id)
            if (
                entry is not None
                and entry.kind != "provider"
                and request.operation not in {"binder_transact", "binder_script"}
                and (
                    request.operation != "auto"
                    or request.method is not None
                    or request.argument is not None
                )
            ):
                # These fields have no execution meaning outside a
                # ContentProvider. Ignore model field contamination instead
                # of discarding an otherwise valid Activity/Service/Receiver
                # or deep-link PoC.
                request = request.model_copy(
                    update={
                        "operation": "auto",
                        "method": None,
                        "argument": None,
                    }
                )
            if (
                entry is not None
                and entry.kind != "provider"
                and request.oracle.kind == "provider_rows"
            ):
                request = request.model_copy(
                    update={
                        "oracle": AgentOracleSpec(
                            kind="reachability",
                            impact="none",
                            refute_on_miss=request.oracle.refute_on_miss,
                        )
                    }
                )
            reason = None
            if entry is None:
                reason = "entry point is outside this task"
            elif hypothesis_ids and request.hypothesis_id is None:
                reason = "hypothesis_id is required for an auditable proof attempt"
            elif (
                request.hypothesis_id is not None
                and hypothesis_ids is not None
                and request.hypothesis_id not in hypothesis_ids
            ):
                reason = "hypothesis is outside this task"
            elif any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", key) for key in request.extras):
                reason = "an extra key is unsafe"
            elif any(
                (isinstance(value, str) and len(value) > 1000)
                or (isinstance(value, int) and not -(2**63) <= value < 2**63)
                for value in request.extras.values()
            ):
                reason = "an extra value exceeds its safety bound"
            elif entry.kind == "provider" and request.extras and request.poc is None:
                if request.operation in {"auto", "query", "delete"}:
                    reason = (
                        "provider query/delete probes do not accept values; use a call, "
                        "insert, or update operation"
                    )
            elif request.oracle.kind == "provider_rows" and request.operation not in {
                "auto",
                "query",
            }:
                reason = "provider_rows Oracle requires a provider query operation"
            elif (
                request.operation in {"binder_transact", "binder_script"}
                and entry.kind != "service"
            ):
                reason = f"{request.operation} is allowed only for Service entries"
            elif (
                entry.kind == "service"
                and request.oracle.kind == "log_contains"
                and request.oracle.impact != "none"
            ):
                # AgentRequestedTest already requires binder_reply for
                # binder_transact/binder_script, but an auto PoC plus a
                # self-reported log is the remaining way a Binder hypothesis
                # burns a device round without an observable impact channel.
                reason = (
                    "a Service PoC's own log cannot establish Binder harm; use "
                    "operation=binder_transact with a binder_reply Oracle"
                )
            elif (request.intent_action or request.categories) and entry.kind == "provider":
                reason = "provider requests do not accept Intent routing fields"
            elif (
                request.poc is not None
                and request.poc.prebuilt_apk_path is not None
                and permission_profile != "personal_lab"
            ):
                reason = "prebuilt Agent APKs require the personal_lab permission profile"
            elif request.uri is not None:
                reason = ScanOrchestrator._validate_requested_uri(entry, request.uri)
            elif entry.kind == "deep_link" and not entry.name:
                reason = "deep-link URI is unavailable"
            if reason:
                gaps.append(
                    f"Rejected agent-requested test for {request.entry_point_id}: {reason}."
                )
                continue
            signature = ScanOrchestrator._requested_test_signature(request)
            if signature in seen:
                continue
            seen.add(signature)
            accepted.append(request)
        return accepted, gaps

    @staticmethod
    def _poc_request_key(request: AgentRequestedTest) -> str:
        if request.poc is None:
            return "platform:" + ScanOrchestrator._requested_test_signature(request)
        return "agent:" + json.dumps(request.poc.model_dump(mode="json"), sort_keys=True)

    def _execute_version_replays(
        self,
        *,
        scan_id: str,
        task_id: str,
        package_name: str,
        attempt: int,
        replay_candidates: list[dict[str, Any]],
        entries: list[EntryPoint],
        hypothesis_context: list[dict[str, Any]],
        hypothesis_ids: set[str],
        budget: TimeBudget,
        evidence_summaries: list[dict[str, Any]],
        cancel_event: threading.Event,
        device: AdbDeviceAdapter,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Migrate proven source PoCs and replay them before fresh exploration."""
        workspace = (
            self.settings.data_dir
            / "workspaces"
            / scan_id
            / "agent_context"
            / task_id
            / f"attempt-{attempt}"
        )
        poc_root = workspace / "poc"
        poc_root.mkdir(parents=True, exist_ok=True)
        entries_by_id = {entry.id: entry for entry in entries}
        requests: list[AgentRequestedTest] = []
        gaps: list[str] = []
        for index, replay in enumerate(replay_candidates, start=1):
            target_entry_id = str(replay.get("target_entry_id") or "")
            if target_entry_id not in entries_by_id:
                gaps.append(
                    f"Version replay skipped: target entry {target_entry_id} is not testable."
                )
                continue
            source_hypothesis = dict(replay.get("source_hypothesis") or {})
            hypothesis_id = next(
                (
                    str(item["id"])
                    for item in hypothesis_context
                    if (
                        item.get("claim") == source_hypothesis.get("claim")
                        or item.get("category") == source_hypothesis.get("category")
                    )
                    and target_entry_id in item.get("entry_point_ids", [])
                ),
                next(
                    (
                        str(item["id"])
                        for item in hypothesis_context
                        if target_entry_id in item.get("entry_point_ids", [])
                    ),
                    next(iter(hypothesis_ids), ""),
                ),
            )
            substitutions: dict[str, str] = {}
            old_manifest = dict((replay.get("baseline_entry") or {}).get("manifest") or {})
            new_manifest = dict((replay.get("target_entry") or {}).get("manifest") or {})
            for key in ("name", "owner_component", "authorities"):
                old_value = old_manifest.get(key)
                new_value = new_manifest.get(key)
                if old_value and new_value and old_value != new_value:
                    substitutions[str(old_value)] = str(new_value)
            try:
                recipe_payload = replay.get("proof_recipe")
                recipe = (
                    ProofRecipe.model_validate(recipe_payload)
                    if isinstance(recipe_payload, dict)
                    else proof_recipe_from_plan(dict(replay.get("plan") or {}))
                )
            except ValueError as exc:
                gaps.append(f"Version replay ProofRecipe is invalid: {exc}.")
                continue
            if recipe is None:
                gaps.append("Version replay skipped: no portable ProofRecipe is available.")
                continue
            project_path: str | None = None
            source_sha: str | None = None
            if recipe.source_archive_required:
                source_path = Path(str(replay.get("source_archive_path") or ""))
                if not source_path.is_file():
                    gaps.append("Version replay skipped: archived Agent PoC source is unavailable.")
                    continue
                source_bytes = source_path.read_bytes()
                source_sha = hashlib.sha256(source_bytes).hexdigest()
                expected_sha = str(replay.get("source_archive_sha256") or "")
                if expected_sha and source_sha != expected_sha:
                    gaps.append("Version replay skipped: archived PoC source hash mismatch.")
                    continue
                project = poc_root / f"version-replay-{index}"
                if project.exists():
                    shutil.rmtree(project)
                project.mkdir(parents=True)
                try:
                    with zipfile.ZipFile(source_path) as archive:
                        members = [member for member in archive.infolist() if not member.is_dir()]
                        source_size = sum(item.file_size for item in members)
                        if len(members) > 64 or source_size > self.settings.poc_max_source_bytes:
                            raise ValueError("archived PoC exceeds source safety limits")
                        for member in members:
                            destination = (project / member.filename).resolve()
                            if (
                                not destination.is_relative_to(project.resolve())
                                or member.filename.startswith("/")
                                or ".." in Path(member.filename).parts
                            ):
                                raise ValueError("archived PoC contains an unsafe path")
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            destination.write_bytes(archive.read(member))
                except (OSError, ValueError, zipfile.BadZipFile) as exc:
                    gaps.append(f"Version replay source migration failed: {exc}.")
                    continue
                for source in [*project.rglob("*.java"), *project.rglob("*.xml")]:
                    content = source.read_text(encoding="utf-8")
                    for old_value, new_value in substitutions.items():
                        content = content.replace(old_value, new_value)
                    source.write_text(content, encoding="utf-8")
                project_path = str(project.relative_to(workspace))
            try:
                requests.append(
                    bind_proof_recipe(
                        recipe,
                        hypothesis_id=hypothesis_id,
                        entry_point_id=target_entry_id,
                        project_path=project_path,
                        substitutions=substitutions,
                    )
                )
            except Exception as exc:
                gaps.append(f"Version replay plan migration failed validation: {exc}.")
                continue
            self._record_exploration_event(
                scan_id,
                task_id,
                "version_replay.migrated",
                (
                    "旧版本 ProofRecipe 已绑定当前入口，平台将重新生成验证 Harness"
                    if recipe.execution_mode == "platform_harness"
                    else "旧版本 Dynamic Experiment 已绑定当前入口并等待重新执行"
                    if recipe.execution_mode == "dynamic_experiment"
                    else "旧版本 ProofRecipe 与 PoC 源码已迁移到当前版本任务工作区"
                ),
                {
                    "source_finding_id": replay.get("source_finding_id"),
                    "source_proof_attempt_id": replay.get("source_proof_attempt_id"),
                    "target_entry_id": target_entry_id,
                    "proof_recipe_fingerprint": recipe.fingerprint,
                    "proof_execution_mode": recipe.execution_mode,
                    "source_sha256": source_sha,
                    "substitutions": substitutions,
                },
            )
        accepted, validation_gaps = self._validate_requested_tests(
            requests,
            entries,
            hypothesis_ids=hypothesis_ids,
            permission_profile=self.settings.agent_permission_profile,
        )
        gaps.extend(validation_gaps)
        if not accepted:
            return [], gaps
        accepted, artifacts, build_gaps = self._build_requested_pocs(
            scan_id=scan_id,
            task_id=task_id,
            workspace=workspace,
            requests=accepted,
            evidence_summaries=evidence_summaries,
            cancel_event=cancel_event,
        )
        gaps.extend(build_gaps)
        if not accepted or budget.expired:
            return [], gaps
        executed, execution_gaps = self._execute_requested_tests(
            scan_id=scan_id,
            task_id=task_id,
            package_name=package_name,
            entries=entries,
            requests=accepted,
            budget=budget,
            evidence_summaries=evidence_summaries,
            round_index=0,
            poc_artifacts=artifacts,
            device=device,
        )
        gaps.extend(execution_gaps)
        self._record_exploration_event(
            scan_id,
            task_id,
            "version_replay.completed",
            "旧 Finding 的 PoC 已在当前版本完成平台回放",
            {
                "requested_count": len(requests),
                "executed_count": len(executed),
                "gaps": gaps,
            },
        )
        return executed, gaps

    def _build_requested_pocs(
        self,
        *,
        scan_id: str,
        task_id: str,
        workspace: Path,
        requests: list[AgentRequestedTest],
        evidence_summaries: list[dict[str, Any]],
        cancel_event: threading.Event,
    ) -> tuple[list[AgentRequestedTest], dict[str, PocBuildResult], list[str]]:
        experiment_requests = [request for request in requests if request.experiment is not None]
        build_requests = [request for request in requests if request.experiment is None]
        accepted: list[AgentRequestedTest] = list(experiment_requests)
        artifacts: dict[str, PocBuildResult] = {}
        gaps: list[str] = []
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            target_package = scan.package_name if scan is not None else None
            requested_entry_ids = {request.entry_point_id for request in requests}
            requested_entries = {
                entry.id: entry
                for entry in session.scalars(
                    select(EntryPoint).where(EntryPoint.id.in_(requested_entry_ids))
                )
            }
        if build_requests:
            self._set_task_stage(
                scan_id,
                task_id,
                "poc_build",
                "running",
                requested_count=len(build_requests),
            )
        for request in build_requests:
            key = self._poc_request_key(request)
            outcome = artifacts.get(key)
            if outcome is None:
                request_entry = requested_entries.get(request.entry_point_id)
                provider_request = request_entry is not None and request_entry.kind == "provider"
                platform_owned = request.poc is None
                spec = request.poc
                if platform_owned:
                    if target_package is None or request_entry is None:
                        outcome = PocBuildResult(
                            ok=False,
                            error="target package or requested entry is unavailable",
                        )
                    else:
                        authorities = [
                            authority.strip()
                            for authority in str(
                                (request_entry.metadata_json or {}).get("authorities") or ""
                            ).split(";")
                            if authority.strip()
                        ]
                        try:
                            spec = self.poc_builder.materialize_proof_harness(
                                workspace,
                                request,
                                entry_kind=request_entry.kind,
                                target_package_name=target_package,
                                target_component=(
                                    request_entry.owner_component
                                    or (
                                        None
                                        if request_entry.kind == "deep_link"
                                        else request_entry.name
                                    )
                                ),
                                default_uri=(
                                    request_entry.name
                                    if request_entry.kind == "deep_link"
                                    else None
                                ),
                                provider_authority=(authorities[0] if authorities else None),
                            )
                        except (OSError, ValueError) as exc:
                            outcome = PocBuildResult(
                                ok=False,
                                error=f"platform proof Harness generation failed: {exc}",
                            )
                assert spec is not None or outcome is not None
                package = spec.package_name if spec is not None else None
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "poc.build.started",
                    (
                        "开始构建平台临时验证 Harness"
                        if platform_owned
                        else "开始构建 Agent 生成的受控 PoC APK"
                    ),
                    {
                        "source": "platform",
                        "hypothesis_id": request.hypothesis_id,
                        "entry_point_id": request.entry_point_id,
                        "package": package,
                        "project_path": (spec.project_path if spec is not None else None),
                        "platform_generated_proof": platform_owned,
                    },
                )
                if outcome is None:
                    acquired_build_slot = False
                    try:
                        while not acquired_build_slot:
                            self._raise_if_cancelled(cancel_event)
                            acquired_build_slot = self._build_slots.acquire(timeout=0.5)
                        outcome = self.poc_builder.build(
                            workspace,
                            spec,
                            oracle=request.oracle,
                            cancel_event=cancel_event,
                            # Android 11+ package visibility applies to explicit component
                            # interactions too. Every ordinary-app proof therefore names the
                            # target package in <queries>.
                            visible_packages=((target_package,) if target_package else ()),
                            visible_provider_authorities=tuple(
                                authority.strip()
                                for authority in str(
                                    (
                                        request_entry.metadata_json
                                        if provider_request and request_entry
                                        else {}
                                    ).get("authorities")
                                    or ""
                                ).split(";")
                                if authority.strip()
                            ),
                        )
                    finally:
                        if acquired_build_slot:
                            self._build_slots.release()
                if platform_owned:
                    outcome.metadata.update(
                        {
                            "caller_identity": "platform_generated_poc",
                            "platform_generated_proof": True,
                            "proof_operation": request.operation,
                        }
                    )
                artifacts[key] = outcome
                if outcome.commands:
                    self._record_commands(
                        scan_id,
                        task_id,
                        outcome.commands,
                        evidence_summaries,
                    )
                if outcome.ok:
                    with self.database.session_factory() as session:
                        evidence = self.evidence.json(
                            session,
                            scan_id=scan_id,
                            task_id=task_id,
                            kind="poc.build_artifact",
                            value={
                                "schema_version": "1.0",
                                "spec": (outcome.effective_spec or spec).model_dump(mode="json"),
                                **outcome.metadata,
                            },
                            summary=(
                                "Platform built and signed an ephemeral proof Harness APK "
                                f"{outcome.apk_sha256}"
                                if platform_owned
                                else f"Platform built and signed an Agent PoC APK {outcome.apk_sha256}"
                            ),
                            metadata={
                                **outcome.metadata,
                                "hypothesis_id": request.hypothesis_id,
                                "entry_point_id": request.entry_point_id,
                            },
                        )
                        session.commit()
                        evidence_summaries.append(self._evidence_summary(evidence))
                        outcome.metadata["build_evidence_id"] = evidence.id
                    self._record_exploration_event(
                        scan_id,
                        task_id,
                        "poc.build.completed",
                        (
                            "平台临时验证 Harness 已完成构建、签名和哈希登记"
                            if platform_owned
                            else "Agent PoC 已完成受控构建、签名和哈希登记"
                        ),
                        {
                            "source": "platform",
                            "package": package,
                            "apk_sha256": outcome.apk_sha256,
                            "source_sha256": outcome.source_sha256,
                            "evidence_id": outcome.metadata.get("build_evidence_id"),
                            "platform_generated_proof": platform_owned,
                        },
                    )
                else:
                    self._record_exploration_event(
                        scan_id,
                        task_id,
                        "poc.build.failed",
                        (
                            "平台临时验证 Harness 构建失败，未进入设备队列"
                            if platform_owned
                            else "Agent PoC 构建失败，未进入设备队列"
                        ),
                        {
                            "source": "platform",
                            "package": package,
                            "error": outcome.error,
                            "platform_generated_proof": platform_owned,
                        },
                    )
            if outcome.ok:
                effective_request = request
                if (
                    request.poc is not None
                    and outcome.effective_spec is not None
                    and outcome.effective_spec != request.poc
                ):
                    effective_request = request.model_copy(update={"poc": outcome.effective_spec})
                    artifacts[self._poc_request_key(effective_request)] = outcome
                accepted.append(effective_request)
            else:
                gaps.append(
                    "Rejected ordinary-app proof test for "
                    f"{request.entry_point_id}: {outcome.error or 'build failed'}."
                )
        if build_requests:
            self._set_task_stage(
                scan_id,
                task_id,
                "poc_build",
                "completed" if not gaps else "inconclusive",
                accepted_count=sum(request.experiment is None for request in accepted),
                gap_count=len(gaps),
                artifact_count=len(
                    {
                        artifact.apk_sha256
                        for artifact in artifacts.values()
                        if artifact.ok and artifact.apk_sha256
                    }
                ),
                platform_harness_requested_count=sum(
                    request.poc is None for request in build_requests
                ),
                platform_harness_built_count=sum(
                    request.experiment is None and request.poc is None for request in accepted
                ),
                agent_poc_requested_count=sum(
                    request.poc is not None for request in build_requests
                ),
                agent_poc_built_count=sum(
                    request.experiment is None and request.poc is not None for request in accepted
                ),
            )
        elif experiment_requests:
            self._set_task_stage(
                scan_id,
                task_id,
                "poc_build",
                "skipped",
                reason="dynamic_experiment_requires_no_apk_build",
                experiment_count=len(experiment_requests),
            )
        return accepted, artifacts, gaps

    @staticmethod
    def _validate_requested_uri(entry: EntryPoint, value: str) -> str | None:
        if len(value) > 4096 or any(character in value for character in "\r\n\x00"):
            return "URI is oversized or contains control characters"
        try:
            candidate = urlsplit(value)
        except ValueError:
            return "URI cannot be parsed"
        if candidate.username or candidate.password:
            return "URI user-info is not allowed"
        if entry.kind in {"deep_link", "activity", "activity_alias"}:
            declared_uris = (
                [entry.name]
                if entry.kind == "deep_link"
                else [
                    str(item.get("uri_template"))
                    for item in entry.deep_links
                    if isinstance(item, dict) and item.get("uri_template")
                ]
            )
            expected_origins: set[tuple[str, str, int | None]] = set()
            try:
                actual = (
                    candidate.scheme.lower(),
                    (candidate.hostname or "").lower(),
                    candidate.port,
                )
                for declared_uri in declared_uris:
                    baseline = urlsplit(declared_uri)
                    expected_origins.add(
                        (
                            baseline.scheme.lower(),
                            (baseline.hostname or "").lower(),
                            baseline.port,
                        )
                    )
            except ValueError:
                return "URI authority or port is invalid"
            if not expected_origins:
                return "activity has no manifest-declared deep-link origin"
            if actual not in expected_origins:
                return "URI must preserve the manifest-declared scheme, host, and port"
            return None
        if entry.kind == "provider":
            authorities = {
                item.strip()
                for item in str(entry.metadata_json.get("authorities") or "").split(";")
                if item.strip()
            }
            if candidate.scheme != "content" or candidate.netloc not in authorities:
                return "provider URI must preserve a manifest-declared authority"
            return None
        return "URI overrides are allowed only for deep links and providers"

    def _execute_requested_tests(
        self,
        *,
        scan_id: str,
        task_id: str,
        package_name: str,
        entries: list[EntryPoint],
        requests: list[AgentRequestedTest],
        budget: TimeBudget,
        evidence_summaries: list[dict[str, Any]],
        round_index: int,
        poc_artifacts: dict[str, PocBuildResult] | None = None,
        device: AdbDeviceAdapter | None = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        if device is None:
            return [], ["No task-scoped ADB device lease is available."]
        active_device = device
        device_profile = active_device.capability(non_blocking=False)
        runtime_verdict_metadata = {
            key: device_profile.get(key)
            for key in (
                "validation_profile",
                "android16_verdict_eligible",
                "dynamic_verdict_eligible",
                "release_gate_eligible",
                "compatibility_smoke_only",
                "verdict_scope",
            )
        }
        device_api_level = device_profile.get("api_level")
        poc_artifacts = poc_artifacts or {}
        indexed = [
            (f"agent-r{round_index}-{index + 1}", request) for index, request in enumerate(requests)
        ]
        executed: list[dict[str, Any]] = []
        gaps: list[str] = []
        for state in ("guest",):
            state_requests = [item for item in indexed if item[1].state == state]
            if not state_requests or budget.expired:
                continue
            for test_case_id, request in state_requests:
                if budget.expired:
                    gaps.append("Task budget expired before all agent-requested tests ran.")
                    break
                requested_reset = request.reset
                if self.settings.device_reset_policy == "never" and request.reset != "preserve":
                    # ``never`` is a hard operator policy: model-authored Proof requests cannot
                    # silently destroy an authenticated target session or first-run consent state.
                    request = request.model_copy(update={"reset": "preserve"})
                before = len(evidence_summaries)
                proof_attempt_id = self.hypothesis_ledger.plan_proof(
                    task_id=task_id,
                    test_case_id=test_case_id,
                    request=request,
                )
                self.hypothesis_ledger.start_proof(proof_attempt_id)
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "action.started",
                    f"开始执行 AI 申请的 {state} 状态入口测试",
                    {
                        "source": "platform",
                        "test_case_id": test_case_id,
                        "hypothesis_id": request.hypothesis_id,
                        "entry_point_id": request.entry_point_id,
                        "state": state,
                        "rationale_summary": request.rationale,
                        "poc_package": (request.poc.package_name if request.poc else None),
                        "operation": request.operation,
                        "reset": request.reset,
                        "requested_reset": requested_reset,
                        "reset_overridden_by_policy": requested_reset != request.reset,
                        "oracle": request.oracle.model_dump(mode="json"),
                        "execution_mode": (
                            "dynamic_experiment"
                            if request.experiment is not None
                            else "android_poc"
                        ),
                    },
                )

                if request.experiment is not None:
                    experiment_result, experiment_error = (
                        self._execute_requested_dynamic_experiment(
                            scan_id=scan_id,
                            task_id=task_id,
                            test_case_id=test_case_id,
                            proof_attempt_id=proof_attempt_id,
                            request=request,
                            device=active_device,
                            runtime_verdict_metadata=runtime_verdict_metadata,
                            evidence_summaries=evidence_summaries,
                        )
                    )
                    if experiment_error is not None:
                        gaps.append(experiment_error)
                    if experiment_result is not None:
                        executed.append(experiment_result)
                    continue

                def tagged(commands, *, case_id: str = test_case_id):  # noqa: ANN001, ANN202
                    return [
                        (
                            kind,
                            result,
                            {
                                **dict(metadata),
                                "test_case_id": case_id,
                                "device_api": (
                                    dict(metadata).get("device_api") or device_api_level
                                ),
                                **runtime_verdict_metadata,
                            },
                        )
                        for kind, result, metadata in commands
                    ]

                should_reset = self.settings.device_reset_policy != "never" and (
                    request.reset == "clean"
                    or (
                        request.reset == "inherit"
                        and self.settings.device_reset_policy == "per_test"
                    )
                )
                if should_reset:
                    reset = tagged(active_device.reset_session(package_name, budget))
                    self._record_commands(scan_id, task_id, reset, evidence_summaries)
                    if any(result.exit_code != 0 for _kind, result, _metadata in reset):
                        proof_evidence = evidence_summaries[before:]
                        error = f"Could not reset the device for {state} test {test_case_id}."
                        self.hypothesis_ledger.complete_proof(
                            proof_attempt_id,
                            proof_evidence,
                            error=error,
                        )
                        gaps.append(error)
                        continue
                elif request.oracle.kind in {"log_contains", "process_crash"}:
                    observation_reset = tagged(active_device.reset_observation_window(budget))
                    self._record_commands(
                        scan_id,
                        task_id,
                        observation_reset,
                        evidence_summaries,
                    )
                    if any(result.exit_code != 0 for _kind, result, _metadata in observation_reset):
                        proof_evidence = evidence_summaries[before:]
                        error = f"Could not isolate logs for {state} test {test_case_id}."
                        self.hypothesis_ledger.complete_proof(
                            proof_attempt_id,
                            proof_evidence,
                            error=error,
                        )
                        gaps.append(error)
                        continue

                execution_error: Exception | None = None
                try:
                    artifact = poc_artifacts.get(self._poc_request_key(request))
                    if artifact is None or not artifact.ok or artifact.apk_path is None:
                        raise RuntimeError(
                            "ordinary-app proof APK was not built by the platform before execution"
                        )
                    execution_spec = request.poc or artifact.effective_spec
                    if execution_spec is None:
                        raise RuntimeError("ordinary-app proof APK has no executable specification")
                    probe = active_device.execute_poc(
                        artifact.apk_path,
                        execution_spec,
                        target_package_name=package_name,
                        state=state,
                        budget=budget,
                        extras=dict(request.extras),
                        oracle=request.oracle,
                        test_case_id=test_case_id,
                        build_metadata=artifact.metadata,
                    )
                    for index, (kind, result, metadata) in enumerate(probe.commands):
                        probe.commands[index] = (
                            kind,
                            result,
                            {
                                **metadata,
                                "poc_apk_sha256": artifact.apk_sha256,
                                "poc_source_sha256": artifact.source_sha256,
                                "poc_build_evidence_id": artifact.metadata.get("build_evidence_id"),
                                **runtime_verdict_metadata,
                            },
                        )
                    self._record_commands(scan_id, task_id, probe.commands, evidence_summaries)
                    if probe.stage == "poc_incompatible":
                        raise RuntimeError(str(probe.summary.get("error") or probe.stage))
                    probe_summary = getattr(probe, "summary", {})
                    receipt_gap = (
                        probe_summary.get("poc_execution_receipt_gap")
                        if isinstance(probe_summary, dict)
                        else None
                    )
                    if isinstance(receipt_gap, str) and receipt_gap:
                        gaps.append(
                            f"Agent-requested test {test_case_id} executed but could not close "
                            f"the ordinary-app execution receipt: {receipt_gap}."
                        )
                except Exception as exc:
                    execution_error = exc

                proof_evidence = [
                    item
                    for item in evidence_summaries[before:]
                    if item.get("metadata", {}).get("test_case_id") == test_case_id
                ]
                self.hypothesis_ledger.complete_proof(
                    proof_attempt_id,
                    proof_evidence,
                    error=str(execution_error) if execution_error else None,
                )
                if execution_error is not None:
                    gaps.append(
                        f"Agent-requested test {test_case_id} failed during execution: "
                        f"{execution_error}"
                    )
                    continue
                evidence_ids = [item["id"] for item in proof_evidence]
                executed.append(
                    {
                        "test_case_id": test_case_id,
                        "proof_attempt_id": proof_attempt_id,
                        "hypothesis_id": request.hypothesis_id,
                        "request": request.model_dump(mode="json"),
                        "evidence_ids": evidence_ids,
                    }
                )
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "action.completed",
                    f"AI 申请的入口测试已完成，生成 {len(evidence_ids)} 条证据",
                    {
                        "source": "platform",
                        "test_case_id": test_case_id,
                        "hypothesis_id": request.hypothesis_id,
                        "entry_point_id": request.entry_point_id,
                        "state": state,
                        "evidence_ids": evidence_ids,
                    },
                )
        return executed, gaps

    def _execute_requested_dynamic_experiment(
        self,
        *,
        scan_id: str,
        task_id: str,
        test_case_id: str,
        proof_attempt_id: str | None,
        request: AgentRequestedTest,
        device: AdbDeviceAdapter,
        runtime_verdict_metadata: dict[str, Any],
        evidence_summaries: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, str | None]:
        plan = request.experiment
        if plan is None or proof_attempt_id is None:
            error = "Dynamic experiment could not be bound to a platform ProofAttempt."
            self.hypothesis_ledger.complete_proof(proof_attempt_id, [], error=error)
            return None, error
        try:
            for step in [*plan.steps, *plan.cleanup_steps]:
                validate_dynamic_experiment_adb_template(step.adb_args)
        except ValueError as exc:
            error = f"Dynamic experiment command is outside platform policy: {exc}"
            self.hypothesis_ledger.complete_proof(proof_attempt_id, [], error=error)
            return None, error
        contract = {
            **plan.proof.model_dump(mode="json"),
            "proof_attempt_id": proof_attempt_id,
            "test_case_id": test_case_id,
            "hypothesis_id": request.hypothesis_id,
            "entry_point_id": request.entry_point_id,
            "runtime_verdict_metadata": runtime_verdict_metadata,
        }
        with self.database.session_factory() as session:
            capsule = DynamicExperimentCapsule(
                scan_id=scan_id,
                task_id=task_id,
                name=plan.name,
                objective=plan.objective,
                preferred_serial=device.serial,
                preconditions=list(plan.preconditions),
                impact_contract=contract,
                steps=[item.model_dump(mode="json") for item in plan.steps],
                cleanup_steps=[item.model_dump(mode="json") for item in plan.cleanup_steps],
                state_json={
                    "scan_id": scan_id,
                    "task_id": task_id,
                    "test_case_id": test_case_id,
                },
            )
            session.add(capsule)
            session.flush()
            capsule_id = capsule.id
            add_event(
                session,
                scan_id,
                "dynamic_experiment.created",
                "Agent 多步骤验证计划已编译为平台动态实验",
                {
                    "capsule_id": capsule_id,
                    "task_id": task_id,
                    "test_case_id": test_case_id,
                    "proof_attempt_id": proof_attempt_id,
                    "hypothesis_id": request.hypothesis_id,
                    "step_count": len(plan.steps),
                },
            )
            session.commit()

        try:
            completed = self.dynamic_experiments.run_on_leased_device(capsule_id, device)
        except Exception as exc:
            error = f"Dynamic experiment {test_case_id} failed to execute: {exc}"
            self.hypothesis_ledger.complete_proof(proof_attempt_id, [], error=error)
            return None, error

        with self.database.session_factory() as session:
            receipts = list(
                session.scalars(
                    select(DynamicExperimentReceipt)
                    .where(DynamicExperimentReceipt.capsule_id == capsule_id)
                    .order_by(
                        DynamicExperimentReceipt.started_at,
                        DynamicExperimentReceipt.attempt,
                    )
                )
            )
            evidence_ids = list(
                dict.fromkeys(
                    evidence_id for receipt in receipts for evidence_id in receipt.evidence_ids
                )
            )
            evidence_by_id = {
                item.id: item
                for item in session.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids)))
            }
            proof_evidence = [
                self._evidence_summary(evidence_by_id[evidence_id])
                for evidence_id in evidence_ids
                if evidence_id in evidence_by_id
            ]
        known_evidence_ids = {str(item.get("id")) for item in evidence_summaries if item.get("id")}
        evidence_summaries.extend(
            item for item in proof_evidence if item["id"] not in known_evidence_ids
        )
        platform_error = (completed.result_json or {}).get("platform_error")
        proof_error = (
            str(platform_error)
            if platform_error
            else completed.error
            if completed.status == "canceled"
            else None
        )
        if completed.status != "paused":
            self.hypothesis_ledger.complete_proof(
                proof_attempt_id,
                proof_evidence,
                error=proof_error,
            )
        else:
            # A paused Capsule is not a verdict, but its completed receipts are
            # still durable Proof progress and must survive task finalization.
            with self.database.session_factory() as session:
                attempt = session.get(ProofAttempt, proof_attempt_id)
                if attempt is not None and attempt.status == "executing":
                    attempt.evidence_ids = list(
                        dict.fromkeys([*attempt.evidence_ids, *evidence_ids])
                    )
                    attempt.oracle = {
                        **dict(attempt.oracle or {}),
                        "dynamic_experiment_capsule_id": capsule_id,
                        "dynamic_experiment_status": "paused",
                        "resumable": True,
                        "harm_demonstrated": False,
                    }
                    session.commit()
        result = {
            "test_case_id": test_case_id,
            "proof_attempt_id": proof_attempt_id,
            "hypothesis_id": request.hypothesis_id,
            "request": request.model_dump(mode="json"),
            "evidence_ids": evidence_ids,
            "dynamic_experiment": {
                "capsule_id": capsule_id,
                "status": completed.status,
                "result": completed.result_json,
                "resumable": completed.status == "paused",
            },
        }
        self._record_exploration_event(
            scan_id,
            task_id,
            "action.completed" if completed.status == "completed" else "action.paused",
            (
                "Agent 多步骤动态实验已完成并回写 Proof Evidence"
                if completed.status == "completed"
                else "Agent 多步骤动态实验已保留断点，当前 Proof 保持未闭合"
            ),
            {
                "source": "platform",
                "test_case_id": test_case_id,
                "proof_attempt_id": proof_attempt_id,
                "hypothesis_id": request.hypothesis_id,
                "capsule_id": capsule_id,
                "capsule_status": completed.status,
                "evidence_ids": evidence_ids,
            },
        )
        error = (
            f"Agent-requested dynamic experiment {test_case_id} paused: {completed.error}"
            if completed.status == "paused"
            else proof_error
        )
        return result, error

    @staticmethod
    def _agent_role_for_phase(phase: str) -> str:
        return (
            "critic"
            if phase == "adversarial_review"
            else "rescue"
            if phase == "rescue_review"
            else "rescue_explorer"
            if phase == "rescue_exploration"
            else "verifier"
            if phase == "adaptive_verification"
            else "primary"
        )

    def _start_agent_turn_record(
        self,
        session,  # noqa: ANN001
        *,
        scan_id: str,
        task_id: str,
        attempt: int,
        phase: str,
        audit_id: str,
        request_evidence_id: str,
        round_index: int = 0,
        workspace_path: str = "",
    ) -> AgentTurnRecord:
        role = self._agent_role_for_phase(phase)
        container_key = f"{scan_id}:scan-container"
        container = session.scalar(
            select(ScanContainerRecord).where(ScanContainerRecord.container_key == container_key)
        )
        if container is None:
            container = ScanContainerRecord(
                scan_id=scan_id,
                task_id=None,
                container_key=container_key,
                isolation=self.settings.codex_isolation,
                workspace_path=workspace_path,
                status="running",
                metadata_json={"session_workspaces": {}},
            )
            session.add(container)
            session.flush()
        else:
            container.status = "running"
            container.completed_at = None
            if workspace_path:
                container.workspace_path = workspace_path
        container_metadata = dict(container.metadata_json or {})
        session_workspaces = dict(container_metadata.get("session_workspaces") or {})
        session_key = f"{scan_id}:{task_id}:{attempt}:{role}"
        if workspace_path:
            session_workspaces[session_key] = workspace_path
        container.metadata_json = {
            **container_metadata,
            "session_workspaces": session_workspaces,
        }
        agent_session = session.scalar(
            select(AgentSessionRecord).where(AgentSessionRecord.session_key == session_key)
        )
        if agent_session is None:
            agent_session = AgentSessionRecord(
                scan_id=scan_id,
                task_id=task_id,
                container_record_id=container.id,
                session_key=session_key,
                role=role,
                attempt=attempt,
                backend="codex",
                provider=self.settings.codex_provider,
                model=self.settings.codex_model,
                status="active",
            )
            session.add(agent_session)
            session.flush()
        else:
            agent_session.status = "active"
            agent_session.completed_at = None
        turn = AgentTurnRecord(
            scan_id=scan_id,
            task_id=task_id,
            session_record_id=agent_session.id,
            audit_id=audit_id,
            phase=phase,
            round_index=round_index,
            status="running",
            request_evidence_id=request_evidence_id,
        )
        session.add(turn)
        return turn

    @staticmethod
    def _finish_agent_turn_record(
        session,  # noqa: ANN001
        *,
        audit_id: str,
        status: str,
        response_evidence_id: str | None = None,
        thread_id: str | None = None,
        turn_id: str | None = None,
        usage: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        turn = session.scalar(select(AgentTurnRecord).where(AgentTurnRecord.audit_id == audit_id))
        if turn is None or turn.status != "running":
            return
        turn.status = status
        turn.response_evidence_id = response_evidence_id
        turn.turn_id = turn_id
        turn.usage_json = usage or {}
        turn.error = error
        turn.completed_at = now()
        agent_session = session.get(AgentSessionRecord, turn.session_record_id)
        if agent_session is not None:
            agent_session.status = "idle" if status == "completed" else status
            agent_session.thread_id = thread_id or agent_session.thread_id
            agent_session.completed_at = turn.completed_at
            container = session.get(ScanContainerRecord, agent_session.container_record_id)
            if container is not None:
                # A task turn ending does not imply the shared scan container ended.
                container.status = "running"
                container.completed_at = None

    def _record_agent_request(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        evidence: list[dict[str, Any]],
        platform_context: dict[str, Any],
        backend: str,
        phase: str,
        capability: dict[str, Any],
        runtime_workspace: Path | None = None,
    ) -> str:
        if backend != "codex":
            raise ValueError("OpenCode and other agent backends are not executable")
        frozen = self.settings.frozen_agent_configuration()
        provider = frozen.provider
        execution = frozen.execution
        frozen.phase_route.provider_profile_id(phase)
        direct_tool_access = True
        shell_access = execution.bash
        workspace_write = execution.workspace_write
        assigned_device = platform_context.get("device")
        assigned_device_serial = (
            assigned_device.get("serial") if isinstance(assigned_device, dict) else None
        )
        proof_replay = platform_context.get("proof_replay")
        gateway_available = bool(
            isinstance(proof_replay, dict) and proof_replay.get("available") is True
        )
        adb_access = (
            execution.adb == "task_gateway" and bool(assigned_device_serial) and gateway_available
        )
        network_access = execution.shell_network == "public_egress"
        audit_id = str(uuid.uuid4())
        metadata = {
            "audit_id": audit_id,
            "backend": "codex",
            "provider": provider.provider,
            "model": provider.model,
            "execution_profile_id": execution.id,
            "execution_profile_sha256": execution.fingerprint(),
            "provider_profile_id": provider.id,
            "provider_profile_sha256": provider.fingerprint(),
            "phase_route_sha256": frozen.phase_route.fingerprint(),
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": task.attempts,
        }
        prompt = investigation_prompt(
            scan,
            task,
            entries,
            evidence,
            platform_context,
            direct_tool_access=direct_tool_access,
            shell_access=shell_access,
            workspace_write=workspace_write,
            adb_access=adb_access,
            network_access=network_access,
        )
        request = {
            "schema_version": "1.0",
            "backend": "codex",
            "provider": provider.provider,
            "model": provider.model,
            "sdk_version": capability.get("version"),
            "runtime_version": capability.get("runtime_version"),
            "isolation": self.settings.codex_isolation,
            "provider_base_url": provider.base_url,
            "phase": phase,
            "task_id": task.id,
            "attempt": task.attempts,
            "developer_instructions": developer_instructions(
                direct_tool_access=direct_tool_access,
                shell_access=shell_access,
                workspace_write=workspace_write,
                adb_access=adb_access,
                network_access=network_access,
            ),
            "prompt": prompt,
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
            "tool_boundary": {
                "direct_tool_access": True,
                "model_tools_enabled": True,
                "workspace_tool_profile": "codex_full_access",
                "workspace_tools": ["file", "shell", "apply_patch", "web_search"],
                "shell_enabled": shell_access,
                "write_enabled": workspace_write,
                "native_write_tools_enabled": execution.apply_patch,
                "allowed_write_roots": ["session_workspace", "session_tmp"],
                "shared_scan_workspace_exposed": True,
                "network_enabled": network_access,
                "network_policy": (execution.shell_network if network_access else "disabled"),
                "adb_enabled": adb_access,
                "adb_evidence_policy": (
                    "exploration_only; ordinary-app replay required for proof"
                    if adb_access
                    else "disabled"
                ),
                "subagents_enabled": False,
                "mcp_allowlist": list(execution.mcp_allowlist),
                "structured_output_tool_enabled": False,
                "platform_executes_requested_tests": True,
            },
            "runtime_options": {
                "reasoning_effort": provider.reasoning_effort,
                "output_mode": "json_schema",
                "execution_profile": execution.model_dump(mode="json"),
                "execution_profile_sha256": execution.fingerprint(),
                "provider_profile": provider.model_dump(mode="json"),
                "provider_profile_sha256": provider.fingerprint(),
                "phase_route": frozen.phase_route.model_dump(mode="json"),
                "phase_route_sha256": frozen.phase_route.fingerprint(),
                "max_agent_steps": None,
                "max_provider_requests": None,
                "structured_output_retries": 1,
                "schema_validator": "pydantic@2",
                "semantic_validator": "apkscanner@1.0",
            },
        }
        with self.database.session_factory() as session:
            request_evidence = self.evidence.json(
                session,
                scan_id=scan.id,
                task_id=task.id,
                kind="agent.request",
                value=request,
                summary=f"{backend} {phase} request",
                metadata=metadata,
            )
            self._start_agent_turn_record(
                session,
                scan_id=scan.id,
                task_id=task.id,
                attempt=task.attempts,
                phase=phase,
                audit_id=audit_id,
                request_evidence_id=request_evidence.id,
                round_index=int(platform_context.get("round_index") or 0),
                workspace_path=str(runtime_workspace or ""),
            )
            session.commit()
        return audit_id

    def _record_agent_response(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        result: Any,
    ) -> None:
        metadata = {
            "audit_id": audit_id,
            "backend": backend,
            "provider": self.settings.codex_provider,
            "model": self.settings.codex_model,
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": attempt,
            "thread_id": result.thread_id,
            "turn_id": result.turn_id,
        }
        response = {
            "schema_version": "1.0",
            "thread_id": result.thread_id,
            "turn_id": result.turn_id,
            "structured_output": result.result.model_dump(mode="json"),
            "model_validation": {
                "rejected_requested_tests": self._rejected_requested_tests(result.result),
                "normalization_repairs": self._normalization_repairs(result.result),
            },
            "usage": result.usage,
            "output_transport": getattr(result, "output_transport", {}),
        }
        with self.database.session_factory() as session:
            response_evidence = self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.response",
                value=response,
                summary=f"{backend} {phase} structured response",
                metadata=metadata,
            )
            self._finish_agent_turn_record(
                session,
                audit_id=audit_id,
                status="completed",
                response_evidence_id=response_evidence.id,
                thread_id=result.thread_id,
                turn_id=result.turn_id,
                usage=result.usage,
            )
            session.commit()

    def _record_agent_runtime_events(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        events: list[dict[str, Any]],
    ) -> None:
        metadata = {
            "audit_id": audit_id,
            "backend": backend,
            "provider": self.settings.codex_provider,
            "model": self.settings.codex_model,
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": attempt,
        }
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.events",
                value={
                    "schema_version": "1.0",
                    "events": events,
                },
                summary=f"{backend} {phase} normalized runtime events",
                metadata=metadata,
            )
            session.commit()

    def _record_agent_error(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        error: Exception | str,
    ) -> None:
        metadata = {
            "audit_id": audit_id,
            "backend": backend,
            "provider": self.settings.codex_provider,
            "model": self.settings.codex_model,
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": attempt,
        }
        error_message = str(error)
        audit_details = getattr(error, "audit_details", None)
        value: dict[str, Any] = {
            "schema_version": "1.0",
            "error": error_message,
        }
        if isinstance(audit_details, dict) and audit_details:
            value["details"] = audit_details
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.error",
                value=value,
                summary=f"{backend} {phase} failed",
                metadata=metadata,
            )
            self._finish_agent_turn_record(
                session,
                audit_id=audit_id,
                status="failed",
                error=error_message,
            )
            session.commit()

    def _record_agent_cancellation(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        error: Exception | str,
    ) -> None:
        metadata = {
            "audit_id": audit_id,
            "backend": backend,
            "provider": self.settings.codex_provider,
            "model": self.settings.codex_model,
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": attempt,
        }
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.cancellation",
                value={
                    "schema_version": "1.0",
                    "requested_by": "local_console_user",
                    "acknowledged": True,
                    "reason": str(error),
                },
                summary=f"{backend} {phase} cancelled by user",
                metadata=metadata,
            )
            self._finish_agent_turn_record(
                session,
                audit_id=audit_id,
                status="canceled",
                error=str(error),
            )
            session.commit()

    def _record_agent_test_validation(
        self,
        *,
        task_id: str,
        turn_id: str,
        submitted: list[dict[str, Any]],
        accepted: list[dict[str, Any]],
        executed: list[dict[str, Any]],
        gaps: list[str],
        model_rejected: list[dict[str, Any]] | None = None,
    ) -> None:
        match = self._agent_response_for_turn(task_id, turn_id)
        if match is None:
            return
        response, metadata = match
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=response.scan_id,
                task_id=task_id,
                kind="agent.test_validation",
                value={
                    "schema_version": "1.0",
                    "submitted": submitted,
                    "accepted": accepted,
                    "executed": executed,
                    "gaps": gaps,
                    "model_rejected": model_rejected or [],
                },
                summary="Platform validation of AI-requested tests",
                metadata=metadata,
            )
            session.commit()

    def _record_agent_validation(
        self,
        *,
        task_id: str,
        turn_id: str,
        raw_payload: dict[str, Any],
        validated_payload: dict[str, Any],
    ) -> None:
        match = self._agent_response_for_turn(task_id, turn_id)
        if match is None:
            return
        response, metadata = match
        claimed_evidence = list(raw_payload.get("evidence_ids", []))
        accepted_evidence = list(validated_payload.get("evidence_ids", []))
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=response.scan_id,
                task_id=task_id,
                kind="agent.validation",
                value={
                    "schema_version": "1.0",
                    "claimed_result": raw_payload.get("result"),
                    "final_result": validated_payload.get("result"),
                    "claimed_severity": raw_payload.get("severity_proposal"),
                    "final_severity": validated_payload.get("platform_severity"),
                    "severity_disposition": validated_payload.get(
                        "severity_disposition", "accepted"
                    ),
                    "downgraded": (raw_payload.get("result") != validated_payload.get("result")),
                    "claimed_evidence_ids": claimed_evidence,
                    "accepted_evidence_ids": accepted_evidence,
                    "rejected_evidence_ids": sorted(set(claimed_evidence) - set(accepted_evidence)),
                    "raw_structured_output": raw_payload,
                    "validated_output": validated_payload,
                },
                summary="Platform evidence validation of AI result",
                metadata=metadata,
            )
            session.commit()

    def _agent_response_for_turn(
        self,
        task_id: str,
        turn_id: str,
    ) -> tuple[Evidence, dict[str, Any]] | None:
        with self.database.session_factory() as session:
            responses = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task_id,
                        Evidence.kind == "agent.response",
                    )
                    .order_by(Evidence.created_at.desc())
                )
            )
            for response in responses:
                if response.metadata_json.get("turn_id") == turn_id:
                    return response, dict(response.metadata_json)
        return None

    def _static_evidence_summaries(self, scan_id: str) -> list[dict[str, Any]]:
        return self._evidence_summaries_for_run(
            scan_id,
            task_id=None,
            include_task_evidence=False,
        )

    def _evidence_summaries_for_run(
        self,
        scan_id: str,
        *,
        task_id: str | None,
        include_task_evidence: bool,
    ) -> list[dict[str, Any]]:
        with self.database.session_factory() as session:
            items = list(
                session.scalars(
                    select(Evidence).where(
                        Evidence.scan_id == scan_id,
                        Evidence.task_id.is_(None),
                    )
                )
            )
            if include_task_evidence and task_id is not None:
                items.extend(
                    session.scalars(
                        select(Evidence).where(
                            Evidence.scan_id == scan_id,
                            Evidence.task_id == task_id,
                        )
                    )
                )
        return [self._evidence_summary(item) for item in items]

    def _target_code_context(
        self,
        scan_id: str,
        entries: list[EntryPoint],
    ) -> dict[str, Any]:
        index = self._load_or_build_code_index(scan_id)
        if index is None:
            return {
                "schema_version": "1.0",
                "global_decompilation": {"status": "index_unavailable"},
                "components": [],
            }
        raw_components = index.get("components")
        if not isinstance(raw_components, dict):
            raw_components = {}
        names = list(
            dict.fromkeys(
                str(entry.owner_component or entry.name)
                for entry in entries
                if entry.owner_component or entry.name
            )
        )
        components: list[dict[str, Any]] = []
        remaining_content = 64_000
        for name in names:
            raw = raw_components.get(name)
            if not isinstance(raw, dict):
                components.append(
                    {
                        "component": name,
                        "status": "source_not_found",
                        "target_in_jadx_failure_list": False,
                        "target_source_has_decompiler_errors": False,
                        "anchors": [],
                    }
                )
                continue
            anchors: list[dict[str, Any]] = []
            for value in raw.get("anchors", []):
                if not isinstance(value, dict):
                    continue
                anchor = dict(value)
                content = anchor.get("content")
                if isinstance(content, str):
                    accepted = content[:remaining_content]
                    anchor["content"] = accepted
                    if len(accepted) < len(content):
                        anchor["context_truncated"] = True
                    remaining_content -= len(accepted)
                anchors.append(anchor)
                if remaining_content <= 0:
                    break
            components.append(
                {
                    "component": name,
                    "status": raw.get("status", "source_not_found"),
                    "target_in_jadx_failure_list": bool(raw.get("target_in_jadx_failure_list")),
                    "target_source_has_decompiler_errors": bool(
                        raw.get("target_source_has_decompiler_errors")
                    ),
                    "global_decompilation_status": raw.get("global_decompilation_status"),
                    "anchors": anchors,
                }
            )
        return {
            "schema_version": "1.0",
            "global_decompilation": {
                key: value
                for key, value in dict(index.get("decompilation") or {}).items()
                if key != "failed_classes"
            },
            "components": components,
        }

    def _run_asc_xrefs(
        self,
        session,  # noqa: ANN001
        scan: Scan,
        entries: list[EntryPoint],
        budget,  # noqa: ANN001
        *,
        progress=None,  # noqa: ANN001
    ) -> None:
        """Record ASC bytecode-level inbound cross references as scan Evidence.

        Optional: disabled by default, and any failure (package missing, sandbox
        without ``multiprocessing``, tool error) becomes an unusable-tool receipt
        instead of failing the scan.
        """

        if not self.settings.asc_enabled:
            return
        if progress is not None:
            progress("asc_xrefs", "started", {"query_limit": self.settings.asc_max_queries})
        queries = build_asc_queries(
            entries,
            max_queries=self.settings.asc_max_queries,
        )
        try:
            extraction = self.asc.extract(
                Path(scan.artifact_path),
                queries,
                budget=budget,
            )
        except Exception as exc:  # defensive: extraction already isolates
            if progress is not None:
                progress(
                    "asc_xrefs",
                    "failed",
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
            return
        payload = extraction.as_evidence_payload()
        usable = extraction.usable
        status = (
            "succeeded"
            if usable
            else "unavailable"
            if not extraction.references and not extraction.tool_version
            else "tool_failed"
        )
        metadata = {
            "static_output_usable": usable,
            "static_tool_status": status,
            "static_tool_timed_out": False,
            "static_tool_exit_code": 0 if usable else 1,
            "asc_transport": extraction.transport,
            "asc_tool_version": extraction.tool_version,
            "asc_reference_count": len(extraction.references),
            "asc_dex_entry_count": int(extraction.stats.get("dex_entry_count") or 0),
            "asc_error_count": len(extraction.errors),
        }
        self.evidence.json(
            session,
            scan_id=scan.id,
            task_id=None,
            kind="static.droidasc",
            value=payload,
            summary=evidence_summary(payload),
            metadata=metadata,
        )
        if progress is not None:
            progress(
                "asc_xrefs",
                "completed" if usable else "failed",
                {
                    "references": len(extraction.references),
                    "queries": len(extraction.queries),
                    "transport": extraction.transport,
                    "errors": extraction.errors[:3],
                },
            )

    def _target_xrefs_context(
        self,
        scan_id: str,
        entries: list[EntryPoint],
    ) -> dict[str, Any] | None:
        """Project the scan's ASC xrefs into a bounded, per-task reference set."""

        with self.database.session_factory() as session:
            record = session.scalar(
                select(Evidence)
                .where(
                    Evidence.scan_id == scan_id,
                    Evidence.kind == "static.droidasc",
                )
                .order_by(desc(Evidence.created_at))
                .limit(1)
            )
            if record is None:
                return None
            record_id = record.id
            artifact_path = record.path
            artifact_sha256 = record.sha256
        try:
            payload = self.store.read_json_artifact(
                "evidence",
                artifact_path,
                artifact_sha256,
            )
        except (OSError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        references = payload.get("references")
        if not isinstance(references, list):
            return None
        selected = relevance_filter(
            [item for item in references if isinstance(item, dict)],
            entries,
            limit=self.settings.asc_context_max_references,
        )
        if not selected:
            return None
        return {
            "schema_version": "1.0",
            "source_evidence_id": record_id,
            "tool": "droidasc",
            "tool_version": payload.get("tool_version"),
            "transport": payload.get("transport"),
            "policy": "platform_issued_bytecode_inbound_references",
            "total_reference_count": len(references),
            "reference_count": len(selected),
            "references": selected,
        }

    def _load_or_build_code_index(self, scan_id: str) -> dict[str, Any] | None:
        workspace = self.settings.data_dir / "workspaces" / scan_id
        index_path = workspace / "code_index.json"
        try:
            value = json.loads(index_path.read_text(encoding="utf-8"))
            if (
                isinstance(value, dict)
                and value.get("context_version") == CODE_INDEX_CONTEXT_VERSION
            ):
                return value
        except (OSError, json.JSONDecodeError):
            pass

        with self.database.session_factory() as session:
            entries = list(session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan_id)))
            scan = session.get(Scan, scan_id)
            jadx_evidence = session.scalar(
                select(Evidence)
                .where(
                    Evidence.scan_id == scan_id,
                    Evidence.kind == "static.jadx",
                )
                .order_by(Evidence.created_at.desc())
                .limit(1)
            )
        if not entries or scan is None or not workspace.is_dir():
            return None

        payload: dict[str, Any] = {}
        if jadx_evidence is not None:
            try:
                stored = self.store.read_json_artifact(
                    "evidence",
                    jadx_evidence.path,
                    jadx_evidence.sha256,
                )
                if isinstance(stored, dict):
                    payload = stored
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                payload = {}
        decompilation = payload.get("decompilation")
        if not isinstance(decompilation, dict):
            exit_code = payload.get("exit_code")
            command_result = CommandResult(
                argv=[str(value) for value in payload.get("argv", []) if isinstance(value, str)],
                exit_code=exit_code if isinstance(exit_code, int) else 1,
                stdout=str(payload.get("stdout") or ""),
                stderr=str(payload.get("stderr") or ""),
                timed_out=bool(payload.get("timed_out")),
            )
            decompilation = self.inspector._jadx_decompilation_summary(
                command_result,
                workspace / "jadx",
            )
        code_index = self.inspector._build_code_index(
            result_entries=entries,
            package_name=scan.package_name,
            workspace=workspace,
            jadx_dir=workspace / "jadx",
            decoded_dir=workspace / "apktool",
            archive_dir=workspace / "archive",
            decompilation=decompilation,
        )
        value = {
            "schema_version": "1.0",
            "context_version": CODE_INDEX_CONTEXT_VERSION,
            "decompilation": decompilation,
            "components": code_index,
            "generated_lazily": True,
        }
        with suppress(OSError):
            index_path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        return value

    @staticmethod
    def _static_tool_evidence_summary(
        tool: str,
        payload: dict[str, Any],
    ) -> str:
        if tool != "jadx":
            return f"{tool} exited with {payload['exit_code']}"
        decompilation = payload.get("decompilation")
        if not isinstance(decompilation, dict):
            return f"jadx exited with {payload['exit_code']}"
        status = str(decompilation.get("status", "unknown"))
        generated = int(decompilation.get("generated_java_files", 0))
        errors = int(decompilation.get("reported_error_count", 0))
        return (
            f"jadx {status}: generated {generated} Java files; "
            f"{errors} errors reported (exit {payload['exit_code']})"
        )

    def _materialize_agent_evidence(
        self,
        scan_id: str,
        task_id: str,
        attempt: int,
        summaries: list[dict[str, Any]],
        *,
        platform_context: dict[str, Any] | None = None,
    ) -> Path:
        static_review = self._is_static_review_context(platform_context)
        context_root = (
            self.settings.data_dir / "agent_context" / scan_id
            if static_review
            else self.settings.data_dir / "workspaces" / scan_id / "agent_context"
        )
        task_root = context_root / task_id / f"attempt-{attempt}"
        task_root.mkdir(parents=True, exist_ok=True)
        self._materialize_target_sources(
            scan_id,
            task_root,
            platform_context or {},
        )
        materialize_attacker_templates(task_root)
        scan_workspace = (self.settings.data_dir / "workspaces" / scan_id).resolve()
        expose_shared_workspace = self.settings.agent_permission_profile == "personal_lab"
        shared_names = [
            name
            for name in ("jadx", "apktool", "archive", "native", "artifacts")
            if (scan_workspace / name).is_dir()
        ]
        ida_path_mappings = [
            {
                "container_prefix": f"/scan-input/{name}",
                "host_prefix": str((scan_workspace / name).resolve()),
            }
            for name in shared_names
            if name in {"apktool", "archive", "native", "artifacts"}
        ]
        workspace_policy = {
            "writable_root": ".",
            # The Agent prompt tells PoC authors to place sources under this
            # relative root; it must exist in the investigation context too, not
            # only in the adaptive-verifier context.
            "poc_root": "poc",
            "shared_scan_workspace_exposed": expose_shared_workspace,
            "context_file": "context.json",
            "decompiled_roots": (
                {
                    "container": [f"/scan-input/{name}" for name in shared_names],
                }
                if expose_shared_workspace
                else {"container": []}
            ),
            "artifact_graph": (
                "/scan-input/artifact_graph.json"
                if expose_shared_workspace and (scan_workspace / "artifact_graph.json").is_file()
                else None
            ),
            "ida_mcp": {
                "available": bool(self.settings.ida_mcp_enabled and ida_path_mappings),
                "server": "ida-headless",
                "path_mappings": ida_path_mappings,
                "session_policy": (
                    "Use one preferred_session_id per SO, pass database explicitly to every "
                    "IDB-dependent tool, and close the session when the bounded native edge is "
                    "resolved."
                ),
            },
            "reason": (
                "This bounded static semantic task receives the exact signal sources and "
                "deterministically resolved one-hop application references under target_source. "
                "The full decompiler workspace is intentionally omitted to prevent unrelated "
                "package inventory."
                if static_review
                else "The task root is independently writable. Complete decompiler outputs are exposed "
                "read-only; relevant target sources and immutable evidence are also materialized "
                "locally."
                if expose_shared_workspace
                else (
                    "Concurrent agents receive isolated writable roots; relevant target code "
                    "and immutable evidence are materialized in this context."
                )
            ),
        }
        if platform_context is not None:
            platform_context["workspace"] = workspace_policy
            platform_context["attacker_templates"] = {
                "catalog_path": "attacker-templates/catalog.json",
                "templates": attacker_template_catalog(),
            }
        self._copy_evidence_artifacts(task_root, summaries)
        effective_context = platform_context or {}
        stable_keys = (
            "validation_fixtures",
            "poc_builder",
            "proof_capabilities",
            "target_code_context",
            "entry_scope",
            "threat_model",
            "workspace",
            "attacker_templates",
            "context_policy",
        )
        stable_context = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "task_id": task_id,
            "attempt": attempt,
            "platform_context": {
                key: effective_context.get(key)
                for key in stable_keys
                if effective_context.get(key) is not None
            },
            "workspace_policy": workspace_policy,
        }
        dynamic_context = {
            "schema_version": "1.0",
            "phase": str(effective_context.get("phase") or "unknown"),
            "round_index": int(effective_context.get("round_index") or 0),
            "platform_context": {
                key: value
                for key, value in effective_context.items()
                if key not in stable_keys and key not in {"context_manifest", "target_xrefs"}
            },
        }
        evidence_index = {
            "schema_version": "1.0",
            "count": len(summaries),
            "evidence": summaries,
        }
        phase_slug = (
            re.sub(
                r"[^a-z0-9-]+",
                "-",
                dynamic_context["phase"].lower().replace("_", "-"),
            ).strip("-")
            or "unknown"
        )
        round_path = Path("rounds") / (f"{dynamic_context['round_index']:03d}-{phase_slug}.json")
        materialized_documents = {
            "stable": (Path("stable-context.json"), stable_context),
            "evidence": (Path("evidence-index.json"), evidence_index),
            "latest_round": (round_path, dynamic_context),
        }
        xrefs_payload = effective_context.get("target_xrefs")
        if isinstance(xrefs_payload, dict) and xrefs_payload.get("references"):
            materialized_documents["xrefs"] = (Path("xrefs.json"), xrefs_payload)
        manifest_documents: dict[str, dict[str, Any]] = {}
        for name, (relative_path, value) in materialized_documents.items():
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            target = task_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.is_file() or target.read_bytes() != encoded:
                target.write_bytes(encoded)
            manifest_documents[name] = {
                "path": relative_path.as_posix(),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "bytes": len(encoded),
            }
        context_manifest = {
            "schema_version": "1.0",
            "read_order": [
                "stable",
                "evidence",
                *(["xrefs"] if "xrefs" in materialized_documents else []),
                "latest_round",
            ],
            "documents": manifest_documents,
            "legacy_context_path": "context.json",
            "policy": (
                "read_manifest_then_open_only_the_evidence_needed_for_the_current_hypothesis; "
                "xrefs.json lists platform-issued bytecode-level inbound references "
                "(which class/method references a queried string/type/method)"
            ),
        }
        effective_context["context_manifest"] = context_manifest
        manifest_bytes = json.dumps(
            context_manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        (task_root / "context-manifest.json").write_bytes(manifest_bytes)
        context = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "task_id": task_id,
            "attempt": attempt,
            "evidence": summaries,
            "platform_context": effective_context,
            "workspace_policy": workspace_policy,
        }
        (task_root / "context.json").write_text(
            json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return task_root

    def _validation_fixture_context(
        self,
        scan_id: str,
        task_id: str,
    ) -> list[dict[str, Any]]:
        with self.database.session_factory() as session:
            fixtures = list(
                session.scalars(
                    select(ValidationFixture)
                    .where(
                        ValidationFixture.scan_id == scan_id,
                        ValidationFixture.status == "active",
                        (
                            ValidationFixture.task_id.is_(None)
                            | (ValidationFixture.task_id == task_id)
                        ),
                    )
                    .order_by(ValidationFixture.created_at)
                )
            )
        return [
            {
                "id": fixture.id,
                "name": fixture.name,
                "type": fixture.fixture_type,
                "payload": fixture.payload,
                "setup_instructions": fixture.setup_instructions,
                "cleanup_instructions": fixture.cleanup_instructions,
                "state_policy": "preserve_target_app_data_unless_fixture_explicitly_allows_reset",
            }
            for fixture in fixtures
        ]

    @staticmethod
    def _is_static_review_context(
        platform_context: dict[str, Any] | None,
    ) -> bool:
        if not isinstance(platform_context, dict):
            return False
        entry_scope = platform_context.get("entry_scope")
        if not isinstance(entry_scope, dict):
            return False
        catalog = entry_scope.get("catalog")
        return isinstance(catalog, list) and any(
            isinstance(item, dict) and item.get("kind") == EntryPointKind.STATIC_SURFACE.value
            for item in catalog
        )

    def _copy_evidence_artifacts(
        self,
        task_root: Path,
        summaries: list[dict[str, Any]],
    ) -> None:
        """Copy immutable evidence records into an active Agent workspace."""

        identifiers = [item["id"] for item in summaries if isinstance(item.get("id"), str)]
        if not identifiers:
            return
        evidence_root = task_root / "evidence"
        evidence_root.mkdir(parents=True, exist_ok=True)
        with self.database.session_factory() as session:
            records = list(session.scalars(select(Evidence).where(Evidence.id.in_(identifiers))))
        by_id = {record.id: record for record in records}
        allowed_root = (self.settings.data_dir / "evidence").resolve()
        for summary in summaries:
            record = by_id.get(summary.get("id"))
            if record is None:
                continue
            source = Path(record.path).resolve()
            if not source.is_relative_to(allowed_root) or not source.is_file():
                continue
            suffix = source.suffix if source.suffix in {".json", ".txt", ".log"} else ".bin"
            target = evidence_root / f"{record.id}{suffix}"
            shutil.copyfile(source, target)
            summary["artifact"] = str(target.relative_to(task_root))

    def _materialize_live_evidence(
        self,
        context: LiveProofContext,
        summaries: list[dict[str, Any]],
    ) -> None:
        """Expose proof evidence before returning the live replay receipt."""

        self._copy_evidence_artifacts(context.workspace, summaries)
        context_path = context.workspace / "context.json"
        try:
            payload = json.loads(context_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        payload["evidence"] = context.evidence_summaries
        temporary = context_path.with_suffix(".json.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            temporary.replace(context_path)
            evidence_index = {
                "schema_version": "1.0",
                "count": len(context.evidence_summaries),
                "evidence": context.evidence_summaries,
            }
            evidence_bytes = json.dumps(
                evidence_index,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            evidence_path = context.workspace / "evidence-index.json"
            evidence_path.write_bytes(evidence_bytes)
            manifest_path = context.workspace / "context-manifest.json"
            if manifest_path.is_file():
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                documents = manifest.setdefault("documents", {})
                documents["evidence"] = {
                    "path": "evidence-index.json",
                    "sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                    "bytes": len(evidence_bytes),
                }
                manifest_path.write_text(
                    json.dumps(
                        manifest,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
        except (OSError, json.JSONDecodeError):
            with suppress(OSError):
                temporary.unlink()

    def _materialize_target_sources(
        self,
        scan_id: str,
        task_root: Path,
        platform_context: dict[str, Any],
        *,
        max_bytes: int = 2_000_000,
    ) -> None:
        """Copy only target-component sources into an agent's writable workspace."""
        target_context = platform_context.get("target_code_context")
        if not isinstance(target_context, dict):
            return
        components = target_context.get("components")
        if not isinstance(components, list):
            return
        scan_workspace = (self.settings.data_dir / "workspaces" / scan_id).resolve()
        source_root = (task_root / "target_source").resolve()
        copied_bytes = 0
        if self._is_static_review_context(platform_context):
            manifest_source = next(
                (
                    candidate
                    for candidate in (
                        scan_workspace / "AndroidManifest.xml",
                        scan_workspace / "apktool" / "AndroidManifest.xml",
                    )
                    if candidate.is_file()
                ),
                None,
            )
            if manifest_source is not None:
                manifest_target = source_root / "AndroidManifest.xml"
                manifest_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(manifest_source, manifest_target)
                copied_bytes += manifest_source.stat().st_size
                platform_context["bounded_manifest_path"] = str(
                    manifest_target.relative_to(task_root)
                )
                try:
                    manifest_document = parse_manifest(
                        manifest_source.read_text(
                            encoding="utf-8",
                            errors="replace",
                        )
                    )
                except (OSError, ValueError):
                    manifest_document = None
                if manifest_document is not None:
                    referenced_classes: set[str] = set()
                    for component in components:
                        if not isinstance(component, dict):
                            continue
                        for anchor in component.get("anchors") or []:
                            if not isinstance(anchor, dict):
                                continue
                            content = anchor.get("content")
                            if not isinstance(content, str):
                                continue
                            referenced_classes.update(
                                descriptor.replace("/", ".")
                                for descriptor in re.findall(
                                    r"L([A-Za-z0-9_/$]+);",
                                    content,
                                )
                            )
                    platform_context["bounded_manifest"] = {
                        "package_name": manifest_document.package_name,
                        "min_sdk": manifest_document.min_sdk,
                        "target_sdk": manifest_document.target_sdk,
                        "application": manifest_document.application,
                        "matching_components": [
                            {
                                "kind": entry.kind,
                                "name": entry.name,
                                "owner_component": entry.owner_component,
                                "exported": entry.exported,
                                "permission": entry.permission,
                                "permission_protection": entry.permission_protection,
                                "intent_filters": entry.intent_filters,
                                "deep_links": entry.deep_links,
                            }
                            for entry in manifest_document.entries
                            if entry.name in referenced_classes
                            or entry.owner_component in referenced_classes
                        ],
                    }
        for component in components:
            if not isinstance(component, dict):
                continue
            anchors = component.get("anchors")
            if not isinstance(anchors, list):
                continue
            for anchor in anchors:
                if not isinstance(anchor, dict):
                    continue
                raw_path = anchor.get("path")
                if not isinstance(raw_path, str):
                    continue
                source = (scan_workspace / raw_path).resolve()
                if not source.is_relative_to(scan_workspace) or not source.is_file():
                    continue
                size = source.stat().st_size
                if copied_bytes + size > max_bytes:
                    anchor["materialization_skipped"] = "task_source_budget_exhausted"
                    continue
                relative = source.relative_to(scan_workspace)
                target = (source_root / relative).resolve()
                if not target.is_relative_to(source_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                copied_bytes += size
                anchor["materialized_path"] = str(target.relative_to(task_root))

    def _record_commands(
        self,
        scan_id: str,
        task_id: str,
        commands: list[tuple[str, Any, dict[str, Any]]],
        summaries: list[dict[str, Any]] | None,
    ) -> None:
        with self.database.session_factory() as session:
            for kind, command_result, metadata in commands:
                command_metadata = dict(metadata)
                argv = list(getattr(command_result, "argv", []) or [])
                if (
                    "device_serial" not in command_metadata
                    and len(argv) >= 3
                    and argv[0] == "adb"
                    and argv[1] == "-s"
                ):
                    command_metadata["device_serial"] = argv[2]
                item = self.evidence.command(
                    session,
                    scan_id=scan_id,
                    task_id=task_id,
                    kind=kind,
                    result=command_result,
                    metadata=command_metadata,
                )
                if summaries is not None:
                    summaries.append(self._evidence_summary(item))
                add_event(
                    session,
                    scan_id,
                    "exploration.evidence.created",
                    f"已生成验证证据：{kind}",
                    {
                        "task_id": task_id,
                        "source": "platform",
                        "evidence_id": item.id,
                        "evidence_kind": kind,
                        "exit_code": item.exit_code,
                        "summary": item.summary,
                        "test_case_id": command_metadata.get("test_case_id"),
                        "request_id": command_metadata.get("request_id"),
                        "device_serial": command_metadata.get("device_serial"),
                    },
                )
            session.commit()

    @staticmethod
    def _evidence_summary(item: Evidence) -> dict[str, Any]:
        return {
            "id": item.id,
            "kind": item.kind,
            "exit_code": item.exit_code,
            "summary": item.summary,
            "metadata": item.metadata_json,
        }

    @staticmethod
    def _validated_hypothesis_payload(
        payload: dict[str, Any],
        hypothesis_context: list[dict[str, Any]],
    ) -> dict[str, Any]:
        valid_ids = {
            str(item["id"])
            for item in hypothesis_context
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        assessments: list[dict[str, Any]] = []
        rejected = 0
        seen: set[str] = set()
        for item in payload.get("hypothesis_assessments", []):
            if not isinstance(item, dict):
                rejected += 1
                continue
            hypothesis_id = item.get("hypothesis_id")
            if (
                not isinstance(hypothesis_id, str)
                or hypothesis_id not in valid_ids
                or hypothesis_id in seen
            ):
                rejected += 1
                continue
            seen.add(hypothesis_id)
            assessments.append(item)
        payload["hypothesis_assessments"] = assessments
        if assessments:
            payload["hypotheses_tested"] = list(
                dict.fromkeys(
                    [
                        value
                        for value in payload.get("hypotheses_tested", [])
                        if isinstance(value, str) and value in valid_ids
                    ]
                    + [item["hypothesis_id"] for item in assessments]
                )
            )
        if rejected:
            payload["coverage_gaps"] = list(
                dict.fromkeys(
                    [
                        *payload.get("coverage_gaps", []),
                        (
                            f"Ignored {rejected} hypothesis assessment(s) that did not "
                            "belong to this task or duplicated another receipt."
                        ),
                    ]
                )
            )
        if (
            payload.get("result") == FindingStatus.SUPPORTED_STATIC.value
            and not any(
                item.get("verdict")
                in {
                    FindingStatus.SUPPORTED_STATIC.value,
                    "needs_dynamic_proof",
                }
                for item in assessments
            )
        ):
            payload["result"] = FindingStatus.INCONCLUSIVE.value
            payload["coverage_gaps"] = list(
                dict.fromkeys(
                    [
                        *payload.get("coverage_gaps", []),
                        (
                            "No task-owned hypothesis assessment passed the platform "
                            "static-support gate; the task remains inconclusive."
                        ),
                    ]
                )
            )
        return payload

    @staticmethod
    def _apply_platform_proof_overrides(
        payload: dict[str, Any],
        *,
        proven_hypotheses: dict[str, list[str]],
        proven_severity: str | None,
        agent_round_history: list[dict[str, Any]],
        debate_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Make accepted platform harm receipts immutable in the final payload."""

        if not proven_hypotheses:
            return payload
        assessments = [
            dict(item)
            for item in payload.get("hypothesis_assessments", [])
            if isinstance(item, dict)
        ]
        by_hypothesis = {
            str(item["hypothesis_id"]): item
            for item in assessments
            if isinstance(item.get("hypothesis_id"), str)
        }
        tested = [value for value in payload.get("hypotheses_tested", []) if isinstance(value, str)]
        all_proof_evidence_ids: list[str] = []
        for hypothesis_id, proof_evidence_ids in proven_hypotheses.items():
            all_proof_evidence_ids.extend(proof_evidence_ids)
            assessment = by_hypothesis.get(hypothesis_id)
            if assessment is None:
                assessment = {
                    "hypothesis_id": hypothesis_id,
                    "source": "platform-correlated ordinary-app proof",
                    "control": "",
                    "sink": "Platform harm Oracle observed the declared security impact.",
                    "reachable_path": "",
                    "boundary": "",
                }
                assessments.append(assessment)
                by_hypothesis[hypothesis_id] = assessment
            assessment.update(
                {
                    "verdict": FindingStatus.REPRODUCED_BLACKBOX.value,
                    "counterevidence": [],
                    "proof_gaps": [],
                    "evidence_ids": list(
                        dict.fromkeys(
                            [
                                *[
                                    value
                                    for value in assessment.get("evidence_ids", [])
                                    if isinstance(value, str)
                                ],
                                *proof_evidence_ids,
                            ]
                        )
                    ),
                    "confidence": "high",
                }
            )
            tested.append(hypothesis_id)

        severity_rank = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        severity_candidates = [
            str(payload.get("severity_proposal") or "info"),
            str(proven_severity or "info"),
        ]
        severity_candidates.extend(
            str(model_result.get("severity_proposal") or "info")
            for round_item in agent_round_history
            if isinstance((model_result := round_item.get("model_result")), dict)
        )
        valid_severities = [value for value in severity_candidates if value in severity_rank]
        severity = max(
            valid_severities or ["info"],
            key=severity_rank.__getitem__,
        )
        if severity == "info":
            severity = "medium"

        protected_objection_ids = {
            str(objection["objection_id"])
            for objection in (
                ((debate_context.get("critic") or {}).get("review_objections", []))
                if isinstance(debate_context.get("critic"), dict)
                else []
            )
            if isinstance(objection, dict)
            and objection.get("hypothesis_id") in proven_hypotheses
            and isinstance(objection.get("objection_id"), str)
        }
        resolutions = [
            dict(item)
            for item in payload.get("objection_resolutions", [])
            if isinstance(item, dict)
        ]
        for resolution in resolutions:
            if resolution.get("objection_id") not in protected_objection_ids:
                continue
            resolution.update(
                {
                    "disposition": "overruled",
                    "rationale": (
                        "平台已通过关联普通应用身份、执行结果与危害 Oracle 的动态证据"
                        "证明该假设；静态 Critic 无权推翻该证明。"
                    ),
                    "evidence_ids": list(
                        dict.fromkeys(
                            [
                                *[
                                    value
                                    for value in resolution.get("evidence_ids", [])
                                    if isinstance(value, str)
                                ],
                                *all_proof_evidence_ids,
                            ]
                        )
                    ),
                }
            )

        payload.update(
            {
                "result": FindingStatus.REPRODUCED_BLACKBOX.value,
                "hypotheses_tested": list(dict.fromkeys(tested)),
                "hypothesis_assessments": assessments,
                "objection_resolutions": resolutions,
                "evidence_ids": list(
                    dict.fromkeys(
                        [
                            *[
                                value
                                for value in payload.get("evidence_ids", [])
                                if isinstance(value, str)
                            ],
                            *all_proof_evidence_ids,
                        ]
                    )
                ),
                "severity_proposal": severity,
                "platform_severity": severity,
                "severity_disposition": "accepted_from_platform_harm_oracle",
                "confidence": "high",
                "platform_proof_overrides": {
                    hypothesis_id: {
                        "result": FindingStatus.REPRODUCED_BLACKBOX.value,
                        "evidence_ids": evidence_ids,
                        "immutable": True,
                    }
                    for hypothesis_id, evidence_ids in proven_hypotheses.items()
                },
            }
        )
        return payload

    @staticmethod
    def _unresolved_static_objection_ids(
        payload: dict[str, Any],
        hypothesis_id: str | None,
        evidence_by_id: dict[str, dict[str, Any]],
    ) -> list[str]:
        """Return Critic objections that lack an evidence-backed overruling receipt."""

        raw_resolutions = payload.get("objection_resolutions", [])
        raw_resolutions = raw_resolutions if isinstance(raw_resolutions, list) else []
        resolutions = {
            str(item.get("objection_id")): item
            for item in raw_resolutions
            if isinstance(item, dict) and isinstance(item.get("objection_id"), str)
        }
        unresolved: list[str] = []
        raw_objections = payload.get("review_objections", [])
        raw_objections = raw_objections if isinstance(raw_objections, list) else []
        for objection in raw_objections:
            if not isinstance(objection, dict):
                continue
            objection_id = objection.get("objection_id")
            if not isinstance(objection_id, str):
                continue
            objection_hypothesis_id = objection.get("hypothesis_id")
            if objection_hypothesis_id not in {None, hypothesis_id}:
                continue
            resolution = resolutions.get(objection_id, {})
            resolution_evidence_ids = resolution.get("evidence_ids", [])
            evidence_backed = isinstance(resolution_evidence_ids, list) and any(
                isinstance(evidence_id, str) and evidence_id in evidence_by_id
                for evidence_id in resolution_evidence_ids
            )
            if (
                resolution.get("disposition") != "overruled"
                or not str(resolution.get("rationale") or "").strip()
                or not evidence_backed
            ):
                unresolved.append(objection_id)
        return list(dict.fromkeys(unresolved))

    @staticmethod
    def _static_support_gate(
        assessment: dict[str, Any],
        evidence_by_id: dict[str, dict[str, Any]],
        *,
        evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Apply deterministic minimum evidence requirements to a static conclusion."""

        placeholder_values = {
            "",
            "n/a",
            "na",
            "none",
            "null",
            "unknown",
            "unknown/none",
            "not applicable",
            "not established",
            "tbd",
            "待确认",
            "待验证",
            "未知",
            "无",
        }

        minimum_lengths = {
            "source": 8,
            "control": 12,
            "sink": 4,
            "reachable_path": 16,
            "boundary": 8,
            "security_impact": 20,
            "missing_control": 16,
        }

        def normalized_text(field: str) -> str:
            value = assessment.get(field)
            return " ".join(value.strip().split()) if isinstance(value, str) else ""

        def is_substantive(field: str) -> bool:
            value = normalized_text(field)
            normalized = value.lower()
            alphanumeric = {character.lower() for character in value if character.isalnum()}
            return (
                normalized not in placeholder_values
                and len(value) >= minimum_lengths[field]
                and len(alphanumeric) >= 3
            )

        def anchor_tokens(field: str) -> set[str]:
            value = normalized_text(field)
            expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
            tokens = {
                token.lower()
                for token in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]{2,}", expanded)
                if token.lower()
                not in {
                    "the",
                    "and",
                    "from",
                    "into",
                    "without",
                    "caller",
                    "controlled",
                    "target",
                    "application",
                    "process",
                }
            }
            for run in re.findall(r"[\u3400-\u9fff]+", value):
                # Chinese descriptions do not have whitespace-delimited words. 3–6 character
                # shingles preserve meaningful anchors such as “外部应用” without treating a
                # generic single character as proof that source/sink appears in the path.
                for width in range(3, min(6, len(run)) + 1):
                    tokens.update(
                        run[index : index + width]
                        for index in range(0, len(run) - width + 1)
                    )
            return tokens

        required_fields = (
            "source",
            "control",
            "sink",
            "reachable_path",
            "boundary",
        )
        suppression_reasons = [
            f"missing_{field}" for field in required_fields if not is_substantive(field)
        ]
        if not is_substantive("security_impact"):
            suppression_reasons.append("missing_concrete_security_impact")
        if not is_substantive("missing_control"):
            suppression_reasons.append("missing_guard_or_control_gap")
        reachable_path = normalized_text("reachable_path")
        boundary = normalized_text("boundary")
        if "->" not in reachable_path and "→" not in reachable_path:
            suppression_reasons.append("unstructured_reachable_path")
        if (
            "->" not in boundary
            and "→" not in boundary
            and "boundary" not in boundary.lower()
            and "_uid" not in boundary.lower()
        ):
            suppression_reasons.append("unstructured_trust_boundary")
        path_tokens = anchor_tokens("reachable_path")
        if is_substantive("source") and not (anchor_tokens("source") & path_tokens):
            suppression_reasons.append("source_not_anchored_in_path")
        if is_substantive("sink") and not (anchor_tokens("sink") & path_tokens):
            suppression_reasons.append("sink_not_anchored_in_path")
        counterevidence = assessment.get("counterevidence", [])
        if isinstance(counterevidence, list) and any(
            isinstance(value, str) and value.strip() for value in counterevidence
        ):
            suppression_reasons.append("unresolved_counterevidence")
        unresolved_objection_ids = assessment.get("unresolved_objection_ids", [])
        unresolved_objection_ids = (
            [value for value in unresolved_objection_ids if isinstance(value, str)]
            if isinstance(unresolved_objection_ids, list)
            else []
        )
        if unresolved_objection_ids:
            suppression_reasons.append("unresolved_critic_objection")

        cited_ids = evidence_ids if evidence_ids is not None else assessment.get("evidence_ids", [])
        static_evidence_ids = list(
            dict.fromkeys(
                evidence_id
                for evidence_id in cited_ids
                if isinstance(evidence_id, str)
                and static_evidence_is_usable(
                    kind=evidence_by_id.get(evidence_id, {}).get("kind"),
                    metadata=evidence_by_id.get(evidence_id, {}).get("metadata"),
                    exit_code=evidence_by_id.get(evidence_id, {}).get("exit_code"),
                )
            )
        )
        if not static_evidence_ids:
            suppression_reasons.append("missing_explicit_static_evidence")
        return {
            "schema_version": "1.0",
            "eligible": not suppression_reasons,
            "required_fields": [
                *required_fields,
                "security_impact",
                "missing_control",
            ],
            "static_evidence_ids": static_evidence_ids,
            "unresolved_objection_ids": unresolved_objection_ids,
            "suppression_reasons": suppression_reasons,
        }

    @staticmethod
    def _static_refutation_gate(
        assessment: dict[str, Any],
        evidence_by_id: dict[str, dict[str, Any]],
        *,
        evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Require a concrete guard/blocked edge and usable static evidence before closure."""

        cited_ids = (
            evidence_ids
            if evidence_ids is not None
            else assessment.get("evidence_ids", [])
        )
        blocked_edge = next(
            (
                value
                for value in (
                    assessment.get("control"),
                    assessment.get("reachable_path"),
                )
                if isinstance(value, str) and len(" ".join(value.strip().split())) >= 12
            ),
            "",
        )
        return build_static_refutation_gate(
            evidence_by_id=evidence_by_id,
            evidence_ids=cited_ids,
            counterevidence=assessment.get("counterevidence"),
            blocked_edge=blocked_edge,
        )

    @staticmethod
    def _validated_agent_payload(
        payload: dict[str, Any],
        evidence_summaries: list[dict[str, Any]],
        *,
        require_structured_static_assessment: bool = True,
    ) -> tuple[dict[str, Any], str]:
        evidence_by_id = {
            item["id"]: item for item in evidence_summaries if isinstance(item.get("id"), str)
        }
        unknown: list[str] = []

        def dynamic_verdict_eligible(item: dict[str, Any]) -> bool:
            metadata = item.get("metadata", {})
            return (
                metadata.get(
                    "dynamic_verdict_eligible",
                    metadata.get("android16_verdict_eligible", True),
                )
                is not False
            )

        def oracle_verdict_eligible(item: dict[str, Any]) -> bool:
            return dynamic_verdict_eligible(item) and (
                item.get("kind") != "dynamic_experiment.adb"
                or item.get("metadata", {}).get("platform_oracle_validated") is True
            )

        def usable_static_summary(item: dict[str, Any]) -> bool:
            return static_evidence_is_usable(
                kind=item.get("kind"),
                metadata=item.get("metadata"),
                exit_code=item.get("exit_code"),
            )

        def resolve_ids(values: Any) -> list[str]:
            resolved: list[str] = []
            for value in values if isinstance(values, list) else []:
                if not isinstance(value, str):
                    continue
                if value in evidence_by_id:
                    resolved.append(value)
                    continue
                prefix_matches = [
                    evidence_id
                    for evidence_id in evidence_by_id
                    if len(value) >= 8 and evidence_id.startswith(value)
                ]
                if len(prefix_matches) == 1:
                    resolved.append(prefix_matches[0])
                else:
                    unknown.append(value)
            return list(dict.fromkeys(resolved))

        resolved_claims = resolve_ids(payload.get("evidence_ids", []))
        nested_ids: list[str] = []
        for assessment in payload.get("hypothesis_assessments", []):
            if not isinstance(assessment, dict):
                continue
            assessment["evidence_ids"] = resolve_ids(assessment.get("evidence_ids", []))
            nested_ids.extend(assessment["evidence_ids"])
        for objection_field in ("review_objections", "objection_resolutions"):
            for item in payload.get(objection_field, []):
                if not isinstance(item, dict):
                    continue
                item["evidence_ids"] = resolve_ids(item.get("evidence_ids", []))
                nested_ids.extend(item["evidence_ids"])
        valid_ids = list(dict.fromkeys(resolved_claims))
        valid_ids = list(dict.fromkeys([*valid_ids, *nested_ids]))
        unknown = sorted(set(unknown))
        result_value = str(payload.get("result", FindingStatus.REFUTED_STATIC.value))
        static_evidence_attached = False
        if result_value in {
            FindingStatus.SUPPORTED_STATIC.value,
            FindingStatus.REFUTED_STATIC.value,
            FindingStatus.REPRODUCED_BLACKBOX.value,
            FindingStatus.NOT_REPRODUCED.value,
        } and not any(
            usable_static_summary(evidence_by_id[evidence_id])
            for evidence_id in valid_ids
        ):
            static_ids = [
                evidence_id
                for evidence_id, item in evidence_by_id.items()
                if usable_static_summary(item)
            ]
            if static_ids:
                valid_ids = list(dict.fromkeys([*valid_ids, *static_ids]))
                static_evidence_attached = True
        payload["evidence_ids"] = valid_ids
        optional_static_tool_markers = (
            "jadx",
            "java decompilation",
            "java source",
            "smali fallback",
            "decompiler output",
        )
        gaps = [
            str(gap)
            for gap in payload.get("coverage_gaps", [])
            if not any(marker in str(gap).lower() for marker in optional_static_tool_markers)
            and not (
                any(
                    marker in str(gap).lower()
                    for marker in (
                        "no device",
                        "device not available",
                        "no dynamic test",
                        "no dynamic reproduction",
                    )
                )
                and any(
                    marker in str(gap).lower()
                    for marker in (
                        "conclusive",
                        "definitive",
                        "merely confirm",
                        "only confirm",
                    )
                )
            )
        ]
        if unknown:
            gaps.append(f"Ignored {len(unknown)} evidence ID(s) not issued for this scan and task.")
        if static_evidence_attached:
            gaps.append("Platform attached the issued static Evidence omitted by the model.")
        cited = [evidence_by_id[value] for value in valid_ids]
        non_verdict_dynamic_cited = any(
            str(item.get("kind") or "").startswith(("blackbox.", "dynamic_experiment."))
            and not dynamic_verdict_eligible(item)
            for item in cited
        )
        if non_verdict_dynamic_cited and result_value in {
            FindingStatus.REPRODUCED_BLACKBOX.value,
            FindingStatus.NOT_REPRODUCED.value,
        }:
            gaps.append(
                "Dynamic Evidence from a non-verdict compatibility scope was retained "
                "for diagnostics but cannot confirm or refute the finding."
            )
        probe_request_tests = {
            (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            for item in cited
            if item["kind"] == "blackbox.probe_app"
            and item.get("exit_code") == 0
            and item.get("metadata", {}).get("caller_identity") == "probe_app"
            and dynamic_verdict_eligible(item)
        }
        log_request_tests = {
            (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            for item in cited
            if item["kind"] == "blackbox.logcat"
            and item.get("metadata", {}).get("request_observed")
            and dynamic_verdict_eligible(item)
        }
        probe_correlated_tests = {
            (request_id, test_case_id)
            for request_id, test_case_id in probe_request_tests & log_request_tests
            if request_id is not None and test_case_id is not None
        }
        poc_request_tests = {
            (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            for item in cited
            if item["kind"] == "blackbox.poc_launch"
            and item.get("exit_code") == 0
            and item.get("metadata", {}).get("caller_identity")
            in {"agent_poc_app", "platform_generated_poc"}
            and dynamic_verdict_eligible(item)
        }
        poc_observation_kinds = {
            "blackbox.poc_logcat",
            "blackbox.poc_durable_receipt",
        }
        poc_observation_request_tests = {
            (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            for item in cited
            if item["kind"] in poc_observation_kinds
            and item.get("metadata", {}).get("request_observed")
            and dynamic_verdict_eligible(item)
        }
        poc_correlated_tests = {
            (request_id, test_case_id)
            for request_id, test_case_id in poc_request_tests & poc_observation_request_tests
            if request_id is not None and test_case_id is not None
        }
        dynamic_experiment_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item["kind"] == "dynamic_experiment.adb"
            and item.get("metadata", {}).get("dynamic_experiment_execution_demonstrated") is True
            and dynamic_verdict_eligible(item)
        } - {None}
        correlated_request_tests = probe_correlated_tests | poc_correlated_tests
        correlated_blackbox = bool(correlated_request_tests or dynamic_experiment_test_ids)
        correlated_blackbox_test_ids = {
            test_case_id for _request_id, test_case_id in correlated_request_tests
        } | dynamic_experiment_test_ids
        independent_poc_effect_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item["kind"] == "blackbox.poc_ui_dump"
            and item.get("metadata", {}).get("impact_contract_satisfied") is True
            and oracle_verdict_eligible(item)
            and (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            in poc_correlated_tests
        } - {None}
        successful_blackbox = (
            bool(dynamic_experiment_test_ids)
            or (
                correlated_blackbox
                and any(
                    (
                        item["kind"] == "blackbox.logcat"
                        and item.get("metadata", {}).get("probe_success")
                        and dynamic_verdict_eligible(item)
                        and (
                            item.get("metadata", {}).get("request_id"),
                            item.get("metadata", {}).get("test_case_id"),
                        )
                        in probe_correlated_tests
                    )
                    or (
                        item["kind"] in poc_observation_kinds
                        and item.get("metadata", {}).get("poc_success")
                        and dynamic_verdict_eligible(item)
                        and (
                            item["kind"] != "blackbox.poc_durable_receipt"
                            or item.get("metadata", {}).get("receipt_terminal") is True
                        )
                        and (
                            item.get("metadata", {}).get("request_id"),
                            item.get("metadata", {}).get("test_case_id"),
                        )
                        in poc_correlated_tests
                    )
                    for item in cited
                )
            )
            or bool(independent_poc_effect_test_ids)
        )
        successful_blackbox_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if (
                (
                    item["kind"] == "blackbox.logcat"
                    and item.get("metadata", {}).get("probe_success")
                    and dynamic_verdict_eligible(item)
                    and (
                        item.get("metadata", {}).get("request_id"),
                        item.get("metadata", {}).get("test_case_id"),
                    )
                    in probe_correlated_tests
                )
                or (
                    item["kind"] in poc_observation_kinds
                    and item.get("metadata", {}).get("poc_success")
                    and dynamic_verdict_eligible(item)
                    and (
                        item["kind"] != "blackbox.poc_durable_receipt"
                        or item.get("metadata", {}).get("receipt_terminal") is True
                    )
                    and (
                        item.get("metadata", {}).get("request_id"),
                        item.get("metadata", {}).get("test_case_id"),
                    )
                    in poc_correlated_tests
                )
            )
        } - {None}
        successful_blackbox_test_ids |= (
            dynamic_experiment_test_ids | independent_poc_effect_test_ids
        )
        impact_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item.get("metadata", {}).get("impact_contract_satisfied") is True
            and oracle_verdict_eligible(item)
        } - {None}
        refuted_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item.get("metadata", {}).get("oracle_refuted") is True
            and oracle_verdict_eligible(item)
        } - {None}
        harmful_blackbox = successful_blackbox and bool(
            successful_blackbox_test_ids & impact_test_ids
        )
        explicitly_refuted = bool(refuted_test_ids & correlated_blackbox_test_ids)
        evidence_valid = True
        if result_value in {
            FindingStatus.SUPPORTED_STATIC.value,
            FindingStatus.REFUTED_STATIC.value,
        }:
            evidence_valid = any(usable_static_summary(item) for item in cited)
        elif result_value == FindingStatus.REPRODUCED_BLACKBOX.value:
            evidence_valid = harmful_blackbox
        elif result_value == FindingStatus.NOT_REPRODUCED.value:
            evidence_valid = explicitly_refuted
        if not evidence_valid:
            static_cited = any(usable_static_summary(item) for item in cited)
            if static_cited and result_value == FindingStatus.REPRODUCED_BLACKBOX.value:
                result_value = FindingStatus.SUPPORTED_STATIC.value
                gaps.append(
                    "Dynamic harm was not correlated by the platform; retained the positive "
                    "conclusion at static-evidence strength."
                )
            elif static_cited and result_value == FindingStatus.NOT_REPRODUCED.value:
                result_value = FindingStatus.SUPPORTED_STATIC.value
                gaps.append(
                    "No platform-correlated negative Oracle exists; the platform refused to "
                    "turn an unexecuted or inconclusive replay into static refutation and "
                    "retained the task as a static risk pending dynamic proof."
                )
            else:
                result_value = FindingStatus.INCONCLUSIVE.value
                gaps.append(
                    "The claimed verdict could not be validated against platform evidence; "
                    "the finding was retained as inconclusive pending further proof."
                )
        for assessment in payload.get("hypothesis_assessments", []):
            if not isinstance(assessment, dict):
                continue
            claimed_assessment = str(assessment.get("verdict") or "")
            explicitly_cited_assessment_evidence_ids = list(
                assessment.get("evidence_ids", [])
                if isinstance(assessment.get("evidence_ids"), list)
                else []
            )
            validation_verdict = (
                FindingStatus.SUPPORTED_STATIC.value
                if claimed_assessment == "needs_dynamic_proof"
                else claimed_assessment
            )
            assessment_payload, assessment_result = ScanOrchestrator._validated_agent_payload(
                {
                    "result": validation_verdict,
                    "evidence_ids": assessment.get("evidence_ids", []),
                    "coverage_gaps": [],
                    "hypothesis_assessments": [],
                },
                evidence_summaries,
                require_structured_static_assessment=False,
            )
            assessment["verdict"] = (
                "needs_dynamic_proof"
                if claimed_assessment
                in {
                    "needs_dynamic_proof",
                    FindingStatus.NOT_REPRODUCED.value,
                }
                and assessment_result == FindingStatus.SUPPORTED_STATIC.value
                else assessment_result
            )
            assessment["evidence_ids"] = assessment_payload["evidence_ids"]
            assessment["proof_gaps"] = list(
                dict.fromkeys(
                    [
                        *assessment.get("proof_gaps", []),
                        *assessment_payload.get("coverage_gaps", []),
                    ]
                )
            )
            if assessment["verdict"] in {
                FindingStatus.SUPPORTED_STATIC.value,
                "needs_dynamic_proof",
            }:
                assessment["unresolved_objection_ids"] = (
                    ScanOrchestrator._unresolved_static_objection_ids(
                        payload,
                        (
                            str(assessment.get("hypothesis_id"))
                            if assessment.get("hypothesis_id") is not None
                            else None
                        ),
                        evidence_by_id,
                    )
                )
                gate = ScanOrchestrator._static_support_gate(
                    assessment,
                    evidence_by_id,
                    evidence_ids=explicitly_cited_assessment_evidence_ids,
                )
                assessment["platform_static_support_gate"] = gate
                if not gate["eligible"]:
                    assessment["model_verdict"] = claimed_assessment
                    assessment["verdict"] = FindingStatus.CANDIDATE.value
                    assessment["suppression_reason"] = "static_support_gate_failed"
                    assessment["suppression_reasons"] = gate["suppression_reasons"]
                    assessment["proof_gaps"] = list(
                        dict.fromkeys(
                            [
                                *assessment["proof_gaps"],
                                (
                                    "Static-support gate suppressed this assessment: "
                                    + ", ".join(gate["suppression_reasons"])
                                    + "."
                                ),
                            ]
                        )
                    )
            elif assessment["verdict"] == FindingStatus.REFUTED_STATIC.value:
                gate = ScanOrchestrator._static_refutation_gate(
                    assessment,
                    evidence_by_id,
                    evidence_ids=explicitly_cited_assessment_evidence_ids,
                )
                assessment["platform_static_refutation_gate"] = gate
                if not gate["eligible"]:
                    assessment["model_verdict"] = claimed_assessment
                    assessment["verdict"] = FindingStatus.CANDIDATE.value
                    assessment["suppression_reason"] = "static_refutation_gate_failed"
                    assessment["suppression_reasons"] = gate["suppression_reasons"]
                    assessment["proof_gaps"] = list(
                        dict.fromkeys(
                            [
                                *assessment["proof_gaps"],
                                (
                                    "Static-refutation gate suppressed this assessment: "
                                    + ", ".join(gate["suppression_reasons"])
                                    + "."
                                ),
                            ]
                        )
                    )
        assessments = [
            item
            for item in payload.get("hypothesis_assessments", [])
            if isinstance(item, dict)
        ]
        if (
            require_structured_static_assessment
            and result_value == FindingStatus.SUPPORTED_STATIC.value
            and not any(
                assessment.get("verdict")
                in {
                    FindingStatus.SUPPORTED_STATIC.value,
                    "needs_dynamic_proof",
                }
                for assessment in assessments
            )
        ):
            result_value = FindingStatus.INCONCLUSIVE.value
            gaps.append(
                "No structured hypothesis assessment passed the platform static-support gate; "
                "the task remains an inconclusive candidate rather than a statically "
                "supported finding."
            )
        if (
            require_structured_static_assessment
            and result_value == FindingStatus.REFUTED_STATIC.value
            and not any(
                assessment.get("verdict") == FindingStatus.REFUTED_STATIC.value
                for assessment in assessments
            )
        ):
            result_value = FindingStatus.INCONCLUSIVE.value
            gaps.append(
                "No hypothesis passed the platform static-refutation gate; the task remains "
                "inconclusive instead of being closed by a model-only negative claim."
            )
        payload["coverage_gaps"] = gaps
        payload["result"] = result_value
        if result_value == FindingStatus.REFUTED_STATIC.value:
            payload["platform_severity"] = None
            payload["severity_disposition"] = "not_applicable_refuted"
        else:
            payload["platform_severity"] = payload.get("severity_proposal")
            payload["severity_disposition"] = "accepted"
        return payload, result_value

    @staticmethod
    def _supersede_prior_agent_findings(
        session,
        task: InvestigationTask,
        result_value: str,
        agent_backend: str,
    ) -> None:  # noqa: ANN001
        current_key = f"agent:{task.id}:{result_value}"
        findings = list(
            session.scalars(
                select(Finding).where(
                    Finding.scan_id == task.scan_id,
                    Finding.source.in_(["codex", "opencode"]),
                    Finding.dedupe_key.like(f"agent:{task.id}:%"),
                    Finding.dedupe_key != current_key,
                )
            )
        )
        for finding in findings:
            metadata = dict(finding.metadata_json or {})
            if (
                finding.status
                in {
                    FindingStatus.FALSE_POSITIVE.value,
                    FindingStatus.ACCEPTED.value,
                }
                and isinstance(finding.review_note, str)
                and finding.review_note.strip()
            ):
                # Automated reruns may append evidence, but only another explicit human review
                # may replace a human disposition.
                continue
            if bool(metadata.get("harm_demonstrated")):
                continue
            if evidence_backed_signal_tier(session, finding) == "runtime_oracle_gap":
                finding.status = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                metadata["signal_tier"] = "runtime_oracle_gap"
                metadata["proof_gap_code"] = "missing_platform_harm_oracle"
                metadata["oracle_gap"] = {
                    **(
                        dict(metadata.get("oracle_gap"))
                        if isinstance(metadata.get("oracle_gap"), dict)
                        else {}
                    ),
                    "schema_version": "1.0",
                    "status": "open",
                    "runtime_observed": True,
                }
                finding.metadata_json = metadata
                continue
            finding.status = FindingStatus.INCONCLUSIVE.value
            finding.metadata_json = {
                **metadata,
                "superseded_by_turn": task.turn_id,
                "superseded_result": result_value,
                "superseded_by_backend": agent_backend,
            }

    def _persist_agent_finding(
        self,
        session,  # noqa: ANN001
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        result_value: str,
        agent_backend: str,
    ) -> None:
        payload = task.result
        evidence_ids = list(payload.get("evidence_ids", []))
        model = self.settings.codex_model if agent_backend == "codex" else None
        hypotheses = list(
            session.scalars(
                select(SecurityHypothesis)
                .where(SecurityHypothesis.task_id == task.id)
                .order_by(SecurityHypothesis.created_at)
            )
        )
        assessment_by_hypothesis = {
            str(item.get("hypothesis_id")): item
            for item in payload.get("hypothesis_assessments", [])
            if isinstance(item, dict) and isinstance(item.get("hypothesis_id"), str)
        }
        entry_name_by_id = {
            entry.id: entry.name
            for entry in session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan.id))
        }
        attempts_by_hypothesis: dict[str, list[ProofAttempt]] = defaultdict(list)
        for attempt in evidence_backed_harm_attempts(
            session,
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_ids={hypothesis.id for hypothesis in hypotheses},
        ):
            attempts_by_hypothesis[attempt.hypothesis_id].append(attempt)
        proven_hypotheses = [
            (hypothesis, attempts_by_hypothesis[hypothesis.id])
            for hypothesis in hypotheses
            if hypothesis.id in attempts_by_hypothesis
        ]
        proven_hypothesis_ids = {hypothesis.id for hypothesis, _attempts in proven_hypotheses}

        if proven_hypotheses:
            for hypothesis, attempts in proven_hypotheses:
                chain_entry_ids = list(
                    dict.fromkeys(
                        [
                            *hypothesis.entry_point_ids,
                            *[
                                str(attempt.plan["entry_point_id"])
                                for attempt in attempts
                                if isinstance(attempt.plan, dict)
                                and isinstance(
                                    attempt.plan.get("entry_point_id"),
                                    str,
                                )
                            ],
                        ]
                    )
                )
                proof_status = FindingStatus.REPRODUCED_BLACKBOX.value
                proof_evidence_ids = list(
                    dict.fromkeys(
                        evidence_id
                        for attempt in attempts
                        for evidence_id in (
                            attempt.evidence_ids
                            if isinstance(attempt.evidence_ids, list)
                            else []
                        )
                        if isinstance(evidence_id, str) and evidence_id
                    )
                )
                proof_rationales = list(
                    dict.fromkeys(
                        str(attempt.plan["rationale"])
                        for attempt in attempts
                        if isinstance(attempt.plan, dict)
                        and isinstance(attempt.plan.get("rationale"), str)
                        and str(attempt.plan["rationale"]).strip()
                    )
                )
                release_gate_eligible = any(
                    bool((attempt.oracle or {}).get("release_gate_eligible"))
                    for attempt in attempts
                )
                android16_verdict_eligible = any(
                    bool((attempt.oracle or {}).get("android16_verdict_eligible"))
                    for attempt in attempts
                )
                proof_scopes = list(
                    dict.fromkeys(
                        str((attempt.oracle or {}).get("verdict_scope"))
                        for attempt in attempts
                        if (attempt.oracle or {}).get("verdict_scope")
                    )
                )
                verdict_scope = (
                    "android16_release"
                    if release_gate_eligible
                    else proof_scopes[0]
                    if proof_scopes
                    else "development_legacy"
                )
                dedupe = f"agent:{task.id}:hypothesis:{hypothesis.id}"
                finding = session.scalar(
                    select(Finding).where(
                        Finding.scan_id == scan.id,
                        Finding.dedupe_key == dedupe,
                    )
                )
                metadata = {
                    "task_id": task.id,
                    "hypothesis_id": hypothesis.id,
                    "agent_backend": agent_backend,
                    "model": model,
                    "coverage_gaps": payload.get("coverage_gaps", []),
                    "harm_demonstrated": True,
                    "android16_verdict_eligible": android16_verdict_eligible,
                    "release_gate_eligible": release_gate_eligible,
                    "verdict_scope": verdict_scope,
                    "proof_attempt_ids": [attempt.id for attempt in attempts],
                    "proof_rationales": proof_rationales,
                    "identity": finding_identity(
                        scan=scan,
                        rule_id="AGENT-ENTRY-INVESTIGATION",
                        category=hypothesis.category,
                        entry_names=[
                            entry_name_by_id.get(entry_id, entry_id) for entry_id in chain_entry_ids
                        ],
                        claim=hypothesis.claim,
                    ),
                }
                report = build_finding_report(
                    task_id=task.id,
                    hypothesis=hypothesis,
                    assessment=assessment_by_hypothesis.get(hypothesis.id),
                    evidence_ids=proof_evidence_ids,
                    attempts=attempts,
                    coverage_gaps=payload.get("coverage_gaps", []),
                )
                metadata["report"] = report.model_dump(mode="json")
                if finding is None:
                    finding = Finding(
                        scan_id=scan.id,
                        dedupe_key=dedupe,
                        rule_id="AGENT-ENTRY-INVESTIGATION",
                        source=agent_backend,
                        title=report.title,
                        description=render_finding_description(report),
                        remediation=render_finding_remediation(report),
                        masvs="MASVS-PLATFORM",
                        severity=payload.get("platform_severity")
                        or payload.get("severity_proposal", "medium"),
                        confidence=payload.get("confidence", "medium"),
                        status=proof_status,
                        entry_point_ids=chain_entry_ids,
                        evidence_ids=proof_evidence_ids,
                        metadata_json=metadata,
                    )
                    session.add(finding)
                    session.flush()
                else:
                    previous_metadata = dict(finding.metadata_json or {})
                    preserve_human_closure = (
                        finding.status
                        in {
                            FindingStatus.FALSE_POSITIVE.value,
                            FindingStatus.ACCEPTED.value,
                        }
                        and isinstance(finding.review_note, str)
                        and bool(finding.review_note.strip())
                    )
                    for merge_key in (
                        "merged_duplicate",
                        "merged_into_finding_id",
                        "merge_basis",
                    ):
                        previous_metadata.pop(merge_key, None)
                    if not preserve_human_closure:
                        finding.source = agent_backend
                        finding.title = report.title
                        finding.description = render_finding_description(report)
                        finding.remediation = render_finding_remediation(report)
                        finding.severity = payload.get("platform_severity") or payload.get(
                            "severity_proposal", "medium"
                        )
                        finding.confidence = payload.get("confidence", "medium")
                        finding.status = proof_status
                        finding.review_note = None
                    finding.entry_point_ids = chain_entry_ids
                    finding.evidence_ids = (
                        list(
                            dict.fromkeys(
                                [*finding.evidence_ids, *proof_evidence_ids]
                            )
                        )
                        if preserve_human_closure
                        else proof_evidence_ids
                    )
                    if preserve_human_closure:
                        metadata["latest_agent_reanalysis"] = {
                            "task_id": task.id,
                            "result": proof_status,
                            "evidence_ids": proof_evidence_ids,
                            "human_closure_preserved": True,
                            "report": metadata.get("report"),
                        }
                    updated_metadata = {
                        **previous_metadata,
                        **metadata,
                    }
                    if preserve_human_closure:
                        if "report" in previous_metadata:
                            updated_metadata["report"] = previous_metadata["report"]
                        else:
                            updated_metadata.pop("report", None)
                    finding.metadata_json = updated_metadata
                hypothesis.final_finding_id = finding.id
                pattern = (
                    self.security_evolution.create_pattern_from_finding(
                        session,
                        scan=scan,
                        finding=finding,
                    )
                    if release_gate_eligible
                    else None
                )
                if pattern is not None:
                    all_entries = list(
                        session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan.id))
                    )
                    new_matches = self.security_evolution.search_patterns(
                        session,
                        scan=scan,
                        entries=all_entries,
                    )
                    self.security_evolution.annotate_new_pattern_matches(
                        session,
                        scan_id=scan.id,
                        matches=new_matches,
                    )

        assessment_records = [
            item
            for item in payload.get("hypothesis_assessments", [])
            if isinstance(item, dict)
        ]
        assessment_evidence_ids = {
            evidence_id
            for assessment in assessment_records
            for evidence_id in assessment.get("evidence_ids", [])
            if isinstance(evidence_id, str) and evidence_id
        }
        assessment_evidence_ids.update(
            evidence_id
            for resolution in payload.get("objection_resolutions", [])
            if isinstance(resolution, dict)
            for evidence_id in (
                resolution.get("evidence_ids", [])
                if isinstance(resolution.get("evidence_ids"), list)
                else []
            )
            if isinstance(evidence_id, str) and evidence_id
        )
        assessment_evidence_by_id = {
            item.id: self._evidence_summary(item)
            for item in (
                session.scalars(
                    select(Evidence).where(
                        Evidence.scan_id == scan.id,
                        Evidence.id.in_(assessment_evidence_ids),
                    )
                )
                if assessment_evidence_ids
                else []
            )
        }
        supported_assessments: list[dict[str, Any]] = []
        static_support_suppressions: list[dict[str, Any]] = []
        for assessment in assessment_records:
            if (
                assessment.get("verdict")
                not in {
                    FindingStatus.SUPPORTED_STATIC.value,
                    "needs_dynamic_proof",
                }
                or assessment.get("hypothesis_id") in proven_hypothesis_ids
            ):
                continue
            assessment["unresolved_objection_ids"] = (
                self._unresolved_static_objection_ids(
                    payload,
                    (
                        str(assessment.get("hypothesis_id"))
                        if assessment.get("hypothesis_id") is not None
                        else None
                    ),
                    assessment_evidence_by_id,
                )
            )
            reported_gate = assessment.get("platform_static_support_gate")
            gate = self._static_support_gate(assessment, assessment_evidence_by_id)
            if isinstance(reported_gate, dict) and reported_gate != gate:
                assessment["reported_static_support_gate"] = reported_gate
            assessment["platform_static_support_gate"] = gate
            if gate.get("eligible") is True:
                supported_assessments.append(assessment)
                continue
            suppression = {
                "hypothesis_id": assessment.get("hypothesis_id"),
                "reason": "static_support_gate_failed",
                "reasons": list(gate.get("suppression_reasons") or []),
            }
            static_support_suppressions.append(suppression)
            assessment["model_verdict"] = assessment.get("model_verdict") or assessment.get(
                "verdict"
            )
            assessment["verdict"] = FindingStatus.CANDIDATE.value
            assessment["suppression_reason"] = suppression["reason"]
            assessment["suppression_reasons"] = suppression["reasons"]
        if static_support_suppressions:
            payload = {
                **dict(payload),
                "hypothesis_assessments": assessment_records,
                "static_support_suppressions": static_support_suppressions,
            }
            task.result = payload
        hypothesis_by_id = {hypothesis.id: hypothesis for hypothesis in hypotheses}
        for suppression in static_support_suppressions:
            hypothesis = hypothesis_by_id.get(str(suppression.get("hypothesis_id")))
            if hypothesis is None or hypothesis.id in proven_hypothesis_ids:
                continue
            hypothesis.status = HypothesisStatus.INCONCLUSIVE.value
            hypothesis.support_evidence_ids = []
            hypothesis.metadata_json = {
                **dict(hypothesis.metadata_json or {}),
                "static_support_suppression": suppression,
            }
        if (
            result_value == FindingStatus.SUPPORTED_STATIC.value
            and not supported_assessments
            and not proven_hypotheses
        ):
            gaps = payload.get("coverage_gaps")
            gaps = [value for value in gaps if isinstance(value, str)] if isinstance(
                gaps, list
            ) else []
            message = (
                "No hypothesis passed the platform static-support gate; the task remains "
                "inconclusive and no supported Finding was emitted."
            )
            payload = {
                **dict(payload),
                "result": FindingStatus.INCONCLUSIVE.value,
                "platform_severity": None,
                "severity_disposition": "not_applicable_inconclusive",
                "coverage_gaps": list(dict.fromkeys([*gaps, message])),
            }
            task.result = payload
            task.status = TaskStatus.INCONCLUSIVE.value
            return
        if (
            result_value
            in {
                FindingStatus.REFUTED_STATIC.value,
                FindingStatus.NOT_REPRODUCED.value,
                FindingStatus.INCONCLUSIVE.value,
            }
            and not supported_assessments
        ):
            return
        if proven_hypotheses and not supported_assessments:
            # Hypothesis-level reproduced findings above fully represent the
            # positive result. Avoid a duplicate task-level weaker record.
            return
        platform_context = (
            payload.get("platform_context")
            if isinstance(payload.get("platform_context"), dict)
            else {}
        )
        executed_tests = platform_context.get("executed_agent_tests", [])
        requested_tests = payload.get("requested_tests", [])
        if isinstance(executed_tests, list) and executed_tests:
            automation_state = "attempted_not_proven"
            proof_reason = "platform_tests_completed_without_harm_oracle"
        elif isinstance(requested_tests, list) and requested_tests:
            automation_state = "blocked_before_execution"
            proof_reason = "agent_requested_tests_not_executed"
        else:
            automation_state = "manual_or_poc_required"
            proof_reason = "agent_did_not_produce_an_automatable_proof"

        for assessment in supported_assessments:
            hypothesis = hypothesis_by_id.get(str(assessment.get("hypothesis_id")))
            if hypothesis is None:
                continue
            signal_entry_ids = list(hypothesis.entry_point_ids) or list(task.target_entry_ids)
            signal_evidence_ids = list(
                dict.fromkeys(
                    evidence_id
                    for evidence_id in assessment.get("evidence_ids", []) or evidence_ids
                    if isinstance(evidence_id, str) and evidence_id
                )
            )
            proof_gaps = list(
                dict.fromkeys(
                    [
                        *[
                            str(gap)
                            for gap in assessment.get("proof_gaps", [])
                            if isinstance(gap, str) and gap
                        ],
                        *[
                            str(gap)
                            for gap in payload.get("coverage_gaps", [])
                            if isinstance(gap, str) and gap
                        ],
                    ]
                )
            )
            proof_backlog = {
                "schema_version": "1.0",
                "status": "proof_required",
                "automation_state": automation_state,
                "reason": proof_reason,
                "task_id": task.id,
                "hypothesis_ids": [hypothesis.id],
                "proof_gaps": proof_gaps,
                "requested_test_count": (
                    len(requested_tests) if isinstance(requested_tests, list) else 0
                ),
                "executed_test_count": (
                    len(executed_tests) if isinstance(executed_tests, list) else 0
                ),
            }
            report = build_finding_report(
                task_id=task.id,
                hypothesis=hypothesis,
                assessment=assessment,
                evidence_ids=signal_evidence_ids,
                coverage_gaps=payload.get("coverage_gaps", []),
            )
            dedupe = f"agent:{task.id}:hypothesis:{hypothesis.id}"
            signal_identity = finding_identity(
                scan=scan,
                rule_id="AGENT-ENTRY-INVESTIGATION",
                category=hypothesis.category,
                entry_names=[
                    entry_name_by_id.get(entry_id, entry_id) for entry_id in signal_entry_ids
                ],
                claim=hypothesis.claim,
            )
            metadata = {
                "task_id": task.id,
                "hypothesis_id": hypothesis.id,
                "agent_backend": agent_backend,
                "model": model,
                "coverage_gaps": payload.get("coverage_gaps", []),
                "harm_demonstrated": False,
                "excluded_proven_hypothesis_ids": sorted(proven_hypothesis_ids),
                "signal_tier": "static_chain",
                "platform_static_support_gate": assessment.get(
                    "platform_static_support_gate"
                ),
                "chain_receipt": {
                    key: assessment.get(key)
                    for key in (
                        "source",
                        "control",
                        "sink",
                        "reachable_path",
                        "boundary",
                        "security_impact",
                        "missing_control",
                    )
                },
                "security_impact": assessment.get("security_impact"),
                "missing_control": assessment.get("missing_control"),
                "proof_backlog": proof_backlog,
                "identity": signal_identity,
                "report": report.model_dump(mode="json"),
            }
            finding = session.scalar(
                select(Finding).where(
                    Finding.scan_id == scan.id,
                    Finding.dedupe_key == dedupe,
                )
            )
            if finding is None:
                finding = Finding(
                    scan_id=scan.id,
                    dedupe_key=dedupe,
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source=agent_backend,
                    title=report.title,
                    description=render_finding_description(report),
                    remediation=render_finding_remediation(report),
                    masvs="MASVS-PLATFORM",
                    severity=payload.get("platform_severity")
                    or payload.get("severity_proposal", "medium"),
                    confidence=assessment.get("confidence") or payload.get("confidence", "medium"),
                    status=FindingStatus.SUPPORTED_STATIC.value,
                    entry_point_ids=signal_entry_ids,
                    evidence_ids=signal_evidence_ids,
                    metadata_json=metadata,
                )
                session.add(finding)
            else:
                previous_metadata = dict(finding.metadata_json or {})
                preserve_human_closure = (
                    finding.status
                    in {
                        FindingStatus.FALSE_POSITIVE.value,
                        FindingStatus.ACCEPTED.value,
                    }
                    and isinstance(finding.review_note, str)
                    and bool(finding.review_note.strip())
                )
                preserve_runtime_observation = (
                    not preserve_human_closure
                    and evidence_backed_signal_tier(session, finding)
                    == "runtime_oracle_gap"
                )
                preserved_runtime_metadata = {
                    key: previous_metadata[key]
                    for key in (
                        "signal_tier",
                        "proof_backlog",
                        "proof_gap_code",
                        "oracle_gap",
                        "adaptive_verification",
                        "adaptive_verification_history",
                        "report",
                    )
                    if key in previous_metadata
                }
                if preserve_runtime_observation:
                    preserved_runtime_metadata["signal_tier"] = "runtime_oracle_gap"
                    preserved_runtime_metadata["proof_gap_code"] = (
                        "missing_platform_harm_oracle"
                    )
                    preserved_runtime_metadata["oracle_gap"] = {
                        **(
                            dict(previous_metadata.get("oracle_gap"))
                            if isinstance(previous_metadata.get("oracle_gap"), dict)
                            else {}
                        ),
                        "schema_version": "1.0",
                        "status": "open",
                        "runtime_observed": True,
                    }
                if not preserve_human_closure:
                    finding.source = agent_backend
                    finding.title = report.title
                    finding.description = render_finding_description(report)
                    finding.remediation = render_finding_remediation(report)
                    finding.severity = payload.get("platform_severity") or payload.get(
                        "severity_proposal", "medium"
                    )
                    finding.confidence = assessment.get("confidence") or payload.get(
                        "confidence", "medium"
                    )
                    finding.status = (
                        FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                        if preserve_runtime_observation
                        else FindingStatus.SUPPORTED_STATIC.value
                    )
                    finding.review_note = None
                finding.entry_point_ids = list(
                    dict.fromkeys([*finding.entry_point_ids, *signal_entry_ids])
                )
                finding.evidence_ids = list(
                    dict.fromkeys([*finding.evidence_ids, *signal_evidence_ids])
                )
                if preserve_human_closure:
                    finding.metadata_json = {
                        **previous_metadata,
                        "latest_agent_reanalysis": {
                            "task_id": task.id,
                            "result": FindingStatus.SUPPORTED_STATIC.value,
                            "evidence_ids": signal_evidence_ids,
                            "human_closure_preserved": True,
                            "report": metadata["report"],
                            "platform_static_support_gate": metadata.get(
                                "platform_static_support_gate"
                            ),
                        },
                    }
                else:
                    finding.metadata_json = {
                        **previous_metadata,
                        **metadata,
                        **(
                            preserved_runtime_metadata
                            if preserve_runtime_observation
                            else {}
                        ),
                        **(
                            {"latest_static_support_report": metadata["report"]}
                            if preserve_runtime_observation
                            else {}
                        ),
                    }
            session.flush()
            hypothesis.final_finding_id = finding.id

    @staticmethod
    def _update_entry_coverage(
        session,
        scan_id: str,
        task: InvestigationTask,
        *,
        stages: dict[str, Any],
        agent_completed: bool,
        coverage_gaps: list[str],
    ) -> None:  # noqa: ANN001
        items = list(
            session.scalars(
                select(CoverageItem).where(
                    CoverageItem.scan_id == scan_id,
                    CoverageItem.entry_point_id.in_(task.target_entry_ids),
                )
            )
        )
        for item in items:
            item_stages = dict(item.stages)
            item_stages["deterministic_dynamic"] = (
                "attempted" if stages["device_attempted"] else "blocked"
            )
            item_stages["blackbox"] = "attempted" if stages["blackbox_attempted"] else "not_tested"
            item_stages["agent"] = "completed" if agent_completed else "not_tested"
            item.stages = item_stages
            complete = agent_completed
            item.status = "covered" if complete and not coverage_gaps else "partial"
            item.gap_reason = "; ".join(dict.fromkeys(coverage_gaps)) or (
                None if complete else task.error or "Investigation coverage is incomplete"
            )

    def _create_scan_seal(
        self,
        session,  # noqa: ANN001
        scan: Scan,
        finding_records: list[Finding],
    ) -> Evidence:
        """Compatibility wrapper around the dedicated finalization service."""

        return self.finalizer.create_scan_seal(session, scan, finding_records)

    def _assign_entry_dispositions(
        self,
        session,  # noqa: ANN001
        scan: Scan,
        finding_records: list[Finding],
        confirmed_finding_ids: set[str],
    ) -> dict[str, str]:
        """Compatibility wrapper around the dedicated finalization service."""

        return self.finalizer.assign_entry_dispositions(
            session,
            scan,
            finding_records,
            confirmed_finding_ids,
        )

    def _finish(self, scan_id: str) -> None:
        self.finalizer.finish(scan_id)
