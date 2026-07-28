from __future__ import annotations

import asyncio
import json
import re
import shutil
import threading
import uuid
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager, suppress
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select, update

from .agent_events import AgentCancelledError, AgentRuntimeEvent
from .agent_prompt import developer_instructions, investigation_prompt
from .artifacts import ArtifactStore
from .codex_runner import CodexInvestigator
from .config import Settings
from .db import Database
from .device import AdbDeviceAdapter, DeviceLeaseCancelledError
from .enums import FindingStatus, ScanStatus, TaskStatus
from .evidence import EvidenceRecorder
from .instrumentation import FridaAdapter
from .mobsf import MobSFAdapter
from .models import (
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from .opencode_runner import (
    AJV_VERSION,
    OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
    OPENCODE_TOOL_PROFILE,
    OPENCODE_WORKSPACE_TOOLS,
    OpenCodeInvestigator,
    opencode_execution_profile,
)
from .planner import InvestigationPlanner
from .poc import PocBuilder, PocBuildResult
from .repository import add_event, now
from .rules import BuiltinRuleEngine
from .schemas import AGENT_RESULT_JSON_SCHEMA, AgentRequestedTest
from .security_pipeline import HypothesisLedger
from .static_analysis import ApkInspector
from .tools import CommandResult, TimeBudget, ToolRunner

AGENT_PLANNING_TIMEOUT_CAP_SECONDS = 300
AGENT_CRITIC_TIMEOUT_CAP_SECONDS = 120
AGENT_FINAL_TIMEOUT_CAP_SECONDS = 180
AGENT_FINAL_RESERVE_SECONDS = 60
AGENT_MIN_OPTIONAL_PHASE_SECONDS = 30


class ScanOrchestrator:
    def __init__(self, settings: Settings, database: Database, store: ArtifactStore):
        self.settings = settings
        self.database = database
        self.store = store
        self.runner = ToolRunner(settings.tool_timeout_seconds)
        self.inspector = ApkInspector(settings, self.runner)
        self.rules = BuiltinRuleEngine()
        self.evidence = EvidenceRecorder(store)
        self.hypothesis_ledger = HypothesisLedger(database)
        self.device = AdbDeviceAdapter(settings, self.runner)
        self.poc_builder = PocBuilder(settings, self.runner, store)
        self.frida = FridaAdapter(settings, self.runner)
        self.mobsf = MobSFAdapter(settings)
        self.codex = CodexInvestigator(settings)
        self.opencode = OpenCodeInvestigator(settings)
        self.investigators = {
            "codex": self.codex,
            "opencode": self.opencode,
        }
        self._running: set[str] = set()
        self._resubmit_requested: set[str] = set()
        self._running_lock = asyncio.Lock()
        self._task_cancellations: dict[str, threading.Event] = {}
        self._task_cancellations_lock = threading.Lock()
        self._shutting_down = threading.Event()
        # Bound task workers across all scans handled by this control-plane
        # process. Per-scan executors may queue work, but model/device orchestration
        # cannot exceed this shared limit.
        self._agent_slots = threading.BoundedSemaphore(settings.agent_concurrency)

    def resolve_investigator(self, requested: str = "configured") -> str:
        backend = (
            self.settings.investigator_backend
            if requested.strip().lower() == "configured"
            else requested.strip().lower()
        )
        if backend not in {*self.investigators, "none"}:
            raise ValueError("investigator must be configured, codex, opencode, or none")
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

    def shutdown(self) -> None:
        """Cancel active orchestration and terminate owned subprocess groups."""
        self._shutting_down.set()
        with self._task_cancellations_lock:
            cancellations = list(self._task_cancellations.values())
        for cancellation in cancellations:
            cancellation.set()
        self.runner.shutdown()
        self.opencode.shutdown()

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
                        queue_data.get("acquired_at")
                        and not queue_data.get("released_at")
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

    def _run_sync(self, scan_id: str) -> None:
        try:
            self._run_static(scan_id)
            self._run_tasks(scan_id)
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
                        cancellation_requested = (
                            task.status == TaskStatus.CANCEL_REQUESTED.value
                        )
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
            result = self.inspector.inspect(
                Path(scan.artifact_path), scan.id, preliminary_budget
            )
            findings, coverage = self.rules.evaluate(result)
            mobsf_result = None
            mobsf_error = None
            if self.mobsf.configured:
                if preliminary_budget.expired:
                    mobsf_error = "MobSF skipped because the preliminary-report budget was exhausted"
                else:
                    try:
                        mobsf_result = self.mobsf.scan(
                            Path(scan.artifact_path), preliminary_budget.remaining()
                        )
                        findings.extend(mobsf_result.findings)
                    except Exception as exc:  # optional external scanner surface
                        mobsf_error = str(exc)
            scan.package_name = result.manifest.package_name
            scan.version_name = result.manifest.version_name
            scan.version_code = result.manifest.version_code
            scan.min_sdk = result.manifest.min_sdk
            scan.target_sdk = result.manifest.target_sdk
            scan.signing = result.signing
            scan.tool_versions = {
                **result.tool_versions,
                "mobsf": self.mobsf.capability(),
            }
            scan.stats = {
                **scan.stats,
                **result.file_inventory,
                "workspace": str(result.workspace),
                "static_finding_count": len(findings),
                "preliminary_deadline": preliminary_deadline.isoformat(),
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
                    {
                        key: value
                        for key, value in anchor.items()
                        if key != "content"
                    }
                    for anchor in code_context.get("anchors", [])
                    if isinstance(anchor, dict)
                ]
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
                        "decompilation": {
                            "status": code_context.get("status", "source_not_found"),
                            "target_in_jadx_failure_list": bool(
                                code_context.get("target_in_jadx_failure_list")
                            ),
                            "target_source_has_decompiler_errors": bool(
                                code_context.get(
                                    "target_source_has_decompiler_errors"
                                )
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
            entry_ids_by_name: dict[str, list[str]] = defaultdict(list)
            for entry in entries:
                entry_ids_by_name[entry.name].append(entry.id)
            for draft in findings:
                entry_ids = [
                    entry_id for name in draft.entry_names for entry_id in entry_ids_by_name.get(name, [])
                ]
                session.add(
                    Finding(
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
                        metadata_json=draft.metadata,
                    )
                )
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
            session.add(
                CoverageItem(
                    scan_id=scan.id,
                    control_id="ENGINE-MOBSF",
                    domain="ENGINE",
                    title="MobSF broad static analysis",
                    status=(
                        "covered"
                        if mobsf_result is not None
                        else "tool_failed"
                        if mobsf_error
                        else "not_tested"
                    ),
                    stages={"static": "completed" if mobsf_result is not None else "not_tested"},
                    gap_reason=(
                        mobsf_error
                        or (
                            None
                            if mobsf_result is not None
                            else "MobSF is optional and was not configured; built-in rules were used."
                        )
                    ),
                )
            )
            for entry in entries:
                session.add(
                    CoverageItem(
                        scan_id=scan.id,
                        control_id=f"ENTRY-{entry.id}",
                        domain="MASVS-PLATFORM",
                        title=f"Entry point: {entry.name}",
                        status="partial",
                        stages={
                            "static": "completed",
                            "deterministic_dynamic": "pending",
                            "agent": "pending",
                            "blackbox": "pending",
                            "instrumented": "pending",
                        },
                        gap_reason="Dynamic and semantic investigation pending.",
                        entry_point_id=entry.id,
                    )
                )
            for tool, payload in result.tool_results.items():
                metadata = (
                    {
                        key: value
                        for key, value in dict(
                            payload.get("decompilation") or {}
                        ).items()
                        if key != "failed_classes"
                    }
                    if tool == "jadx"
                    else None
                )
                self.evidence.json(
                    session,
                    scan_id=scan.id,
                    task_id=None,
                    kind=f"static.{tool}",
                    value=payload,
                    summary=self._static_tool_evidence_summary(tool, payload),
                    metadata=metadata,
                )
            if mobsf_result is not None:
                self.evidence.json(
                    session,
                    scan_id=scan.id,
                    task_id=None,
                    kind="static.mobsf",
                    value=mobsf_result.report,
                    summary=f"MobSF produced {len(mobsf_result.findings)} normalized findings",
                    metadata=mobsf_result.metadata,
                )
            elif mobsf_error:
                add_event(
                    session,
                    scan.id,
                    "static.mobsf_failed",
                    "MobSF failed; built-in static analysis continued",
                    {"error": mobsf_error},
                )
            planner = InvestigationPlanner(
                android_version=self.settings.device_android_version,
                adb_configured=self.device.configured,
            )
            tasks = planner.plan(scan.id, entries)
            session.add_all(tasks)
            scan.status = ScanStatus.PRELIMINARY_READY.value
            scan.preliminary_at = now()
            scan.stats = {
                **scan.stats,
                "entry_point_count": len(entries),
                "task_count": len(tasks),
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
                {"entries": len(entries), "findings": len(findings), "tasks": len(tasks)},
            )
            add_event(
                session,
                scan.id,
                "scan.preliminary_ready",
                "Preliminary report is ready; investigations may continue",
            )
            session.commit()

    def _run_tasks(self, scan_id: str) -> None:
        max_workers = self.settings.agent_concurrency
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            scan.stats = {
                **dict(scan.stats or {}),
                "execution_policy": {
                    "agent_concurrency": max_workers,
                    "adb_concurrency": 1,
                    "device_wait_excluded_from_task_budget": True,
                    "agent_workspace_scope": "task_attempt",
                },
            }
            add_event(
                session,
                scan_id,
                "investigation.pool.started",
                f"入口探索池已启动：最多 {max_workers} 个并发任务，ADB 固定单并发",
                {
                    "agent_concurrency": max_workers,
                    "adb_concurrency": 1,
                },
            )
            session.commit()
        futures: dict[Future[None], str] = {}
        with ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=f"apk-investigation-{scan_id[:8]}",
        ) as executor:
            while True:
                while len(futures) < max_workers:
                    claimed = self._claim_next_task(scan_id)
                    if claimed is None:
                        break
                    task_id, timeout_seconds = claimed
                    future = executor.submit(
                        self._run_task,
                        scan_id,
                        task_id,
                        timeout_seconds,
                    )
                    futures[future] = task_id
                if not futures:
                    return
                completed, _pending = wait(
                    futures,
                    return_when=FIRST_COMPLETED,
                )
                for future in completed:
                    task_id = futures.pop(future)
                    try:
                        future.result()
                    except Exception as exc:
                        self._mark_task_worker_failed(scan_id, task_id, exc)

    def _claim_next_task(self, scan_id: str) -> tuple[str, int] | None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            task = session.scalar(
                select(InvestigationTask)
                .where(
                    InvestigationTask.scan_id == scan_id,
                    InvestigationTask.status == TaskStatus.QUEUED.value,
                )
                .order_by(
                    InvestigationTask.priority.desc(),
                    InvestigationTask.created_at,
                )
                .limit(1)
            )
            if task is None:
                return None
            created_at = scan.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            scan_deadline = created_at + timedelta(
                seconds=self.settings.scan_deadline_seconds
            )
            task_result = dict(task.result or {})
            manual_dispatch = bool(
                task_result.get("manual_rerun")
                or task_result.get("manual_continuation")
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
            self.device.scheduler.wake_waiters()
            return True

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
                or not self.device.configured
                or not scan.package_name
                or not self.device.package_safe(scan.package_name)
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
            task.result = {
                **dict(task.result or {}),
                "device_queue": {
                    "history": history,
                    "serial": self.device.serial,
                    "position_at_enqueue": position,
                    "requested_at": requested_at.isoformat(),
                },
            }
            add_event(
                session,
                scan_id,
                "task.awaiting_device",
                f"任务正在等待唯一云真机，当前排队位置 {position}",
                {
                    "task_id": task_id,
                    "status": TaskStatus.AWAITING_DEVICE.value,
                    "queue_position": position,
                    "priority": task.priority,
                    "device_serial": self.device.serial,
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
                    "device_serial": self.device.serial,
                },
            )
            session.commit()

    def _record_device_acquired(
        self,
        scan_id: str,
        task_id: str,
        waited_seconds: float,
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
                    "acquired_at": acquired_at.isoformat(),
                    "wait_seconds": round(waited_seconds, 3),
                },
            }
            task.status = TaskStatus.RUNNING.value
            add_event(
                session,
                scan_id,
                "task.device_acquired",
                f"任务已独占云真机，等待 {waited_seconds:.1f} 秒",
                {
                    "task_id": task_id,
                    "device_serial": self.device.serial,
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
                    "device_serial": self.device.serial,
                    "wait_seconds": round(waited_seconds, 3),
                },
            )
            session.commit()

    def _record_device_released(
        self,
        scan_id: str,
        task_id: str,
        held_seconds: float,
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
            add_event(
                session,
                scan_id,
                "task.device_released",
                "云真机清理完成，独占租约已释放",
                {
                    "task_id": task_id,
                    "device_serial": self.device.serial,
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
                    "device_serial": self.device.serial,
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
    ):  # noqa: ANN201
        try:
            with self.device.task_lease(
                task_id,
                priority=priority,
                cancel_event=cancel_event,
                on_queued=lambda position: self._mark_task_awaiting_device(
                    scan_id, task_id, position
                ),
                on_acquired=lambda waited: self._record_device_acquired(
                    scan_id, task_id, waited
                ),
                on_released=lambda held: self._record_device_released(
                    scan_id, task_id, held
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
        slot_acquired = False
        with self._task_cancellations_lock:
            self._task_cancellations[task_id] = cancel_event
        try:
            while not self._agent_slots.acquire(timeout=0.25):
                self._raise_if_cancelled(cancel_event)
            slot_acquired = True
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
            if slot_acquired:
                self._agent_slots.release()
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
            entries = list(
                session.scalars(
                    select(EntryPoint).where(
                        EntryPoint.scan_id == scan.id,
                        EntryPoint.id.in_(task.target_entry_ids),
                    )
                )
            )
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
            continuation_context = dict(
                persisted_task_result.get("manual_continuation") or {}
            )
            manual_dispatch = bool(
                persisted_task_result.get("manual_rerun")
                or persisted_task_result.get("manual_continuation")
            )
            agent_backend = self.resolve_task_investigator(scan, task)
            task.status = TaskStatus.RUNNING.value
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
                    "model": (
                        self.settings.codex_worker_model
                        if agent_backend == "codex"
                        else self.settings.opencode_model
                        if agent_backend == "opencode"
                        else None
                    ),
                    "entry_point_ids": list(task.target_entry_ids),
                    "hypotheses": list(task.hypotheses),
                    "continuation_number": continuation_context.get(
                        "continuation_number"
                    ),
                    "reusing_task_evidence": bool(continuation_context),
                    "agent_concurrency": self.settings.agent_concurrency,
                },
            )
            session.commit()

        self.hypothesis_ledger.ensure_task_hypotheses(task)
        hypothesis_context = self.hypothesis_ledger.task_context(task_id)
        hypothesis_ids = {item["id"] for item in hypothesis_context}
        self._raise_if_cancelled(cancel_event)
        task_budget_seconds = (
            self.settings.task_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
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
                    "continuation_number": continuation_context.get(
                        "continuation_number"
                    ),
                    "prior_evidence_count": len(evidence_summaries),
                    "new_budget_seconds": task_budget_seconds,
                },
            )
        target_code_context = self._target_code_context(scan_id, entries)
        coverage_gaps: list[str] = []
        stages: dict[str, Any] = {
            "device_attempted": False,
            "blackbox_attempted": False,
            "authenticated_blackbox": False,
            "instrumented_attempted": False,
            "instrumented_observed": False,
        }
        device_capability = self.device.capability(non_blocking=True)
        auth_capability: dict[str, Any] = {"available": False, "detail": "not evaluated"}
        frida_capability = self.frida.capability(deep=False)
        agent_result = None
        agent_error = None
        executed_agent_tests: list[dict[str, Any]] = []
        debate_context: dict[str, Any] = {}
        package_name = scan.package_name
        investigator = self.investigators.get(agent_backend)
        agent_enabled = self.settings.investigator_enabled(agent_backend)

        def invoke_agent(
            *,
            phase: str,
            timeout_cap: int | None = None,
            executed_tests: list[dict[str, Any]] | None = None,
            candidate_under_review: dict[str, Any] | None = None,
            round_index: int = 0,
        ):  # noqa: ANN202
            audit_id: str | None = None
            runtime_events: list[dict[str, Any]] = []
            self._raise_if_cancelled(cancel_event)
            if investigator is None:
                return None, "AI investigation is disabled for this scan"
            if not agent_enabled:
                return None, f"{agent_backend} investigation is disabled"

            def dispatch_remaining() -> int:
                remaining_seconds = budget.remaining()
                if timeout_cap is not None:
                    remaining_seconds = min(remaining_seconds, timeout_cap)
                return remaining_seconds

            remaining = dispatch_remaining()
            if remaining <= 0:
                return None, "task time budget exhausted before AI dispatch"
            capability = investigator.capability(deep=True)
            self._raise_if_cancelled(cancel_event)
            if not capability.get("available"):
                return None, capability.get(
                    "detail", f"{agent_backend} capability probe failed"
                )
            remaining = dispatch_remaining()
            if remaining <= 0:
                return None, "task time budget exhausted during AI capability probe"
            try:
                platform_context = {
                    "phase": phase,
                    "round_index": round_index,
                    "device": device_capability,
                    "authentication": auth_capability,
                    "frida": frida_capability,
                    "poc_builder": self.poc_builder.capability(),
                    "coverage_gaps": coverage_gaps,
                    "target_code_context": target_code_context,
                    "executed_agent_tests": executed_tests or [],
                    "further_test_rounds_available": (
                        phase != "final_evaluation"
                        and round_index < self.settings.agent_max_rounds
                    ),
                    "exploration_limits": {
                        "max_rounds": self.settings.agent_max_rounds,
                        "tests_per_round": self.settings.agent_tests_per_round,
                    },
                    "continuation": continuation_context or None,
                    "security_hypotheses": hypothesis_context,
                    "candidate_under_review": candidate_under_review,
                    "debate": debate_context or None,
                }
                agent_workspace = self._materialize_agent_evidence(
                    scan_id,
                    task_id,
                    task.attempts,
                    evidence_summaries,
                    platform_context=platform_context,
                )
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
                            item.get("status")
                            for item in target_code_context.get("components", [])
                        ],
                        "executed_test_count": len(executed_tests or []),
                        "agent_backend": agent_backend,
                    },
                )
                audit_id = self._record_agent_request(
                    scan=scan,
                    task=task,
                    entries=entries,
                    evidence=evidence_summaries,
                    platform_context=platform_context,
                    backend=agent_backend,
                    phase=phase,
                    capability=capability,
                )

                def on_runtime_event(event: AgentRuntimeEvent) -> None:
                    record = {
                        "sequence": len(runtime_events) + 1,
                        "event_type": event.event_type,
                        "message": event.message,
                        "data": event.data,
                        "created_at": datetime.now(UTC).isoformat(),
                    }
                    runtime_events.append(record)
                    self._record_exploration_event(
                        scan_id,
                        task_id,
                        event.event_type,
                        event.message,
                        {
                            "source": "sdk",
                            "phase": phase,
                            "round_index": round_index,
                            "agent_backend": agent_backend,
                            **event.data,
                        },
                    )

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
                result = investigator.investigate(
                    scan=scan,
                    task=task,
                    entries=entries,
                    workspace=agent_workspace,
                    evidence=evidence_summaries,
                    platform_context=platform_context,
                    timeout_seconds=remaining,
                    event_callback=on_runtime_event,
                    cancel_event=cancel_event,
                )
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
                role = (
                    "critic"
                    if phase == "adversarial_review"
                    else "hunter"
                    if phase in {"static_only", "test_planning"}
                    else "advocate"
                )
                self.hypothesis_ledger.record_argument(
                    task_id=task_id,
                    role=role,
                    phase=phase,
                    backend=agent_backend,
                    model=(
                        self.settings.codex_worker_model
                        if agent_backend == "codex"
                        else self.settings.opencode_model
                    ),
                    payload=result.result.model_dump(mode="json"),
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
                for request in result.result.requested_tests[
                    : self.settings.agent_tests_per_round
                ]:
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
                            "poc_package": (
                                request.poc.package_name if request.poc else None
                            ),
                            "poc_project_path": (
                                request.poc.project_path if request.poc else None
                            ),
                        },
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

        # A busy non-blocking snapshot remains eligible for the device queue, but
        # an explicit unavailable result should degrade directly to static AI.
        device_ready = bool(
            self.device.configured
            and package_name
            and self.device.package_safe(package_name)
            and (
                device_capability.get("available")
                or device_capability.get("busy")
            )
        )
        if not device_ready:
            package_gap = (
                "Manifest package name is unsafe for remote ADB commands."
                if package_name and not self.device.package_safe(package_name)
                else None
            )
            coverage_gaps.append(
                str(
                    package_gap
                    or device_capability.get("detail")
                    or "Remote Android 16 device is unavailable or package metadata is missing."
                )
            )
            agent_result, agent_error = invoke_agent(
                phase="static_only",
                timeout_cap=AGENT_PLANNING_TIMEOUT_CAP_SECONDS,
            )
        else:
            device_session = self._task_device_session(
                scan_id,
                task_id,
                priority=int(task.priority),
                cancel_event=cancel_event,
            )
            lease_metadata = device_session.__enter__()
            budget = budget.extend(
                lease_metadata["wait_seconds"],
                maximum_deadline=scan_deadline,
            )
            if device_session is not None:
                frida_session = None
                prepared = False
                target_installed = False
                try:
                    stages["device_attempted"] = True
                    prepare_commands = self.device.prepare(
                        Path(scan.artifact_path), package_name, budget
                    )
                    self._record_commands(
                        scan_id, task_id, prepare_commands, evidence_summaries
                    )
                    target_installed = any(
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
                    else:
                        prepared = True
                        if not self.settings.probe_apk_path:
                            coverage_gaps.append(
                                "Probe APK is not configured; adb-shell results do not prove "
                                "ordinary third-party app reachability."
                            )
                        elif not any(
                            kind == "device.install_probe" and result.exit_code == 0
                            for kind, result, _metadata in prepare_commands
                        ):
                            coverage_gaps.append(
                                "Probe APK installation failed; ordinary-app-UID reachability is unverified."
                            )

                        if self.frida.configured:
                            stages["instrumented_attempted"] = True
                            frida_session, startup_error = self.frida.start(package_name, budget)
                            if startup_error is not None:
                                self._record_commands(
                                    scan_id,
                                    task_id,
                                    [
                                        (
                                            "instrumented.frida",
                                            startup_error,
                                            self.frida.metadata(startup_error),
                                        )
                                    ],
                                    evidence_summaries,
                                )
                                coverage_gaps.append(
                                    startup_error.stderr or "Frida could not attach to the target."
                                )
                        for entry in entries:
                            if budget.expired:
                                break
                            probe = self.device.probe(
                                entry, package_name, state="guest", budget=budget
                            )
                            stages["blackbox_attempted"] = True
                            self._record_commands(
                                scan_id, task_id, probe.commands, evidence_summaries
                            )

                        auth_capability = self.device.auth_capability(package_name)
                        auth_commands = self.device.authenticate(package_name, budget)
                        self._record_commands(
                            scan_id, task_id, auth_commands, evidence_summaries
                        )
                        auth_ok = bool(auth_capability.get("available")) and all(
                            result.exit_code == 0
                            for _kind, result, _metadata in auth_commands
                        )
                        if auth_ok:
                            stages["authenticated_blackbox"] = True
                            for entry in entries:
                                if budget.expired:
                                    break
                                probe = self.device.probe(
                                    entry,
                                    package_name,
                                    state="authenticated",
                                    budget=budget,
                                )
                                self._record_commands(
                                    scan_id, task_id, probe.commands, evidence_summaries
                                )
                        else:
                            coverage_gaps.append(
                                str(
                                    auth_capability.get("detail")
                                    or "Authenticated-state replay failed."
                                )
                            )

                        if frida_session is not None:
                            frida_result = self.frida.collect(frida_session)
                            frida_session = None
                            frida_metadata = self.frida.metadata(frida_result)
                            stages["instrumented_observed"] = bool(
                                frida_metadata["capture_success"]
                                and frida_metadata["observation_count"] > 0
                            )
                            self._record_commands(
                                scan_id,
                                task_id,
                                [("instrumented.frida", frida_result, frida_metadata)],
                                evidence_summaries,
                            )
                            if not stages["instrumented_observed"]:
                                coverage_gaps.append(
                                    "Frida was attempted but produced no validated entry-flow observations."
                                )
                    if target_installed:
                        cleanup = self.device.cleanup(package_name)
                        self._record_commands(scan_id, task_id, cleanup, None)
                    completed_device_session = device_session
                    device_session = None
                    completed_device_session.__exit__(None, None, None)
                    planning_reserve = min(
                        AGENT_CRITIC_TIMEOUT_CAP_SECONDS
                        + AGENT_FINAL_RESERVE_SECONDS,
                        max(0, budget.remaining() // 3),
                    )
                    phase_one_cap = min(
                        AGENT_PLANNING_TIMEOUT_CAP_SECONDS,
                        max(1, budget.remaining() - planning_reserve),
                    )
                    agent_result, agent_error = invoke_agent(
                        phase="test_planning",
                        timeout_cap=phase_one_cap,
                        round_index=0,
                    )
                    critic_budget = min(
                        AGENT_CRITIC_TIMEOUT_CAP_SECONDS,
                        max(
                            0,
                            budget.remaining() - AGENT_FINAL_RESERVE_SECONDS,
                        ),
                    )
                    if (
                        agent_result is not None
                        and not budget.expired
                        and critic_budget >= AGENT_MIN_OPTIONAL_PHASE_SECONDS
                    ):
                        candidate_payload = agent_result.result.model_dump(mode="json")
                        critic_result, critic_error = invoke_agent(
                            phase="adversarial_review",
                            timeout_cap=critic_budget,
                            candidate_under_review=candidate_payload,
                            round_index=0,
                        )
                        if critic_result is not None:
                            critic_payload = critic_result.result.model_dump(mode="json")
                            debate_context = {
                                "candidate": candidate_payload,
                                "critic": critic_payload,
                                "critic_thread_id": critic_result.thread_id,
                                "critic_turn_id": critic_result.turn_id,
                            }
                            merged_requests: list[AgentRequestedTest] = []
                            seen_requests: set[str] = set()
                            for request in [
                                *agent_result.result.requested_tests,
                                *critic_result.result.requested_tests,
                            ]:
                                signature = json.dumps(
                                    request.model_dump(mode="json"),
                                    sort_keys=True,
                                )
                                if signature in seen_requests:
                                    continue
                                seen_requests.add(signature)
                                merged_requests.append(request)
                            agent_result.result = agent_result.result.model_copy(
                                update={
                                    "requested_tests": merged_requests[
                                        : self.settings.agent_tests_per_round
                                    ],
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
                            self._record_exploration_event(
                                scan_id,
                                task_id,
                                "debate.completed",
                                "Hunter 候选已完成独立 Critic 质疑",
                                {
                                    "source": "platform",
                                    "candidate_result": candidate_payload.get("result"),
                                    "critic_result": critic_payload.get("result"),
                                    "critic_objection_count": len(
                                        critic_payload.get("coverage_gaps", [])
                                    ),
                                    "merged_test_count": len(merged_requests),
                                },
                            )
                        elif critic_error:
                            coverage_gaps.append(
                                f"Adversarial review was unavailable: {critic_error}"
                            )
                    elif agent_result is not None and not budget.expired:
                        coverage_gaps.append(
                            "Adversarial review was skipped to preserve the final-evaluation "
                            "budget."
                        )
                    completed_rounds = 0
                    while (
                        agent_result
                        and agent_result.result.requested_tests
                        and prepared
                        and completed_rounds < self.settings.agent_max_rounds
                        and not budget.expired
                    ):
                        planning_result = agent_result
                        planning_turn_id = planning_result.turn_id
                        submitted_tests = [
                            item.model_dump(mode="json")
                            for item in planning_result.result.requested_tests
                        ]
                        requested, request_gaps = self._validate_requested_tests(
                            planning_result.result.requested_tests,
                            entries,
                            auth_available=bool(auth_capability.get("available")),
                            limit=self.settings.agent_tests_per_round,
                            hypothesis_ids=hypothesis_ids,
                        )
                        poc_artifacts: dict[str, PocBuildResult] = {}
                        if requested:
                            agent_workspace = (
                                self.settings.data_dir
                                / "workspaces"
                                / scan_id
                                / "agent_context"
                                / task_id
                                / f"attempt-{task.attempts}"
                            )
                            (
                                requested,
                                poc_artifacts,
                                poc_build_gaps,
                            ) = self._build_requested_pocs(
                                scan_id=scan_id,
                                task_id=task_id,
                                workspace=agent_workspace,
                                requests=requested,
                                evidence_summaries=evidence_summaries,
                                cancel_event=cancel_event,
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
                                        accepted.poc.package_name
                                        if accepted.poc
                                        else None
                                    ),
                                },
                            )
                        if request_gaps or len(requested) < len(submitted_tests):
                            self._record_exploration_event(
                                scan_id,
                                task_id,
                                "action.rejected",
                                "部分 AI 测试申请被平台边界策略拒绝或截断",
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
                        requested_observed = False
                        if requested and not budget.expired:
                            with self._task_device_session(
                                scan_id,
                                task_id,
                                priority=int(task.priority),
                                cancel_event=cancel_event,
                            ) as requested_lease:
                                budget = budget.extend(
                                    requested_lease["wait_seconds"],
                                    maximum_deadline=scan_deadline,
                                )
                                round_target_installed = False
                                try:
                                    round_prepare = self.device.prepare(
                                        Path(scan.artifact_path),
                                        package_name,
                                        budget,
                                    )
                                    self._record_commands(
                                        scan_id,
                                        task_id,
                                        round_prepare,
                                        evidence_summaries,
                                    )
                                    round_target_installed = any(
                                        kind == "device.install"
                                        and result.exit_code == 0
                                        for kind, result, _metadata in round_prepare
                                    )
                                    round_critical = {
                                        kind: result
                                        for kind, result, _metadata in round_prepare
                                        if kind
                                        in {
                                            "device.health",
                                            "device.install",
                                            "device.clear",
                                        }
                                        and result.exit_code != 0
                                    }
                                    if round_critical:
                                        failures = ", ".join(
                                            f"{kind}=exit {result.exit_code}"
                                            for kind, result in round_critical.items()
                                        )
                                        execution_gaps.append(
                                            "Device preparation failed before "
                                            f"agent-requested tests: {failures}"
                                        )
                                    else:
                                        (
                                            executed_this_round,
                                            execution_gaps,
                                            requested_observed,
                                        ) = self._execute_requested_tests(
                                            scan_id=scan_id,
                                            task_id=task_id,
                                            package_name=package_name,
                                            entries=entries,
                                            requests=requested,
                                            budget=budget,
                                            evidence_summaries=evidence_summaries,
                                            round_index=completed_rounds + 1,
                                            poc_artifacts=poc_artifacts,
                                        )
                                finally:
                                    if round_target_installed:
                                        cleanup = self.device.cleanup(package_name)
                                        self._record_commands(
                                            scan_id,
                                            task_id,
                                            cleanup,
                                            None,
                                        )
                            executed_agent_tests.extend(executed_this_round)
                            coverage_gaps.extend(execution_gaps)
                            stages["instrumented_attempted"] = (
                                stages["instrumented_attempted"]
                                or (bool(requested) and self.frida.configured)
                            )
                            stages["instrumented_observed"] = (
                                stages["instrumented_observed"] or requested_observed
                            )
                        elif requested:
                            execution_gaps.append(
                                "Task budget expired before accepted AI-requested tests ran."
                            )
                            coverage_gaps.extend(execution_gaps)

                        self._record_agent_test_validation(
                            task_id=task_id,
                            turn_id=planning_turn_id,
                            submitted=submitted_tests,
                            accepted=[
                                item.model_dump(mode="json") for item in requested
                            ],
                            executed=executed_this_round,
                            gaps=[*request_gaps, *execution_gaps],
                        )
                        completed_rounds += 1
                        if (
                            not executed_this_round
                            or budget.expired
                            or completed_rounds >= self.settings.agent_max_rounds
                        ):
                            break
                        exploration_budget = min(
                            AGENT_PLANNING_TIMEOUT_CAP_SECONDS,
                            max(
                                0,
                                budget.remaining() - AGENT_FINAL_RESERVE_SECONDS,
                            ),
                        )
                        if exploration_budget < AGENT_MIN_OPTIONAL_PHASE_SECONDS:
                            coverage_gaps.append(
                                "Adaptive AI exploration was skipped to preserve the "
                                "final-evaluation budget."
                            )
                            break
                        next_result, next_error = invoke_agent(
                            phase="exploration_round",
                            timeout_cap=exploration_budget,
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

                    if (
                        agent_result
                        and agent_result.result.requested_tests
                        and completed_rounds >= self.settings.agent_max_rounds
                    ):
                        coverage_gaps.append(
                            "Further AI-requested tests were not executed because the configured "
                            "adaptive exploration round limit was reached."
                        )
                    final_budget = min(
                        AGENT_FINAL_TIMEOUT_CAP_SECONDS,
                        budget.remaining(),
                    )
                    if (
                        (executed_agent_tests or debate_context)
                        and final_budget >= AGENT_MIN_OPTIONAL_PHASE_SECONDS
                    ):
                        final_result, final_error = invoke_agent(
                            phase="final_evaluation",
                            timeout_cap=final_budget,
                            executed_tests=executed_agent_tests,
                            round_index=completed_rounds,
                        )
                        if final_result is not None:
                            agent_result = final_result
                            agent_error = None
                            if final_result.result.requested_tests:
                                coverage_gaps.append(
                                    "Final evaluation requested additional tests, but final turns "
                                    "cannot schedule new device actions."
                                )
                        else:
                            coverage_gaps.append(
                                "Final AI evaluation failed; retained the latest exploration result: "
                                f"{final_error}"
                            )
                    elif (executed_agent_tests or debate_context) and not budget.expired:
                        coverage_gaps.append(
                            "Final AI evaluation was skipped because less than "
                            f"{AGENT_MIN_OPTIONAL_PHASE_SECONDS} seconds remained; retained "
                            "the latest validated planning result."
                        )
                except AgentCancelledError:
                    raise
                except Exception as exc:
                    if frida_session is not None:
                        frida_result = self.frida.collect(frida_session)
                        frida_session = None
                        self._record_commands(
                            scan_id,
                            task_id,
                            [
                                (
                                    "instrumented.frida",
                                    frida_result,
                                    self.frida.metadata(frida_result),
                                )
                            ],
                            evidence_summaries,
                        )
                    if device_session is not None:
                        if target_installed:
                            cleanup = self.device.cleanup(package_name)
                            self._record_commands(
                                scan_id,
                                task_id,
                                cleanup,
                                None,
                            )
                        failed_device_session = device_session
                        device_session = None
                        failed_device_session.__exit__(None, None, None)
                    coverage_gaps.append(f"Dynamic investigation failed safely: {exc}")
                    if agent_result is None:
                        agent_result, agent_error = invoke_agent(
                            phase="recovery_evaluation",
                            timeout_cap=AGENT_FINAL_TIMEOUT_CAP_SECONDS,
                        )
                finally:
                    if frida_session is not None:
                        frida_result = self.frida.collect(frida_session)
                        self._record_commands(
                            scan_id,
                            task_id,
                            [
                                (
                                    "instrumented.frida",
                                    frida_result,
                                    self.frida.metadata(frida_result),
                                )
                            ],
                            evidence_summaries,
                        )
                    if device_session is not None and target_installed:
                        cleanup = self.device.cleanup(package_name)
                        self._record_commands(scan_id, task_id, cleanup, None)
                    if device_session is not None:
                        final_device_session = device_session
                        device_session = None
                        final_device_session.__exit__(None, None, None)

        self._raise_if_cancelled(cancel_event)
        validated_payload: dict[str, Any] | None = None
        validated_result_value: str | None = None
        if agent_result:
            raw_payload = agent_result.result.model_dump(mode="json")
            validated_payload, validated_result_value = self._validated_agent_payload(
                deepcopy(raw_payload), evidence_summaries
            )
            platform_proof = self.hypothesis_ledger.task_proof_result(task_id)
            if platform_proof is not None:
                proof_status, proof_evidence_ids = platform_proof
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
                validated_result_value = proof_status
                validated_payload["result"] = proof_status
                validated_payload["evidence_ids"] = list(
                    dict.fromkeys(
                        [
                            *validated_payload.get("evidence_ids", []),
                            *proof_evidence_ids,
                        ]
                    )
                )
                validated_payload["platform_severity"] = validated_payload.get(
                    "severity_proposal"
                )
                validated_payload["severity_disposition"] = (
                    "accepted_from_platform_harm_oracle"
                )
            self._record_agent_validation(
                task_id=task_id,
                turn_id=agent_result.turn_id,
                raw_payload=raw_payload,
                validated_payload=validated_payload,
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
                                "device": device_capability,
                                "authentication": auth_capability,
                                "frida": frida_capability,
                                "executed_agent_tests": executed_agent_tests,
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
                        },
                    },
                )
            else:
                terminal_values.update(
                    {
                        "status": TaskStatus.BLOCKED_DEVICE.value,
                        "error": agent_error or str(device_capability.get("detail")),
                        "result": {
                            **existing_result,
                            "coverage_gaps": coverage_gaps,
                            "static_agent_attempted": agent_enabled,
                            "agent_backend": agent_backend,
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
                    select(InvestigationTask.status).where(
                        InvestigationTask.id == task_id
                    )
                )
                if current_status in {
                    TaskStatus.CANCEL_REQUESTED.value,
                    TaskStatus.DELETED.value,
                }:
                    raise AgentCancelledError(
                        "task cancellation won the terminal-state transition"
                    )
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
                    model=(
                        self.settings.codex_worker_model
                        if agent_backend == "codex"
                        else self.settings.opencode_model
                    ),
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
                self._supersede_prior_agent_findings(
                    session, task, result_value, agent_backend
                )
                self._persist_agent_finding(
                    session,
                    scan,
                    task,
                    entries,
                    result_value,
                    agent_backend,
                )
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

    @staticmethod
    def _raise_if_cancelled(cancel_event: threading.Event) -> None:
        if cancel_event.is_set():
            raise AgentCancelledError("investigation was cancelled by the user")

    def _mark_task_canceled(self, scan_id: str, task_id: str) -> None:
        with self.database.session_factory() as session:
            for _attempt in range(3):
                task = session.get(InvestigationTask, task_id)
                if task is None:
                    return
                observed_status = task.status
                completed_at = now()
                existing_cancellation = dict(
                    (task.result or {}).get("cancellation") or {}
                )
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
    def _validate_requested_tests(
        requests: list[AgentRequestedTest],
        entries: list[EntryPoint],
        *,
        auth_available: bool,
        limit: int = 800,
        hypothesis_ids: set[str] | None = None,
    ) -> tuple[list[AgentRequestedTest], list[str]]:
        entries_by_id = {entry.id: entry for entry in entries}
        accepted: list[AgentRequestedTest] = []
        gaps: list[str] = []
        seen: set[str] = set()
        for request in requests[:limit]:
            entry = entries_by_id.get(request.entry_point_id)
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
            elif request.state == "authenticated" and not auth_available:
                reason = "authenticated replay is unavailable"
            elif any(
                not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", key)
                for key in request.extras
            ):
                reason = "an extra key is unsafe"
            elif any(
                (isinstance(value, str) and len(value) > 1000)
                or (isinstance(value, int) and not -(2**63) <= value < 2**63)
                for value in request.extras.values()
            ):
                reason = "an extra value exceeds its safety bound"
            elif entry.kind == "provider" and request.extras and request.poc is None:
                reason = "provider probes do not accept Intent extras"
            elif request.uri is not None:
                reason = ScanOrchestrator._validate_requested_uri(entry, request.uri)
            elif entry.kind == "deep_link" and not entry.name:
                reason = "deep-link URI is unavailable"
            if reason:
                gaps.append(f"Rejected agent-requested test for {request.entry_point_id}: {reason}.")
                continue
            signature = json.dumps(request.model_dump(mode="json"), sort_keys=True)
            if signature in seen:
                continue
            seen.add(signature)
            accepted.append(request)
        if len(requests) > limit:
            gaps.append(
                f"Rejected {len(requests) - limit} agent-requested test(s) above the "
                f"per-round limit of {limit}."
            )
        return accepted, gaps

    @staticmethod
    def _poc_request_key(request: AgentRequestedTest) -> str:
        if request.poc is None:
            return ""
        return json.dumps(request.poc.model_dump(mode="json"), sort_keys=True)

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
        accepted: list[AgentRequestedTest] = []
        artifacts: dict[str, PocBuildResult] = {}
        gaps: list[str] = []
        for request in requests:
            if request.poc is None:
                accepted.append(request)
                continue
            key = self._poc_request_key(request)
            outcome = artifacts.get(key)
            if outcome is None:
                self._record_exploration_event(
                    scan_id,
                    task_id,
                    "poc.build.started",
                    "开始构建 Agent 生成的受控 PoC APK",
                    {
                        "source": "platform",
                        "hypothesis_id": request.hypothesis_id,
                        "entry_point_id": request.entry_point_id,
                        "package": request.poc.package_name,
                        "project_path": request.poc.project_path,
                    },
                )
                outcome = self.poc_builder.build(
                    workspace,
                    request.poc,
                    cancel_event=cancel_event,
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
                                "spec": request.poc.model_dump(mode="json"),
                                **outcome.metadata,
                            },
                            summary=(
                                "Platform built and signed an Agent PoC APK "
                                f"{outcome.apk_sha256}"
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
                        "Agent PoC 已完成受控构建、签名和哈希登记",
                        {
                            "source": "platform",
                            "package": request.poc.package_name,
                            "apk_sha256": outcome.apk_sha256,
                            "source_sha256": outcome.source_sha256,
                            "evidence_id": outcome.metadata.get("build_evidence_id"),
                        },
                    )
                else:
                    self._record_exploration_event(
                        scan_id,
                        task_id,
                        "poc.build.failed",
                        "Agent PoC 构建失败，未进入设备队列",
                        {
                            "source": "platform",
                            "package": request.poc.package_name,
                            "error": outcome.error,
                        },
                    )
            if outcome.ok:
                accepted.append(request)
            else:
                gaps.append(
                    "Rejected Agent PoC test for "
                    f"{request.entry_point_id}: {outcome.error or 'build failed'}."
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
        if entry.kind in {"deep_link", "activity"}:
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
                item
                for item in str(entry.metadata_json.get("authorities") or "").split(";")
                if item
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
    ) -> tuple[list[dict[str, Any]], list[str], bool]:
        poc_artifacts = poc_artifacts or {}
        entries_by_id = {entry.id: entry for entry in entries}
        indexed = [
            (f"agent-r{round_index}-{index + 1}", request)
            for index, request in enumerate(requests)
        ]
        executed: list[dict[str, Any]] = []
        gaps: list[str] = []
        instrumented_observed = False
        for state in ("guest", "authenticated"):
            state_requests = [item for item in indexed if item[1].state == state]
            if not state_requests or budget.expired:
                continue
            for test_case_id, request in state_requests:
                if budget.expired:
                    gaps.append("Task budget expired before all agent-requested tests ran.")
                    break
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
                        "poc_package": (
                            request.poc.package_name if request.poc else None
                        ),
                    },
                )

                def tagged(commands, *, case_id: str = test_case_id):  # noqa: ANN001, ANN202
                    return [
                        (
                            kind,
                            result,
                            {**dict(metadata), "test_case_id": case_id},
                        )
                        for kind, result, metadata in commands
                    ]

                reset = tagged(self.device.reset_session(package_name, budget))
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

                if state == "authenticated":
                    auth = tagged(self.device.authenticate(package_name, budget))
                    self._record_commands(scan_id, task_id, auth, evidence_summaries)
                    if any(result.exit_code != 0 for _kind, result, _metadata in auth):
                        proof_evidence = evidence_summaries[before:]
                        error = (
                            f"Authenticated replay failed before requested test {test_case_id}."
                        )
                        self.hypothesis_ledger.complete_proof(
                            proof_attempt_id,
                            proof_evidence,
                            error=error,
                        )
                        gaps.append(error)
                        continue

                frida_session, frida_error = self.frida.start(package_name, budget)
                if frida_error is not None:
                    self._record_commands(
                        scan_id,
                        task_id,
                        tagged(
                            [
                                (
                                    "instrumented.frida",
                                    frida_error,
                                    self.frida.metadata(frida_error),
                                )
                            ]
                        ),
                        evidence_summaries,
                    )
                execution_error: Exception | None = None
                try:
                    if request.poc is not None:
                        artifact = poc_artifacts.get(self._poc_request_key(request))
                        if artifact is None or not artifact.ok or artifact.apk_path is None:
                            raise RuntimeError(
                                "Agent PoC was not built by the platform before execution"
                            )
                        probe = self.device.execute_poc(
                            artifact.apk_path,
                            request.poc,
                            state=state,
                            budget=budget,
                            extras=dict(request.extras),
                            test_case_id=test_case_id,
                        )
                        for index, (kind, result, metadata) in enumerate(probe.commands):
                            probe.commands[index] = (
                                kind,
                                result,
                                {
                                    **metadata,
                                    "poc_apk_sha256": artifact.apk_sha256,
                                    "poc_source_sha256": artifact.source_sha256,
                                    "poc_build_evidence_id": artifact.metadata.get(
                                        "build_evidence_id"
                                    ),
                                },
                            )
                    else:
                        probe = self.device.probe(
                            entries_by_id[request.entry_point_id],
                            package_name,
                            state=state,
                            budget=budget,
                            uri_override=request.uri,
                            extras=dict(request.extras),
                            test_case_id=test_case_id,
                        )
                    self._record_commands(
                        scan_id, task_id, probe.commands, evidence_summaries
                    )
                except Exception as exc:
                    execution_error = exc
                finally:
                    if frida_session is not None:
                        result = self.frida.collect(frida_session)
                        metadata = {
                            **self.frida.metadata(result),
                            "test_case_id": test_case_id,
                        }
                        instrumented_observed = instrumented_observed or bool(
                            metadata["capture_success"]
                            and metadata["observation_count"] > 0
                        )
                        self._record_commands(
                            scan_id,
                            task_id,
                            [("instrumented.frida", result, metadata)],
                            evidence_summaries,
                        )

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
                    raise execution_error
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
        return executed, gaps, instrumented_observed

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
    ) -> str:
        provider = "openai" if backend == "codex" else "deepseek"
        model = (
            self.settings.codex_worker_model
            if backend == "codex"
            else self.settings.opencode_model
        )
        execution_profile = (
            opencode_execution_profile(
                phase,
                reasoning_effort=self.settings.opencode_reasoning_effort,
                enable_thinking_explorer=self.settings.opencode_thinking_explorer,
            )
            if backend == "opencode"
            else None
        )
        opencode_workspace_tools = bool(
            execution_profile
            and any(stage.workspace_tools for stage in execution_profile.stages)
        )
        direct_tool_access = backend == "codex" or opencode_workspace_tools
        shell_access = backend == "codex" or opencode_workspace_tools
        workspace_write = backend == "opencode" and opencode_workspace_tools
        output_mode = (
            execution_profile.output_mode
            if execution_profile is not None
            else "json_schema"
        )
        isolation = (
            self.settings.codex_isolation
            if backend == "codex"
            else self.settings.opencode_isolation
        )
        audit_id = str(uuid.uuid4())
        metadata = {
            "audit_id": audit_id,
            "backend": backend,
            "provider": provider,
            "model": model,
            "isolation": isolation,
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
        )
        request = {
            "schema_version": "1.0",
            "backend": backend,
            "provider": provider,
            "model": model,
            "sdk_version": capability.get("version"),
            "isolation": isolation,
            "provider_base_url": (
                self.settings.deepseek_base_url or "provider_default"
                if backend == "opencode"
                else "provider_default"
            ),
            "phase": phase,
            "task_id": task.id,
            "attempt": task.attempts,
            "developer_instructions": developer_instructions(
                direct_tool_access=direct_tool_access,
                shell_access=shell_access,
                workspace_write=workspace_write,
            ),
            "prompt": prompt,
            "explorer_instructions": (
                developer_instructions(
                    direct_tool_access=True,
                    shell_access=True,
                    workspace_write=True,
                    response_contract="analysis_memo",
                )
                if backend == "opencode"
                and execution_profile is not None
                and any(stage.output_mode == "text" for stage in execution_profile.stages)
                else None
            ),
            "explorer_prompt": (
                investigation_prompt(
                    scan,
                    task,
                    entries,
                    evidence,
                    platform_context,
                    direct_tool_access=True,
                    shell_access=True,
                    workspace_write=True,
                    response_contract="analysis_memo",
                )
                if backend == "opencode"
                and execution_profile is not None
                and any(stage.output_mode == "text" for stage in execution_profile.stages)
                else None
            ),
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
            "tool_boundary": {
                "direct_tool_access": direct_tool_access,
                "model_tools_enabled": direct_tool_access,
                "workspace_tool_profile": (
                    OPENCODE_TOOL_PROFILE if backend == "opencode" else "codex_readonly"
                ),
                "workspace_tools": (
                    list(OPENCODE_WORKSPACE_TOOLS)
                    if backend == "opencode" and opencode_workspace_tools
                    else ["file", "shell"]
                    if backend == "codex"
                    else []
                ),
                "shell_enabled": shell_access,
                "write_enabled": workspace_write,
                "native_write_tools_enabled": False,
                "allowed_write_roots": (
                    ["task_attempt_workspace", "/tmp"] if workspace_write else []
                ),
                "shared_scan_workspace_exposed": False,
                "network_enabled": backend == "opencode",
                "network_policy": (
                    "container_bridge; target requests prohibited by developer instructions"
                    if backend == "opencode" and opencode_workspace_tools
                    else "sandbox_disabled"
                ),
                "adb_enabled": False,
                "subagents_enabled": False,
                "structured_output_tool_enabled": (
                    backend == "opencode"
                    and execution_profile is not None
                    and any(
                        stage.output_mode == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
                        for stage in execution_profile.stages
                    )
                ),
                "platform_executes_requested_tests": True,
            },
            "runtime_options": {
                "reasoning_effort": (
                    "medium"
                    if backend == "codex"
                    else self.settings.opencode_reasoning_effort
                ),
                "output_mode": output_mode,
                "execution_profile": (
                    execution_profile.as_payload()
                    if execution_profile is not None
                    else None
                ),
                "max_agent_steps": (
                    self.settings.opencode_agent_steps
                    if backend == "opencode"
                    else None
                ),
                "max_provider_requests": (
                    self.settings.opencode_agent_steps + 100
                    if backend == "opencode"
                    else None
                ),
                "structured_output_retries": (
                    2
                    if backend == "opencode"
                    and execution_profile is not None
                    and any(
                        stage.output_mode == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
                        for stage in execution_profile.stages
                    )
                    else None
                ),
                "schema_validator": (
                    f"ajv@{AJV_VERSION}"
                    if backend == "opencode"
                    and execution_profile is not None
                    else None
                ),
                "semantic_validator": (
                    "apkscanner@1.0"
                    if backend == "opencode"
                    and execution_profile is not None
                    else None
                ),
            },
        }
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan.id,
                task_id=task.id,
                kind="agent.request",
                value=request,
                summary=f"{backend} {phase} request",
                metadata=metadata,
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
            "provider": "openai" if backend == "codex" else "deepseek",
            "model": (
                self.settings.codex_worker_model
                if backend == "codex"
                else self.settings.opencode_model
            ),
            "isolation": (
                self.settings.codex_isolation
                if backend == "codex"
                else self.settings.opencode_isolation
            ),
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
            "usage": result.usage,
            "output_transport": getattr(result, "output_transport", {}),
        }
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.response",
                value=response,
                summary=f"{backend} {phase} structured response",
                metadata=metadata,
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
            "provider": "openai" if backend == "codex" else "deepseek",
            "model": (
                self.settings.codex_worker_model
                if backend == "codex"
                else self.settings.opencode_model
            ),
            "isolation": (
                self.settings.codex_isolation
                if backend == "codex"
                else self.settings.opencode_isolation
            ),
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
            "provider": "openai" if backend == "codex" else "deepseek",
            "model": (
                self.settings.codex_worker_model
                if backend == "codex"
                else self.settings.opencode_model
            ),
            "isolation": (
                self.settings.codex_isolation
                if backend == "codex"
                else self.settings.opencode_isolation
            ),
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
            "provider": "openai" if backend == "codex" else "deepseek",
            "model": (
                self.settings.codex_worker_model
                if backend == "codex"
                else self.settings.opencode_model
            ),
            "isolation": (
                self.settings.codex_isolation
                if backend == "codex"
                else self.settings.opencode_isolation
            ),
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
                    "downgraded": (
                        raw_payload.get("result") != validated_payload.get("result")
                    ),
                    "claimed_evidence_ids": claimed_evidence,
                    "accepted_evidence_ids": accepted_evidence,
                    "rejected_evidence_ids": sorted(
                        set(claimed_evidence) - set(accepted_evidence)
                    ),
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
                    "target_in_jadx_failure_list": bool(
                        raw.get("target_in_jadx_failure_list")
                    ),
                    "target_source_has_decompiler_errors": bool(
                        raw.get("target_source_has_decompiler_errors")
                    ),
                    "global_decompilation_status": raw.get(
                        "global_decompilation_status"
                    ),
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

    def _load_or_build_code_index(self, scan_id: str) -> dict[str, Any] | None:
        workspace = self.settings.data_dir / "workspaces" / scan_id
        index_path = workspace / "code_index.json"
        try:
            value = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                return value
        except (OSError, json.JSONDecodeError):
            pass

        with self.database.session_factory() as session:
            entries = list(
                session.scalars(
                    select(EntryPoint).where(EntryPoint.scan_id == scan_id)
                )
            )
            jadx_evidence = session.scalar(
                select(Evidence)
                .where(
                    Evidence.scan_id == scan_id,
                    Evidence.kind == "static.jadx",
                )
                .order_by(Evidence.created_at.desc())
                .limit(1)
            )
        if not entries or not workspace.is_dir():
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
                argv=[
                    str(value)
                    for value in payload.get("argv", [])
                    if isinstance(value, str)
                ],
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
            workspace=workspace,
            jadx_dir=workspace / "jadx",
            decoded_dir=workspace / "apktool",
            archive_dir=workspace / "archive",
            decompilation=decompilation,
        )
        value = {
            "schema_version": "1.0",
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
        identifiers = [item["id"] for item in summaries if isinstance(item.get("id"), str)]
        task_root = (
            self.settings.data_dir
            / "workspaces"
            / scan_id
            / "agent_context"
            / task_id
            / f"attempt-{attempt}"
        )
        evidence_root = task_root / "evidence"
        evidence_root.mkdir(parents=True, exist_ok=True)
        self._materialize_target_sources(
            scan_id,
            task_root,
            platform_context or {},
        )
        with self.database.session_factory() as session:
            records = list(
                session.scalars(select(Evidence).where(Evidence.id.in_(identifiers)))
            )
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
        context = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "task_id": task_id,
            "attempt": attempt,
            "evidence": summaries,
            "platform_context": platform_context or {},
            "workspace_policy": {
                "writable_root": ".",
                "shared_scan_workspace_exposed": False,
                "reason": (
                    "Concurrent agents receive isolated writable roots; relevant target code "
                    "and immutable evidence are materialized in this context."
                ),
            },
        }
        (task_root / "context.json").write_text(
            json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return task_root

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
        scan_workspace = (
            self.settings.data_dir / "workspaces" / scan_id
        ).resolve()
        source_root = (task_root / "target_source").resolve()
        copied_bytes = 0
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
                if (
                    not source.is_relative_to(scan_workspace)
                    or not source.is_file()
                ):
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
                item = self.evidence.command(
                    session,
                    scan_id=scan_id,
                    task_id=task_id,
                    kind=kind,
                    result=command_result,
                    metadata=metadata,
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
                        "test_case_id": metadata.get("test_case_id"),
                        "request_id": metadata.get("request_id"),
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
    def _validated_agent_payload(
        payload: dict[str, Any], evidence_summaries: list[dict[str, Any]]
    ) -> tuple[dict[str, Any], str]:
        evidence_by_id = {
            item["id"]: item for item in evidence_summaries if isinstance(item.get("id"), str)
        }
        claimed = [value for value in payload.get("evidence_ids", []) if isinstance(value, str)]
        valid_ids = list(dict.fromkeys(value for value in claimed if value in evidence_by_id))
        unknown = sorted(set(claimed) - evidence_by_id.keys())
        payload["evidence_ids"] = valid_ids
        gaps = list(payload.get("coverage_gaps", []))
        if unknown:
            gaps.append(
                f"Ignored {len(unknown)} evidence ID(s) not issued for this scan and task."
            )
        cited = [evidence_by_id[value] for value in valid_ids]
        probe_request_tests = {
            (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            for item in cited
            if item["kind"] == "blackbox.probe_app"
            and item.get("exit_code") == 0
            and item.get("metadata", {}).get("caller_identity") == "probe_app"
        }
        log_request_tests = {
            (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            for item in cited
            if item["kind"] == "blackbox.logcat"
            and item.get("metadata", {}).get("request_observed")
        }
        correlated_request_tests = {
            (request_id, test_case_id)
            for request_id, test_case_id in probe_request_tests & log_request_tests
            if request_id is not None and test_case_id is not None
        }
        correlated_blackbox = bool(correlated_request_tests)
        correlated_blackbox_test_ids = {
            test_case_id
            for _request_id, test_case_id in correlated_request_tests
        }
        successful_blackbox = correlated_blackbox and any(
            item["kind"] == "blackbox.logcat"
            and (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            in correlated_request_tests
            and item.get("metadata", {}).get("probe_success")
            for item in cited
        )
        successful_blackbox_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item["kind"] == "blackbox.logcat"
            and (
                item.get("metadata", {}).get("request_id"),
                item.get("metadata", {}).get("test_case_id"),
            )
            in correlated_request_tests
            and item.get("metadata", {}).get("probe_success")
        } - {None}
        instrumented_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item["kind"] == "instrumented.frida"
            and item.get("metadata", {}).get("capture_success")
            and item.get("metadata", {}).get("observation_count", 0) > 0
        } - {None}
        impact_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item.get("metadata", {}).get("security_impact_observed") is True
        } - {None}
        refuted_test_ids = {
            item.get("metadata", {}).get("test_case_id")
            for item in cited
            if item.get("metadata", {}).get("oracle_refuted") is True
        } - {None}
        harmful_blackbox = successful_blackbox and bool(
            successful_blackbox_test_ids & impact_test_ids
        )
        harmful_instrumented = bool(instrumented_test_ids & impact_test_ids)
        explicitly_refuted = bool(
            refuted_test_ids
            & (correlated_blackbox_test_ids | instrumented_test_ids)
        )
        result_value = str(payload.get("result", FindingStatus.INCONCLUSIVE.value))
        evidence_valid = True
        if result_value == FindingStatus.SUPPORTED_STATIC.value:
            evidence_valid = any(item["kind"].startswith("static.") for item in cited)
        elif result_value == FindingStatus.REPRODUCED_BLACKBOX.value:
            evidence_valid = harmful_blackbox
        elif result_value == FindingStatus.OBSERVED_INSTRUMENTED.value:
            evidence_valid = harmful_instrumented
        elif result_value == FindingStatus.NOT_REPRODUCED.value:
            evidence_valid = explicitly_refuted
        if not evidence_valid:
            gaps.append(
                f"{result_value} was downgraded because its required platform evidence "
                "or correlated concrete-harm Oracle was absent."
            )
            result_value = FindingStatus.INCONCLUSIVE.value
        payload["coverage_gaps"] = gaps
        payload["result"] = result_value
        if result_value == FindingStatus.INCONCLUSIVE.value:
            payload["platform_severity"] = None
            payload["severity_disposition"] = "undetermined_due_to_incomplete_evidence"
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
            if bool((finding.metadata_json or {}).get("harm_demonstrated")):
                continue
            finding.status = FindingStatus.INCONCLUSIVE.value
            finding.metadata_json = {
                **finding.metadata_json,
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
        model = (
            self.settings.codex_worker_model
            if agent_backend == "codex"
            else self.settings.opencode_model
            if agent_backend == "opencode"
            else None
        )
        hypotheses = list(
            session.scalars(
                select(SecurityHypothesis)
                .where(SecurityHypothesis.task_id == task.id)
                .order_by(SecurityHypothesis.created_at)
            )
        )
        proven_hypotheses: list[
            tuple[SecurityHypothesis, list[ProofAttempt]]
        ] = []
        for hypothesis in hypotheses:
            attempts = list(
                session.scalars(
                    select(ProofAttempt)
                    .where(
                        ProofAttempt.hypothesis_id == hypothesis.id,
                        ProofAttempt.harm_demonstrated.is_(True),
                    )
                    .order_by(ProofAttempt.created_at)
                )
            )
            if attempts:
                proven_hypotheses.append((hypothesis, attempts))

        if proven_hypotheses:
            for hypothesis, attempts in proven_hypotheses:
                instrumented = any(
                    bool((attempt.oracle or {}).get("instrumented_observation"))
                    for attempt in attempts
                )
                proof_status = (
                    FindingStatus.OBSERVED_INSTRUMENTED.value
                    if instrumented
                    else FindingStatus.REPRODUCED_BLACKBOX.value
                )
                proof_evidence_ids = list(
                    dict.fromkeys(
                        evidence_id
                        for attempt in attempts
                        for evidence_id in attempt.evidence_ids
                    )
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
                    "proof_attempt_ids": [attempt.id for attempt in attempts],
                }
                if finding is None:
                    finding = Finding(
                        scan_id=scan.id,
                        dedupe_key=dedupe,
                        rule_id="AGENT-ENTRY-INVESTIGATION",
                        source=agent_backend,
                        title=f"Validated hypothesis: {hypothesis.claim}",
                        description=payload.get(
                            "summary",
                            hypothesis.impact or "Platform harm Oracle succeeded.",
                        ),
                        remediation=(
                            "Review the affected handler and enforce input validation, "
                            "caller authorization, and explicit trust-boundary checks."
                        ),
                        masvs="MASVS-PLATFORM",
                        severity=payload.get("platform_severity")
                        or payload.get("severity_proposal", "medium"),
                        confidence=payload.get("confidence", "medium"),
                        status=proof_status,
                        entry_point_ids=list(hypothesis.entry_point_ids),
                        evidence_ids=proof_evidence_ids,
                        metadata_json=metadata,
                    )
                    session.add(finding)
                    session.flush()
                else:
                    finding.source = agent_backend
                    finding.title = f"Validated hypothesis: {hypothesis.claim}"
                    finding.description = payload.get(
                        "summary",
                        hypothesis.impact or "Platform harm Oracle succeeded.",
                    )
                    finding.severity = payload.get("platform_severity") or payload.get(
                        "severity_proposal", "medium"
                    )
                    finding.confidence = payload.get("confidence", "medium")
                    finding.status = proof_status
                    finding.entry_point_ids = list(hypothesis.entry_point_ids)
                    finding.evidence_ids = proof_evidence_ids
                    finding.metadata_json = {
                        **dict(finding.metadata_json or {}),
                        **metadata,
                    }
                hypothesis.final_finding_id = finding.id
            return

        if result_value in {
            FindingStatus.NOT_REPRODUCED.value,
            FindingStatus.INCONCLUSIVE.value,
        }:
            return
        dedupe = f"agent:{task.id}:{result_value}"
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
                title=f"Agent investigation: {entries[0].name if entries else task.id}",
                description=payload.get("summary", "Agent investigation result"),
                remediation="Review the affected handler and enforce validation and caller authorization.",
                masvs="MASVS-PLATFORM",
                severity=payload.get("platform_severity")
                or payload.get("severity_proposal", "medium"),
                confidence=payload.get("confidence", "medium"),
                status=result_value,
                entry_point_ids=task.target_entry_ids,
                evidence_ids=evidence_ids,
                metadata_json={
                    "task_id": task.id,
                    "agent_backend": agent_backend,
                    "model": model,
                    "coverage_gaps": payload.get("coverage_gaps", []),
                    "harm_demonstrated": False,
                },
            )
            session.add(finding)
        else:
            finding.source = agent_backend
            finding.description = payload.get("summary", "Agent investigation result")
            finding.severity = payload.get("platform_severity") or payload.get(
                "severity_proposal", "medium"
            )
            finding.confidence = payload.get("confidence", "medium")
            finding.status = result_value
            finding.evidence_ids = evidence_ids
            finding.metadata_json = {
                "task_id": task.id,
                "agent_backend": agent_backend,
                "model": model,
                "coverage_gaps": payload.get("coverage_gaps", []),
                "harm_demonstrated": False,
            }

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
            item_stages["blackbox"] = (
                "attempted" if stages["blackbox_attempted"] else "not_tested"
            )
            item_stages["authenticated_blackbox"] = (
                "attempted" if stages["authenticated_blackbox"] else "not_tested"
            )
            item_stages["instrumented"] = (
                "observed"
                if stages["instrumented_observed"]
                else "attempted"
                if stages["instrumented_attempted"]
                else "not_tested"
            )
            item_stages["agent"] = "completed" if agent_completed else "not_tested"
            item.stages = item_stages
            complete = (
                agent_completed
                and stages["blackbox_attempted"]
                and stages["authenticated_blackbox"]
            )
            item.status = "covered" if complete and not coverage_gaps else "partial"
            item.gap_reason = "; ".join(dict.fromkeys(coverage_gaps)) or (
                None if complete else task.error or "Investigation coverage is incomplete"
            )

    def _finish(self, scan_id: str) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            counts: dict[str, int] = defaultdict(int)
            for status in session.scalars(
                select(InvestigationTask.status).where(InvestigationTask.scan_id == scan_id)
            ):
                counts[status] += 1
            finding_count = len(
                list(session.scalars(select(Finding.id).where(Finding.scan_id == scan_id)))
            )
            scan.status = ScanStatus.FINAL.value
            scan.completed_at = datetime.now(UTC)
            scan.stats = {
                **scan.stats,
                "task_status_counts": dict(counts),
                "finding_count": finding_count,
            }
            add_event(
                session,
                scan_id,
                "scan.final",
                "Final report is ready",
                {"task_status_counts": dict(counts), "findings": finding_count},
            )
            session.commit()
