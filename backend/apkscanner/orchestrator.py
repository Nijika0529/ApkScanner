from __future__ import annotations

import asyncio
import json
import re
import shutil
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from .artifacts import ArtifactStore
from .codex_runner import CodexInvestigator
from .config import Settings
from .db import Database
from .device import AdbDeviceAdapter
from .enums import FindingStatus, ScanStatus, TaskStatus
from .evidence import EvidenceRecorder
from .instrumentation import FridaAdapter
from .mobsf import MobSFAdapter
from .models import CoverageItem, EntryPoint, Evidence, Finding, InvestigationTask, Scan
from .opencode_runner import OpenCodeInvestigator
from .planner import InvestigationPlanner
from .repository import add_event, now
from .rules import BuiltinRuleEngine
from .schemas import AgentRequestedTest
from .static_analysis import ApkInspector
from .tools import TimeBudget, ToolRunner


class ScanOrchestrator:
    def __init__(self, settings: Settings, database: Database, store: ArtifactStore):
        self.settings = settings
        self.database = database
        self.store = store
        self.runner = ToolRunner(settings.tool_timeout_seconds)
        self.inspector = ApkInspector(settings, self.runner)
        self.rules = BuiltinRuleEngine()
        self.evidence = EvidenceRecorder(store)
        self.device = AdbDeviceAdapter(settings, self.runner)
        self.frida = FridaAdapter(settings, self.runner)
        self.mobsf = MobSFAdapter(settings)
        self.codex = CodexInvestigator(settings)
        self.opencode = OpenCodeInvestigator(settings)
        self.investigators = {
            "codex": self.codex,
            "opencode": self.opencode,
        }
        self._running: set[str] = set()
        self._running_lock = asyncio.Lock()

    def resolve_investigator(self, requested: str = "configured") -> str:
        backend = (
            self.settings.investigator_backend
            if requested.strip().lower() == "configured"
            else requested.strip().lower()
        )
        if backend not in {*self.investigators, "none"}:
            raise ValueError("investigator must be configured, codex, opencode, or none")
        return backend

    async def submit(self, scan_id: str) -> None:
        async with self._running_lock:
            if scan_id in self._running:
                return
            self._running.add(scan_id)
        try:
            await asyncio.to_thread(self._run_sync, scan_id)
        finally:
            async with self._running_lock:
                self._running.discard(scan_id)

    def _run_sync(self, scan_id: str) -> None:
        try:
            self._run_static(scan_id)
            self._run_tasks(scan_id)
            self._finish(scan_id)
        except Exception as exc:
            with self.database.session_factory() as session:
                scan = session.get(Scan, scan_id)
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.error = str(exc)
                    scan.completed_at = now()
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
            }
            entries: list[EntryPoint] = []
            for parsed in result.manifest.entries:
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
                    metadata_json=parsed.metadata,
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
                self.evidence.json(
                    session,
                    scan_id=scan.id,
                    task_id=None,
                    kind=f"static.{tool}",
                    value=payload,
                    summary=f"{tool} exited with {payload['exit_code']}",
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
        while True:
            with self.database.session_factory() as session:
                scan = session.get(Scan, scan_id)
                assert scan is not None
                created_at = scan.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=UTC)
                scan_deadline = created_at + timedelta(
                    seconds=self.settings.scan_deadline_seconds
                )
                task = session.scalar(
                    select(InvestigationTask)
                    .where(
                        InvestigationTask.scan_id == scan_id,
                        InvestigationTask.status == TaskStatus.QUEUED.value,
                    )
                    .order_by(InvestigationTask.priority.desc(), InvestigationTask.created_at)
                    .limit(1)
                )
            if task is None:
                return
            remaining = int((scan_deadline - datetime.now(UTC)).total_seconds())
            if remaining <= 0:
                with self.database.session_factory() as session:
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
                return
            self._run_task(scan_id, task.id, min(self.settings.task_timeout_seconds, remaining))

    def _run_task(self, scan_id: str, task_id: str, timeout_seconds: int | None = None) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            task = session.get(InvestigationTask, task_id)
            assert scan is not None and task is not None
            entries = list(
                session.scalars(select(EntryPoint).where(EntryPoint.id.in_(task.target_entry_ids)))
            )
            agent_backend = self.resolve_investigator(
                str(scan.stats.get("investigator", "configured"))
            )
            task.status = TaskStatus.RUNNING.value
            task.attempts += 1
            task.started_at = now()
            scan.status = ScanStatus.INVESTIGATING.value
            add_event(
                session,
                scan_id,
                "task.started",
                f"Investigation started for {len(entries)} entry point(s)",
                {"task_id": task.id, "agent_backend": agent_backend},
            )
            session.commit()

        budget = TimeBudget.from_seconds(timeout_seconds or self.settings.task_timeout_seconds)
        evidence_summaries = self._static_evidence_summaries(scan_id)
        coverage_gaps: list[str] = []
        stages: dict[str, Any] = {
            "device_attempted": False,
            "blackbox_attempted": False,
            "authenticated_blackbox": False,
            "instrumented_attempted": False,
            "instrumented_observed": False,
        }
        device_capability = self.device.capability()
        auth_capability: dict[str, Any] = {"available": False, "detail": "not evaluated"}
        frida_capability = self.frida.capability(deep=False)
        agent_result = None
        agent_error = None
        executed_agent_tests: list[dict[str, Any]] = []
        package_name = scan.package_name
        investigator = self.investigators.get(agent_backend)
        agent_enabled = self.settings.investigator_enabled(agent_backend)

        def invoke_agent(
            *,
            phase: str,
            timeout_cap: int | None = None,
            executed_tests: list[dict[str, Any]] | None = None,
        ):  # noqa: ANN202
            if investigator is None:
                return None, "AI investigation is disabled for this scan"
            if not agent_enabled:
                return None, f"{agent_backend} investigation is disabled"
            remaining = budget.remaining()
            if timeout_cap is not None:
                remaining = min(remaining, timeout_cap)
            if remaining <= 0:
                return None, "task time budget exhausted before AI dispatch"
            capability = investigator.capability(deep=True)
            if not capability.get("available"):
                return None, capability.get(
                    "detail", f"{agent_backend} capability probe failed"
                )
            try:
                self._materialize_agent_evidence(
                    scan_id,
                    task_id,
                    task.attempts,
                    evidence_summaries,
                )
                return (
                    investigator.investigate(
                        scan=scan,
                        task=task,
                        entries=entries,
                        workspace=self.settings.data_dir / "workspaces" / scan_id,
                        evidence=evidence_summaries,
                        platform_context={
                            "phase": phase,
                            "device": device_capability,
                            "authentication": auth_capability,
                            "frida": frida_capability,
                            "coverage_gaps": coverage_gaps,
                            "executed_agent_tests": executed_tests or [],
                            "further_test_rounds_available": phase == "test_planning",
                        },
                        timeout_seconds=remaining,
                    ),
                    None,
                )
            except Exception as exc:
                return None, str(exc)

        device_ready = bool(
            device_capability.get("available")
            and package_name
            and self.device.package_safe(package_name)
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
            agent_result, agent_error = invoke_agent(phase="static_only")
        else:
            with self.device.lease():
                frida_session = None
                prepared = False
                try:
                    stages["device_attempted"] = True
                    prepare_commands = self.device.prepare(
                        Path(scan.artifact_path), package_name, budget
                    )
                    self._record_commands(
                        scan_id, task_id, prepare_commands, evidence_summaries
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
                        else:
                            coverage_gaps.append(
                                str(frida_capability.get("detail") or "Frida is not configured.")
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
                    phase_one_cap = max(1, budget.remaining() // 2)
                    agent_result, agent_error = invoke_agent(
                        phase="test_planning", timeout_cap=phase_one_cap
                    )
                    if agent_result and agent_result.result.requested_tests and prepared:
                        requested, request_gaps = self._validate_requested_tests(
                            agent_result.result.requested_tests,
                            entries,
                            auth_available=bool(auth_capability.get("available")),
                        )
                        coverage_gaps.extend(request_gaps)
                        if requested and not budget.expired:
                            executed_agent_tests, execution_gaps, requested_observed = (
                                self._execute_requested_tests(
                                    scan_id=scan_id,
                                    task_id=task_id,
                                    package_name=package_name,
                                    entries=entries,
                                    requests=requested,
                                    budget=budget,
                                    evidence_summaries=evidence_summaries,
                                )
                            )
                            coverage_gaps.extend(execution_gaps)
                            stages["instrumented_attempted"] = (
                                stages["instrumented_attempted"]
                                or (bool(requested) and self.frida.configured)
                            )
                            stages["instrumented_observed"] = (
                                stages["instrumented_observed"] or requested_observed
                            )
                            final_result, final_error = invoke_agent(
                                phase="final_evaluation",
                                executed_tests=executed_agent_tests,
                            )
                            if final_result is not None:
                                agent_result = final_result
                                agent_error = None
                                if final_result.result.requested_tests:
                                    coverage_gaps.append(
                                        "Additional agent-requested tests were not executed because "
                                        "the platform permits one bounded follow-up round per task."
                                    )
                            else:
                                coverage_gaps.append(
                                    "Final AI evaluation failed; retained first-pass result: "
                                    f"{final_error}"
                                )
                except Exception as exc:
                    coverage_gaps.append(f"Dynamic investigation failed safely: {exc}")
                    if agent_result is None:
                        agent_result, agent_error = invoke_agent(phase="recovery_evaluation")
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
                    if prepared or stages["device_attempted"]:
                        cleanup = self.device.cleanup(package_name)
                        self._record_commands(scan_id, task_id, cleanup, None)

        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            scan = session.get(Scan, scan_id)
            assert task is not None and scan is not None
            if agent_result:
                payload, result_value = self._validated_agent_payload(
                    agent_result.result.model_dump(mode="json"), evidence_summaries
                )
                task.thread_id = agent_result.thread_id
                task.turn_id = agent_result.turn_id
                task.result = {
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
                }
                task.status = (
                    TaskStatus.NOT_REPRODUCED.value
                    if result_value == FindingStatus.NOT_REPRODUCED.value
                    else TaskStatus.COMPLETED.value
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
            elif budget.expired:
                task.status = TaskStatus.TIMED_OUT.value
                task.error = agent_error or "task time budget exhausted"
                task.result = {
                    "deterministic_evidence": evidence_summaries,
                    "coverage_gaps": coverage_gaps,
                    "agent_backend": agent_backend,
                }
            elif stages["device_attempted"]:
                task.status = TaskStatus.INCONCLUSIVE.value
                task.error = agent_error
                task.result = {
                    "deterministic_evidence": evidence_summaries,
                    "coverage_gaps": [
                        *coverage_gaps,
                        f"{agent_backend} semantic investigation was disabled or unavailable.",
                    ],
                    "agent_backend": agent_backend,
                }
            else:
                task.status = TaskStatus.BLOCKED_DEVICE.value
                task.error = agent_error or str(device_capability.get("detail"))
                task.result = {
                    "coverage_gaps": coverage_gaps,
                    "static_agent_attempted": agent_enabled,
                    "agent_backend": agent_backend,
                }
            task.completed_at = now()
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
            session.commit()

    @staticmethod
    def _validate_requested_tests(
        requests: list[AgentRequestedTest],
        entries: list[EntryPoint],
        *,
        auth_available: bool,
    ) -> tuple[list[AgentRequestedTest], list[str]]:
        entries_by_id = {entry.id: entry for entry in entries}
        accepted: list[AgentRequestedTest] = []
        gaps: list[str] = []
        seen: set[str] = set()
        for request in requests[:12]:
            entry = entries_by_id.get(request.entry_point_id)
            reason = None
            if entry is None:
                reason = "entry point is outside this task"
            elif request.state == "authenticated" and not auth_available:
                reason = "authenticated replay is unavailable"
            elif any(
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", key)
                for key in request.extras
            ):
                reason = "an extra key is unsafe"
            elif any(
                (isinstance(value, str) and len(value) > 1000)
                or (isinstance(value, int) and not -(2**63) <= value < 2**63)
                for value in request.extras.values()
            ):
                reason = "an extra value exceeds its safety bound"
            elif entry.kind == "provider" and request.extras:
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
        return accepted, gaps

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
        if entry.kind == "deep_link":
            try:
                baseline = urlsplit(entry.name)
                expected = (
                    baseline.scheme.lower(),
                    (baseline.hostname or "").lower(),
                    baseline.port,
                )
                actual = (
                    candidate.scheme.lower(),
                    (candidate.hostname or "").lower(),
                    candidate.port,
                )
            except ValueError:
                return "URI authority or port is invalid"
            if actual != expected:
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
    ) -> tuple[list[dict[str, Any]], list[str], bool]:
        entries_by_id = {entry.id: entry for entry in entries}
        indexed = [(f"agent-{index + 1}", request) for index, request in enumerate(requests)]
        executed: list[dict[str, Any]] = []
        gaps: list[str] = []
        instrumented_observed = False
        for state in ("guest", "authenticated"):
            state_requests = [item for item in indexed if item[1].state == state]
            if not state_requests or budget.expired:
                continue
            reset = self.device.reset_session(package_name, budget)
            self._record_commands(scan_id, task_id, reset, evidence_summaries)
            if any(result.exit_code != 0 for _kind, result, _metadata in reset):
                gaps.append(f"Could not reset the device for {state} agent-requested tests.")
                continue
            if state == "authenticated":
                auth = self.device.authenticate(package_name, budget)
                self._record_commands(scan_id, task_id, auth, evidence_summaries)
                if any(result.exit_code != 0 for _kind, result, _metadata in auth):
                    gaps.append("Authenticated replay failed before agent-requested tests.")
                    continue
            frida_session, frida_error = self.frida.start(package_name, budget)
            if frida_error is not None:
                self._record_commands(
                    scan_id,
                    task_id,
                    [("instrumented.frida", frida_error, self.frida.metadata(frida_error))],
                    evidence_summaries,
                )
            try:
                for test_case_id, request in state_requests:
                    if budget.expired:
                        gaps.append("Task budget expired before all agent-requested tests ran.")
                        break
                    before = len(evidence_summaries)
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
                    evidence_ids = [
                        item["id"]
                        for item in evidence_summaries[before:]
                        if item.get("metadata", {}).get("test_case_id") == test_case_id
                    ]
                    executed.append(
                        {
                            "test_case_id": test_case_id,
                            "request": request.model_dump(mode="json"),
                            "evidence_ids": evidence_ids,
                        }
                    )
            finally:
                if frida_session is not None:
                    result = self.frida.collect(frida_session)
                    metadata = self.frida.metadata(result)
                    instrumented_observed = instrumented_observed or bool(
                        metadata["capture_success"] and metadata["observation_count"] > 0
                    )
                    self._record_commands(
                        scan_id,
                        task_id,
                        [("instrumented.frida", result, metadata)],
                        evidence_summaries,
                    )
        return executed, gaps, instrumented_observed

    def _static_evidence_summaries(self, scan_id: str) -> list[dict[str, Any]]:
        with self.database.session_factory() as session:
            items = list(
                session.scalars(
                    select(Evidence).where(
                        Evidence.scan_id == scan_id,
                        Evidence.task_id.is_(None),
                    )
                )
            )
        return [self._evidence_summary(item) for item in items]

    def _materialize_agent_evidence(
        self,
        scan_id: str,
        task_id: str,
        attempt: int,
        summaries: list[dict[str, Any]],
    ) -> None:
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
            summary["artifact"] = str(target.relative_to(self.settings.data_dir / "workspaces" / scan_id))
        context = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "task_id": task_id,
            "attempt": attempt,
            "evidence": summaries,
        }
        (task_root / "context.json").write_text(
            json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8"
        )

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
        probe_request_ids = {
            item.get("metadata", {}).get("request_id")
            for item in cited
            if item["kind"] == "blackbox.probe_app"
            and item.get("exit_code") == 0
            and item.get("metadata", {}).get("caller_identity") == "probe_app"
        }
        log_request_ids = {
            item.get("metadata", {}).get("request_id")
            for item in cited
            if item["kind"] == "blackbox.logcat"
            and item.get("metadata", {}).get("request_observed")
        }
        correlated_blackbox = bool((probe_request_ids & log_request_ids) - {None})
        successful_blackbox = correlated_blackbox and any(
            item["kind"] == "blackbox.logcat"
            and item.get("metadata", {}).get("request_id") in probe_request_ids
            and item.get("metadata", {}).get("probe_success")
            for item in cited
        )
        result_value = str(payload.get("result", FindingStatus.INCONCLUSIVE.value))
        evidence_valid = True
        if result_value == FindingStatus.SUPPORTED_STATIC.value:
            evidence_valid = any(item["kind"].startswith("static.") for item in cited)
        elif result_value == FindingStatus.REPRODUCED_BLACKBOX.value:
            evidence_valid = successful_blackbox
        elif result_value == FindingStatus.OBSERVED_INSTRUMENTED.value:
            evidence_valid = any(
                item["kind"] == "instrumented.frida"
                and item.get("metadata", {}).get("capture_success")
                and item.get("metadata", {}).get("observation_count", 0) > 0
                for item in cited
            )
        elif result_value == FindingStatus.NOT_REPRODUCED.value:
            evidence_valid = correlated_blackbox
        if not evidence_valid:
            gaps.append(
                f"{result_value} was downgraded because its required platform evidence was absent."
            )
            result_value = FindingStatus.INCONCLUSIVE.value
        payload["coverage_gaps"] = gaps
        payload["result"] = result_value
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
            finding.status = FindingStatus.INCONCLUSIVE.value
            finding.metadata_json = {
                **finding.metadata_json,
                "superseded_by_turn": task.turn_id,
                "superseded_result": result_value,
                "superseded_by_backend": agent_backend,
            }

    @staticmethod
    def _persist_agent_finding(
        session,  # noqa: ANN001
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        result_value: str,
        agent_backend: str,
    ) -> None:
        if result_value in {FindingStatus.NOT_REPRODUCED.value, FindingStatus.INCONCLUSIVE.value}:
            return
        payload = task.result
        evidence_ids = payload.get("evidence_ids", [])
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
                severity=payload.get("severity_proposal", "medium"),
                confidence=payload.get("confidence", "medium"),
                status=result_value,
                entry_point_ids=task.target_entry_ids,
                evidence_ids=evidence_ids,
                metadata_json={
                    "task_id": task.id,
                    "agent_backend": agent_backend,
                    "coverage_gaps": payload.get("coverage_gaps", []),
                },
            )
            session.add(finding)
        else:
            finding.source = agent_backend
            finding.description = payload.get("summary", "Agent investigation result")
            finding.severity = payload.get("severity_proposal", "medium")
            finding.confidence = payload.get("confidence", "medium")
            finding.status = result_value
            finding.evidence_ids = evidence_ids
            finding.metadata_json = {
                "task_id": task.id,
                "agent_backend": agent_backend,
                "coverage_gaps": payload.get("coverage_gaps", []),
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
