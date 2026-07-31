from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from apkscanner.agent_audit import build_agent_audits
from apkscanner.agent_events import AgentCancelledError, AgentRuntimeEvent
from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.models import (
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    HypothesisArgument,
    InvestigationTask,
    Scan,
    ScanEvent,
    SecurityHypothesis,
)
from apkscanner.orchestrator import ScanOrchestrator
from apkscanner.planner import StaticEntryClosure
from apkscanner.reports import ReportBuilder
from apkscanner.schemas import AgentInvestigationResult
from apkscanner.tools import CommandResult
from sqlalchemy import select


def test_blocked_direct_entry_does_not_turn_a_finding_into_false_positive() -> None:
    entry_id = "00000000-0000-0000-0000-000000000010"
    finding = Finding(
        scan_id="scan",
        dedupe_key="finding",
        rule_id="TEST",
        source="builtin",
        title="Potential delegated access",
        description="An exported seed may delegate access to this component.",
        remediation="Validate the complete caller chain.",
        masvs="MASVS-PLATFORM",
        severity="high",
        confidence="medium",
        status="candidate",
        entry_point_ids=[entry_id],
        metadata_json={},
    )
    closure = StaticEntryClosure(
        entry_point_id=entry_id,
        kind="service",
        name="com.example.TrustedService",
        reason_code="strong_permission_guard",
        reason="Ordinary apps cannot invoke this service directly.",
        permission="com.example.TRUSTED",
        permission_protection="signature",
    )

    annotated = ScanOrchestrator._annotate_direct_reachability(
        finding,
        {entry_id: closure},
    )

    assert annotated is True
    assert finding.status == "candidate"
    assessment = finding.metadata_json["direct_reachability_assessment"]
    assert assessment["scope"] == "ordinary_app_direct_invocation_only"
    assert assessment["indirect_chain_paths_evaluated"] is False


def test_task_fails_closed_when_entry_belongs_to_another_scan(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    with database.session_factory() as session:
        selected_scan = Scan(
            status="final",
            filename="selected.apk",
            artifact_sha256="1" * 64,
            artifact_path=str(settings.data_dir / "selected.apk"),
        )
        foreign_scan = Scan(
            status="final",
            filename="foreign.apk",
            artifact_sha256="2" * 64,
            artifact_path=str(settings.data_dir / "foreign.apk"),
        )
        foreign_entry = EntryPoint(
            scan=foreign_scan,
            kind="provider",
            name="com.example.ForeignProvider",
            owner_component="com.example.ForeignProvider",
            exported=True,
        )
        session.add_all([selected_scan, foreign_scan, foreign_entry])
        session.flush()
        task = InvestigationTask(
            scan=selected_scan,
            task_type="component",
            status="queued",
            target_entry_ids=[foreign_entry.id],
        )
        session.add(task)
        session.commit()
        selected_scan_id = selected_scan.id
        task_id = task.id

    orchestrator = ScanOrchestrator(settings, database, store)
    orchestrator._run_task(selected_scan_id, task_id, 1)

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.status == "failed"
        assert "outside its scan" in str(task.error)
        events = list(
            session.scalars(
                select(ScanEvent).where(
                    ScanEvent.scan_id == selected_scan_id,
                    ScanEvent.event_type == "task.failed",
                )
            )
        )
        assert len(events) == 1
        assert events[0].data["loaded_entry_point_ids"] == []


def test_task_dispatch_runs_one_investigation_at_a_time(settings) -> None:  # noqa: ANN001
    configured = settings
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="preliminary_ready",
            filename="parallel.apk",
            artifact_sha256="9" * 64,
            artifact_path=str(configured.data_dir / "parallel.apk"),
        )
        session.add(scan)
        session.flush()
        session.add_all(
            [
                InvestigationTask(
                    scan_id=scan.id,
                    task_type="component",
                    status="queued",
                    priority=100 - index,
                )
                for index in range(6)
            ]
        )
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    state_lock = threading.Lock()
    active = 0
    max_active = 0

    def fake_run_task(
        _scan_id: str,
        task_id: str,
        _timeout_seconds: int | None = None,
    ) -> None:
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.08)
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            task.status = "completed"
            task.completed_at = datetime.now(UTC)
            session.commit()
        with state_lock:
            active -= 1

    orchestrator._run_task = fake_run_task  # type: ignore[method-assign]
    orchestrator._run_tasks(scan_id)

    assert max_active == 1
    with database.session_factory() as session:
        persisted_scan = session.get(Scan, scan_id)
        statuses = list(
            session.scalars(
                select(InvestigationTask.status).where(
                    InvestigationTask.scan_id == scan_id
                )
            )
        )
    assert persisted_scan is not None
    assert persisted_scan.stats["execution_policy"] == {
        "investigation_concurrency": 1,
        "adb_concurrency": 1,
        "device_ownership": "complete_task",
        "agent_workspace_scope": "task_attempt",
    }
    assert statuses == ["completed"] * 6


def test_two_configured_devices_run_two_investigations_concurrently(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="device-a",
        adb_serials=("device-a", "device-b"),
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="preliminary_ready",
            filename="two-devices.apk",
            artifact_sha256="8" * 64,
            artifact_path=str(configured.data_dir / "two-devices.apk"),
        )
        session.add(scan)
        session.flush()
        session.add_all(
            [
                InvestigationTask(
                    scan_id=scan.id,
                    task_type="component",
                    status="queued",
                    priority=100 - index,
                )
                for index in range(4)
            ]
        )
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(
        configured,
        database,
        ArtifactStore(configured),
    )
    state_lock = threading.Lock()
    active = 0
    max_active = 0

    def fake_run_task(
        _scan_id: str,
        task_id: str,
        _timeout_seconds: int | None = None,
    ) -> None:
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.08)
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            task.status = "completed"
            task.completed_at = datetime.now(UTC)
            session.commit()
        with state_lock:
            active -= 1

    orchestrator._run_task = fake_run_task  # type: ignore[method-assign]
    orchestrator._run_tasks(scan_id)

    assert max_active == 2
    with database.session_factory() as session:
        persisted_scan = session.get(Scan, scan_id)
        statuses = list(
            session.scalars(
                select(InvestigationTask.status).where(
                    InvestigationTask.scan_id == scan_id
                )
            )
        )
    assert persisted_scan is not None
    assert persisted_scan.stats["execution_policy"] == {
        "investigation_concurrency": 2,
        "adb_concurrency": 2,
        "device_ownership": "complete_task",
        "agent_workspace_scope": "task_attempt",
    }
    assert statuses == ["completed"] * 4


def test_single_investigation_limit_is_shared_across_scans(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scans = [
            Scan(
                status="preliminary_ready",
                filename=f"scan-{index}.apk",
                artifact_sha256=str(index + 1) * 64,
                artifact_path=str(settings.data_dir / f"scan-{index}.apk"),
            )
            for index in range(2)
        ]
        session.add_all(scans)
        session.flush()
        session.add_all(
            [
                InvestigationTask(
                    scan_id=scan.id,
                    task_type="component",
                    status="queued",
                    priority=90,
                )
                for scan in scans
            ]
        )
        session.commit()
        scan_ids = [scan.id for scan in scans]

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    state_lock = threading.Lock()
    start = threading.Barrier(2)
    active = 0
    max_active = 0

    def fake_run_task(
        _scan_id: str,
        task_id: str,
        _timeout_seconds: int | None = None,
    ) -> None:
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.08)
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            task.status = "completed"
            task.completed_at = datetime.now(UTC)
            session.commit()
        with state_lock:
            active -= 1

    orchestrator._run_task = fake_run_task  # type: ignore[method-assign]

    def run(scan_id: str) -> None:
        start.wait(timeout=5)
        orchestrator._run_tasks(scan_id)

    workers = [threading.Thread(target=run, args=(scan_id,)) for scan_id in scan_ids]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert max_active == 1


def test_parallel_workers_share_only_one_device_session(settings) -> None:  # noqa: ANN001
    configured = settings
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="one-device.apk",
            artifact_sha256="8" * 64,
            artifact_path=str(configured.data_dir / "one-device.apk"),
        )
        session.add(scan)
        session.flush()
        tasks = [
            InvestigationTask(
                scan_id=scan.id,
                task_type="component",
                status="running",
                priority=90 - index,
            )
            for index in range(3)
        ]
        session.add_all(tasks)
        session.commit()
        scan_id = scan.id
        task_ids = [task.id for task in tasks]

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    state_lock = threading.Lock()
    entered = 0
    max_entered = 0
    start = threading.Barrier(3)

    def use_device(task_id: str, priority: int) -> None:
        nonlocal entered, max_entered
        start.wait(timeout=5)
        with orchestrator._task_device_session(
            scan_id,
            task_id,
            priority=priority,
            cancel_event=threading.Event(),
        ):
            with state_lock:
                entered += 1
                max_entered = max(max_entered, entered)
            time.sleep(0.05)
            with state_lock:
                entered -= 1

    workers = [
        threading.Thread(target=use_device, args=(task_id, 90 - index))
        for index, task_id in enumerate(task_ids)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()

    assert max_entered == 1
    assert orchestrator.device.scheduler.snapshot() == {
        "active_task_id": None,
        "waiting": [],
    }
    with database.session_factory() as session:
        persisted = [
            session.get(InvestigationTask, task_id) for task_id in task_ids
        ]
        assert all(task is not None and task.status == "running" for task in persisted)
        assert all(
            (task.result.get("device_queue") or {}).get("released_at")
            for task in persisted
            if task is not None
        )


def test_device_task_keeps_one_lease_through_agent_investigation(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="exclusive-device:5555",
        codex_enabled=True,
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="exclusive.apk",
            package_name="com.example.exclusive",
            artifact_sha256="7" * 64,
            artifact_path=str(configured.data_dir / "exclusive.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.exclusive.MainActivity",
            owner_component="com.example.exclusive.MainActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="queued",
            target_entry_ids=[entry.id],
        )
        session.add(task)
        session.commit()
        scan_id = scan.id
        task_id = task.id

    orchestrator = ScanOrchestrator(
        configured,
        database,
        ArtifactStore(configured),
    )
    timeline: list[str] = []
    monkeypatch.setattr(
        orchestrator.device.runner,
        "available",
        lambda executable: executable == "adb",
    )
    monkeypatch.setattr(
        orchestrator.device,
        "capability",
        lambda *, non_blocking=False: {"available": True},
    )
    monkeypatch.setattr(
        orchestrator.device,
        "prepare",
        lambda *_args, **_kwargs: [
            (
                "device.install",
                CommandResult(["adb", "install"], 0, "", ""),
                {},
            )
        ],
    )
    monkeypatch.setattr(
        orchestrator.device,
        "probe",
        lambda *_args, **_kwargs: SimpleNamespace(commands=[]),
    )

    def cleanup(_package_name: str):  # noqa: ANN202
        assert orchestrator.device.scheduler.snapshot()["active_task_id"] == task_id
        timeline.append("cleanup")
        return []

    monkeypatch.setattr(orchestrator.device, "cleanup", cleanup)
    monkeypatch.setattr(
        orchestrator,
        "_validated_agent_payload",
        lambda payload, _evidence: (payload, "refuted_static"),
    )

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**_kwargs):  # noqa: ANN003, ANN205
            assert (
                orchestrator.device.scheduler.snapshot()["active_task_id"]
                == task_id
            )
            device_context = _kwargs["platform_context"]["device"]
            assert device_context["available"] is True
            assert device_context["busy"] is False
            assert device_context["lease_owned_by_current_task"] is True
            assert device_context["active_task_id"] == task_id
            timeline.append("agent")
            return SimpleNamespace(
                thread_id="thread-exclusive",
                turn_id="turn-exclusive",
                usage={"input_tokens": 1, "output_tokens": 1},
                result=AgentInvestigationResult(
                    summary="静态证据未显示普通应用可利用的安全风险。",
                    result="refuted_static",
                    hypotheses_tested=[],
                    test_cases=[],
                    evidence_ids=[],
                    severity_proposal="info",
                    confidence="high",
                    coverage_gaps=[],
                    followups=[],
                    requested_tests=[],
                ),
            )

    orchestrator.investigators["codex"] = FakeInvestigator()
    orchestrator._run_task(scan_id, task_id, 30)

    assert timeline == ["agent", "agent", "cleanup"]
    assert orchestrator.device.scheduler.snapshot() == {
        "active_task_id": None,
        "waiting": [],
    }
    with database.session_factory() as session:
        completed_task = session.get(InvestigationTask, task_id)
        assert completed_task is not None
        terminal_device = completed_task.result["platform_context"]["device"]
        assert terminal_device["lease_completed_by_current_task"] is True
        assert terminal_device["busy"] is False
        events = list(
            session.scalars(
                select(ScanEvent).where(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.event_type.in_(
                        {
                            "exploration.device.acquired",
                            "exploration.device.released",
                        }
                    ),
                )
            )
        )
    assert [event.event_type for event in events] == [
        "exploration.device.acquired",
        "exploration.device.released",
    ]


@pytest.mark.parametrize("rejection_mode", ["platform_policy", "model_schema"])
def test_rejected_agent_test_is_handed_to_next_exploration_round(
    settings,
    monkeypatch,
    rejection_mode,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="iterative-device:5555",
        codex_enabled=True,
        agent_max_rounds=3,
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="iterative.apk",
            package_name="com.example.iterative",
            artifact_sha256="6" * 64,
            artifact_path=str(configured.data_dir / "iterative.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.iterative.MainActivity",
            owner_component="com.example.iterative.MainActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="queued",
            target_entry_ids=[entry.id],
        )
        session.add(task)
        session.commit()
        scan_id = scan.id
        task_id = task.id
        entry_id = entry.id

    orchestrator = ScanOrchestrator(
        configured,
        database,
        ArtifactStore(configured),
    )
    monkeypatch.setattr(
        orchestrator.device.runner,
        "available",
        lambda executable: executable == "adb",
    )
    monkeypatch.setattr(
        orchestrator.device,
        "capability",
        lambda *, non_blocking=False: {"available": True},
    )
    monkeypatch.setattr(
        orchestrator.device,
        "prepare",
        lambda *_args, **_kwargs: [
            (
                "device.install",
                CommandResult(["adb", "install"], 0, "", ""),
                {},
            )
        ],
    )
    monkeypatch.setattr(
        orchestrator.device,
        "probe",
        lambda *_args, **_kwargs: SimpleNamespace(commands=[]),
    )
    monkeypatch.setattr(orchestrator.device, "cleanup", lambda _package: [])
    monkeypatch.setattr(
        orchestrator,
        "_validated_agent_payload",
        lambda payload, _evidence: (payload, "refuted_static"),
    )
    phases: list[str] = []

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            context = kwargs["platform_context"]
            phase = context["phase"]
            phases.append(phase)
            hypothesis_id = context["security_hypotheses"][0]["id"]
            requested_tests = []
            if phase == "test_planning":
                request = {
                    "hypothesis_id": hypothesis_id,
                    "entry_point_id": (
                        "00000000-0000-0000-0000-000000000099"
                        if rejection_mode == "platform_policy"
                        else entry_id
                    ),
                    "state": "guest",
                    "uri": None,
                    "extras": {},
                    "rationale": "先尝试一个需要根据平台反馈修正的测试。",
                }
                if rejection_mode == "model_schema":
                    request.update(
                        {
                            "operation": "auto",
                            "method": "bindOrTransact",
                            "argument": "1",
                        }
                    )
                requested_tests = [request]
            elif phase == "exploration_round":
                history = context["agent_round_history"]
                planning = next(
                    item for item in history if item["phase"] == "test_planning"
                )
                validation = planning["test_validation"]
                assert len(validation["submitted"]) == 1
                assert validation["accepted"] == []
                assert validation["executed"] == []
                if rejection_mode == "platform_policy":
                    assert validation["model_rejected"] == []
                    assert any(
                        "outside this task" in gap for gap in validation["gaps"]
                    )
                else:
                    assert len(validation["model_rejected"]) == 1
                    assert validation["model_rejected"][0]["request"]["method"] == (
                        "bindOrTransact"
                    )
                    assert any(
                        "schema validation failed" in gap
                        and "only valid for provider call" in gap
                        for gap in validation["gaps"]
                    )
            elif phase == "rescue_review":
                assert context["agent_round_history"] == []
                assert context["candidate_under_review"] is None
                assert context["debate"] is None
                assert context["rescue"] is None
                assert context["blind_rescue"] == {
                    "mode": "independent_negative_closure_review",
                    "prior_model_conclusion_withheld": True,
                }
            return SimpleNamespace(
                thread_id=f"thread-{phase}",
                turn_id=f"turn-{phase}",
                usage={"input_tokens": 1, "output_tokens": 1},
                result=AgentInvestigationResult(
                    summary="本轮已根据平台反馈调整验证策略。",
                    result="refuted_static",
                    hypotheses_tested=[hypothesis_id],
                    test_cases=[],
                    evidence_ids=[],
                    severity_proposal="info",
                    confidence="medium",
                    coverage_gaps=[],
                    followups=[],
                    requested_tests=requested_tests,
                ),
            )

    orchestrator.investigators["codex"] = FakeInvestigator()
    orchestrator._run_task(scan_id, task_id, 120)

    assert phases == ["test_planning", "exploration_round", "rescue_review"]
    with database.session_factory() as session:
        completed_task = session.get(InvestigationTask, task_id)
        assert completed_task is not None
        history = completed_task.result["platform_context"]["agent_round_history"]
        assert [item["phase"] for item in history] == [
            "test_planning",
            "exploration_round",
            "rescue_review",
        ]
        assert history[0]["test_validation"]["accepted"] == []
        if rejection_mode == "model_schema":
            assert len(
                history[0]["model_validation"]["rejected_requested_tests"]
            ) == 1


def test_blind_rescue_reopens_a_model_negative_before_closure(
    settings,
) -> None:  # noqa: ANN001
    configured = replace(settings, codex_enabled=True, adb_serial=None)
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)
    static_sha, static_path = store.put_json(
        "evidence",
        {
            "kind": "static.manifest",
            "component": "com.example.rescue.EntryActivity",
            "exported": True,
        },
    )
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="blind-rescue.apk",
            package_name="com.example.rescue",
            artifact_sha256="9" * 64,
            artifact_path=str(configured.data_dir / "blind-rescue.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.rescue.EntryActivity",
            owner_component="com.example.rescue.EntryActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="queued",
            target_entry_ids=[entry.id],
            hypotheses=[
                "The exported entry may delegate attacker data to an internal sensitive sink."
            ],
        )
        static_evidence = Evidence(
            scan_id=scan.id,
            kind="static.manifest",
            sha256=static_sha,
            path=str(static_path),
            summary="Exported rescue fixture entry",
        )
        session.add_all([task, static_evidence])
        session.commit()
        scan_id = scan.id
        task_id = task.id

    phases: list[str] = []

    class RescueInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            context = kwargs["platform_context"]
            phase = context["phase"]
            phases.append(phase)
            hypothesis_id = context["security_hypotheses"][0]["id"]
            evidence_id = kwargs["evidence"][0]["id"]
            result = "refuted_static" if phase == "static_only" else "supported_static"
            assessments = []
            tested = []
            if phase != "adversarial_review":
                tested = [hypothesis_id]
                assessments = [
                    {
                        "hypothesis_id": hypothesis_id,
                        "verdict": result,
                        "source": "EntryActivity attacker-controlled extra",
                        "control": "No caller validation",
                        "sink": "InternalDispatcher sensitive action",
                        "reachable_path": (
                            "EntryActivity -> RouteHelper -> InternalDispatcher"
                        ),
                        "boundary": "android_component_export_boundary",
                        "counterevidence": (
                            ["Initial analyst did not follow RouteHelper"]
                            if phase == "static_only"
                            else []
                        ),
                        "proof_gaps": [],
                        "evidence_ids": [evidence_id],
                        "confidence": "high",
                    }
                ]
            if phase == "rescue_review":
                assert context["agent_round_history"] == []
                assert context["candidate_under_review"] is None
                assert context["blind_rescue"][
                    "prior_model_conclusion_withheld"
                ] is True
            if phase == "rescue_exploration":
                assert context["rescue"]["strategy"]["result"] == "supported_static"
                assert context["rescue"][
                    "prior_model_conclusion_withheld_during_review"
                ] is True
            return SimpleNamespace(
                thread_id=f"thread-{phase}",
                turn_id=f"turn-{phase}",
                usage={"input_tokens": 1, "output_tokens": 1},
                result=AgentInvestigationResult(
                    summary=(
                        "独立救援发现并确认了从导出入口到内部敏感操作的委托链。"
                        if result == "supported_static"
                        else "第一轮分析未发现可利用链。"
                    ),
                    result=result,
                    hypotheses_tested=tested,
                    hypothesis_assessments=assessments,
                    review_objections=[],
                    objection_resolutions=[],
                    test_cases=[],
                    evidence_ids=[evidence_id],
                    severity_proposal=(
                        "high" if result == "supported_static" else "info"
                    ),
                    confidence="high",
                    coverage_gaps=[],
                    followups=(
                        ["沿 RouteHelper 验证 InternalDispatcher 的具体敏感影响。"]
                        if phase == "rescue_review"
                        else []
                    ),
                    requested_tests=[],
                ),
            )

    orchestrator = ScanOrchestrator(configured, database, store)
    orchestrator.investigators["codex"] = RescueInvestigator()
    orchestrator._run_task(scan_id, task_id, 120)

    assert phases == [
        "static_only",
        "rescue_review",
        "rescue_exploration",
    ]
    with database.session_factory() as session:
        completed = session.get(InvestigationTask, task_id)
        assert completed is not None
        assert completed.status == "completed"
        assert completed.result["result"] == "supported_static"
        rescue = completed.result["negative_closure_rescue"]
        assert rescue["passed"] is True
        assert rescue["outcome"] == "negative_closure_reopened"
        assert rescue["candidate_result"] == "refuted_static"
        arguments = list(
            session.scalars(
                select(HypothesisArgument).where(
                    HypothesisArgument.task_id == task_id
                )
            )
        )
        assert any(argument.role == "rescuer" for argument in arguments)
        assert not any(argument.role == "critic" for argument in arguments)
        assert completed.result["debate_policy"]["phase_counts"] == {
            "rescue_exploration": 1,
            "rescue_review": 1,
            "static_only": 1,
        }


@pytest.mark.parametrize("critic_objects", [False, True])
def test_positive_debate_is_single_pass_and_arbitrates_only_real_objections(
    settings,
    monkeypatch,
    critic_objects,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="single-pass-device:5555",
        codex_enabled=True,
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)
    cited_sha, cited_path = store.put_json(
        "evidence",
        {"kind": "static.manifest", "exported": True},
    )
    unused_sha, unused_path = store.put_json(
        "evidence",
        {"kind": "static.code", "unrelated": True},
    )
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="single-pass.apk",
            package_name="com.example.singlepass",
            artifact_sha256="7" * 64,
            artifact_path=str(configured.data_dir / "single-pass.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.singlepass.EntryActivity",
            owner_component="com.example.singlepass.EntryActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="queued",
            target_entry_ids=[entry.id],
            hypotheses=["The exported entry reaches a privileged internal action."],
        )
        cited = Evidence(
            scan_id=scan.id,
            kind="static.manifest",
            sha256=cited_sha,
            path=str(cited_path),
            summary="Exported entry without a permission",
        )
        unused = Evidence(
            scan_id=scan.id,
            kind="static.code",
            sha256=unused_sha,
            path=str(unused_path),
            summary="Unrelated component evidence",
        )
        session.add_all([task, cited, unused])
        session.commit()
        scan_id, task_id, cited_id = scan.id, task.id, cited.id

    orchestrator = ScanOrchestrator(configured, database, store)
    monkeypatch.setattr(
        orchestrator.device.runner,
        "available",
        lambda executable: executable == "adb",
    )
    monkeypatch.setattr(
        orchestrator.device,
        "capability",
        lambda *, non_blocking=False: {"available": True},
    )
    monkeypatch.setattr(
        orchestrator.device,
        "prepare",
        lambda *_args, **_kwargs: [
            (
                "device.install",
                CommandResult(["adb", "install"], 0, "", ""),
                {},
            )
        ],
    )
    monkeypatch.setattr(
        orchestrator.device,
        "probe",
        lambda *_args, **_kwargs: SimpleNamespace(commands=[]),
    )
    monkeypatch.setattr(orchestrator.device, "cleanup", lambda _package: [])
    phases: list[str] = []

    class SinglePassInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            context = kwargs["platform_context"]
            phase = context["phase"]
            phases.append(phase)
            hypothesis_id = context["security_hypotheses"][0]["id"]
            if phase == "adversarial_review":
                assert [item["id"] for item in kwargs["evidence"]] == [cited_id]
                assert context["agent_round_history"] == []
                assert context["executed_agent_tests"] == []
                assert context["target_code_context"] == {
                    "status": "candidate_evidence_only",
                    "components": [],
                }
                assert context["critic_scope"] == {
                    "mode": "candidate_and_cited_evidence_only",
                    "evidence_ids": [cited_id],
                    "maximum_objections": 2,
                }
                objections = (
                    [
                        {
                            "objection_id": "OBJ-1",
                            "hypothesis_id": hypothesis_id,
                            "claim": "The candidate did not establish the sensitive sink.",
                            "basis": "The cited manifest proves export only.",
                            "evidence_ids": [cited_id],
                        }
                    ]
                    if critic_objects
                    else []
                )
                return SimpleNamespace(
                    thread_id="thread-critic",
                    turn_id="turn-critic",
                    usage={"input_tokens": 1, "output_tokens": 1},
                    result=AgentInvestigationResult(
                        summary="Critic 已完成一次证据审查。",
                        result=(
                            "refuted_static"
                            if critic_objects
                            else "supported_static"
                        ),
                        hypotheses_tested=[],
                        hypothesis_assessments=[],
                        review_objections=objections,
                        objection_resolutions=[],
                        test_cases=[],
                        evidence_ids=[cited_id],
                        severity_proposal=(
                            "info" if critic_objects else "high"
                        ),
                        confidence="high",
                        coverage_gaps=[],
                        followups=[],
                        requested_tests=[],
                    ),
                )
            if phase == "final_evaluation":
                assert critic_objects
                assert context["debate"]["critic"]["review_objections"][0][
                    "objection_id"
                ] == "OBJ-1"
                return SimpleNamespace(
                    thread_id="thread-final",
                    turn_id="turn-final",
                    usage={"input_tokens": 1, "output_tokens": 1},
                    result=AgentInvestigationResult(
                        summary="最终裁决采纳了 Critic 的实质异议。",
                        result="refuted_static",
                        hypotheses_tested=[hypothesis_id],
                        hypothesis_assessments=[
                            {
                                "hypothesis_id": hypothesis_id,
                                "verdict": "refuted_static",
                                "source": "Exported manifest entry",
                                "control": "Explicit Intent",
                                "sink": "",
                                "reachable_path": "Caller -> EntryActivity",
                                "boundary": "android_component_export_boundary",
                                "counterevidence": [
                                    "No sensitive sink is present in cited evidence"
                                ],
                                "proof_gaps": [],
                                "evidence_ids": [cited_id],
                                "confidence": "high",
                            }
                        ],
                        review_objections=[],
                        objection_resolutions=[
                            {
                                "objection_id": "OBJ-1",
                                "disposition": "sustained",
                                "rationale": "现有证据只证明入口可达。",
                                "evidence_ids": [cited_id],
                            }
                        ],
                        test_cases=[],
                        evidence_ids=[cited_id],
                        severity_proposal="info",
                        confidence="high",
                        coverage_gaps=[],
                        followups=[],
                        requested_tests=[],
                    ),
                )
            return SimpleNamespace(
                thread_id="thread-hunter",
                turn_id="turn-hunter",
                usage={"input_tokens": 1, "output_tokens": 1},
                result=AgentInvestigationResult(
                    summary="Hunter 发现了一个需要独立审查的高风险候选。",
                    result="supported_static",
                    hypotheses_tested=[hypothesis_id],
                    hypothesis_assessments=[
                        {
                            "hypothesis_id": hypothesis_id,
                            "verdict": "supported_static",
                            "source": "EntryActivity",
                            "control": "Attacker Intent",
                            "sink": "PrivilegedAction",
                            "reachable_path": "EntryActivity -> PrivilegedAction",
                            "boundary": "android_component_export_boundary",
                            "counterevidence": [],
                            "proof_gaps": [],
                            "evidence_ids": [cited_id],
                            "confidence": "high",
                        }
                    ],
                    review_objections=[],
                    objection_resolutions=[],
                    test_cases=[],
                    evidence_ids=[cited_id],
                    severity_proposal="high",
                    confidence="high",
                    coverage_gaps=[],
                    followups=[],
                    requested_tests=[],
                ),
            )

    orchestrator.investigators["codex"] = SinglePassInvestigator()
    orchestrator._run_task(scan_id, task_id, 120)

    assert phases == (
        ["test_planning", "adversarial_review", "final_evaluation"]
        if critic_objects
        else ["test_planning", "adversarial_review"]
    )
    with database.session_factory() as session:
        completed = session.get(InvestigationTask, task_id)
        assert completed is not None
        assert completed.status == "completed"
        assert completed.result["result"] == (
            "refuted_static" if critic_objects else "supported_static"
        )
        policy = completed.result["debate_policy"]
        assert policy["phase_counts"]["adversarial_review"] == 1
        assert policy["phase_counts"].get("rescue_review", 0) == 0
        assert policy["phase_counts"].get("final_evaluation", 0) == int(
            critic_objects
        )
        assert policy["outcome"] == (
            "arbiter_completed"
            if critic_objects
            else "candidate_kept_without_arbiter"
        )


def test_agent_attempt_workspaces_are_isolated_per_task(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    orchestrator = ScanOrchestrator(settings, database, store)
    scan_id = "00000000-0000-0000-0000-000000000070"
    first_task_id = "00000000-0000-0000-0000-000000000071"
    second_task_id = "00000000-0000-0000-0000-000000000072"
    digest, evidence_path = store.put_json(
        "evidence",
        {"kind": "static.manifest", "exported": True},
    )
    with database.session_factory() as session:
        scan = Scan(
            id=scan_id,
            status="preliminary_ready",
            filename="isolated.apk",
            artifact_sha256="7" * 64,
            artifact_path=str(settings.data_dir / "isolated.apk"),
        )
        session.add(scan)
        session.flush()
        session.add_all(
            [
                InvestigationTask(
                    id=first_task_id,
                    scan_id=scan_id,
                    task_type="component",
                    status="running",
                ),
                InvestigationTask(
                    id=second_task_id,
                    scan_id=scan_id,
                    task_type="component",
                    status="running",
                ),
            ]
        )
        session.flush()
        evidence = Evidence(
            scan_id=scan_id,
            kind="static.manifest",
            sha256=digest,
            path=str(evidence_path),
            summary="Manifest exported component",
        )
        session.add(evidence)
        session.commit()
        evidence_summary = orchestrator._evidence_summary(evidence)
    source = (
        settings.data_dir
        / "workspaces"
        / scan_id
        / "jadx"
        / "sources"
        / "example"
        / "ExportedProvider.java"
    )
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("class ExportedProvider {}", encoding="utf-8")
    manifest = source.parents[3] / "AndroidManifest.xml"
    manifest.write_text(
        "<manifest package=\"example\"><application /></manifest>",
        encoding="utf-8",
    )

    def context() -> dict[str, object]:
        return {
            "phase": "test_planning",
            "target_code_context": {
                "components": [
                    {
                        "component": "example.ExportedProvider",
                        "anchors": [
                            {
                                "path": "jadx/sources/example/ExportedProvider.java",
                            }
                        ],
                    }
                ]
            },
        }

    first = orchestrator._materialize_agent_evidence(
        scan_id,
        first_task_id,
        1,
        [dict(evidence_summary)],
        platform_context=context(),
    )
    second = orchestrator._materialize_agent_evidence(
        scan_id,
        second_task_id,
        1,
        [dict(evidence_summary)],
        platform_context=context(),
    )
    assert first != second
    (first / "agent-note.txt").write_text("first", encoding="utf-8")
    assert not (second / "agent-note.txt").exists()
    first_context = json.loads((first / "context.json").read_text(encoding="utf-8"))
    second_context = json.loads((second / "context.json").read_text(encoding="utf-8"))
    assert first_context["task_id"] != second_context["task_id"]
    assert first_context["workspace_policy"]["shared_scan_workspace_exposed"] is True
    assert str(source.parents[2]) in first_context["workspace_policy"][
        "decompiled_roots"
    ]["host"]
    assert first_context["evidence"][0]["artifact"] == (
        f"evidence/{evidence.id}.json"
    )
    assert (first / first_context["evidence"][0]["artifact"]).is_file()
    materialized = "target_source/jadx/sources/example/ExportedProvider.java"
    assert (first / materialized).read_text(encoding="utf-8") == (
        "class ExportedProvider {}"
    )
    assert (
        first_context["platform_context"]["target_code_context"]["components"][0][
            "anchors"
        ][0]["materialized_path"]
        == materialized
    )

    static_context = context()
    static_context["entry_scope"] = {
        "catalog": [{"kind": "static_surface"}],
    }
    bounded = orchestrator._materialize_agent_evidence(
        scan_id,
        "00000000-0000-0000-0000-000000000073",
        1,
        [dict(evidence_summary)],
        platform_context=static_context,
    )
    bounded_context = json.loads(
        (bounded / "context.json").read_text(encoding="utf-8")
    )
    assert bounded.is_relative_to(settings.data_dir / "agent_context" / scan_id)
    assert not bounded.is_relative_to(settings.data_dir / "workspaces" / scan_id)
    assert bounded_context["workspace_policy"]["shared_scan_workspace_exposed"] is False
    assert bounded_context["workspace_policy"]["decompiled_roots"] == {
        "host": [],
        "container": [],
    }
    assert (bounded / materialized).is_file()
    assert (
        bounded_context["platform_context"]["bounded_manifest_path"]
        == "target_source/AndroidManifest.xml"
    )
    assert bounded_context["platform_context"]["bounded_manifest"]["package_name"] == (
        "example"
    )
    assert (bounded / "target_source/AndroidManifest.xml").is_file()


def test_end_to_end_static_scan_reaches_final_with_explicit_dynamic_gaps(settings, fixture_apk) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    target_dir = settings.data_dir / "artifacts" / "fixture"
    target_dir.mkdir(parents=True)
    target = target_dir / "fixture.apk"
    shutil.copyfile(fixture_apk, target)
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            artifact_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
            artifact_path=str(target),
            stats={"investigator": "none"},
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    assert orchestrator.resolve_investigator() == "codex"
    assert orchestrator.resolve_investigator("opencode") == "opencode"
    assert orchestrator.resolve_investigator("none") == "none"
    orchestrator._run_sync(scan_id)

    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "final"
        assert scan.package_name == "com.example.vulnerable"
        assert scan.stats["investigator"] == "none"
        assert scan.stats["threat_model"]["digest"]
        seal = session.get(Evidence, scan.stats["seal"]["evidence_id"])
        assert seal is not None
        assert seal.kind == "scan.seal"
        assert seal.sha256 == scan.stats["seal"]["sha256"]
        entries = list(
            session.scalars(
                select(EntryPoint).where(EntryPoint.scan_id == scan_id)
            )
        )
        assert len(entries) == 9
        assert sum(entry.kind == "static_surface" for entry in entries) == 1
        findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == scan_id))
        )
        assert len(findings) >= 5
        assert all(
            finding.metadata_json["identity"]["finding_id"] for finding in findings
        )
        tasks = list(session.scalars(select(InvestigationTask).where(InvestigationTask.scan_id == scan_id)))
        assert tasks
        assert sum(task.task_type == "static_review" for task in tasks) == 1
        assert {task.status for task in tasks} == {"blocked_device"}
        assert len(list(session.scalars(select(CoverageItem).where(CoverageItem.scan_id == scan_id)))) >= 16
        report = ReportBuilder().build(session, scan)
        sarif = ReportBuilder().sarif(report)
        assert sarif["version"] == "2.1.0"
        assert report["scan"]["limitations"]
        html_report = ReportBuilder().html(report)
        embedded = html_report.split(
            '<script type="application/json" id="report-data">', 1
        )[1].split("</script>", 1)[0]
        assert json.loads(embedded)["scan"]["id"] == scan_id
        first_seal_id = seal.id

    orchestrator._finish(scan_id)
    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.stats["seal"]["evidence_id"] != first_seal_id
        seals = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.scan_id == scan_id,
                    Evidence.kind == "scan.seal",
                )
            )
        )
        assert len(seals) == 2


def test_isolated_fresh_run_does_not_load_version_or_pattern_history(
    settings,
    fixture_apk,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    target_dir = settings.data_dir / "artifacts" / "fresh"
    target_dir.mkdir(parents=True)
    target = target_dir / "fixture.apk"
    shutil.copyfile(fixture_apk, target)
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            artifact_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
            artifact_path=str(target),
            stats={
                "investigator": "none",
                "fresh_run": {
                    "source_scan_id": "00000000-0000-0000-0000-000000000099",
                    "mode": "isolated",
                    "reuse_apk_only": True,
                },
            },
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))

    def reject_history(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("isolated fresh scans must not load historical results")

    monkeypatch.setattr(
        orchestrator.security_evolution,
        "build_version_diff",
        reject_history,
    )
    monkeypatch.setattr(
        orchestrator.security_evolution,
        "apply_diff_and_patterns",
        reject_history,
    )

    orchestrator._run_sync(scan_id)

    with database.session_factory() as session:
        persisted = session.get(Scan, scan_id)
        assert persisted is not None
        assert persisted.status == "final"
        assert persisted.stats["version_diff_id"] is None
        assert persisted.stats["version_replay_candidate_count"] == 0
        assert persisted.stats["pattern_match_count"] == 0
        event_types = set(
            session.scalars(
                select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id)
            )
        )
        assert "planning.fresh_run.isolated" in event_types


def test_continuation_context_includes_prior_task_evidence(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            filename="continuation.apk",
            artifact_sha256="7" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        task = InvestigationTask(scan=scan, task_type="component")
        session.add_all([scan, task])
        session.flush()
        global_evidence = orchestrator.evidence.json(
            session,
            scan_id=scan.id,
            task_id=None,
            kind="static.manifest",
            value={"exported": True},
            summary="Manifest evidence",
        )
        prior_task_evidence = orchestrator.evidence.json(
            session,
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.logcat",
            value={"observed": True},
            summary="Prior dynamic evidence",
        )
        session.commit()
        scan_id = scan.id
        task_id = task.id
        global_evidence_id = global_evidence.id
        prior_task_evidence_id = prior_task_evidence.id

    initial = orchestrator._evidence_summaries_for_run(
        scan_id,
        task_id=task_id,
        include_task_evidence=False,
    )
    continued = orchestrator._evidence_summaries_for_run(
        scan_id,
        task_id=task_id,
        include_task_evidence=True,
    )
    assert {item["id"] for item in initial} == {global_evidence_id}
    assert {item["id"] for item in continued} == {
        global_evidence_id,
        prior_task_evidence_id,
    }


def test_manual_continuation_gets_a_fresh_budget_after_scan_deadline(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            filename="late-continuation.apk",
            artifact_sha256="6" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
            created_at=datetime.now(UTC)
            - timedelta(seconds=settings.scan_deadline_seconds + 60),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="queued",
            result={"manual_continuation": {"continuation_number": 1}},
        )
        session.add_all([scan, task])
        session.commit()
        scan_id = scan.id
        task_id = task.id

    dispatched: list[tuple[str, str, int | None]] = []

    def run_task(actual_scan_id: str, actual_task_id: str, timeout: int | None) -> None:
        dispatched.append((actual_scan_id, actual_task_id, timeout))
        with database.session_factory() as session:
            persisted = session.get(InvestigationTask, actual_task_id)
            assert persisted is not None
            persisted.status = "completed"
            session.commit()

    monkeypatch.setattr(orchestrator, "_run_task", run_task)
    orchestrator._run_tasks(scan_id)
    assert dispatched == [(scan_id, task_id, settings.task_timeout_seconds)]


def test_orchestrator_persists_audit_evidence_for_every_ai_call(
    settings, fixture_apk
) -> None:  # noqa: ANN001
    configured = replace(settings, codex_enabled=True)
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    target_dir = configured.data_dir / "artifacts" / "fixture"
    target_dir.mkdir(parents=True)
    target = target_dir / "fixture.apk"
    shutil.copyfile(fixture_apk, target)
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            artifact_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
            artifact_path=str(target),
            stats={"investigator": "codex"},
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            task = kwargs["task"]
            evidence = kwargs["evidence"]
            assert kwargs["platform_context"]["output_language"] == "zh-CN"
            entry_scope = kwargs["platform_context"]["entry_scope"]
            assert entry_scope["policy"] == (
                "seed_entry_with_scan_wide_chain_exploration"
            )
            assert entry_scope["seed_entry_point_ids"] == task.target_entry_ids
            assert {
                item["id"] for item in entry_scope["catalog"]
            } == set(task.target_entry_ids)
            assert all(
                item["assigned_seed"] for item in entry_scope["catalog"]
            )
            assert all(
                item["name"] != "com.example.vulnerable.TrustedService"
                for item in entry_scope["catalog"]
            )
            representatives = kwargs["platform_context"]["threat_model"][
                "attack_surface"
            ]["representative_entries"]
            assert all(
                item["name"] != "com.example.vulnerable.TrustedService"
                for item in representatives
            )
            code_context = kwargs["platform_context"]["target_code_context"]
            assert code_context["schema_version"] == "1.0"
            assert code_context["components"]
            kwargs["event_callback"](
                AgentRuntimeEvent(
                    event_type="model.turn.started",
                    message="Fake SDK turn started",
                    data={"turn_id": f"turn-{task.id}"},
                )
            )
            return SimpleNamespace(
                thread_id=f"thread-{task.id}",
                turn_id=f"turn-{task.id}",
                usage={"input_tokens": 10, "output_tokens": 5},
                result=AgentInvestigationResult(
                    summary="Manifest 静态证据支持该风险线索。",
                    result="supported_static",
                    hypotheses_tested=task.hypotheses,
                    test_cases=[],
                    evidence_ids=[evidence[0]["id"]],
                    severity_proposal="medium",
                    confidence="medium",
                    coverage_gaps=["No dynamic device"],
                    followups=[],
                    requested_tests=[],
                ),
            )

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    orchestrator.investigators["codex"] = FakeInvestigator()
    orchestrator._run_sync(scan_id)

    with database.session_factory() as session:
        tasks = list(
            session.scalars(
                select(InvestigationTask).where(InvestigationTask.scan_id == scan_id)
            )
        )
        audit_evidence = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.scan_id == scan_id,
                        Evidence.kind.in_(
                            {
                                "agent.request",
                                "agent.events",
                                "agent.response",
                                "agent.validation",
                            }
                        ),
                    )
                )
            )
        exploration_events = list(
            session.scalars(
                select(ScanEvent).where(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.event_type == "exploration.model.turn.started",
                )
            )
        )
        proof_backlog = list(
            session.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.source == "codex",
                    Finding.status == "supported_static",
                )
            )
        )
        trusted_service = session.scalar(
            select(EntryPoint).where(
                EntryPoint.scan_id == scan_id,
                EntryPoint.name == "com.example.vulnerable.TrustedService",
            )
        )
        trusted_coverage = (
            session.scalar(
                select(CoverageItem).where(
                    CoverageItem.entry_point_id == trusted_service.id,
                )
            )
            if trusted_service is not None
            else None
        )
        static_closure_events = list(
            session.scalars(
                select(ScanEvent).where(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.event_type == "planning.static_closed",
                )
            )
        )
    assert tasks
    assert len(audit_evidence) == len(tasks) * 4
    assert {item.kind for item in audit_evidence} == {
        "agent.request",
        "agent.events",
        "agent.response",
        "agent.validation",
    }
    assert len(exploration_events) == len(tasks)
    assert len(proof_backlog) == len(tasks)
    assert all(
        finding.metadata_json["proof_backlog"]["status"] == "proof_required"
        for finding in proof_backlog
    )
    assert all(
        finding.metadata_json["proof_backlog"]["automation_state"]
        == "manual_or_poc_required"
        for finding in proof_backlog
    )
    assert trusted_service is not None
    assert all(trusted_service.id not in task.target_entry_ids for task in tasks)
    assert trusted_coverage is not None
    assert trusted_coverage.status == "covered"
    assert trusted_coverage.stages["agent"] == "not_applicable"
    assert (
        trusted_coverage.stages["indirect_chain"]
        == "retained_for_scan_wide_seed_exploration"
    )
    assert "普通第三方应用无法直接调用" in str(trusted_coverage.gap_reason)
    assert len(static_closure_events) == 1
    assert any(
        item["entry_point_id"] == trusted_service.id
        and item["reason_code"] == "strong_permission_guard"
        for item in static_closure_events[0].data["decisions"]
    )


def test_existing_scan_lazily_builds_target_code_context_from_partial_jadx(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    scan_id = "00000000-0000-0000-0000-000000000090"
    component = "com.example.PartialProvider"
    source = (
        settings.data_dir
        / "workspaces"
        / scan_id
        / "jadx"
        / "sources"
        / "com"
        / "example"
        / "PartialProvider.java"
    )
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\npublic class PartialProvider {}\n",
        encoding="utf-8",
    )
    evidence_sha, evidence_path = store.put_json(
        "evidence",
        {
            "argv": ["jadx", "legacy.apk"],
            "exit_code": 3,
            "stdout": "ERROR - finished with errors, count: 322",
            "stderr": "Failed to decompile class: com.example.OtherBrokenClass",
            "timed_out": False,
        },
    )
    with database.session_factory() as session:
        scan = Scan(
            id=scan_id,
            status="final",
            filename="legacy.apk",
            artifact_sha256="f" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        entry = EntryPoint(
            scan_id=scan_id,
            kind="provider",
            name=component,
            owner_component=component,
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        session.add(
            Evidence(
                scan_id=scan_id,
                kind="static.jadx",
                sha256=evidence_sha,
                path=str(evidence_path),
                summary="jadx exited with 3",
            )
        )
        session.commit()

    orchestrator = ScanOrchestrator(settings, database, store)
    context = orchestrator._target_code_context(scan_id, [entry])
    assert context["global_decompilation"]["status"] == "partial_success"
    assert context["components"][0]["status"] == "source_available"
    assert "class PartialProvider" in context["components"][0]["anchors"][0]["content"]
    assert (
        settings.data_dir / "workspaces" / scan_id / "code_index.json"
    ).is_file()


def test_running_agent_is_interrupted_and_audited_as_cancelled(settings) -> None:  # noqa: ANN001
    configured = replace(settings, codex_enabled=True)
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)
    started = threading.Event()
    scan_id = "00000000-0000-0000-0000-000000000095"
    task_id = "00000000-0000-0000-0000-000000000096"
    entry_id = "00000000-0000-0000-0000-000000000097"
    workspace = configured.data_dir / "workspaces" / scan_id
    workspace.mkdir(parents=True)
    with database.session_factory() as session:
        scan = Scan(
            id=scan_id,
            status="final",
            filename="cancel.apk",
            artifact_sha256="3" * 64,
            artifact_path=str(configured.data_dir / "missing.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            id=entry_id,
            scan_id=scan_id,
            kind="provider",
            name="com.example.CancelProvider",
            owner_component="com.example.CancelProvider",
            exported=True,
        )
        task = InvestigationTask(
            id=task_id,
            scan_id=scan_id,
            task_type="component",
            status="queued",
            target_entry_ids=[entry_id],
        )
        session.add_all([scan, entry, task])
        session.commit()

    class BlockingInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            started.set()
            assert kwargs["cancel_event"].wait(timeout=5)
            raise AgentCancelledError("cancelled by unit test")

    orchestrator = ScanOrchestrator(configured, database, store)
    orchestrator.investigators["codex"] = BlockingInvestigator()
    worker = threading.Thread(
        target=orchestrator._run_task,
        args=(scan_id, task_id, 10),
    )
    worker.start()
    assert started.wait(timeout=5)
    assert orchestrator.request_task_cancellation(task_id) is True
    worker.join(timeout=5)
    assert not worker.is_alive()

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.status == "canceled"
        assert task.result["cancellation"]["acknowledged"] is True
        audits = build_agent_audits(session, store, scan_id)
        assert audits[0]["status"] == "cancelled"
        assert "cancellation" in audits[0]["artifacts"]


@pytest.mark.parametrize(
    ("winning_status", "expected_status"),
    [
        ("cancel_requested", "canceled"),
        ("deleted", "deleted"),
    ],
)
def test_cancellation_after_runtime_registration_is_acknowledged_before_task_load(
    settings,
    monkeypatch,
    winning_status: str,
    expected_status: str,
) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="startup-cancel.apk",
            artifact_sha256="6" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="receiver",
            name="com.example.StartupReceiver",
            owner_component="com.example.StartupReceiver",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="running",
            target_entry_ids=[entry.id],
        )
        session.add(task)
        session.commit()
        scan_id = scan.id
        task_id = task.id

    orchestrator = ScanOrchestrator(settings, database, store)

    def cancel_before_task_load(
        _scan_id: str,
        _task_id: str,
        _timeout_seconds: int | None,
        *,
        cancel_event: threading.Event,
    ) -> None:
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            task.status = winning_status
            task.result = {
                "cancellation": {
                    "requested": True,
                    "acknowledged": False,
                },
                **(
                    {"deletion": {"soft_deleted": True}}
                    if winning_status == "deleted"
                    else {}
                ),
            }
            session.commit()
        assert orchestrator.request_task_cancellation(task_id) is True
        orchestrator._raise_if_cancelled(cancel_event)

    monkeypatch.setattr(orchestrator, "_run_task_impl", cancel_before_task_load)
    orchestrator._run_task(scan_id, task_id, 10)

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.status == expected_status
        assert task.result["cancellation"]["acknowledged"] is True


@pytest.mark.parametrize(
    ("winning_status", "expected_status"),
    [
        ("cancel_requested", "canceled"),
        ("deleted", "deleted"),
    ],
)
def test_terminal_write_yields_to_cancel_or_delete_without_completion_side_effects(
    settings,
    monkeypatch,
    winning_status: str,
    expected_status: str,
) -> None:  # noqa: ANN001
    configured = replace(settings, codex_enabled=True)
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="terminal-race.apk",
            artifact_sha256="8" * 64,
            artifact_path=str(configured.data_dir / "missing.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="provider",
            name="com.example.RaceProvider",
            owner_component="com.example.RaceProvider",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="queued",
            target_entry_ids=[entry.id],
        )
        coverage = CoverageItem(
            scan=scan,
            control_id="entry:terminal-race",
            domain="entry_point",
            title="Terminal transition race",
            status="not_tested",
            stages={"agent": "not_tested"},
            entry_point_id=entry.id,
        )
        session.add_all([task, coverage])
        session.commit()
        scan_id = scan.id
        task_id = task.id
        coverage_id = coverage.id

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**_kwargs):  # noqa: ANN003, ANN205
            return SimpleNamespace(
                thread_id="thread-terminal-race",
                turn_id="turn-terminal-race",
                usage={"input_tokens": 1, "output_tokens": 1},
                result=AgentInvestigationResult(
                    summary="当前没有形成可验证的动态危害证据。",
                    result="refuted_static",
                    hypotheses_tested=[],
                    test_cases=[],
                    evidence_ids=[],
                        severity_proposal="info",
                    confidence="low",
                    coverage_gaps=["No device evidence"],
                    followups=[],
                    requested_tests=[],
                ),
            )

    def win_terminal_race(**_kwargs) -> None:  # noqa: ANN003
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None and task.status == "running"
            task.status = winning_status
            task.result = {
                "race_winner": winning_status,
                "cancellation": {
                    "requested": True,
                    "acknowledged": False,
                },
                **(
                    {"deletion": {"soft_deleted": True}}
                    if winning_status == "deleted"
                    else {}
                ),
            }
            session.commit()

    orchestrator = ScanOrchestrator(configured, database, store)
    orchestrator.investigators["codex"] = FakeInvestigator()
    monkeypatch.setattr(
        orchestrator,
        "_validated_agent_payload",
        lambda payload, _evidence: (payload, "refuted_static"),
    )
    monkeypatch.setattr(
        orchestrator,
        "_record_agent_validation",
        win_terminal_race,
    )

    orchestrator._run_task(scan_id, task_id, 10)

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        coverage = session.get(CoverageItem, coverage_id)
        assert task is not None and task.status == expected_status
        assert task.result["race_winner"] == winning_status
        assert task.result["cancellation"]["acknowledged"] is True
        assert coverage is not None and coverage.status == "partial"
        assert coverage.stages["agent"] == "cancelled"
        assert (
            session.scalar(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.metadata_json["task_id"].as_string() == task_id,
                )
            )
            is None
        )
        event_types = set(
            session.scalars(
                select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id)
            )
        )
        assert "exploration.conclusion.recorded" not in event_types
        assert "task.completed" not in event_types
        assert "exploration.completed" not in event_types
        assert (
            session.scalar(
                select(HypothesisArgument.id)
                .where(
                    HypothesisArgument.task_id == task_id,
                    HypothesisArgument.role == "arbiter",
                )
                .limit(1)
            )
            is None
        )
        hypotheses = list(
            session.scalars(
                select(SecurityHypothesis).where(SecurityHypothesis.task_id == task_id)
            )
        )
        assert hypotheses
        assert all(
            "platform_result" not in hypothesis.metadata_json
            for hypothesis in hypotheses
        )


@pytest.mark.parametrize(
    "terminal_status",
    [
        "blocked_device",
        "completed",
        "not_reproduced",
        "inconclusive",
        "timed_out",
        "failed",
        "canceled",
    ],
)
def test_cancel_acknowledgement_does_not_overwrite_terminal_task(
    settings,
    terminal_status: str,
) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="already-terminal.apk",
            artifact_sha256="7" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status=terminal_status,
            result={"terminal_winner": terminal_status},
            error="terminal result",
            completed_at=datetime(2025, 1, 1, tzinfo=UTC),
        )
        session.add_all([scan, task])
        session.commit()
        scan_id = scan.id
        task_id = task.id

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    orchestrator._mark_task_canceled(scan_id, task_id)

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.status == terminal_status
        assert task.result == {"terminal_winner": terminal_status}
        assert task.error == "terminal result"
        assert task.completed_at == datetime(2025, 1, 1)
        assert (
            session.scalar(
                select(ScanEvent).where(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.event_type.in_(
                        {
                            "task.cancelled",
                            "exploration.cancelled",
                        }
                    ),
                )
            )
            is None
        )


def test_predispatch_cancellation_finishes_coverage_and_audit(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="predispatch-cancel.apk",
            artifact_sha256="5" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.CancelledActivity",
            owner_component="com.example.CancelledActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="canceled",
            target_entry_ids=[entry.id],
            result={
                "cancellation": {
                    "requested": True,
                    "acknowledged": True,
                    "requested_at": "2026-07-28T00:00:00+00:00",
                }
            },
        )
        coverage = CoverageItem(
            scan=scan,
            control_id="entry:predispatch-cancel",
            domain="entry_point",
            title="Predispatch cancellation",
            status="not_tested",
            stages={"agent": "pending"},
            entry_point_id=entry.id,
        )
        session.add_all([task, coverage])
        session.commit()
        scan_id = scan.id
        task_id = task.id
        coverage_id = coverage.id

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    orchestrator._mark_task_canceled(scan_id, task_id)

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        coverage = session.get(CoverageItem, coverage_id)
        assert task is not None
        assert task.status == "canceled"
        assert task.result["cancellation"]["acknowledged"] is True
        assert "completed_at" in task.result["cancellation"]
        assert coverage is not None
        assert coverage.status == "partial"
        assert coverage.stages["agent"] == "cancelled"
        event_types = set(
            session.scalars(
                select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id)
            )
        )
        assert {"task.cancelled", "exploration.cancelled"} <= event_types


def test_canceled_task_selected_before_dispatch_is_not_restarted(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    scan_id = "00000000-0000-0000-0000-000000000098"
    task_id = "00000000-0000-0000-0000-000000000099"
    with database.session_factory() as session:
        scan = Scan(
            id=scan_id,
            status="investigating",
            filename="dispatch-race.apk",
            artifact_sha256="4" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        task = InvestigationTask(
            id=task_id,
            scan_id=scan_id,
            task_type="component",
            status="canceled",
            attempts=0,
        )
        session.add_all([scan, task])
        session.commit()

    orchestrator = ScanOrchestrator(settings, database, store)
    orchestrator._run_task(scan_id, task_id, 10)

    with database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.status == "canceled"
        assert task.attempts == 0


def test_unexpected_scan_failure_terminalizes_transient_tasks(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="unexpected-failure.apk",
            artifact_sha256="e" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        queued = InvestigationTask(scan=scan, task_type="component", status="queued")
        running = InvestigationTask(scan=scan, task_type="component", status="running")
        canceling = InvestigationTask(
            scan=scan,
            task_type="component",
            status="cancel_requested",
        )
        completed = InvestigationTask(
            scan=scan,
            task_type="component",
            status="completed",
        )
        session.add_all([scan, queued, running, canceling, completed])
        session.commit()
        identifiers = {
            "scan": scan.id,
            "queued": queued.id,
            "running": running.id,
            "canceling": canceling.id,
            "completed": completed.id,
        }

    orchestrator = ScanOrchestrator(settings, database, store)
    monkeypatch.setattr(
        orchestrator,
        "_run_static",
        lambda _scan_id: (_ for _ in ()).throw(RuntimeError("unexpected failure")),
    )
    orchestrator._run_sync(identifiers["scan"])

    with database.session_factory() as session:
        scan = session.get(Scan, identifiers["scan"])
        assert scan is not None and scan.status == "failed"
        assert session.get(InvestigationTask, identifiers["queued"]).status == "failed"
        assert session.get(InvestigationTask, identifiers["running"]).status == "failed"
        assert session.get(InvestigationTask, identifiers["canceling"]).status == "canceled"
        assert session.get(InvestigationTask, identifiers["completed"]).status == "completed"


@pytest.mark.asyncio
async def test_submit_coalesces_a_rerun_requested_during_active_scan(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def run(scan_id: str) -> None:
        calls.append(scan_id)
        if len(calls) == 1:
            started.set()
            assert release.wait(timeout=5)

    monkeypatch.setattr(orchestrator, "_run_sync", run)
    first = asyncio.create_task(orchestrator.submit("scan-race"))
    assert await asyncio.to_thread(started.wait, 5)
    await orchestrator.submit("scan-race")
    release.set()
    await first
    assert calls == ["scan-race", "scan-race"]


def test_restart_recovery_normalizes_transient_device_states(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    scan_id = "00000000-0000-0000-0000-000000000100"
    task_ids = {
        "awaiting": "00000000-0000-0000-0000-000000000101",
        "running_agent": "00000000-0000-0000-0000-000000000102",
        "cancel": "00000000-0000-0000-0000-000000000103",
        "running_device": "00000000-0000-0000-0000-000000000104",
    }
    with database.session_factory() as session:
        scan = Scan(
            id=scan_id,
            status="investigating",
            filename="restart.apk",
            artifact_sha256="6" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
        )
        session.add(scan)
        session.add_all(
            [
                InvestigationTask(
                    id=task_ids["awaiting"],
                    scan_id=scan_id,
                    task_type="component",
                    status="awaiting_device",
                ),
                InvestigationTask(
                    id=task_ids["running_agent"],
                    scan_id=scan_id,
                    task_type="component",
                    status="running",
                    attempts=1,
                ),
                InvestigationTask(
                    id=task_ids["cancel"],
                    scan_id=scan_id,
                    task_type="component",
                    status="cancel_requested",
                ),
                InvestigationTask(
                    id=task_ids["running_device"],
                    scan_id=scan_id,
                    task_type="component",
                    status="running",
                    attempts=1,
                    result={
                        "device_queue": {
                            "requested_at": datetime.now(UTC).isoformat(),
                            "acquired_at": datetime.now(UTC).isoformat(),
                        }
                    },
                ),
            ]
        )
        session.commit()

    orchestrator = ScanOrchestrator(settings, database, store)
    orchestrator.recover_interrupted_device_tasks()

    with database.session_factory() as session:
        awaiting = session.get(InvestigationTask, task_ids["awaiting"])
        running_agent = session.get(InvestigationTask, task_ids["running_agent"])
        running_device = session.get(InvestigationTask, task_ids["running_device"])
        canceled = session.get(InvestigationTask, task_ids["cancel"])
        assert awaiting is not None and awaiting.status == "queued"
        assert awaiting.result["device_queue"]["recovered_at"]
        assert running_agent is not None and running_agent.status == "queued"
        assert (
            running_agent.result["worker_recovery"]["reason"]
            == "interrupted_outside_device_session"
        )
        assert running_device is not None and running_device.status == "inconclusive"
        assert "restart" in running_device.result["coverage_gaps"][0].lower()
        assert canceled is not None and canceled.status == "canceled"
        assert canceled.result["cancellation"]["acknowledged"] is True


def test_refuted_static_agent_result_has_no_platform_risk_severity() -> None:
    payload = AgentInvestigationResult(
        summary="静态证据表明攻击路径受到有效控制。",
        result="refuted_static",
        hypotheses_tested=["Exported provider may expose data"],
        test_cases=[],
        evidence_ids=["static"],
        severity_proposal="info",
        confidence="low",
        coverage_gaps=[],
        followups=[],
        requested_tests=[],
    ).model_dump(mode="json")

    validated, result = ScanOrchestrator._validated_agent_payload(
        payload,
        [{"id": "static", "kind": "static.apktool", "metadata": {}}],
    )

    assert result == "refuted_static"
    assert validated["severity_proposal"] == "info"
    assert validated["platform_severity"] is None
    assert validated["severity_disposition"] == "not_applicable_refuted"


def test_platform_proof_overrides_refuting_arbiter_payload() -> None:
    hypothesis_id = "00000000-0000-0000-0000-000000000091"
    payload = {
        "result": "refuted_static",
        "severity_proposal": "info",
        "platform_severity": None,
        "confidence": "low",
        "hypotheses_tested": [hypothesis_id],
        "hypothesis_assessments": [
            {
                "hypothesis_id": hypothesis_id,
                "verdict": "refuted_static",
                "source": "",
                "control": "",
                "sink": "",
                "reachable_path": "",
                "boundary": "",
                "counterevidence": ["Static Critic disagreement."],
                "proof_gaps": ["Critic did not inspect the device replay."],
                "evidence_ids": ["static-only"],
                "confidence": "high",
            }
        ],
        "objection_resolutions": [
            {
                "objection_id": "OBJ-1",
                "disposition": "sustained",
                "rationale": "The Arbiter accepted the static objection.",
                "evidence_ids": [],
            }
        ],
        "evidence_ids": ["static-only"],
    }

    overridden = ScanOrchestrator._apply_platform_proof_overrides(
        payload,
        proven_hypotheses={
            hypothesis_id: ["poc-logcat", "impact-observed"],
        },
        proven_severity="high",
        agent_round_history=[
            {
                "model_result": {
                    "result": "reproduced_blackbox",
                    "severity_proposal": "low",
                }
            }
        ],
        debate_context={
            "critic": {
                "review_objections": [
                    {
                        "objection_id": "OBJ-1",
                        "hypothesis_id": hypothesis_id,
                    }
                ]
            }
        },
    )

    assert overridden["result"] == "reproduced_blackbox"
    assert overridden["severity_proposal"] == "high"
    assert overridden["platform_severity"] == "high"
    assert overridden["confidence"] == "high"
    assert overridden["hypothesis_assessments"][0]["verdict"] == (
        "reproduced_blackbox"
    )
    assert overridden["hypothesis_assessments"][0]["counterevidence"] == []
    assert overridden["hypothesis_assessments"][0]["proof_gaps"] == []
    assert overridden["objection_resolutions"][0]["disposition"] == "overruled"
    assert overridden["platform_proof_overrides"][hypothesis_id]["immutable"] is True


def test_negative_model_results_require_blind_rescue_review() -> None:
    for result in ("refuted_static", "not_reproduced"):
        assert ScanOrchestrator._needs_rescue_review(
            SimpleNamespace(result=result)
        )
    for result in ("supported_static", "reproduced_blackbox"):
        assert not ScanOrchestrator._needs_rescue_review(
            SimpleNamespace(result=result)
        )
