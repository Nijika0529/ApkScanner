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
from apkscanner.reports import ReportBuilder
from apkscanner.schemas import AgentInvestigationResult
from sqlalchemy import select


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


def test_task_dispatch_uses_configured_agent_concurrency(settings) -> None:  # noqa: ANN001
    configured = replace(settings, agent_concurrency=3)
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

    assert max_active == 3
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
        "agent_concurrency": 3,
        "adb_concurrency": 1,
        "device_wait_excluded_from_task_budget": True,
        "agent_workspace_scope": "task_attempt",
    }
    assert statuses == ["completed"] * 6


def test_agent_concurrency_limit_is_shared_across_scan_workers(settings) -> None:  # noqa: ANN001
    configured = replace(settings, agent_concurrency=3)
    orchestrator = ScanOrchestrator(
        configured,
        Database(configured),
        ArtifactStore(configured),
    )
    state_lock = threading.Lock()
    active = 0
    max_active = 0
    start = threading.Barrier(6)

    def fake_run_task_impl(
        _scan_id: str,
        _task_id: str,
        _timeout_seconds: int | None,
        *,
        cancel_event: threading.Event,
    ) -> None:
        nonlocal active, max_active
        assert not cancel_event.is_set()
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.06)
        with state_lock:
            active -= 1

    orchestrator._run_task_impl = fake_run_task_impl  # type: ignore[method-assign]

    def run(index: int) -> None:
        start.wait(timeout=5)
        orchestrator._run_task(
            f"scan-{index % 2}",
            f"task-{index}",
            60,
        )

    workers = [threading.Thread(target=run, args=(index,)) for index in range(6)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert max_active == 3


def test_parallel_workers_share_only_one_device_session(settings) -> None:  # noqa: ANN001
    configured = replace(settings, agent_concurrency=3)
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
        assert len(list(session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan_id)))) == 8
        findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == scan_id))
        )
        assert len(findings) >= 5
        assert all(
            finding.metadata_json["identity"]["finding_id"] for finding in findings
        )
        tasks = list(session.scalars(select(InvestigationTask).where(InvestigationTask.scan_id == scan_id)))
        assert tasks
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
                    summary="The manifest supports this candidate.",
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
    assert tasks
    assert len(audit_evidence) == len(tasks) * 4
    assert {item.kind for item in audit_evidence} == {
        "agent.request",
        "agent.events",
        "agent.response",
        "agent.validation",
    }
    assert len(exploration_events) == len(tasks)


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

    class CancelOnAcquire:
        @staticmethod
        def acquire(*, timeout: float) -> bool:
            del timeout
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
            return True

        @staticmethod
        def release() -> None:
            return None

    orchestrator._agent_slots = CancelOnAcquire()  # type: ignore[assignment]
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
                    summary="No conclusive dynamic evidence.",
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
        summary="Static evidence refutes the attacker path.",
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
