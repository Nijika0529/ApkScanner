from __future__ import annotations

import hashlib
import json
import shutil
import threading
from dataclasses import replace
from types import SimpleNamespace

from apkscanner.agent_audit import build_agent_audits
from apkscanner.agent_events import AgentCancelledError, AgentRuntimeEvent
from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.models import (
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    Scan,
    ScanEvent,
)
from apkscanner.orchestrator import ScanOrchestrator
from apkscanner.reports import ReportBuilder
from apkscanner.schemas import AgentInvestigationResult
from sqlalchemy import select


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
        assert len(list(session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan_id)))) == 8
        assert len(list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)))) >= 5
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
