from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from types import SimpleNamespace

from apkscanner.agent_events import AgentRuntimeEvent
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
