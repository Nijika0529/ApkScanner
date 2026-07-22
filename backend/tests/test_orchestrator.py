from __future__ import annotations

import hashlib
import shutil

from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.models import CoverageItem, EntryPoint, Finding, InvestigationTask, Scan
from apkscanner.orchestrator import ScanOrchestrator
from apkscanner.reports import ReportBuilder
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
            stats={},
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    orchestrator._run_sync(scan_id)

    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "final"
        assert scan.package_name == "com.example.vulnerable"
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
