from __future__ import annotations

from apkscanner.core.db import Database
from apkscanner.core.models import (
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.runtime.finding_policy import partition_findings
from apkscanner.runtime.orchestrator import ScanOrchestrator
from sqlalchemy import select


def test_mixed_proven_and_static_hypotheses_persist_separate_records(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))

    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="mixed.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "mixed.apk"),
            package_name="com.example.mixed",
        )
        proven_entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.ProvenActivity",
            exported=True,
        )
        static_entry = EntryPoint(
            scan=scan,
            kind="provider",
            name="com.example.StaticProvider",
            exported=True,
        )
        task = InvestigationTask(
            scan=scan,
            task_type="exported_component",
            status="completed",
            target_entry_ids=[],
            hypotheses=[],
        )
        session.add_all([scan, proven_entry, static_entry, task])
        session.flush()
        task.target_entry_ids = [proven_entry.id]

        proven = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="1" * 64,
            category="android.intent_redirect",
            claim="Attacker-controlled redirect reaches a privileged action",
            impact="Unauthorized privileged action",
            entry_point_ids=[proven_entry.id],
        )
        static = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="2" * 64,
            category="android.provider",
            claim="Exported provider may disclose sensitive rows",
            impact="Potential unauthorized data access",
            entry_point_ids=[static_entry.id],
        )
        session.add_all([proven, static])
        session.flush()
        task.hypotheses = [proven.id, static.id]

        proof_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.poc_ui_dump",
            sha256="b" * 64,
            path="proof.json",
            summary="Platform Oracle observed the unauthorized action",
        )
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.apktool",
            sha256="c" * 64,
            path="static.json",
            summary="Static provider path",
        )
        session.add_all([proof_evidence, static_evidence])
        session.flush()
        session.add(
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=proven.id,
                test_case_id="agent-r1-1",
                status="proven",
                plan={"entry_point_id": proven_entry.id},
                evidence_ids=[proof_evidence.id],
                harm_demonstrated=True,
            )
        )
        task.result = {
            "summary": "One hypothesis was dynamically proven; another remains static.",
            "result": "supported_static",
            "evidence_ids": [proof_evidence.id, static_evidence.id],
            "severity_proposal": "high",
            "platform_severity": "high",
            "confidence": "high",
            "coverage_gaps": [],
            "requested_tests": [],
            "hypothesis_assessments": [
                {
                    "hypothesis_id": proven.id,
                    "verdict": "supported_static",
                    "evidence_ids": [proof_evidence.id],
                    "proof_gaps": [],
                },
                {
                    "hypothesis_id": static.id,
                    "verdict": "supported_static",
                    "evidence_ids": [static_evidence.id],
                    "proof_gaps": ["Dedicated ordinary-app replay is still required."],
                },
            ],
        }
        session.flush()

        orchestrator._persist_agent_finding(
            session,
            scan,
            task,
            [proven_entry],
            "supported_static",
            "opencode",
        )
        session.flush()

        records = list(
            session.scalars(select(Finding).where(Finding.scan_id == scan.id))
        )
        confirmed, signals = partition_findings(session, records)

        assert len(confirmed) == 1
        assert confirmed[0].status == "reproduced_blackbox"
        assert confirmed[0].evidence_ids == [proof_evidence.id]
        assert confirmed[0].entry_point_ids == [proven_entry.id]
        assert len(signals) == 1
        assert signals[0].status == "supported_static"
        assert signals[0].evidence_ids == [static_evidence.id]
        assert signals[0].entry_point_ids == [static_entry.id]
        assert signals[0].metadata_json["excluded_proven_hypothesis_ids"] == [
            proven.id
        ]
