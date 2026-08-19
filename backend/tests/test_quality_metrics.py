from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apkscanner.db import Database
from apkscanner.models import (
    AgentSessionRecord,
    AgentTurnRecord,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    ScanEvent,
    SecurityHypothesis,
)
from apkscanner.quality_metrics import build_scan_quality_summary


def test_quality_summary_tracks_funnel_cost_and_failures(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    started = datetime.now(UTC) - timedelta(seconds=12)
    with database.session_factory() as session:
        scan = Scan(
            filename="quality.apk",
            artifact_sha256="a" * 64,
            artifact_path="quality.apk",
        )
        session.add(scan)
        session.flush()
        entry = EntryPoint(
            scan_id=scan.id,
            kind="activity",
            name="com.example.Entry",
            exported=True,
        )
        session.add(entry)
        session.flush()
        task = InvestigationTask(
            scan_id=scan.id,
            task_type="component",
            status="completed",
            target_entry_ids=[entry.id, "merged-entry"],
        )
        session.add(task)
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="b" * 64,
            category="component",
            claim="An exported activity reaches a privileged sink.",
            support_evidence_ids=["static-evidence"],
            status="proven",
        )
        session.add(hypothesis)
        session.flush()
        dynamic_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="dynamic_experiment.adb",
            sha256="c" * 64,
            path="evidence.json",
            exit_code=0,
            metadata_json={"impact_contract_satisfied": True},
        )
        session.add(dynamic_evidence)
        session.flush()
        attempt = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="agent-r1-1",
            status="proven",
            evidence_ids=[dynamic_evidence.id],
            harm_demonstrated=True,
        )
        session.add(attempt)
        finding = Finding(
            scan_id=scan.id,
            dedupe_key="quality-finding",
            rule_id="AGENT",
            title="Proven issue",
            description="A dynamic proof demonstrated impact.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
        )
        session.add(finding)
        session.flush()
        hypothesis.final_finding_id = finding.id
        agent_session = AgentSessionRecord(
            scan_id=scan.id,
            task_id=task.id,
            session_key="quality-session",
            role="primary",
        )
        session.add(agent_session)
        session.flush()
        session.add(
            AgentTurnRecord(
                scan_id=scan.id,
                task_id=task.id,
                session_record_id=agent_session.id,
                audit_id="00000000-0000-0000-0000-000000000001",
                phase="test_planning",
                status="completed",
                usage_json={
                    "input_tokens": 100,
                    "output_tokens": 25,
                    "input_tokens_details": {"cached_tokens": 40},
                },
                started_at=started,
                completed_at=started + timedelta(seconds=10),
            )
        )
        session.add_all(
            [
                ScanEvent(
                    scan_id=scan.id,
                    event_type="task.device_acquired",
                    message="acquired",
                    data={"wait_seconds": 2.5},
                ),
                ScanEvent(
                    scan_id=scan.id,
                    event_type="task.device_released",
                    message="released",
                    data={"held_seconds": 8.5},
                ),
                ScanEvent(
                    scan_id=scan.id,
                    event_type="exploration.poc.build.failed",
                    message="build failed",
                    data={"error": "d8 compile failed"},
                ),
            ]
        )
        session.commit()
        scan_id = scan.id

    with database.session_factory() as session:
        summary = build_scan_quality_summary(session, scan_id)

    funnel = {item["key"]: item["count"] for item in summary["funnel"]}
    assert funnel["entry_points"] == 1
    assert funnel["proof_planned"] == 1
    assert funnel["device_executed"] == 1
    assert funnel["harm_proven"] == 1
    assert funnel["reproduced_findings"] == 1
    assert summary["cost"]["agent_calls"] == 1
    assert summary["cost"]["total_tokens"] == 125
    assert summary["cost"]["cached_input_tokens"] == 40
    assert summary["cost"]["device_held_seconds"] == 8.5
    assert summary["efficiency"]["merged_entry_variants"] == 1
    assert summary["failure_reasons"][0]["kind"] == "poc_build"
