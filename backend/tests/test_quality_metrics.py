from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apkscanner.core.db import Database
from apkscanner.core.models import (
    AgentSessionRecord,
    AgentTurnRecord,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    RuntimeObservation,
    Scan,
    ScanEvent,
    SecurityHypothesis,
)
from apkscanner.runtime.quality_metrics import _classify_failure, build_scan_quality_summary

VALID_STATIC_GATE = {
    "schema_version": "1.0",
    "eligible": True,
    "required_fields": [
        "source",
        "control",
        "sink",
        "reachable_path",
        "boundary",
        "security_impact",
        "missing_control",
    ],
    "static_evidence_ids": ["static-chain"],
    "suppression_reasons": [],
}


def test_failure_classifier_distinguishes_planning_and_runtime_receipt_gaps() -> None:
    assert _classify_failure("no_accepted_proof_request") == "planning"
    assert (
        _classify_failure("adb logcat: poc_execution_receipt_missing:receipt_unreadable")
        == "runtime_correlation"
    )
    assert _classify_failure("adb worker timed out while observing Oracle") == "timeout"


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
            evidence_ids=[dynamic_evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "proof_attempt_ids": [attempt.id],
                "harm_demonstrated": True,
            },
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


def test_quality_funnel_does_not_count_oracle_gaps_as_static_support(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="noise-tiers.apk",
            artifact_sha256="d" * 64,
            artifact_path="noise-tiers.apk",
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="completed",
        )
        session.add_all([scan, task])
        session.flush()
        static_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="e" * 64,
            category="component",
            claim="A complete static chain reaches a sensitive sink.",
            status="accepted_for_proof",
            support_evidence_ids=["static-chain"],
        )
        runtime_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="f" * 64,
            category="component",
            claim="Runtime behavior was observed without a harm Oracle.",
            status="accepted_for_proof",
            support_evidence_ids=["runtime-observation"],
        )
        session.add_all([static_hypothesis, runtime_hypothesis])
        session.flush()
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="1" * 64,
            path="static-chain.json",
        )
        runtime_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.logcat",
            sha256="2" * 64,
            path="runtime-observation.log",
            metadata_json={"request_observed": True},
        )
        session.add_all([static_evidence, runtime_evidence])
        session.flush()
        static_finding = Finding(
            scan_id=scan.id,
            dedupe_key="static-chain",
            rule_id="AGENT",
            title="Static chain",
            description="Complete static chain",
            masvs="MASVS-PLATFORM",
            severity="medium",
            status="supported_static",
            evidence_ids=[static_evidence.id],
            metadata_json={
                "platform_static_support_gate": {
                    **VALID_STATIC_GATE,
                    "static_evidence_ids": [static_evidence.id],
                }
            },
        )
        runtime_finding = Finding(
            scan_id=scan.id,
            dedupe_key="runtime-gap",
            rule_id="AGENT",
            title="Runtime Oracle gap",
            description="Observed behavior without proven harm",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="runtime_observed_unverified",
            evidence_ids=[runtime_evidence.id],
            metadata_json={
                "harm_demonstrated": False,
                "adaptive_verification": {
                    "runtime_observed": True,
                    "model_verdict": "reproduced_blackbox",
                },
            },
        )
        session.add_all([static_finding, runtime_finding])
        session.flush()
        session.add(
            RuntimeObservation(
                scan_id=scan.id,
                task_id=task.id,
                finding_id=runtime_finding.id,
                observation_key=f"quality-runtime:{runtime_finding.id}",
                kind="request.observed",
                source="adb",
                evidence_ids=[runtime_evidence.id],
                payload={"request_observed": True},
            )
        )
        static_hypothesis.final_finding_id = static_finding.id
        runtime_hypothesis.final_finding_id = runtime_finding.id
        session.commit()
        scan_id = scan.id

    with database.session_factory() as session:
        summary = build_scan_quality_summary(session, scan_id)

    funnel = {item["key"]: item["count"] for item in summary["funnel"]}
    assert funnel["static_supported"] == 1
    assert funnel["runtime_observed_unverified"] == 1


def test_quality_funnel_ignores_merged_runtime_duplicates(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="merged-quality.apk",
            artifact_sha256="1" * 64,
            artifact_path="merged-quality.apk",
        )
        canonical = Finding(
            scan=scan,
            dedupe_key="canonical-runtime",
            rule_id="AGENT",
            title="Canonical runtime gap",
            description="One active Oracle gap.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="runtime_observed_unverified",
            metadata_json={"signal_tier": "runtime_oracle_gap"},
        )
        duplicate = Finding(
            scan=scan,
            dedupe_key="merged-runtime",
            rule_id="AGENT",
            title="Merged runtime gap",
            description="Hidden duplicate audit row.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="inconclusive",
            metadata_json={
                "merged_into_finding_id": "pending-canonical-id",
                "adaptive_verification": {
                    "runtime_observed": True,
                    "model_verdict": "reproduced_blackbox",
                    "verdict_override_reason": "missing platform Oracle",
                },
                "harm_demonstrated": False,
            },
        )
        session.add_all([scan, canonical, duplicate])
        session.flush()
        runtime_evidence = Evidence(
            scan_id=scan.id,
            kind="blackbox.logcat",
            sha256="3" * 64,
            path="merged-runtime.log",
            metadata_json={"request_observed": True},
        )
        session.add(runtime_evidence)
        session.flush()
        canonical.evidence_ids = [runtime_evidence.id]
        session.add(
            RuntimeObservation(
                scan_id=scan.id,
                finding_id=canonical.id,
                observation_key=f"merged-quality:{canonical.id}",
                kind="request.observed",
                source="adb",
                evidence_ids=[runtime_evidence.id],
                payload={"request_observed": True},
            )
        )
        duplicate.metadata_json = {
            **dict(duplicate.metadata_json or {}),
            "merged_into_finding_id": canonical.id,
        }
        session.commit()
        scan_id = scan.id

    with database.session_factory() as session:
        summary = build_scan_quality_summary(session, scan_id)

    funnel = {item["key"]: item["count"] for item in summary["funnel"]}
    assert funnel["runtime_observed_unverified"] == 1
