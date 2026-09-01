from __future__ import annotations

from apkscanner.core.db import Database
from apkscanner.core.models import (
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    RuntimeObservation,
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
                    "source": "Exported content provider URI",
                    "control": "The caller controls the queried URI.",
                    "sink": "SQLiteDatabase.query",
                    "reachable_path": "ContentProvider.query -> repository -> SQLiteDatabase.query",
                    "boundary": "ordinary_app_uid -> exported_provider",
                    "security_impact": "An ordinary app can read private application rows.",
                    "missing_control": "No read permission or caller authorization is enforced.",
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
        assert signals[0].metadata_json["signal_tier"] == "static_chain"
        assert signals[0].metadata_json["platform_static_support_gate"]["eligible"] is True
        assert signals[0].metadata_json["excluded_proven_hypothesis_ids"] == [
            proven.id
        ]


def test_failed_static_gate_clears_stale_hypothesis_support_before_return(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            filename="stale-support.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "stale-support.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="completed",
        )
        session.add_all([scan, task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="e" * 64,
            category="android.component",
            claim="A previous turn claimed a static vulnerability.",
            status="accepted_for_proof",
            support_evidence_ids=["stale-evidence"],
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.apktool",
            sha256="f" * 64,
            path="static.json",
        )
        session.add_all([hypothesis, evidence])
        session.flush()
        task.result = {
            "result": "supported_static",
            "evidence_ids": [evidence.id],
            "hypothesis_assessments": [
                {
                    "hypothesis_id": hypothesis.id,
                    "verdict": "supported_static",
                    "evidence_ids": [evidence.id],
                    "platform_static_support_gate": {"eligible": True},
                }
            ],
        }

        orchestrator._persist_agent_finding(
            session,
            scan,
            task,
            [],
            "supported_static",
            "codex",
        )
        session.flush()

        assert hypothesis.status == "inconclusive"
        assert hypothesis.support_evidence_ids == []
        assert hypothesis.metadata_json["static_support_suppression"]["reason"] == (
            "static_support_gate_failed"
        )
        assert task.result["static_support_suppressions"][0]["hypothesis_id"] == (
            hypothesis.id
        )
        assert task.result["hypothesis_assessments"][0][
            "reported_static_support_gate"
        ] == {"eligible": True}
        assert task.result["result"] == "inconclusive"
        assert task.status == "inconclusive"
        assert list(session.scalars(select(Finding).where(Finding.scan_id == scan.id))) == []


def test_static_rerun_does_not_erase_a_runtime_oracle_gap(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            filename="runtime-gap-rerun.apk",
            artifact_sha256="1" * 64,
            artifact_path=str(settings.data_dir / "runtime-gap-rerun.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.RuntimeGapActivity",
            exported=True,
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="completed",
        )
        session.add_all([scan, entry, task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="2" * 64,
            category="android.component",
            claim="Runtime behavior reaches a sensitive WebView sink.",
            entry_point_ids=[entry.id],
        )
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="3" * 64,
            path="jadx.json",
        )
        session.add_all([hypothesis, static_evidence])
        session.flush()
        runtime_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.logcat",
            sha256="4" * 64,
            path="runtime.log",
            metadata_json={"request_observed": True},
        )
        session.add(runtime_evidence)
        session.flush()
        finding = Finding(
            scan_id=scan.id,
            dedupe_key=f"agent:{task.id}:hypothesis:{hypothesis.id}",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="codex",
            title="Runtime Oracle gap",
            description="Runtime behavior was observed.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
            entry_point_ids=[entry.id],
            evidence_ids=[runtime_evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "proof_backlog": {"status": "oracle_gap"},
                "adaptive_verification": {
                    "runtime_observed": True,
                    "model_verdict": "reproduced_blackbox",
                },
                "report": {"title": "runtime report"},
            },
        )
        session.add(finding)
        session.flush()
        session.add(
            RuntimeObservation(
                scan_id=scan.id,
                task_id=task.id,
                finding_id=finding.id,
                observation_key=f"static-rerun:{finding.id}",
                kind="request.observed",
                source="adb",
                evidence_ids=[runtime_evidence.id],
                payload={"request_observed": True},
            )
        )
        hypothesis.final_finding_id = finding.id
        assessment = {
            "hypothesis_id": hypothesis.id,
            "verdict": "supported_static",
            "source": "Exported activity intent",
            "control": "The URI is caller controlled.",
            "sink": "WebView.loadUrl",
            "reachable_path": "Activity -> handler -> WebView.loadUrl",
            "boundary": "ordinary_app_uid -> target_app_process",
            "security_impact": "Attacker content can execute in a privileged WebView context.",
            "missing_control": "No origin allowlist is enforced.",
            "evidence_ids": [static_evidence.id],
            "proof_gaps": [],
            "platform_static_support_gate": {
                "eligible": True,
                "suppression_reasons": [],
            },
        }
        task.result = {
            "result": "supported_static",
            "evidence_ids": [static_evidence.id],
            "hypothesis_assessments": [assessment],
        }

        orchestrator._supersede_prior_agent_findings(
            session, task, "supported_static", "codex"
        )
        orchestrator._persist_agent_finding(
            session, scan, task, [entry], "supported_static", "codex"
        )
        session.flush()

        assert finding.status == "runtime_observed_unverified"
        assert finding.evidence_ids == [runtime_evidence.id, static_evidence.id]
        assert finding.metadata_json["signal_tier"] == "runtime_oracle_gap"
        assert finding.metadata_json["proof_backlog"]["status"] == "oracle_gap"
        assert finding.metadata_json["adaptive_verification"]["runtime_observed"] is True
        assert "latest_static_support_report" in finding.metadata_json


def test_static_rerun_preserves_a_human_false_positive_closure(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            filename="human-closure.apk",
            artifact_sha256="9" * 64,
            artifact_path=str(settings.data_dir / "human-closure.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.DeepLinkActivity",
            exported=True,
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, entry, task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="8" * 64,
            category="android.webview",
            claim="External URI may reach a privileged WebView.",
            entry_point_ids=[entry.id],
        )
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="7" * 64,
            path="human-closure-static.json",
        )
        session.add_all([hypothesis, static_evidence])
        session.flush()
        finding = Finding(
            scan=scan,
            dedupe_key=f"agent:{task.id}:hypothesis:{hypothesis.id}",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="codex",
            title="人工确认的误报",
            description="该路径受业务约束保护。",
            remediation="无需修改。",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="false_positive",
            review_note="已核对业务调用者白名单。",
            entry_point_ids=[entry.id],
            evidence_ids=[static_evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "task_id": task.id,
                "report": {
                    "kind": "pending_risk",
                    "conclusion": "人工复核结论保持关闭。",
                    "verification": {"status": "refuted"},
                },
            },
        )
        session.add(finding)
        session.flush()
        hypothesis.final_finding_id = finding.id
        task.result = {
            "result": "supported_static",
            "evidence_ids": [static_evidence.id],
            "severity_proposal": "high",
            "confidence": "high",
            "hypothesis_assessments": [
                {
                    "hypothesis_id": hypothesis.id,
                    "verdict": "supported_static",
                    "source": "Exported activity intent URI",
                    "control": "The URI remains fully caller controlled.",
                    "sink": "WebView.loadUrl",
                    "reachable_path": "DeepLinkActivity -> router -> WebView.loadUrl",
                    "boundary": "ordinary_app_uid -> target_app_process",
                    "security_impact": "Attacker-controlled content could run in app context.",
                    "missing_control": "The model did not observe a destination allowlist.",
                    "evidence_ids": [static_evidence.id],
                    "proof_gaps": [],
                }
            ],
        }

        orchestrator._supersede_prior_agent_findings(
            session, task, "supported_static", "codex"
        )
        orchestrator._persist_agent_finding(
            session, scan, task, [entry], "supported_static", "codex"
        )
        session.flush()

        assert finding.status == "false_positive"
        assert finding.review_note == "已核对业务调用者白名单。"
        assert finding.title == "人工确认的误报"
        assert finding.description == "该路径受业务约束保护。"
        assert finding.metadata_json["report"]["verification"]["status"] == "refuted"
        latest = finding.metadata_json["latest_agent_reanalysis"]
        assert latest["task_id"] == task.id
        assert latest["result"] == "supported_static"
        assert latest["evidence_ids"] == [static_evidence.id]
        assert latest["human_closure_preserved"] is True
        assert latest["report"]["verification"]["status"] == "pending"
