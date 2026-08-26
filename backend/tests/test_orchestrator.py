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
from apkscanner.core.db import Database
from apkscanner.core.models import (
    AdaptiveVerificationCheckpoint,
    AgentRuntimeEventRecord,
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    HypothesisArgument,
    InvestigationTask,
    ProofAttempt,
    RuntimeObservation,
    Scan,
    ScanEvent,
    SecurityHypothesis,
)
from apkscanner.core.schemas import (
    AdaptiveVerificationResult,
    AdbDeviceOut,
    AgentInvestigationResult,
    AgentRuntimeObservation,
)
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.platform.reports import ReportBuilder
from apkscanner.platform.tools import CommandResult, TimeBudget, ToolRunner
from apkscanner.runtime.adb_gateway import AdbGatewayRequest
from apkscanner.runtime.agent_audit import build_agent_audits
from apkscanner.runtime.agent_events import AgentCancelledError, AgentRuntimeEvent
from apkscanner.runtime.device import AdbDeviceAdapter
from apkscanner.runtime.finding_policy import partition_findings
from apkscanner.runtime.orchestrator import ScanOrchestrator, _LiveProofContext
from apkscanner.runtime.planner import StaticEntryClosure
from sqlalchemy import select


@pytest.mark.parametrize(
    "args",
    [
        ["shell", "pm", "clear", "com.example.target"],
        ["shell", "sh", "-c", "pm clear com.example.target"],
        ["uninstall", "com.example.target"],
        ["shell", "run-as", "com.example.target", "rm", "databases/session.db"],
    ],
)
def test_preserve_policy_recognizes_adaptive_adb_target_data_destruction(
    args: list[str],
) -> None:
    assert ScanOrchestrator._adb_command_destroys_target_data(
        args,
        package_name="com.example.target",
    )


def test_preserve_policy_allows_target_launch_and_poc_cleanup() -> None:
    assert not ScanOrchestrator._adb_command_destroys_target_data(
        ["shell", "am", "start", "-n", "com.example.target/.MainActivity"],
        package_name="com.example.target",
    )
    assert not ScanOrchestrator._adb_command_destroys_target_data(
        ["uninstall", "io.apkscanner.runtime.poc.zipprobe"],
        package_name="com.example.target",
    )


def test_adaptive_adb_maps_relative_host_files_into_the_verifier_workspace(
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "verifier"
    workspace.mkdir()

    assert ScanOrchestrator._translate_adaptive_adb_paths(
        ["pull", "/data/app/example/base.apk", "probe.apk"],
        container_workspace="/agent-workspaces/task-verifier/workspace",
        host_workspace=workspace,
    ) == ["pull", "/data/app/example/base.apk", str(workspace / "probe.apk")]
    assert ScanOrchestrator._translate_adaptive_adb_paths(
        ["pull", "/data/local/tmp/result.json"],
        container_workspace="/agent-workspaces/task-verifier/workspace",
        host_workspace=workspace,
    ) == ["pull", "/data/local/tmp/result.json", str(workspace / "result.json")]
    assert ScanOrchestrator._translate_adaptive_adb_paths(
        ["install", "-r", "poc/test.apk"],
        container_workspace="/agent-workspaces/task-verifier/workspace",
        host_workspace=workspace,
    ) == ["install", "-r", str(workspace / "poc/test.apk")]

    with pytest.raises(ValueError, match="escapes the verifier workspace"):
        ScanOrchestrator._translate_adaptive_adb_paths(
            ["pull", "/data/app/example/base.apk", "../probe.apk"],
            container_workspace="/agent-workspaces/task-verifier/workspace",
            host_workspace=workspace,
        )


def test_adaptive_gateway_replaces_only_a_stale_apkscanner_poc(
    settings,
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    workspace = tmp_path / "verifier"
    workspace.mkdir()
    (workspace / "poc.apk").write_bytes(b"apk")
    recorded: list[tuple[str, CommandResult, dict]] = []

    class RetryDevice:
        serial = "device-1"
        calls: list[list[str]] = []

        @classmethod
        def execute_gateway(cls, args, **_kwargs):  # noqa: ANN001, ANN206
            cls.calls.append(args)
            if len(cls.calls) == 1:
                return CommandResult(
                    ["adb", *args],
                    1,
                    "Performing Streamed Install",
                    (
                        "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Existing package "
                        "io.apkscanner.runtime.poc.compat signatures do not match newer version]"
                    ),
                )
            return CommandResult(["adb", *args], 0, "Success\n", "")

    monkeypatch.setattr(
        orchestrator,
        "_record_commands",
        lambda _scan_id, _task_id, commands, _summaries: recorded.extend(commands),
    )
    monkeypatch.setattr(orchestrator, "_materialize_live_evidence", lambda *_args: None)
    monkeypatch.setattr(orchestrator, "_record_exploration_event", lambda *_args: None)
    context = _LiveProofContext(
        token="gateway-token",
        scan_id="scan-1",
        task_id="task-1",
        package_name="com.example.target",
        workspace=workspace,
        entries=[],
        default_entry_id="",
        hypotheses=[],
        budget=TimeBudget.from_seconds(30),
        evidence_summaries=[],
        cancel_event=threading.Event(),
        round_index=0,
        device=RetryDevice(),  # type: ignore[arg-type]
        adb_policy="adaptive",
        container_workspace="/agent-workspaces/task/workspace",
    )
    orchestrator._register_live_proof_context(context)

    try:
        response = orchestrator.execute_live_adb(
            "task-1",
            "gateway-token",
            AdbGatewayRequest(
                args=["install", "-r", "/agent-workspaces/task/workspace/poc.apk"],
                policy="adaptive",
            ),
        )
    finally:
        orchestrator.shutdown()

    assert response["exit_code"] == 0
    assert RetryDevice.calls == [
        ["install", "-r", str(workspace / "poc.apk")],
        ["uninstall", "io.apkscanner.runtime.poc.compat"],
        ["install", "-r", str(workspace / "poc.apk")],
    ]
    assert [kind for kind, _result, _metadata in recorded] == [
        "agent.adb.gateway",
        "agent.adb.gateway.poc_cleanup",
        "agent.adb.gateway.poc_install_retry",
    ]


def test_adaptive_gateway_treats_textual_am_start_error_as_failure() -> None:
    raw = CommandResult(
        ["adb", "shell", "am", "start"],
        0,
        "Starting: Intent { cmp=io.apkscanner.runtime.poc.compat/.MainActivity }",
        "Error type 3\nError: Activity class does not exist.\n",
    )

    normalized = ScanOrchestrator._normalize_adaptive_adb_result(
        ["shell", "am", "start", "-n", "io.apkscanner.runtime.poc.compat/.MainActivity"],
        raw,
    )

    assert normalized.exit_code == 1
    assert "component_not_found" in normalized.stderr


def test_device_listing_fills_verdict_contract_for_partial_capability(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(settings, adb_serial="offline-device:5555")
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    orchestrator = ScanOrchestrator(
        configured,
        database,
        ArtifactStore(configured),
    )
    adapter = orchestrator.device_pool.adapters[0]
    monkeypatch.setattr(
        adapter,
        "capability",
        lambda **_kwargs: {
            "available": False,
            "detail": "device offline",
        },
    )

    listed = orchestrator.list_adb_devices(probe=True)

    assert len(listed) == 1
    validated = AdbDeviceOut.model_validate(listed[0])
    assert validated.available is False
    assert validated.android16_verdict_eligible is False
    assert validated.dynamic_verdict_eligible is False
    assert validated.verdict_scope == "unavailable"


def test_adaptive_verifier_batches_high_value_static_findings_once(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_enabled=True,
        adaptive_verifier_enabled=True,
        adaptive_verifier_min_severity="high",
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="adaptive.apk",
            package_name="com.example.adaptive",
            artifact_sha256="a" * 64,
            artifact_path=str(configured.data_dir / "adaptive.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="deep_link",
            name="adaptive://open/",
            owner_component="com.example.adaptive.WebActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        session.add_all(
            [
                Finding(
                    scan_id=scan.id,
                    dedupe_key="adaptive-high",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    title="JSB token leak",
                    description="Attacker HTML reaches a JavaScript bridge token source.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    confidence="high",
                    status="supported_static",
                    entry_point_ids=[entry.id],
                ),
                Finding(
                    scan_id=scan.id,
                    dedupe_key="adaptive-medium",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    title="Lower priority signal",
                    description="Not selected by the configured severity gate.",
                    masvs="MASVS-PLATFORM",
                    severity="medium",
                    confidence="medium",
                    status="supported_static",
                    entry_point_ids=[entry.id],
                ),
            ]
        )
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    dispatched: list[list[str]] = []

    def complete_batch(actual_scan_id: str, task_id: str, _cancel_event) -> None:  # noqa: ANN001
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            dispatched.append(list(task.preconditions["candidate_finding_ids"]))
            task.status = "completed"
            task.completed_at = datetime.now(UTC)
            session.commit()

    monkeypatch.setattr(orchestrator, "_run_adaptive_verifier_impl", complete_batch)
    orchestrator._run_adaptive_verifier(scan_id)

    with database.session_factory() as session:
        tasks = list(
            session.scalars(
                select(InvestigationTask).where(
                    InvestigationTask.scan_id == scan_id,
                    InvestigationTask.task_type == "adaptive_verification",
                )
            )
        )
        high = session.scalar(select(Finding).where(Finding.dedupe_key == "adaptive-high"))
        assert high is not None
        assert dispatched == [[high.id]]
        assert len(tasks) == 1
        assert tasks[0].target_entry_ids


def test_adaptive_verifier_splits_transport_safe_turns_and_merges_results(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_enabled=True,
        adaptive_verifier_enabled=True,
        adaptive_verifier_prompt_max_chars=25_000,
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="large-adaptive.apk",
            package_name="com.example.largeadaptive",
            artifact_sha256="a" * 64,
            artifact_path=str(configured.data_dir / "large-adaptive.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.largeadaptive.EntryActivity",
            owner_component="com.example.largeadaptive.EntryActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        findings = [
            Finding(
                scan=scan,
                dedupe_key=f"large-adaptive-{index}",
                rule_id="AGENT-ENTRY-INVESTIGATION",
                title=f"候选风险 {index}",
                description=(f"候选 {index} 的完整静态攻击链。" + "证据上下文" * 1500),
                masvs="MASVS-PLATFORM",
                severity="high",
                confidence="medium",
                status="supported_static",
                entry_point_ids=[entry.id],
            )
            for index in range(6)
        ]
        session.add_all(findings)
        session.flush()
        candidate_ids = [finding.id for finding in findings]
        task = InvestigationTask(
            scan=scan,
            task_type="adaptive_verification",
            status="running",
            priority=100,
            target_entry_ids=[entry.id],
            preconditions={"candidate_finding_ids": candidate_ids},
            attempts=1,
            started_at=datetime.now(UTC),
        )
        session.add(task)
        session.commit()
        scan_id = scan.id
        task_id = task.id

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    monkeypatch.setattr(
        orchestrator.codex,
        "capability",
        lambda *, deep=False: {"available": True, "deep": deep},
    )
    monkeypatch.setattr(
        orchestrator,
        "_target_code_context",
        lambda _scan_id, _entries: {
            "schema_version": "1.0",
            "global_decompilation": {"status": "complete"},
            "components": [],
        },
    )

    def materialize(_scan_id, actual_task_id, attempt, summaries, *, platform_context=None):  # noqa: ANN001, ANN202
        root = configured.data_dir / "adaptive-test-workspace" / actual_task_id / str(attempt)
        root.mkdir(parents=True, exist_ok=True)
        (root / "context.json").write_text(
            json.dumps(
                {
                    "evidence": summaries,
                    "platform_context": platform_context or {},
                }
            ),
            encoding="utf-8",
        )
        return root

    monkeypatch.setattr(orchestrator, "_materialize_agent_evidence", materialize)
    monkeypatch.setattr(
        orchestrator.codex,
        "prepare_session_workspace",
        lambda **kwargs: kwargs["workspace"],
    )
    closed_batch_threads: list[tuple[str, str, int, str]] = []
    monkeypatch.setattr(
        orchestrator.codex,
        "close_task_role",
        lambda scan_id, task_id, attempt, role: closed_batch_threads.append(
            (scan_id, task_id, attempt, role)
        ),
    )
    dispatched: list[dict[str, object]] = []

    def verify_batch(**kwargs):  # noqa: ANN003, ANN202
        prompt = kwargs["prompt"]
        payload = json.loads(prompt.split("ADAPTIVE_VERIFICATION_CONTEXT_JSON:\n", 1)[1])
        batch_ids = [item["finding_id"] for item in payload["candidates"]]
        dispatched.append(
            {
                "prompt_characters": len(prompt),
                "candidate_ids": batch_ids,
            }
        )
        batch_number = len(dispatched)
        return SimpleNamespace(
            thread_id=f"thread-budgeted-adaptive-{batch_number}",
            turn_id=f"turn-{batch_number}",
            usage={"input_tokens": 1, "output_tokens": 1},
            result=AdaptiveVerificationResult.model_validate(
                {
                    "summary": f"第 {batch_number} 批候选已完成语义检查。",
                    "assessments": [
                        {
                            "finding_id": finding_id,
                            "verdict": "supported_static",
                            "confidence": "medium",
                            "runtime_observed": False,
                            "summary": "静态攻击链仍成立，但当前没有足够运行态证据。",
                            "attack_chain": "exported entry -> sensitive sink",
                            "security_impact": "需要进一步真机证明。",
                            "counterevidence": [],
                            "remaining_gaps": ["缺少运行态危害观测。"],
                            "evidence_ids": [],
                            "experiments": [],
                        }
                        for finding_id in batch_ids
                    ],
                    "shared_observations": [],
                    "cleanup_actions": [],
                    "coverage_gaps": [],
                }
            ),
        )

    monkeypatch.setattr(orchestrator.codex, "verify_batch", verify_batch)

    orchestrator._run_adaptive_verifier_impl(scan_id, task_id, threading.Event())

    assert len(dispatched) > 1
    assert all(
        int(item["prompt_characters"]) <= configured.adaptive_verifier_prompt_max_chars
        for item in dispatched
    )
    assert [
        finding_id for item in dispatched for finding_id in item["candidate_ids"]
    ] == candidate_ids
    assert len(closed_batch_threads) == len(dispatched) - 1
    assert all(item[3] == "verifier" for item in closed_batch_threads)
    with database.session_factory() as session:
        completed = session.get(InvestigationTask, task_id)
        persisted_scan = session.get(Scan, scan_id)
        persisted_findings = list(
            session.scalars(select(Finding).where(Finding.id.in_(candidate_ids)))
        )
        assert completed is not None and persisted_scan is not None
        assert completed.status == "completed"
        assert len(completed.result["adaptive_batches"]) == len(dispatched)
        assert len(completed.result["response_evidence_ids"]) == len(dispatched)
        assert persisted_scan.stats["adaptive_verification"]["batch_count"] == len(dispatched)
        assert {finding.status for finding in persisted_findings} == {"supported_static"}
        assert all(finding.evidence_ids for finding in persisted_findings)
        assert {
            finding.metadata_json["adaptive_verification"]["thread_id"]
            for finding in persisted_findings
        } == {f"thread-budgeted-adaptive-{index}" for index in range(1, len(dispatched) + 1)}
        checkpoint_count = len(
            list(
                session.scalars(
                    select(AdaptiveVerificationCheckpoint).where(
                        AdaptiveVerificationCheckpoint.task_id == task_id
                    )
                )
            )
        )
        assert checkpoint_count == len(candidate_ids)
        completed.status = "running"
        completed.attempts += 1
        completed.completed_at = None
        session.commit()

    dispatch_count = len(dispatched)
    orchestrator._run_adaptive_verifier_impl(scan_id, task_id, threading.Event())
    assert len(dispatched) == dispatch_count
    with database.session_factory() as session:
        resumed = session.get(InvestigationTask, task_id)
        assert resumed is not None
        assert resumed.status == "completed"
        assert {item["status"] for item in resumed.result["adaptive_batches"]} == {
            "restored_checkpoint"
        }


def test_adaptive_verifier_automatically_resumes_only_missing_candidates(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_enabled=True,
        adaptive_verifier_enabled=True,
        adaptive_verifier_resume_attempts=1,
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="adaptive-resume.apk",
            package_name="com.example.adaptiveresume",
            artifact_sha256="7" * 64,
            artifact_path=str(configured.data_dir / "adaptive-resume.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.adaptiveresume.EntryActivity",
            exported=True,
        )
        session.add_all([scan, entry])
        session.flush()
        findings = [
            Finding(
                scan=scan,
                dedupe_key=f"adaptive-resume-{index}",
                rule_id="AGENT-ENTRY-INVESTIGATION",
                title=f"待验证风险 {index}",
                description="Static chain requires a terminal runtime assessment.",
                masvs="MASVS-PLATFORM",
                severity="high",
                confidence="medium",
                status="supported_static",
                entry_point_ids=[entry.id],
            )
            for index in range(2)
        ]
        session.add_all(findings)
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    calls: list[int] = []

    def run_pass(_scan_id: str, task_id: str, _cancel_event) -> None:  # noqa: ANN001
        calls.append(len(calls) + 1)
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            candidate_ids = list(task.preconditions["candidate_finding_ids"])
            if len(calls) == 1:
                response = orchestrator.evidence.json(
                    session,
                    scan_id=scan_id,
                    task_id=task_id,
                    kind="agent.response",
                    value={"assessment": candidate_ids[0]},
                    summary="First candidate assessment",
                )
                session.add(
                    AdaptiveVerificationCheckpoint(
                        scan_id=scan_id,
                        task_id=task_id,
                        finding_id=candidate_ids[0],
                        batch_index=1,
                        audit_id="11111111-2222-4333-8444-555555555555",
                        response_evidence_id=response.id,
                        thread_id="thread-first",
                        turn_id="turn-first",
                        assessment_json={
                            "finding_id": candidate_ids[0],
                            "verdict": "supported_static",
                            "confidence": "medium",
                            "runtime_observed": False,
                            "summary": "First candidate is checkpointed.",
                        },
                    )
                )
                task.status = "inconclusive"
                task.result = {
                    "missing_candidate_assessments": [candidate_ids[1]],
                }
                task.completed_at = datetime.now(UTC)
            else:
                checkpoints = list(
                    session.scalars(
                        select(AdaptiveVerificationCheckpoint).where(
                            AdaptiveVerificationCheckpoint.task_id == task_id
                        )
                    )
                )
                assert [item.finding_id for item in checkpoints] == [candidate_ids[0]]
                task.status = "completed"
                task.result = {
                    **dict(task.result or {}),
                    "missing_candidate_assessments": [],
                }
                task.completed_at = datetime.now(UTC)
            session.commit()

    monkeypatch.setattr(orchestrator, "_run_adaptive_verifier_impl", run_pass)
    orchestrator._run_adaptive_verifier(scan_id)

    assert calls == [1, 2]
    with database.session_factory() as session:
        task = session.scalar(
            select(InvestigationTask).where(
                InvestigationTask.scan_id == scan_id,
                InvestigationTask.task_type == "adaptive_verification",
            )
        )
        scan = session.get(Scan, scan_id)
        assert task is not None and scan is not None
        assert task.status == "completed"
        assert task.attempts == 2
        assert len(task.result["adaptive_resume_history"]) == 1
        assert task.result["adaptive_resume_history"][0]["checkpoint_count"] == 1
        assert scan.stats["adaptive_verification"]["restored_checkpoint_count"] == 1


@pytest.mark.parametrize(
    ("android16_eligible", "expected_status", "expected_backlog"),
    [
        (True, "supported_static", "proof_required"),
        (False, "supported_static", "proof_required"),
    ],
)
def test_adaptive_verifier_cannot_promote_without_platform_proof_attempt(
    settings,  # noqa: ANN001
    android16_eligible: bool,
    expected_status: str,
    expected_backlog: str,
) -> None:
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    orchestrator = ScanOrchestrator(settings, database, store)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="semantic.apk",
            package_name="com.example.semantic",
            artifact_sha256="b" * 64,
            artifact_path=str(settings.data_dir / "semantic.apk"),
        )
        finding = Finding(
            scan=scan,
            dedupe_key="semantic-jsb",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="JSB credential exposure",
            description="Static bridge chain",
            masvs="MASVS-PLATFORM",
            severity="high",
            confidence="medium",
            status="supported_static",
            metadata_json={"proof_backlog": {"status": "proof_required"}},
        )
        task = InvestigationTask(
            scan=scan,
            task_type="adaptive_verification",
            status="running",
        )
        session.add_all([scan, finding, task])
        session.flush()
        response = orchestrator.evidence.json(
            session,
            scan_id=scan.id,
            task_id=task.id,
            kind="agent.adaptive_response",
            value={"observed": "token from target bridge"},
            summary="Adaptive response",
        )
        session.commit()
        scan_id = scan.id
        task_id = task.id
        finding_id = finding.id
        response_id = response.id

    result = AdaptiveVerificationResult.model_validate(
        {
            "summary": "高权限 Agent 在真实 WebView 中取得目标 Bridge 返回的账号令牌。",
            "assessments": [
                {
                    "finding_id": finding_id,
                    "verdict": "reproduced_blackbox",
                    "confidence": "high",
                    "runtime_observed": True,
                    "summary": "恶意页面调用 Bridge 后把目标进程返回值发送到测试服务器。",
                    "attack_chain": "Deep Link -> WebView -> JSB -> token -> remote callback",
                    "security_impact": "普通第三方应用可诱导泄露当前账号凭据。",
                    "counterevidence": [],
                    "remaining_gaps": [],
                    "evidence_ids": [],
                    "experiments": [
                        {
                            "objective": "验证攻击者页面能否取得 Bridge token",
                            "actions": ["部署 HTML", "触发 Deep Link", "读取回调日志"],
                            "observations": ["回调日志收到目标进程产生的 token"],
                            "artifact_paths": ["output/jsb-callback.log"],
                            "conclusion": "运行结果支持凭据泄露。",
                        }
                    ],
                }
            ],
            "shared_observations": [],
            "cleanup_actions": [],
            "coverage_gaps": [],
        }
    )
    orchestrator._apply_adaptive_verifier_result(
        scan_id=scan_id,
        task_id=task_id,
        candidate_ids=[finding_id],
        result=result,
        thread_id="thread-adaptive",
        turn_id="turn-adaptive",
        response_evidence_id=response_id,
        android16_verdict_eligible=android16_eligible,
    )

    with database.session_factory() as session:
        finding = session.get(Finding, finding_id)
        task = session.get(InvestigationTask, task_id)
        scan = session.get(Scan, scan_id)
        assert finding is not None and task is not None and scan is not None
        assert finding.status == expected_status
        assert finding.confidence == "high"
        assert response_id in finding.evidence_ids
        assert finding.metadata_json["verification_mode"] == "adaptive_agent"
        assert finding.metadata_json["proof_backlog"]["status"] == expected_backlog
        assert finding.metadata_json["harm_demonstrated"] is False
        verification = finding.metadata_json["adaptive_verification"]
        assert verification["model_verdict"] == "reproduced_blackbox"
        assert verification["verdict"] == "supported_static"
        assert "ProofAttempt" in verification["verdict_override_reason"]
        assert verification["android16_verdict_eligible"] is android16_eligible
        assert task.status == "completed"
        assert task.thread_id == "thread-adaptive"
        assert scan.stats["adaptive_verification"]["verdict_counts"] == {expected_status: 1}
        assert scan.stats["adaptive_verification"]["compatibility_override_count"] == 1


def test_adaptive_verifier_preserves_an_existing_platform_proof(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="proof-preserved.apk",
            package_name="com.example.proofpreserved",
            artifact_sha256="c" * 64,
            artifact_path=str(settings.data_dir / "proof-preserved.apk"),
        )
        source_task = InvestigationTask(scan=scan, task_type="component", status="completed")
        verifier_task = InvestigationTask(
            scan=scan,
            task_type="adaptive_verification",
            status="running",
        )
        session.add_all([scan, source_task, verifier_task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=source_task.id,
            fingerprint="7" * 64,
            category="android.webview",
            claim="An attacker page receives the target account token.",
        )
        proof_evidence = Evidence(
            scan_id=scan.id,
            task_id=source_task.id,
            kind="blackbox.poc_ui_dump",
            sha256="8" * 64,
            path="proof.json",
            summary="Platform Oracle observed token disclosure",
        )
        session.add_all([hypothesis, proof_evidence])
        session.flush()
        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=source_task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="proof-preserved",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
            oracle={"release_gate_eligible": True},
        )
        finding = Finding(
            scan=scan,
            dedupe_key="proof-preserved",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="Account token disclosure",
            description="Platform proof already exists.",
            masvs="MASVS-PLATFORM",
            severity="critical",
            confidence="high",
            status="reproduced_blackbox",
            evidence_ids=[proof_evidence.id],
        )
        session.add_all([proof, finding])
        session.flush()
        finding.metadata_json = {
            "hypothesis_id": hypothesis.id,
            "proof_attempt_ids": [proof.id],
            "harm_demonstrated": True,
        }
        response = orchestrator.evidence.json(
            session,
            scan_id=scan.id,
            task_id=verifier_task.id,
            kind="agent.adaptive_response",
            value={"assessment": "model attempted downgrade"},
            summary="Adaptive response",
        )
        session.commit()
        scan_id = scan.id
        task_id = verifier_task.id
        finding_id = finding.id
        proof_id = proof.id
        proof_evidence_id = proof_evidence.id
        response_id = response.id

    result = AdaptiveVerificationResult.model_validate(
        {
            "summary": "模型未能重新观察到此前的平台证明。",
            "assessments": [
                {
                    "finding_id": finding_id,
                    "verdict": "supported_static",
                    "confidence": "medium",
                    "runtime_observed": False,
                    "summary": "本轮未重新观察到影响。",
                    "attack_chain": "Deep Link -> WebView -> bridge",
                    "security_impact": "Existing platform receipt remains authoritative.",
                }
            ],
        }
    )
    orchestrator._apply_adaptive_verifier_result(
        scan_id=scan_id,
        task_id=task_id,
        candidate_ids=[finding_id],
        result=result,
        thread_id="thread-proof-preserved",
        turn_id="turn-proof-preserved",
        response_evidence_id=response_id,
        android16_verdict_eligible=True,
    )

    with database.session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "reproduced_blackbox"
        assert finding.metadata_json["harm_demonstrated"] is True
        assert finding.metadata_json["proof_attempt_ids"] == [proof_id]
        assert proof_evidence_id in finding.evidence_ids
        assert (
            "cannot downgrade"
            in (finding.metadata_json["adaptive_verification"]["verdict_override_reason"])
        )


def test_exact_finding_identity_is_consolidated_across_tasks(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="duplicates.apk",
            package_name="com.example.duplicates",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "duplicates.apk"),
        )
        first_task = InvestigationTask(scan=scan, task_type="component", status="completed")
        second_task = InvestigationTask(scan=scan, task_type="static_review", status="completed")
        first_entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.duplicates.BridgeActivity",
            exported=True,
        )
        second_entry = EntryPoint(
            scan=scan,
            kind="static_surface",
            name="static://web_content_boundary",
            exported=False,
        )
        session.add_all([scan, first_task, second_task, first_entry, second_entry])
        session.flush()
        first_evidence = Evidence(
            scan_id=scan.id,
            task_id=first_task.id,
            kind="blackbox.poc_ui_dump",
            sha256="1" * 64,
            path="first.json",
            summary="Bridge token reached the attacker page",
        )
        second_evidence = Evidence(
            scan_id=scan.id,
            task_id=second_task.id,
            kind="static.jadx",
            sha256="2" * 64,
            path="second.json",
            summary="Static WebView bridge chain",
        )
        session.add_all([first_evidence, second_evidence])
        session.flush()
        shared_identity = {
            "schema_version": "1.0",
            "finding_id": "f" * 64,
            "semantic_fingerprint": "f" * 64,
            "occurrence_id": "e" * 64,
        }
        first_finding = Finding(
            scan=scan,
            dedupe_key=f"agent:{first_task.id}:hypothesis:first",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="codex",
            title="AccountBridge token disclosure",
            description="Runtime proof",
            remediation="Restrict the bridge and trusted origins.",
            masvs="MASVS-PLATFORM",
            severity="critical",
            confidence="high",
            status="reproduced_blackbox",
            entry_point_ids=[first_entry.id],
            evidence_ids=[first_evidence.id],
            metadata_json={
                "identity": shared_identity,
                "harm_demonstrated": True,
                "task_id": first_task.id,
            },
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        second_finding = Finding(
            scan=scan,
            dedupe_key=f"agent:{second_task.id}:supported_static",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="codex",
            title="Web content boundary reaches AccountBridge",
            description="Static proof",
            remediation="Restrict the bridge and trusted origins.",
            masvs="MASVS-PLATFORM",
            severity="high",
            confidence="medium",
            status="supported_static",
            entry_point_ids=[second_entry.id],
            evidence_ids=[second_evidence.id],
            metadata_json={
                "identity": shared_identity,
                "harm_demonstrated": False,
                "task_id": second_task.id,
            },
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        )
        session.add_all([first_finding, second_finding])
        session.flush()
        first_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=first_task.id,
            fingerprint="4" * 64,
            category="android.webview",
            claim="Runtime ingress reaches AccountBridge token disclosure",
            final_finding_id=first_finding.id,
        )
        session.add(first_hypothesis)
        session.flush()
        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=first_task.id,
            hypothesis_id=first_hypothesis.id,
            test_case_id="bridge-proof",
            status="proven",
            evidence_ids=[first_evidence.id],
            harm_demonstrated=True,
            oracle={"release_gate_eligible": True},
        )
        session.add(proof)
        session.flush()
        first_finding.metadata_json = {
            **first_finding.metadata_json,
            "hypothesis_id": first_hypothesis.id,
            "proof_attempt_ids": [proof.id],
        }
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=second_task.id,
            fingerprint="3" * 64,
            category="android.webview",
            claim="Static ingress reaches the same AccountBridge sink",
            final_finding_id=second_finding.id,
        )
        session.add(hypothesis)
        session.flush()

        merged = orchestrator._consolidate_findings(session, scan_id=scan.id)
        session.flush()

        assert merged == {second_finding.id: first_finding.id}
        assert first_finding.status == "reproduced_blackbox"
        assert first_finding.entry_point_ids == [first_entry.id, second_entry.id]
        assert first_finding.evidence_ids == [first_evidence.id, second_evidence.id]
        assert first_finding.metadata_json["harm_demonstrated"] is True
        assert second_finding.metadata_json["merged_into_finding_id"] == first_finding.id
        assert hypothesis.final_finding_id == first_finding.id
        records = list(session.scalars(select(Finding).where(Finding.scan_id == scan.id)))
        confirmed, signals = partition_findings(session, records)
        assert [item.id for item in confirmed] == [first_finding.id]
        assert signals == []


def test_same_task_hypotheses_sharing_one_platform_oracle_are_consolidated(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="binder.apk",
            package_name="com.example.binder",
            artifact_sha256="b" * 64,
            artifact_path=str(settings.data_dir / "binder.apk"),
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        entry = EntryPoint(
            scan=scan,
            kind="service",
            name="com.example.binder.SecretService",
            exported=True,
        )
        session.add_all([scan, task, entry])
        session.flush()
        reachability = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="1" * 64,
            category="android.exported_component",
            claim="A third-party application can bind to the service.",
            entry_point_ids=[entry.id],
        )
        impact = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="2" * 64,
            category="android.exported_component",
            claim="The exported service returns a native secret without caller authorization.",
            entry_point_ids=[entry.id],
        )
        session.add_all([reachability, impact])
        session.flush()
        shared_plan = {
            "entry_point_id": entry.id,
            "operation": "binder_transact",
            "binder_transaction_code": 1,
            "binder_interface_descriptor": None,
            "binder_reply_type": "long",
            "binder_script": None,
            "poc": None,
            "oracle": {
                "kind": "binder_reply",
                "impact": "unauthorized_data_access",
                "impact_contract_id": "builtin:binder_reply:unauthorized_data_access",
                "expected_text": "87109624524081870",
                "match_mode": "exact",
                "reply_index": 0,
                "target_path": None,
            },
        }
        first_proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=reachability.id,
            test_case_id="binder-reachability",
            status="proven",
            plan={**shared_plan, "hypothesis_id": reachability.id},
            harm_demonstrated=True,
        )
        second_proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=impact.id,
            test_case_id="binder-impact",
            status="proven",
            plan={**shared_plan, "hypothesis_id": impact.id},
            harm_demonstrated=True,
        )
        session.add_all([first_proof, second_proof])
        session.flush()
        first_finding = Finding(
            scan=scan,
            dedupe_key=f"agent:{task.id}:hypothesis:{reachability.id}",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="codex",
            title="Service is reachable",
            description="Reachability hypothesis",
            remediation="Restrict the service.",
            masvs="MASVS-PLATFORM",
            severity="high",
            confidence="high",
            status="reproduced_blackbox",
            entry_point_ids=[entry.id],
            metadata_json={
                "identity": {"finding_id": "3" * 64},
                "harm_demonstrated": True,
                "task_id": task.id,
                "hypothesis_id": reachability.id,
                "proof_attempt_ids": [first_proof.id],
            },
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        second_finding = Finding(
            scan=scan,
            dedupe_key=f"agent:{task.id}:hypothesis:{impact.id}",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="codex",
            title="Native Binder secret disclosure",
            description="Concrete unauthorized data access",
            remediation="Authorize the Binder caller.",
            masvs="MASVS-PLATFORM",
            severity="high",
            confidence="high",
            status="reproduced_blackbox",
            entry_point_ids=[entry.id],
            metadata_json={
                "identity": {"finding_id": "4" * 64},
                "harm_demonstrated": True,
                "task_id": task.id,
                "hypothesis_id": impact.id,
                "proof_attempt_ids": [second_proof.id],
            },
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        )
        session.add_all([first_finding, second_finding])
        session.flush()
        reachability.final_finding_id = first_finding.id
        impact.final_finding_id = second_finding.id

        merged = orchestrator._consolidate_findings(session, scan_id=scan.id)
        session.flush()

        assert merged == {first_finding.id: second_finding.id}
        assert second_finding.status == "reproduced_blackbox"
        assert second_finding.title == "Native Binder secret disclosure"
        assert first_finding.status == "inconclusive"
        assert first_finding.metadata_json["merge_basis"] == "shared_platform_proof_oracle"
        assert reachability.final_finding_id == second_finding.id
        assert impact.final_finding_id == second_finding.id


def test_adaptive_verifier_merges_semantic_duplicate_ingress_findings(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="semantic-duplicates.apk",
            package_name="com.example.semanticduplicates",
            artifact_sha256="4" * 64,
            artifact_path=str(settings.data_dir / "semantic-duplicates.apk"),
        )
        canonical = Finding(
            scan=scan,
            dedupe_key="component-bridge",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="Explicit Intent reaches AccountBridge",
            description="Component ingress",
            remediation="Restrict bridge origins.",
            masvs="MASVS-PLATFORM",
            severity="critical",
            confidence="medium",
            status="supported_static",
            metadata_json={"identity": {"finding_id": "5" * 64}},
        )
        duplicate = Finding(
            scan=scan,
            dedupe_key="deep-link-bridge",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="Deep Link reaches AccountBridge",
            description="Deep-link ingress",
            remediation="Restrict bridge origins.",
            masvs="MASVS-PLATFORM",
            severity="critical",
            confidence="medium",
            status="supported_static",
            metadata_json={"identity": {"finding_id": "6" * 64}},
        )
        task = InvestigationTask(scan=scan, task_type="adaptive_verification", status="running")
        session.add_all([scan, canonical, duplicate, task])
        session.flush()
        response = orchestrator.evidence.json(
            session,
            scan_id=scan.id,
            task_id=task.id,
            kind="agent.adaptive_response",
            value={"observed": "same AccountBridge token sink"},
            summary="Adaptive duplicate response",
        )
        session.commit()
        scan_id = scan.id
        task_id = task.id
        canonical_id = canonical.id
        duplicate_id = duplicate.id
        response_id = response.id

    result = AdaptiveVerificationResult.model_validate(
        {
            "summary": "两个入口到达同一个 AccountBridge token sink，合并为一个漏洞。",
            "assessments": [
                {
                    "finding_id": canonical_id,
                    "verdict": "reproduced_blackbox",
                    "confidence": "high",
                    "runtime_observed": True,
                    "summary": "恶意页面取得同一 token。",
                    "attack_chain": "Intent -> WebView -> AccountBridge.getSessionToken",
                    "security_impact": "会话令牌泄露。",
                },
                {
                    "finding_id": duplicate_id,
                    "duplicate_of_finding_id": canonical_id,
                    "verdict": "reproduced_blackbox",
                    "confidence": "high",
                    "runtime_observed": True,
                    "summary": "Deep Link 是同一 sink 的另一入口表述。",
                    "attack_chain": "Deep Link -> WebView -> AccountBridge.getSessionToken",
                    "security_impact": "会话令牌泄露。",
                },
            ],
        }
    )
    orchestrator._apply_adaptive_verifier_result(
        scan_id=scan_id,
        task_id=task_id,
        candidate_ids=[canonical_id, duplicate_id],
        result=result,
        thread_id="thread-duplicates",
        turn_id="turn-duplicates",
        response_evidence_id=response_id,
        android16_verdict_eligible=True,
    )

    with database.session_factory() as session:
        canonical = session.get(Finding, canonical_id)
        duplicate = session.get(Finding, duplicate_id)
        scan = session.get(Scan, scan_id)
        task = session.get(InvestigationTask, task_id)
        assert (
            canonical is not None
            and duplicate is not None
            and scan is not None
            and task is not None
        )
        assert canonical.status == "supported_static"
        assert canonical.metadata_json["harm_demonstrated"] is False
        assert duplicate.metadata_json["merged_into_finding_id"] == canonical_id
        assert task.result["merged_finding_map"] == {duplicate_id: canonical_id}
        assert scan.stats["adaptive_verification"]["verdict_counts"] == {"supported_static": 1}
        records = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        confirmed, signals = partition_findings(session, records)
        assert confirmed == []
        assert [item.id for item in signals] == [canonical_id]


def test_live_runtime_observation_is_persisted_and_deduplicated(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="observation.apk",
            package_name="com.example.observation",
            artifact_sha256="e" * 64,
            artifact_path="observation.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="running")
        session.add_all([scan, task])
        session.commit()
        scan_id = scan.id
        task_id = task.id
    workspace = settings.data_dir / "observation-context"
    workspace.mkdir()
    (workspace / "context.json").write_text('{"evidence": []}', encoding="utf-8")
    device = SimpleNamespace(
        serial="legacy-device",
        capability=lambda **_kwargs: {
            "api_level": "33",
            "dynamic_verdict_eligible": True,
            "release_gate_eligible": False,
            "verdict_scope": "development_legacy",
        },
    )
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    token = "observation-token"
    orchestrator._register_live_proof_context(
        SimpleNamespace(
            token=token,
            scan_id=scan_id,
            task_id=task_id,
            cancel_event=threading.Event(),
            device=device,
            evidence_summaries=[],
            workspace=workspace,
        )
    )
    payload = AgentRuntimeObservation(
        kind="webview.bridge.callback",
        source="webview_callback",
        payload={"canary": "APKSCANNER-CANARY", "returned_token": "runtime-value"},
    )
    first = orchestrator.record_live_runtime_observation(task_id, token, payload)
    second = orchestrator.record_live_runtime_observation(task_id, token, payload)
    assert first["deduplicated"] is False
    assert second["deduplicated"] is True
    assert second["id"] == first["id"]
    with database.session_factory() as session:
        observations = list(
            session.scalars(select(RuntimeObservation).where(RuntimeObservation.task_id == task_id))
        )
        assert len(observations) == 1
        assert observations[0].environment["validation"]["verdict_scope"] == ("development_legacy")


def test_runtime_event_projection_is_idempotent_across_spool_replay(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="events.apk",
            artifact_sha256="e" * 64,
            artifact_path=str(settings.data_dir / "events.apk"),
        )
        task = InvestigationTask(scan=scan, task_type="component", status="running")
        session.add_all([scan, task])
        session.commit()

    orchestrator = ScanOrchestrator(settings, database, store)
    live = AgentRuntimeEvent(
        event_type="model.turn.started",
        message="Codex 开始处理本轮探索",
        data={"turn_id": "turn-1"},
        session_id="task:a1:primary",
        protocol_stream_id="stream-1",
        worker_sequence=3,
        delivery_source="live",
        protocol_record_key="task:a1:primary:stream-1:event:3",
    )
    replayed = replace(live, delivery_source="spool_replay")

    assert orchestrator._record_agent_runtime_event(
        scan.id,
        task.id,
        live,
        phase="test_planning",
        round_index=0,
        agent_backend="codex",
    )
    assert not orchestrator._record_agent_runtime_event(
        scan.id,
        task.id,
        replayed,
        phase="test_planning",
        round_index=0,
        agent_backend="codex",
    )

    with database.session_factory() as session:
        records = list(session.scalars(select(AgentRuntimeEventRecord)))
        events = list(
            session.scalars(
                select(ScanEvent).where(ScanEvent.event_type == "exploration.model.turn.started")
            )
        )
    assert len(records) == len(events) == 1
    assert events[0].data["worker_sequence"] == 3
    orchestrator.shutdown()


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


def test_task_dispatch_honors_configured_analysis_slots(settings) -> None:  # noqa: ANN001
    configured = replace(settings, agent_analysis_slots=1)
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
                select(InvestigationTask.status).where(InvestigationTask.scan_id == scan_id)
            )
        )
    assert persisted_scan is not None
    assert persisted_scan.stats["execution_policy"] == {
        "concurrency_policy": "resource_aware_phase_admission",
        "investigation_concurrency_at_start": 1,
        "adb_concurrency": 0,
        "analysis_slots": 1,
        "build_slots": configured.poc_build_slots,
        "device_slots": 0,
        "device_ownership": "dynamic_execution_phase",
        "agent_workspace_scope": "task_attempt",
    }
    assert statuses == ["completed"] * 6


def test_analysis_dispatch_is_not_bounded_by_device_count(settings) -> None:  # noqa: ANN001
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

    assert max_active == configured.agent_analysis_slots
    with database.session_factory() as session:
        persisted_scan = session.get(Scan, scan_id)
        statuses = list(
            session.scalars(
                select(InvestigationTask.status).where(InvestigationTask.scan_id == scan_id)
            )
        )
    assert persisted_scan is not None
    assert persisted_scan.stats["execution_policy"] == {
        "concurrency_policy": "resource_aware_phase_admission",
        "investigation_concurrency_at_start": configured.agent_analysis_slots,
        "adb_concurrency": 2,
        "analysis_slots": configured.agent_analysis_slots,
        "build_slots": configured.poc_build_slots,
        "device_slots": 2,
        "device_ownership": "dynamic_execution_phase",
        "agent_workspace_scope": "task_attempt",
    }
    assert statuses == ["completed"] * 4


def test_paused_scan_does_not_claim_queued_tasks_until_resumed(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="preliminary_ready",
            filename="paused.apk",
            artifact_sha256="5" * 64,
            artifact_path=str(settings.data_dir / "paused.apk"),
            stats={"execution_control": {"state": "paused"}},
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
                for index in range(2)
            ]
        )
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    started = threading.Event()

    def fake_run_task(
        _scan_id: str,
        task_id: str,
        _timeout_seconds: int | None = None,
    ) -> None:
        started.set()
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            task.status = "completed"
            task.completed_at = datetime.now(UTC)
            session.commit()

    orchestrator._run_task = fake_run_task  # type: ignore[method-assign]
    worker = threading.Thread(target=orchestrator._run_tasks, args=(scan_id,))
    worker.start()
    assert not started.wait(timeout=0.8)
    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        scan.stats = {"execution_control": {"state": "running"}}
        session.commit()
    assert started.wait(timeout=3)
    worker.join(timeout=5)
    assert not worker.is_alive()
    with database.session_factory() as session:
        statuses = list(
            session.scalars(
                select(InvestigationTask.status).where(InvestigationTask.scan_id == scan_id)
            )
        )
    assert statuses == ["completed", "completed"]


def test_running_dispatch_expands_when_a_device_is_added(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="initial-device",
        adb_serials=("initial-device",),
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="preliminary_ready",
            filename="live-expand.apk",
            artifact_sha256="7" * 64,
            artifact_path=str(settings.data_dir / "live-expand.apk"),
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
                for index in range(3)
            ]
        )
        session.commit()
        scan_id = scan.id

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    first_started = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()
    active_lock = threading.Lock()
    active = 0

    def fake_run_task(
        _scan_id: str,
        task_id: str,
        _timeout_seconds: int | None = None,
    ) -> None:
        nonlocal active
        with active_lock:
            active += 1
            if active == 1:
                first_started.set()
            elif active == 2:
                second_started.set()
        if not second_started.is_set():
            assert release_first.wait(timeout=5)
        with database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            task.status = "completed"
            session.commit()
        with active_lock:
            active -= 1

    orchestrator._run_task = fake_run_task  # type: ignore[method-assign]
    worker = threading.Thread(target=orchestrator._run_tasks, args=(scan_id,))
    worker.start()
    assert first_started.wait(timeout=5)
    orchestrator.device_pool.add(
        AdbDeviceAdapter(
            replace(configured, adb_serial="live-device"),
            ToolRunner(),
            serial="live-device",
        )
    )
    assert second_started.wait(timeout=3)
    release_first.set()
    worker.join(timeout=5)
    assert not worker.is_alive()


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
    assert max_active == 2


def test_parallel_workers_share_only_one_device_session(settings) -> None:  # noqa: ANN001
    configured = replace(settings, adb_serial="device-a")
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
    assert orchestrator.device_pool.scheduler.snapshot() == {
        "capacity": 1,
        "active": {},
        "waiting": [],
    }
    with database.session_factory() as session:
        persisted = [session.get(InvestigationTask, task_id) for task_id in task_ids]
        assert all(task is not None and task.status == "running" for task in persisted)
        assert all(
            (task.result.get("device_queue") or {}).get("released_at")
            for task in persisted
            if task is not None
        )


def test_device_task_leases_only_for_dynamic_execution(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="exclusive-device:5555",
        codex_enabled=True,
        rescue_audit_sample_rate=0.0,
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
        assert orchestrator.device_pool.scheduler.snapshot()["active"] == {
            "exclusive-device:5555": task_id
        }
        timeline.append("cleanup")
        return []

    monkeypatch.setattr(orchestrator.device, "cleanup", cleanup)
    monkeypatch.setattr(
        orchestrator,
        "_validated_agent_payload",
        lambda payload, _evidence: (payload, "refuted_static"),
    )
    monkeypatch.setattr(orchestrator, "_needs_adversarial_review", lambda _result: False)
    monkeypatch.setattr(orchestrator, "_needs_rescue_review", lambda _result: False)

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**_kwargs):  # noqa: ANN003, ANN205
            assert orchestrator.device_pool.scheduler.snapshot()["active"] == {}
            device_context = _kwargs["platform_context"]["device"]
            assert device_context["available"] is True
            assert device_context.get("lease_owned_by_current_task") is not True
            timeline.append(f"agent:{device_context.get('lease_completed_by_current_task', False)}")
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

    assert timeline == ["agent:False"]
    assert orchestrator.device_pool.scheduler.snapshot()["active"] == {}
    assert orchestrator.device_pool.scheduler.snapshot() == {
        "capacity": 1,
        "active": {},
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
        rescue_audit_sample_rate=0.0,
        agent_initial_phase_seconds=91,
        agent_exploration_phase_seconds=73,
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
    dispatch_timeouts: list[int | None] = []

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            context = kwargs["platform_context"]
            phase = context["phase"]
            phases.append(phase)
            dispatch_timeouts.append(kwargs.get("timeout_seconds"))
            assert context["exploration_policy"] == {
                "mode": "agent_directed",
                "count_limits": False,
                "termination": [
                    "agent_reports_no_material_followup",
                    "all_hypotheses_proven",
                    "task_cancelled",
                    "task_lifecycle_deadline",
                ],
            }
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
                planning = next(item for item in history if item["phase"] == "test_planning")
                validation = planning["test_validation"]
                assert len(validation["submitted"]) == 1
                assert validation["accepted"] == []
                assert validation["executed"] == []
                if rejection_mode == "platform_policy":
                    assert validation["model_rejected"] == []
                    assert any("outside this task" in gap for gap in validation["gaps"])
                else:
                    assert len(validation["model_rejected"]) == 1
                    assert validation["model_rejected"][0]["request"]["method"] == (
                        "bindOrTransact"
                    )
                    assert any(
                        "schema validation failed" in gap and "only valid for provider call" in gap
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
    orchestrator._run_task(scan_id, task_id, 3600)

    assert phases == ["test_planning", "exploration_round"]
    assert dispatch_timeouts == [91, 73]
    with database.session_factory() as session:
        completed_task = session.get(InvestigationTask, task_id)
        assert completed_task is not None
        history = completed_task.result["platform_context"]["agent_round_history"]
        assert [item["phase"] for item in history] == [
            "test_planning",
            "exploration_round",
        ]
        assert history[0]["test_validation"]["accepted"] == []
        if rejection_mode == "model_schema":
            assert len(history[0]["model_validation"]["rejected_requested_tests"]) == 1


def test_agent_generated_poc_is_built_from_the_docker_session_workspace(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="runtime-workspace-device:5555",
        codex_enabled=True,
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="runtime-workspace.apk",
            package_name="com.example.runtime",
            artifact_sha256="7" * 64,
            artifact_path=str(configured.data_dir / "runtime-workspace.apk"),
            stats={"investigator": "codex"},
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.runtime.MainActivity",
            owner_component="com.example.runtime.MainActivity",
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

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
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
            ("device.install", CommandResult(["adb", "install"], 0, "", ""), {})
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
        lambda payload, _evidence: (payload, "needs_dynamic_proof"),
    )

    runtime_workspace = configured.data_dir / "agent-sessions" / "runtime-workspace"
    captured_build_workspaces = []

    class FakeInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def prepare_session_workspace(**_kwargs):  # noqa: ANN003, ANN205
            runtime_workspace.mkdir(parents=True, exist_ok=True)
            return runtime_workspace

        @staticmethod
        def investigate(**kwargs):  # noqa: ANN003, ANN205
            context = kwargs["platform_context"]
            hypothesis_id = context["security_hypotheses"][0]["id"]
            requested_tests = []
            if context["phase"] == "test_planning":
                generated = runtime_workspace / "poc" / "generated"
                generated.mkdir(parents=True, exist_ok=True)
                (generated / "written-by-agent.txt").write_text("present", encoding="utf-8")
                requested_tests = [
                    {
                        "hypothesis_id": hypothesis_id,
                        "entry_point_id": entry_id,
                        "state": "guest",
                        "uri": None,
                        "extras": {},
                        "operation": "auto",
                        "oracle": {
                            "kind": "log_contains",
                            "expected_text": "security_impact_observed",
                            "impact": "privileged_action",
                        },
                        "rationale": "Use the PoC generated in the writable session.",
                        "poc": {
                            "project_path": "poc/generated",
                            "package_name": "io.apkscanner.runtime.poc.runtime",
                            "launch_component": ".MainActivity",
                            "log_tag": "APKSCANNER_POC",
                            "timeout_seconds": 30,
                        },
                    }
                ]
            return SimpleNamespace(
                thread_id="thread-runtime",
                turn_id=f"turn-{context['phase']}",
                usage={"input_tokens": 1, "output_tokens": 1},
                result=AgentInvestigationResult(
                    summary="已检查隔离工作区中的动态验证项目。",
                    result="supported_static",
                    hypotheses_tested=[hypothesis_id],
                    test_cases=[],
                    evidence_ids=[],
                    severity_proposal="info",
                    confidence="low",
                    coverage_gaps=[],
                    followups=[],
                    requested_tests=requested_tests,
                ),
            )

    def capture_build(*, workspace, **_kwargs):  # noqa: ANN001, ANN202
        captured_build_workspaces.append(workspace)
        assert (workspace / "poc" / "generated" / "written-by-agent.txt").is_file()
        return [], {}, ["capture-only build"]

    orchestrator.investigators["codex"] = FakeInvestigator()
    monkeypatch.setattr(orchestrator, "_build_requested_pocs", capture_build)
    orchestrator._run_task(scan_id, task_id, 120)

    assert captured_build_workspaces == [runtime_workspace]


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
            priority=100,
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
                        "reachable_path": ("EntryActivity -> RouteHelper -> InternalDispatcher"),
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
                assert context["blind_rescue"]["prior_model_conclusion_withheld"] is True
            if phase == "rescue_exploration":
                assert context["rescue"]["strategy"]["result"] == "supported_static"
                assert context["rescue"]["prior_model_conclusion_withheld_during_review"] is True
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
                    severity_proposal=("high" if result == "supported_static" else "info"),
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
            session.scalars(select(HypothesisArgument).where(HypothesisArgument.task_id == task_id))
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
        rescue_audit_sample_rate=0.0,
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
                    "schema_version": "1.0",
                    "global_decompilation": {"status": "index_unavailable"},
                    "components": [],
                }
                assert context["critic_scope"] == {
                    "mode": "candidate_and_cited_evidence_only",
                    "evidence_ids": [cited_id],
                    "bounded_source_recheck_allowed": True,
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
                        result=("refuted_static" if critic_objects else "supported_static"),
                        hypotheses_tested=[],
                        hypothesis_assessments=[],
                        review_objections=objections,
                        objection_resolutions=[],
                        test_cases=[],
                        evidence_ids=[cited_id],
                        severity_proposal=("info" if critic_objects else "high"),
                        confidence="high",
                        coverage_gaps=[],
                        followups=[],
                        requested_tests=[],
                    ),
                )
            if phase == "final_evaluation":
                assert critic_objects
                assert (
                    context["debate"]["critic"]["review_objections"][0]["objection_id"] == "OBJ-1"
                )
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
            if phase == "rescue_review":
                assert critic_objects
                assert context["blind_rescue"] == {
                    "mode": "independent_negative_closure_review",
                    "prior_model_conclusion_withheld": True,
                }
                assert context["candidate_under_review"] is None
                return SimpleNamespace(
                    thread_id="thread-rescue",
                    turn_id="turn-rescue",
                    usage={"input_tokens": 1, "output_tokens": 1},
                    result=AgentInvestigationResult(
                        summary="盲审独立确认当前证据没有敏感操作链。",
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
                                "counterevidence": ["Independent review found no sensitive sink"],
                                "proof_gaps": [],
                                "evidence_ids": [cited_id],
                                "confidence": "high",
                            }
                        ],
                        review_objections=[],
                        objection_resolutions=[],
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
        [
            "test_planning",
            "adversarial_review",
            "final_evaluation",
        ]
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
        assert policy["phase_counts"].get("final_evaluation", 0) == int(critic_objects)
        assert policy["outcome"] == (
            "arbiter_completed" if critic_objects else "candidate_kept_without_arbiter"
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
        '<manifest package="example"><application /></manifest>',
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
    assert first_context["workspace_policy"]["decompiled_roots"] == {
        "container": ["/scan-input/jadx"]
    }
    assert first_context["evidence"][0]["artifact"] == (f"evidence/{evidence.id}.json")
    assert (first / first_context["evidence"][0]["artifact"]).is_file()
    materialized = "target_source/jadx/sources/example/ExportedProvider.java"
    assert (first / materialized).read_text(encoding="utf-8") == ("class ExportedProvider {}")
    assert (
        first_context["platform_context"]["target_code_context"]["components"][0]["anchors"][0][
            "materialized_path"
        ]
        == materialized
    )
    manifest_payload = json.loads((first / "context-manifest.json").read_text(encoding="utf-8"))
    assert manifest_payload["read_order"] == ["stable", "evidence", "latest_round"]
    for document in manifest_payload["documents"].values():
        content = (first / document["path"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == document["sha256"]
    stable_digest = manifest_payload["documents"]["stable"]["sha256"]
    next_context = context()
    next_context.update({"phase": "exploration_round", "round_index": 1})
    orchestrator._materialize_agent_evidence(
        scan_id,
        first_task_id,
        1,
        [dict(evidence_summary)],
        platform_context=next_context,
    )
    next_manifest = json.loads((first / "context-manifest.json").read_text(encoding="utf-8"))
    assert next_manifest["documents"]["stable"]["sha256"] == stable_digest
    assert next_manifest["documents"]["latest_round"]["path"] == (
        "rounds/001-exploration-round.json"
    )
    assert (first / "rounds/000-test-planning.json").is_file()

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
    bounded_context = json.loads((bounded / "context.json").read_text(encoding="utf-8"))
    assert bounded.is_relative_to(settings.data_dir / "agent_context" / scan_id)
    assert not bounded.is_relative_to(settings.data_dir / "workspaces" / scan_id)
    assert bounded_context["workspace_policy"]["shared_scan_workspace_exposed"] is True
    assert bounded_context["workspace_policy"]["decompiled_roots"] == {
        "container": ["/scan-input/jadx"],
    }
    assert (bounded / materialized).is_file()
    assert (
        bounded_context["platform_context"]["bounded_manifest_path"]
        == "target_source/AndroidManifest.xml"
    )
    assert bounded_context["platform_context"]["bounded_manifest"]["package_name"] == ("example")
    assert (bounded / "target_source/AndroidManifest.xml").is_file()

    native_root = settings.data_dir / "workspaces" / scan_id / "native"
    native_root.mkdir()
    (native_root / "libdemo.so").write_bytes(b"ELF-test-placeholder")
    ida_settings = replace(settings, ida_mcp_enabled=True)
    ida_orchestrator = ScanOrchestrator(ida_settings, database, store)
    ida_workspace = ida_orchestrator._materialize_agent_evidence(
        scan_id,
        "00000000-0000-0000-0000-000000000074",
        1,
        [dict(evidence_summary)],
        platform_context=context(),
    )
    ida_context = json.loads((ida_workspace / "context.json").read_text(encoding="utf-8"))
    ida_mcp = ida_context["workspace_policy"]["ida_mcp"]
    assert ida_mcp["available"] is True
    assert ida_mcp["server"] == "ida-headless"
    assert {
        "container_prefix": "/scan-input/native",
        "host_prefix": str(native_root.resolve()),
    } in ida_mcp["path_mappings"]


def test_end_to_end_static_scan_reaches_final_with_explicit_dynamic_gaps(
    settings, fixture_apk
) -> None:  # noqa: ANN001
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
    with pytest.raises(ValueError, match="codex"):
        orchestrator.resolve_investigator("opencode")
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
        entries = list(session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan_id)))
        assert len(entries) == 9
        assert sum(entry.kind == "static_surface" for entry in entries) == 1
        findings = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        assert len(findings) >= 5
        assert all(finding.metadata_json["identity"]["finding_id"] for finding in findings)
        tasks = list(
            session.scalars(select(InvestigationTask).where(InvestigationTask.scan_id == scan_id))
        )
        assert tasks
        assert sum(task.task_type == "static_review" for task in tasks) == 1
        static_task = next(task for task in tasks if task.task_type == "static_review")
        assert static_task.status == "inconclusive"
        assert static_task.result["failure_category"] == "agent_unavailable"
        assert {task.status for task in tasks if task.task_type != "static_review"} == {
            "blocked_device"
        }
        assert all(
            task.result["failure_category"] == "device_unavailable"
            for task in tasks
            if task.task_type != "static_review"
        )
        assert (
            len(list(session.scalars(select(CoverageItem).where(CoverageItem.scan_id == scan_id))))
            >= 16
        )
        report = ReportBuilder().build(session, scan)
        sarif = ReportBuilder().sarif(report)
        assert sarif["version"] == "2.1.0"
        assert report["scan"]["limitations"]
        html_report = ReportBuilder().html(report)
        embedded = html_report.split('<script type="application/json" id="report-data">', 1)[
            1
        ].split("</script>", 1)[0]
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


def test_agent_schema_failure_is_not_misreported_as_device_blocking(
    settings,
    fixture_apk,
) -> None:  # noqa: ANN001
    configured = replace(settings, codex_enabled=True, adaptive_verifier_enabled=False)
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

    class InvalidSchemaInvestigator:
        @staticmethod
        def capability(*, deep=False):  # noqa: ANN001, ANN205
            return {"available": True, "version": "fake-sdk", "deep": deep}

        @staticmethod
        def investigate(**_kwargs):  # noqa: ANN003, ANN205
            raise ValueError(
                "hypothesis_assessments.0.counterevidence: Input should be a valid list"
            )

    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    orchestrator.investigators["codex"] = InvalidSchemaInvestigator()
    orchestrator._run_sync(scan_id)

    with database.session_factory() as session:
        tasks = list(
            session.scalars(select(InvestigationTask).where(InvestigationTask.scan_id == scan_id))
        )
    assert tasks
    assert {task.status for task in tasks} == {"failed"}
    assert all(
        task.result["failure_category"] == "agent_structured_output_or_runtime" for task in tasks
    )
    assert all("counterevidence" in str(task.error) for task in tasks)


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
            session.scalars(select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id))
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
            created_at=datetime.now(UTC) - timedelta(seconds=settings.scan_deadline_seconds + 60),
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


def test_orchestrator_persists_audit_evidence_for_every_ai_call(settings, fixture_apk) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_enabled=True,
        adaptive_verifier_enabled=False,
    )
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
            assert entry_scope["policy"] == ("seed_entry_with_scan_wide_chain_exploration")
            assert entry_scope["seed_entry_point_ids"] == task.target_entry_ids
            assert {item["id"] for item in entry_scope["catalog"]} == set(task.target_entry_ids)
            assert all(item["assigned_seed"] for item in entry_scope["catalog"])
            assert all(
                item["name"] != "com.example.vulnerable.TrustedService"
                for item in entry_scope["catalog"]
            )
            representatives = kwargs["platform_context"]["threat_model"]["attack_surface"][
                "representative_entries"
            ]
            assert all(
                item["name"] != "com.example.vulnerable.TrustedService" for item in representatives
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
            session.scalars(select(InvestigationTask).where(InvestigationTask.scan_id == scan_id))
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
        finding.metadata_json["proof_backlog"]["automation_state"] == "manual_or_poc_required"
        for finding in proof_backlog
    )
    assert trusted_service is not None
    assert all(trusted_service.id not in task.target_entry_ids for task in tasks)
    assert trusted_coverage is not None
    assert trusted_coverage.status == "covered"
    assert trusted_coverage.stages["agent"] == "not_applicable"
    assert trusted_coverage.stages["indirect_chain"] == "retained_for_scan_wide_seed_exploration"
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
    assert (settings.data_dir / "workspaces" / scan_id / "code_index.json").is_file()


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
                **({"deletion": {"soft_deleted": True}} if winning_status == "deleted" else {}),
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
                **({"deletion": {"soft_deleted": True}} if winning_status == "deleted" else {}),
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
            session.scalars(select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id))
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
            session.scalars(select(SecurityHypothesis).where(SecurityHypothesis.task_id == task_id))
        )
        assert hypotheses
        assert all("platform_result" not in hypothesis.metadata_json for hypothesis in hypotheses)


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
            session.scalars(select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id))
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
    assert overridden["hypothesis_assessments"][0]["verdict"] == ("reproduced_blackbox")
    assert overridden["hypothesis_assessments"][0]["counterevidence"] == []
    assert overridden["hypothesis_assessments"][0]["proof_gaps"] == []
    assert overridden["objection_resolutions"][0]["disposition"] == "overruled"
    assert overridden["platform_proof_overrides"][hypothesis_id]["immutable"] is True


def test_negative_model_results_require_blind_rescue_review() -> None:
    for result in ("refuted_static", "not_reproduced"):
        assert ScanOrchestrator._needs_rescue_review(SimpleNamespace(result=result))
    for result in ("supported_static", "reproduced_blackbox"):
        assert not ScanOrchestrator._needs_rescue_review(SimpleNamespace(result=result))
