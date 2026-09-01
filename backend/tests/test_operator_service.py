from __future__ import annotations

from apkscanner.core.db import Database
from apkscanner.core.models import (
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.platform.operator_schemas import (
    OPERATOR_RECEIPT_JSON_SCHEMA,
    OperatorReceipt,
    OperatorSessionCreate,
)
from apkscanner.platform.operator_service import PlatformOperatorService
from apkscanner.runtime.finding_reports import build_finding_report, render_finding_description
from apkscanner.runtime.orchestrator import ScanOrchestrator


def test_finding_report_is_hypothesis_scoped_and_compact(settings) -> None:  # noqa: ANN001
    hypothesis = SecurityHypothesis(
        id="3" * 36,
        scan_id="1" * 36,
        task_id="2" * 36,
        fingerprint="a" * 64,
        category="android.webview",
        claim="攻击者可通过导出 Activity 把任意 URL 送入带账号桥的 WebView",
        impact="账号 Token 可返回到攻击者控制的页面。",
        preconditions=["攻击者安装普通应用", "目标用户已登录", "多余条件"],
        entry_point_ids=[],
    )
    report = build_finding_report(
        task_id=hypothesis.task_id,
        hypothesis=hypothesis,
        assessment={
            "source": "exported BridgeActivity",
            "reachable_path": "Intent extra url -> WebView.loadUrl",
            "sink": "AccountBridge.getToken",
            "proof_gaps": ["缺少攻击者页面收到真实 Token 的网络回调证据"],
        },
        evidence_ids=["evidence-static"],
    )

    assert report.kind == "pending_risk"
    assert report.hypothesis_id == hypothesis.id
    assert len(report.conditions) == 2
    assert len(report.attack_chain) <= 5
    assert report.verification.status == "pending"
    assert "网络回调" in (report.verification.missing_proof or "")
    assert "任务总结" not in render_finding_description(report)


def test_operator_indexes_historical_poc_for_selected_finding(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    orchestrator = ScanOrchestrator(settings, database, store)
    service = PlatformOperatorService(database, store, orchestrator)

    with database.session_factory() as db:
        scan = Scan(
            status="final",
            filename="target.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "target.apk"),
            package_name="com.example.target",
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="completed",
            target_entry_ids=[],
            hypotheses=[],
        )
        db.add_all([scan, task])
        db.flush()
        finding = Finding(
            scan=scan,
            dedupe_key="operator-test",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="待验证：WebView token 泄露",
            description="静态链路成立",
            remediation="限制 URL",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
            metadata_json={"task_id": task.id},
        )
        db.add(finding)
        db.commit()
        scan_id, task_id, finding_id = scan.id, task.id, finding.id

    compact = task_id.replace("-", "")[:16]
    poc_root = (
        settings.data_dir
        / "agent-sessions"
        / scan_id
        / f"{compact}-a1-primary"
        / "workspace"
        / "poc"
    )
    poc_root.mkdir(parents=True)
    (poc_root / "bridge-poc.apk").write_bytes(b"test-poc-apk")

    session_id, _turn_id = service.create_session(
        OperatorSessionCreate(
            instruction="复用历史 PoC",
            finding_ids=[finding_id],
            device_mode="none",
        )
    )
    indexed = service.index_artifacts(session_id)

    assert len(indexed) == 1
    assert indexed[0].artifact_type == "poc_apk"
    assert indexed[0].finding_id == finding_id
    assert service.artifact_path(indexed[0].id).read_bytes() == b"test-poc-apk"


def test_operator_indexes_adaptive_verifier_artifacts(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    orchestrator = ScanOrchestrator(settings, database, store)
    service = PlatformOperatorService(database, store, orchestrator)

    with database.session_factory() as db:
        scan = Scan(
            status="final",
            filename="target.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(settings.data_dir / "target.apk"),
            package_name="com.example.target",
        )
        primary = InvestigationTask(
            scan=scan,
            task_type="component",
            status="completed",
            target_entry_ids=[],
            hypotheses=[],
        )
        verifier = InvestigationTask(
            scan=scan,
            task_type="adaptive_verifier",
            status="completed",
            target_entry_ids=[],
            hypotheses=[],
        )
        db.add_all([scan, primary, verifier])
        db.flush()
        finding = Finding(
            scan=scan,
            dedupe_key="operator-adaptive-test",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="待验证：Binder 数据泄露",
            description="静态链路成立",
            remediation="校验调用方",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
            metadata_json={
                "task_id": primary.id,
                "proof_backlog": {"verifier_task_id": verifier.id},
                "adaptive_verification": {"task_id": verifier.id},
            },
        )
        db.add(finding)
        db.commit()
        scan_id, verifier_id, finding_id = scan.id, verifier.id, finding.id

    compact = verifier_id.replace("-", "")[:16]
    artifact_root = (
        settings.data_dir
        / "agent-sessions"
        / scan_id
        / f"{compact}-a2-verifier"
        / "workspace"
        / "artifacts"
    )
    artifact_root.mkdir(parents=True)
    (artifact_root / "binder-run.txt").write_text("binder reply", encoding="utf-8")
    (artifact_root.parent / "poc" / "binder.apk").parent.mkdir(parents=True)
    (artifact_root.parent / "poc" / "binder.apk").write_bytes(b"binder-apk")

    session_id, _turn_id = service.create_session(
        OperatorSessionCreate(
            instruction="读取验证任务产物",
            finding_ids=[finding_id],
            device_mode="none",
        )
    )
    indexed = service.index_artifacts(session_id)

    assert {item.name for item in indexed} == {"binder-run.txt", "binder.apk"}
    assert {item.task_id for item in indexed} == {verifier_id}


def test_artifact_store_streams_local_file(settings, tmp_path) -> None:  # noqa: ANN001
    settings.ensure_directories()
    source = tmp_path / "payload.apk"
    source.write_bytes(b"streamed-payload")

    sha256, stored, size = ArtifactStore(settings).put_file(
        "operator_artifacts", source
    )

    assert size == len(b"streamed-payload")
    assert stored.name == f"{sha256}.apk"
    assert stored.read_bytes() == b"streamed-payload"


def test_operator_does_not_reindex_imported_artifacts(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "imports").mkdir()
    (tmp_path / "imports" / "historical.apk").write_bytes(b"old")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "receipt.json").write_text("{}", encoding="utf-8")
    (tmp_path / "output").mkdir()
    produced = tmp_path / "output" / "new.apk"
    produced.write_bytes(b"new")

    assert PlatformOperatorService._artifact_files(tmp_path) == [produced]


def test_operator_receipt_uses_strict_responses_object_schema() -> None:
    def assert_strict(value) -> None:  # noqa: ANN001
        if isinstance(value, list):
            for item in value:
                assert_strict(item)
            return
        if not isinstance(value, dict):
            return
        properties = value.get("properties")
        if isinstance(properties, dict):
            assert value.get("required") == list(properties)
        assert "$ref" not in value
        for item in value.values():
            assert_strict(item)

    assert_strict(OPERATOR_RECEIPT_JSON_SCHEMA)


def test_operator_cannot_confirm_harm_without_an_attributable_proof_attempt(
    settings,  # noqa: ANN001
) -> None:
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    orchestrator = ScanOrchestrator(settings, database, store)
    service = PlatformOperatorService(database, store, orchestrator)
    with database.session_factory() as db:
        scan = Scan(
            filename="operator-proof-policy.apk",
            artifact_sha256="c" * 64,
            artifact_path="operator-proof-policy.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        db.add_all([scan, task])
        db.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="d" * 64,
            category="component",
            claim="A candidate requires platform proof.",
        )
        db.add(hypothesis)
        db.flush()
        finding = Finding(
            scan=scan,
            dedupe_key="operator-proof-policy",
            rule_id="AGENT",
            title="Unproven candidate",
            description="Static evidence alone is not runtime harm proof.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
            metadata_json={"hypothesis_id": hypothesis.id},
        )
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="e" * 64,
            path="operator-static.json",
        )
        receipt_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="operator.receipt",
            sha256="f" * 64,
            path="operator-receipt.json",
        )
        db.add_all([finding, static_evidence, receipt_evidence])
        db.flush()
        hypothesis.final_finding_id = finding.id
        db.commit()
        finding_id = finding.id
        static_evidence_id = static_evidence.id
        receipt_evidence_id = receipt_evidence.id

    session_id, _turn_id = service.create_session(
        OperatorSessionCreate(
            instruction="复核该候选是否已经证明危害",
            finding_ids=[finding_id],
            device_mode="none",
        )
    )
    service._apply_finding_updates(
        session_id,
        OperatorReceipt.model_validate(
            {
                "result": "reproduced",
                "summary": "模型声称已复现，但只有静态证据。",
                "finding_updates": [
                    {
                        "finding_id": finding_id,
                        "verdict": "reproduced_blackbox",
                        "conclusion": "静态代码显示该路径可能存在。",
                        "evidence_ids": [static_evidence_id],
                    }
                ],
            }
        ),
        receipt_evidence_id,
    )

    with database.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "inconclusive"
        assert finding.metadata_json["harm_demonstrated"] is False
        history = finding.metadata_json["operator_history"][-1]
        assert history["requested_verdict"] == "reproduced_blackbox"
        assert history["verdict"] == "inconclusive"
        assert "ProofAttempt" in history["verdict_override_reason"]


def test_operator_static_refutation_requires_a_complete_platform_gate(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    service = PlatformOperatorService(
        database,
        store,
        ScanOrchestrator(settings, database, store),
    )
    with database.session_factory() as db:
        scan = Scan(
            filename="operator-static-refutation.apk",
            artifact_sha256="0" * 64,
            artifact_path="operator-static-refutation.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        db.add_all([scan, task])
        db.flush()
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="1" * 64,
            path="operator-static-refutation.json",
            metadata_json={"static_output_usable": True},
        )
        receipt_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="operator.receipt",
            sha256="2" * 64,
            path="operator-static-refutation-receipt.json",
        )
        generic = Finding(
            scan=scan,
            dedupe_key="operator-generic-refutation",
            rule_id="AGENT",
            title="Generic model closure",
            description="A vague conclusion must not close this candidate.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
        )
        concrete = Finding(
            scan=scan,
            dedupe_key="operator-concrete-refutation",
            rule_id="AGENT",
            title="Concrete static closure",
            description="A specific caller check blocks this path.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
        )
        db.add_all([static_evidence, receipt_evidence, generic, concrete])
        db.flush()
        generic.evidence_ids = [static_evidence.id]
        concrete.evidence_ids = [static_evidence.id]
        db.commit()
        finding_ids = [generic.id, concrete.id]
        static_evidence_id = static_evidence.id
        receipt_evidence_id = receipt_evidence.id

    session_id, _turn_id = service.create_session(
        OperatorSessionCreate(
            instruction="用静态证据复核两个候选。",
            finding_ids=finding_ids,
            device_mode="none",
        )
    )
    service._apply_finding_updates(
        session_id,
        OperatorReceipt.model_validate(
            {
                "result": "refuted",
                "summary": "一个结论泛泛，另一个有具体调用者校验。",
                "finding_updates": [
                    {
                        "finding_id": finding_ids[0],
                        "verdict": "refuted_static",
                        "conclusion": "代码看起来没有问题。",
                        "evidence_ids": [static_evidence_id],
                    },
                    {
                        "finding_id": finding_ids[1],
                        "verdict": "refuted_static",
                        "conclusion": "Binder 入口在敏感调用前强制校验调用 UID。",
                        "evidence_ids": [static_evidence_id],
                        "counterevidence": [
                            "静态分支显示 Binder.getCallingUid() 不匹配时立即抛出 SecurityException。"
                        ],
                        "blocked_edge": (
                            "untrusted Binder caller -> UID equality guard -> privileged sink blocked"
                        ),
                    },
                ],
            }
        ),
        receipt_evidence_id,
    )

    with database.session_factory() as db:
        generic = db.get(Finding, finding_ids[0])
        concrete = db.get(Finding, finding_ids[1])
        assert generic is not None and generic.status == "inconclusive"
        assert "platform_static_refutation_gate" not in generic.metadata_json
        generic_gate = generic.metadata_json["operator_history"][-1][
            "platform_static_refutation_gate"
        ]
        assert generic_gate["eligible"] is False
        assert "missing_concrete_counterevidence" in generic_gate[
            "suppression_reasons"
        ]
        assert concrete is not None and concrete.status == "refuted_static"
        concrete_gate = concrete.metadata_json["platform_static_refutation_gate"]
        assert concrete_gate["eligible"] is True
        assert concrete_gate["static_evidence_ids"] == [static_evidence_id]
        assert "UID equality guard" in concrete_gate["blocked_edge"]


def test_operator_unchanged_promotes_an_attributable_harm_receipt(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    service = PlatformOperatorService(
        database,
        store,
        ScanOrchestrator(settings, database, store),
    )
    with database.session_factory() as db:
        scan = Scan(
            filename="operator-existing-proof.apk",
            artifact_sha256="1" * 64,
            artifact_path="operator-existing-proof.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        db.add_all([scan, task])
        db.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="2" * 64,
            category="component",
            claim="A platform receipt already proves this hypothesis.",
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="3" * 64,
            path="operator-proof.json",
        )
        receipt_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="operator.receipt",
            sha256="4" * 64,
            path="operator-existing-proof-receipt.json",
        )
        db.add_all([hypothesis, evidence, receipt_evidence])
        db.flush()
        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="operator-existing-proof",
            status="proven",
            evidence_ids=[evidence.id],
            harm_demonstrated=True,
        )
        finding = Finding(
            scan=scan,
            dedupe_key="operator-existing-proof",
            rule_id="AGENT",
            title="Existing proof",
            description="The finding write lagged behind its proof receipt.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
            evidence_ids=[evidence.id],
            metadata_json={"hypothesis_id": hypothesis.id},
        )
        db.add_all([proof, finding])
        db.flush()
        hypothesis.final_finding_id = finding.id
        db.commit()
        finding_id = finding.id
        receipt_evidence_id = receipt_evidence.id

    session_id, _turn_id = service.create_session(
        OperatorSessionCreate(
            instruction="保留现状并检查现有平台证明",
            finding_ids=[finding_id],
            device_mode="none",
        )
    )
    service._apply_finding_updates(
        session_id,
        OperatorReceipt.model_validate(
            {
                "result": "completed",
                "summary": "平台证明已存在。",
                "finding_updates": [
                    {
                        "finding_id": finding_id,
                        "verdict": "unchanged",
                        "conclusion": "沿用平台证明。",
                        "evidence_ids": [],
                    }
                ],
            }
        ),
        receipt_evidence_id,
    )

    with database.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "reproduced_blackbox"
        assert finding.metadata_json["harm_demonstrated"] is True


def test_operator_cannot_reopen_a_human_false_positive_closure(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    service = PlatformOperatorService(
        database,
        store,
        ScanOrchestrator(settings, database, store),
    )
    with database.session_factory() as db:
        scan = Scan(
            filename="operator-human-closure.apk",
            artifact_sha256="5" * 64,
            artifact_path="operator-human-closure.apk",
        )
        db.add(scan)
        db.flush()
        finding = Finding(
            scan=scan,
            dedupe_key="operator-human-closure",
            rule_id="AGENT",
            title="Human-reviewed false positive",
            description="Only an explicit human review may reopen this record.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="false_positive",
            review_note="业务约束已人工确认，保持关闭。",
        )
        receipt_evidence = Evidence(
            scan_id=scan.id,
            kind="operator.receipt",
            sha256="6" * 64,
            path="operator-human-closure.json",
        )
        db.add_all([finding, receipt_evidence])
        db.commit()
        finding_id = finding.id
        receipt_evidence_id = receipt_evidence.id

    session_id, _turn_id = service.create_session(
        OperatorSessionCreate(
            instruction="重新分析人工关闭项，但不要覆盖人工结论",
            finding_ids=[finding_id],
            device_mode="none",
        )
    )
    service._apply_finding_updates(
        session_id,
        OperatorReceipt.model_validate(
            {
                "result": "completed",
                "summary": "模型建议重新打开，但没有平台危害证明。",
                "finding_updates": [
                    {
                        "finding_id": finding_id,
                        "verdict": "reproduced_blackbox",
                        "conclusion": "模型认为静态路径可利用。",
                        "evidence_ids": [],
                    }
                ],
            }
        ),
        receipt_evidence_id,
    )

    with database.session_factory() as db:
        finding = db.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "false_positive"
        assert finding.review_note == "业务约束已人工确认，保持关闭。"
        history = finding.metadata_json["operator_history"][-1]
        assert history["verdict"] == "false_positive"
        assert "human disposition" in history["verdict_override_reason"]
