from __future__ import annotations

from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.finding_reports import build_finding_report, render_finding_description
from apkscanner.models import Finding, InvestigationTask, Scan, SecurityHypothesis
from apkscanner.operator_schemas import OPERATOR_RECEIPT_JSON_SCHEMA, OperatorSessionCreate
from apkscanner.operator_service import PlatformOperatorService
from apkscanner.orchestrator import ScanOrchestrator


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
