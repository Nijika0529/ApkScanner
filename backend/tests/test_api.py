from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from apkscanner.main import create_app
from apkscanner.models import EntryPoint, Evidence, InvestigationTask, Scan
from apkscanner.schemas import AgentInvestigationResult
from fastapi.testclient import TestClient
from sqlalchemy import select


def test_local_api_requires_console_marker_for_mutations(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        blocked = client.post(
            "/api/v1/scans",
            files={"apk": ("sample.apk", b"not-an-apk", "application/octet-stream")},
        )
        assert blocked.status_code == 403
        accepted_request = client.post(
            "/api/v1/scans",
            headers={"X-APKScanner-Request": "console"},
            files={"apk": ("sample.txt", b"not-an-apk", "application/octet-stream")},
        )
        assert accepted_request.status_code == 415
        invalid_investigator = client.post(
            "/api/v1/scans",
            headers={"X-APKScanner-Request": "console"},
            files={"apk": ("sample.apk", b"not-an-apk", "application/octet-stream")},
            data={"investigator": "unknown"},
        )
        assert invalid_investigator.status_code == 422

        health = client.get("/api/v1/health").json()
        assert health["default_investigator"] == "codex"
        assert {item["name"] for item in health["capabilities"]} >= {
            "codex",
            "opencode_deepseek",
        }


def test_completed_scan_can_be_deleted_with_its_unshared_files(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    store = app.state.store
    artifact_sha, artifact_path = store.put_bytes("artifacts", b"test-apk", suffix=".apk")
    evidence_sha, evidence_path = store.put_json("evidence", {"proof": True})
    workspace = settings.data_dir / "workspaces" / "00000000-0000-0000-0000-000000000010"
    workspace.mkdir(parents=True)
    (workspace / "context.json").write_text("{}", encoding="utf-8")
    with app.state.database.session_factory() as session:
        scan = Scan(
            id="00000000-0000-0000-0000-000000000010",
            status="final",
            filename="delete.apk",
            artifact_sha256=artifact_sha,
            artifact_path=str(artifact_path),
        )
        session.add(scan)
        session.flush()
        session.add(
            Evidence(
                scan_id=scan.id,
                kind="static.test",
                sha256=evidence_sha,
                path=str(evidence_path),
            )
        )
        session.commit()

    with TestClient(app) as client:
        blocked = client.delete(f"/api/v1/scans/{scan.id}")
        assert blocked.status_code == 403
        deleted = client.delete(
            f"/api/v1/scans/{scan.id}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert deleted.status_code == 200
        assert deleted.json()["files_removed"] == 3
        assert client.get(f"/api/v1/scans/{scan.id}").status_code == 404

    assert not artifact_path.exists()
    assert not evidence_path.exists()
    assert not workspace.exists()
    with app.state.database.session_factory() as session:
        assert session.get(Scan, scan.id) is None
        assert not list(
            session.scalars(select(Evidence).where(Evidence.scan_id == scan.id))
        )


def test_running_scan_cannot_be_deleted(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="queued",
                filename="running.apk",
                artifact_sha256="a" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            session.add(scan)
            session.commit()
        response = client.delete(
            f"/api/v1/scans/{scan.id}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 409


def test_deleting_one_scan_preserves_a_shared_apk(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    sha256, artifact_path = app.state.store.put_bytes(
        "artifacts", b"shared-apk", suffix=".apk"
    )
    scan_ids = [
        "00000000-0000-0000-0000-000000000030",
        "00000000-0000-0000-0000-000000000031",
    ]
    with app.state.database.session_factory() as session:
        for scan_id in scan_ids:
            session.add(
                Scan(
                    id=scan_id,
                    status="final",
                    filename="shared.apk",
                    artifact_sha256=sha256,
                    artifact_path=str(artifact_path),
                )
            )
        session.commit()

    with TestClient(app) as client:
        first = client.delete(
            f"/api/v1/scans/{scan_ids[0]}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert first.status_code == 200
        assert artifact_path.exists()
        second = client.delete(
            f"/api/v1/scans/{scan_ids[1]}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert second.status_code == 200
        assert not artifact_path.exists()


def test_ai_calls_are_exposed_as_integrity_checked_audit_records(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    orchestrator = app.state.orchestrator
    with app.state.database.session_factory() as session:
        scan = Scan(
            id="00000000-0000-0000-0000-000000000020",
            status="final",
            filename="audit.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(settings.data_dir / "missing.apk"),
            package_name="com.example.audit",
        )
        task = InvestigationTask(
            id="00000000-0000-0000-0000-000000000021",
            scan_id=scan.id,
            task_type="component",
            status="completed",
            hypotheses=["Check exported reachability"],
            attempts=1,
        )
        entry = EntryPoint(
            id="00000000-0000-0000-0000-000000000022",
            scan_id=scan.id,
            kind="activity",
            name="com.example.audit.ExportedActivity",
            exported=True,
        )
        session.add_all([scan, task, entry])
        session.commit()

    audit_id = orchestrator._record_agent_request(
        scan=scan,
        task=task,
        entries=[entry],
        evidence=[],
        platform_context={"phase": "static_only"},
        backend="codex",
        phase="static_only",
        capability={"version": "test-sdk"},
    )
    result = SimpleNamespace(
        thread_id="thread-audit",
        turn_id="turn-audit",
        usage={"input_tokens": 12, "output_tokens": 4},
        result=AgentInvestigationResult(
            summary="Static evidence is insufficient.",
            result="inconclusive",
            hypotheses_tested=["Check exported reachability"],
            test_cases=[],
            evidence_ids=[],
            severity_proposal="info",
            confidence="low",
            coverage_gaps=["No dynamic evidence"],
            followups=[],
            requested_tests=[],
        ),
    )
    orchestrator._record_agent_response(
        scan_id=scan.id,
        task_id=task.id,
        audit_id=audit_id,
        backend="codex",
        phase="static_only",
        attempt=1,
        result=result,
    )
    raw = result.result.model_dump(mode="json")
    orchestrator._record_agent_validation(
        task_id=task.id,
        turn_id=result.turn_id,
        raw_payload=raw,
        validated_payload=raw,
    )

    with TestClient(app) as client:
        audits = client.get(f"/api/v1/scans/{scan.id}/agent-audits")
        assert audits.status_code == 200
        payload = audits.json()
        assert len(payload) == 1
        assert payload[0]["id"] == audit_id
        assert payload[0]["integrity"] == "verified"
        assert payload[0]["thread_id"] == "thread-audit"
        assert payload[0]["artifacts"]["request"]["content"]["model"]
        assert (
            payload[0]["artifacts"]["response"]["content"]["structured_output"][
                "result"
            ]
            == "inconclusive"
        )
        assert (
            payload[0]["artifacts"]["validation"]["content"]["downgraded"]
            is False
        )
        report = client.get(f"/api/v1/scans/{scan.id}/report/json").json()
        assert report["agent_audits"][0]["id"] == audit_id
        html_report = client.get(f"/api/v1/scans/{scan.id}/report/html").text
        assert "AI 审计" in html_report
        assert "turn-audit" in html_report

        with app.state.database.session_factory() as session:
            request_evidence = session.scalar(
                select(Evidence).where(
                    Evidence.scan_id == scan.id,
                    Evidence.kind == "agent.request",
                )
            )
            assert request_evidence is not None
            Path(request_evidence.path).write_text('{"tampered":true}', encoding="utf-8")
        tampered = client.get(f"/api/v1/scans/{scan.id}/agent-audits").json()
        assert tampered[0]["status"] == "completed"
        assert tampered[0]["integrity"] == "failed"
        assert tampered[0]["artifacts"]["request"]["content"] is None
        download = client.get(
            f"/api/v1/evidence/{request_evidence.id}/download"
        )
        assert download.status_code == 409


def test_opencode_pro_audit_records_toolless_json_transport(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    orchestrator = app.state.orchestrator
    with app.state.database.session_factory() as session:
        scan = Scan(
            id="00000000-0000-0000-0000-000000000030",
            status="final",
            filename="pro-audit.apk",
            artifact_sha256="c" * 64,
            artifact_path=str(settings.data_dir / "missing-pro.apk"),
            package_name="com.example.pro",
        )
        task = InvestigationTask(
            id="00000000-0000-0000-0000-000000000031",
            scan_id=scan.id,
            task_type="component",
            status="completed",
            hypotheses=["Check exported reachability"],
            attempts=1,
        )
        entry = EntryPoint(
            id="00000000-0000-0000-0000-000000000032",
            scan_id=scan.id,
            kind="activity",
            name="com.example.pro.ExportedActivity",
            exported=True,
        )
        session.add_all([scan, task, entry])
        session.commit()

    audit_id = orchestrator._record_agent_request(
        scan=scan,
        task=task,
        entries=[entry],
        evidence=[],
        platform_context={"phase": "static_only"},
        backend="opencode",
        phase="static_only",
        capability={"version": "1.18.4"},
    )
    transport = {
        "mode": "prompted_json",
        "format": "text",
        "tool_choice": "omitted",
        "tools": [],
        "schema_validator": "ajv@8.20.0",
        "retry_count": 2,
        "model_calls": [
            {
                "attempt": 1,
                "prompt": "exact model prompt",
                "response_text": '{"result":"inconclusive"}',
                "accepted": True,
            }
        ],
    }
    result = SimpleNamespace(
        thread_id="thread-pro",
        turn_id="turn-pro",
        usage={"calls": 1},
        output_transport=transport,
        result=AgentInvestigationResult(
            summary="Static evidence is insufficient.",
            result="inconclusive",
            hypotheses_tested=["Check exported reachability"],
            test_cases=[],
            evidence_ids=[],
            severity_proposal="info",
            confidence="low",
            coverage_gaps=["No dynamic evidence"],
            followups=[],
            requested_tests=[],
        ),
    )
    orchestrator._record_agent_response(
        scan_id=scan.id,
        task_id=task.id,
        audit_id=audit_id,
        backend="opencode",
        phase="static_only",
        attempt=1,
        result=result,
    )

    with TestClient(app) as client:
        response = client.get(f"/api/v1/scans/{scan.id}/agent-audits")
        assert response.status_code == 200
        audit = response.json()[0]
        request = audit["artifacts"]["request"]["content"]
        assert request["runtime_options"]["output_mode"] == "prompted_json"
        assert request["runtime_options"]["schema_validator"] == "ajv@8.20.0"
        assert request["tool_boundary"]["model_tools_enabled"] is False
        assert request["tool_boundary"]["structured_output_tool_enabled"] is False
        assert "DEEPSEEK_THINKING_OUTPUT_ADAPTER" in request["prompt"]
        recorded_transport = audit["artifacts"]["response"]["content"][
            "output_transport"
        ]
        assert recorded_transport == transport
