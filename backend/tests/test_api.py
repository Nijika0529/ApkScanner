from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import apkscanner.api as api_module
import pytest
from apkscanner.enums import TaskStatus
from apkscanner.main import create_app
from apkscanner.models import EntryPoint, Evidence, Finding, InvestigationTask, Scan
from apkscanner.schemas import AgentInvestigationResult
from fastapi.testclient import TestClient
from sqlalchemy import select


def test_frontend_index_is_revalidated_after_a_rebuild(settings, tmp_path) -> None:  # noqa: ANN001
    frontend = tmp_path / "frontend-dist"
    frontend.mkdir()
    (frontend / "index.html").write_text(
        "<html><body>current frontend</body></html>",
        encoding="utf-8",
    )
    app = create_app(replace(settings, frontend_dist=frontend))

    with TestClient(app) as client:
        response = client.get("/existing-scan")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    assert "current frontend" in response.text


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
        assert health["max_upload_bytes"] == settings.max_upload_bytes
        assert {item["name"] for item in health["capabilities"]} >= {
            "codex",
            "opencode_deepseek",
        }


def test_in_memory_sqlite_is_shared_with_app_worker_threads(settings) -> None:  # noqa: ANN001
    app = create_app(replace(settings, database_url="sqlite:///:memory:"))

    with TestClient(app) as client:
        response = client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "suffix",
    ["entries", "findings", "signals", "tasks", "hypotheses", "coverage", "events"],
)
def test_scan_child_collections_return_not_found_for_unknown_scan(
    settings,
    suffix: str,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/scans/00000000-0000-0000-0000-000000000099/{suffix}"
        )
    assert response.status_code == 404


def test_report_exports_scan_error_and_entry_code_anchors(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="failed",
                filename="failed.apk",
                artifact_sha256="e" * 64,
                artifact_path=str(settings.data_dir / "missing-failed.apk"),
                error="static analysis failed",
            )
            entry = EntryPoint(
                scan=scan,
                kind="activity",
                name="com.example.FailedActivity",
                exported=True,
                code_anchors=[
                    {
                        "path": "sources/com/example/FailedActivity.java",
                        "line": 42,
                    }
                ],
            )
            session.add_all([scan, entry])
            session.commit()
            scan_id = scan.id

        response = client.get(f"/api/v1/scans/{scan_id}/report/json")

    assert response.status_code == 200
    report = response.json()
    assert report["scan"]["error"] == "static analysis failed"
    assert report["entry_points"][0]["code_anchors"] == [
        {
            "path": "sources/com/example/FailedActivity.java",
            "line": 42,
        }
    ]


def test_findings_require_platform_harm_and_valid_evidence(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="proof-policy.apk",
                artifact_sha256="f" * 64,
                artifact_path=str(settings.data_dir / "proof-policy.apk"),
            )
            session.add(scan)
            session.flush()
            evidence = Evidence(
                scan_id=scan.id,
                kind="dynamic.oracle",
                sha256="a" * 64,
                path=str(settings.data_dir / "evidence.json"),
                summary="Platform Oracle observed unauthorized impact",
            )
            session.add(evidence)
            session.flush()
            records = [
                Finding(
                    scan_id=scan.id,
                    dedupe_key="builtin-static",
                    rule_id="BUILTIN",
                    source="builtin",
                    title="Static candidate",
                    description="Rule-only signal",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="candidate",
                ),
                Finding(
                    scan_id=scan.id,
                    dedupe_key="agent-static",
                    rule_id="AGENT",
                    source="opencode",
                    title="Static support",
                    description="Static evidence only",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="supported_static",
                    evidence_ids=[evidence.id],
                    metadata_json={"harm_demonstrated": False},
                ),
                Finding(
                    scan_id=scan.id,
                    dedupe_key="proven",
                    rule_id="AGENT",
                    source="opencode",
                    title="Proven impact",
                    description="Platform-correlated harm",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    evidence_ids=[evidence.id],
                    metadata_json={"harm_demonstrated": True},
                ),
                Finding(
                    scan_id=scan.id,
                    dedupe_key="invalid-proof",
                    rule_id="AGENT",
                    source="opencode",
                    title="Invalid proof reference",
                    description="Missing evidence",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    evidence_ids=["00000000-0000-0000-0000-000000000099"],
                    metadata_json={"harm_demonstrated": True},
                ),
            ]
            session.add_all(records)
            session.commit()
            scan_id = scan.id

        findings = client.get(f"/api/v1/scans/{scan_id}/findings")
        signals = client.get(f"/api/v1/scans/{scan_id}/signals")
        report = client.get(f"/api/v1/scans/{scan_id}/report/json")

    assert findings.status_code == 200
    assert [item["title"] for item in findings.json()] == ["Proven impact"]
    assert signals.status_code == 200
    assert {item["title"] for item in signals.json()} == {
        "Static candidate",
        "Static support",
        "Invalid proof reference",
    }
    assert [item["title"] for item in report.json()["findings"]] == ["Proven impact"]
    assert {item["title"] for item in report.json()["signals"]} == {
        "Static candidate",
        "Static support",
        "Invalid proof reference",
    }


@pytest.mark.asyncio
async def test_event_stream_ends_if_scan_is_deleted(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with app.state.database.session_factory() as session:
        scan = Scan(
            status="queued",
            filename="stream-delete.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "missing-stream-delete.apk"),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    class ConnectedRequest:
        headers: dict[str, str] = {}

        @staticmethod
        async def is_disconnected() -> bool:
            return False

    response = await api_module.stream_events(
        scan_id,
        ConnectedRequest(),
        app.state.database,
    )
    with app.state.database.session_factory() as session:
        persisted = session.get(Scan, scan_id)
        assert persisted is not None
        session.delete(persisted)
        session.commit()

    end_event = await asyncio.wait_for(anext(response.body_iterator), timeout=1)
    assert end_event == "event: end\ndata: {}\n\n"
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(response.body_iterator), timeout=1)


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


def test_terminal_task_can_be_deleted_while_ai_audit_is_preserved(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    evidence_sha, evidence_path = app.state.store.put_json(
        "evidence",
        {"task_id": "00000000-0000-0000-0000-000000000042"},
    )
    with app.state.database.session_factory() as session:
        scan = Scan(
            id="00000000-0000-0000-0000-000000000040",
            status="final",
            filename="task-delete.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "missing-task-delete.apk"),
        )
        task = InvestigationTask(
            id="00000000-0000-0000-0000-000000000042",
            scan_id=scan.id,
            task_type="component",
            status="blocked_device",
            attempts=1,
        )
        session.add_all([scan, task])
        session.flush()
        session.add(
            Evidence(
                scan_id=scan.id,
                task_id=task.id,
                kind="agent.request",
                sha256=evidence_sha,
                path=str(evidence_path),
                metadata_json={
                    "audit_id": "00000000-0000-0000-0000-000000000043",
                    "backend": "opencode",
                    "provider": "deepseek",
                    "model": "deepseek-v4-pro",
                    "isolation": "host",
                    "phase": "test_planning",
                    "attempt": 1,
                },
            )
        )
        session.commit()

    with app.state.database.session_factory() as session:
        persisted_task = session.get(InvestigationTask, task.id)
        assert persisted_task is not None
        app.state.orchestrator.hypothesis_ledger.ensure_task_hypotheses(
            persisted_task
        )

    with TestClient(app) as client:
        blocked = client.delete(f"/api/v1/tasks/{task.id}")
        assert blocked.status_code == 403
        deleted = client.delete(
            f"/api/v1/tasks/{task.id}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert deleted.status_code == 200
        assert deleted.json() == {
            "id": task.id,
            "deleted": True,
            "audit_artifacts_preserved": 1,
        }
        assert client.get(f"/api/v1/scans/{scan.id}/tasks").json() == []
        audits = client.get(f"/api/v1/scans/{scan.id}/agent-audits").json()
        assert audits[0]["task_id"] == task.id
        assert audits[0]["integrity"] == "verified"
        hypotheses = client.get(f"/api/v1/scans/{scan.id}/hypotheses").json()
        assert len(hypotheses) == 1
        assert hypotheses[0]["task_id"] == task.id

    assert evidence_path.exists()
    with app.state.database.session_factory() as session:
        deleted_task = session.get(InvestigationTask, task.id)
        assert deleted_task is not None
        assert deleted_task.status == "deleted"
        assert deleted_task.result["deletion"]["soft_deleted"] is True
        evidence = session.scalar(select(Evidence).where(Evidence.scan_id == scan.id))
        assert evidence is not None
        assert evidence.task_id == task.id


@pytest.mark.parametrize(
    ("method", "suffix", "payload"),
    [
        ("PATCH", "agent-control", {"enabled": False}),
        ("POST", "retry", None),
        ("POST", "rerun", None),
        ("POST", "continue", None),
        ("POST", "cancel", None),
        ("DELETE", "", None),
    ],
)
def test_deleted_task_cannot_be_mutated_or_restored(
    settings,
    monkeypatch,
    method: str,
    suffix: str,
    payload: dict[str, bool] | None,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    submitted: list[str] = []

    async def submit(scan_id: str) -> None:
        submitted.append(scan_id)

    monkeypatch.setattr(app.state.orchestrator, "submit", submit)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="deleted-task.apk",
                artifact_sha256="f" * 64,
                artifact_path=str(settings.data_dir / "missing-deleted-task.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="deleted",
                result={"deletion": {"soft_deleted": True}},
            )
            session.add_all([scan, task])
            session.commit()
            scan_id = scan.id
            task_id = task.id

        path = f"/api/v1/tasks/{task_id}"
        if suffix:
            path = f"{path}/{suffix}"
        request_options = {
            "headers": {"X-APKScanner-Request": "console"},
        }
        if payload is not None:
            request_options["json"] = payload
        response = client.request(method, path, **request_options)

        assert response.status_code == 404
        assert client.get(f"/api/v1/scans/{scan_id}/tasks").json() == []

    with app.state.database.session_factory() as session:
        persisted = session.get(InvestigationTask, task_id)
        assert persisted is not None
        assert persisted.status == "deleted"
        assert persisted.result == {"deletion": {"soft_deleted": True}}
    assert submitted == []


def test_running_task_cannot_be_deleted(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                id="00000000-0000-0000-0000-000000000050",
                status="investigating",
                filename="running-task.apk",
                artifact_sha256="e" * 64,
                artifact_path=str(settings.data_dir / "missing-running-task.apk"),
            )
            task = InvestigationTask(
                id="00000000-0000-0000-0000-000000000051",
                scan_id=scan.id,
                task_type="component",
                status="running",
            )
            session.add_all([scan, task])
            session.commit()
        response = client.delete(
            f"/api/v1/tasks/{task.id}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 409


def test_stopping_task_can_be_deleted_without_being_restored(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    signaled: list[str] = []
    monkeypatch.setattr(
        app.state.orchestrator,
        "request_task_cancellation",
        lambda task_id: signaled.append(task_id) or True,
    )
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="investigating",
                filename="stopping-task.apk",
                artifact_sha256="9" * 64,
                artifact_path=str(settings.data_dir / "missing-stopping.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="cancel_requested",
                result={
                    "cancellation": {
                        "requested": True,
                        "acknowledged": False,
                    }
                },
            )
            session.add_all([scan, task])
            session.commit()
            scan_id = scan.id
            task_id = task.id

        deleted = client.delete(
            f"/api/v1/tasks/{task_id}",
            headers={"X-APKScanner-Request": "console"},
        )
        assert deleted.status_code == 200
        assert signaled == [task_id]
        assert client.get(f"/api/v1/scans/{scan_id}/tasks").json() == []

    app.state.orchestrator._mark_task_canceled(scan_id, task_id)
    with app.state.database.session_factory() as session:
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.status == "deleted"
        assert task.result["deletion"]["runtime_stop_pending"] is True
        assert task.result["cancellation"]["acknowledged"] is True


def test_waiting_task_can_be_cancelled_before_dispatch(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="queued-cancel.apk",
                artifact_sha256="1" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="queued",
            )
            session.add_all([scan, task])
            session.commit()
        response = client.post(
            f"/api/v1/tasks/{task.id}/cancel",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "canceled"
        assert response.json()["result"]["cancellation"]["acknowledged"] is True


def test_running_task_cancellation_signals_the_orchestrator(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    signaled: list[str] = []
    monkeypatch.setattr(
        app.state.orchestrator,
        "request_task_cancellation",
        lambda task_id: signaled.append(task_id) or True,
    )
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="running-cancel.apk",
                artifact_sha256="2" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="running",
                attempts=1,
            )
            session.add_all([scan, task])
            session.commit()
        response = client.post(
            f"/api/v1/tasks/{task.id}/cancel",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "cancel_requested"
        assert signaled == [task.id]


def test_device_queue_cancellation_wakes_the_waiting_runtime(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    signaled: list[str] = []
    monkeypatch.setattr(
        app.state.orchestrator,
        "request_task_cancellation",
        lambda task_id: signaled.append(task_id) or True,
    )
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="investigating",
                filename="device-queue-cancel.apk",
                artifact_sha256="5" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="awaiting_device",
                result={"device_queue": {"position_at_enqueue": 2}},
            )
            session.add_all([scan, task])
            session.commit()
        response = client.post(
            f"/api/v1/tasks/{task.id}/cancel",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "cancel_requested"
        assert response.json()["result"]["cancellation"]["acknowledged"] is False
        assert signaled == [task.id]


def test_running_task_cancellation_is_acknowledged_when_runtime_already_exited(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    monkeypatch.setattr(
        app.state.orchestrator,
        "request_task_cancellation",
        lambda _task_id: False,
    )
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="late-cancel.apk",
                artifact_sha256="3" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="running",
                attempts=1,
            )
            session.add_all([scan, task])
            session.commit()
        response = client.post(
            f"/api/v1/tasks/{task.id}/cancel",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "canceled"
        assert response.json()["result"]["cancellation"]["acknowledged"] is True


def test_worker_completion_wins_a_race_with_task_cancellation(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    transition_started = threading.Event()
    allow_transition = threading.Event()
    original_transition = api_module._transition_task

    def delayed_transition(
        session,
        task_id: str,
        *,
        expected_status: str,
        values,
    ) -> bool:  # noqa: ANN001
        if expected_status == TaskStatus.RUNNING.value:
            transition_started.set()
            assert allow_transition.wait(timeout=5)
        return original_transition(
            session,
            task_id,
            expected_status=expected_status,
            values=values,
        )

    monkeypatch.setattr(api_module, "_transition_task", delayed_transition)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="investigating",
                filename="cancel-race.apk",
                artifact_sha256="4" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="running",
                result={"initial": True},
            )
            session.add_all([scan, task])
            session.commit()
            task_id = task.id

        response_box = {}

        def cancel() -> None:
            response_box["response"] = client.post(
                f"/api/v1/tasks/{task_id}/cancel",
                headers={"X-APKScanner-Request": "console"},
            )

        request_thread = threading.Thread(target=cancel)
        request_thread.start()
        assert transition_started.wait(timeout=5)
        with app.state.database.session_factory() as worker_session:
            worker_task = worker_session.get(InvestigationTask, task_id)
            assert worker_task is not None
            worker_task.status = TaskStatus.COMPLETED.value
            worker_task.result = {"worker_success": True}
            worker_session.commit()
        allow_transition.set()
        request_thread.join(timeout=5)
        assert not request_thread.is_alive()

        response = response_box["response"]
        assert response.status_code == 409
        with app.state.database.session_factory() as session:
            persisted = session.get(InvestigationTask, task_id)
            assert persisted is not None
            assert persisted.status == TaskStatus.COMPLETED.value
            assert persisted.result == {"worker_success": True}


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
            summary="静态证据不足，当前攻击路径已按证据强度处理。",
            result="refuted_static",
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
                == "refuted_static"
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


def test_opencode_audit_records_explicit_phase_execution_profile(settings) -> None:  # noqa: ANN001
    settings = replace(settings, opencode_model="deepseek-v4-pro")
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
        "mode": "structured_output_tool",
        "profile": "structured_finalizer",
        "format": "json_schema",
        "request_mode": "prompt_sync",
        "stages": [
            {
                "name": "finalizer",
                "thinking_mode": "disabled",
                "wire_tool_choice": "required",
            },
        ],
        "schema_validator": "ajv@8.20.0",
        "structured_retry_count": 2,
        "model_calls": [
            {
                "stage": "finalizer",
                "attempt": 1,
                "prompt": "exact model prompt",
                "response_text": "",
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
            summary="静态证据不足，当前攻击路径已按证据强度处理。",
            result="refuted_static",
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
        assert request["runtime_options"]["output_mode"] == "analyze_then_finalize"
        assert (
            request["runtime_options"]["execution_profile"]["name"]
            == "stable_analyzer"
        )
        assert (
            request["runtime_options"]["execution_profile"]["stages"][0][
                "thinking_mode"
            ]
            == "disabled"
        )
        assert request["runtime_options"]["schema_validator"] == "ajv@8.20.0"
        assert request["runtime_options"]["semantic_validator"] == "apkscanner@1.0"
        assert request["runtime_options"]["max_agent_steps"] is None
        assert request["runtime_options"]["max_provider_requests"] is None
        assert request["tool_boundary"]["model_tools_enabled"] is True
        assert request["tool_boundary"]["workspace_tool_profile"] == "workspace_shell"
        assert request["tool_boundary"]["workspace_tools"] == ["read", "glob", "grep", "bash"]
        assert request["tool_boundary"]["shell_enabled"] is True
        assert request["tool_boundary"]["write_enabled"] is True
        assert request["tool_boundary"]["native_write_tools_enabled"] is False
        assert request["tool_boundary"]["allowed_write_roots"] == [
            "task_attempt_workspace",
            "/tmp",
        ]
        assert request["tool_boundary"]["shared_scan_workspace_exposed"] is True
        assert request["tool_boundary"]["adb_enabled"] is False
        assert request["tool_boundary"]["structured_output_tool_enabled"] is True
        assert "DEEPSEEK_THINKING_OUTPUT_ADAPTER" not in request["prompt"]
        assert request["explorer_prompt"] is not None
        assert "Inspect context.json first" in request["explorer_prompt"]
        recorded_transport = audit["artifacts"]["response"]["content"][
            "output_transport"
        ]
        assert recorded_transport == transport


def test_scan_and_task_agent_controls_are_persisted(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="agent-control.apk",
                artifact_sha256="7" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
                stats={"investigator": "codex"},
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="inconclusive",
            )
            session.add_all([scan, task])
            session.commit()

        scan_response = client.patch(
            f"/api/v1/scans/{scan.id}/agent-control",
            headers={"X-APKScanner-Request": "console"},
            json={"enabled": False, "backend": "opencode"},
        )
        assert scan_response.status_code == 200
        control = scan_response.json()["stats"]["agent_control"]
        assert control["enabled"] is False
        assert control["backend"] == "opencode"
        assert control["updated_at"]

        task_response = client.patch(
            f"/api/v1/tasks/{task.id}/agent-control",
            headers={"X-APKScanner-Request": "console"},
            json={"enabled": False},
        )
        assert task_response.status_code == 200
        assert task_response.json()["preconditions"]["agent_enabled"] is False

        with app.state.database.session_factory() as session:
            persisted_scan = session.get(Scan, scan.id)
            persisted_task = session.get(InvestigationTask, task.id)
            assert persisted_scan is not None and persisted_task is not None
            assert (
                app.state.orchestrator.resolve_task_investigator(
                    persisted_scan, persisted_task
                )
                == "none"
            )


def test_batch_rerun_only_queues_incomplete_tasks(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    submitted: list[str] = []

    async def submit(scan_id: str) -> None:
        submitted.append(scan_id)

    monkeypatch.setattr(app.state.orchestrator, "submit", submit)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="supplement.apk",
                artifact_sha256="8" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
                stats={"investigator": "codex"},
            )
            blocked = InvestigationTask(
                scan=scan,
                task_type="component",
                status="blocked_device",
                attempts=2,
            )
            incomplete = InvestigationTask(
                scan=scan,
                task_type="component",
                status="completed",
                attempts=3,
                result={"result": "inconclusive", "severity_proposal": "low"},
            )
            confirmed = InvestigationTask(
                scan=scan,
                task_type="component",
                status="completed",
                result={"result": "supported_static"},
            )
            session.add_all([scan, blocked, incomplete, confirmed])
            session.commit()

        response = client.post(
            f"/api/v1/scans/{scan.id}/rerun-incomplete",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        assert response.json()["queued_count"] == 2
        assert set(response.json()["queued_task_ids"]) == {blocked.id, incomplete.id}

        with app.state.database.session_factory() as session:
            assert session.get(InvestigationTask, blocked.id).status == "queued"
            assert session.get(InvestigationTask, incomplete.id).status == "queued"
            assert session.get(InvestigationTask, confirmed.id).status == "completed"
            persisted_scan = session.get(Scan, scan.id)
            assert persisted_scan is not None
            assert persisted_scan.status == "investigating"
        assert submitted == [scan.id]


def test_manual_task_rerun_is_not_blocked_by_automatic_attempt_budget(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)

    async def submit(_scan_id: str) -> None:
        return None

    monkeypatch.setattr(app.state.orchestrator, "submit", submit)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="manual-rerun.apk",
                artifact_sha256="9" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="inconclusive",
                attempts=settings.task_max_attempts,
            )
            session.add_all([scan, task])
            session.commit()
        budgeted = client.post(
            f"/api/v1/tasks/{task.id}/retry",
            headers={"X-APKScanner-Request": "console"},
        )
        assert budgeted.status_code == 409
        response = client.post(
            f"/api/v1/tasks/{task.id}/rerun",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "queued"
        assert response.json()["attempts"] == settings.task_max_attempts
        assert response.json()["result"]["manual_rerun"]["previous_status"] == "inconclusive"


def test_timed_out_task_can_continue_with_a_fresh_budget_and_prior_context(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    app = create_app(settings)
    submitted: list[str] = []

    async def submit(scan_id: str) -> None:
        submitted.append(scan_id)

    monkeypatch.setattr(app.state.orchestrator, "submit", submit)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="deep-continuation.apk",
                artifact_sha256="8" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
            )
            task = InvestigationTask(
                scan=scan,
                task_type="component",
                status="timed_out",
                attempts=3,
                thread_id="prior-thread",
                turn_id="prior-turn",
                result={
                    "coverage_gaps": ["Task budget expired before all tests ran."],
                    "result": "inconclusive",
                },
            )
            session.add_all([scan, task])
            session.commit()
            scan_id = scan.id
            task_id = task.id

        response = client.post(
            f"/api/v1/tasks/{task_id}/continue",
            headers={"X-APKScanner-Request": "console"},
        )
        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "queued"
        continuation = payload["result"]["manual_continuation"]
        assert continuation["continuation_number"] == 1
        assert continuation["previous_attempt"] == 3
        assert continuation["previous_thread_id"] == "prior-thread"
        assert continuation["reuse_task_evidence"] is True
        assert continuation["prior_result"]["result"] == "inconclusive"
        assert submitted == [scan_id]

        rejected = client.post(
            f"/api/v1/tasks/{task_id}/continue",
            headers={"X-APKScanner-Request": "console"},
        )
        assert rejected.status_code == 409


def test_hypothesis_and_private_evaluation_endpoints(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session_factory() as session:
            scan = Scan(
                status="final",
                filename="evaluation.apk",
                artifact_sha256="5" * 64,
                artifact_path=str(settings.data_dir / "missing.apk"),
                stats={"investigator": "opencode"},
            )
            entry = EntryPoint(
                scan=scan,
                kind="deep_link",
                name="demo://example.test/open",
                exported=True,
            )
            task = InvestigationTask(
                scan=scan,
                task_type="deep_link",
                target_entry_ids=[],
                hypotheses=["Guest route may trigger protected behavior."],
            )
            session.add_all([scan, entry, task])
            session.flush()
            task.target_entry_ids = [entry.id]
            probe_evidence = Evidence(
                scan_id=scan.id,
                task_id=task.id,
                kind="dynamic.probe",
                sha256="6" * 64,
                path=str(settings.data_dir / "probe.json"),
            )
            log_evidence = Evidence(
                scan_id=scan.id,
                task_id=task.id,
                kind="dynamic.log",
                sha256="7" * 64,
                path=str(settings.data_dir / "log.json"),
            )
            session.add_all([probe_evidence, log_evidence])
            session.flush()
            session.add(
                Finding(
                    scan=scan,
                    dedupe_key="agent:proven",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Agent investigation: route",
                    description="Guest route triggers protected behavior.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    entry_point_ids=[entry.id],
                    evidence_ids=[probe_evidence.id, log_evidence.id],
                    metadata_json={"harm_demonstrated": True},
                )
            )
            session.commit()
            scan_id = scan.id
            task_id = task.id

        with app.state.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            assert task is not None
            app.state.orchestrator.hypothesis_ledger.ensure_task_hypotheses(task)

        hypotheses = client.get(f"/api/v1/scans/{scan_id}/hypotheses")
        assert hypotheses.status_code == 200
        assert len(hypotheses.json()) == 1
        assert hypotheses.json()[0]["status"] == "candidate"

        evaluation = client.post(
            f"/api/v1/scans/{scan_id}/evaluations",
            headers={"X-APKScanner-Request": "console"},
            json={
                "schema_version": "1.0",
                "name": "private-evaluation",
                "apk_sha256": "5" * 64,
                "vulnerabilities": [
                    {
                        "id": "GT-1",
                        "title": "Route authorization bypass",
                        "harm": "Guest triggers protected behavior.",
                        "severity": "high",
                        "minimum_proof": "dynamic",
                        "match": {
                            "rule_ids": ["AGENT-ENTRY-INVESTIGATION"],
                            "entry_names": ["demo://example.test/open"],
                            "title_contains": ["protected behavior"],
                        },
                    }
                ],
            },
        )
        assert evaluation.status_code == 200
        assert evaluation.json()["result"]["metrics"]["score_100"] == 100.0
        listed = client.get(f"/api/v1/scans/{scan_id}/evaluations")
        assert listed.status_code == 200
        assert len(listed.json()) == 1
        report = client.get(f"/api/v1/scans/{scan_id}/report/json")
        assert report.status_code == 200
        assert report.json()["security_hypotheses"][0]["task_id"] == task_id
        assert report.json()["benchmark_evaluations"][0]["name"] == "private-evaluation"
        html_report = client.get(f"/api/v1/scans/{scan_id}/report/html")
        assert "验证链" in html_report.text
