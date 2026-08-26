from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import replace

import pytest
from apkscanner.core.db import Database
from apkscanner.core.models import Evidence, InvestigationTask, Scan
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.platform.tools import TimeBudget
from apkscanner.runtime.orchestrator import ScanOrchestrator, _LiveProofContext
from sqlalchemy import select


@pytest.mark.skipif(
    os.getenv("APKSCANNER_RUN_ADB_TESTS") != "1"
    or not os.getenv("APKSCANNER_TEST_ADB_SERIAL")
    or not os.getenv("APKSCANNER_HOST_ADB")
    or shutil.which("docker") is None,
    reason="requires explicit ADB integration opt-in, a serial, Docker and host adb path",
)
def test_container_adb_wrapper_reaches_fixed_serial_gateway(settings, monkeypatch) -> None:  # noqa: ANN001
    serial = os.environ["APKSCANNER_TEST_ADB_SERIAL"]
    configured = replace(
        settings,
        host_adb_executable=os.environ["APKSCANNER_HOST_ADB"],
        adb_serial=serial,
        adb_serials=(serial,),
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    orchestrator = ScanOrchestrator(configured, database, ArtifactStore(configured))
    workspace = configured.data_dir / "gateway-workspace"
    workspace.mkdir()
    (workspace / "context.json").write_text("{}", encoding="utf-8")
    with database.session_factory() as session:
        scan = Scan(
            filename="gateway.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(configured.data_dir / "gateway.apk"),
            package_name="io.apkscanner.vulntest",
        )
        session.add(scan)
        session.flush()
        task = InvestigationTask(scan_id=scan.id, task_type="component")
        session.add(task)
        session.commit()
        scan_id = scan.id
        task_id = task.id
    token = "a" * 64
    orchestrator._register_live_proof_context(
        _LiveProofContext(
            token=token,
            scan_id=scan_id,
            task_id=task_id,
            package_name="io.apkscanner.vulntest",
            workspace=workspace,
            entries=[],
            default_entry_id="",
            hypotheses=[],
            budget=TimeBudget.from_seconds(60),
            evidence_summaries=[],
            cancel_event=threading.Event(),
            round_index=0,
            device=orchestrator.devices[0],
        )
    )
    endpoint = orchestrator._ensure_live_proof_endpoint()
    port = endpoint.rsplit(":", 1)[1]
    monkeypatch.setenv("APKSCANNER_ADB_TASK_ID", task_id)
    monkeypatch.setenv(
        "APKSCANNER_ADB_GATEWAY_URL",
        f"http://apkscanner-host:{port}/api/v1/internal/tasks/{task_id}/adb",
    )
    monkeypatch.setenv("APKSCANNER_ADB_TOKEN", token)
    command = [
        "docker",
        "run",
        "--rm",
        "--add-host",
        "apkscanner-host:host-gateway",
        "--env",
        "APKSCANNER_ADB_TASK_ID",
        "--env",
        "APKSCANNER_ADB_GATEWAY_URL",
        "--env",
        "APKSCANNER_ADB_TOKEN",
        "--entrypoint",
        "adb",
        "apk-scanner-codex-worker:0.2.0",
        "get-state",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "device"
        with database.session_factory() as session:
            evidence = session.scalar(
                select(Evidence).where(Evidence.kind == "agent.adb.gateway")
            )
            assert evidence is not None
            assert evidence.command[:3] == ["adb", "-s", serial]
    finally:
        orchestrator.shutdown()
