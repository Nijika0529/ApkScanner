from __future__ import annotations

from dataclasses import replace

from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.dynamic_experiments import DynamicExperimentService
from apkscanner.evidence import EvidenceRecorder
from apkscanner.models import DynamicExperimentCapsule, DynamicExperimentReceipt, Scan
from apkscanner.schemas import DynamicExperimentCreate
from apkscanner.tools import CommandResult, ToolRunner
from sqlalchemy import select


def test_dynamic_experiment_resumes_only_the_failed_step(settings, monkeypatch) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="device-1",
        adb_serials=("device-1",),
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)

    from apkscanner.device import AdbDeviceAdapter, AdbDevicePool

    adapter = AdbDeviceAdapter(configured, ToolRunner(30), serial="device-1")
    pool = AdbDevicePool([adapter])
    service = DynamicExperimentService(database, EvidenceRecorder(store), pool)
    outputs = iter(
        [
            CommandResult(["adb", "step-one"], 0, "PREPARED", ""),
            CommandResult(["adb", "step-two"], 0, "WAITING", ""),
            CommandResult(["adb", "step-two"], 0, "READY", ""),
            CommandResult(["adb", "cleanup"], 0, "", ""),
        ]
    )
    monkeypatch.setattr(adapter, "execute_gateway", lambda *_args, **_kwargs: next(outputs))
    payload = DynamicExperimentCreate.model_validate(
        {
            "name": "resumable callback",
            "objective": "Retain the successful preparation when the callback is late.",
            "steps": [
                {
                    "id": "prepare",
                    "title": "Prepare state",
                    "phase": "prepare",
                    "adb_args": ["get-state"],
                    "stdout_contains": ["PREPARED"],
                },
                {
                    "id": "callback",
                    "title": "Observe callback",
                    "phase": "assert",
                    "adb_args": ["shell", "logcat", "-d"],
                    "stdout_contains": ["READY"],
                    "observation_kind": "callback.ready",
                },
            ],
            "cleanup_steps": [
                {
                    "id": "cleanup",
                    "title": "Cleanup",
                    "phase": "cleanup",
                    "adb_args": ["shell", "am", "force-stop", "com.example.fixture"],
                }
            ],
        }
    )
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            artifact_sha256="a" * 64,
            artifact_path="fixture.apk",
        )
        session.add(scan)
        session.flush()
        capsule = DynamicExperimentCapsule(
            scan_id=scan.id,
            name=payload.name,
            objective=payload.objective,
            steps=[item.model_dump(mode="json") for item in payload.steps],
            cleanup_steps=[item.model_dump(mode="json") for item in payload.cleanup_steps],
        )
        session.add(capsule)
        session.commit()
        capsule_id = capsule.id

    first = service.run(capsule_id)
    assert first.status == "paused"
    assert first.result_json["failed_step_ids"] == ["callback"]
    second = service.run(capsule_id)
    assert second.status == "completed"
    assert second.result_json["cleanup_complete"] is True
    with database.session_factory() as session:
        receipts = list(
            session.scalars(
                select(DynamicExperimentReceipt)
                .where(DynamicExperimentReceipt.capsule_id == capsule_id)
                .order_by(
                    DynamicExperimentReceipt.step_id,
                    DynamicExperimentReceipt.attempt,
                )
            )
        )
    assert [(item.step_id, item.attempt, item.status) for item in receipts] == [
        ("callback", 1, "failed"),
        ("callback", 2, "passed"),
        ("cleanup", 1, "passed"),
        ("prepare", 1, "passed"),
    ]
