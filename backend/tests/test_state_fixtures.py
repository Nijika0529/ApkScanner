from __future__ import annotations

import pytest
from apkscanner.core.db import Database
from apkscanner.core.evidence import EvidenceRecorder
from apkscanner.core.models import (
    DynamicExperimentCapsule,
    DynamicExperimentReceipt,
    EntryPoint,
    Scan,
    ValidationFixture,
)
from apkscanner.core.schemas import AgentRequestedTest, ValidationFixtureCreate
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.platform.tools import CommandResult, ToolRunner
from apkscanner.runtime.device import AdbDeviceAdapter, AdbDevicePool
from apkscanner.runtime.dynamic_experiments import DynamicExperimentService, fixture_state_check
from apkscanner.runtime.orchestrator import ScanOrchestrator
from sqlalchemy import select


def _fixture_check() -> dict[str, object]:
    return {
        "id": "operator-session",
        "title": "Verify logged-in state",
        "phase": "assert",
        "adb_args": ["shell", "pm", "get-app-links", "com.example.target"],
        "stdout_contains": ["Session active"],
    }


def test_fixture_state_requires_a_real_predicate() -> None:
    with pytest.raises(ValueError, match="state_fixture_id"):
        AgentRequestedTest.model_validate(
            {
                "hypothesis_id": "11111111-1111-1111-1111-111111111111",
                "entry_point_id": "22222222-2222-2222-2222-222222222222",
                "state": "fixture",
                "rationale": "Replay from an authenticated account",
            }
        )
    with pytest.raises(ValueError, match="output predicate"):
        ValidationFixtureCreate.model_validate(
            {
                "scan_id": "11111111-1111-1111-1111-111111111111",
                "name": "account",
                "fixture_type": "account",
                "payload": {
                    "state_check": {**_fixture_check(), "stdout_contains": []},
                },
            }
        )
    with pytest.raises(ValueError, match="no executable state_check"):
        fixture_state_check({}, "fixture-1")
    with pytest.raises(ValueError, match="live device state"):
        fixture_state_check(
            {"state_check": {**_fixture_check(), "adb_args": ["shell", "echo", "Session active"]}},
            "fixture-1",
        )


def test_requested_fixture_state_must_be_active_for_task() -> None:
    fixture_id = "33333333-3333-3333-3333-333333333333"
    request = AgentRequestedTest.model_validate(
        {
            "hypothesis_id": "11111111-1111-1111-1111-111111111111",
            "entry_point_id": "22222222-2222-2222-2222-222222222222",
            "state": "fixture",
            "state_fixture_id": fixture_id,
            "rationale": "Test an authenticated session",
        }
    )
    entry = EntryPoint(
        id=request.entry_point_id,
        kind="activity",
        name="com.example.target.MainActivity",
        exported=True,
    )
    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request], [entry], hypothesis_ids={request.hypothesis_id}
    )
    assert not accepted
    assert any("fixture" in gap for gap in gaps)
    accepted, gaps = ScanOrchestrator._validate_requested_tests(
        [request],
        [entry],
        hypothesis_ids={request.hypothesis_id},
        fixture_ids={fixture_id},
    )
    assert accepted == [request]
    assert not gaps


def test_dynamic_experiment_verifies_fixture_before_attack_and_rechecks_on_resume(
    settings, monkeypatch  # noqa: ANN001
) -> None:
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    adapter = AdbDeviceAdapter(settings, ToolRunner(10), serial="device-1")
    service = DynamicExperimentService(
        database,
        EvidenceRecorder(ArtifactStore(settings)),
        AdbDevicePool([adapter]),
    )
    outputs = iter(
        [
            CommandResult(["adb", "state"], 0, "Session active", ""),
            CommandResult(["adb", "attack"], 0, "WAITING", ""),
            CommandResult(["adb", "state"], 0, "Session expired", ""),
        ]
    )
    calls: list[list[str]] = []

    def execute(args, **_kwargs):  # noqa: ANN001, ANN202
        calls.append(list(args))
        return next(outputs)

    monkeypatch.setattr(adapter, "execute_gateway", execute)
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            status="final",
            artifact_sha256="a" * 64,
            artifact_path="fixture.apk",
        )
        session.add(scan)
        session.flush()
        fixture = ValidationFixture(
            scan_id=scan.id,
            name="logged-in",
            fixture_type="account",
            payload={"state_check": _fixture_check()},
        )
        session.add(fixture)
        session.flush()
        capsule = DynamicExperimentCapsule(
            scan_id=scan.id,
            name="authenticated attack",
            objective="Only execute in a verified session",
            fixture_ids=[fixture.id],
            steps=[
                {
                    "id": "attack",
                    "title": "Run attack",
                    "phase": "action",
                    "adb_args": ["get-state"],
                    "stdout_contains": ["ready"],
                }
            ],
        )
        session.add(capsule)
        session.commit()
        capsule_id = capsule.id

    first = service.run_on_leased_device(capsule_id, adapter)
    assert first.status == "paused"
    assert first.result_json["failed_step_ids"] == ["attack"]
    second = service.run_on_leased_device(capsule_id, adapter)
    assert second.status == "paused"
    assert second.result_json["failed_step_ids"] == [f"fixture:{fixture.id}"]
    assert len(calls) == 3  # The attack was never retried after session expiry.
    with database.session_factory() as session:
        receipts = list(
            session.scalars(
                select(DynamicExperimentReceipt).where(
                    DynamicExperimentReceipt.capsule_id == capsule_id
                )
            )
        )
    assert [receipt.status for receipt in receipts] == ["passed", "failed", "failed"]


def test_dynamic_experiment_rejects_text_only_fixture(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    adapter = AdbDeviceAdapter(settings, ToolRunner(10), serial="device-1")
    service = DynamicExperimentService(
        database,
        EvidenceRecorder(ArtifactStore(settings)),
        AdbDevicePool([adapter]),
    )
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            status="final",
            artifact_sha256="a" * 64,
            artifact_path="fixture.apk",
        )
        session.add(scan)
        session.flush()
        fixture = ValidationFixture(
            scan_id=scan.id,
            name="instructions-only",
            fixture_type="account",
            setup_instructions=["Sign in manually"],
        )
        session.add(fixture)
        session.flush()
        capsule = DynamicExperimentCapsule(
            scan_id=scan.id,
            name="unsafe fixture experiment",
            objective="Must reject unverified state",
            fixture_ids=[fixture.id],
            steps=[
                {"id": "attack", "title": "Attack", "adb_args": ["get-state"]}
            ],
        )
        session.add(capsule)
        session.commit()
        capsule_id = capsule.id
    result = service.run_on_leased_device(capsule_id, adapter)
    assert result.status == "failed"
    assert "no executable state_check" in (result.error or "")
