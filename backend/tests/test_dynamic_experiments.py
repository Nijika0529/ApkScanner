from __future__ import annotations

from dataclasses import replace

from apkscanner.core.db import Database
from apkscanner.core.evidence import EvidenceRecorder
from apkscanner.core.models import (
    DynamicExperimentCapsule,
    DynamicExperimentReceipt,
    Evidence,
    Finding,
    RuntimeObservation,
    Scan,
)
from apkscanner.core.schemas import DynamicExperimentCreate
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.platform.tools import CommandResult, ToolRunner
from apkscanner.runtime.dynamic_experiments import DynamicExperimentService
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

    from apkscanner.runtime.device import AdbDeviceAdapter, AdbDevicePool

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
            status="final",
            filename="fixture.apk",
            artifact_sha256="a" * 64,
            artifact_path="fixture.apk",
            stats={
                "finding_count": 0,
                "signal_count": 1,
                "seal": {"evidence_id": "old-seal", "sha256": "b" * 64},
            },
        )
        session.add(scan)
        session.flush()
        finding = Finding(
            scan_id=scan.id,
            dedupe_key="dynamic-failed-assertion",
            rule_id="AGENT",
            title="Callback candidate",
            description="The callback assertion has not passed yet.",
            masvs="MASVS-PLATFORM",
            severity="medium",
            status="not_reproduced",
        )
        session.add(finding)
        session.flush()
        capsule = DynamicExperimentCapsule(
            scan_id=scan.id,
            finding_id=finding.id,
            name=payload.name,
            objective=payload.objective,
            steps=[item.model_dump(mode="json") for item in payload.steps],
            cleanup_steps=[item.model_dump(mode="json") for item in payload.cleanup_steps],
        )
        session.add(capsule)
        session.commit()
        capsule_id = capsule.id
        finding_id = finding.id

    first = service.run(capsule_id)
    assert first.status == "paused"
    assert first.result_json["failed_step_ids"] == ["callback"]
    with database.session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "not_reproduced"
    second = service.run(capsule_id)
    assert second.status == "completed"
    assert second.result_json["cleanup_complete"] is True
    with database.session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "runtime_observed_unverified"
        scan = session.get(Scan, finding.scan_id)
        assert scan is not None
        assert scan.stats["seal"]["current"] is False
        assert scan.stats["materialized_summary"]["current"] is False
        assert "finding_count" not in scan.stats
        assert "signal_count" not in scan.stats
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


def test_dynamic_experiment_satisfies_only_a_structured_impact_contract(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="device-1",
        adb_serials=("device-1",),
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)

    from apkscanner.runtime.device import AdbDeviceAdapter, AdbDevicePool

    adapter = AdbDeviceAdapter(configured, ToolRunner(30), serial="device-1")
    service = DynamicExperimentService(
        database,
        EvidenceRecorder(store),
        AdbDevicePool([adapter]),
    )
    outputs = iter(
        [
            CommandResult(["adb", "trigger"], 0, "TRIGGERED", ""),
            CommandResult(["adb", "observe"], 0, "TOKEN=fixture-secret", ""),
            CommandResult(["adb", "cleanup"], 0, "", ""),
        ]
    )
    executed_args: list[list[str]] = []

    def execute_gateway(args, **_kwargs):  # noqa: ANN001, ANN202
        executed_args.append(list(args))
        return next(outputs)

    monkeypatch.setattr(adapter, "execute_gateway", execute_gateway)
    payload = DynamicExperimentCreate.model_validate(
        {
            "name": "token callback proof",
            "objective": "Trigger the flow and independently observe the returned token.",
            "impact_contract": {
                "contract_id": "semantic:token.callback",
                "impact": "unauthorized_data_access",
                "observed_fact": "A token value was returned to the untrusted caller.",
                "assertion_step_ids": ["assert-token"],
                "observation_kinds": ["token.callback"],
            },
            "steps": [
                {
                    "id": "trigger",
                    "title": "Trigger target flow",
                    "phase": "action",
                    "adb_args": [
                        "shell",
                        "am",
                        "start",
                        "-W",
                        "-d",
                        "https://example.test/callback?a=1&b=2",
                        "-n",
                        "com.example/.Outer$Inner",
                    ],
                    "stdout_contains": ["TRIGGERED"],
                },
                {
                    "id": "assert-token",
                    "title": "Observe token callback",
                    "phase": "assert",
                    "adb_args": ["shell", "logcat", "-d", "-s", "TARGET_CALLBACK"],
                    "stdout_regex": "TOKEN=.+",
                    "observation_kind": "token.callback",
                },
            ],
            "cleanup_steps": [
                {
                    "id": "cleanup",
                    "title": "Remove temporary state",
                    "phase": "cleanup",
                    "adb_args": ["shell", "true"],
                }
            ],
        }
    )
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            artifact_sha256="b" * 64,
            artifact_path="fixture.apk",
        )
        session.add(scan)
        session.flush()
        capsule = DynamicExperimentCapsule(
            scan_id=scan.id,
            name=payload.name,
            objective=payload.objective,
            impact_contract=payload.impact_contract,
            steps=[item.model_dump(mode="json") for item in payload.steps],
            cleanup_steps=[item.model_dump(mode="json") for item in payload.cleanup_steps],
        )
        session.add(capsule)
        session.commit()
        capsule_id = capsule.id

    completed = service.run_on_leased_device(capsule_id, adapter)
    assert completed.status == "completed"
    assert completed.result_json["agent_assertion_contract_matched"] is True
    assert completed.result_json["platform_oracle_validated"] is False
    assert completed.result_json["harm_demonstrated"] is False
    assert executed_args[0][-2:] == ["-n", "'com.example/.Outer$Inner'"]
    assert "'https://example.test/callback?a=1&b=2'" in executed_args[0]
    with database.session_factory() as session:
        assert_evidence = session.scalar(
            select(Evidence).where(
                Evidence.scan_id == completed.scan_id,
                Evidence.kind == "dynamic_experiment.adb",
                Evidence.metadata_json["step_id"].as_string() == "assert-token",
            )
        )
        observations = list(
            session.scalars(
                select(RuntimeObservation).where(RuntimeObservation.scan_id == completed.scan_id)
            )
        )
    assert assert_evidence is not None
    assert assert_evidence.metadata_json["agent_assertion_contract_matched"] is True
    assert assert_evidence.metadata_json["platform_oracle_validated"] is False
    assert assert_evidence.metadata_json["impact_contract_satisfied"] is False
    assert (
        assert_evidence.metadata_json["agent_claimed_oracle"]["observed_fact"]["kind"]
        == "token.callback"
    )
    assert [item.kind for item in observations] == ["token.callback"]


def test_dynamic_experiment_rejects_host_file_transfer_before_gateway_execution(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        adb_serial="device-1",
        adb_serials=("device-1",),
    )
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)

    from apkscanner.runtime.device import AdbDeviceAdapter, AdbDevicePool

    adapter = AdbDeviceAdapter(configured, ToolRunner(30), serial="device-1")
    service = DynamicExperimentService(
        database,
        EvidenceRecorder(store),
        AdbDevicePool([adapter]),
    )
    gateway_calls: list[list[str]] = []

    def execute_gateway(args, *_args, **_kwargs):  # noqa: ANN001, ANN202
        gateway_calls.append(list(args))
        return CommandResult(["adb", *args], 0, "", "")

    monkeypatch.setattr(adapter, "execute_gateway", execute_gateway)
    payload = DynamicExperimentCreate.model_validate(
        {
            "name": "forbidden host transfer",
            "objective": "Attempt to transfer a host file through a persisted Agent plan.",
            "steps": [
                {
                    "id": "safe-action",
                    "title": "Read device state",
                    "phase": "action",
                    "adb_args": ["get-state"],
                }
            ],
            "cleanup_steps": [
                {
                    "id": "escape",
                    "title": "Push an arbitrary host file during cleanup",
                    "phase": "cleanup",
                    "adb_args": [
                        "${operation}",
                        "/etc/passwd",
                        "/data/local/tmp/input",
                    ],
                }
            ],
        }
    )
    with database.session_factory() as session:
        scan = Scan(
            filename="fixture.apk",
            artifact_sha256="c" * 64,
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
            state_json={"operation": "push"},
        )
        session.add(capsule)
        session.commit()
        capsule_id = capsule.id

    completed = service.run_on_leased_device(capsule_id, adapter)

    assert completed.status == "failed"
    assert completed.result_json["resumable"] is False
    assert completed.result_json["failure_stage"] == "policy_validation"
    assert gateway_calls == []
    with database.session_factory() as session:
        capsule = session.get(DynamicExperimentCapsule, capsule_id)
        receipts = list(
            session.scalars(
                select(DynamicExperimentReceipt).where(
                    DynamicExperimentReceipt.capsule_id == capsule_id
                )
            )
        )
    assert capsule is not None
    assert capsule.status == "failed"
    assert receipts == []
