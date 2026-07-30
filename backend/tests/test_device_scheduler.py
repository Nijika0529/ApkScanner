from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.device import (
    AdbDeviceAdapter,
    DeviceLeaseCancelledError,
    SingleDeviceScheduler,
)
from apkscanner.models import EntryPoint
from apkscanner.schemas import AgentOracleSpec, AgentPocSpec
from apkscanner.tools import CommandResult


def test_single_device_scheduler_orders_waiters_by_priority_then_fifo() -> None:
    scheduler = SingleDeviceScheduler()
    active_acquired = threading.Event()
    release_active = threading.Event()
    low_queued = threading.Event()
    high_queued = threading.Event()
    acquisition_order: list[str] = []

    def hold_active() -> None:
        with scheduler.lease(
            "active",
            priority=50,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: active_acquired.set(),
        ):
            assert release_active.wait(timeout=5)

    def wait_for_device(
        task_id: str,
        priority: int,
        queued: threading.Event,
    ) -> None:
        with scheduler.lease(
            task_id,
            priority=priority,
            cancel_event=threading.Event(),
            on_queued=lambda _position: queued.set(),
        ):
            acquisition_order.append(task_id)

    active = threading.Thread(target=hold_active)
    active.start()
    assert active_acquired.wait(timeout=5)

    low = threading.Thread(target=wait_for_device, args=("low", 70, low_queued))
    high = threading.Thread(target=wait_for_device, args=("high", 95, high_queued))
    low.start()
    assert low_queued.wait(timeout=5)
    high.start()
    assert high_queued.wait(timeout=5)

    snapshot = scheduler.snapshot()
    assert [item["task_id"] for item in snapshot["waiting"]] == ["high", "low"]
    release_active.set()
    for worker in (active, low, high):
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert acquisition_order == ["high", "low"]
    assert scheduler.snapshot() == {"active_task_id": None, "waiting": []}


def test_waiting_device_lease_can_be_cancelled_without_acquiring() -> None:
    scheduler = SingleDeviceScheduler()
    active_acquired = threading.Event()
    release_active = threading.Event()
    waiting_queued = threading.Event()
    cancel_event = threading.Event()
    cancelled: list[bool] = []
    acquired: list[bool] = []

    def hold_active() -> None:
        with scheduler.lease(
            "active",
            priority=50,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: active_acquired.set(),
        ):
            assert release_active.wait(timeout=5)

    def wait_and_cancel() -> None:
        try:
            with scheduler.lease(
                "waiting",
                priority=90,
                cancel_event=cancel_event,
                on_queued=lambda _position: waiting_queued.set(),
            ):
                acquired.append(True)
        except DeviceLeaseCancelledError:
            cancelled.append(True)

    active = threading.Thread(target=hold_active)
    active.start()
    assert active_acquired.wait(timeout=5)
    waiting = threading.Thread(target=wait_and_cancel)
    waiting.start()
    assert waiting_queued.wait(timeout=5)

    cancel_event.set()
    scheduler.wake_waiters()
    waiting.join(timeout=5)
    assert not waiting.is_alive()
    assert cancelled == [True]
    assert acquired == []
    assert scheduler.snapshot()["waiting"] == []

    release_active.set()
    active.join(timeout=5)
    assert not active.is_alive()


def test_queue_callback_failure_does_not_poison_the_device_queue() -> None:
    scheduler = SingleDeviceScheduler()

    def fail_queue_callback(_position: int) -> None:
        raise RuntimeError("database callback failed")

    with (
        pytest.raises(RuntimeError, match="database callback failed"),
        scheduler.lease(
            "failed",
            priority=90,
            cancel_event=threading.Event(),
            on_queued=fail_queue_callback,
        ),
    ):
        raise AssertionError("failed queue callback must not acquire the device")

    assert scheduler.snapshot() == {"active_task_id": None, "waiting": []}
    with scheduler.lease(
        "next",
        priority=80,
        cancel_event=threading.Event(),
    ):
        assert scheduler.snapshot()["active_task_id"] == "next"


def test_health_capability_does_not_enter_an_active_device_session(settings) -> None:  # noqa: ANN001
    class NoAdbRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN205
            raise AssertionError("health check must not run ADB during an active lease")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        NoAdbRunner(),  # type: ignore[arg-type]
    )
    acquired = threading.Event()
    release = threading.Event()

    def hold_device() -> None:
        with adapter.task_lease(
            "active",
            priority=90,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: acquired.set(),
        ):
            assert release.wait(timeout=5)

    worker = threading.Thread(target=hold_device)
    worker.start()
    assert acquired.wait(timeout=5)
    capability = adapter.capability(non_blocking=True)
    assert capability["available"] is True
    assert capability["busy"] is True
    assert capability["active_task_id"] == "active"
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()


def test_active_task_allows_live_replay_thread_to_take_command_lock(settings) -> None:  # noqa: ANN001
    class NoAdbRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        NoAdbRunner(),  # type: ignore[arg-type]
    )
    task_acquired = threading.Event()
    replay_completed = threading.Event()
    release_task = threading.Event()

    def hold_task() -> None:
        with adapter.task_lease(
            "active",
            priority=90,
            cancel_event=threading.Event(),
            on_acquired=lambda _waited: task_acquired.set(),
        ):
            assert release_task.wait(timeout=5)

    def replay_command() -> None:
        with adapter.lease():
            replay_completed.set()

    task_thread = threading.Thread(target=hold_task)
    task_thread.start()
    assert task_acquired.wait(timeout=5)
    replay_thread = threading.Thread(target=replay_command)
    replay_thread.start()
    assert replay_completed.wait(timeout=5)
    replay_thread.join(timeout=5)
    assert not replay_thread.is_alive()
    assert adapter.scheduler.snapshot()["active_task_id"] == "active"
    release_task.set()
    task_thread.join(timeout=5)
    assert not task_thread.is_alive()


def test_non_blocking_health_probe_does_not_wait_behind_an_adb_command(settings) -> None:  # noqa: ANN001
    class NoAdbRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN205
            raise AssertionError("non-blocking capability must not run or wait for ADB")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        NoAdbRunner(),  # type: ignore[arg-type]
    )
    acquired = threading.Event()
    release = threading.Event()

    def hold_command_lock() -> None:
        with adapter.lease():
            acquired.set()
            assert release.wait(timeout=5)

    worker = threading.Thread(target=hold_command_lock)
    worker.start()
    assert acquired.wait(timeout=5)
    capability = adapter.capability(non_blocking=True)
    assert capability["available"] is True
    assert capability["busy"] is True
    assert capability["active_task_id"] is None
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()


def test_device_prepare_stops_after_failed_health_check(settings) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    class FailingRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            calls.append(argv)
            return CommandResult(argv, 1, "", "device unavailable")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        FailingRunner(),  # type: ignore[arg-type]
    )

    commands = adapter.prepare(Path("/tmp/sample.apk"), "com.example.app")

    assert [kind for kind, _result, _metadata in commands] == ["device.health"]
    assert len(calls) == 1


def test_non_blocking_device_health_reuses_recent_failure(settings) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    class FailingRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            calls.append(argv)
            return CommandResult(argv, 1, "", "device unavailable")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        FailingRunner(),  # type: ignore[arg-type]
    )

    first = adapter.capability(non_blocking=True)
    second = adapter.capability(non_blocking=True)

    assert first["available"] is False
    assert second["available"] is False
    assert second["cached"] is True
    assert len(calls) == 1


def test_device_prepare_stops_after_failed_install(settings) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    class InstallFailingRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            calls.append(argv)
            exit_code = 0 if argv[-1] == "get-state" else 1
            return CommandResult(argv, exit_code, "device" if exit_code == 0 else "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        InstallFailingRunner(),  # type: ignore[arg-type]
    )

    commands = adapter.prepare(Path("/tmp/sample.apk"), "com.example.app")

    assert [kind for kind, _result, _metadata in commands] == [
        "device.health",
        "device.package_status",
        "device.install",
    ]
    assert len(calls) == 3


def test_device_prepare_reuses_an_installed_system_package_after_install_failure(
    settings,
) -> None:  # noqa: ANN001
    class SystemPackageRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            if argv[-1] == "get-state":
                return CommandResult(argv, 0, "device", "")
            if argv[-3:] == ["pm", "path", "com.vendor.system"]:
                return CommandResult(argv, 0, "package:/system/app/System.apk", "")
            if "install" in argv:
                return CommandResult(argv, 1, "", "INSTALL_FAILED_UPDATE_INCOMPATIBLE")
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(
            settings,
            adb_serial="cloud-device:5555",
            device_install_policy="install_or_reuse",
        ),
        SystemPackageRunner(),  # type: ignore[arg-type]
    )

    commands = adapter.prepare(Path("/tmp/system.apk"), "com.vendor.system")
    by_kind = {kind: (result, metadata) for kind, result, metadata in commands}

    assert by_kind["device.install_attempt"][0].exit_code == 1
    assert by_kind["device.install"][0].exit_code == 0
    assert by_kind["device.install"][1]["install_mode"] == "reuse_after_install_failure"
    assert "device.clear" in by_kind


def test_typed_provider_oracle_emits_platform_impact_signal() -> None:
    oracle = AgentOracleSpec(
        kind="provider_rows",
        minimum_rows=1,
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_probe_oracle(
        oracle,
        probe_payload={"success": True, "rowCount": 3},
        output="",
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["matched"] is True
    assert metadata["oracle"]["observation"]["row_count"] == 3


def test_typed_provider_oracle_accepts_correlated_poc_row_count() -> None:
    oracle = AgentOracleSpec(
        kind="provider_rows",
        minimum_rows=1,
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_poc_oracle(
        oracle,
        poc_payload={
            "request_id": "request-1",
            "success": True,
            "security_impact_observed": True,
            "row_count": 2,
        },
        output="",
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["matched"] is True
    assert metadata["oracle"]["observation"]["row_count"] == 2


def test_provider_poc_claim_without_row_count_is_not_platform_proof() -> None:
    oracle = AgentOracleSpec(
        kind="provider_rows",
        minimum_rows=1,
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_poc_oracle(
        oracle,
        poc_payload={
            "request_id": "request-1",
            "success": True,
            "security_impact_observed": True,
        },
        output="leaked data claimed by the PoC",
    )

    assert metadata["security_impact_observed"] is False
    assert metadata["oracle"]["matched"] is False


def test_correlated_poc_log_oracle_can_report_structured_impact() -> None:
    oracle = AgentOracleSpec(
        kind="log_contains",
        expected_text="demo-password=hunter2",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_poc_oracle(
        oracle,
        poc_payload={
            "request_id": "request-1",
            "success": True,
            "security_impact_observed": True,
            "detail": "secret_disclosed:demo-password=hunter2",
        },
        output=(
            '{"request_id":"request-1","success":true,'
            '"security_impact_observed":true,'
            '"detail":"secret_disclosed:demo-password=hunter2"}'
        ),
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["matched"] is True


def test_poc_log_oracle_uses_all_correlated_json_lines() -> None:
    oracle = AgentOracleSpec(
        kind="log_contains",
        expected_text="security_impact_observed",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_poc_oracle(
        oracle,
        # The parser returns the final JSON object. A PoC may emit the concrete
        # successful step first and a summary without a success field last.
        poc_payload={
            "request_id": "request-1",
            "test": "summary",
            "security_impact_observed": True,
        },
        output=(
            '{"request_id":"request-1","test":"redirect",'
            '"success":true,"security_impact_observed":true}\n'
            '{"request_id":"request-1","test":"summary",'
            '"security_impact_observed":true}'
        ),
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["matched"] is True


def test_process_correlated_plain_poc_log_can_report_impact() -> None:
    oracle = AgentOracleSpec(
        kind="log_contains",
        expected_text="vault_secret=rescue-chain-secret",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_poc_oracle(
        oracle,
        poc_payload=None,
        output=(
            "I APKSCANNER_POC: vault_secret=rescue-chain-secret\n"
            "I APKSCANNER_POC: security_impact_observed=true"
        ),
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["matched"] is True


def test_poc_log_claim_without_expected_observation_is_not_proof() -> None:
    oracle = AgentOracleSpec(
        kind="log_contains",
        expected_text="demo-password=hunter2",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_poc_oracle(
        oracle,
        poc_payload={
            "request_id": "request-1",
            "success": True,
            "security_impact_observed": True,
            "detail": "no secret returned",
        },
        output='{"security_impact_observed":true,"detail":"no secret returned"}',
    )

    assert metadata["security_impact_observed"] is False
    assert metadata["oracle"]["matched"] is False


def test_missing_optional_probe_does_not_emit_a_failed_probe_broadcast(settings) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    class RecordingRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            calls.append(argv)
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555", probe_apk_path=None),
        RecordingRunner(),  # type: ignore[arg-type]
    )
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.MainActivity",
        exported=True,
    )

    result = adapter.probe(entry, "com.example")

    assert adapter.probe_ready is False
    assert [kind for kind, _result, _metadata in result.commands] == [
        "blackbox.adb_shell",
        "blackbox.ui_dump",
    ]
    assert not any("io.apkscanner.probe/.ProbeReceiver" in argv for argv in calls)


def test_dedicated_poc_collects_an_independent_platform_ui_oracle(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    class PocRunner:
        request_id = ""
        ui_dump_count = 0

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            if "apkscanner_request_id" in argv:
                cls.request_id = argv[argv.index("apkscanner_request_id") + 1]
            if "getprop" in argv:
                stdout = "33\n"
            elif "APKSCANNER_POC:V" in argv:
                stdout = (
                    f'I/APKSCANNER_POC: {{"request_id":"{cls.request_id}",'
                    '"success":true,"security_impact_observed":true}'
                )
            elif "uiautomator" in argv:
                cls.ui_dump_count += 1
                stdout = (
                    '<hierarchy><node package="com.example.target" text="" />'
                    "</hierarchy>"
                    if cls.ui_dump_count == 1
                    else (
                        '<hierarchy><node package="com.example.target" '
                        'text="Imported secret" /></hierarchy>'
                    )
                )
            else:
                stdout = ""
            return CommandResult(argv, 0, stdout, "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        PocRunner(),  # type: ignore[arg-type]
    )
    apk = tmp_path / "poc.apk"
    apk.write_bytes(b"APK")
    spec = AgentPocSpec(
        project_path="poc/test",
        package_name="io.apkscanner.poc.test",
        launch_component=".MainActivity",
        log_tag="APKSCANNER_POC",
    )
    oracle = AgentOracleSpec(
        kind="ui_text",
        expected_text="Imported secret",
        impact="unauthorized_data_access",
    )

    result = adapter.execute_poc(
        apk,
        spec,
        target_package_name="com.example.target",
        state="guest",
        oracle=oracle,
        test_case_id="agent-r1-1",
        build_metadata={"compile_api": 23, "min_api": 26, "target_api": 36},
    )
    by_kind = {
        kind: metadata for kind, _command_result, metadata in result.commands
    }

    assert by_kind["blackbox.poc_logcat"]["poc_success"] is True
    assert by_kind["blackbox.poc_logcat"]["poc_claimed_security_impact"] is True
    assert by_kind["blackbox.device_profile"]["device_api"] == "33"
    assert (
        by_kind["blackbox.device_profile"]["device_api_matches_poc_target"]
        is False
    )
    assert (
        by_kind["blackbox.device_profile"]["device_api_satisfies_poc_min"]
        is True
    )
    assert by_kind["blackbox.device_profile"]["poc_runtime_compatible"] is True
    assert "blackbox.poc_pre_uninstall" in by_kind
    assert "security_impact_observed" not in by_kind["blackbox.poc_logcat"]
    assert (
        by_kind["blackbox.poc_ui_baseline"]["target_text_present"]
        is False
    )
    assert by_kind["blackbox.poc_ui_dump"]["security_impact_observed"] is True
    assert by_kind["blackbox.poc_ui_dump"]["oracle"]["matched"] is True
    assert (
        by_kind["blackbox.poc_ui_dump"]["oracle"]["observation"][
            "target_text_transition"
        ]
        is True
    )


def test_poc_log_collection_accepts_debug_priority(settings) -> None:  # noqa: ANN001
    class DebugLogRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            assert "APKSCANNER_POC:V" in argv
            return CommandResult(
                argv,
                0,
                (
                    "07-30 19:54:14.790 13786 13786 D APKSCANNER_POC: "
                    '{"apkscanner_request_id":"request-debug",'
                    '"success":true,"security_impact_observed":true}'
                ),
                "",
            )

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        DebugLogRunner(),  # type: ignore[arg-type]
    )

    _result, matching, attempts, _elapsed = adapter._poll_poc_logcat(
        log_tag="APKSCANNER_POC",
        request_id="request-debug",
        timeout_seconds=5,
        budget=None,
    )

    assert len(matching) == 1
    assert attempts == 1


def test_poc_log_evidence_waits_for_delayed_correlated_result(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    class DelayedLogRunner:
        attempts = 0

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.attempts += 1
            stdout = (
                'I/APKSCANNER_POC: {"request_id":"request-1","success":true}'
                if cls.attempts == 2
                else ""
            )
            return CommandResult(argv, 0, stdout, "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        DelayedLogRunner(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr("apkscanner.device.time.sleep", lambda _seconds: None)

    result, matching, attempts, _elapsed = adapter._poll_poc_logcat(
        log_tag="APKSCANNER_POC",
        request_id="request-1",
        timeout_seconds=5,
        budget=None,
    )

    assert result.exit_code == 0
    assert len(matching) == 1
    assert attempts == 2


def test_poc_log_accepts_lines_from_the_launched_poc_process(
    settings,
) -> None:  # noqa: ANN001
    class ProcessLogRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            return CommandResult(
                argv,
                0,
                (
                    "07-30 17:51:49.595 20460 20460 I APKSCANNER_POC: "
                    "security_impact_observed=true\n"
                ),
                "",
            )

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        ProcessLogRunner(),  # type: ignore[arg-type]
    )

    _result, matching, attempts, _elapsed = adapter._poll_poc_logcat(
        log_tag="APKSCANNER_POC",
        request_id="not-logged-by-agent",
        process_ids={"20460"},
        timeout_seconds=5,
        budget=None,
    )

    assert len(matching) == 1
    assert attempts == 1


def test_poc_log_does_not_stop_on_an_intermediate_negative_result(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    class IntermediateLogRunner:
        attempts = 0

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.attempts += 1
            impact = "true" if cls.attempts == 2 else "false"
            return CommandResult(
                argv,
                0,
                (
                    "07-30 17:51:49.595 20460 20460 I APKSCANNER_POC: "
                    f'{{"success":true,"security_impact_observed":{impact}}}\n'
                ),
                "",
            )

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        IntermediateLogRunner(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr("apkscanner.device.time.sleep", lambda _seconds: None)

    _result, matching, attempts, _elapsed = adapter._poll_poc_logcat(
        log_tag="APKSCANNER_POC",
        request_id="not-logged-by-agent",
        process_ids={"20460"},
        wait_for_security_impact=True,
        timeout_seconds=5,
        budget=None,
    )

    assert len(matching) == 1
    assert '"security_impact_observed":true' in matching[0]
    assert attempts == 2


def test_poc_owned_ui_cannot_forge_a_target_security_impact() -> None:
    oracle = AgentOracleSpec(
        kind="ui_text",
        expected_text="Imported secret",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_ui_oracle(
        oracle,
        (
            '<hierarchy><node package="io.apkscanner.poc.test" '
            'text="Imported secret" /></hierarchy>'
        ),
        package_name="com.example.target",
        baseline_output=(
            '<hierarchy><node package="com.example.target" text="" /></hierarchy>'
        ),
        baseline_valid=True,
    )

    assert metadata["oracle"]["matched"] is False
    assert metadata["security_impact_observed"] is False


def test_preexisting_target_ui_text_is_not_a_new_impact() -> None:
    oracle = AgentOracleSpec(
        kind="ui_text",
        expected_text="Imported secret",
        impact="unauthorized_data_access",
    )
    target_ui = (
        '<hierarchy><node package="com.example.target" '
        'text="Imported secret" /></hierarchy>'
    )

    metadata = AdbDeviceAdapter._evaluate_ui_oracle(
        oracle,
        target_ui,
        package_name="com.example.target",
        baseline_output=target_ui,
        baseline_valid=True,
    )

    assert metadata["oracle"]["matched"] is True
    assert (
        metadata["oracle"]["observation"]["target_text_transition"]
        is False
    )
    assert metadata["security_impact_observed"] is False


def test_process_crash_oracle_requires_the_target_process() -> None:
    oracle = AgentOracleSpec(
        kind="process_crash",
        impact="denial_of_service",
    )
    unrelated = AdbDeviceAdapter._evaluate_target_log_oracle(
        oracle,
        (
            "Process: com.example.target, PID: 99\n"
            "FATAL EXCEPTION: main\n"
            "Process: io.apkscanner.poc.test, PID: 123\n"
            "noise mentioning com.example.target"
        ),
        "com.example.target",
    )
    target = AdbDeviceAdapter._evaluate_target_log_oracle(
        oracle,
        (
            "FATAL EXCEPTION: main\n"
            "Process: com.example.target:remote, PID: 456"
        ),
        "com.example.target",
    )

    assert unrelated["security_impact_observed"] is False
    assert target["security_impact_observed"] is True


def test_activity_deep_link_probe_preserves_uri_and_expected_component() -> None:
    entry = EntryPoint(
        id="11111111-1111-1111-1111-111111111111",
        scan_id="scan",
        kind="activity",
        name="com.example.LinkActivity",
        owner_component="com.example.LinkActivity",
        exported=True,
        deep_links=[
            {
                "scheme": "example",
                "host": "open",
                "uri_template": "example://open/path",
            }
        ],
    )

    request = AdbDeviceAdapter._probe_request(
        entry,
        "com.example",
        uri_override="example://open/path?source=test",
        extras={":settings:fragment_args_key": "privacy"},
    )

    assert request == {
        "kind": "deep_link",
        "package": "com.example",
        "component": "com.example.LinkActivity",
        "uri": "example://open/path?source=test",
        "extras": {":settings:fragment_args_key": "privacy"},
    }
