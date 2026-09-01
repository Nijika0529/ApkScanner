from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.core.config import Settings
from apkscanner.core.models import EntryPoint
from apkscanner.core.schemas import AgentOracleSpec, AgentPocSpec
from apkscanner.platform.tools import CommandResult, ToolRunner
from apkscanner.runtime.device import (
    AdbDeviceAdapter,
    AdbDevicePool,
    DeviceLeaseCancelledError,
    DevicePoolScheduler,
    SingleDeviceScheduler,
)


def test_settings_parse_a_comma_separated_device_pool(
    monkeypatch,
    tmp_path: Path,
) -> None:  # noqa: ANN001
    monkeypatch.setenv("APKSCANNER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(
        "APKSCANNER_ADB_SERIALS",
        "device-a, device-b,device-a",
    )
    monkeypatch.delenv("APKSCANNER_ADB_SERIAL", raising=False)

    settings = Settings.from_env()

    assert settings.adb_serial == "device-a"
    assert settings.configured_adb_serials == ("device-a", "device-b")


def test_settings_accept_an_absolute_host_adb_executable(
    monkeypatch,
    tmp_path: Path,
) -> None:  # noqa: ANN001
    monkeypatch.setenv("APKSCANNER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APKSCANNER_HOST_ADB", "/opt/android/platform-tools/adb")

    settings = Settings.from_env()

    assert settings.host_adb_executable == "/opt/android/platform-tools/adb"


def test_settings_parse_an_independent_exploration_phase_budget(
    monkeypatch,
    tmp_path: Path,
) -> None:  # noqa: ANN001
    monkeypatch.setenv("APKSCANNER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APKSCANNER_AGENT_INITIAL_PHASE_SECONDS", "900")
    monkeypatch.setenv("APKSCANNER_AGENT_EXPLORATION_PHASE_SECONDS", "725")

    settings = Settings.from_env()

    assert settings.agent_initial_phase_seconds == 900
    assert settings.agent_exploration_phase_seconds == 725


def test_settings_reject_a_relative_host_adb_executable(
    monkeypatch,
    tmp_path: Path,
) -> None:  # noqa: ANN001
    monkeypatch.setenv("APKSCANNER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APKSCANNER_HOST_ADB", "adb")

    with pytest.raises(ValueError, match="absolute executable path"):
        Settings.from_env()


def test_ui_observation_window_adapts_to_recent_adb_latency(settings) -> None:  # noqa: ANN001
    adapter = AdbDeviceAdapter(settings, object())  # type: ignore[arg-type]

    assert adapter._adaptive_ui_observation_window(5) == 15.0
    adapter._ui_dump_latencies.extend([3.0, 4.0, 5.0])
    assert adapter._adaptive_ui_observation_window(5) == 21.0
    assert adapter._adaptive_ui_observation_window(90) == 90.0


def test_fully_leased_device_pool_is_busy_but_still_available() -> None:
    class AvailableRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

    class FakeAdapter:
        def __init__(self, serial: str) -> None:
            self.serial = serial
            self.runner = AvailableRunner()
            self._active_cancel_event = None

        @staticmethod
        def capability(*, non_blocking: bool = False) -> dict:  # noqa: ARG004
            raise AssertionError("busy pool health must not issue an ADB command")

    pool = AdbDevicePool(
        [FakeAdapter("device-a"), FakeAdapter("device-b")]  # type: ignore[list-item]
    )
    both_acquired = threading.Event()
    release = threading.Event()
    acquired_count = 0
    acquired_lock = threading.Lock()

    def hold(task_id: str) -> None:
        nonlocal acquired_count
        with pool.task_lease(
            task_id,
            priority=90,
            cancel_event=threading.Event(),
        ):
            with acquired_lock:
                acquired_count += 1
                if acquired_count == 2:
                    both_acquired.set()
            assert release.wait(timeout=5)

    workers = [threading.Thread(target=hold, args=(f"task-{index}",)) for index in range(2)]
    for worker in workers:
        worker.start()
    assert both_acquired.wait(timeout=5)

    capability = pool.capability(non_blocking=True)
    assert capability["available"] is True
    assert capability["busy"] is True
    assert set(capability["active"]) == {"device-a", "device-b"}

    release.set()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()


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


def test_device_pool_assigns_two_tasks_to_distinct_devices() -> None:
    scheduler = DevicePoolScheduler(("device-a", "device-b"))
    both_acquired = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    assignments: dict[str, str] = {}

    def hold(task_id: str) -> None:
        with scheduler.lease(
            task_id,
            priority=90,
            cancel_event=threading.Event(),
        ) as lease:
            with lock:
                assignments[task_id] = lease["serial"]
                if len(assignments) == 2:
                    both_acquired.set()
            assert release.wait(timeout=5)

    workers = [threading.Thread(target=hold, args=(f"task-{index}",)) for index in range(2)]
    for worker in workers:
        worker.start()
    assert both_acquired.wait(timeout=5)
    assert set(assignments.values()) == {"device-a", "device-b"}
    assert scheduler.snapshot()["active"] == {
        assignments["task-0"]: "task-0",
        assignments["task-1"]: "task-1",
    }

    release.set()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert scheduler.snapshot() == {
        "capacity": 2,
        "active": {},
        "waiting": [],
    }


def test_device_pool_preserves_sticky_serial_without_blocking_other_work() -> None:
    scheduler = DevicePoolScheduler(("device-a", "device-b"))
    release_a = threading.Event()
    a_acquired = threading.Event()
    sticky_queued = threading.Event()
    sticky_acquired = threading.Event()
    flexible_acquired = threading.Event()
    assignments: dict[str, str] = {}

    def hold_a() -> None:
        with scheduler.lease(
            "holder",
            priority=100,
            cancel_event=threading.Event(),
            preferred_serial="device-a",
        ) as lease:
            assignments["holder"] = lease["serial"]
            a_acquired.set()
            assert release_a.wait(timeout=5)

    def sticky() -> None:
        with scheduler.lease(
            "sticky",
            priority=95,
            cancel_event=threading.Event(),
            preferred_serial="device-a",
            on_queued=lambda _position: sticky_queued.set(),
        ) as lease:
            assignments["sticky"] = lease["serial"]
            sticky_acquired.set()

    def flexible() -> None:
        with scheduler.lease(
            "flexible",
            priority=90,
            cancel_event=threading.Event(),
        ) as lease:
            assignments["flexible"] = lease["serial"]
            flexible_acquired.set()

    holder = threading.Thread(target=hold_a)
    holder.start()
    assert a_acquired.wait(timeout=5)
    sticky_worker = threading.Thread(target=sticky)
    flexible_worker = threading.Thread(target=flexible)
    sticky_worker.start()
    assert sticky_queued.wait(timeout=5)
    flexible_worker.start()

    assert flexible_acquired.wait(timeout=5)
    assert assignments["flexible"] == "device-b"
    assert not sticky_acquired.is_set()
    release_a.set()
    assert sticky_acquired.wait(timeout=5)
    assert assignments["sticky"] == "device-a"
    for worker in (holder, sticky_worker, flexible_worker):
        worker.join(timeout=5)
        assert not worker.is_alive()


def test_device_pool_can_expand_and_drain_without_interrupting_an_active_lease() -> None:
    scheduler = DevicePoolScheduler(("device-a",))
    release = threading.Event()
    acquired = threading.Event()

    def hold() -> None:
        with scheduler.lease(
            "task-a",
            priority=90,
            cancel_event=threading.Event(),
        ):
            acquired.set()
            assert release.wait(timeout=5)

    worker = threading.Thread(target=hold)
    worker.start()
    assert acquired.wait(timeout=5)
    assert scheduler.drain_serial("device-a") is True
    assert scheduler.snapshot()["active"] == {"device-a": "task-a"}
    scheduler.add_serial("device-b")
    with scheduler.lease(
        "task-b",
        priority=80,
        cancel_event=threading.Event(),
    ) as lease:
        assert lease["serial"] == "device-b"
    assert scheduler.remove_serial("device-a") is False
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert scheduler.remove_serial("device-a") is True


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
    assert capability["android16_verdict_eligible"] is False
    assert capability["dynamic_verdict_eligible"] is False
    assert capability["release_gate_eligible"] is False
    assert capability["compatibility_smoke_only"] is False
    assert capability["validation_profile"] == settings.validation_profile
    assert capability["verdict_scope"] == "unavailable"
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
    assert capability["android16_verdict_eligible"] is False
    assert capability["dynamic_verdict_eligible"] is False
    assert capability["release_gate_eligible"] is False
    assert capability["compatibility_smoke_only"] is False
    assert capability["validation_profile"] == settings.validation_profile
    assert capability["verdict_scope"] == "unavailable"
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
    assert first["android16_verdict_eligible"] is False
    assert first["dynamic_verdict_eligible"] is False
    assert first["release_gate_eligible"] is False
    assert first["compatibility_smoke_only"] is False
    assert first["validation_profile"] == settings.validation_profile
    assert first["verdict_scope"] == "unavailable"
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
            device_reset_policy="per_round",
        ),
        SystemPackageRunner(),  # type: ignore[arg-type]
    )

    commands = adapter.prepare(Path("/tmp/system.apk"), "com.vendor.system")
    by_kind = {kind: (result, metadata) for kind, result, metadata in commands}

    assert by_kind["device.install_attempt"][0].exit_code == 1
    assert by_kind["device.install"][0].exit_code == 0
    assert by_kind["device.install"][1]["install_mode"] == "reuse_after_install_failure"
    assert "device.clear" in by_kind


def test_default_device_policy_preserves_target_application_data(settings) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    class PreserveRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            calls.append(argv)
            return CommandResult(argv, 0, "device", "")

    assert settings.device_reset_policy == "never"
    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        PreserveRunner(),  # type: ignore[arg-type]
    )

    prepare = adapter.prepare(Path("/tmp/sample.apk"), "com.example.target")
    cleanup = adapter.cleanup("com.example.target")

    assert all(kind != "device.clear" for kind, _result, _metadata in prepare)
    assert cleanup == []
    assert not any(command[-3:] == ["pm", "clear", "com.example.target"] for command in calls)


def test_opt_in_per_round_policy_still_clears_disposable_target(settings) -> None:  # noqa: ANN001
    class ResetRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            return CommandResult(argv, 0, "Success", "")

    adapter = AdbDeviceAdapter(
        replace(
            settings,
            adb_serial="cloud-device:5555",
            device_reset_policy="per_round",
        ),
        ResetRunner(),  # type: ignore[arg-type]
    )

    cleanup = adapter.cleanup("com.example.target")

    assert cleanup[0][0] == "device.clear"
    assert cleanup[0][1].argv[-3:] == ["pm", "clear", "com.example.target"]


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


def test_typed_binder_reply_oracle_emits_platform_impact_signal() -> None:
    oracle = AgentOracleSpec(
        kind="binder_reply",
        expected_text="service-secret=hunter2",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_probe_oracle(
        oracle,
        probe_payload={
            "success": True,
            "binderTransactReturned": True,
            "binderReplyType": "string",
            "binderReply": "service-secret=hunter2",
        },
        output="",
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["matched"] is True
    assert metadata["oracle"]["observation"]["actual_text"] == "service-secret=hunter2"


def test_binder_reply_claim_requires_successful_platform_transaction() -> None:
    oracle = AgentOracleSpec(
        kind="binder_reply",
        expected_text="service-secret=hunter2",
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_probe_oracle(
        oracle,
        probe_payload={
            "success": False,
            "binderTransactReturned": False,
            "binderReply": "service-secret=hunter2",
        },
        output="service-secret=hunter2",
    )

    assert metadata["security_impact_observed"] is False
    assert metadata["oracle"]["matched"] is False


def test_binder_script_oracle_matches_selected_reply_with_contains() -> None:
    oracle = AgentOracleSpec(
        kind="binder_reply",
        expected_text="hunter2",
        match_mode="contains",
        reply_index=1,
        impact="unauthorized_data_access",
    )

    metadata = AdbDeviceAdapter._evaluate_probe_oracle(
        oracle,
        probe_payload={
            "success": True,
            "binderTransactReturned": True,
            "binderReplies": [200, "service-secret=hunter2"],
        },
        output="",
    )

    assert metadata["security_impact_observed"] is True
    assert metadata["oracle"]["observation"]["reply_index"] == 1
    assert metadata["oracle"]["observation"]["match_mode"] == "contains"


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


def test_correlated_poc_log_oracle_is_not_independent_platform_impact() -> None:
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

    assert metadata["security_impact_observed"] is False
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

    assert metadata["security_impact_observed"] is False
    assert metadata["oracle"]["matched"] is True


def test_process_correlated_plain_poc_log_is_not_platform_impact() -> None:
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

    assert metadata["security_impact_observed"] is False
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


def test_target_uid_log_oracle_records_target_owned_reachability_only() -> None:
    oracle = AgentOracleSpec(
        kind="target_uid_log_contains",
        expected_text="APKSCANNER_TARGET_COMMAND_MARKER",
        impact="none",
    )
    output = (
        "07-30 22:11:02.460 10413 2423 2968 I APKSCANNER_TARGET: "
        "APKSCANNER_TARGET_COMMAND_MARKER\n"
        "07-30 22:11:03.000 10414 2500 2500 I APKSCANNER_POC: "
        "APKSCANNER_TARGET_COMMAND_MARKER"
    )

    matched = AdbDeviceAdapter._evaluate_target_log_oracle(
        oracle,
        output,
        "io.apkscanner.specialcases",
        target_uid=10413,
    )
    wrong_uid = AdbDeviceAdapter._evaluate_target_log_oracle(
        oracle,
        output,
        "io.apkscanner.specialcases",
        target_uid=99999,
    )

    assert matched["oracle"]["matched"] is True
    assert matched["oracle"]["observed_fact"]["fact_type"] == "target_uid_marker_observed"
    assert matched["security_impact_observed"] is False
    assert matched["impact_contract_satisfied"] is False
    assert wrong_uid["oracle"]["matched"] is False
    assert wrong_uid["security_impact_observed"] is False


def test_initial_probe_uses_only_shell_reachability(settings) -> None:  # noqa: ANN001
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
        replace(settings, adb_serial="cloud-device:5555"),
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

    assert [kind for kind, _result, _metadata in result.commands] == [
        "blackbox.adb_shell",
        "blackbox.ui_dump",
    ]
    assert not any("broadcast" in argv for argv in calls)


def test_execute_poc_rejects_target_package_collision_before_adb(
    settings,
    tmp_path: Path,
) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    class NoCallRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            calls.append(argv)
            raise AssertionError("package collision must fail before ADB is invoked")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        NoCallRunner(),  # type: ignore[arg-type]
    )
    apk = tmp_path / "colliding-poc.apk"
    apk.write_bytes(b"APK")
    spec = AgentPocSpec(
        project_path="poc/collision",
        package_name="io.apkscanner.poc.collision",
        launch_component=".MainActivity",
    )

    with pytest.raises(ValueError, match="must differ from the target package"):
        adapter.execute_poc(
            apk,
            spec,
            target_package_name=spec.package_name,
            state="guest",
        )

    assert calls == []


def test_oem_jump_prompt_prefers_one_time_open_and_removes_dump(settings) -> None:  # noqa: ANN001
    dump_path = "/data/local/tmp/apkscanner_oem_jump.dump"

    class PromptRunner:
        calls: list[list[str]] = []
        tapped = False

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.calls.append(argv)
            if argv[-4:-3] == ["input"] and argv[-3] == "tap":
                cls.tapped = True
                return CommandResult(argv, 0, "", "")
            if "uiautomator" in argv:
                return CommandResult(argv, 0, "UI hierarchy dumped", "")
            if argv[-2:] == ["cat", dump_path]:
                if cls.tapped:
                    return CommandResult(
                        argv,
                        0,
                        '<hierarchy><node package="com.example.target" /></hierarchy>',
                        "",
                    )
                return CommandResult(
                    argv,
                    0,
                    (
                        "<hierarchy>"
                        '<node package="com.vivo.appfilter" text="始终打开" '
                        'clickable="true" bounds="[0,0][100,100]" />'
                        '<node package="com.vivo.appfilter" text="仅打开一次" '
                        'resource-id="com.vivo.appfilter:id/once" clickable="true" '
                        'bounds="[200,20][400,120]" />'
                        "</hierarchy>"
                    ),
                    "",
                )
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        PromptRunner(),  # type: ignore[arg-type]
    )

    result = adapter._dismiss_oem_jump_prompt()

    assert result["detected"] is True
    assert result["dismissed"] is True
    assert result["button"] == "仅打开一次"
    assert result["tap_center"] == [300, 70]
    assert any(argv[-4:] == ["input", "tap", "300", "70"] for argv in PromptRunner.calls)
    assert PromptRunner.calls[-1][-3:] == ["rm", "-f", dump_path]
    assert all("/sdcard/oem_jump.dump" not in argv for argv in PromptRunner.calls)


def test_oem_jump_prompt_removes_dump_when_capture_fails(settings) -> None:  # noqa: ANN001
    dump_path = "/data/local/tmp/apkscanner_oem_jump.dump"

    class FailedDumpRunner:
        calls: list[list[str]] = []

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.calls.append(argv)
            if "uiautomator" in argv:
                return CommandResult(argv, 1, "", "dump failed")
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        FailedDumpRunner(),  # type: ignore[arg-type]
    )

    result = adapter._dismiss_oem_jump_prompt()

    assert result == {"detected": False, "reason": "dump_failed"}
    assert FailedDumpRunner.calls[-1][-3:] == ["rm", "-f", dump_path]


def test_oem_jump_prompt_does_not_accept_permanent_only_button(settings) -> None:  # noqa: ANN001
    dump_path = "/data/local/tmp/apkscanner_oem_jump.dump"

    class PermanentOnlyRunner:
        calls: list[list[str]] = []

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.calls.append(argv)
            if "uiautomator" in argv:
                return CommandResult(argv, 0, "UI hierarchy dumped", "")
            if argv[-2:] == ["cat", dump_path]:
                return CommandResult(
                    argv,
                    0,
                    (
                        "<hierarchy>"
                        '<node package="com.vivo.appfilter" text="始终打开" '
                        'clickable="true" bounds="[0,0][100,100]" />'
                        "</hierarchy>"
                    ),
                    "",
                )
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        PermanentOnlyRunner(),  # type: ignore[arg-type]
    )

    result = adapter._dismiss_oem_jump_prompt()

    assert result == {"detected": True, "dismissed": False, "reason": "no_known_button"}
    assert not any("tap" in argv for argv in PermanentOnlyRunner.calls)
    assert PermanentOnlyRunner.calls[-1][-3:] == ["rm", "-f", dump_path]


def test_oem_jump_prompt_requires_disappearance_after_a_successful_tap(settings) -> None:  # noqa: ANN001
    dump_path = "/data/local/tmp/apkscanner_oem_jump.dump"

    class StalePromptRunner:
        calls: list[list[str]] = []

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.calls.append(argv)
            if "uiautomator" in argv:
                return CommandResult(argv, 0, "UI hierarchy dumped", "")
            if argv[-2:] == ["cat", dump_path]:
                return CommandResult(
                    argv,
                    0,
                    (
                        "<hierarchy>"
                        '<node package="com.vivo.appfilter" text="仅打开一次" '
                        'clickable="true" bounds="[20,20][220,120]" />'
                        "</hierarchy>"
                    ),
                    "",
                )
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        StalePromptRunner(),  # type: ignore[arg-type]
    )

    result = adapter._dismiss_oem_jump_prompt()

    assert result["detected"] is True
    assert result["dismissed"] is False
    assert result["reason"] == "prompt_still_present"
    assert StalePromptRunner.calls[-1][-3:] == ["rm", "-f", dump_path]


def test_oem_jump_prompt_ignores_button_text_owned_by_another_package(settings) -> None:  # noqa: ANN001
    dump_path = "/data/local/tmp/apkscanner_oem_jump.dump"

    class ForeignButtonRunner:
        calls: list[list[str]] = []

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            cls.calls.append(argv)
            if "uiautomator" in argv:
                return CommandResult(argv, 0, "UI hierarchy dumped", "")
            if argv[-2:] == ["cat", dump_path]:
                return CommandResult(
                    argv,
                    0,
                    (
                        "<hierarchy>"
                        '<node package="com.vivo.appfilter" text="提示" />'
                        '<node package="com.example.target" text="打开" '
                        'clickable="true" bounds="[0,0][100,100]" />'
                        "</hierarchy>"
                    ),
                    "",
                )
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        ForeignButtonRunner(),  # type: ignore[arg-type]
    )

    result = adapter._dismiss_oem_jump_prompt()

    assert result == {"detected": True, "dismissed": False, "reason": "no_known_button"}
    assert not any("tap" in argv for argv in ForeignButtonRunner.calls)


def test_android13_device_is_local_verdict_but_not_release_gate_eligible(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    class LegacyRunner:
        request_id = ""

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
                stdout = f'I/APKSCANNER_POC: {{"request_id":"{cls.request_id}","success":true}}'
            else:
                stdout = ""
            return CommandResult(argv, 0, stdout, "")

    apk = tmp_path / "legacy-smoke-poc.apk"
    apk.write_bytes(b"APK")
    spec = AgentPocSpec(
        project_path="poc/test",
        package_name="io.apkscanner.poc.legacysmoke",
        launch_component=".MainActivity",
        log_tag="APKSCANNER_POC",
        timeout_seconds=5,
    )
    strict = AdbDeviceAdapter(
        replace(
            settings,
            adb_serial="legacy-device",
            validation_profile="android16_release",
            device_min_api=36,
            allow_legacy_device_smoke=False,
        ),
        LegacyRunner(),  # type: ignore[arg-type]
    )
    rejected = strict.execute_poc(
        apk,
        spec,
        target_package_name="com.example.target",
        state="guest",
        build_metadata={"compile_api": 36, "min_api": 21, "target_api": 36},
    )
    assert rejected.stage == "poc_incompatible"

    smoke = AdbDeviceAdapter(
        replace(
            settings,
            adb_serial="legacy-device",
            device_min_api=33,
            allow_legacy_device_smoke=True,
        ),
        LegacyRunner(),  # type: ignore[arg-type]
    )
    accepted = smoke.execute_poc(
        apk,
        spec,
        target_package_name="com.example.target",
        state="guest",
        build_metadata={"compile_api": 36, "min_api": 21, "target_api": 36},
    )
    assert accepted.stage == "blackbox_poc"
    metadata = accepted.commands[0][2]
    assert metadata["device_api"] == "33"
    assert metadata["android16_verdict_eligible"] is False
    assert metadata["dynamic_verdict_eligible"] is True
    assert metadata["release_gate_eligible"] is False
    assert metadata["verdict_scope"] == "development_legacy"
    assert metadata["compatibility_smoke_only"] is False


def test_dedicated_poc_collects_an_independent_platform_ui_oracle(
    settings,
    tmp_path,
    monkeypatch,
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
                stdout = "36\n"
            elif "APKSCANNER_POC:V" in argv:
                stdout = (
                    f'I/APKSCANNER_POC: {{"request_id":"{cls.request_id}",'
                    '"success":true,"security_impact_observed":true}'
                )
            elif "uiautomator" in argv:
                cls.ui_dump_count += 1
                stdout = "UI hierarchy dumped"
            elif "cat" in argv and any("apkscanner-ui-" in item for item in argv):
                stdout = (
                    '<hierarchy><node package="com.example.target" text="" /></hierarchy>'
                    if cls.ui_dump_count < 3
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
    monkeypatch.setattr("apkscanner.runtime.device.time.sleep", lambda _seconds: None)
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
    logcat_poll_timeouts = []
    original_poll_poc_logcat = adapter._poll_poc_logcat

    def capture_poll_poc_logcat(**kwargs):  # noqa: ANN003, ANN202
        logcat_poll_timeouts.append(kwargs["timeout_seconds"])
        return original_poll_poc_logcat(**kwargs)

    monkeypatch.setattr(adapter, "_poll_poc_logcat", capture_poll_poc_logcat)

    result = adapter.execute_poc(
        apk,
        spec,
        target_package_name="com.example.target",
        state="guest",
        oracle=oracle,
        test_case_id="agent-r1-1",
        build_metadata={"compile_api": 23, "min_api": 26, "target_api": 36},
    )
    by_kind = {kind: metadata for kind, _command_result, metadata in result.commands}

    assert logcat_poll_timeouts == [1]
    assert by_kind["blackbox.poc_logcat"]["poc_success"] is True
    assert by_kind["blackbox.poc_logcat"]["poc_claimed_security_impact"] is True
    assert by_kind["blackbox.device_profile"]["device_api"] == "36"
    assert by_kind["blackbox.device_profile"]["device_api_matches_poc_target"] is True
    assert by_kind["blackbox.device_profile"]["device_api_satisfies_poc_min"] is True
    assert by_kind["blackbox.device_profile"]["poc_runtime_compatible"] is True
    assert "blackbox.poc_pre_uninstall" in by_kind
    assert "security_impact_observed" not in by_kind["blackbox.poc_logcat"]
    assert by_kind["blackbox.poc_ui_baseline"]["target_text_present"] is False
    assert by_kind["blackbox.poc_ui_wake"]["action"] == "wake_display"
    assert by_kind["blackbox.poc_ui_unlock"]["action"] == "dismiss_keyguard"
    assert by_kind["blackbox.poc_ui_dump"]["security_impact_observed"] is True
    assert by_kind["blackbox.poc_system_logcat"]["background_activity_start_blocked"] is False
    assert by_kind["blackbox.poc_ui_dump"]["oracle"]["matched"] is True
    assert by_kind["blackbox.poc_ui_dump"]["poll_attempts"] == 1
    assert (
        by_kind["blackbox.poc_ui_dump"]["oracle"]["observation"]["target_text_transition"] is True
    )


def test_ui_hierarchy_retry_recovers_from_android_null_root(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    class TransientUiRunner:
        dump_attempts = 0

        @staticmethod
        def available(_name: str) -> bool:
            return True

        @classmethod
        def run(cls, argv, **_kwargs):  # noqa: ANN001, ANN206
            if "uiautomator" in argv:
                cls.dump_attempts += 1
                if cls.dump_attempts == 1:
                    return CommandResult(argv, 1, "", "ERROR: null root node returned")
                return CommandResult(argv, 0, "UI hierarchy dumped", "")
            if "cat" in argv and any("apkscanner-ui-" in item for item in argv):
                return CommandResult(
                    argv,
                    0,
                    '<hierarchy><node package="com.example.target" text="ready" /></hierarchy>',
                    "",
                )
            return CommandResult(argv, 0, "", "")

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        TransientUiRunner(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr("apkscanner.runtime.device.time.sleep", lambda _seconds: None)

    result, attempts = adapter._dump_ui_hierarchy_with_retry(budget=None, cap=10)

    assert result.exit_code == 0
    assert 'text="ready"' in result.stdout
    assert attempts == 2


def test_background_activity_start_denial_is_attributed_to_target_package(
    settings,
) -> None:  # noqa: ANN001
    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        ToolRunner(30),
    )
    output = (
        "W/ActivityTaskManager: Background activity start "
        "[callingPackage: io.apkscanner.vulntest; "
        "allowBackgroundActivityStart: false]\n"
        "E/ActivityTaskManager: Abort background activity starts from 10421"
    )

    assert adapter._background_activity_start_blocked(
        output,
        "io.apkscanner.vulntest",
    )
    assert not adapter._background_activity_start_blocked(
        output,
        "com.example.other",
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


def test_poc_durable_receipt_is_a_terminal_request_bound_observation(settings) -> None:  # noqa: ANN001
    class ReceiptRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            assert argv[-2:] == [
                "cat",
                "files/apkscanner-proof-receipt.json",
            ]
            return CommandResult(
                argv,
                0,
                (
                    '{"apkscanner_request_id":"request-receipt",'
                    '"receipt_schema_version":"1.0",'
                    '"receipt_stage":"completed","receipt_terminal":true,'
                    '"success":true}'
                ),
                "",
            )

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        ReceiptRunner(),  # type: ignore[arg-type]
    )

    result, payload, metadata = adapter._poll_poc_durable_receipt(
        package_name="io.apkscanner.poc.receipt",
        request_id="request-receipt",
        timeout_seconds=5,
        budget=None,
    )

    assert result.exit_code == 0
    assert payload is not None and payload["success"] is True
    assert metadata["request_observed"] is True
    assert metadata["correlation_mode"] == "durable_receipt"
    assert metadata["receipt_terminal"] is True
    assert metadata["poc_success"] is True


def test_poc_runtime_diagnostics_classify_install_launch_and_dex_failures() -> None:
    install = AdbDeviceAdapter._poc_install_diagnostics(
        CommandResult(
            ["adb", "install"],
            0,
            "Failure [INSTALL_FAILED_OLDER_SDK: Requires newer sdk version]",
            "",
        )
    )
    launch = AdbDeviceAdapter._poc_launch_diagnostics(
        CommandResult(
            ["adb", "shell", "am", "start"],
            0,
            "Error type 3\nActivity class does not exist.",
            "",
        )
    )
    runtime = AdbDeviceAdapter._poc_runtime_diagnostics(
        (
            "FATAL EXCEPTION: main\n"
            "Process: io.apkscanner.poc.compat, PID: 123\n"
            "java.lang.VerifyError: rejected class"
        ),
        "io.apkscanner.poc.compat",
    )

    assert install == {
        "install_accepted": False,
        "install_failure_kind": "min_sdk_too_high",
    }
    assert launch == {
        "launch_accepted": False,
        "launch_failure_kind": "component_not_found",
    }
    assert runtime["runtime_failure_kind"] == "dex_verification_failed"
    assert runtime["runtime_crash_observed"] is True


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
    monkeypatch.setattr("apkscanner.runtime.device.time.sleep", lambda _seconds: None)

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
    monkeypatch.setattr("apkscanner.runtime.device.time.sleep", lambda _seconds: None)

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
        ('<hierarchy><node package="io.apkscanner.poc.test" text="Imported secret" /></hierarchy>'),
        package_name="com.example.target",
        baseline_output=('<hierarchy><node package="com.example.target" text="" /></hierarchy>'),
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
        '<hierarchy><node package="com.example.target" text="Imported secret" /></hierarchy>'
    )

    metadata = AdbDeviceAdapter._evaluate_ui_oracle(
        oracle,
        target_ui,
        package_name="com.example.target",
        baseline_output=target_ui,
        baseline_valid=True,
    )

    assert metadata["oracle"]["matched"] is True
    assert metadata["oracle"]["observation"]["target_text_transition"] is False
    assert metadata["security_impact_observed"] is False


def test_new_target_ui_text_can_prove_unauthorized_state_change() -> None:
    oracle = AgentOracleSpec(
        kind="ui_text",
        expected_text="Imported entries: [../shared_prefs/session.xml]",
        impact="unauthorized_state_change",
    )

    metadata = AdbDeviceAdapter._evaluate_ui_oracle(
        oracle,
        (
            '<hierarchy><node package="com.example.target" '
            'text="Imported entries: [../shared_prefs/session.xml]" /></hierarchy>'
        ),
        package_name="com.example.target",
        baseline_output='<hierarchy><node package="com.example.target" text="Ready" /></hierarchy>',
        baseline_valid=True,
    )

    assert metadata["oracle"]["matched"] is True
    assert metadata["oracle"]["observation"]["target_text_transition"] is True
    assert metadata["security_impact_observed"] is True


def test_target_file_hash_transition_proves_unauthorized_state_change() -> None:
    oracle = AgentOracleSpec(
        kind="target_file_sha256",
        target_path="shared_prefs/session.xml",
        impact="unauthorized_state_change",
    )

    metadata = AdbDeviceAdapter._evaluate_target_file_oracle(
        oracle,
        before={
            "observer_available": True,
            "file_exists": True,
            "sha256": "a" * 64,
        },
        after={
            "observer_available": True,
            "file_exists": True,
            "sha256": "b" * 64,
        },
    )

    assert metadata["oracle"]["matched"] is True
    assert metadata["oracle"]["observation"]["state_transition"] is True
    assert metadata["security_impact_observed"] is True


def test_unavailable_target_file_observer_is_a_gap_not_refutation() -> None:
    oracle = AgentOracleSpec(
        kind="target_file_sha256",
        target_path="shared_prefs/session.xml",
        impact="unauthorized_state_change",
        refute_on_miss=True,
    )

    metadata = AdbDeviceAdapter._evaluate_target_file_oracle(
        oracle,
        before={"observer_available": False, "observer_gap": "not debuggable"},
        after={"observer_available": False, "observer_gap": "not debuggable"},
    )

    assert metadata["oracle"]["matched"] is False
    assert metadata["oracle_refuted"] is False
    assert metadata["security_impact_observed"] is False


@pytest.mark.parametrize(
    ("stderr", "observer_available"),
    [
        (
            "/system/bin/sha256sum: shared_prefs/session.xml: No such file or directory",
            True,
        ),
        (
            "run-as: exec failed for /system/bin/sha256sum: No such file or directory",
            False,
        ),
    ],
)
def test_target_file_snapshot_distinguishes_missing_file_from_missing_observer(
    settings,  # noqa: ANN001
    stderr: str,
    observer_available: bool,
) -> None:
    class SnapshotRunner:
        @staticmethod
        def available(_name: str) -> bool:
            return True

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            return CommandResult(argv, 1, "", stderr)

    adapter = AdbDeviceAdapter(
        replace(settings, adb_serial="cloud-device:5555"),
        SnapshotRunner(),  # type: ignore[arg-type]
    )

    _result, snapshot = adapter._target_file_snapshot(
        "com.example.target",
        "shared_prefs/session.xml",
        budget=None,
    )

    assert snapshot["observer_available"] is observer_available
    assert snapshot["file_exists"] is False


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
        ("FATAL EXCEPTION: main\nProcess: com.example.target:remote, PID: 456"),
        "com.example.target",
    )

    assert unrelated["security_impact_observed"] is False
    assert target["security_impact_observed"] is True


def test_process_crash_miss_requires_a_completed_isolated_observation_window() -> None:
    oracle = AgentOracleSpec(
        kind="process_crash",
        impact="denial_of_service",
        refute_on_miss=True,
    )

    incomplete = AdbDeviceAdapter._evaluate_target_log_oracle(
        oracle,
        "Activity started without a fatal exception",
        "com.example.target",
        refutation_observed=False,
    )
    complete = AdbDeviceAdapter._evaluate_target_log_oracle(
        oracle,
        "Activity started without a fatal exception",
        "com.example.target",
        refutation_observed=True,
    )

    assert incomplete["oracle_refuted"] is False
    assert complete["oracle_refuted"] is True
