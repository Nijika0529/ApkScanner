from __future__ import annotations

import base64
import hashlib
import heapq
import json
import re
import secrets
import threading
import time
import xml.etree.ElementTree as ElementTree
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings
from .models import EntryPoint
from .schemas import AgentOracleSpec, AgentPocSpec
from .tools import CommandResult, TimeBudget, ToolRunner


@dataclass(slots=True)
class DeviceProbeResult:
    stage: str
    commands: list[tuple[str, CommandResult, dict[str, Any]]]
    summary: dict[str, Any]


class DeviceLeaseCancelledError(RuntimeError):
    """Raised when a task is cancelled while waiting for the single device."""


@dataclass(order=True, slots=True)
class _DeviceWaiter:
    sort_key: tuple[int, int]
    task_id: str = field(compare=False)
    enqueued_at: float = field(compare=False)
    cancel_event: threading.Event = field(compare=False)


class SingleDeviceScheduler:
    """Observable priority queue for one exclusive Android device."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._queue: list[_DeviceWaiter] = []
        self._sequence = 0
        self._active_task_id: str | None = None

    @contextmanager
    def lease(
        self,
        task_id: str,
        *,
        priority: int,
        cancel_event: threading.Event,
        on_queued=None,  # noqa: ANN001
        on_acquired=None,  # noqa: ANN001
    ):  # noqa: ANN201
        with self._condition:
            self._sequence += 1
            waiter = _DeviceWaiter(
                sort_key=(-priority, self._sequence),
                task_id=task_id,
                enqueued_at=time.monotonic(),
                cancel_event=cancel_event,
            )
            heapq.heappush(self._queue, waiter)
            position = self._position(waiter)
            self._condition.notify_all()
        acquired = False
        try:
            if on_queued is not None:
                on_queued(position)
            with self._condition:
                while True:
                    if cancel_event.is_set():
                        self._remove(waiter)
                        self._condition.notify_all()
                        raise DeviceLeaseCancelledError("device lease was cancelled while queued")
                    if self._active_task_id is None and self._queue[0] is waiter:
                        heapq.heappop(self._queue)
                        self._active_task_id = task_id
                        acquired = True
                        break
                    self._condition.wait(timeout=0.25)
            waited_seconds = max(0.0, time.monotonic() - waiter.enqueued_at)
            if on_acquired is not None:
                on_acquired(waited_seconds)
            yield {
                "task_id": task_id,
                "wait_seconds": waited_seconds,
            }
        finally:
            with self._condition:
                if not acquired:
                    self._remove(waiter)
                elif self._active_task_id == task_id:
                    self._active_task_id = None
                self._condition.notify_all()

    def wake_waiters(self) -> None:
        with self._condition:
            self._condition.notify_all()

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            waiting = sorted(self._queue)
            return {
                "active_task_id": self._active_task_id,
                "waiting": [
                    {
                        "task_id": waiter.task_id,
                        "position": index,
                        "priority": -waiter.sort_key[0],
                    }
                    for index, waiter in enumerate(waiting, start=1)
                ],
            }

    def _position(self, target: _DeviceWaiter) -> int:
        return sorted(self._queue).index(target) + 1

    def _remove(self, target: _DeviceWaiter) -> None:
        try:
            self._queue.remove(target)
        except ValueError:
            return
        heapq.heapify(self._queue)


class DevicePoolScheduler:
    """Priority queue that assigns one complete task to one free device."""

    def __init__(self, serials: tuple[str, ...]) -> None:
        self._serials = list(dict.fromkeys(serials))
        self._draining: set[str] = set()
        self._condition = threading.Condition()
        self._queue: list[_DeviceWaiter] = []
        self._sequence = 0
        self._active_by_serial: dict[str, str] = {}

    @contextmanager
    def lease(
        self,
        task_id: str,
        *,
        priority: int,
        cancel_event: threading.Event,
        on_queued=None,  # noqa: ANN001
        on_acquired=None,  # noqa: ANN001
    ):  # noqa: ANN201
        with self._condition:
            self._sequence += 1
            waiter = _DeviceWaiter(
                sort_key=(-priority, self._sequence),
                task_id=task_id,
                enqueued_at=time.monotonic(),
                cancel_event=cancel_event,
            )
            heapq.heappush(self._queue, waiter)
            position = self._position(waiter)
            self._condition.notify_all()
        acquired_serial: str | None = None
        try:
            if on_queued is not None:
                on_queued(position)
            with self._condition:
                while True:
                    if cancel_event.is_set():
                        self._remove(waiter)
                        self._condition.notify_all()
                        raise DeviceLeaseCancelledError("device lease was cancelled while queued")
                    available_serial = next(
                        (
                            serial
                            for serial in self._serials
                            if serial not in self._active_by_serial
                            and serial not in self._draining
                        ),
                        None,
                    )
                    if available_serial is not None and self._queue and self._queue[0] is waiter:
                        heapq.heappop(self._queue)
                        self._active_by_serial[available_serial] = task_id
                        acquired_serial = available_serial
                        break
                    self._condition.wait(timeout=0.25)
            waited_seconds = max(0.0, time.monotonic() - waiter.enqueued_at)
            if on_acquired is not None:
                on_acquired(waited_seconds, acquired_serial)
            yield {
                "task_id": task_id,
                "serial": acquired_serial,
                "wait_seconds": waited_seconds,
            }
        finally:
            with self._condition:
                if acquired_serial is None:
                    self._remove(waiter)
                elif self._active_by_serial.get(acquired_serial) == task_id:
                    self._active_by_serial.pop(acquired_serial, None)
                self._condition.notify_all()

    def wake_waiters(self) -> None:
        with self._condition:
            self._condition.notify_all()

    def add_serial(self, serial: str) -> None:
        with self._condition:
            if serial not in self._serials:
                self._serials.append(serial)
            self._draining.discard(serial)
            self._condition.notify_all()

    def drain_serial(self, serial: str) -> bool:
        with self._condition:
            if serial not in self._serials:
                return False
            self._draining.add(serial)
            self._condition.notify_all()
            return True

    def restore_serial(self, serial: str) -> bool:
        with self._condition:
            if serial not in self._serials:
                return False
            self._draining.discard(serial)
            self._condition.notify_all()
            return True

    def remove_serial(self, serial: str) -> bool:
        with self._condition:
            if serial in self._active_by_serial:
                return False
            try:
                self._serials.remove(serial)
            except ValueError:
                return False
            self._draining.discard(serial)
            self._condition.notify_all()
            return True

    def is_active(self, serial: str) -> bool:
        with self._condition:
            return serial in self._active_by_serial

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            waiting = sorted(self._queue)
            snapshot = {
                "capacity": len(self._serials),
                "active": dict(self._active_by_serial),
                "waiting": [
                    {
                        "task_id": waiter.task_id,
                        "position": index,
                        "priority": -waiter.sort_key[0],
                    }
                    for index, waiter in enumerate(waiting, start=1)
                ],
            }
            if self._draining:
                snapshot["draining"] = sorted(self._draining)
            return snapshot

    def _position(self, target: _DeviceWaiter) -> int:
        return sorted(self._queue).index(target) + 1

    def _remove(self, target: _DeviceWaiter) -> None:
        try:
            self._queue.remove(target)
        except ValueError:
            return
        heapq.heapify(self._queue)


class AdbDeviceAdapter:
    """Serialized remote-ADB adapter for the single-device MVP."""

    NON_BLOCKING_CAPABILITY_TTL_SECONDS = 30.0

    def __init__(
        self,
        settings: Settings,
        runner: ToolRunner,
        *,
        serial: str | None = None,
    ):
        self.settings = settings
        self.runner = runner
        self.serial = serial or settings.adb_serial
        self._lease = threading.RLock()
        self.scheduler = SingleDeviceScheduler()
        self._last_capability: dict[str, Any] | None = None
        self._last_capability_at: float | None = None
        self._active_cancel_event: threading.Event | None = None
        self._probe_apk_sha256: str | None = None
        self._probe_ready = False
        self._ui_dump_latencies: list[float] = []

    @property
    def configured(self) -> bool:
        return bool(self.serial and self.runner.available("adb"))

    @property
    def probe_ready(self) -> bool:
        """Whether the optional ordinary-app Probe fast path is usable."""
        return self._probe_ready

    @contextmanager
    def lease(self):  # noqa: ANN201
        """Keep the single cloud device assigned to one investigation task."""
        with self._lease:
            yield

    @contextmanager
    def task_lease(
        self,
        task_id: str,
        *,
        priority: int,
        cancel_event: threading.Event,
        on_queued=None,  # noqa: ANN001
        on_acquired=None,  # noqa: ANN001
        on_released=None,  # noqa: ANN001
    ):  # noqa: ANN201
        """Queue and exclusively assign the single cloud device to one task."""
        with self.scheduler.lease(
            task_id,
            priority=priority,
            cancel_event=cancel_event,
            on_queued=on_queued,
        ) as metadata:
            acquired_at = time.monotonic()
            session_started = False
            try:
                if cancel_event.is_set():
                    raise DeviceLeaseCancelledError(
                        "device lease was cancelled before the command session"
                    )
                # The scheduler owns the device for the complete task. Do not hold
                # the command RLock here: live proof replay enters through the API
                # thread while the Agent thread waits for its response. Individual
                # device operations take `_lease`, so commands remain serialized
                # without deadlocking a replay submitted by the owning task.
                self._active_cancel_event = cancel_event
                session_started = True
                if on_acquired is not None:
                    on_acquired(metadata["wait_seconds"])
                yield metadata
            finally:
                held_seconds = max(0.0, time.monotonic() - acquired_at)
                self._active_cancel_event = None
                if session_started and on_released is not None:
                    on_released(held_seconds)

    def capability(self, *, non_blocking: bool = False) -> dict[str, Any]:
        if not self.configured:
            return {"available": False, "detail": "APKSCANNER_ADB_SERIAL is not configured"}
        scheduler_state = self.scheduler.snapshot()
        active_task_id = scheduler_state["active_task_id"]
        if non_blocking and active_task_id:
            return self._busy_capability(
                active_task_id=active_task_id,
                waiting_count=len(scheduler_state["waiting"]),
            )
        if (
            non_blocking
            and self._last_capability is not None
            and self._last_capability_at is not None
        ):
            age = max(0.0, time.monotonic() - self._last_capability_at)
            if age < self.NON_BLOCKING_CAPABILITY_TTL_SECONDS:
                return {
                    **self._last_capability,
                    "cached": True,
                    "cache_age_seconds": round(age, 3),
                }
        if non_blocking:
            acquired = self._lease.acquire(blocking=False)
            if not acquired:
                return self._busy_capability(
                    active_task_id=active_task_id,
                    waiting_count=len(scheduler_state["waiting"]),
                )
            try:
                return self._probe_capability()
            finally:
                self._lease.release()
        with self._lease:
            return self._probe_capability()

    def _busy_capability(
        self,
        *,
        active_task_id: str | None,
        waiting_count: int,
    ) -> dict[str, Any]:
        cached = dict(
            self._last_capability
            or {
                "available": True,
                "serial": self.serial,
            }
        )
        cached.update(
            {
                "busy": True,
                "active_task_id": active_task_id,
                "waiting_count": waiting_count,
                "detail": "云真机正在执行其他操作，健康检查使用最近一次状态",
            }
        )
        return cached

    def _probe_capability(self) -> dict[str, Any]:
        """Probe device health while the caller owns the command lock."""
        state = self._adb(["get-state"], timeout=30)
        if state.exit_code != 0:
            result = {
                "available": False,
                "state": state.stdout.strip(),
                "serial": self.serial,
                "detail": state.stderr.strip() or "ADB device is unavailable",
            }
            self._last_capability = dict(result)
            self._last_capability_at = time.monotonic()
            return result
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="adb-capability") as executor:
            version_future = executor.submit(
                self._adb, ["shell", "getprop", "ro.build.version.release"], 30
            )
            sdk_future = executor.submit(
                self._adb, ["shell", "getprop", "ro.build.version.sdk"], 30
            )
            root_future = executor.submit(self._adb, ["shell", "id", "-u"], 30)
            version = version_future.result()
            sdk = sdk_future.result()
            root = root_future.result()
        actual_api = sdk.stdout.strip()
        try:
            actual_api_number = int(actual_api)
        except ValueError:
            actual_api_number = None
        ready = (
            state.exit_code == 0
            and actual_api_number is not None
            and self.settings.device_min_api <= actual_api_number <= self.settings.device_max_api
        )
        detail = None
        if not ready:
            detail = (
                f"expected Android API {self.settings.device_min_api}.."
                f"{self.settings.device_max_api}, found {version.stdout.strip()} / API "
                f"{actual_api or 'unknown'}"
            )
        verdict_metadata = self.settings.verdict_metadata(actual_api_number)
        result = {
            "available": ready,
            "state": state.stdout.strip(),
            "android_version": version.stdout.strip(),
            "api_level": actual_api,
            "root": root.exit_code == 0 and root.stdout.strip() == "0",
            "serial": self.serial,
            "detail": detail,
            **{
                key: value if ready else False
                for key, value in verdict_metadata.items()
                if key
                in {
                    "android16_verdict_eligible",
                    "dynamic_verdict_eligible",
                    "release_gate_eligible",
                    "compatibility_smoke_only",
                }
            },
            "validation_profile": verdict_metadata["validation_profile"],
            "verdict_scope": verdict_metadata["verdict_scope"] if ready else "unavailable",
        }
        self._last_capability = dict(result)
        self._last_capability_at = time.monotonic()
        return result

    def prepare(
        self, apk_path: Path, package_name: str, budget: TimeBudget | None = None
    ) -> list[tuple[str, CommandResult, dict]]:
        self._validate_package(package_name)
        self._probe_ready = False
        commands: list[tuple[str, CommandResult, dict]] = []
        health = self._adb_budget(["get-state"], budget, 30)
        commands.append(("device.health", health, {}))
        if health.exit_code != 0:
            return commands
        installed = self._adb_budget(
            ["shell", "pm", "path", package_name],
            budget,
            45,
        )
        commands.append(
            (
                "device.package_status",
                installed,
                {
                    "package": package_name,
                    "installed_before_prepare": installed.exit_code == 0,
                },
            )
        )
        policy = self.settings.device_install_policy
        if policy not in {"replace", "install_or_reuse", "reuse_installed"}:
            raise ValueError(
                "APKSCANNER_DEVICE_INSTALL_POLICY must be replace, "
                "install_or_reuse, or reuse_installed"
            )
        if policy == "reuse_installed" and installed.exit_code == 0:
            install = CommandResult(
                ["adb", "-s", self.serial or "", "reuse-installed", package_name],
                0,
                installed.stdout,
                "",
            )
            commands.append(
                (
                    "device.install",
                    install,
                    {"package": package_name, "install_mode": "reuse_installed"},
                )
            )
        else:
            attempted = self._adb_budget(
                ["install", "-r", "-t", str(apk_path)],
                budget,
                300,
            )
            if (
                attempted.exit_code != 0
                and policy == "install_or_reuse"
                and installed.exit_code == 0
            ):
                commands.append(
                    (
                        "device.install_attempt",
                        attempted,
                        {"package": package_name, "fallback": "reuse_installed"},
                    )
                )
                install = CommandResult(
                    ["adb", "-s", self.serial or "", "reuse-installed", package_name],
                    0,
                    installed.stdout,
                    "",
                )
                commands.append(
                    (
                        "device.install",
                        install,
                        {
                            "package": package_name,
                            "install_mode": "reuse_after_install_failure",
                            "install_error": attempted.stderr[-4000:],
                        },
                    )
                )
            else:
                install = attempted
                commands.append(
                    (
                        "device.install",
                        install,
                        {"package": package_name, "install_mode": "replace"},
                    )
                )
        if install.exit_code != 0:
            return commands
        if self.settings.probe_apk_path and self.settings.probe_apk_path.is_file():
            probe_sha256 = self._file_sha256(self.settings.probe_apk_path)
            probe_status = self._adb_budget(
                ["shell", "pm", "path", "io.apkscanner.probe"],
                budget,
                45,
            )
            if self._probe_apk_sha256 == probe_sha256 and probe_status.exit_code == 0:
                probe_install = CommandResult(
                    ["adb", "-s", self.serial or "", "reuse-probe"],
                    0,
                    probe_status.stdout,
                    "",
                )
                commands.append(
                    (
                        "device.probe_cached",
                        probe_install,
                        {
                            "package": "io.apkscanner.probe",
                            "apk_sha256": probe_sha256,
                        },
                    )
                )
                self._probe_ready = True
            else:
                probe_install = self._adb_budget(
                    ["install", "-r", "-t", str(self.settings.probe_apk_path)],
                    budget,
                    300,
                )
                commands.append(
                    (
                        "device.install_probe",
                        probe_install,
                        {
                            "package": "io.apkscanner.probe",
                            "apk_sha256": probe_sha256,
                        },
                    )
                )
                if probe_install.exit_code == 0:
                    self._probe_apk_sha256 = probe_sha256
                    self._probe_ready = True
        if self.settings.device_reset_policy != "never":
            commands.append(
                (
                    "device.clear",
                    self._adb_budget(["shell", "pm", "clear", package_name], budget, 60),
                    {"package": package_name, "reason": "prepare"},
                )
            )
        commands.append(("device.logcat_clear", self._adb_budget(["logcat", "-c"], budget, 30), {}))
        commands.append(
            (
                "device.app_links",
                self._adb_budget(
                    ["shell", "pm", "get-app-links", "--user", "cur", package_name],
                    budget,
                    45,
                ),
                {"package": package_name},
            )
        )
        return commands

    def cleanup(self, package_name: str) -> list[tuple[str, CommandResult, dict]]:
        self._validate_package(package_name)
        if self.settings.device_reset_policy == "never":
            # Preserve the target's login, first-run consent, local databases, and app-link state.
            # Temporary PoC applications are uninstalled by execute_poc() independently.
            return []
        return [
            (
                "device.clear",
                self._adb(
                    ["shell", "pm", "clear", package_name],
                    timeout=60,
                    respect_cancellation=False,
                ),
                {"package": package_name},
            ),
            (
                "device.applink_reset",
                self._adb(
                    ["shell", "pm", "set-app-links", "--package", package_name, "0", "all"],
                    timeout=60,
                    respect_cancellation=False,
                ),
                {"package": package_name},
            ),
        ]

    def reset_session(
        self, package_name: str, budget: TimeBudget | None = None
    ) -> list[tuple[str, CommandResult, dict[str, Any]]]:
        self._validate_package(package_name)
        return [
            (
                "device.clear",
                self._adb_budget(["shell", "pm", "clear", package_name], budget, 60),
                {"package": package_name, "reason": "agent_requested_tests"},
            ),
            (
                "device.logcat_clear",
                self._adb_budget(["logcat", "-c"], budget, 30),
                {"reason": "agent_requested_tests"},
            ),
        ]

    def reset_observation_window(
        self,
        budget: TimeBudget | None = None,
    ) -> list[tuple[str, CommandResult, dict[str, Any]]]:
        """Isolate per-test logs without destroying application state."""

        return [
            (
                "device.logcat_clear",
                self._adb_budget(["logcat", "-c"], budget, 30),
                {"reason": "agent_requested_test_observation_window"},
            )
        ]

    def probe(
        self,
        entry: EntryPoint,
        package_name: str,
        *,
        state: str = "guest",
        budget: TimeBudget | None = None,
        uri_override: str | None = None,
        extras: dict[str, str | int | bool] | None = None,
        operation: str = "auto",
        method: str | None = None,
        argument: str | None = None,
        binder_transaction_code: int | None = None,
        binder_interface_descriptor: str | None = None,
        binder_reply_type: str | None = None,
        binder_read_exception: bool | None = None,
        binder_script: list[dict[str, Any]] | None = None,
        intent_action: str | None = None,
        categories: list[str] | None = None,
        oracle: AgentOracleSpec | None = None,
        test_case_id: str | None = None,
    ) -> DeviceProbeResult:
        if not self.configured:
            raise RuntimeError("remote ADB device is not configured")
        self._validate_package(package_name)
        commands: list[tuple[str, CommandResult, dict[str, Any]]] = []
        with self._lease:
            direct_argv = (
                self._direct_probe_args(entry, package_name)
                if (
                    uri_override is None
                    and extras is None
                    and operation == "auto"
                    and intent_action is None
                    and not categories
                )
                else None
            )
            probe_request = (
                self._probe_request(
                    entry,
                    package_name,
                    uri_override=uri_override,
                    extras=extras,
                    operation=operation,
                    method=method,
                    argument=argument,
                    binder_transaction_code=binder_transaction_code,
                    binder_interface_descriptor=binder_interface_descriptor,
                    binder_reply_type=binder_reply_type,
                    binder_read_exception=binder_read_exception,
                    binder_script=binder_script,
                    intent_action=intent_action,
                    categories=categories,
                )
                if self._probe_ready
                else None
            )
            request_id = secrets.token_hex(8) if probe_request else None
            action_attempted = bool(direct_argv or probe_request)
            ui_baseline: CommandResult | None = None
            if action_attempted and oracle is not None and oracle.kind == "ui_text":
                ui_baseline, baseline_attempts = self._dump_ui_hierarchy_with_retry(
                    budget=budget,
                    cap=45,
                )
                commands.append(
                    (
                        "blackbox.ui_baseline",
                        ui_baseline,
                        {
                            "entry_point": entry.id,
                            "session_state": state,
                            "test_case_id": test_case_id,
                            "observation_role": "pre_action_baseline",
                            "poll_attempts": baseline_attempts,
                            "target_package": package_name,
                            "target_text_present": self._ui_text_in_package(
                                ui_baseline.stdout,
                                oracle.expected_text or "",
                                package_name,
                            ),
                        },
                    )
                )
            if direct_argv:
                commands.append(
                    (
                        "blackbox.adb_shell",
                        self._adb_budget(direct_argv, budget, 90),
                        {
                            "caller_identity": "adb_shell",
                            "entry_point": entry.id,
                            "session_state": state,
                            "test_case_id": test_case_id,
                        },
                    )
                )
            if probe_request:
                probe_request["request_id"] = request_id
                encoded = base64.urlsafe_b64encode(json.dumps(probe_request).encode()).decode()
                commands.append(
                    (
                        "blackbox.probe_app",
                        self._adb_budget(
                            [
                                "shell",
                                "am",
                                "broadcast",
                                "-a",
                                "io.apkscanner.probe.EXECUTE",
                                "-n",
                                "io.apkscanner.probe/.ProbeReceiver",
                                "--es",
                                "request_base64",
                                encoded,
                            ],
                            budget,
                            90,
                        ),
                        {
                            "caller_identity": "probe_app",
                            "entry_point": entry.id,
                            "session_state": state,
                            "request_id": request_id,
                            "test_case_id": test_case_id,
                        },
                    )
                )
            if probe_request:
                log_result, matching_log, poll_attempts, poll_seconds = self._poll_probe_logcat(
                    request_id=str(request_id),
                    timeout_seconds=15,
                    budget=budget,
                )
                probe_payload = self._last_json_payload(matching_log)
                oracle_metadata = self._evaluate_probe_oracle(
                    oracle,
                    probe_payload=probe_payload,
                    output=log_result.stdout,
                )
                commands.append(
                    (
                        "blackbox.logcat",
                        log_result,
                        {
                            "entry_point": entry.id,
                            "session_state": state,
                            "request_id": request_id,
                            "test_case_id": test_case_id,
                            "request_observed": bool(matching_log),
                            "poll_attempts": poll_attempts,
                            "poll_seconds": round(poll_seconds, 3),
                            "probe_success": any(
                                '"success":true' in line.replace('\\"', '"')
                                for line in matching_log
                            ),
                            "probe_result": probe_payload,
                            **oracle_metadata,
                        },
                    )
                )
            if action_attempted:
                ui_result, ui_attempts = self._dump_ui_hierarchy_with_retry(
                    budget=budget,
                    cap=45,
                )
                commands.append(
                    (
                        "blackbox.ui_dump",
                        ui_result,
                        {
                            "entry_point": entry.id,
                            "session_state": state,
                            "test_case_id": test_case_id,
                            "poll_attempts": ui_attempts,
                            **self._evaluate_ui_oracle(
                                oracle,
                                ui_result.stdout,
                                package_name=package_name,
                                baseline_output=(
                                    ui_baseline.stdout if ui_baseline is not None else None
                                ),
                                baseline_valid=bool(
                                    ui_baseline is not None and ui_baseline.exit_code == 0
                                ),
                                observation_valid=ui_result.exit_code == 0,
                            ),
                        },
                    )
                )
            if action_attempted and oracle and oracle.kind in {"log_contains", "process_crash"}:
                target_log = self._adb_budget(["logcat", "-d", "-t", "800"], budget, 60)
                commands.append(
                    (
                        "blackbox.target_logcat",
                        target_log,
                        {
                            "entry_point": entry.id,
                            "session_state": state,
                            "test_case_id": test_case_id,
                            **self._evaluate_target_log_oracle(
                                oracle,
                                target_log.stdout,
                                package_name,
                            ),
                        },
                    )
                )
        return DeviceProbeResult(
            stage="blackbox",
            commands=commands,
            summary={
                "entry_point": entry.id,
                "session_state": state,
                "probe_identity_attempted": probe_request is not None,
                "command_count": len(commands),
            },
        )

    def _poll_probe_logcat(
        self,
        *,
        request_id: str,
        timeout_seconds: int,
        budget: TimeBudget | None,
    ) -> tuple[CommandResult, list[str], int, float]:
        """Wait for an asynchronous Probe result correlated to one request."""

        started = time.monotonic()
        deadline = started + max(timeout_seconds, 1)
        attempts = 0
        last = self._budget_exhausted(["adb", "-s", self.serial or "", "logcat"])
        while True:
            attempts += 1
            remaining = max(1, int(deadline - time.monotonic()))
            last = self._adb_budget(
                ["logcat", "-d", "-t", "300", "-s", "APKSCANNER_PROBE:I"],
                budget,
                min(15, remaining),
            )
            matching = [line for line in last.stdout.splitlines() if request_id in line]
            if matching or last.exit_code != 0:
                return last, matching, attempts, time.monotonic() - started
            if time.monotonic() >= deadline or (budget is not None and budget.expired):
                return last, matching, attempts, time.monotonic() - started
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

    def execute_poc(
        self,
        apk_path: Path,
        spec: AgentPocSpec,
        *,
        target_package_name: str,
        state: str,
        budget: TimeBudget | None = None,
        extras: dict[str, str | int | bool] | None = None,
        oracle: AgentOracleSpec | None = None,
        test_case_id: str | None = None,
        build_metadata: dict[str, Any] | None = None,
    ) -> DeviceProbeResult:
        """Install and launch a dedicated PoC as an ordinary application UID."""
        if not self.configured:
            raise RuntimeError("remote ADB device is not configured")
        self._validate_package(spec.package_name)
        self._validate_package(target_package_name)
        if not apk_path.is_file():
            raise ValueError("platform-built PoC APK is unavailable")
        component = (
            f"{spec.package_name}{spec.launch_component}"
            if spec.launch_component.startswith(".")
            else spec.launch_component
        )
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.$]+", component):
            raise ValueError("PoC launch component is unsafe")
        request_id = secrets.token_hex(12)
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "request_id": request_id,
                    "state": state,
                    "extras": extras or {},
                },
                separators=(",", ":"),
            ).encode()
        ).decode()
        built_target_api = (
            (build_metadata or {}).get("target_api")
            or self.settings.poc_target_api
            or self.settings.device_android_api
        )
        common = {
            "caller_identity": "agent_poc_app",
            "poc_package": spec.package_name,
            "poc_compile_api": (build_metadata or {}).get("compile_api"),
            "poc_min_api": (build_metadata or {}).get("min_api"),
            "poc_target_api": built_target_api,
            "request_id": request_id,
            "session_state": state,
            "test_case_id": test_case_id,
        }
        commands: list[tuple[str, CommandResult, dict[str, Any]]] = []
        with self._lease:
            device_api = self._adb_budget(
                ["shell", "getprop", "ro.build.version.sdk"],
                budget,
                30,
            )
            actual_api = device_api.stdout.strip()
            common["device_api"] = actual_api or None
            common["device_api_matches_poc_target"] = actual_api == str(built_target_api)
            device_api_number = -1
            built_target_api_number = -1
            try:
                device_api_number = int(actual_api)
                minimum_api_number = int(common["poc_min_api"])
                built_target_api_number = int(built_target_api)
            except (TypeError, ValueError):
                common["device_api_satisfies_poc_min"] = None
                common["poc_runtime_compatible"] = None
            else:
                common["device_api_satisfies_poc_min"] = device_api_number >= minimum_api_number
                # compileSdk/targetSdk do not need to equal the device API.
                # The install/launch results remain the authoritative runtime
                # compatibility checks; this flag only captures the hard
                # minSdk boundary.
                common["poc_runtime_compatible"] = device_api_number >= minimum_api_number
            verdict_metadata = self.settings.verdict_metadata(device_api_number)
            common.update(verdict_metadata)
            commands.append(("blackbox.device_profile", device_api, dict(common)))
            if (
                device_api.exit_code != 0
                or common.get("poc_runtime_compatible") is not True
                or built_target_api_number < 36
                or (
                    not bool(common.get("dynamic_verdict_eligible"))
                )
            ):
                return DeviceProbeResult(
                    stage="poc_incompatible",
                    commands=commands,
                    summary={
                        **common,
                        "error": (
                            "PoC/runtime profile is incompatible; targetSdkVersion 36+ is "
                            "required, and the selected validation profile does not permit "
                            "this device to issue a scoped dynamic verdict"
                        ),
                    },
                )
            target_uid_result = self._adb_budget(
                [
                    "shell",
                    "cmd",
                    "package",
                    "list",
                    "packages",
                    "-U",
                    target_package_name,
                ],
                budget,
                30,
            )
            target_uid_match = re.search(
                rf"package:{re.escape(target_package_name)}\s+uid:(\d+)",
                target_uid_result.stdout,
            )
            target_uid = int(target_uid_match.group(1)) if target_uid_match is not None else None
            common["target_uid"] = target_uid
            commands.append(("blackbox.target_uid", target_uid_result, dict(common)))
            # A prior worker may have been interrupted before its cleanup, or a
            # fresh data directory may use a different signing key. Removing
            # only the validated io.apkscanner.poc.* package makes the next
            # install deterministic without touching the target application.
            stale_uninstall = self._adb_budget(
                ["uninstall", spec.package_name],
                budget,
                90,
            )
            commands.append(("blackbox.poc_pre_uninstall", stale_uninstall, dict(common)))
            install = self._adb_budget(
                ["install", "-r", "-t", str(apk_path)],
                budget,
                300,
            )
            commands.append(("blackbox.poc_install", install, dict(common)))
            if install.exit_code == 0:
                clear = self._adb_budget(
                    ["shell", "pm", "clear", spec.package_name],
                    budget,
                    60,
                )
                commands.append(("blackbox.poc_clear", clear, dict(common)))
                log_clear = self._adb_budget(
                    ["logcat", "-c"],
                    budget,
                    30,
                )
                commands.append(("blackbox.poc_logcat_clear", log_clear, dict(common)))
                target_file_baseline: dict[str, Any] | None = None
                if oracle is not None and oracle.kind == "target_file_sha256":
                    baseline_result, target_file_baseline = self._target_file_snapshot(
                        target_package_name,
                        oracle.target_path or "",
                        budget=budget,
                    )
                    commands.append(
                        (
                            "blackbox.poc_target_file_baseline",
                            baseline_result,
                            {
                                **common,
                                "observation_role": "pre_action_baseline",
                                **target_file_baseline,
                            },
                        )
                    )
                ui_baseline: CommandResult | None = None
                if oracle is not None and oracle.kind == "ui_text":
                    ui_wake = self._adb_budget(
                        ["shell", "input", "keyevent", "KEYCODE_WAKEUP"],
                        budget,
                        15,
                    )
                    commands.append(
                        (
                            "blackbox.poc_ui_wake",
                            ui_wake,
                            {
                                **common,
                                "action": "wake_display",
                            },
                        )
                    )
                    ui_unlock = self._adb_budget(
                        ["shell", "wm", "dismiss-keyguard"],
                        budget,
                        15,
                    )
                    commands.append(
                        (
                            "blackbox.poc_ui_unlock",
                            ui_unlock,
                            {
                                **common,
                                "action": "dismiss_keyguard",
                            },
                        )
                    )
                    ui_prepare = self._adb_budget(
                        ["shell", "cmd", "statusbar", "collapse"],
                        budget,
                        15,
                    )
                    commands.append(
                        (
                            "blackbox.poc_ui_prepare",
                            ui_prepare,
                            {
                                **common,
                                "action": "collapse_status_bar",
                            },
                        )
                    )
                    ui_home = self._adb_budget(
                        ["shell", "input", "keyevent", "KEYCODE_HOME"],
                        budget,
                        15,
                    )
                    commands.append(
                        (
                            "blackbox.poc_ui_home",
                            ui_home,
                            {
                                **common,
                                "action": "establish_neutral_baseline",
                            },
                        )
                    )
                    ui_baseline, baseline_attempts = self._dump_ui_hierarchy_with_retry(
                        budget=budget,
                        cap=45,
                    )
                    commands.append(
                        (
                            "blackbox.poc_ui_baseline",
                            ui_baseline,
                            {
                                **common,
                                "observation_role": "pre_action_baseline",
                                "poll_attempts": baseline_attempts,
                                "target_package": target_package_name,
                                "target_text_present": self._ui_text_in_package(
                                    ui_baseline.stdout,
                                    oracle.expected_text or "",
                                    target_package_name,
                                ),
                            },
                        )
                    )
                launch = self._adb_budget(
                    [
                        "shell",
                        "am",
                        "start",
                        "-W",
                        "-n",
                        f"{spec.package_name}/{component}",
                        "--es",
                        "apkscanner_request_id",
                        request_id,
                        "--es",
                        "apkscanner_payload_base64",
                        encoded_payload,
                    ],
                    budget,
                    spec.timeout_seconds,
                )
                commands.append(("blackbox.poc_launch", launch, dict(common)))
                process = self._adb_budget(
                    ["shell", "pidof", spec.package_name],
                    budget,
                    15,
                )
                poc_process_ids = {value for value in process.stdout.split() if value.isdigit()}
                commands.append(
                    (
                        "blackbox.poc_process",
                        process,
                        {
                            **common,
                            "process_ids": sorted(poc_process_ids),
                        },
                    )
                )
                log_result, matching, poll_attempts, observation_seconds = self._poll_poc_logcat(
                    log_tag=spec.log_tag,
                    request_id=request_id,
                    process_ids=poc_process_ids,
                    wait_for_security_impact=bool(
                        oracle is not None
                        and oracle.kind in {"log_contains", "provider_rows"}
                        and oracle.impact != "none"
                    ),
                    timeout_seconds=(
                        1
                        if oracle is not None and oracle.kind == "ui_text"
                        else spec.timeout_seconds
                        if launch.exit_code == 0
                        else 1
                    ),
                    budget=budget,
                )
                normalized = [line.lower().replace(" ", "") for line in matching]
                poc_payload = self._last_json_payload(matching)
                poc_oracle = self._evaluate_poc_oracle(
                    oracle,
                    poc_payload=poc_payload,
                    output="\n".join(matching),
                )
                oracle_matched = bool((poc_oracle.get("oracle") or {}).get("matched"))
                poc_success = any('"success":true' in line for line in normalized) or oracle_matched
                commands.append(
                    (
                        "blackbox.poc_logcat",
                        log_result,
                        {
                            **common,
                            "request_observed": bool(matching),
                            "correlation_mode": (
                                "request_id"
                                if any(request_id in line for line in matching)
                                else "poc_process_id"
                                if matching and poc_process_ids
                                else None
                            ),
                            "poc_success": poc_success,
                            "poc_claimed_security_impact": any(
                                (
                                    '"security_impact_observed":true' in line
                                    or "security_impact_observed=true" in line
                                )
                                for line in normalized
                            ),
                            "matching_line_count": len(matching),
                            "poll_attempts": poll_attempts,
                            "observation_window_seconds": observation_seconds,
                            **poc_oracle,
                        },
                    )
                )
                if oracle is not None and oracle.kind == "target_file_sha256":
                    (
                        target_file_result,
                        target_file_oracle,
                        target_file_poll_attempts,
                        target_file_observation_seconds,
                    ) = self._poll_target_file_change(
                        oracle=oracle,
                        package_name=target_package_name,
                        baseline=target_file_baseline,
                        timeout_seconds=spec.timeout_seconds,
                        budget=budget,
                    )
                    commands.append(
                        (
                            "blackbox.poc_target_file_after",
                            target_file_result,
                            {
                                **common,
                                "observation_role": "post_action_observation",
                                "poll_attempts": target_file_poll_attempts,
                                "observation_window_seconds": target_file_observation_seconds,
                                **target_file_oracle,
                            },
                        )
                    )
                if oracle is not None and oracle.kind == "ui_text":
                    ui_result, ui_oracle, ui_poll_attempts, ui_observation_seconds = (
                        self._poll_poc_ui(
                            oracle=oracle,
                            package_name=target_package_name,
                            baseline_output=(
                                ui_baseline.stdout if ui_baseline is not None else None
                            ),
                            baseline_valid=bool(
                                ui_baseline is not None and ui_baseline.exit_code == 0
                            ),
                            timeout_seconds=(spec.timeout_seconds if launch.exit_code == 0 else 1),
                            budget=budget,
                        )
                    )
                    commands.append(
                        (
                            "blackbox.poc_ui_dump",
                            ui_result,
                            {
                                **common,
                                "poll_attempts": ui_poll_attempts,
                                "observation_window_seconds": ui_observation_seconds,
                                **ui_oracle,
                            },
                        )
                    )
                    system_log = self._adb_budget(
                        [
                            "logcat",
                            "-d",
                            "-t",
                            "800",
                            "-s",
                            "ActivityTaskManager:I",
                            "ActivityManager:I",
                        ],
                        budget,
                        60,
                    )
                    commands.append(
                        (
                            "blackbox.poc_system_logcat",
                            system_log,
                            {
                                **common,
                                "target_package": target_package_name,
                                "background_activity_start_blocked": (
                                    self._background_activity_start_blocked(
                                        system_log.stdout,
                                        target_package_name,
                                    )
                                ),
                            },
                        )
                    )
                if oracle is not None and oracle.kind in {
                    "log_contains",
                    "target_uid_log_contains",
                    "process_crash",
                }:
                    target_log = self._adb_budget(
                        (
                            ["logcat", "-d", "-v", "uid", "-t", "800"]
                            if oracle.kind == "target_uid_log_contains"
                            else ["logcat", "-d", "-t", "800"]
                        ),
                        budget,
                        60,
                    )
                    commands.append(
                        (
                            "blackbox.poc_target_logcat",
                            target_log,
                            {
                                **common,
                                **self._evaluate_target_log_oracle(
                                    oracle,
                                    target_log.stdout,
                                    target_package_name,
                                    target_uid=target_uid,
                                ),
                            },
                        )
                    )
            uninstall = self._adb(
                ["uninstall", spec.package_name],
                timeout=90,
                respect_cancellation=False,
            )
            commands.append(("blackbox.poc_uninstall", uninstall, dict(common)))
        return DeviceProbeResult(
            stage="blackbox_poc",
            commands=commands,
            summary={
                "poc_package": spec.package_name,
                "request_id": request_id,
                "session_state": state,
                "command_count": len(commands),
            },
        )

    def _poll_poc_logcat(
        self,
        *,
        log_tag: str,
        request_id: str,
        timeout_seconds: int,
        budget: TimeBudget | None,
        process_ids: set[str] | None = None,
        wait_for_security_impact: bool = False,
    ) -> tuple[CommandResult, list[str], int, float]:
        started = time.monotonic()
        deadline = started + max(timeout_seconds, 1)
        attempts = 0
        last = self._budget_exhausted(["adb", "-s", self.serial or "", "logcat"])
        while True:
            attempts += 1
            remaining = max(1, int(deadline - time.monotonic()))
            last = self._adb_budget(
                ["logcat", "-d", "-t", "500", "-s", f"{log_tag}:V"],
                budget,
                min(15, remaining),
            )
            matching = [
                line
                for line in last.stdout.splitlines()
                if request_id in line or self._logcat_process_id(line) in (process_ids or set())
            ]
            normalized = [line.lower().replace(" ", "") for line in matching]
            impact_observed = any(
                (
                    '"security_impact_observed":true' in line
                    or "security_impact_observed=true" in line
                )
                for line in normalized
            )
            if (
                matching and (not wait_for_security_impact or impact_observed)
            ) or last.exit_code != 0:
                return last, matching, attempts, time.monotonic() - started
            if time.monotonic() >= deadline or (budget is not None and budget.expired):
                return last, matching, attempts, time.monotonic() - started
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

    def _poll_poc_ui(
        self,
        *,
        oracle: AgentOracleSpec,
        package_name: str,
        baseline_output: str | None,
        baseline_valid: bool,
        timeout_seconds: int,
        budget: TimeBudget | None,
    ) -> tuple[CommandResult, dict[str, Any], int, float]:
        """Wait for an asynchronous target-owned UI transition within the PoC window."""

        started = time.monotonic()
        adaptive_window = self._adaptive_ui_observation_window(timeout_seconds)
        deadline = started + adaptive_window
        attempts = 0
        last = self._budget_exhausted(
            ["adb", "-s", self.serial or "", "shell", "uiautomator", "dump"]
        )
        metadata: dict[str, Any] = {}
        while True:
            attempts += 1
            remaining = max(1, int(deadline - time.monotonic()))
            last = self._dump_ui_hierarchy(
                budget=budget,
                cap=min(45, remaining),
            )
            metadata = self._evaluate_ui_oracle(
                oracle,
                last.stdout,
                package_name=package_name,
                baseline_output=baseline_output,
                baseline_valid=baseline_valid,
                observation_valid=last.exit_code == 0,
            )
            metadata["observation_policy"] = {
                "mode": "adaptive_adb_latency",
                "window_seconds": adaptive_window,
                "recent_ui_dump_p50_seconds": self._recent_ui_dump_p50(),
            }
            if (
                bool((metadata.get("oracle") or {}).get("matched"))
                or time.monotonic() >= deadline
                or (budget is not None and budget.expired)
            ):
                return last, metadata, attempts, time.monotonic() - started
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

    def _poll_target_file_change(
        self,
        *,
        oracle: AgentOracleSpec,
        package_name: str,
        baseline: dict[str, Any] | None,
        timeout_seconds: int,
        budget: TimeBudget | None,
    ) -> tuple[CommandResult, dict[str, Any], int, float]:
        """Wait for an asynchronous target-private state transition after PoC dispatch."""

        started = time.monotonic()
        deadline = started + max(timeout_seconds, 1)
        attempts = 0
        last = self._budget_exhausted(
            ["adb", "-s", self.serial or "", "shell", "run-as", package_name]
        )
        metadata: dict[str, Any] = {}
        while True:
            attempts += 1
            last, observation = self._target_file_snapshot(
                package_name,
                oracle.target_path or "",
                budget=budget,
            )
            metadata = self._evaluate_target_file_oracle(
                oracle,
                before=baseline,
                after=observation,
            )
            observer_available = observation.get("observer_available") is True
            baseline_available = (baseline or {}).get("observer_available") is True
            if (
                bool((metadata.get("oracle") or {}).get("matched"))
                or not observer_available
                or not baseline_available
                or time.monotonic() >= deadline
                or (budget is not None and budget.expired)
            ):
                return last, metadata, attempts, time.monotonic() - started
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

    def _dump_ui_hierarchy_with_retry(
        self,
        *,
        budget: TimeBudget | None,
        cap: int,
        max_attempts: int = 3,
    ) -> tuple[CommandResult, int]:
        """Retry transient Android UI automation failures for a stable snapshot."""

        attempts = 0
        last = self._budget_exhausted(
            ["adb", "-s", self.serial or "", "shell", "uiautomator", "dump"]
        )
        while attempts < max(1, max_attempts):
            attempts += 1
            last = self._dump_ui_hierarchy(budget=budget, cap=cap)
            if last.exit_code == 0 and last.stdout.strip():
                return last, attempts
            if budget is not None and budget.expired:
                break
            if attempts < max_attempts:
                time.sleep(0.5)
        return last, attempts

    def _dump_ui_hierarchy(
        self,
        *,
        budget: TimeBudget | None,
        cap: int,
    ) -> CommandResult:
        """Dump UI XML through a device file so bridged ADB never depends on `/dev/tty`."""

        started = time.monotonic()
        remote_path = f"/data/local/tmp/apkscanner-ui-{secrets.token_hex(8)}.xml"
        dump = self._adb_budget(
            ["shell", "uiautomator", "dump", remote_path],
            budget,
            cap,
        )
        try:
            if dump.exit_code != 0:
                return dump
            readback = self._adb_budget(
                ["shell", "cat", remote_path],
                budget,
                min(15, cap),
            )
            stderr = "\n".join(value for value in (dump.stderr, readback.stderr) if value)
            return CommandResult(
                argv=dump.argv,
                exit_code=readback.exit_code,
                stdout=readback.stdout,
                stderr=stderr,
                timed_out=dump.timed_out or readback.timed_out,
                canceled=dump.canceled or readback.canceled,
            )
        finally:
            self._adb(
                ["shell", "rm", "-f", remote_path],
                timeout=15,
                respect_cancellation=False,
            )
            self._ui_dump_latencies.append(max(0.0, time.monotonic() - started))
            del self._ui_dump_latencies[:-12]

    def _recent_ui_dump_p50(self) -> float | None:
        if not self._ui_dump_latencies:
            return None
        ordered = sorted(self._ui_dump_latencies)
        return round(ordered[len(ordered) // 2], 3)

    def _adaptive_ui_observation_window(self, requested_seconds: int) -> float:
        latency = self._recent_ui_dump_p50() or 2.5
        adaptive = min(60, max(15, latency * 4 + 5))
        return float(max(requested_seconds, adaptive))

    @staticmethod
    def _logcat_process_id(line: str) -> str | None:
        # `logcat -v threadtime` and the default device format both place PID
        # immediately after the timestamp. Ignore short/tag-only formats,
        # which remain correlated through the injected request ID.
        match = re.match(
            r"^\s*\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(\d+)\s+\d+\s",
            line,
        )
        return match.group(1) if match else None

    def _direct_probe_args(self, entry: EntryPoint, package_name: str) -> list[str] | None:
        if entry.kind in {"activity", "activity_alias"}:
            if not re.fullmatch(r"[A-Za-z0-9_.$]+", entry.name):
                return None
            return ["shell", "am", "start", "-W", "-n", f"{package_name}/{entry.name}"]
        if entry.kind == "deep_link":
            # Manifest URI values are untrusted and adb shell has a remote shell boundary.
            # Deep links are dispatched through the base64 Probe APK protocol instead.
            return None
        if entry.kind == "service":
            if not re.fullmatch(r"[A-Za-z0-9_.$]+", entry.name):
                return None
            return ["shell", "am", "startservice", "-n", f"{package_name}/{entry.name}"]
        if entry.kind == "receiver":
            if not re.fullmatch(r"[A-Za-z0-9_.$]+", entry.name):
                return None
            return ["shell", "am", "broadcast", "-n", f"{package_name}/{entry.name}"]
        if entry.kind == "provider":
            authority = entry.metadata_json.get("authorities")
            if authority and re.fullmatch(r"[A-Za-z0-9_.-]+(?:;[A-Za-z0-9_.-]+)*", str(authority)):
                authority = str(authority).split(";", 1)[0]
                return ["shell", "content", "query", "--uri", f"content://{authority}"]
        return None

    @staticmethod
    def _background_activity_start_blocked(output: str, package_name: str) -> bool:
        """Identify an Android system BAL denial for the target package."""

        relevant = [line for line in output.splitlines() if package_name in line]
        return any(
            (
                "Abort background activity start" in line
                or (
                    "Background activity start" in line
                    and "allowBackgroundActivityStart: false" in line
                )
            )
            for line in relevant
        )

    @staticmethod
    def _probe_request(
        entry: EntryPoint,
        package_name: str,
        *,
        uri_override: str | None = None,
        extras: dict[str, str | int | bool] | None = None,
        operation: str = "auto",
        method: str | None = None,
        argument: str | None = None,
        binder_transaction_code: int | None = None,
        binder_interface_descriptor: str | None = None,
        binder_reply_type: str | None = None,
        binder_read_exception: bool | None = None,
        binder_script: list[dict[str, Any]] | None = None,
        intent_action: str | None = None,
        categories: list[str] | None = None,
    ) -> dict[str, Any] | None:
        request: dict[str, Any] = {
            "kind": entry.kind,
            "package": package_name,
            "component": (
                entry.owner_component or ("" if entry.kind == "deep_link" else entry.name)
            ),
        }
        if entry.kind in {"activity", "activity_alias"} and uri_override is not None:
            # Preserve implicit URI dispatch semantics even when the planner
            # attached a manifest deep link to its owning Activity entry.
            # Older Probe APKs already understand the deep_link request kind.
            request["kind"] = "deep_link"
            request["uri"] = uri_override
        elif entry.kind == "deep_link":
            request["uri"] = uri_override or entry.name
        elif entry.kind == "provider":
            authority = entry.metadata_json.get("authorities")
            if not authority:
                return None
            authority = str(authority).split(";", 1)[0]
            request["uri"] = uri_override or f"content://{authority}"
        if extras:
            request["extras"] = extras
        if operation != "auto":
            request["operation"] = operation
        if method is not None:
            request["method"] = method
        if argument is not None:
            request["argument"] = argument
        if operation in {"binder_transact", "binder_script"}:
            request["binder_transaction_code"] = binder_transaction_code
            request["binder_read_exception"] = (
                True if binder_read_exception is None else binder_read_exception
            )
            if binder_reply_type is not None:
                request["binder_reply_type"] = binder_reply_type
            if binder_script is not None:
                request["binder_script"] = binder_script
            if binder_interface_descriptor is not None:
                request["binder_interface_descriptor"] = binder_interface_descriptor
        if intent_action is not None:
            request["intent_action"] = intent_action
        if categories:
            request["categories"] = categories
        return request

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _target_file_snapshot(
        self,
        package_name: str,
        target_path: str,
        *,
        budget: TimeBudget | None,
    ) -> tuple[CommandResult, dict[str, Any]]:
        """Hash a target-private file without returning its contents.

        Android permits this observer only for debuggable targets through ``run-as`` (or on a
        separately authorized privileged test image). Failure to obtain the snapshot is recorded
        as an Oracle capability gap and never treated as evidence that the file did not change.
        """

        result = self._adb_budget(
            ["shell", "run-as", package_name, "/system/bin/sha256sum", target_path],
            budget,
            30,
        )
        combined = "\n".join(value for value in (result.stdout, result.stderr) if value)
        normalized_output = combined.lower()
        hash_match = re.search(r"(?m)^([a-fA-F0-9]{64})(?:\s|$)", result.stdout)
        missing = bool(
            result.exit_code != 0
            and target_path.lower() in normalized_output
            and any(
                marker in normalized_output
                for marker in ("no such file", "not found")
            )
            and "exec failed" not in normalized_output
            and "not debuggable" not in normalized_output
            and "is unknown" not in normalized_output
        )
        observer_available = bool(hash_match is not None or missing)
        return result, {
            "target_path": target_path,
            "observer": "adb_run_as_sha256sum",
            "observer_available": observer_available,
            "file_exists": bool(hash_match is not None),
            "sha256": hash_match.group(1).lower() if hash_match is not None else None,
            "observer_gap": (
                None
                if observer_available
                else "Target-private hash observation requires a debuggable target or an "
                "explicitly authorized privileged test device."
            ),
        }

    @staticmethod
    def _last_json_payload(lines: list[str]) -> dict[str, Any] | None:
        for line in reversed(lines):
            start = line.find("{")
            if start < 0:
                continue
            try:
                value = json.loads(line[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
        return None

    @staticmethod
    def _oracle_metadata(
        oracle: AgentOracleSpec,
        *,
        matched: bool,
        observation: dict[str, Any],
        impact_observed: bool = False,
        refutation_observed: bool = False,
    ) -> dict[str, Any]:
        impact = bool(oracle.impact != "none" and matched and impact_observed)
        return {
            "oracle": {
                "kind": oracle.kind,
                "impact": oracle.impact,
                "matched": matched,
                "observation": observation,
                "impact_predicate_satisfied": impact,
            },
            "security_impact_observed": impact,
            "oracle_refuted": bool(oracle.refute_on_miss and not matched and refutation_observed),
        }

    @classmethod
    def _evaluate_probe_oracle(
        cls,
        oracle: AgentOracleSpec | None,
        *,
        probe_payload: dict[str, Any] | None,
        output: str,
    ) -> dict[str, Any]:
        if oracle is None:
            return {}
        success = bool(probe_payload and probe_payload.get("success") is True)
        if oracle.kind == "reachability":
            return cls._oracle_metadata(
                oracle,
                matched=success,
                observation={"probe_success": success},
                refutation_observed=probe_payload is not None,
            )
        if oracle.kind == "provider_rows":
            rows = probe_payload.get("rowCount") if isinstance(probe_payload, dict) else None
            matched = success and isinstance(rows, int) and rows >= int(oracle.minimum_rows or 1)
            return cls._oracle_metadata(
                oracle,
                matched=matched,
                observation={"row_count": rows, "minimum_rows": oracle.minimum_rows or 1},
                impact_observed=(matched and oracle.impact == "unauthorized_data_access"),
                refutation_observed=success,
            )
        if (
            oracle.kind == "binder_reply"
            and oracle.match_mode != "non_empty"
            and oracle.expected_text
        ):
            replies = probe_payload.get("binderReplies") if isinstance(probe_payload, dict) else None
            reply = (
                replies[oracle.reply_index]
                if isinstance(replies, list) and oracle.reply_index < len(replies)
                else probe_payload.get("binderReply")
                if isinstance(probe_payload, dict) and oracle.reply_index == 0
                else None
            )
            transact_returned = bool(
                isinstance(probe_payload, dict)
                and probe_payload.get("binderTransactReturned") is True
            )
            actual_text = str(reply).lower() if isinstance(reply, bool) else str(reply)
            if oracle.match_mode == "contains":
                predicate_matched = oracle.expected_text in actual_text
            elif oracle.match_mode == "regex":
                predicate_matched = re.search(oracle.expected_text, actual_text) is not None
            elif oracle.match_mode == "sha256":
                predicate_matched = hashlib.sha256(actual_text.encode()).hexdigest() == (
                    oracle.expected_text
                )
            else:
                predicate_matched = actual_text == oracle.expected_text
            matched = success and transact_returned and reply is not None and predicate_matched
            return cls._oracle_metadata(
                oracle,
                matched=matched,
                observation={
                    "expected_text": oracle.expected_text,
                    "actual_text": actual_text if reply is not None else None,
                    "reply_type": (
                        probe_payload.get("binderReplyType")
                        if isinstance(probe_payload, dict)
                        else None
                    ),
                    "reply_index": oracle.reply_index,
                    "match_mode": oracle.match_mode,
                    "transact_returned": transact_returned,
                },
                impact_observed=(matched and oracle.impact == "unauthorized_data_access"),
                refutation_observed=success and transact_returned,
            )
        if oracle.kind == "binder_reply" and oracle.match_mode == "non_empty":
            replies = probe_payload.get("binderReplies") if isinstance(probe_payload, dict) else None
            reply = (
                replies[oracle.reply_index]
                if isinstance(replies, list) and oracle.reply_index < len(replies)
                else probe_payload.get("binderReply")
                if isinstance(probe_payload, dict) and oracle.reply_index == 0
                else None
            )
            transact_returned = bool(
                isinstance(probe_payload, dict)
                and probe_payload.get("binderTransactReturned") is True
            )
            matched = bool(
                success
                and transact_returned
                and reply is not None
                and reply != ""
                and reply != b""
            )
            return cls._oracle_metadata(
                oracle,
                matched=matched,
                observation={
                    "reply_index": oracle.reply_index,
                    "match_mode": oracle.match_mode,
                    "actual_text": str(reply) if reply is not None else None,
                    "transact_returned": transact_returned,
                },
                impact_observed=False,
                refutation_observed=success and transact_returned,
            )
        if oracle.kind == "log_contains" and oracle.expected_text:
            matched = oracle.expected_text in output
            return cls._oracle_metadata(
                oracle,
                matched=matched,
                observation={"expected_text": oracle.expected_text},
            )
        return {}

    @classmethod
    def _evaluate_poc_oracle(
        cls,
        oracle: AgentOracleSpec | None,
        *,
        poc_payload: dict[str, Any] | None,
        output: str,
    ) -> dict[str, Any]:
        if oracle is None:
            return {}
        payload = dict(poc_payload or {})
        if "rowCount" not in payload and "row_count" in payload:
            payload["rowCount"] = payload["row_count"]
        if oracle.kind in {"reachability", "provider_rows"}:
            return cls._evaluate_probe_oracle(
                oracle,
                probe_payload=payload or None,
                output=output,
            )
        if oracle.kind == "log_contains" and oracle.expected_text:
            normalized_output = output.lower().replace(" ", "")
            structured_success = bool(
                payload.get("success") is True
                or '"success":true' in normalized_output
                or "success=true" in normalized_output
            )
            plain_impact_claim = (
                '"security_impact_observed":true' in normalized_output
                or "'security_impact_observed':true" in normalized_output
                or "security_impact_observed=true" in normalized_output
            )
            matched = bool(
                (structured_success or plain_impact_claim) and oracle.expected_text in output
            )
            return cls._oracle_metadata(
                oracle,
                matched=matched,
                observation={
                    "expected_text": oracle.expected_text,
                    "structured_poc_result": bool(payload),
                },
                impact_observed=False,
                refutation_observed=bool(payload) or plain_impact_claim,
            )
        return {}

    @classmethod
    def _evaluate_target_file_oracle(
        cls,
        oracle: AgentOracleSpec,
        *,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if oracle.kind != "target_file_sha256":
            return {}
        baseline = dict(before or {})
        observation = dict(after or {})
        baseline_available = baseline.get("observer_available") is True
        observation_available = observation.get("observer_available") is True
        comparable = baseline_available and observation_available
        before_state = (baseline.get("file_exists"), baseline.get("sha256"))
        after_state = (observation.get("file_exists"), observation.get("sha256"))
        changed = bool(comparable and before_state != after_state)
        return cls._oracle_metadata(
            oracle,
            matched=changed,
            observation={
                "target_path": oracle.target_path,
                "observer": "adb_run_as_sha256sum",
                "baseline_available": baseline_available,
                "observation_available": observation_available,
                "file_existed_before": baseline.get("file_exists"),
                "file_exists_after": observation.get("file_exists"),
                "sha256_before": baseline.get("sha256"),
                "sha256_after": observation.get("sha256"),
                "state_transition": changed,
                "observer_gap": baseline.get("observer_gap")
                or observation.get("observer_gap"),
            },
            impact_observed=changed,
            refutation_observed=comparable,
        )

    @classmethod
    def _evaluate_ui_oracle(
        cls,
        oracle: AgentOracleSpec | None,
        output: str,
        *,
        package_name: str | None = None,
        baseline_output: str | None = None,
        baseline_valid: bool = False,
        observation_valid: bool = True,
    ) -> dict[str, Any]:
        if oracle is None or oracle.kind != "ui_text" or not oracle.expected_text:
            return {}
        target_match = bool(
            package_name
            and observation_valid
            and cls._ui_text_in_package(
                output,
                oracle.expected_text,
                package_name,
            )
        )
        baseline_match = bool(
            package_name
            and baseline_valid
            and baseline_output is not None
            and cls._ui_text_in_package(
                baseline_output,
                oracle.expected_text,
                package_name,
            )
        )
        target_transition = bool(
            baseline_valid and observation_valid and target_match and not baseline_match
        )
        return cls._oracle_metadata(
            oracle,
            matched=target_match,
            observation={
                "expected_text": oracle.expected_text,
                "target_package": package_name,
                "target_text_present_before": baseline_match,
                "target_text_present_after": target_match,
                "target_text_transition": target_transition,
                "baseline_valid": baseline_valid,
                "observation_valid": observation_valid,
            },
            impact_observed=(
                target_transition
                and oracle.impact
                in {"unauthorized_data_access", "unauthorized_state_change"}
            ),
        )

    @staticmethod
    def _ui_text_in_package(
        output: str,
        expected_text: str,
        package_name: str,
    ) -> bool:
        """Match UI text only when uiautomator attributes it to the target app."""

        if not output or not expected_text or not package_name:
            return False
        starts = [
            position
            for marker in ("<?xml", "<hierarchy", "<node")
            if (position := output.find(marker)) >= 0
        ]
        if not starts:
            return False
        fragment = output[min(starts) :]
        hierarchy_end = fragment.rfind("</hierarchy>")
        if hierarchy_end >= 0:
            fragment = fragment[: hierarchy_end + len("</hierarchy>")]
        try:
            root = ElementTree.fromstring(fragment)
        except ElementTree.ParseError:
            return False
        for node in root.iter():
            if node.attrib.get("package") != package_name:
                continue
            if expected_text in node.attrib.get("text", ""):
                return True
            if expected_text in node.attrib.get("content-desc", ""):
                return True
        return False

    @classmethod
    def _evaluate_target_log_oracle(
        cls,
        oracle: AgentOracleSpec,
        output: str,
        package_name: str,
        *,
        target_uid: int | None = None,
    ) -> dict[str, Any]:
        if oracle.kind == "log_contains" and oracle.expected_text:
            matched = oracle.expected_text in output
            observation = {"expected_text": oracle.expected_text}
            impact_observed = False
        elif oracle.kind == "target_uid_log_contains":
            matching_lines = [
                line
                for line in output.splitlines()
                if oracle.expected_text
                and oracle.expected_text in line
                and cls._logcat_line_uid(line) == target_uid
            ]
            matched = bool(target_uid is not None and matching_lines)
            observation = {
                "expected_text": oracle.expected_text,
                "target_uid": target_uid,
                "matching_target_uid_lines": len(matching_lines),
            }
            impact_observed = bool(matched and oracle.impact == "privileged_action")
        elif oracle.kind == "process_crash":
            matched = cls._target_process_crashed(output, package_name)
            observation = {
                "package": package_name,
                "target_process_fatal_exception": matched,
            }
            impact_observed = matched and oracle.impact == "denial_of_service"
        else:
            return {}
        return cls._oracle_metadata(
            oracle,
            matched=matched,
            observation=observation,
            impact_observed=impact_observed,
        )

    @staticmethod
    def _logcat_line_uid(line: str) -> int | None:
        match = re.match(
            r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(\d+)\s+\d+\s+\d+\s+",
            line,
        )
        return int(match.group(1)) if match is not None else None

    @staticmethod
    def _target_process_crashed(output: str, package_name: str) -> bool:
        """Require a FATAL EXCEPTION block owned by the exact target process."""

        process_pattern = re.compile(
            rf"Process:\s*{re.escape(package_name)}"
            r"(?::[A-Za-z0-9_.-]+)?(?:,|\s|$)"
        )
        fatal_markers = list(re.finditer(r"FATAL EXCEPTION", output))
        for index, fatal in enumerate(fatal_markers):
            next_fatal = (
                fatal_markers[index + 1].start() if index + 1 < len(fatal_markers) else len(output)
            )
            block_end = min(next_fatal, fatal.end() + 4000)
            if process_pattern.search(output[fatal.start() : block_end]):
                return True
        return False

    def _adb(
        self,
        args: list[str],
        timeout: int | None = None,
        *,
        respect_cancellation: bool = True,
    ) -> CommandResult:
        if not self.serial:
            return CommandResult(["adb", *args], 127, "", "ADB serial is not configured")
        return self.runner.run(
            ["adb", "-s", self.serial, *args],
            timeout=timeout,
            cancel_event=self._active_cancel_event if respect_cancellation else None,
        )

    def execute_gateway(
        self,
        args: list[str],
        timeout: int = 30,
        *,
        policy: str = "scoped",
    ) -> CommandResult:
        """Execute a policy-validated command on this adapter's fixed serial."""

        from .adb_gateway import validate_adaptive_adb_args, validate_adb_args

        if policy == "adaptive":
            validate_adaptive_adb_args(args)
        else:
            validate_adb_args(args)
        with self._lease:
            return self._adb(args, timeout=max(1, min(120, timeout)))

    def _adb_budget(self, args: list[str], budget: TimeBudget | None, cap: int) -> CommandResult:
        timeout = cap if budget is None else budget.remaining(cap)
        if timeout <= 0:
            return self._budget_exhausted(["adb", "-s", self.serial or "", *args])
        return self._adb(args, timeout=timeout)

    @staticmethod
    def _budget_exhausted(argv: list[str]) -> CommandResult:
        return CommandResult(
            argv=argv,
            exit_code=124,
            stdout="",
            stderr="task time budget exhausted",
            timed_out=True,
        )

    @staticmethod
    def _validate_package(package_name: str) -> None:
        if not AdbDeviceAdapter.package_safe(package_name):
            raise ValueError("manifest package name is unsafe for remote ADB commands")

    @staticmethod
    def package_safe(package_name: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package_name))


class AdbDevicePool:
    """Assign each investigation one exclusive adapter for its complete task."""

    def __init__(self, adapters: list[AdbDeviceAdapter]) -> None:
        self._lock = threading.RLock()
        self._by_serial = {
            str(adapter.serial): adapter for adapter in adapters if adapter.serial is not None
        }
        self.scheduler = DevicePoolScheduler(tuple(self._by_serial))

    @property
    def adapters(self) -> tuple[AdbDeviceAdapter, ...]:
        with self._lock:
            return tuple(self._by_serial.values())

    @property
    def configured(self) -> bool:
        state = self.scheduler.snapshot()
        draining = set(state.get("draining", []))
        assignable = [item for item in self.adapters if item.serial not in draining]
        return bool(assignable) and all(
            adapter.runner.available("adb") for adapter in assignable
        )

    @property
    def capacity(self) -> int:
        state = self.scheduler.snapshot()
        return max(0, len(self.adapters) - len(state.get("draining", [])))

    @property
    def serials(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._by_serial)

    def add(self, adapter: AdbDeviceAdapter) -> None:
        if adapter.serial is None:
            raise ValueError("ADB adapter serial is required")
        serial = str(adapter.serial)
        with self._lock:
            self._by_serial[serial] = adapter
            self.scheduler.add_serial(serial)

    def drain(self, serial: str) -> bool:
        return self.scheduler.drain_serial(serial)

    def restore(self, serial: str) -> bool:
        return self.scheduler.restore_serial(serial)

    def remove(self, serial: str) -> bool:
        if not self.scheduler.remove_serial(serial):
            return False
        with self._lock:
            self._by_serial.pop(serial, None)
        return True

    def is_active(self, serial: str) -> bool:
        return self.scheduler.is_active(serial)

    @staticmethod
    def package_safe(package_name: str) -> bool:
        return AdbDeviceAdapter.package_safe(package_name)

    def wake_waiters(self) -> None:
        self.scheduler.wake_waiters()

    def snapshot(self) -> dict[str, Any]:
        state = self.scheduler.snapshot()
        return {
            "configured": self.configured,
            "capacity": len(self.adapters),
            "serials": list(self.serials),
            "active": state["active"],
            "draining": state.get("draining", []),
            "waiting": state["waiting"],
        }

    def capability(self, *, non_blocking: bool = False) -> dict[str, Any]:
        if not self.configured:
            snapshot = self.scheduler.snapshot()
            return {
                "available": False,
                "detail": (
                    "All ADB devices are draining"
                    if snapshot.get("draining") and self.serials
                    else "No ADB device serial is configured"
                ),
                "serials": list(self.serials),
                "draining": snapshot.get("draining", []),
            }
        snapshot = self.scheduler.snapshot()
        active_serials = set(snapshot["active"])
        draining_serials = set(snapshot.get("draining", []))
        available = [
            adapter
            for adapter in self.adapters
            if adapter.serial not in active_serials
            and adapter.serial not in draining_serials
        ]
        if non_blocking and not available:
            return {
                # The pool is healthy but temporarily has no free lease. Callers
                # must distinguish this from a disconnected or invalid device.
                "available": True,
                "busy": True,
                "detail": "All configured ADB devices are assigned to active tasks",
                "serials": list(self.serials),
                "active": snapshot["active"],
                "waiting_count": len(snapshot["waiting"]),
            }
        failures: list[dict[str, Any]] = []
        for adapter in available or list(self.adapters):
            capability = adapter.capability(non_blocking=non_blocking)
            if capability.get("available"):
                return {
                    **capability,
                    "pool_capacity": len(self.adapters),
                    "pool_serials": list(self.serials),
                }
            failures.append(
                {
                    "serial": adapter.serial,
                    "detail": capability.get("detail"),
                }
            )
        return {
            "available": False,
            "busy": False,
            "detail": "No configured ADB device passed its capability check",
            "serials": list(self.serials),
            "failures": failures,
        }

    @contextmanager
    def task_lease(
        self,
        task_id: str,
        *,
        priority: int,
        cancel_event: threading.Event,
        on_queued=None,  # noqa: ANN001
        on_acquired=None,  # noqa: ANN001
        on_released=None,  # noqa: ANN001
    ):  # noqa: ANN201
        with self.scheduler.lease(
            task_id,
            priority=priority,
            cancel_event=cancel_event,
            on_queued=on_queued,
        ) as metadata:
            serial = str(metadata["serial"])
            with self._lock:
                adapter = self._by_serial[serial]
            acquired_at = time.monotonic()
            session_started = False
            try:
                if cancel_event.is_set():
                    raise DeviceLeaseCancelledError(
                        "device lease was cancelled before the command session"
                    )
                adapter._active_cancel_event = cancel_event
                session_started = True
                if on_acquired is not None:
                    on_acquired(metadata["wait_seconds"], adapter)
                yield {
                    **metadata,
                    "device": adapter,
                }
            finally:
                held_seconds = max(0.0, time.monotonic() - acquired_at)
                adapter._active_cancel_event = None
                if session_started and on_released is not None:
                    on_released(held_seconds, adapter)
