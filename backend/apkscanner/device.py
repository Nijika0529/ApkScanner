from __future__ import annotations

import base64
import heapq
import json
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auth import CredentialStore, load_auth_flow
from .config import Settings
from .models import EntryPoint
from .schemas import AgentPocSpec
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
                        raise DeviceLeaseCancelledError(
                            "device lease was cancelled while queued"
                        )
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


class AdbDeviceAdapter:
    """Serialized remote-ADB adapter for the single-device MVP."""

    NON_BLOCKING_CAPABILITY_TTL_SECONDS = 30.0

    def __init__(self, settings: Settings, runner: ToolRunner):
        self.settings = settings
        self.runner = runner
        self.serial = settings.adb_serial
        self._lease = threading.RLock()
        self.scheduler = SingleDeviceScheduler()
        self._last_capability: dict[str, Any] | None = None
        self._last_capability_at: float | None = None
        self._active_cancel_event: threading.Event | None = None
        self.credentials = CredentialStore()
        self.auth_flow_error: str | None = None
        try:
            self.auth_flow = load_auth_flow(settings.auth_flow_path)
        except (OSError, ValueError) as exc:
            self.auth_flow = None
            self.auth_flow_error = str(exc)

    @property
    def configured(self) -> bool:
        return bool(self.serial and self.runner.available("adb"))

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
            command_lock_wait_started = time.monotonic()
            held_seconds = 0.0
            session_started = False
            try:
                with self._lease:
                    self._active_cancel_event = cancel_event
                    held_at = time.monotonic()
                    metadata["wait_seconds"] += held_at - command_lock_wait_started
                    try:
                        if cancel_event.is_set():
                            raise DeviceLeaseCancelledError(
                                "device lease was cancelled before the command session"
                            )
                        session_started = True
                        if on_acquired is not None:
                            on_acquired(metadata["wait_seconds"])
                        yield metadata
                    finally:
                        held_seconds = max(0.0, time.monotonic() - held_at)
                        self._active_cancel_event = None
            finally:
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
        ready = state.exit_code == 0 and actual_api == str(self.settings.device_android_api)
        detail = None
        if actual_api != str(self.settings.device_android_api):
            detail = (
                f"expected Android {self.settings.device_android_version} / API "
                f"{self.settings.device_android_api}, found {version.stdout.strip()} / API "
                f"{actual_api or 'unknown'}"
            )
        result = {
            "available": ready,
            "state": state.stdout.strip(),
            "android_version": version.stdout.strip(),
            "api_level": actual_api,
            "root": root.exit_code == 0 and root.stdout.strip() == "0",
            "serial": self.serial,
            "detail": detail,
        }
        self._last_capability = dict(result)
        self._last_capability_at = time.monotonic()
        return result

    def auth_capability(self, package_name: str | None = None) -> dict[str, Any]:
        if self.auth_flow_error:
            return {"available": False, "detail": self.auth_flow_error}
        if self.auth_flow is None:
            return {"available": False, "detail": "APKSCANNER_AUTH_FLOW is not configured"}
        if self.auth_flow.steps[-1].action != "assert_text":
            return {
                "available": False,
                "detail": (
                    "auth flow must end with an assert_text step to prove login succeeded"
                ),
            }
        if package_name and self.auth_flow.package and self.auth_flow.package != package_name:
            return {
                "available": False,
                "detail": f"auth flow targets {self.auth_flow.package}, not {package_name}",
            }
        missing: list[str] = []
        try:
            for name in sorted(self.auth_flow.required_secrets):
                if self.credentials.get(self.auth_flow.profile, name) is None:
                    missing.append(name)
        except Exception as exc:  # host keyring surface
            return {"available": False, "detail": f"keyring unavailable: {exc}"}
        if missing:
            return {"available": False, "detail": f"missing keyring secrets: {', '.join(missing)}"}
        return {
            "available": True,
            "profile": self.auth_flow.profile,
            "step_count": len(self.auth_flow.steps),
        }

    def prepare(
        self, apk_path: Path, package_name: str, budget: TimeBudget | None = None
    ) -> list[tuple[str, CommandResult, dict]]:
        self._validate_package(package_name)
        commands: list[tuple[str, CommandResult, dict]] = []
        health = self._adb_budget(["get-state"], budget, 30)
        commands.append(("device.health", health, {}))
        if health.exit_code != 0:
            return commands
        install = self._adb_budget(["install", "-r", "-t", str(apk_path)], budget, 300)
        commands.append(
            (
                "device.install",
                install,
                {"package": package_name},
            )
        )
        if install.exit_code != 0:
            return commands
        if self.settings.probe_apk_path and self.settings.probe_apk_path.is_file():
            commands.append(
                (
                    "device.install_probe",
                    self._adb_budget(
                        ["install", "-r", "-t", str(self.settings.probe_apk_path)], budget, 300
                    ),
                    {"package": "io.apkscanner.probe"},
                )
            )
        commands.append(
            (
                "device.clear",
                self._adb_budget(["shell", "pm", "clear", package_name], budget, 60),
                {"package": package_name},
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

    def probe(
        self,
        entry: EntryPoint,
        package_name: str,
        *,
        state: str = "guest",
        budget: TimeBudget | None = None,
        uri_override: str | None = None,
        extras: dict[str, str | int | bool] | None = None,
        test_case_id: str | None = None,
    ) -> DeviceProbeResult:
        if not self.configured:
            raise RuntimeError("remote ADB device is not configured")
        self._validate_package(package_name)
        commands: list[tuple[str, CommandResult, dict[str, Any]]] = []
        with self._lease:
            direct_argv = (
                self._direct_probe_args(entry, package_name)
                if uri_override is None and extras is None
                else None
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
            probe_request = self._probe_request(
                entry, package_name, uri_override=uri_override, extras=extras
            )
            request_id = secrets.token_hex(8) if probe_request else None
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
            log_result = self._adb_budget(
                ["logcat", "-d", "-t", "300", "-s", "APKSCANNER_PROBE:I"],
                budget,
                60,
            )
            matching_log = [
                line for line in log_result.stdout.splitlines() if request_id and request_id in line
            ]
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
                        "probe_success": any(
                            '"success":true' in line.replace('\\"', '"')
                            for line in matching_log
                        ),
                    },
                )
            )
            commands.append(
                (
                    "blackbox.ui_dump",
                    self._adb_budget(
                        ["shell", "uiautomator", "dump", "/dev/tty"], budget, 45
                    ),
                    {
                        "entry_point": entry.id,
                        "session_state": state,
                        "test_case_id": test_case_id,
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

    def execute_poc(
        self,
        apk_path: Path,
        spec: AgentPocSpec,
        *,
        state: str,
        budget: TimeBudget | None = None,
        extras: dict[str, str | int | bool] | None = None,
        test_case_id: str | None = None,
    ) -> DeviceProbeResult:
        """Install and launch a platform-built PoC as an ordinary application UID."""
        if not self.configured:
            raise RuntimeError("remote ADB device is not configured")
        self._validate_package(spec.package_name)
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
        common = {
            "caller_identity": "agent_poc_app",
            "poc_package": spec.package_name,
            "request_id": request_id,
            "session_state": state,
            "test_case_id": test_case_id,
        }
        commands: list[tuple[str, CommandResult, dict[str, Any]]] = []
        with self._lease:
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
                log_result = self._adb_budget(
                    ["logcat", "-d", "-t", "500", "-s", f"{spec.log_tag}:I"],
                    budget,
                    60,
                )
                matching = [
                    line for line in log_result.stdout.splitlines() if request_id in line
                ]
                normalized = [line.lower().replace(" ", "") for line in matching]
                commands.append(
                    (
                        "blackbox.poc_logcat",
                        log_result,
                        {
                            **common,
                            "request_observed": bool(matching),
                            "poc_success": any('"success":true' in line for line in normalized),
                            "poc_claimed_security_impact": any(
                                '"security_impact_observed":true' in line
                                for line in normalized
                            ),
                            "matching_line_count": len(matching),
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

    def authenticate(
        self, package_name: str, budget: TimeBudget | None = None
    ) -> list[tuple[str, CommandResult, dict[str, Any]]]:
        self._validate_package(package_name)
        capability = self.auth_capability(package_name)
        if not capability.get("available") or self.auth_flow is None:
            return [
                (
                    "auth.unavailable",
                    CommandResult(
                        argv=["auth-flow"],
                        exit_code=125,
                        stdout="",
                        stderr=str(capability.get("detail", "authentication unavailable")),
                    ),
                    {"profile": self.auth_flow.profile if self.auth_flow else "unconfigured"},
                )
            ]
        commands: list[tuple[str, CommandResult, dict[str, Any]]] = []
        for index, step in enumerate(self.auth_flow.steps):
            if budget and budget.expired:
                commands.append(
                    (
                        "auth.timeout",
                        self._budget_exhausted(["auth-flow", str(index)]),
                        {"step": index, "action": step.action},
                    )
                )
                break
            metadata = {
                "profile": self.auth_flow.profile,
                "step": index,
                "action": step.action,
                "redacted": step.action == "text",
            }
            if step.action == "wait":
                seconds = min(step.seconds or 0, budget.remaining() if budget else 30)
                time.sleep(seconds)
                result = CommandResult(["wait", str(seconds)], 0, f"waited {seconds}s", "")
            elif step.action == "start":
                if step.component:
                    args = ["shell", "am", "start", "-W", "-n", f"{package_name}/{step.component}"]
                else:
                    args = [
                        "shell",
                        "monkey",
                        "-p",
                        package_name,
                        "-c",
                        "android.intent.category.LAUNCHER",
                        "1",
                    ]
                result = self._adb_budget(args, budget, 60)
            elif step.action == "tap":
                result = self._adb_budget(
                    ["shell", "input", "tap", str(step.x), str(step.y)], budget, 30
                )
            elif step.action == "keyevent":
                result = self._adb_budget(
                    ["shell", "input", "keyevent", str(step.keycode)], budget, 30
                )
            elif step.action == "assert_text":
                observed = self._adb_budget(
                    ["shell", "uiautomator", "dump", "/dev/tty"], budget, 45
                )
                if observed.exit_code == 0 and step.value not in observed.stdout:
                    result = CommandResult(
                        argv=observed.argv,
                        exit_code=3,
                        stdout=observed.stdout,
                        stderr="authentication verification text was not observed",
                    )
                else:
                    result = observed
            else:
                value = step.value
                if step.secret:
                    value = self.credentials.get(self.auth_flow.profile, step.secret)
                assert value is not None
                encoded = self._safe_input_text(value)
                actual = self._adb_budget(["shell", "input", "text", encoded], budget, 30)
                stdout = actual.stdout.replace(value, "<redacted>").replace(
                    encoded, "<redacted>"
                )
                stderr = actual.stderr.replace(value, "<redacted>").replace(
                    encoded, "<redacted>"
                )
                result = CommandResult(
                    argv=["adb", "-s", self.serial or "", "shell", "input", "text", "<redacted>"],
                    exit_code=actual.exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=actual.timed_out,
                    canceled=actual.canceled,
                )
            commands.append(("auth.step", result, metadata))
            if result.exit_code != 0:
                break
        return commands

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
    def _probe_request(
        entry: EntryPoint,
        package_name: str,
        *,
        uri_override: str | None = None,
        extras: dict[str, str | int | bool] | None = None,
    ) -> dict[str, Any] | None:
        request: dict[str, Any] = {
            "kind": entry.kind,
            "package": package_name,
            "component": (
                entry.owner_component
                or ("" if entry.kind == "deep_link" else entry.name)
            ),
        }
        if (
            entry.kind in {"activity", "activity_alias"}
            and uri_override is not None
        ):
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
        return request

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

    def _adb_budget(
        self, args: list[str], budget: TimeBudget | None, cap: int
    ) -> CommandResult:
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
    def _safe_input_text(value: str) -> str:
        if not value or len(value) > 500:
            raise ValueError("auth text must contain between 1 and 500 characters")
        if "%s" in value:
            raise ValueError(
                "auth text cannot contain the adb input-text space escape sequence %s"
            )
        encoded = value.replace(" ", "%s")
        if not re.fullmatch(r"[A-Za-z0-9@._+%=-]+", encoded):
            raise ValueError(
                "auth text contains characters unsafe for adb shell input; use a test credential "
                "containing only letters, digits, spaces, and @._+%=-"
            )
        return encoded

    @staticmethod
    def _validate_package(package_name: str) -> None:
        if not AdbDeviceAdapter.package_safe(package_name):
            raise ValueError("manifest package name is unsafe for remote ADB commands")

    @staticmethod
    def package_safe(package_name: str) -> bool:
        return bool(
            re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package_name)
        )
