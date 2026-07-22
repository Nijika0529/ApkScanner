from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auth import CredentialStore, load_auth_flow
from .config import Settings
from .models import EntryPoint
from .tools import CommandResult, TimeBudget, ToolRunner


@dataclass(slots=True)
class DeviceProbeResult:
    stage: str
    commands: list[tuple[str, CommandResult, dict[str, Any]]]
    summary: dict[str, Any]


class AdbDeviceAdapter:
    """Serialized remote-ADB adapter for the single-device MVP."""

    def __init__(self, settings: Settings, runner: ToolRunner):
        self.settings = settings
        self.runner = runner
        self.serial = settings.adb_serial
        self._lease = threading.RLock()
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

    def capability(self) -> dict[str, Any]:
        if not self.configured:
            return {"available": False, "detail": "APKSCANNER_ADB_SERIAL is not configured"}
        state = self._adb(["get-state"], timeout=30)
        if state.exit_code != 0:
            return {
                "available": False,
                "state": state.stdout.strip(),
                "serial": self.serial,
                "detail": state.stderr.strip() or "ADB device is unavailable",
            }
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
        return {
            "available": ready,
            "state": state.stdout.strip(),
            "android_version": version.stdout.strip(),
            "api_level": actual_api,
            "root": root.exit_code == 0 and root.stdout.strip() == "0",
            "serial": self.serial,
            "detail": detail,
        }

    def auth_capability(self, package_name: str | None = None) -> dict[str, Any]:
        if self.auth_flow_error:
            return {"available": False, "detail": self.auth_flow_error}
        if self.auth_flow is None:
            return {"available": False, "detail": "APKSCANNER_AUTH_FLOW is not configured"}
        if not any(step.action == "assert_text" for step in self.auth_flow.steps):
            return {
                "available": False,
                "detail": "auth flow requires an assert_text step to prove login succeeded",
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
        commands.append(("device.health", self._adb_budget(["get-state"], budget, 30), {}))
        commands.append(
            (
                "device.install",
                self._adb_budget(["install", "-r", "-t", str(apk_path)], budget, 300),
                {"package": package_name},
            )
        )
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
                self._adb(["shell", "pm", "clear", package_name], timeout=60),
                {"package": package_name},
            ),
            (
                "device.applink_reset",
                self._adb(
                    ["shell", "pm", "set-app-links", "--package", package_name, "0", "all"],
                    timeout=60,
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
            "component": entry.name,
        }
        if entry.kind == "deep_link":
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

    def _adb(self, args: list[str], timeout: int | None = None) -> CommandResult:
        if not self.serial:
            return CommandResult(["adb", *args], 127, "", "ADB serial is not configured")
        return self.runner.run(["adb", "-s", self.serial, *args], timeout=timeout)

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
