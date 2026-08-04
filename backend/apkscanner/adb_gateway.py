from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .tools import CommandResult

_SHELL_META = re.compile(r"[\x00\r\n;&|`$<>]")
_PACKAGE_QUERY = frozenset(
    {
        "list",
        "path",
        "dump",
        "resolve-activity",
        "query-activities",
        "query-services",
        "query-receivers",
        "get-app-links",
        "get-install-location",
    }
)
_AM_ALLOWED = frozenset(
    {
        "start",
        "startservice",
        "start-foreground-service",
        "broadcast",
        "force-stop",
    }
)
_SIMPLE_SHELL_COMMANDS = frozenset(
    {
        "dumpsys",
        "getprop",
        "id",
        "logcat",
        "pidof",
        "ps",
        "service",
        "toybox",
        "wm",
    }
)


class AdbGatewayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    args: list[str] = Field(min_length=1, max_length=64)
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    policy: Literal["scoped", "adaptive"] = "scoped"

    @model_validator(mode="after")
    def validate_policy(self) -> AdbGatewayRequest:
        if self.policy == "adaptive":
            validate_adaptive_adb_args(self.args)
        else:
            validate_adb_args(self.args)
        return self


class AdbGatewayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    canceled: bool = False
    truncated: bool = False

    @classmethod
    def from_command(cls, result: CommandResult, *, max_bytes: int = 1_000_000):
        stdout, stdout_truncated = _bounded_text(result.stdout, max_bytes)
        stderr, stderr_truncated = _bounded_text(result.stderr, max_bytes)
        return cls(
            argv=result.argv,
            exit_code=result.exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=result.timed_out,
            canceled=result.canceled,
            truncated=stdout_truncated or stderr_truncated,
        )


def validate_adb_args(args: list[str]) -> None:
    if not args:
        raise ValueError("ADB command cannot be empty")
    for value in args:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError("ADB argument is invalid")
        if _SHELL_META.search(value):
            raise ValueError("ADB shell metacharacters are not allowed")
    if args[0].startswith("-"):
        raise ValueError("ADB transport selectors are controlled by the platform")
    if args[0] in {
        "connect",
        "disconnect",
        "forward",
        "install",
        "install-multi-package",
        "install-multiple",
        "kill-server",
        "reboot",
        "remount",
        "reverse",
        "root",
        "sideload",
        "start-server",
        "sync",
        "tcpip",
        "uninstall",
        "unroot",
        "usb",
    }:
        raise ValueError("ADB command is reserved for the platform proof executor")
    if args[0] in {"get-state", "get-serialno", "wait-for-device", "logcat"}:
        return
    if args[0] != "shell" or len(args) < 2:
        raise ValueError("ADB gateway supports read-only diagnostics and scoped shell exploration")
    command = args[1]
    tail = args[2:]
    if command in {"sh", "bash", "su", "run-as"}:
        raise ValueError("nested shells and privilege changes are not allowed")
    if command in _SIMPLE_SHELL_COMMANDS:
        return
    if command == "am" and tail and tail[0] in _AM_ALLOWED:
        return
    if command == "pm" and tail and tail[0] in _PACKAGE_QUERY:
        return
    if command == "settings" and tail and tail[0] in {"get", "list"}:
        return
    if command == "content" and tail and tail[0] in {"query", "read"}:
        return
    if command == "cmd" and tail and tail[0] in {"package", "activity"}:
        disallowed = {"install", "uninstall", "clear", "grant", "revoke", "suspend"}
        if not any(item in disallowed for item in tail[1:]):
            return
    raise ValueError("ADB shell command is outside the task-scoped exploration policy")


def validate_adaptive_adb_args(args: list[str]) -> None:
    """Allow arbitrary device-side experiments without surrendering transport ownership."""

    if not args:
        raise ValueError("ADB command cannot be empty")
    for value in args:
        if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
            raise ValueError("ADB argument is invalid")
    if args[0].startswith("-"):
        raise ValueError("ADB transport selectors are controlled by the platform")
    if args[0] in {
        "connect",
        "disconnect",
        "kill-server",
        "start-server",
        "tcpip",
        "usb",
    }:
        raise ValueError("ADB server and transport commands remain platform-owned")


def main() -> None:
    task_id = os.getenv("APKSCANNER_ADB_TASK_ID", "")
    endpoint = os.getenv("APKSCANNER_ADB_GATEWAY_URL", "")
    token = os.getenv("APKSCANNER_ADB_TOKEN", "")
    if not task_id or not endpoint or not token:
        print("adb: task-scoped APKScanner gateway is unavailable", file=sys.stderr)
        raise SystemExit(126)
    raw_args = sys.argv[1:]
    try:
        policy = (
            "adaptive"
            if os.getenv("APKSCANNER_ADB_POLICY", "scoped").lower() == "adaptive"
            else "scoped"
        )
        payload = AdbGatewayRequest(args=raw_args, policy=policy).model_dump_json().encode()
    except ValueError as exc:
        print(f"adb: {exc}", file=sys.stderr)
        raise SystemExit(126) from exc
    request = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-APKScanner-ADB-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=135) as response:
            value: Any = json.load(response)
        result = AdbGatewayResponse.model_validate(value)
    except urllib.error.HTTPError as exc:
        detail = exc.read(8192).decode(errors="replace")
        print(f"adb: gateway rejected command ({exc.code}): {detail}", file=sys.stderr)
        raise SystemExit(126) from exc
    except (OSError, ValueError) as exc:
        print(f"adb: gateway request failed: {exc}", file=sys.stderr)
        raise SystemExit(126) from exc
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    raise SystemExit(max(0, min(125, result.exit_code)))


def _bounded_text(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", errors="replace") + "\n[truncated]\n", True


if __name__ == "__main__":
    main()
