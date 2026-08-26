from __future__ import annotations

import pytest
from apkscanner.platform.tools import CommandResult
from apkscanner.runtime.adb_gateway import (
    AdbGatewayRequest,
    AdbGatewayResponse,
    validate_adaptive_adb_args,
    validate_adb_args,
)
from pydantic import ValidationError


@pytest.mark.parametrize(
    "args",
    [
        ["get-state"],
        ["shell", "getprop", "ro.build.version.sdk"],
        ["shell", "dumpsys", "package", "com.example.target"],
        ["shell", "am", "start", "-n", "com.example/.MainActivity"],
        ["shell", "pm", "path", "com.example.target"],
        ["logcat", "-d", "-t", "20"],
    ],
)
def test_gateway_allows_scoped_diagnostics_and_entry_exploration(args: list[str]) -> None:
    validate_adb_args(args)


@pytest.mark.parametrize(
    "args",
    [
        ["-s", "other", "shell", "id"],
        ["install", "/tmp/evil.apk"],
        ["shell", "sh", "-c", "id"],
        ["shell", "su", "0", "id"],
        ["shell", "pm", "clear", "com.example.target"],
        ["shell", "getprop;id"],
        ["reboot"],
    ],
)
def test_gateway_rejects_transport_escape_and_platform_owned_mutations(args: list[str]) -> None:
    with pytest.raises((ValueError, ValidationError)):
        AdbGatewayRequest(args=args)


def test_gateway_response_bounds_command_output() -> None:
    result = CommandResult(["adb", "-s", "serial", "logcat"], 0, "x" * 100, "")
    response = AdbGatewayResponse.from_command(result, max_bytes=16)
    assert response.truncated is True
    assert len(response.stdout) < 100


@pytest.mark.parametrize(
    "args",
    [
        ["install", "/agent-workspaces/verifier/workspace/poc.apk"],
        ["uninstall", "io.apkscanner.runtime.poc.verify"],
        ["push", "/agent-workspaces/verifier/workspace/page.html", "/data/local/tmp/page.html"],
        ["shell", "sh", "-c", "am start -a android.intent.action.VIEW"],
        ["forward", "tcp:8080", "tcp:8080"],
    ],
)
def test_adaptive_gateway_allows_verifier_device_experiments(args: list[str]) -> None:
    validate_adaptive_adb_args(args)
    request = AdbGatewayRequest(args=args, policy="adaptive")
    assert request.policy == "adaptive"


@pytest.mark.parametrize(
    "args",
    [
        ["-s", "other", "shell", "id"],
        ["connect", "other:5555"],
        ["disconnect"],
        ["kill-server"],
        ["tcpip", "5555"],
    ],
)
def test_adaptive_gateway_keeps_serial_and_server_ownership(args: list[str]) -> None:
    with pytest.raises((ValueError, ValidationError)):
        AdbGatewayRequest(args=args, policy="adaptive")
