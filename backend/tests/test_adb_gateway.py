from __future__ import annotations

import pytest
from apkscanner.adb_gateway import AdbGatewayRequest, AdbGatewayResponse, validate_adb_args
from apkscanner.tools import CommandResult
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
