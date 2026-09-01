from __future__ import annotations

import pytest
from apkscanner.platform.tools import CommandResult
from apkscanner.runtime.adb_gateway import (
    AdbGatewayRequest,
    AdbGatewayResponse,
    quote_dynamic_experiment_adb_args,
    validate_adaptive_adb_args,
    validate_adb_args,
    validate_dynamic_experiment_adb_args,
    validate_dynamic_experiment_adb_template,
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
        ["shell", "toybox", "sh", "-c", "id"],
        ["shell", "service", "call", "activity", "1"],
        ["shell", "wm", "size", "720x1280"],
        ["shell", "dumpsys", "battery", "set", "level", "1"],
        ["shell", "logcat", "-c"],
        ["logcat", "-G", "1M"],
        ["get-state", "shell", "id"],
        ["shell", "cmd", "package", "compile", "com.example.target"],
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
        ["uninstall", "io.apkscanner.poc.verify"],
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


@pytest.mark.parametrize(
    "args",
    [
        ["get-state"],
        ["get-serialno"],
        ["logcat", "-d", "-t", "20"],
        ["shell", "getprop", "ro.build.version.sdk"],
        ["shell", "am", "start", "-W", "demo://entry"],
        ["shell", "am", "force-stop", "com.example.target"],
        ["shell", "echo", "TRIGGERED"],
        ["shell", "pm", "path", "com.example.target"],
        ["shell", "uiautomator", "dump", "/data/local/tmp/apkscanner_window.xml"],
        ["shell", "cat", "/data/local/tmp/sh"],
        ["shell", "am", "start", "-W", "-d", "https://example.test/root"],
        [
            "shell",
            "am",
            "start",
            "-W",
            "-d",
            "https://example.test/path?a=1&b=2",
        ],
        ["shell", "am", "start", "-n", "com.example/.Outer$Inner"],
        ["shell", "/system/bin/am", "force-stop", "com.example.target"],
        ["shell", "dumpsys", "package", "com.example.target"],
        ["shell", "rm", "-f", "/data/local/tmp/apkscanner_probe/result.txt"],
    ],
)
def test_dynamic_experiment_gateway_allows_device_only_commands(args: list[str]) -> None:
    validate_dynamic_experiment_adb_args(args)


@pytest.mark.parametrize(
    "args",
    [
        ["pull", "/data/local/tmp/result", "/agent-workspaces/result"],
        ["push", "/etc/passwd", "/data/local/tmp/input"],
        ["sync", "data"],
        ["install", "/agent-workspaces/poc.apk"],
        ["install-streaming", "/agent-workspaces/poc.apk"],
        ["install-multiple", "/agent-workspaces/base.apk"],
        ["uninstall", "com.example.target"],
        ["backup", "-f", "/agent-workspaces/target.ab", "com.example.target"],
        ["restore", "/agent-workspaces/target.ab"],
        ["bugreport", "/agent-workspaces/report.zip"],
        ["forward", "tcp:8080", "tcp:8080"],
        ["reverse", "tcp:8080", "tcp:8080"],
        ["reboot"],
        ["root"],
        ["remount"],
        ["shell", "pm", "install", "/data/local/tmp/poc.apk"],
        ["shell", "pm", "install-streaming", "/data/local/tmp/poc.apk"],
        ["shell", "pm install /data/local/tmp/poc.apk"],
        ["shell", "cmd", "package", "uninstall", "com.example.target"],
        ["shell", "/system/bin/pm", "uninstall", "com.example.target"],
        ["shell", "sh", "-c", "pm install /data/local/tmp/poc.apk"],
        ["shell", "echo", "ready;", "reboot"],
        ["shell", "toybox", "sh", "-c", "reboot"],
        ["shell", "env", "/system/bin/reboot"],
        ["shell", "mksh", "-c", "pm install /data/local/tmp/poc.apk"],
        ["shell", "exec", "pm", "install", "/data/local/tmp/poc.apk"],
        ["shell", "command", "pm", "install", "/data/local/tmp/poc.apk"],
        ["shell", "pm", "clear", "com.example.target"],
        ["shell", "settings", "put", "global", "adb_enabled", "0"],
        ["shell", "content", "insert", "--uri", "content://example"],
        ["shell", "uiautomator", "runtest", "Agent.jar"],
        ["shell", "uiautomator", "dump", "/sdcard/user-file.xml"],
        ["shell", "uiautomator", "dump", "/data/local/tmp/window.xml"],
        ["shell", "logcat", "-c"],
        ["logcat", "--clear"],
        ["logcat", "-G", "1M"],
        ["logcat", "--prune", "~!"],
        ["shell", "logcat", "-f", "/data/local/tmp/apkscanner_log.txt"],
        ["shell", "dumpsys", "battery", "set", "level", "1"],
        ["shell", "dumpsys", "deviceidle", "force-idle"],
        ["shell", "/data/local/tmp/am", "force-stop", "com.example.target"],
        ["shell", "./am", "force-stop", "com.example.target"],
        ["shell", "rm", "-rf", "/data/local/tmp"],
        ["shell", "echo", "ready&reboot"],
        ["shell", "echo", "-d", "x:&reboot"],
        ["shell", "am", "force-stop", "-d", "x:&reboot"],
        ["logcat", "-d", "x:&reboot"],
        ["shell", "echo", "Outer$Inner"],
        ["get-state", "push", "/etc/passwd", "/data/local/tmp/input"],
        ["exec-out", "cat", "/data/local/tmp/result"],
    ],
)
def test_dynamic_experiment_gateway_rejects_host_and_transport_operations(
    args: list[str],
) -> None:
    with pytest.raises(ValueError):
        validate_dynamic_experiment_adb_args(args)


def test_dynamic_experiment_template_requires_a_fixed_command_shape() -> None:
    validate_dynamic_experiment_adb_template(
        ["shell", "rm", "-f", "/data/local/tmp/apkscanner_${artifact_id}"]
    )

    with pytest.raises(ValueError):
        validate_dynamic_experiment_adb_template(
            ["shell", "${command}", "/data/local/tmp/apkscanner_result"]
        )


def test_dynamic_experiment_quotes_remote_shell_data_arguments() -> None:
    args = [
        "shell",
        "am",
        "start",
        "-d",
        "https://example.test/path?a=1&b=2",
        "-n",
        "com.example/.Outer$Inner",
    ]

    quoted = quote_dynamic_experiment_adb_args(args)

    assert quoted == [
        "shell",
        "am",
        "start",
        "-d",
        "'https://example.test/path?a=1&b=2'",
        "-n",
        "'com.example/.Outer$Inner'",
    ]
