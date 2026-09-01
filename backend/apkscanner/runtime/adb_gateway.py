from __future__ import annotations

import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..platform.tools import CommandResult

_SHELL_META = re.compile(r"[\x00\r\n;&|`$<>]")
_DYNAMIC_CONTROL_META = re.compile(r"[\x00\r\n;|`<>]")
_SAFE_COMPONENT = re.compile(
    r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*/(?:\.?[A-Za-z0-9_]+(?:[.$][A-Za-z0-9_]+)*)$"
)
_SAFE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\x00\r\n;|`$<>]*$")
_SAFE_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_SAFE_TEMP_PATH = re.compile(
    r"^/data/local/tmp/apkscanner(?:[_.-][A-Za-z0-9_.-]+)?(?:/[A-Za-z0-9_.-]+)*$"
)
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
    }
)
_DYNAMIC_EXPERIMENT_READ_ONLY_ADB_COMMANDS = frozenset(
    {
        "get-serialno",
        "get-state",
        "logcat",
        "wait-for-device",
    }
)
_DYNAMIC_EXPERIMENT_FORBIDDEN_ADB_COMMANDS = frozenset(
    {
        "backup",
        "bugreport",
        "connect",
        "disable-verity",
        "disconnect",
        "enable-verity",
        "forward",
        "install",
        "install-multi-package",
        "install-multiple",
        "kill-server",
        "pair",
        "pull",
        "push",
        "reboot",
        "remount",
        "restore",
        "reverse",
        "root",
        "sideload",
        "start-server",
        "sync",
        "tcpip",
        "uninstall",
        "unroot",
        "usb",
    }
)
_DYNAMIC_EXPERIMENT_FORBIDDEN_SHELL_COMMANDS = frozenset(
    {
        "bash",
        "reboot",
        "remount",
        "root",
        "sh",
        "su",
        "unroot",
    }
)
_DYNAMIC_EXPERIMENT_ALLOWED_SHELL_COMMANDS = frozenset(
    {
        "am",
        "cat",
        "content",
        "dumpsys",
        "echo",
        "false",
        "getprop",
        "grep",
        "head",
        "id",
        "input",
        "logcat",
        "ls",
        "mkdir",
        "pidof",
        "pm",
        "ps",
        "rm",
        "settings",
        "sleep",
        "stat",
        "tail",
        "true",
        "uiautomator",
    }
)
_DYNAMIC_EXPERIMENT_INPUT_ACTIONS = frozenset(
    {"keyevent", "motionevent", "swipe", "tap", "text"}
)

_DUMPSYS_READ_ONLY_SUBCOMMANDS = {
    "activity": frozenset(
        {
            "activities",
            "associations",
            "broadcasts",
            "exit-info",
            "lastanr",
            "lru",
            "permissions",
            "processes",
            "providers",
            "recents",
            "services",
            "starter",
            "top",
        }
    ),
    "window": frozenset({"animator", "displays", "policy", "sessions", "tokens", "windows"}),
}

_LOGCAT_MUTATING_LONG_OPTIONS = frozenset(
    {
        "--buffer-size",
        "--clear",
        "--file",
        "--prune",
        "--rotate-count",
        "--rotate-kbytes",
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
    if args[0] in {"get-state", "get-serialno", "wait-for-device"}:
        if len(args) != 1:
            raise ValueError("this ADB diagnostic does not accept a nested command")
        return
    if args[0] == "logcat":
        _validate_logcat_observation(args[1:])
        return
    if args[0] != "shell" or len(args) < 2:
        raise ValueError("ADB gateway supports read-only diagnostics and scoped shell exploration")
    command = args[1]
    tail = args[2:]
    if command in {"sh", "bash", "su", "run-as"}:
        raise ValueError("nested shells and privilege changes are not allowed")
    if command == "dumpsys":
        _validate_dumpsys_observation(tail)
        return
    if command == "logcat":
        _validate_logcat_observation(tail)
        return
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


def validate_dynamic_experiment_adb_args(args: list[str]) -> None:
    """Keep persisted Agent experiments inside a device-only ADB boundary.

    The live adaptive verifier intentionally has a broader contract, including
    workspace-aware host file transfer. Persisted ``DynamicExperimentService``
    plans do not receive that path translation, so they may use only direct
    diagnostics or device-side shell commands and must never name host paths.
    """

    validate_adaptive_adb_args(args)
    _validate_dynamic_argument_boundaries(args)
    command = args[0].lower()
    if command in _DYNAMIC_EXPERIMENT_FORBIDDEN_ADB_COMMANDS or command.startswith(
        ("install-", "uninstall-")
    ):
        raise ValueError(
            "ADB host transfer, installation, and transport commands are not allowed "
            "in dynamic experiment steps"
        )
    if command in _DYNAMIC_EXPERIMENT_READ_ONLY_ADB_COMMANDS:
        if command != "logcat" and len(args) != 1:
            raise ValueError("this read-only ADB diagnostic does not accept a nested command")
        if command == "logcat":
            _validate_logcat_observation(args[1:])
        return
    if command != "shell" or len(args) < 2:
        raise ValueError(
            "dynamic experiment steps support only read-only ADB diagnostics and "
            "device-side shell commands"
        )

    raw_shell_command = args[1]
    if not re.fullmatch(r"/?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", raw_shell_command):
        raise ValueError("the device-side shell command name is invalid")
    if "/" in raw_shell_command and not re.fullmatch(
        r"/system/bin/[A-Za-z0-9_.-]+", raw_shell_command
    ):
        raise ValueError("device-side executables must be bare names or trusted system binaries")
    shell_command = raw_shell_command.rsplit("/", 1)[-1].lower()
    shell_tail_raw = args[2:]
    shell_tail = [value.lower() for value in args[2:]]
    if (
        shell_command.startswith("-")
        or shell_command in _DYNAMIC_EXPERIMENT_FORBIDDEN_SHELL_COMMANDS
    ):
        raise ValueError("nested shells and privileged device commands are not allowed")
    if shell_command not in _DYNAMIC_EXPERIMENT_ALLOWED_SHELL_COMMANDS:
        raise ValueError("the device-side shell command is outside the experiment allowlist")
    if shell_command == "am" and (not shell_tail or shell_tail[0] not in _AM_ALLOWED):
        raise ValueError("this Activity Manager action is outside the experiment allowlist")
    if shell_command == "am" and shell_tail[0] == "force-stop" and (
        len(shell_tail_raw) != 2 or _SAFE_PACKAGE.fullmatch(shell_tail_raw[1]) is None
    ):
        raise ValueError("force-stop must name exactly one Android package")
    if shell_command == "pm" and (not shell_tail or shell_tail[0] not in _PACKAGE_QUERY):
        raise ValueError("dynamic experiments may query but not mutate package state")
    if shell_command == "settings" and (
        not shell_tail or shell_tail[0] not in {"get", "list"}
    ):
        raise ValueError("dynamic experiments may query but not mutate settings")
    if shell_command == "content" and (
        not shell_tail or shell_tail[0] not in {"query", "read"}
    ):
        raise ValueError("dynamic experiments may query but not mutate content")
    if shell_command == "dumpsys":
        _validate_dumpsys_observation(shell_tail_raw)
    if shell_command == "input" and (
        not shell_tail or shell_tail[0] not in _DYNAMIC_EXPERIMENT_INPUT_ACTIONS
    ):
        raise ValueError("this input action is outside the experiment allowlist")
    if shell_command == "uiautomator":
        _validate_uiautomator_dump(shell_tail_raw)
    if shell_command == "logcat":
        _validate_logcat_observation(shell_tail_raw)
    if shell_command in {"mkdir", "rm"}:
        _validate_temp_file_operation(shell_command, shell_tail_raw)


def validate_dynamic_experiment_adb_template(args: list[str]) -> None:
    """Validate every persisted step before any action obtains a device lease.

    State references may fill data values, but may not select a command or
    subcommand because replacing them with a neutral token must still satisfy
    the same structural policy.
    """

    rendered = [
        _STATE_TEMPLATE_REFERENCE.sub("apkscanner_state", value) for value in args
    ]
    validate_dynamic_experiment_adb_args(rendered)


def quote_dynamic_experiment_adb_args(args: list[str]) -> list[str]:
    """Quote remote-shell argv because the adb client joins it without escaping."""

    validate_dynamic_experiment_adb_args(args)
    if args[0].lower() != "shell":
        return list(args)
    return [args[0], *(shlex.quote(value) for value in args[1:])]


_STATE_TEMPLATE_REFERENCE = re.compile(r"\$\{[A-Za-z][A-Za-z0-9_.-]{0,127}\}")


def _validate_dynamic_argument_boundaries(args: list[str]) -> None:
    """Reject remote-shell control syntax while allowing typed URI/component data."""

    for index, value in enumerate(args):
        if _DYNAMIC_CONTROL_META.search(value):
            raise ValueError(
                "shell control characters are not allowed in dynamic experiment commands"
            )
        if "&" in value:
            previous = args[index - 1].lower() if index else ""
            if (
                previous not in {"-d", "--uri"}
                or _SAFE_URI.fullmatch(value) is None
                or not _is_typed_dynamic_uri_position(args, index)
            ):
                raise ValueError("ampersands are allowed only inside a typed URI argument")
        if "$" in value:
            previous = args[index - 1].lower() if index else ""
            if (
                previous not in {"-n", "--component"}
                or _SAFE_COMPONENT.fullmatch(value) is None
                or not _is_typed_dynamic_component_position(args, index)
            ):
                raise ValueError("dollar signs are allowed only inside a typed component name")


def _is_typed_dynamic_uri_position(args: list[str], index: int) -> bool:
    if len(args) < 4 or args[0].lower() != "shell" or index < 3:
        return False
    command = args[1].rsplit("/", 1)[-1].lower()
    subcommand = args[2].lower()
    previous = args[index - 1].lower()
    return (
        command == "am"
        and subcommand in _AM_ALLOWED - {"force-stop"}
        and previous == "-d"
    ) or (
        command == "content"
        and subcommand in {"query", "read"}
        and previous == "--uri"
    )


def _is_typed_dynamic_component_position(args: list[str], index: int) -> bool:
    if len(args) < 4 or args[0].lower() != "shell" or index < 3:
        return False
    command = args[1].rsplit("/", 1)[-1].lower()
    subcommand = args[2].lower()
    return (
        command == "am"
        and subcommand in _AM_ALLOWED - {"force-stop"}
        and args[index - 1].lower() in {"-n", "--component"}
    )


def _validate_dumpsys_observation(tail: list[str]) -> None:
    if not tail:
        return
    service = tail[0].lower()
    if len(tail) == 1:
        return
    if service == "package" and len(tail) == 2 and _SAFE_PACKAGE.fullmatch(tail[1]):
        return
    if service in {"gfxinfo", "meminfo", "procstats", "batterystats"} and (
        len(tail) == 2 and _SAFE_PACKAGE.fullmatch(tail[1])
    ):
        return
    allowed = _DUMPSYS_READ_ONLY_SUBCOMMANDS.get(service)
    if allowed is not None and len(tail) == 2 and tail[1].lower() in allowed:
        return
    raise ValueError("dynamic experiments may inspect but not mutate dumpsys services")


def _validate_logcat_observation(tail: list[str]) -> None:
    for value in tail:
        lowered = value.lower()
        name = lowered.split("=", 1)[0]
        if name in _LOGCAT_MUTATING_LONG_OPTIONS:
            raise ValueError("dynamic experiments may observe but not reconfigure device logs")
        if value.startswith(("-G", "-P", "-f", "-r", "-n")):
            raise ValueError("dynamic experiments may observe but not reconfigure device logs")
        if re.fullmatch(r"-[A-Za-z]+", value) and "c" in value:
            raise ValueError("dynamic experiments may observe but not clear device logs")


def _validate_uiautomator_dump(tail: list[str]) -> None:
    if not tail or tail[0].lower() != "dump":
        raise ValueError("dynamic experiments may only dump the UI hierarchy")
    output_args = tail[1:]
    if output_args and output_args[0] == "--compressed":
        output_args = output_args[1:]
    if len(output_args) != 1 or not _is_safe_dynamic_temp_path(output_args[0]):
        raise ValueError(
            "UI hierarchy dumps must use a platform-scoped /data/local/tmp/apkscanner path"
        )


def _validate_temp_file_operation(command: str, tail: list[str]) -> None:
    allowed_options = {"mkdir": {"-p"}, "rm": {"-f", "-r", "-rf", "-fr"}}[command]
    paths = [value for value in tail if not value.startswith("-")]
    options = {value for value in tail if value.startswith("-")}
    if not paths or not options <= allowed_options:
        raise ValueError("temporary file operation options are outside the allowlist")
    if any(not _is_safe_dynamic_temp_path(value) for value in paths):
        raise ValueError(
            "temporary file operations are restricted to /data/local/tmp/apkscanner paths"
        )


def _is_safe_dynamic_temp_path(value: str) -> bool:
    if _SAFE_TEMP_PATH.fullmatch(value) is None:
        return False
    return all(segment not in {"", ".", ".."} for segment in value.split("/")[1:])


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
