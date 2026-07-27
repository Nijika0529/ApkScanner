from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    canceled: bool = False


@dataclass(frozen=True, slots=True)
class TimeBudget:
    """Monotonic task budget shared by deterministic and agent stages."""

    deadline: float

    @classmethod
    def from_seconds(cls, seconds: int | float) -> TimeBudget:
        return cls(deadline=time.monotonic() + max(float(seconds), 0.0))

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def remaining(self, cap: int | float | None = None) -> int:
        seconds = max(0, int(self.deadline - time.monotonic()))
        if cap is not None:
            seconds = min(seconds, int(cap))
        return seconds

    def extend(
        self,
        seconds: int | float,
        *,
        maximum_deadline: float | None = None,
    ) -> TimeBudget:
        """Return a budget that excludes time spent waiting for a shared resource."""
        deadline = self.deadline + max(float(seconds), 0.0)
        if maximum_deadline is not None:
            deadline = min(deadline, maximum_deadline)
        return TimeBudget(deadline=deadline)


class ToolRunner:
    def __init__(self, timeout_seconds: int = 600, max_output_chars: int = 2_000_000):
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    def available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> CommandResult:
        if not argv or not shutil.which(argv[0]):
            return CommandResult(argv=argv, exit_code=127, stdout="", stderr="tool not found")
        if cancel_event is not None and cancel_event.is_set():
            return CommandResult(
                argv=argv,
                exit_code=130,
                stdout="",
                stderr="command cancelled before dispatch",
                canceled=True,
            )
        command_env = os.environ.copy()
        if env:
            command_env.update(env)
        effective_timeout = self.timeout_seconds if timeout is None else timeout
        if cancel_event is not None:
            return self._run_cancelable(
                argv,
                cwd=cwd,
                env=command_env,
                timeout=effective_timeout,
                cancel_event=cancel_event,
            )
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=command_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout,
                check=False,
            )
            return CommandResult(
                argv=argv,
                exit_code=completed.returncode,
                stdout=completed.stdout[-self.max_output_chars :],
                stderr=completed.stderr[-self.max_output_chars :],
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=argv,
                exit_code=124,
                stdout=self._decode_timeout(exc.stdout),
                stderr=self._decode_timeout(exc.stderr) or "command timed out",
                timed_out=True,
            )

    def _run_cancelable(
        self,
        argv: list[str],
        *,
        cwd: Path | None,
        env: dict[str, str],
        timeout: int,
        cancel_event: threading.Event,
    ) -> CommandResult:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        while True:
            if cancel_event.is_set():
                stdout, stderr = self._terminate(process)
                return CommandResult(
                    argv=argv,
                    exit_code=130,
                    stdout=stdout[-self.max_output_chars :],
                    stderr=(stderr or "command cancelled")[-self.max_output_chars :],
                    canceled=True,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stdout, stderr = self._terminate(process)
                return CommandResult(
                    argv=argv,
                    exit_code=124,
                    stdout=stdout[-self.max_output_chars :],
                    stderr=(stderr or "command timed out")[-self.max_output_chars :],
                    timed_out=True,
                )
            try:
                stdout, stderr = process.communicate(timeout=min(0.1, remaining))
                return CommandResult(
                    argv=argv,
                    exit_code=process.returncode,
                    stdout=stdout[-self.max_output_chars :],
                    stderr=stderr[-self.max_output_chars :],
                )
            except subprocess.TimeoutExpired:
                continue

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> tuple[str, str]:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
        try:
            return process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            return process.communicate()

    @staticmethod
    def _decode_timeout(value: str | bytes | None) -> str:
        if value is None:
            return ""
        return value.decode(errors="replace") if isinstance(value, bytes) else value

    def version(self, tool: str) -> str | None:
        if not self.available(tool):
            return None
        candidates = ([tool, "--version"], [tool, "version"], [tool, "-version"])
        for argv in candidates:
            result = self.run(list(argv), timeout=20)
            text = (result.stdout or result.stderr).strip().splitlines()
            if result.exit_code == 0 and text:
                return text[0][:300]
        return "available"


TOOL_NAMES = ("aapt2", "apksigner", "apktool", "apkanalyzer", "jadx", "adb", "frida")


def discover_tools(runner: ToolRunner) -> dict[str, str | None]:
    return {tool: runner.version(tool) for tool in TOOL_NAMES}
