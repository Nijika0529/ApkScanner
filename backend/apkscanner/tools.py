from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from contextlib import suppress
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
        self._shutdown = threading.Event()

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
        if self._shutdown.is_set() or (
            cancel_event is not None and cancel_event.is_set()
        ):
            return CommandResult(
                argv=argv,
                exit_code=130,
                stdout="",
                stderr="command cancelled before dispatch or during scanner shutdown",
                canceled=True,
            )
        command_env = os.environ.copy()
        if env:
            command_env.update(env)
        effective_timeout = self.timeout_seconds if timeout is None else timeout
        return self._run_cancelable(
            argv,
            cwd=cwd,
            env=command_env,
            timeout=effective_timeout,
            cancel_event=cancel_event or threading.Event(),
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
        process_options: dict[str, object] = {}
        if os.name == "posix":
            process_options["start_new_session"] = True
        elif os.name == "nt":
            process_options["creationflags"] = getattr(
                subprocess,
                "CREATE_NEW_PROCESS_GROUP",
                0,
            )
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **process_options,
        )
        deadline = time.monotonic() + timeout
        while True:
            if self._shutdown.is_set() or cancel_event.is_set():
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

    def shutdown(self) -> None:
        """Request cancellation of every current and future tool subprocess."""
        self._shutdown.set()

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> tuple[str, str]:
        def signal_process_group(*, force: bool) -> None:
            if os.name == "posix":
                requested_signal = signal.SIGKILL if force else signal.SIGTERM
                try:
                    os.killpg(process.pid, requested_signal)
                    return
                except OSError:
                    pass
            if process.poll() is None:
                try:
                    if force:
                        process.kill()
                    else:
                        process.terminate()
                except OSError:
                    pass

        signal_process_group(force=False)
        try:
            return process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            signal_process_group(force=True)
            try:
                return process.communicate(timeout=2)
            except subprocess.TimeoutExpired as exc:
                stdout = ToolRunner._decode_timeout(exc.stdout)
                stderr = ToolRunner._decode_timeout(exc.stderr)
                if process.poll() is None:
                    with suppress(OSError):
                        process.kill()
                if process.stdout is not None:
                    with suppress(OSError):
                        process.stdout.close()
                if process.stderr is not None:
                    with suppress(OSError):
                        process.stderr.close()
                with suppress(Exception):
                    process.wait(timeout=1)
                return stdout, stderr

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
