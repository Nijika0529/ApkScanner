from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from .config import Settings
from .tools import CommandResult, TimeBudget, ToolRunner


@dataclass(slots=True)
class FridaSession:
    argv: list[str]
    process: subprocess.Popen[bytes]
    stdout_file: BinaryIO
    stderr_file: BinaryIO
    started_at: float


class FridaAdapter:
    """Bounded Frida observation; it never treats instrumentation as black-box proof."""

    def __init__(self, settings: Settings, runner: ToolRunner):
        self.settings = settings
        self.runner = runner
        self.script_path = Path(__file__).with_name("instrumentation") / "android_entry_trace.js"

    @property
    def selector(self) -> list[str] | None:
        if self.settings.frida_host:
            return ["-H", self.settings.frida_host]
        device = self.settings.frida_device or self.settings.adb_serial
        return ["-D", device] if device else None

    @property
    def configured(self) -> bool:
        return bool(self.selector and self.runner.available("frida") and self.script_path.is_file())

    def capability(self, *, deep: bool = False) -> dict[str, Any]:
        version = self.runner.version("frida")
        if version is None:
            return {"available": False, "detail": "frida CLI is not installed"}
        if self.selector is None:
            return {
                "available": False,
                "version": version,
                "detail": "configure APKSCANNER_FRIDA_DEVICE or APKSCANNER_FRIDA_HOST",
            }
        payload: dict[str, Any] = {
            "available": True,
            "version": version,
            "selector": self.selector,
        }
        if deep:
            result = self.runner.run(["frida-ps", *self.selector, "-a", "-j"], timeout=30)
            payload["available"] = result.exit_code == 0
            if result.exit_code != 0:
                payload["detail"] = result.stderr.strip() or "Frida device probe failed"
        return payload

    def start(
        self, package_name: str, budget: TimeBudget | None = None
    ) -> tuple[FridaSession | None, CommandResult | None]:
        if not self.configured or self.selector is None:
            return None, None
        if not re.fullmatch(r"[A-Za-z0-9_.]+", package_name):
            return None, CommandResult(
                ["frida"], 2, "", "package name is unsafe for Frida invocation"
            )
        seconds = self.settings.frida_capture_seconds
        if budget is not None:
            seconds = min(seconds, budget.remaining(seconds))
        if seconds < 2:
            return None, CommandResult(
                ["frida"], 124, "", "task time budget exhausted", timed_out=True
            )
        argv = [
            "frida",
            *self.selector,
            "-f",
            package_name,
            "-l",
            str(self.script_path),
            "--runtime",
            "v8",
            "--no-auto-reload",
            "--exit-on-error",
            "-q",
            "-t",
            str(seconds),
        ]
        executable = shutil.which("frida")
        if executable is None:
            return None, CommandResult(argv, 127, "", "frida CLI is not installed")
        # The files intentionally outlive this method and are closed by collect().
        stdout_file = tempfile.TemporaryFile()  # noqa: SIM115
        stderr_file = tempfile.TemporaryFile()  # noqa: SIM115
        try:
            process = subprocess.Popen(
                [executable, *argv[1:]],
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=os.environ.copy(),
            )
        except OSError as exc:
            stdout_file.close()
            stderr_file.close()
            return None, CommandResult(argv, 127, "", str(exc))
        session = FridaSession(argv, process, stdout_file, stderr_file, time.monotonic())
        time.sleep(min(1.0, max(0.0, seconds / 4)))
        if process.poll() is not None:
            return None, self.collect(session)
        return session, None

    def collect(self, session: FridaSession) -> CommandResult:
        deliberately_stopped = session.process.poll() is None
        if deliberately_stopped:
            session.process.terminate()
        try:
            session.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            session.process.kill()
            session.process.wait(timeout=5)
        stdout = self._read_and_close(session.stdout_file)
        stderr = self._read_and_close(session.stderr_file)
        code = session.process.returncode or 0
        if deliberately_stopped and code in {-15, 143}:
            code = 0
        return CommandResult(
            argv=session.argv,
            exit_code=code,
            stdout=stdout[-self.runner.max_output_chars :],
            stderr=stderr[-self.runner.max_output_chars :],
        )

    @staticmethod
    def metadata(result: CommandResult) -> dict[str, Any]:
        output = f"{result.stdout}\n{result.stderr}"
        trace_count = output.count("APKSCANNER_TRACE")
        hook_errors = output.count("hook_error")
        return {
            "observation_count": max(0, trace_count - hook_errors),
            "hook_error_count": hook_errors,
            "capture_success": result.exit_code == 0 and "APKSCANNER_READY" in output,
            "trust_level": "instrumented_observation",
        }

    @staticmethod
    def _read_and_close(stream: BinaryIO) -> str:
        try:
            stream.flush()
            stream.seek(0)
            return stream.read().decode("utf-8", errors="replace")
        finally:
            stream.close()
