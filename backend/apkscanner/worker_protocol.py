from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from .agent_events import AgentEventCallback, runtime_event_from_mapping


class WorkerTimeoutError(TimeoutError):
    pass


class WorkerCancelledError(RuntimeError):
    pass


def consume_worker_process(
    process: subprocess.Popen[str],
    *,
    payload: dict[str, Any],
    timeout_seconds: int,
    event_callback: AgentEventCallback | None = None,
    on_timeout: Callable[[], None] | None = None,
    cancel_event: threading.Event | None = None,
    on_cancel: Callable[[], None] | None = None,
    on_error_cleanup: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], str]:
    """Exchange one request with an NDJSON worker while forwarding event envelopes."""

    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise RuntimeError("worker process pipes are unavailable")

    messages: queue.Queue[tuple[str, Any]] = queue.Queue()
    stderr_chunks: list[str] = []
    writer_errors: list[BaseException] = []
    reader_errors: list[tuple[str, BaseException]] = []
    deadline = time.monotonic() + timeout_seconds
    owns_process_group = False
    if os.name == "posix":
        with suppress(OSError):
            owns_process_group = os.getpgid(process.pid) == process.pid

    def read_stdout() -> None:
        try:
            for line in process.stdout:
                messages.put(("stdout", line))
        except BaseException as exc:
            reader_errors.append(("stdout", exc))
            messages.put(("stdout_error", exc))
        finally:
            messages.put(("stdout_eof", None))

    def read_stderr() -> None:
        try:
            for chunk in iter(lambda: process.stderr.read(4096), ""):
                if not chunk:
                    break
                stderr_chunks.append(chunk)
        except BaseException as exc:
            reader_errors.append(("stderr", exc))
            messages.put(("stderr_error", exc))
        finally:
            messages.put(("stderr_eof", None))

    def write_stdin() -> None:
        try:
            process.stdin.write(json.dumps(payload, ensure_ascii=False))
            process.stdin.close()
        except BaseException as exc:
            writer_errors.append(exc)
            messages.put(("stdin_error", exc))
        finally:
            messages.put(("stdin_done", None))

    stdout_thread = threading.Thread(
        target=read_stdout,
        name="apk-scanner-worker-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_stderr,
        name="apk-scanner-worker-stderr",
        daemon=True,
    )
    stdin_thread = threading.Thread(
        target=write_stdin,
        name="apk-scanner-worker-stdin",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    stdin_thread.start()

    def terminate_process(callback: Callable[[], None] | None) -> None:
        if callback is not None:
            with suppress(Exception):
                callback()
        if owns_process_group:
            with suppress(Exception):
                os.killpg(process.pid, signal.SIGKILL)
        if process.poll() is None:
            with suppress(Exception):
                process.kill()
        try:
            process.wait(timeout=5)
        except Exception:
            if process.poll() is None:
                with suppress(Exception):
                    process.kill()
            with suppress(Exception):
                process.wait(timeout=1)

    result: dict[str, Any] | None = None
    stdout_eof = False
    try:
        while not stdout_eof:
            if cancel_event is not None and cancel_event.is_set():
                terminate_process(on_cancel)
                raise WorkerCancelledError("worker was cancelled by the user")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_process(on_timeout)
                raise WorkerTimeoutError(f"worker exceeded {timeout_seconds} seconds")
            try:
                kind, raw = messages.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            if kind == "stdin_error":
                raise RuntimeError("worker request write failed") from raw
            if kind == "stdout_error":
                raise RuntimeError("worker stdout reader failed") from raw
            if kind == "stderr_error":
                raise RuntimeError("worker stderr reader failed") from raw
            if kind == "stdout_eof":
                stdout_eof = True
                continue
            if kind != "stdout" or not isinstance(raw, str) or not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError("worker returned invalid NDJSON") from exc
            if not isinstance(value, dict):
                raise RuntimeError("worker returned a non-object NDJSON record")
            envelope_type = value.get("type")
            if envelope_type == "event":
                event = runtime_event_from_mapping(value.get("event"))
                if event is not None and event_callback is not None:
                    # Observability must never fail or cancel the security investigation.
                    with suppress(Exception):
                        event_callback(event)
                continue
            if envelope_type == "result":
                candidate = value.get("result")
                if not isinstance(candidate, dict):
                    raise RuntimeError("worker result envelope is invalid")
                result = candidate
                continue
            # Compatibility with workers that still emit a single JSON object.
            result = value

        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                terminate_process(on_cancel)
                raise WorkerCancelledError("worker was cancelled by the user")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_process(on_timeout)
                raise WorkerTimeoutError(f"worker exceeded {timeout_seconds} seconds")
            time.sleep(min(0.05, remaining))

        io_threads = (stdin_thread, stdout_thread, stderr_thread)
        while any(thread.is_alive() for thread in io_threads):
            if cancel_event is not None and cancel_event.is_set():
                terminate_process(on_cancel)
                raise WorkerCancelledError("worker was cancelled by the user")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_process(on_timeout)
                raise WorkerTimeoutError(f"worker exceeded {timeout_seconds} seconds")
            for thread in io_threads:
                thread.join(timeout=min(0.02, remaining))
        if writer_errors:
            raise RuntimeError("worker request write failed") from writer_errors[0]
        if reader_errors:
            stream, error = reader_errors[0]
            raise RuntimeError(f"worker {stream} reader failed") from error
        stderr = "".join(stderr_chunks)
        if process.returncode != 0:
            detail = stderr.strip()[-3000:] or "worker returned no diagnostic"
            raise RuntimeError(detail)
        if result is None:
            raise RuntimeError("worker returned no result envelope")
        return result, stderr
    except (WorkerCancelledError, WorkerTimeoutError):
        raise
    except BaseException:
        terminate_process(on_error_cleanup)
        raise
    finally:
        stdin_thread.join(timeout=1)
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
