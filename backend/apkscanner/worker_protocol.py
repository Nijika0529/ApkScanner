from __future__ import annotations

import json
import queue
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
) -> tuple[dict[str, Any], str]:
    """Exchange one request with an NDJSON worker while forwarding event envelopes."""

    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise RuntimeError("worker process pipes are unavailable")

    messages: queue.Queue[tuple[str, str | None]] = queue.Queue()
    stderr_chunks: list[str] = []

    def read_stdout() -> None:
        try:
            for line in process.stdout:
                messages.put(("stdout", line))
        finally:
            messages.put(("stdout_eof", None))

    def read_stderr() -> None:
        try:
            for chunk in iter(lambda: process.stderr.read(4096), ""):
                if not chunk:
                    break
                stderr_chunks.append(chunk)
        finally:
            messages.put(("stderr_eof", None))

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
    stdout_thread.start()
    stderr_thread.start()
    process.stdin.write(json.dumps(payload, ensure_ascii=False))
    process.stdin.close()

    def terminate_process(callback: Callable[[], None] | None) -> None:
        if callback is not None:
            with suppress(Exception):
                callback()
        if process.poll() is None:
            with suppress(Exception):
                process.kill()
        with suppress(Exception):
            process.wait(timeout=5)

    deadline = time.monotonic() + timeout_seconds
    result: dict[str, Any] | None = None
    stdout_eof = False
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
        if kind == "stdout_eof":
            stdout_eof = True
            continue
        if kind != "stdout" or raw is None or not raw.strip():
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

    remaining = max(0.0, deadline - time.monotonic())
    try:
        return_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        terminate_process(on_timeout)
        raise WorkerTimeoutError(f"worker exceeded {timeout_seconds} seconds") from exc
    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)
    stderr = "".join(stderr_chunks)
    if return_code != 0:
        detail = stderr.strip()[-3000:] or "worker returned no diagnostic"
        raise RuntimeError(detail)
    if result is None:
        raise RuntimeError("worker returned no result envelope")
    return result, stderr
