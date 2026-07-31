from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

from .agent_events import AgentEventCallback, redact_event_data, runtime_event_from_mapping


class PersistentWorkerError(RuntimeError):
    pass


class PersistentWorkerTimeout(TimeoutError):
    pass


class PersistentWorkerCancelled(RuntimeError):
    pass


class PersistentWorkerClient:
    """Host-side controller for one long-lived Codex worker process.

    The worker's stdout is a protocol stream. Every validated envelope is also
    appended to a host-only audit spool; prompts, credentials and raw model
    output are never written there.
    """

    PROTOCOL_VERSION = "3.0"

    def __init__(
        self,
        process: subprocess.Popen[str],
        *,
        session_id: str,
        event_spool: Path,
        cleanup: Callable[[], None],
        ready_timeout_seconds: int = 30,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("persistent worker process pipes are unavailable")
        self.process = process
        self.session_id = session_id
        self.event_spool = event_spool
        self.cleanup = cleanup
        self.thread_id: str | None = None
        self._messages: queue.Queue[dict[str, Any] | BaseException | None] = queue.Queue()
        self._stderr: list[str] = []
        self._write_lock = threading.Lock()
        self._turn_lock = threading.Lock()
        self._closed = False
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._prepare_spool()
        self._reader.start()
        self._stderr_reader.start()
        ready = self._wait_for(
            lambda item: item.get("type") == "worker.ready",
            timeout_seconds=ready_timeout_seconds,
            no_event_timeout_seconds=ready_timeout_seconds,
        )
        if ready.get("protocol_version") != self.PROTOCOL_VERSION:
            self.kill()
            raise PersistentWorkerError("worker protocol version is incompatible")

    def open_session(
        self,
        *,
        configuration: dict[str, Any],
        gateway_environment: dict[str, str] | None = None,
        resume_thread_id: str | None = None,
    ) -> str:
        request_id = self._request_id()
        command_type = "session.resume" if resume_thread_id else "session.open"
        self._send(
            {
                "schema_version": self.PROTOCOL_VERSION,
                "type": command_type,
                "request_id": request_id,
                "session_id": self.session_id,
                "configuration": configuration,
                "gateway_environment": gateway_environment or {},
                **({"thread_id": resume_thread_id} if resume_thread_id else {}),
            }
        )
        response = self._wait_terminal(request_id, timeout_seconds=60, no_event_timeout_seconds=60)
        if response.get("type") != "session.opened":
            raise PersistentWorkerError(self._error_detail(response))
        thread_id = response.get("thread_id")
        if not isinstance(thread_id, str) or not thread_id:
            raise PersistentWorkerError("worker opened a session without a thread ID")
        self.thread_id = thread_id
        return thread_id

    def turn(
        self,
        *,
        prompt: str,
        output_schema: dict[str, Any],
        timeout_seconds: int,
        no_event_timeout_seconds: int,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
        with self._turn_lock:
            if not self.thread_id:
                raise PersistentWorkerError("worker session is not open")
            request_id = self._request_id()
            self._send(
                {
                    "schema_version": self.PROTOCOL_VERSION,
                    "type": "turn.start",
                    "request_id": request_id,
                    "session_id": self.session_id,
                    "prompt": prompt,
                    "output_schema": output_schema,
                }
            )
            try:
                response = self._wait_terminal(
                    request_id,
                    timeout_seconds=timeout_seconds,
                    no_event_timeout_seconds=no_event_timeout_seconds,
                    event_callback=event_callback,
                    cancel_event=cancel_event,
                )
            except (PersistentWorkerCancelled, PersistentWorkerTimeout):
                self._interrupt(request_id)
                try:
                    self._wait_terminal(
                        request_id,
                        timeout_seconds=10,
                        no_event_timeout_seconds=10,
                    )
                except Exception:
                    self.kill()
                raise
            if response.get("type") == "turn.error":
                raise PersistentWorkerError(self._error_detail(response))
            if response.get("type") != "turn.result":
                raise PersistentWorkerError("worker returned an unexpected terminal envelope")
            result = response.get("result")
            if not isinstance(result, dict):
                raise PersistentWorkerError("worker turn result is invalid")
            return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process.poll() is None:
            with suppress(Exception):
                request_id = self._request_id()
                self._send(
                    {
                        "schema_version": self.PROTOCOL_VERSION,
                        "type": "session.close",
                        "request_id": request_id,
                        "session_id": self.session_id,
                    }
                )
                self._wait_terminal(request_id, timeout_seconds=10, no_event_timeout_seconds=10)
            with suppress(Exception):
                self._send(
                    {
                        "schema_version": self.PROTOCOL_VERSION,
                        "type": "worker.shutdown",
                        "request_id": self._request_id(),
                        "session_id": self.session_id,
                    }
                )
            with suppress(Exception):
                self.process.stdin.close()
            with suppress(Exception):
                self.process.wait(timeout=10)
        if self.process.poll() is None:
            self.kill()
        self._reader.join(timeout=1)
        self._stderr_reader.join(timeout=1)

    def kill(self) -> None:
        self._closed = True
        with suppress(Exception):
            self.cleanup()
        if self.process.poll() is None:
            if os.name == "posix":
                with suppress(OSError):
                    os.killpg(self.process.pid, signal.SIGKILL)
            with suppress(Exception):
                self.process.kill()
        with suppress(Exception):
            self.process.wait(timeout=5)

    @property
    def stderr_tail(self) -> str:
        return "".join(self._stderr)[-3000:]

    def _wait_terminal(
        self,
        request_id: str,
        *,
        timeout_seconds: int,
        no_event_timeout_seconds: int,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        terminal = {"session.opened", "session.closed", "turn.result", "turn.error", "worker.error"}
        return self._wait_for(
            lambda item: item.get("request_id") == request_id and item.get("type") in terminal,
            timeout_seconds=timeout_seconds,
            no_event_timeout_seconds=no_event_timeout_seconds,
            event_callback=event_callback,
            cancel_event=cancel_event,
        )

    def _wait_for(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        *,
        timeout_seconds: int,
        no_event_timeout_seconds: int,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + max(0, timeout_seconds)
        activity_deadline = time.monotonic() + max(0, no_event_timeout_seconds)
        deferred: list[dict[str, Any]] = []
        try:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise PersistentWorkerCancelled("worker turn was cancelled by the user")
                now = time.monotonic()
                if now >= deadline:
                    raise PersistentWorkerTimeout(f"worker exceeded {timeout_seconds} seconds")
                if now >= activity_deadline:
                    raise PersistentWorkerTimeout(
                        f"worker emitted no event for {no_event_timeout_seconds} seconds"
                    )
                try:
                    item = self._messages.get(timeout=min(0.25, deadline - now, activity_deadline - now))
                except queue.Empty:
                    continue
                if item is None:
                    detail = self.stderr_tail or "worker stdout closed without a terminal envelope"
                    raise PersistentWorkerError(detail)
                if isinstance(item, BaseException):
                    raise PersistentWorkerError("worker protocol reader failed") from item
                activity_deadline = time.monotonic() + max(0, no_event_timeout_seconds)
                if item.get("type") == "event":
                    event = runtime_event_from_mapping(item.get("event"))
                    if event is not None and event_callback is not None:
                        with suppress(Exception):
                            event_callback(event)
                if predicate(item):
                    return item
                if item.get("type") not in {"event", "heartbeat"}:
                    deferred.append(item)
        finally:
            for item in deferred:
                self._messages.put(item)

    def _interrupt(self, turn_request_id: str) -> None:
        if self.process.poll() is not None:
            return
        with suppress(Exception):
            self._send(
                {
                    "schema_version": self.PROTOCOL_VERSION,
                    "type": "turn.interrupt",
                    "request_id": self._request_id(),
                    "session_id": self.session_id,
                    "turn_request_id": turn_request_id,
                }
            )

    def _send(self, value: dict[str, Any]) -> None:
        if self.process.poll() is not None:
            raise PersistentWorkerError(self.stderr_tail or "worker process is not running")
        line = json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._write_lock:
            self.process.stdin.write(line)
            self.process.stdin.flush()

    def _read_stdout(self) -> None:
        try:
            for line in self.process.stdout:
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("NDJSON record must be an object")
                    self._append_spool(value)
                    self._messages.put(value)
                except BaseException as exc:
                    self._messages.put(exc)
                    return
        except BaseException as exc:
            self._messages.put(exc)
        finally:
            self._messages.put(None)

    def _read_stderr(self) -> None:
        try:
            for chunk in iter(lambda: self.process.stderr.read(4096), ""):
                if not chunk:
                    break
                self._stderr.append(chunk)
        except Exception:
            return

    def _prepare_spool(self) -> None:
        self.event_spool.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.event_spool.parent.chmod(0o700)
        if not self.event_spool.exists():
            self.event_spool.touch(mode=0o600)
        self.event_spool.chmod(0o600)

    def _append_spool(self, value: dict[str, Any]) -> None:
        safe = {
            key: item
            for key, item in value.items()
            if key not in {"prompt", "configuration", "gateway_environment", "result"}
        }
        if "event" in safe and isinstance(safe["event"], dict):
            safe["event"] = redact_event_data(safe["event"])
        record = {
            "recorded_at": time.time(),
            "session_id": self.session_id,
            "envelope": safe,
        }
        with self.event_spool.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    @staticmethod
    def _request_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _error_detail(response: dict[str, Any]) -> str:
        error = response.get("error")
        if isinstance(error, dict):
            detail = error.get("detail") or error.get("message")
            if isinstance(detail, str) and detail:
                return detail
        return "persistent Codex worker failed"
