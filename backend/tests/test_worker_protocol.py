from __future__ import annotations

import subprocess
import sys
import threading
import time

import pytest
from apkscanner.worker_protocol import (
    WorkerCancelledError,
    WorkerTimeoutError,
    consume_worker_process,
)


def test_worker_protocol_forwards_events_and_returns_terminal_result() -> None:
    script = """
import json
import sys

json.load(sys.stdin)
print(json.dumps({
    "type": "event",
    "event": {
        "event_type": "model.turn.started",
        "message": "turn started",
        "data": {"turn_id": "turn-test"}
    }
}), flush=True)
print(json.dumps({
    "type": "result",
    "result": {"thread_id": "thread-test", "ok": True}
}), flush=True)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    events = []
    result, stderr = consume_worker_process(
        process,
        payload={"schema_version": "1.0"},
        timeout_seconds=None,
        event_callback=events.append,
    )
    assert stderr == ""
    assert result == {"thread_id": "thread-test", "ok": True}
    assert len(events) == 1
    assert events[0].event_type == "model.turn.started"
    assert events[0].data["turn_id"] == "turn-test"


def test_worker_protocol_cancellation_terminates_the_process() -> None:
    script = """
import json
import sys
import time

json.load(sys.stdin)
time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    cancel_event = threading.Event()
    timer = threading.Timer(0.1, cancel_event.set)
    timer.start()
    try:
        with pytest.raises(WorkerCancelledError, match="cancelled"):
            consume_worker_process(
                process,
                payload={"schema_version": "1.0"},
                timeout_seconds=5,
                cancel_event=cancel_event,
            )
    finally:
        timer.cancel()
    assert process.poll() is not None


def test_worker_protocol_timeout_covers_a_blocked_stdin_write() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    started = time.monotonic()
    with pytest.raises(WorkerTimeoutError, match="exceeded"):
        consume_worker_process(
            process,
            payload={"blob": "x" * 1_000_000},
            timeout_seconds=0.2,
        )
    assert time.monotonic() - started < 2
    assert process.poll() is not None


def test_worker_protocol_no_event_timeout_terminates_a_silent_worker() -> None:
    script = """
import json
import sys
import time

json.load(sys.stdin)
time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    with pytest.raises(WorkerTimeoutError, match="emitted no event"):
        consume_worker_process(
            process,
            payload={"schema_version": "1.0"},
            timeout_seconds=5,
            no_event_timeout_seconds=0.1,
        )
    assert process.poll() is not None


def test_worker_protocol_cancellation_covers_a_blocked_stdin_write() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    cancel_event = threading.Event()
    timer = threading.Timer(0.1, cancel_event.set)
    timer.start()
    try:
        with pytest.raises(WorkerCancelledError, match="cancelled"):
            consume_worker_process(
                process,
                payload={"blob": "x" * 1_000_000},
                timeout_seconds=5,
                cancel_event=cancel_event,
            )
    finally:
        timer.cancel()
    assert process.poll() is not None


def test_worker_protocol_error_terminates_a_still_running_worker() -> None:
    script = """
import json
import sys
import time

json.load(sys.stdin)
print("not-json", flush=True)
time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    callbacks: list[str] = []
    cleanup_callbacks: list[str] = []
    with pytest.raises(RuntimeError, match="invalid NDJSON"):
        consume_worker_process(
            process,
            payload={"schema_version": "1.0"},
            timeout_seconds=5,
            on_cancel=lambda: callbacks.append("cancel"),
            on_timeout=lambda: callbacks.append("timeout"),
            on_error_cleanup=lambda: cleanup_callbacks.append("cleanup"),
        )
    assert process.poll() is not None
    assert callbacks == []
    assert cleanup_callbacks == ["cleanup"]


def test_worker_protocol_checks_cancellation_after_stdout_eof() -> None:
    script = """
import json
import os
import sys
import time

json.load(sys.stdin)
print(json.dumps({"type": "result", "result": {"ok": True}}), flush=True)
os.close(sys.stdout.fileno())
time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    cancel_event = threading.Event()
    timer = threading.Timer(0.1, cancel_event.set)
    timer.start()
    try:
        with pytest.raises(WorkerCancelledError, match="cancelled"):
            consume_worker_process(
                process,
                payload={"schema_version": "1.0"},
                timeout_seconds=5,
                cancel_event=cancel_event,
            )
    finally:
        timer.cancel()
    assert process.poll() is not None
