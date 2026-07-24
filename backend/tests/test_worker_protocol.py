from __future__ import annotations

import subprocess
import sys
import threading

import pytest
from apkscanner.worker_protocol import WorkerCancelledError, consume_worker_process


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
        timeout_seconds=5,
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
