from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from apkscanner.codex_protocol import (
    PersistentWorkerCancelled,
    PersistentWorkerClient,
)

FAKE_WORKER = r"""
import json
import sys
import time

print(json.dumps({"type":"worker.ready","protocol_version":"3.0"}), flush=True)
thread_id = None
turn_index = 0
for line in sys.stdin:
    command = json.loads(line)
    kind = command["type"]
    request_id = command["request_id"]
    if kind in {"session.open", "session.resume"}:
        thread_id = command.get("thread_id") or "thread-persistent"
        print(json.dumps({
            "type":"session.opened", "request_id":request_id,
            "thread_id":thread_id
        }), flush=True)
    elif kind == "turn.start":
        turn_index += 1
        print(json.dumps({
            "type":"event", "request_id":request_id,
            "event":{"event_type":"model.turn.started","message":"started","data":{}}
        }), flush=True)
        if command["prompt"] == "block":
            time.sleep(30)
        else:
            print(json.dumps({
                "type":"turn.result", "request_id":request_id,
                "result":{"thread_id":thread_id,"turn_id":f"turn-{turn_index}",
                "result":{"result":"no_issue"},"usage":{}}
            }), flush=True)
    elif kind == "turn.interrupt":
        print(json.dumps({
            "type":"turn.error", "request_id":command["turn_request_id"],
            "error":{"detail":"interrupted"}
        }), flush=True)
    elif kind == "session.close":
        print(json.dumps({"type":"session.closed","request_id":request_id}), flush=True)
    elif kind == "worker.shutdown":
        break
"""


def _client(tmp_path: Path) -> PersistentWorkerClient:
    process = subprocess.Popen(
        [sys.executable, "-c", FAKE_WORKER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    return PersistentWorkerClient(
        process,
        session_id="task:a1:primary",
        event_spool=tmp_path / "events.ndjson",
        cleanup=process.kill,
    )


def test_persistent_worker_reuses_thread_and_records_redacted_event_spool(tmp_path: Path) -> None:
    client = _client(tmp_path)
    try:
        thread_id = client.open_session(
            configuration={"secret": "not-written"},
            gateway_environment={"APKSCANNER_ADB_TOKEN": "not-written"},
        )
        events = []
        first = client.turn(
            prompt="first secret prompt",
            output_schema={},
            timeout_seconds=5,
            no_event_timeout_seconds=5,
            event_callback=events.append,
            cancel_event=None,
        )
        second = client.turn(
            prompt="second secret prompt",
            output_schema={},
            timeout_seconds=5,
            no_event_timeout_seconds=5,
            event_callback=events.append,
            cancel_event=None,
        )
    finally:
        client.close()
    assert thread_id == first["thread_id"] == second["thread_id"]
    assert first["turn_id"] == "turn-1"
    assert second["turn_id"] == "turn-2"
    assert len(events) == 2
    spool = tmp_path.joinpath("events.ndjson").read_text(encoding="utf-8")
    assert "first secret prompt" not in spool
    assert "second secret prompt" not in spool
    assert "not-written" not in spool
    assert any(json.loads(line)["envelope"]["type"] == "turn.result" for line in spool.splitlines())


def test_persistent_worker_cancellation_interrupts_or_kills_session(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.open_session(configuration={}, gateway_environment={})
    cancel = threading.Event()
    cancel.set()
    try:
        with pytest.raises(PersistentWorkerCancelled):
            client.turn(
                prompt="block",
                output_schema={},
                timeout_seconds=5,
                no_event_timeout_seconds=5,
                event_callback=None,
                cancel_event=cancel,
            )
    finally:
        client.kill()
