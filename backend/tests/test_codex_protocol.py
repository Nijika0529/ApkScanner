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

sequence = 0
def emit(value):
    global sequence
    sequence += 1
    print(json.dumps({"sequence":sequence, **value}), flush=True)

emit({"type":"worker.ready","protocol_version":"3.0"})
thread_id = None
turn_index = 0
for line in sys.stdin:
    command = json.loads(line)
    kind = command["type"]
    request_id = command["request_id"]
    if kind in {"session.open", "session.resume"}:
        thread_id = command.get("thread_id") or "thread-persistent"
        emit({
            "type":"session.opened", "request_id":request_id,
            "thread_id":thread_id
        })
    elif kind == "turn.start":
        turn_index += 1
        emit({
            "type":"event", "request_id":request_id,
            "event":{"event_type":"model.turn.started","message":"started","data":{}}
        })
        if command["prompt"] == "block":
            time.sleep(30)
        else:
            emit({
                "type":"turn.result", "request_id":request_id,
                "result":{"thread_id":thread_id,"turn_id":f"turn-{turn_index}",
                "result":{"result":"no_issue"},"usage":{}}
            })
    elif kind == "turn.interrupt":
        emit({
            "type":"turn.error", "request_id":command["turn_request_id"],
            "error":{"detail":"interrupted"}
        })
    elif kind == "session.close":
        emit({"type":"session.closed","request_id":request_id})
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


def test_replacement_worker_replays_prior_spool_events_once(tmp_path: Path) -> None:
    first = _client(tmp_path)
    first.open_session(configuration={}, gateway_environment={})
    first.turn(
        prompt="first",
        output_schema={},
        timeout_seconds=5,
        no_event_timeout_seconds=5,
        event_callback=None,
        cancel_event=None,
    )
    first.close()

    recovered = []
    replacement = _client(tmp_path)
    try:
        replacement.open_session(configuration={}, gateway_environment={})
        replacement.turn(
            prompt="replacement",
            output_schema={},
            timeout_seconds=5,
            no_event_timeout_seconds=5,
            event_callback=recovered.append,
            cancel_event=None,
        )
    finally:
        replacement.close()

    assert [event.delivery_source for event in recovered] == ["spool_replay", "live"]
    assert recovered[0].protocol_stream_id != recovered[1].protocol_stream_id
    assert len({event.protocol_record_key for event in recovered}) == 2


def test_spool_replay_emits_explicit_worker_sequence_gap(tmp_path: Path) -> None:
    spool = tmp_path / "events.ndjson"
    records = [
        {
            "recorded_at": 1.0,
            "session_id": "task:a1:primary",
            "stream_id": "crashed-stream",
            "worker_sequence": 1,
            "envelope": {
                "type": "worker.ready",
                "protocol_version": "3.0",
                "sequence": 1,
            },
        },
        {
            "recorded_at": 2.0,
            "session_id": "task:a1:primary",
            "stream_id": "crashed-stream",
            "worker_sequence": 3,
            "envelope": {
                "type": "event",
                "sequence": 3,
                "event": {
                    "event_type": "model.turn.completed",
                    "message": "completed",
                    "data": {},
                },
            },
        },
    ]
    spool.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    events = []
    client = _client(tmp_path)
    try:
        client.open_session(configuration={}, gateway_environment={})
        client.turn(
            prompt="recover-gap",
            output_schema={},
            timeout_seconds=5,
            no_event_timeout_seconds=5,
            event_callback=events.append,
            cancel_event=None,
        )
    finally:
        client.close()

    gap = next(event for event in events if event.event_type == "event.gap")
    assert gap.delivery_source == "spool_replay"
    assert gap.data["reason"] == "worker_sequence_gap"
    assert gap.data["missing_from"] == gap.data["missing_to"] == 2


def test_spool_replay_marks_a_dispatched_turn_without_terminal_envelope(tmp_path: Path) -> None:
    spool = tmp_path / "events.ndjson"
    spool.write_text(
        json.dumps(
            {
                "recorded_at": 1.0,
                "session_id": "task:a1:primary",
                "stream_id": "crashed-stream",
                "direction": "host",
                "worker_sequence": None,
                "envelope": {
                    "type": "turn.start",
                    "request_id": "lost-turn",
                    "session_id": "task:a1:primary",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = []
    client = _client(tmp_path)
    try:
        client.open_session(configuration={}, gateway_environment={})
        client.turn(
            prompt="recover-incomplete",
            output_schema={},
            timeout_seconds=5,
            no_event_timeout_seconds=5,
            event_callback=events.append,
            cancel_event=None,
        )
    finally:
        client.close()

    gap = next(
        event
        for event in events
        if event.event_type == "event.gap" and event.data["reason"] == "incomplete_turn"
    )
    assert "lost-turn" in gap.data["detail"]
    assert gap.protocol_stream_id == "crashed-stream"
