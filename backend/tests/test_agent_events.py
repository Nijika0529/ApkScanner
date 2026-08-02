from __future__ import annotations

from types import SimpleNamespace

from apkscanner.agent_events import (
    normalize_codex_notification,
    redact_event_data,
    runtime_event_from_mapping,
)


def test_unknown_sdk_notifications_are_safely_summarized() -> None:
    event = normalize_codex_notification(
        SimpleNamespace(
            method="future/event",
            payload={"newField": "must-not-be-copied", "authorization": "Bearer sk-secret123"},
        )
    )

    assert event is not None
    assert event.event_type == "sdk.notification.unknown"
    assert event.data == {
        "method": "future/event",
        "payload_keys": ["authorization", "newField"],
    }
    assert len(event.dedupe_key) == 64


def test_high_frequency_codex_deltas_and_user_messages_are_not_persisted() -> None:
    delta = normalize_codex_notification(
        SimpleNamespace(
            method="item/reasoning/textDelta",
            payload={"delta": "private reasoning fragment"},
        )
    )
    user_message = normalize_codex_notification(
        SimpleNamespace(
            method="item/started",
            payload={"item": {"id": "item-1", "type": "userMessage"}},
        )
    )

    assert delta is None
    assert user_message is None


def test_redundant_usage_and_diff_snapshots_are_not_persisted() -> None:
    assert (
        normalize_codex_notification(
            SimpleNamespace(method="thread/tokenUsage/updated", payload={})
        )
        is None
    )
    assert (
        normalize_codex_notification(
            SimpleNamespace(method="turn/diff/updated", payload={})
        )
        is None
    )


def test_web_search_items_have_explicit_audit_event_types() -> None:
    started = normalize_codex_notification(
        SimpleNamespace(
            method="item/started",
            payload={
                "item": {
                    "id": "web-1",
                    "type": "webSearch",
                    "query": "Android Binder security",
                    "action": {"type": "search"},
                }
            },
        )
    )
    completed = normalize_codex_notification(
        SimpleNamespace(
            method="item/completed",
            payload={
                "item": {
                    "id": "web-1",
                    "type": "webSearch",
                    "query": "Android Binder security",
                    "action": {"type": "search"},
                }
            },
        )
    )

    assert started is not None and started.event_type == "web_search.started"
    assert completed is not None and completed.event_type == "web_search.completed"
    assert completed.data["query"] == "Android Binder security"
    assert completed.data["action_type"] == "search"


def test_worker_events_redact_secret_keys_and_values() -> None:
    event = runtime_event_from_mapping(
        {
            "event_type": "model.tool.completed",
            "message": "done",
            "data": {
                "api_key": "sk-never-store-this",
                "output": "request used Bearer sk-also-secret-value",
                "nested": {"credential": "sensitive"},
            },
        }
    )

    assert event is not None
    assert event.data["api_key"] == "[REDACTED]"
    assert event.data["output"] == "request used [REDACTED]"
    assert event.data["nested"]["credential"] == "[REDACTED]"


def test_redaction_preserves_non_secret_event_fields() -> None:
    assert redact_event_data({"turn_id": "turn-1", "exit_code": 0}) == {
        "turn_id": "turn-1",
        "exit_code": 0,
    }
