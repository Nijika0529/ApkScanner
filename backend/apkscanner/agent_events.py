from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class AgentCancelledError(RuntimeError):
    """Raised when a user-requested investigation cancellation is acknowledged."""


@dataclass(frozen=True, slots=True)
class AgentRuntimeEvent:
    """A provider-neutral, intentionally compact SDK/runtime event."""

    event_type: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


AgentEventCallback = Callable[[AgentRuntimeEvent], None]


def emit_agent_event(
    callback: AgentEventCallback | None,
    event_type: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    if callback is None:
        return
    callback(AgentRuntimeEvent(event_type=event_type, message=message, data=data or {}))


def normalize_codex_notification(notification: Any) -> AgentRuntimeEvent | None:
    method = str(getattr(notification, "method", ""))
    payload = _model_dump(getattr(notification, "payload", None))

    if method == "turn/started":
        turn = _mapping(payload.get("turn"))
        return AgentRuntimeEvent(
            "model.turn.started",
            "Codex 开始处理本轮探索",
            _compact({"turn_id": turn.get("id"), "status": turn.get("status")}),
        )
    if method == "turn/completed":
        turn = _mapping(payload.get("turn"))
        return AgentRuntimeEvent(
            "model.turn.completed",
            "Codex 本轮处理完成",
            _compact(
                {
                    "turn_id": turn.get("id"),
                    "status": turn.get("status"),
                    "error": _safe_error(turn.get("error")),
                }
            ),
        )
    if method == "error":
        return AgentRuntimeEvent(
            "model.error",
            "Codex SDK 报告运行错误",
            {"error": _safe_error(payload.get("error") or payload)},
        )
    if method not in {"item/started", "item/completed"}:
        return None

    item = _mapping(payload.get("item"))
    item_type = str(item.get("type") or "unknown")
    item_id = item.get("id")
    state = "started" if method.endswith("started") else "completed"
    common = _compact(
        {
            "item_id": item_id,
            "item_type": item_type,
            "status": item.get("status"),
        }
    )
    normalized = item_type.replace("_", "").lower()
    if normalized == "reasoning":
        return AgentRuntimeEvent(
            f"model.reasoning.{state}",
            "Codex 正在整理验证思路" if state == "started" else "Codex 已完成验证思路整理",
            common,
        )
    if normalized in {"agentmessage", "message"}:
        return AgentRuntimeEvent(
            f"model.response.{state}",
            "Codex 正在生成结构化判断" if state == "started" else "Codex 已生成结构化判断",
            common,
        )
    if normalized == "plan":
        return AgentRuntimeEvent(
            f"model.plan.{state}",
            "Codex 正在制定探索计划" if state == "started" else "Codex 已完成探索计划",
            common,
        )
    if normalized in {
        "commandexecution",
        "filechange",
        "mcptoolcall",
        "dynamictoolcall",
        "websearch",
        "collabtoolcall",
    }:
        return AgentRuntimeEvent(
            f"model.tool.{state}",
            (
                f"Codex 开始执行 {item_type}"
                if state == "started"
                else f"Codex 已完成 {item_type}"
            ),
            _compact(
                {
                    **common,
                    "exit_code": item.get("exitCode") or item.get("exit_code"),
                    "duration_ms": item.get("durationMs") or item.get("duration_ms"),
                }
            ),
        )
    return None


def runtime_event_from_mapping(value: Any) -> AgentRuntimeEvent | None:
    if not isinstance(value, dict):
        return None
    event_type = value.get("event_type")
    message = value.get("message")
    data = value.get("data", {})
    if not isinstance(event_type, str) or not event_type:
        return None
    if not isinstance(message, str) or not message:
        return None
    return AgentRuntimeEvent(
        event_type=event_type,
        message=message,
        data=data if isinstance(data, dict) else {},
    )


def _model_dump(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        result = dump(mode="json", exclude_none=True)
        return result if isinstance(result, dict) else {}
    return {}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_error(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value[:1000]
    if isinstance(value, dict):
        message = value.get("message")
        if isinstance(message, str):
            return message[:1000]
        error_type = value.get("type") or value.get("name")
        return str(error_type)[:1000] if error_type else "runtime error"
    return str(value)[:1000]


def _compact(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}
