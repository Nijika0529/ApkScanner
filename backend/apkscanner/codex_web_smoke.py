from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .agent_events import normalize_codex_notification
from .codex_runner import codex_config_overrides

WEB_SMOKE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "source_url": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "summary": {"type": "string"},
    },
    "required": ["ok", "source_url", "summary"],
}


def run_web_search_smoke() -> dict[str, Any]:
    """Exercise the configured Responses provider's native Codex Web Search path."""

    if not os.getenv("DEEPSEEK_API_KEY"):
        raise RuntimeError("DEEPSEEK_API_KEY is required for the Web Search smoke test")
    from openai_codex import ApprovalMode, Codex, CodexConfig, Sandbox
    from openai_codex.api import _collect_turn_result

    provider = os.getenv("APKSCANNER_CODEX_PROVIDER", "deepseek")
    model = os.getenv("APKSCANNER_CODEX_MODEL", "deepseek-v4-flash")
    base_url = os.getenv("APKSCANNER_DEEPSEEK_BASE_URL", "https://api.deepseek.com/")
    catalog = Path(
        os.getenv(
            "APKSCANNER_CODEX_MODEL_CATALOG",
            "/opt/apk-scanner/config/deepseek-models.json",
        )
    )
    config = CodexConfig(
        config_overrides=codex_config_overrides(
            provider=provider,
            model=model,
            reasoning_effort="high",
            base_url=base_url,
            model_catalog_path=catalog,
            web_search="live",
        )
    )
    events = []
    with (
        tempfile.TemporaryDirectory(prefix="apkscanner-web-smoke-") as workspace,
        Codex(config) as codex,
    ):
        thread = codex.thread_start(
            approval_mode=ApprovalMode.deny_all,
            cwd=workspace,
            developer_instructions=(
                "This is a capability smoke test. Use Web Search exactly once. "
                "Do not use shell, files, MCP, or any other tool."
            ),
            ephemeral=True,
            model=model,
            model_provider=provider,
            sandbox=Sandbox.read_only,
            service_name="apk-scanner-web-smoke",
        )
        handle = thread.turn(
            (
                "Use Web Search to locate the official DeepSeek updates page. Return only "
                "the requested JSON with its direct HTTPS URL and a short Chinese summary."
            ),
            approval_mode=ApprovalMode.deny_all,
            cwd=workspace,
            model=model,
            output_schema=WEB_SMOKE_SCHEMA,
            sandbox=Sandbox.read_only,
        )

        def stream():  # noqa: ANN202
            for notification in handle.stream():
                event = normalize_codex_notification(notification)
                if event is not None:
                    events.append(event)
                yield notification

        turn = _collect_turn_result(stream(), turn_id=handle.id)
    payload = json.loads(turn.final_response or "")
    source_url = payload.get("source_url") if isinstance(payload, dict) else None
    parsed_url = urlsplit(source_url) if isinstance(source_url, str) else None
    event_types = [event.event_type for event in events]
    search_started = "web_search.started" in event_types
    search_completed = "web_search.completed" in event_types
    passed = bool(
        isinstance(payload, dict)
        and payload.get("ok") is True
        and parsed_url is not None
        and parsed_url.scheme == "https"
        and parsed_url.hostname == "api-docs.deepseek.com"
        and search_started
        and search_completed
    )
    return {
        "schema_version": "1.0",
        "passed": passed,
        "provider": provider,
        "model": model,
        "thread_id": thread.id,
        "turn_id": turn.id,
        "source_url": source_url,
        "web_search_events": [
            {
                "event_type": event.event_type,
                "message": event.message,
                "data": event.data,
            }
            for event in events
            if event.event_type.startswith("web_search.")
        ],
    }


def main() -> None:
    result = run_web_search_smoke()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
