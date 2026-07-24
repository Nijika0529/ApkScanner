from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_events import normalize_codex_notification
from .codex_runner import CodexInvestigator


class WorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    prompt: str = Field(min_length=1, max_length=10_000_000)
    developer_instructions: str = Field(min_length=1, max_length=100_000)
    model: str = Field(min_length=1, max_length=256)
    output_schema: dict[str, Any]


def _prepare_auth() -> None:
    source_value = os.getenv("APKSCANNER_CODEX_AUTH_FILE")
    if not source_value:
        return
    source = Path(source_value)
    codex_home = Path(os.environ.get("CODEX_HOME", "/codex-home"))
    codex_home.mkdir(parents=True, exist_ok=True)
    target = codex_home / "auth.json"
    shutil.copyfile(source, target)
    target.chmod(0o600)


def main() -> None:
    raw = sys.stdin.buffer.read(10_000_001)
    if len(raw) > 10_000_000:
        raise ValueError("worker request exceeds 10 MB")
    request = WorkerRequest.model_validate_json(raw)
    _prepare_auth()

    from openai_codex import ApprovalMode, Codex, CodexConfig, Sandbox
    from openai_codex.generated.v2_all import ReasoningEffort

    with Codex(CodexConfig(config_overrides=("agents.max_threads=1",))) as codex:
        thread = codex.thread_start(
            approval_mode=ApprovalMode.deny_all,
            cwd="/workspace",
            developer_instructions=request.developer_instructions,
            ephemeral=True,
            model=request.model,
            sandbox=Sandbox.read_only,
            service_name="apk-scanner-container-worker",
        )
        _emit_event(
            "model.session.started",
            "Codex SDK 会话已建立",
            {"thread_id": thread.id},
        )
        handle = thread.turn(
            request.prompt,
            approval_mode=ApprovalMode.deny_all,
            cwd="/workspace",
            effort=ReasoningEffort.medium,
            model=request.model,
            output_schema=request.output_schema,
            sandbox=Sandbox.read_only,
        )
        from openai_codex.api import _collect_turn_result

        def stream():  # noqa: ANN202
            for notification in handle.stream():
                event = normalize_codex_notification(notification)
                if event is not None:
                    _emit_event(event.event_type, event.message, event.data)
                yield notification

        turn = _collect_turn_result(stream(), turn_id=handle.id)
    parsed = CodexInvestigator._parse_response(turn.final_response)
    _emit_event(
        "model.output.validated",
        "Codex 结构化输出已通过本地校验",
        {"turn_id": turn.id},
    )
    usage = turn.usage.model_dump(mode="json") if turn.usage else {}
    _emit_record(
        {
            "type": "result",
            "result": {
                "thread_id": thread.id,
                "turn_id": turn.id,
                "result": parsed.model_dump(mode="json"),
                "usage": usage,
            },
        }
    )


def _emit_event(event_type: str, message: str, data: dict[str, Any]) -> None:
    _emit_record(
        {
            "type": "event",
            "event": {
                "event_type": event_type,
                "message": message,
                "data": data,
            },
        }
    )


def _emit_record(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
