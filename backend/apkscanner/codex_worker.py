from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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


def _connect_remote_adb() -> None:
    serial = os.getenv("APKSCANNER_ADB_SERIAL")
    if not serial or not re.fullmatch(r"[A-Za-z0-9_.-]+:\d{1,5}", serial):
        return
    subprocess.run(
        ["adb", "connect", serial],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
    )


def main() -> None:
    raw = sys.stdin.buffer.read(10_000_001)
    if len(raw) > 10_000_000:
        raise ValueError("worker request exceeds 10 MB")
    request = WorkerRequest.model_validate_json(raw)
    _prepare_auth()
    _connect_remote_adb()

    from openai_codex import ApprovalMode, Codex, CodexConfig, Sandbox
    from openai_codex.generated.v2_all import ReasoningEffort

    with Codex(CodexConfig(config_overrides=("agents.max_threads=1",))) as codex:
        thread = codex.thread_start(
            approval_mode=ApprovalMode.deny_all,
            cwd="/workspace",
            developer_instructions=request.developer_instructions,
            ephemeral=True,
            model=request.model,
            sandbox=Sandbox.full_access,
            service_name="apk-scanner-container-worker",
        )
        turn = thread.run(
            request.prompt,
            approval_mode=ApprovalMode.deny_all,
            cwd="/workspace",
            effort=ReasoningEffort.medium,
            model=request.model,
            output_schema=request.output_schema,
            sandbox=Sandbox.full_access,
        )
    parsed = CodexInvestigator._parse_response(turn.final_response)
    usage = turn.usage.model_dump(mode="json") if turn.usage else {}
    print(
        json.dumps(
            {
                "thread_id": thread.id,
                "turn_id": turn.id,
                "result": parsed.model_dump(mode="json"),
                "usage": usage,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
