from __future__ import annotations

import json
import os
import re
import sys
import threading
from contextlib import suppress
from typing import Any, Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from .agent_events import normalize_codex_notification
from .codex_runner import CodexInvestigator, codex_config_overrides
from .schemas import AGENT_RESULT_JSON_SCHEMA

PROTOCOL_VERSION = "3.0"
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


class WorkerConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    developer_instructions: str = Field(min_length=1, max_length=100_000)
    model: str = Field(min_length=1, max_length=256)
    model_provider: Literal["deepseek"]
    reasoning_effort: Literal["low", "high", "max"]
    provider_base_url: str = Field(min_length=1, max_length=2048)
    model_catalog_path: str = Field(min_length=1, max_length=4096)
    workspace_path: str = Field(pattern=r"^/agent-workspaces/[a-z0-9-]+/workspace$")


class BaseCommand(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal["3.0"]
    type: str
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")


class SessionCommand(BaseCommand):
    configuration: WorkerConfiguration
    gateway_environment: dict[str, str] = Field(default_factory=dict)
    thread_id: str | None = None


class TurnCommand(BaseCommand):
    prompt: str = Field(min_length=1, max_length=10_000_000)
    result_contract: Literal["agent_investigation.v1", "json_object.v1"] = (
        "agent_investigation.v1"
    )
    output_schema: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_result_contract(self) -> TurnCommand:
        if self.result_contract == "agent_investigation.v1":
            if self.output_schema is not None and self.output_schema != AGENT_RESULT_JSON_SCHEMA:
                raise ValueError(
                    "agent_investigation.v1 does not accept an arbitrary output schema"
                )
        elif not self.output_schema:
            raise ValueError("json_object.v1 requires an explicit output schema")
        return self

    def resolved_output_schema(self) -> dict[str, Any]:
        if self.result_contract == "agent_investigation.v1":
            return AGENT_RESULT_JSON_SCHEMA
        assert self.output_schema is not None
        return self.output_schema


class PersistentCodexWorker:
    def __init__(self) -> None:
        self.codex: Any = None
        self.thread: Any = None
        self.configuration: WorkerConfiguration | None = None
        self.session_id: str | None = None
        self.active_handle: Any = None
        self.active_request_id: str | None = None
        self.active_thread: threading.Thread | None = None
        self.lock = threading.RLock()
        self.emit_lock = threading.Lock()
        self.sequence = 0
        self.shutdown_requested = threading.Event()

    def run(self) -> None:
        self.emit(
            {
                "type": "worker.ready",
                "protocol_version": PROTOCOL_VERSION,
                "worker_pid": os.getpid(),
            }
        )
        for raw in sys.stdin:
            value: Any = None
            if self.shutdown_requested.is_set():
                break
            if len(raw) > 10_000_001:
                self.error(None, "command_too_large", "worker command exceeds 10 MB")
                continue
            try:
                value = json.loads(raw)
                command = BaseCommand.model_validate(value)
                self.dispatch(command, value)
            except (json.JSONDecodeError, ValidationError, ValueError) as exc:
                request_id = value.get("request_id") if isinstance(value, dict) else None
                self.error(request_id, "invalid_command", str(exc))
            except Exception as exc:
                request_id = value.get("request_id") if isinstance(value, dict) else None
                self.error(request_id, "worker_failure", str(exc))
        self.shutdown()

    def dispatch(self, command: BaseCommand, value: dict[str, Any]) -> None:
        if command.type in {"session.open", "session.resume"}:
            self.open_session(SessionCommand.model_validate(value), resume=command.type.endswith("resume"))
        elif command.type == "turn.start":
            self.start_turn(TurnCommand.model_validate(value))
        elif command.type == "turn.interrupt":
            self.interrupt(command.request_id)
        elif command.type == "session.close":
            self.close_session(command.request_id)
        elif command.type == "worker.ping":
            self.emit(
                {
                    "type": "heartbeat",
                    "request_id": command.request_id,
                    "session_id": command.session_id,
                    "active_turn": self.active_request_id,
                }
            )
        elif command.type == "worker.shutdown":
            self.shutdown_requested.set()
        else:
            self.error(command.request_id, "unsupported_command", f"unsupported command: {command.type}")

    def open_session(self, command: SessionCommand, *, resume: bool) -> None:
        with self.lock:
            if self.codex is not None:
                self.error(command.request_id, "session_already_open", "a worker owns only one session")
                return
            if resume and (not command.thread_id or not _ID.fullmatch(command.thread_id)):
                raise ValueError("session.resume requires a valid thread_id")
            self._install_gateway_environment(command.gateway_environment)
            from openai_codex import ApprovalMode, Codex, CodexConfig, Sandbox

            config = command.configuration
            codex = Codex(
                CodexConfig(
                    config_overrides=codex_config_overrides(
                        provider=config.model_provider,
                        model=config.model,
                        reasoning_effort=config.reasoning_effort,
                        base_url=config.provider_base_url,
                        model_catalog_path=config.model_catalog_path,
                        web_search="live",
                    )
                )
            )
            try:
                if resume:
                    thread = codex.thread_resume(
                        command.thread_id,
                        approval_mode=ApprovalMode.deny_all,
                        cwd=config.workspace_path,
                        developer_instructions=config.developer_instructions,
                        model=config.model,
                        model_provider=config.model_provider,
                        sandbox=Sandbox.full_access,
                    )
                else:
                    thread = codex.thread_start(
                        approval_mode=ApprovalMode.deny_all,
                        cwd=config.workspace_path,
                        developer_instructions=config.developer_instructions,
                        ephemeral=False,
                        model=config.model,
                        model_provider=config.model_provider,
                        sandbox=Sandbox.full_access,
                        service_name="apk-scanner-container-worker",
                    )
            except Exception:
                codex.close()
                raise
            self.codex = codex
            self.thread = thread
            self.configuration = config
            self.session_id = command.session_id
            self.emit(
                {
                    "type": "session.opened",
                    "request_id": command.request_id,
                    "session_id": command.session_id,
                    "thread_id": thread.id,
                    "resumed": resume,
                }
            )

    def start_turn(self, command: TurnCommand) -> None:
        with self.lock:
            if self.thread is None or self.configuration is None:
                self.error(command.request_id, "session_not_open", "open a session before starting a turn")
                return
            if command.session_id != self.session_id:
                self.error(command.request_id, "session_mismatch", "command does not own this session")
                return
            if self.active_thread is not None and self.active_thread.is_alive():
                self.error(command.request_id, "turn_already_active", "only one turn may run per session")
                return
            self.active_request_id = command.request_id
            self.active_thread = threading.Thread(
                target=self._run_turn,
                args=(command,),
                name="apkscanner-codex-turn",
                daemon=True,
            )
            self.active_thread.start()

    def _run_turn(self, command: TurnCommand) -> None:
        try:
            from openai_codex import ApprovalMode, Sandbox
            from openai_codex.api import _collect_turn_result
            from openai_codex.generated.v2_all import ReasoningEffort

            config = self.configuration
            if config is None:
                raise RuntimeError("session configuration disappeared")
            handle = self.thread.turn(
                command.prompt,
                approval_mode=ApprovalMode.deny_all,
                cwd=config.workspace_path,
                effort=ReasoningEffort(config.reasoning_effort),
                model=config.model,
                output_schema=command.resolved_output_schema(),
                sandbox=Sandbox.full_access,
            )
            with self.lock:
                self.active_handle = handle
            heartbeat_stop = threading.Event()
            heartbeat = threading.Thread(
                target=self._heartbeat_loop,
                args=(command.request_id, handle.id, heartbeat_stop),
                daemon=True,
            )
            heartbeat.start()

            def stream():  # noqa: ANN202
                for notification in handle.stream():
                    event = normalize_codex_notification(notification)
                    if event is not None:
                        self.emit(
                            {
                                "type": "event",
                                "request_id": command.request_id,
                                "session_id": command.session_id,
                                "thread_id": self.thread.id,
                                "turn_id": handle.id,
                                "event": {
                                    "event_type": event.event_type,
                                    "message": event.message,
                                    "data": event.data,
                                },
                            }
                        )
                    yield notification

            try:
                turn = _collect_turn_result(stream(), turn_id=handle.id)
            finally:
                heartbeat_stop.set()
                heartbeat.join(timeout=1)
            model_validation: dict[str, Any] = {}
            if command.result_contract == "agent_investigation.v1":
                parsed_result = CodexInvestigator._parse_response(turn.final_response)
                parsed = parsed_result.model_dump(mode="json")
                model_validation = {
                    "rejected_requested_tests": parsed_result.rejected_requested_tests,
                    "normalization_repairs": parsed_result.normalization_repairs,
                }
            else:
                required = command.resolved_output_schema().get("required")
                required_keys = (
                    {item for item in required if isinstance(item, str)}
                    if isinstance(required, list)
                    else None
                )
                parsed = CodexInvestigator._parse_json_object(
                    turn.final_response,
                    required_keys=required_keys,
                )
            usage = turn.usage.model_dump(mode="json") if turn.usage else {}
            self.emit(
                {
                    "type": "event",
                    "request_id": command.request_id,
                    "session_id": command.session_id,
                    "thread_id": self.thread.id,
                    "turn_id": turn.id,
                    "event": {
                        "event_type": "model.output.validated",
                        "message": "Codex 结构化输出已通过本地校验",
                        "data": {
                            "turn_id": turn.id,
                            "result_contract": command.result_contract,
                        },
                    },
                }
            )
            self.emit(
                {
                    "type": "turn.result",
                    "request_id": command.request_id,
                    "session_id": command.session_id,
                    "thread_id": self.thread.id,
                    "turn_id": turn.id,
                    "result": {
                        "thread_id": self.thread.id,
                        "turn_id": turn.id,
                        "result": parsed,
                        "result_contract": command.result_contract,
                        "model_validation": model_validation,
                        "usage": usage,
                    },
                }
            )
        except Exception as exc:
            self.emit(
                {
                    "type": "turn.error",
                    "request_id": command.request_id,
                    "session_id": command.session_id,
                    "error": {"code": "turn_failed", "detail": str(exc)[:3000]},
                }
            )
        finally:
            with self.lock:
                self.active_handle = None
                self.active_request_id = None

    def _heartbeat_loop(self, request_id: str, turn_id: str, stop: threading.Event) -> None:
        while not stop.wait(15):
            self.emit(
                {
                    "type": "heartbeat",
                    "request_id": request_id,
                    "session_id": self.session_id,
                    "thread_id": self.thread.id,
                    "turn_id": turn_id,
                }
            )

    def interrupt(self, request_id: str) -> None:
        with self.lock:
            handle = self.active_handle
            active_request_id = self.active_request_id
        if handle is not None:
            with suppress(Exception):
                handle.interrupt()
        self.emit(
            {
                "type": "event",
                "request_id": active_request_id or request_id,
                "session_id": self.session_id,
                "event": {
                    "event_type": "model.turn.interrupt.requested",
                    "message": "Codex 本轮分析已收到停止请求",
                    "data": {},
                },
            }
        )

    def close_session(self, request_id: str) -> None:
        with self.lock:
            handle = self.active_handle
        if handle is not None:
            with suppress(Exception):
                handle.interrupt()
        active = self.active_thread
        if active is not None:
            active.join(timeout=10)
        with self.lock:
            if self.codex is not None:
                self.codex.close()
            self.codex = None
            self.thread = None
            self.configuration = None
        self.emit(
            {
                "type": "session.closed",
                "request_id": request_id,
                "session_id": self.session_id,
            }
        )

    def shutdown(self) -> None:
        if self.codex is not None:
            with suppress(Exception):
                self.close_session("worker-shutdown")

    def error(self, request_id: str | None, code: str, detail: str) -> None:
        self.emit(
            {
                "type": "worker.error",
                "request_id": request_id,
                "session_id": self.session_id,
                "error": {"code": code, "detail": detail[:3000]},
            }
        )

    def emit(self, value: dict[str, Any]) -> None:
        with self.emit_lock:
            self.sequence += 1
            value = {"schema_version": PROTOCOL_VERSION, "sequence": self.sequence, **value}
            print(json.dumps(value, ensure_ascii=False, separators=(",", ":")), flush=True)

    @staticmethod
    def _install_gateway_environment(values: dict[str, str]) -> None:
        allowed = {
            "APKSCANNER_ADB_TASK_ID",
            "APKSCANNER_ADB_GATEWAY_URL",
            "APKSCANNER_ADB_TOKEN",
            "APKSCANNER_ADB_POLICY",
            "APKSCANNER_PROOF_TASK_ID",
            "APKSCANNER_PROOF_REPLAY_URL",
            "APKSCANNER_PROOF_TOKEN",
        }
        unknown = set(values) - allowed
        if unknown:
            raise ValueError("gateway environment contains unsupported names")
        url_adapter = TypeAdapter(AnyHttpUrl)
        for name, value in values.items():
            if not isinstance(value, str) or len(value) > 4096:
                raise ValueError("gateway environment value is invalid")
            if name == "APKSCANNER_ADB_POLICY":
                if value not in {"scoped", "adaptive"}:
                    raise ValueError("gateway ADB policy is invalid")
            elif name.endswith("_URL"):
                parsed = url_adapter.validate_python(value)
                if parsed.scheme != "http" or parsed.host not in {"apkscanner-host", "127.0.0.1"}:
                    raise ValueError("gateway URL must target the platform bridge")
            elif name.endswith("_TOKEN"):
                if not _TOKEN.fullmatch(value):
                    raise ValueError("gateway token is invalid")
            elif not _ID.fullmatch(value):
                raise ValueError("gateway task ID is invalid")
            os.environ[name] = value


def main() -> None:
    PersistentCodexWorker().run()


if __name__ == "__main__":
    main()
