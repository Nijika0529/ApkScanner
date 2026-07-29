from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .agent_events import AgentCancelledError, AgentEventCallback, emit_agent_event
from .agent_prompt import developer_instructions, investigation_prompt
from .config import Settings
from .models import EntryPoint, InvestigationTask, Scan
from .schemas import AGENT_RESULT_JSON_SCHEMA, AgentInvestigationResult
from .worker_protocol import (
    WorkerCancelledError,
    WorkerTimeoutError,
    consume_worker_process,
)

OPENCODE_SDK_VERSION = "1.18.4"
OPENCODE_CLI_VERSION = "1.18.4"
AJV_VERSION = "8.20.0"
OPENCODE_WORKER_PROTOCOL_VERSION = "7"
OPENCODE_PROVIDER = "deepseek"
OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL = "structured_output_tool"
OPENCODE_OUTPUT_MODE_ANALYZE_THEN_FINALIZE = "analyze_then_finalize"
OPENCODE_TOOL_PROFILE = "workspace_shell"
OPENCODE_WORKSPACE_TOOLS = ("read", "glob", "grep", "bash")
OPENCODE_PROFILE_STABLE_ANALYZER = "stable_analyzer"
OPENCODE_PROFILE_STRUCTURED_FINALIZER = "structured_finalizer"
OPENCODE_PROVIDER_KEY_FIELD = "_provider_api_key"
OPENCODE_FINALIZER_PHASES = frozenset({"final_evaluation", "recovery_evaluation"})
OPENCODE_BOUNDED_STRUCTURED_PHASES = OPENCODE_FINALIZER_PHASES | {
    "adversarial_review"
}


@dataclass(frozen=True, slots=True)
class OpenCodeExecutionStage:
    name: str
    thinking_mode: str
    output_mode: str
    workspace_tools: bool
    reasoning_effort: str | None = None


@dataclass(frozen=True, slots=True)
class OpenCodeExecutionProfile:
    name: str
    output_mode: str
    stages: tuple[OpenCodeExecutionStage, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "output_mode": self.output_mode,
            "stages": [
                {
                    "name": stage.name,
                    "thinking_mode": stage.thinking_mode,
                    "reasoning_effort": stage.reasoning_effort,
                    "output_mode": stage.output_mode,
                    "workspace_tools": stage.workspace_tools,
                    "wire_tool_choice": (
                        "required"
                        if stage.output_mode == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
                        else (
                            "omitted"
                            if stage.thinking_mode == "enabled"
                            else "auto"
                        )
                    ),
                }
                for stage in self.stages
            ],
        }


def opencode_execution_profile(
    phase: str | None,
    *,
    reasoning_effort: str = "high",
    enable_thinking_explorer: bool = False,
    enable_workspace_analyzer: bool = False,
) -> OpenCodeExecutionProfile:
    normalized = (phase or "").strip().lower()
    # Critic and final decision phases already receive the full evidence context
    # produced by earlier exploration. Running another workspace analyzer here
    # consumes their short reserve and can strand the required StructuredOutput
    # finalizer at the worker deadline.
    if normalized in OPENCODE_BOUNDED_STRUCTURED_PHASES:
        return OpenCodeExecutionProfile(
            name=OPENCODE_PROFILE_STRUCTURED_FINALIZER,
            output_mode=OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
            stages=(
                OpenCodeExecutionStage(
                    name="finalizer",
                    thinking_mode="disabled",
                    reasoning_effort=None,
                    output_mode=OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
                    workspace_tools=False,
                ),
            ),
        )
    if enable_workspace_analyzer:
        return OpenCodeExecutionProfile(
            name=OPENCODE_PROFILE_STABLE_ANALYZER,
            output_mode=OPENCODE_OUTPUT_MODE_ANALYZE_THEN_FINALIZE,
            stages=(
                OpenCodeExecutionStage(
                    name="analyzer",
                    thinking_mode="disabled",
                    reasoning_effort=None,
                    output_mode="text",
                    workspace_tools=True,
                ),
                OpenCodeExecutionStage(
                    name="finalizer",
                    thinking_mode="disabled",
                    reasoning_effort=None,
                    output_mode=OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
                    workspace_tools=False,
                ),
            ),
        )
    # Without workspace tools, DeepSeek V4 Flash is most reliable when the
    # complete bounded context is sent through one non-thinking StructuredOutput
    # turn. The former thinking explorer is retired even when its legacy setting
    # remains present.
    return OpenCodeExecutionProfile(
        name=OPENCODE_PROFILE_STRUCTURED_FINALIZER,
        output_mode=OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
        stages=(
            OpenCodeExecutionStage(
                name="finalizer",
                thinking_mode="disabled",
                reasoning_effort=None,
                output_mode=OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
                workspace_tools=False,
            ),
        ),
    )


def opencode_output_mode(
    model: str | None = None,
    *,
    phase: str | None = None,
    reasoning_effort: str = "high",
    enable_thinking_explorer: bool = False,
    enable_workspace_analyzer: bool = False,
) -> str:
    # ``model`` is retained for API compatibility, but execution semantics are
    # deliberately selected by phase rather than inferred from a model name.
    del model
    return opencode_execution_profile(
        phase,
        reasoning_effort=reasoning_effort,
        enable_thinking_explorer=enable_thinking_explorer,
        enable_workspace_analyzer=enable_workspace_analyzer,
    ).output_mode


def opencode_prompt_for_model(
    prompt: str,
    *,
    model: str,
    output_schema: dict[str, Any],
) -> str:
    # Compatibility wrapper for older audit readers. V4 output transport is now
    # selected explicitly and no model receives a schema pasted into its prompt.
    del model, output_schema
    return prompt


@dataclass(slots=True)
class OpenCodeRunResult:
    thread_id: str
    turn_id: str
    result: AgentInvestigationResult
    usage: dict[str, Any]
    output_transport: dict[str, Any]


class OpenCodeInvestigationError(RuntimeError):
    def __init__(self, message: str, *, audit_details: dict[str, Any] | None = None):
        super().__init__(message)
        self.audit_details = audit_details or {}


class OpenCodeInvestigator:
    name = "opencode"

    def __init__(self, settings: Settings):
        self.settings = settings
        self.worker_dir = settings.opencode_worker_dir or (
            Path(__file__).resolve().parents[2] / "opencode-worker"
        )
        self._deep_capability: dict[str, Any] | None = None
        self._capability_lock = threading.Lock()
        self._process_lock = threading.Lock()
        self._active_process_cleanups: dict[int, Callable[[], None]] = {}
        self._shutting_down = threading.Event()

    def capability(self, *, deep: bool = False) -> dict[str, Any]:
        personal_lab = self.settings.agent_permission_profile == "personal_lab"
        default_profile = opencode_execution_profile(
            "static_only",
            reasoning_effort=self.settings.opencode_reasoning_effort,
            enable_thinking_explorer=self.settings.opencode_thinking_explorer,
            enable_workspace_analyzer=personal_lab,
        )
        capability: dict[str, Any] = {
            "available": True,
            "version": OPENCODE_SDK_VERSION,
            "provider": OPENCODE_PROVIDER,
            "model": self.settings.opencode_model,
            "isolation": self.settings.opencode_isolation,
            "output_mode": default_profile.output_mode,
            "execution_profile": default_profile.as_payload(),
            "execution_profiles": [
                OPENCODE_PROFILE_STABLE_ANALYZER,
                OPENCODE_PROFILE_STRUCTURED_FINALIZER,
            ],
            "thinking_explorer_retired": True,
            "tool_profile": OPENCODE_TOOL_PROFILE,
            "workspace_tools": list(OPENCODE_WORKSPACE_TOOLS),
            "max_steps": None,
            "max_provider_requests": None,
        }
        detail = self._configuration_error()
        if detail:
            return {**capability, "available": False, "detail": detail}
        if self.settings.opencode_isolation == "docker":
            capability = self._docker_capability(capability)
        else:
            capability = self._host_capability(capability)
        if not deep or not capability.get("available"):
            return capability
        with self._capability_lock:
            if self._deep_capability is not None:
                return dict(self._deep_capability)
            try:
                probe = self._invoke(
                    {
                        "schema_version": "1.0",
                        "action": "capability",
                        "model": self.settings.opencode_model,
                        "base_url": self.settings.deepseek_base_url,
                        "timeout_ms": 30_000,
                        "live_probe": True,
                        "tool_profile": OPENCODE_TOOL_PROFILE,
                        "execution_profile": default_profile.as_payload(),
                        "max_agent_steps": self.settings.opencode_agent_steps,
                    },
                    timeout_seconds=45,
                )
                models = [str(item) for item in probe.get("models", [])]
                capability["server_version"] = str(probe.get("server_version", ""))
                capability["models"] = models
                capability["output_mode"] = str(
                    probe.get(
                        "output_mode",
                        default_profile.output_mode,
                    )
                )
                live_probe = probe.get("live_probe")
                if not isinstance(live_probe, dict) or live_probe.get("ok") is not True:
                    capability["available"] = False
                    capability["detail"] = "OpenCode live DeepSeek probe did not complete"
                else:
                    capability["live_probe"] = live_probe
                capability["tool_profile"] = str(
                    probe.get("tool_profile", OPENCODE_TOOL_PROFILE)
                )
                capability["workspace_tools"] = [
                    str(item)
                    for item in probe.get("workspace_tools", OPENCODE_WORKSPACE_TOOLS)
                ]
                capability["max_steps"] = probe.get("max_steps")
                capability["max_provider_requests"] = probe.get(
                    "max_provider_requests"
                )
                if (
                    capability.get("available")
                    and self.settings.opencode_model not in models
                ):
                    capability["available"] = False
                    capability["detail"] = (
                        f"DeepSeek model {self.settings.opencode_model!r} is not exposed by OpenCode"
                    )
            except Exception as exc:
                capability["available"] = False
                capability["detail"] = f"OpenCode capability probe failed: {exc}"
            if capability.get("available"):
                self._deep_capability = dict(capability)
        return capability

    def investigate(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        workspace: Path,
        evidence: list[dict[str, Any]],
        platform_context: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> OpenCodeRunResult:
        if not workspace.is_dir():
            raise ValueError("scan workspace is unavailable")
        capability = self.capability(deep=False)
        if not capability.get("available"):
            raise RuntimeError(str(capability.get("detail")))
        # OpenCode analysis is deliberately not assigned a wall-clock deadline.
        # The caller can still stop it through cancel_event or scanner shutdown.
        timeout = None
        context = platform_context or {}
        phase = str(context.get("phase") or "static_only")
        execution_profile = opencode_execution_profile(
            phase,
            reasoning_effort=self.settings.opencode_reasoning_effort,
            enable_thinking_explorer=self.settings.opencode_thinking_explorer,
            enable_workspace_analyzer=(
                self.settings.agent_permission_profile == "personal_lab"
            ),
        )
        workspace_tools_enabled = any(
            stage.workspace_tools for stage in execution_profile.stages
        )
        prompt = investigation_prompt(
            scan,
            task,
            entries,
            evidence,
            context,
            direct_tool_access=workspace_tools_enabled,
            shell_access=workspace_tools_enabled,
            workspace_write=workspace_tools_enabled,
            adb_access=(
                self.settings.agent_permission_profile == "personal_lab"
                and self.settings.opencode_isolation == "host"
                and bool(self.settings.adb_serial)
            ),
            network_access=self.settings.agent_permission_profile == "personal_lab",
            response_contract="structured_result",
        )
        instructions = developer_instructions(
            direct_tool_access=workspace_tools_enabled,
            shell_access=workspace_tools_enabled,
            workspace_write=workspace_tools_enabled,
            adb_access=(
                self.settings.agent_permission_profile == "personal_lab"
                and self.settings.opencode_isolation == "host"
                and bool(self.settings.adb_serial)
            ),
            network_access=self.settings.agent_permission_profile == "personal_lab",
            response_contract="structured_result",
        )
        scan_workspace = (self.settings.data_dir / "workspaces" / scan.id).resolve()
        shared_names = [
            name
            for name in ("jadx", "apktool", "archive")
            if (scan_workspace / name).is_dir()
        ]
        if self.settings.opencode_isolation == "docker":
            external_read_roots = [f"/scan-workspace/{name}" for name in shared_names]
        else:
            external_read_roots = [
                str((scan_workspace / name).resolve()) for name in shared_names
            ]
        payload = {
            "schema_version": "1.0",
            "action": "investigate",
            "prompt": prompt,
            "developer_instructions": instructions,
            "model": self.settings.opencode_model,
            "base_url": self.settings.deepseek_base_url,
            "phase": phase,
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
            "tool_profile": OPENCODE_TOOL_PROFILE,
            "execution_profile": execution_profile.as_payload(),
            "max_agent_steps": None,
            "permission_profile": self.settings.agent_permission_profile,
            "allow_adb": (
                self.settings.agent_permission_profile == "personal_lab"
                and self.settings.opencode_isolation == "host"
                and bool(self.settings.adb_serial)
            ),
            "allow_network": self.settings.agent_permission_profile == "personal_lab",
            "external_read_roots": external_read_roots,
            "_readonly_mounts": [
                {
                    "source": str((scan_workspace / name).resolve()),
                    "target": f"/scan-workspace/{name}",
                }
                for name in shared_names
            ],
            "timeout_ms": None,
            "allowed_hypothesis_ids": sorted(
                str(item["id"])
                for item in context.get("security_hypotheses", [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ),
            "require_hypothesis_receipts": phase != "adversarial_review",
            "allowed_entry_point_ids": sorted(
                {
                    entry.id for entry in entries
                }
                | {
                    str(entry_id)
                    for entry_id in (
                        (context.get("entry_scope") or {}).get(
                            "direct_test_entry_point_ids",
                            [],
                        )
                        if isinstance(context.get("entry_scope"), dict)
                        else []
                    )
                    if isinstance(entry_id, str)
                }
            ),
            "allowed_evidence_ids": sorted(
                str(item["id"])
                for item in evidence
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ),
        }
        if workspace_tools_enabled:
            payload["explorer_prompt"] = investigation_prompt(
                scan,
                task,
                entries,
                evidence,
                context,
                direct_tool_access=True,
                shell_access=True,
                workspace_write=True,
                adb_access=bool(payload["allow_adb"]),
                network_access=bool(payload["allow_network"]),
                response_contract="analysis_memo",
            )
            payload["explorer_instructions"] = developer_instructions(
                direct_tool_access=True,
                shell_access=True,
                workspace_write=True,
                adb_access=bool(payload["allow_adb"]),
                network_access=bool(payload["allow_network"]),
                response_contract="analysis_memo",
            )
        response = self._invoke_investigation_with_retry(
            payload,
            timeout_seconds=timeout,
            workspace=workspace,
            event_callback=event_callback,
            cancel_event=cancel_event,
        )
        if response.get("error"):
            error = response["error"]
            message = (
                str(error.get("message", "OpenCode investigation failed"))
                if isinstance(error, dict)
                else str(error)
            )
            raise OpenCodeInvestigationError(
                message,
                audit_details={
                    "worker_error": error,
                    "output_transport": response.get("output_transport") or {},
                    "thread_id": response.get("thread_id"),
                    "turn_id": response.get("turn_id"),
                    "usage": response.get("usage") or {},
                },
            )
        return OpenCodeRunResult(
            thread_id=str(response["thread_id"]),
            turn_id=str(response["turn_id"]),
            result=AgentInvestigationResult.model_validate(response["result"]),
            usage=dict(response.get("usage") or {}),
            output_transport=dict(response.get("output_transport") or {}),
        )

    def _invoke_investigation_with_retry(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: int | None,
        workspace: Path,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
        transport_attempt = 1
        retry_history: list[dict[str, Any]] = []
        while True:
            attempt_payload = {
                **payload,
                "timeout_ms": None,
            }
            try:
                if event_callback is None and cancel_event is None:
                    response = self._invoke(
                        attempt_payload,
                        timeout_seconds=None,
                        workspace=workspace,
                    )
                else:
                    response = self._invoke(
                        attempt_payload,
                        timeout_seconds=None,
                        workspace=workspace,
                        event_callback=event_callback,
                        cancel_event=cancel_event,
                    )
            except (AgentCancelledError, TimeoutError):
                raise
            except RuntimeError as exc:
                if (
                    transport_attempt >= 2
                    or not self._retryable_transport_failure(exc)
                ):
                    raise
                retry_history.append(
                    {
                        "attempt": transport_attempt,
                        "kind": "worker_transport_exception",
                        "error": str(exc)[:4000],
                    }
                )
                transport_attempt += 1
                with suppress(Exception):
                    emit_agent_event(
                        event_callback,
                        "model.worker.retry",
                        "OpenCode 本地 Server 连接中断，正在用剩余任务预算重建会话",
                        {
                            "attempt": transport_attempt,
                            "remaining_seconds": None,
                            "error": str(exc)[:1000],
                        },
                    )
                continue

            if (
                response.get("error")
                and transport_attempt < 2
                and self._retryable_worker_response(response)
            ):
                retry_history.append(
                    {
                        "attempt": transport_attempt,
                        "kind": "retryable_worker_response",
                        "error": response.get("error"),
                        "thread_id": response.get("thread_id"),
                        "turn_id": response.get("turn_id"),
                        "usage": response.get("usage") or {},
                        "output_transport": response.get("output_transport") or {},
                    }
                )
                transport_attempt += 1
                with suppress(Exception):
                    emit_agent_event(
                        event_callback,
                        "model.worker.retry",
                        "DeepSeek 可重试调用失败，正在用剩余任务预算重建会话",
                        {
                            "attempt": transport_attempt,
                            "remaining_seconds": None,
                            "error": response.get("error"),
                        },
                    )
                continue

            transport = dict(response.get("output_transport") or {})
            transport["worker_transport_attempts"] = transport_attempt
            if retry_history:
                transport["worker_retry_history"] = retry_history
            response["output_transport"] = transport
            return response

    @staticmethod
    def _retryable_transport_failure(error: RuntimeError) -> bool:
        message = str(error).lower()
        return any(
            marker in message
            for marker in (
                "typeerror: fetch failed",
                "econnrefused",
                "econnreset",
                "epipe",
                "und_err_connect_timeout",
                "und_err_headers_timeout",
                "und_err_socket",
            )
        )

    @classmethod
    def _retryable_worker_response(cls, response: dict[str, Any]) -> bool:
        error = response.get("error")
        if isinstance(error, dict):
            if error.get("retryable") is True:
                return True
            if error.get("type") in {
                "provider_unavailable",
                "provider_proxy_error",
                "transport_error",
            }:
                return True
            message = str(error.get("message") or "")
        else:
            message = str(error or "")
        return cls._retryable_transport_failure(RuntimeError(message))

    def _configuration_error(self) -> str | None:
        if self.settings.agent_permission_profile not in {"strict", "personal_lab"}:
            return (
                "APKSCANNER_AGENT_PERMISSION_PROFILE must be strict or personal_lab"
            )
        if self.settings.opencode_isolation not in {"host", "docker"}:
            return "APKSCANNER_OPENCODE_ISOLATION must be host or docker"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.settings.opencode_model):
            return "APKSCANNER_OPENCODE_MODEL contains unsupported characters"
        if self.settings.opencode_model.lower() in {
            "deepseek-chat",
            "deepseek-reasoner",
        }:
            return (
                "deepseek-chat and deepseek-reasoner are retired; use "
                "deepseek-v4-flash"
            )
        if self.settings.opencode_model.lower() == "deepseek-v4-pro":
            return (
                "deepseek-v4-pro exposes text-only output and cannot satisfy the scanner's "
                "required StructuredOutput contract; use deepseek-v4-flash"
            )
        if self.settings.opencode_reasoning_effort not in {"high", "max"}:
            return "APKSCANNER_OPENCODE_REASONING_EFFORT must be high or max"
        if self.settings.deepseek_base_url:
            parsed = urlsplit(self.settings.deepseek_base_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                return (
                    "APKSCANNER_DEEPSEEK_BASE_URL must be an HTTP(S) URL without credentials, "
                    "query parameters, or fragments"
                )
            if parsed.scheme == "http" and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                return "plain HTTP DeepSeek gateways are allowed only on loopback"
            if (
                parsed.hostname in {"api.deepseek.com", "api.deepseek.com.cn"}
                and parsed.path.rstrip("/") not in {"", "/"}
            ):
                return (
                    "the official DeepSeek base URL must not append /v1 or another path; "
                    "use https://api.deepseek.com"
                )
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key or not api_key.strip():
            return "DEEPSEEK_API_KEY is not configured"
        return None

    def _host_capability(self, capability: dict[str, Any]) -> dict[str, Any]:
        node = self.settings.opencode_node_bin or shutil.which("node")
        if node is None:
            return {
                **capability,
                "available": False,
                "detail": "Node.js 22 or newer is required for the OpenCode worker",
            }
        try:
            node_version = subprocess.run(
                [node, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {
                **capability,
                "available": False,
                "detail": "Node.js 22 or newer is required for the OpenCode worker",
            }
        match = re.fullmatch(
            r"v?(?P<major>\d+)(?:\.\d+){0,2}", node_version.stdout.strip()
        )
        if node_version.returncode != 0 or match is None or int(match.group("major")) < 22:
            return {
                **capability,
                "available": False,
                "detail": "Node.js 22 or newer is required for the OpenCode worker",
            }
        worker = self.worker_dir / "worker.mjs"
        if not worker.is_file():
            return {
                **capability,
                "available": False,
                "detail": f"OpenCode worker is missing: {worker}",
            }
        sdk_version = self._installed_package_version("@opencode-ai/sdk")
        cli_version = self._installed_package_version("opencode-ai")
        ajv_version = self._installed_package_version("ajv")
        if (
            sdk_version != OPENCODE_SDK_VERSION
            or cli_version != OPENCODE_CLI_VERSION
            or ajv_version != AJV_VERSION
        ):
            return {
                **capability,
                "available": False,
                "detail": (
                    f"run npm ci --prefix {self.worker_dir}; expected SDK/CLI/Ajv "
                    f"{OPENCODE_SDK_VERSION}/{OPENCODE_CLI_VERSION}/{AJV_VERSION}, found "
                    f"{sdk_version or 'missing'}/{cli_version or 'missing'}/"
                    f"{ajv_version or 'missing'}"
                ),
            }
        opencode_bin = self.worker_dir / "node_modules" / ".bin" / "opencode"
        if not opencode_bin.is_file() or not os.access(opencode_bin, os.X_OK):
            return {
                **capability,
                "available": False,
                "detail": "the pinned OpenCode CLI executable is missing or not executable",
            }
        for helper in ("adb", "bash"):
            helper_path = self.worker_dir / "bin" / helper
            if not helper_path.is_file() or not os.access(helper_path, os.X_OK):
                return {
                    **capability,
                    "available": False,
                    "detail": (
                        f"the OpenCode {helper} boundary helper is missing or not executable: "
                        f"{helper_path}"
                    ),
                }
        return capability

    def _docker_capability(self, capability: dict[str, Any]) -> dict[str, Any]:
        executable = shutil.which("docker")
        if executable is None:
            return {
                **capability,
                "available": False,
                "detail": "Docker isolation was requested but docker is not installed",
            }
        image = self.settings.opencode_docker_image
        if not image or not re.fullmatch(r"[A-Za-z0-9_./:@-]+", image):
            return {
                **capability,
                "available": False,
                "detail": "APKSCANNER_OPENCODE_DOCKER_IMAGE is invalid",
            }
        try:
            inspected = subprocess.run(
                [
                    executable,
                    "image",
                    "inspect",
                    "--format",
                    (
                        '{{ index .Config.Labels "io.apkscanner.opencode-sdk-version" }}'
                        '|{{ index .Config.Labels "io.apkscanner.opencode-version" }}'
                        '|{{ index .Config.Labels "io.apkscanner.ajv-version" }}'
                        '|{{ index .Config.Labels "io.apkscanner.worker-protocol" }}'
                    ),
                    image,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {**capability, "available": False, "detail": f"Docker probe failed: {exc}"}
        if inspected.returncode != 0:
            return {
                **capability,
                "available": False,
                "detail": f"build the OpenCode worker image first: {image}",
            }
        expected = (
            f"{OPENCODE_SDK_VERSION}|{OPENCODE_CLI_VERSION}|{AJV_VERSION}|"
            f"{OPENCODE_WORKER_PROTOCOL_VERSION}"
        )
        if inspected.stdout.strip() != expected:
            return {
                **capability,
                "available": False,
                "detail": "OpenCode worker image is stale or has incompatible SDK/CLI labels",
            }
        return capability

    def _installed_package_version(self, package: str) -> str | None:
        package_path = self.worker_dir / "node_modules"
        for part in package.split("/"):
            package_path /= part
        package_path /= "package.json"
        try:
            value = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        version = value.get("version")
        return str(version) if version else None

    def _invoke(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: int | None,
        workspace: Path | None = None,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        if self._shutting_down.is_set():
            raise AgentCancelledError("OpenCode investigator is shutting down")
        worker_payload = self._worker_payload(payload)
        if self.settings.opencode_isolation == "docker":
            return self._invoke_docker(
                worker_payload,
                timeout_seconds=timeout_seconds,
                workspace=workspace,
                event_callback=event_callback,
                cancel_event=cancel_event,
            )
        return self._invoke_host(
            worker_payload,
            timeout_seconds=timeout_seconds,
            workspace=workspace,
            event_callback=event_callback,
            cancel_event=cancel_event,
        )

    @staticmethod
    def _worker_payload(payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key or not api_key.strip():
            raise RuntimeError("DEEPSEEK_API_KEY is not configured")
        # The worker must not inherit the provider credential in its initial
        # environment: deleting an environment variable after process startup
        # does not remove it from /proc/<pid>/environ. The one-shot stdin pipe
        # is consumed and closed before any workspace tool is made available.
        return {
            **payload,
            OPENCODE_PROVIDER_KEY_FIELD: api_key,
        }

    def _invoke_host(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: int | None,
        workspace: Path | None,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
        payload.pop("_readonly_mounts", None)
        node = self.settings.opencode_node_bin or shutil.which("node")
        if node is None:
            raise RuntimeError("Node.js is not installed")
        worker = self.worker_dir / "worker.mjs"
        with tempfile.TemporaryDirectory(prefix="apkscanner-opencode-") as temporary:
            root = Path(temporary)
            env = self._worker_environment(
                root,
                allow_adb=bool(payload.get("allow_adb")),
            )
            cwd = workspace.resolve() if workspace is not None else root
            if workspace is not None and not cwd.is_dir():
                raise ValueError("scan workspace is unavailable")
            process = subprocess.Popen(
                [node, str(worker)],
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self._register_process(
                process,
                lambda: self._kill_process_group(process),
            )
            try:
                try:
                    response, _stderr = consume_worker_process(
                        process,
                        payload=payload,
                        timeout_seconds=timeout_seconds,
                        event_callback=event_callback,
                        on_timeout=lambda: self._kill_process_group(process),
                        cancel_event=cancel_event,
                        on_cancel=lambda: self._kill_process_group(process),
                    )
                except WorkerCancelledError as exc:
                    raise AgentCancelledError(
                        "OpenCode investigation was cancelled by the user"
                    ) from exc
                except WorkerTimeoutError as exc:
                    raise TimeoutError(
                        "OpenCode investigation exceeded its worker deadline"
                    ) from exc
                except RuntimeError as exc:
                    raise RuntimeError(f"OpenCode worker failed: {exc}") from exc
            finally:
                self._kill_process_group(process)
                self._unregister_process(process)
        return response

    def _worker_environment(self, root: Path, *, allow_adb: bool = False) -> dict[str, str]:
        allowed = {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "all_proxy",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
        }
        env = {key: value for key, value in os.environ.items() if key in allowed}
        bin_dir = self.worker_dir / "node_modules" / ".bin"
        blocker_dir = self.worker_dir / "bin"
        env["PATH"] = os.pathsep.join(
            value
            for value in (
                None if allow_adb else str(blocker_dir),
                str(bin_dir),
                os.environ.get("PATH"),
            )
            if value
        )
        env.update(
            {
                "HOME": str(root / "home"),
                "XDG_DATA_HOME": str(root / "data"),
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_CACHE_HOME": str(root / "cache"),
                "XDG_STATE_HOME": str(root / "state"),
                "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                "OPENCODE_DISABLE_CLAUDE_CODE": "1",
                "OPENCODE_DISABLE_MODELS_FETCH": "1",
                "OPENCODE_DISABLE_AUTOUPDATE": "1",
                "OPENCODE_PURE": "1",
            }
        )
        return env

    def _invoke_docker(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: int | None,
        workspace: Path | None,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
        readonly_mounts = payload.pop("_readonly_mounts", [])
        executable = shutil.which("docker")
        if executable is None:
            raise RuntimeError("Docker is not installed")
        safe_action = re.sub(r"[^a-z0-9-]", "-", str(payload.get("action", "run")).lower())[:24]
        container_name = f"apk-scanner-opencode-{safe_action}-{uuid.uuid4().hex[:8]}"
        worker_uid = os.getuid() if hasattr(os, "getuid") else 1000
        worker_gid = os.getgid() if hasattr(os, "getgid") else 1000
        command = [
            executable,
            "run",
            "--rm",
            "--name",
            container_name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=3g",
            "--cpus=2",
            "--network=bridge",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "--env",
            "HOME=/tmp/opencode-home",
            "--env",
            "XDG_DATA_HOME=/tmp/opencode-home/data",
            "--env",
            "XDG_CONFIG_HOME=/tmp/opencode-home/config",
            "--env",
            "XDG_CACHE_HOME=/tmp/opencode-home/cache",
            "--env",
            "XDG_STATE_HOME=/tmp/opencode-home/state",
        ]
        if worker_uid != 0:
            command.extend(["--user", f"{worker_uid}:{worker_gid}"])
        if workspace is not None:
            resolved_workspace = workspace.resolve()
            if not resolved_workspace.is_dir() or "," in str(resolved_workspace):
                raise ValueError(
                    "scan workspace is unavailable or unsafe for a Docker bind mount"
                )
            if worker_uid == 0:
                self._prepare_root_owned_docker_workspace(resolved_workspace)
            command.extend(
                [
                    "--mount",
                    f"type=bind,source={resolved_workspace},target=/workspace",
                    "--workdir",
                    "/workspace",
                ]
            )
        else:
            command.extend(["--workdir", "/sandbox"])
        for mount in readonly_mounts:
            if not isinstance(mount, dict):
                continue
            source = Path(str(mount.get("source", ""))).resolve()
            target = str(mount.get("target", ""))
            if (
                not source.is_dir()
                or "," in str(source)
                or not re.fullmatch(r"/scan-workspace/[A-Za-z0-9_.-]+", target)
            ):
                raise ValueError("read-only scan workspace mount is unsafe")
            command.extend(
                [
                    "--mount",
                    f"type=bind,source={source},target={target},readonly",
                ]
            )
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "all_proxy",
        ):
            if os.getenv(name):
                command.extend(["--env", name])
        command.append(self.settings.opencode_docker_image)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

        def stop_container() -> None:
            self._kill_process_group(process)
            subprocess.run(
                [executable, "rm", "-f", container_name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=20,
                check=False,
            )

        self._register_process(process, stop_container)
        try:
            try:
                response, _stderr = consume_worker_process(
                    process,
                    payload=payload,
                    timeout_seconds=timeout_seconds,
                    event_callback=event_callback,
                    on_timeout=stop_container,
                    cancel_event=cancel_event,
                    on_cancel=stop_container,
                    on_error_cleanup=stop_container,
                )
            except WorkerCancelledError as exc:
                raise AgentCancelledError(
                    "containerized OpenCode investigation was cancelled by the user"
                ) from exc
            except WorkerTimeoutError as exc:
                raise TimeoutError(
                    "containerized OpenCode investigation exceeded its worker deadline"
                ) from exc
            except RuntimeError as exc:
                raise RuntimeError(f"containerized OpenCode worker failed: {exc}") from exc
        finally:
            self._unregister_process(process)
        return response

    def _register_process(
        self,
        process: subprocess.Popen[str],
        cleanup: Callable[[], None],
    ) -> None:
        with self._process_lock:
            if self._shutting_down.is_set():
                cleanup()
                raise AgentCancelledError("OpenCode investigator is shutting down")
            self._active_process_cleanups[process.pid] = cleanup

    def _unregister_process(self, process: subprocess.Popen[str]) -> None:
        with self._process_lock:
            self._active_process_cleanups.pop(process.pid, None)

    def shutdown(self) -> None:
        """Terminate worker process groups, including capability probes."""
        self._shutting_down.set()
        with self._process_lock:
            cleanups = list(self._active_process_cleanups.values())
        for cleanup in cleanups:
            with suppress(Exception):
                cleanup()

    @staticmethod
    def _prepare_root_owned_docker_workspace(workspace: Path) -> None:
        """Give the image's non-root node user access to its isolated workspace copy."""
        for candidate in (workspace, *workspace.rglob("*")):
            if candidate.is_symlink():
                raise ValueError("scan workspace must not contain symbolic links")
            os.chown(candidate, 1000, 1000, follow_symlinks=False)

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[str]) -> None:
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            return
        if process.poll() is None:
            process.kill()

    @staticmethod
    def _parse_worker_response(stdout: str) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        for raw in stdout.splitlines() or [stdout]:
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError("OpenCode worker returned invalid JSON") from exc
            if not isinstance(value, dict):
                raise RuntimeError("OpenCode worker returned a non-object response")
            if value.get("type") == "event":
                continue
            if value.get("type") == "result":
                candidate = value.get("result")
                if not isinstance(candidate, dict):
                    raise RuntimeError("OpenCode worker returned an invalid result envelope")
                result = candidate
            else:
                result = value
        if result is None:
            raise RuntimeError("OpenCode worker returned no result")
        return result
