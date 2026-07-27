from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
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
OPENCODE_PROVIDER = "deepseek"
OPENCODE_OUTPUT_MODE_PROMPTED_JSON = "prompted_json"
OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL = "structured_output_tool"
OPENCODE_TOOL_PROFILE = "workspace_shell"
OPENCODE_WORKSPACE_TOOLS = ("read", "glob", "grep", "bash")
OPENCODE_MAX_STEPS = 100


def opencode_output_mode(model: str) -> str:
    normalized = model.strip().lower()
    if re.fullmatch(r"deepseek-v4-pro(?:[-._].*)?", normalized):
        return OPENCODE_OUTPUT_MODE_PROMPTED_JSON
    return OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL


def opencode_prompt_for_model(
    prompt: str,
    *,
    model: str,
    output_schema: dict[str, Any],
) -> str:
    if opencode_output_mode(model) != OPENCODE_OUTPUT_MODE_PROMPTED_JSON:
        return prompt
    example = _json_schema_example(output_schema)
    return (
        f"{prompt}\n\n"
        "DEEPSEEK_THINKING_OUTPUT_ADAPTER:\n"
        "Use the permitted workspace tools as needed to investigate before answering. "
        "After tool exploration is complete, the final assistant answer must be exactly one "
        "JSON object as plain text, without Markdown fences or commentary. The object must "
        "validate against OUTPUT_JSON_SCHEMA. All required keys must be present and no "
        "undeclared top-level keys are allowed.\n\n"
        "OUTPUT_JSON_SCHEMA:\n"
        f"{json.dumps(output_schema, ensure_ascii=False, indent=2)}\n\n"
        "MINIMAL_JSON_EXAMPLE:\n"
        f"{json.dumps(example, ensure_ascii=False, indent=2)}"
    )


def _json_schema_example(schema: dict[str, Any]) -> Any:
    if "const" in schema:
        return schema["const"]
    if "default" in schema:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    variants = schema.get("anyOf") or schema.get("oneOf")
    if isinstance(variants, list):
        candidate = next(
            (
                item
                for item in variants
                if isinstance(item, dict) and item.get("type") != "null"
            ),
            variants[0] if variants else {},
        )
        return _json_schema_example(candidate) if isinstance(candidate, dict) else None
    schema_type = schema.get("type")
    if schema_type == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            return {}
        return {
            key: _json_schema_example(properties[key])
            for key in required
            if key in properties and isinstance(properties[key], dict)
        }
    if schema_type == "array":
        return []
    if schema_type == "string":
        return "string"
    if schema_type in {"integer", "number"}:
        return 0
    if schema_type == "boolean":
        return False
    return None


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

    def capability(self, *, deep: bool = False) -> dict[str, Any]:
        capability: dict[str, Any] = {
            "available": True,
            "version": OPENCODE_SDK_VERSION,
            "provider": OPENCODE_PROVIDER,
            "model": self.settings.opencode_model,
            "isolation": self.settings.opencode_isolation,
            "output_mode": opencode_output_mode(self.settings.opencode_model),
            "tool_profile": OPENCODE_TOOL_PROFILE,
            "workspace_tools": list(OPENCODE_WORKSPACE_TOOLS),
            "max_steps": OPENCODE_MAX_STEPS,
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
                },
                timeout_seconds=45,
            )
            models = [str(item) for item in probe.get("models", [])]
            capability["server_version"] = str(probe.get("server_version", ""))
            capability["models"] = models
            capability["output_mode"] = str(
                probe.get(
                    "output_mode",
                    opencode_output_mode(self.settings.opencode_model),
                )
            )
            capability["tool_profile"] = str(
                probe.get("tool_profile", OPENCODE_TOOL_PROFILE)
            )
            capability["workspace_tools"] = [
                str(item)
                for item in probe.get("workspace_tools", OPENCODE_WORKSPACE_TOOLS)
            ]
            capability["max_steps"] = int(
                probe.get("max_steps", OPENCODE_MAX_STEPS)
            )
            if self.settings.opencode_model not in models:
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
        timeout = (
            self.settings.task_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        payload = {
            "schema_version": "1.0",
            "action": "investigate",
            "prompt": opencode_prompt_for_model(
                investigation_prompt(
                    scan,
                    task,
                    entries,
                    evidence,
                    platform_context or {},
                    direct_tool_access=True,
                    shell_access=True,
                    workspace_write=True,
                ),
                model=self.settings.opencode_model,
                output_schema=AGENT_RESULT_JSON_SCHEMA,
            ),
            "developer_instructions": developer_instructions(
                direct_tool_access=True,
                shell_access=True,
                workspace_write=True,
            ),
            "model": self.settings.opencode_model,
            "base_url": self.settings.deepseek_base_url,
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
            "tool_profile": OPENCODE_TOOL_PROFILE,
            "timeout_ms": max(1, timeout) * 1000,
        }
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
        timeout_seconds: int,
        workspace: Path,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + max(timeout_seconds, 0)
        transport_attempt = 1
        attempt_timeout = max(timeout_seconds, 0)
        while True:
            attempt_payload = {
                **payload,
                "timeout_ms": max(1, attempt_timeout) * 1000,
            }
            try:
                if event_callback is None and cancel_event is None:
                    response = self._invoke(
                        attempt_payload,
                        timeout_seconds=attempt_timeout + 15,
                        workspace=workspace,
                    )
                else:
                    response = self._invoke(
                        attempt_payload,
                        timeout_seconds=attempt_timeout + 15,
                        workspace=workspace,
                        event_callback=event_callback,
                        cancel_event=cancel_event,
                    )
            except (AgentCancelledError, TimeoutError):
                raise
            except RuntimeError as exc:
                remaining = int(deadline - time.monotonic())
                if (
                    transport_attempt >= 2
                    or remaining <= 0
                    or not self._retryable_transport_failure(exc)
                ):
                    raise
                transport_attempt += 1
                attempt_timeout = remaining
                with suppress(Exception):
                    emit_agent_event(
                        event_callback,
                        "model.worker.retry",
                        "OpenCode 本地 Server 连接中断，正在用剩余任务预算重建会话",
                        {
                            "attempt": transport_attempt,
                            "remaining_seconds": remaining,
                            "error": str(exc)[:1000],
                        },
                    )
                continue

            transport = dict(response.get("output_transport") or {})
            transport["worker_transport_attempts"] = transport_attempt
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

    def _configuration_error(self) -> str | None:
        if self.settings.opencode_isolation not in {"host", "docker"}:
            return "APKSCANNER_OPENCODE_ISOLATION must be host or docker"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.settings.opencode_model):
            return "APKSCANNER_OPENCODE_MODEL contains unsupported characters"
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
        expected = f"{OPENCODE_SDK_VERSION}|{OPENCODE_CLI_VERSION}|{AJV_VERSION}|4"
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
        timeout_seconds: int,
        workspace: Path | None = None,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        if self.settings.opencode_isolation == "docker":
            return self._invoke_docker(
                payload,
                timeout_seconds=timeout_seconds,
                workspace=workspace,
                event_callback=event_callback,
                cancel_event=cancel_event,
            )
        return self._invoke_host(
            payload,
            timeout_seconds=timeout_seconds,
            workspace=workspace,
            event_callback=event_callback,
            cancel_event=cancel_event,
        )

    def _invoke_host(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: int,
        workspace: Path | None,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
        node = self.settings.opencode_node_bin or shutil.which("node")
        if node is None:
            raise RuntimeError("Node.js is not installed")
        worker = self.worker_dir / "worker.mjs"
        with tempfile.TemporaryDirectory(prefix="apkscanner-opencode-") as temporary:
            root = Path(temporary)
            env = self._worker_environment(root)
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
                    f"OpenCode investigation exceeded {timeout_seconds} seconds"
                ) from exc
            except RuntimeError as exc:
                raise RuntimeError(f"OpenCode worker failed: {exc}") from exc
        return response

    def _worker_environment(self, root: Path) -> dict[str, str]:
        allowed = {
            "DEEPSEEK_API_KEY",
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
        blocker_dir = self.worker_dir / "bin"
        bin_dir = self.worker_dir / "node_modules" / ".bin"
        env["PATH"] = os.pathsep.join(
            value
            for value in (str(blocker_dir), str(bin_dir), os.environ.get("PATH"))
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
        timeout_seconds: int,
        workspace: Path | None,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> dict[str, Any]:
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
            "--user",
            f"{worker_uid}:{worker_gid}",
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
            "--env",
            "DEEPSEEK_API_KEY",
        ]
        if workspace is not None:
            resolved_workspace = workspace.resolve()
            if not resolved_workspace.is_dir() or "," in str(resolved_workspace):
                raise ValueError(
                    "scan workspace is unavailable or unsafe for a Docker bind mount"
                )
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

        try:
            response, _stderr = consume_worker_process(
                process,
                payload=payload,
                timeout_seconds=timeout_seconds,
                event_callback=event_callback,
                on_timeout=stop_container,
                cancel_event=cancel_event,
                on_cancel=stop_container,
            )
        except WorkerCancelledError as exc:
            raise AgentCancelledError(
                "containerized OpenCode investigation was cancelled by the user"
            ) from exc
        except WorkerTimeoutError as exc:
            raise TimeoutError(
                f"containerized OpenCode investigation exceeded {timeout_seconds} seconds"
            ) from exc
        except RuntimeError as exc:
            raise RuntimeError(f"containerized OpenCode worker failed: {exc}") from exc
        return response

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            return
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
