from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent_events import (
    AgentCancelledError,
    AgentEventCallback,
    emit_agent_event,
    normalize_codex_notification,
)
from .agent_prompt import developer_instructions, investigation_prompt
from .config import Settings
from .models import EntryPoint, InvestigationTask, Scan
from .schemas import AGENT_RESULT_JSON_SCHEMA, AgentInvestigationResult
from .worker_protocol import (
    WorkerCancelledError,
    WorkerTimeoutError,
    consume_worker_process,
)


@dataclass(slots=True)
class CodexRunResult:
    thread_id: str
    turn_id: str
    result: AgentInvestigationResult
    usage: dict[str, Any]


class CodexInvestigator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._deep_capability: dict[str, Any] | None = None

    def capability(self, *, deep: bool = False) -> dict[str, Any]:
        try:
            version = importlib.metadata.version("openai-codex")
        except importlib.metadata.PackageNotFoundError:
            return {"available": False, "detail": "openai-codex==0.144.4 is not installed"}
        capability: dict[str, Any] = {"available": True, "version": version}
        if version != "0.144.4":
            capability["available"] = False
            capability["detail"] = f"expected 0.144.4, found {version}"
            return capability
        capability["isolation"] = self.settings.codex_isolation
        if self.settings.codex_isolation not in {"host", "docker"}:
            capability["available"] = False
            capability["detail"] = "APKSCANNER_CODEX_ISOLATION must be host or docker"
            return capability
        if self.settings.codex_isolation == "docker":
            return self._docker_capability(capability)
        if deep:
            if self._deep_capability is not None:
                return dict(self._deep_capability)
            try:
                with self._client() as codex:
                    account = codex.account()
                    models = codex.models()
                    capability["account"] = account.model_dump(mode="json", exclude_none=True)
                    capability["model_count"] = len(models.data)
            except Exception as exc:  # external process/auth surface
                capability["available"] = False
                capability["detail"] = f"Codex capability probe failed: {exc}"
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
    ) -> CodexRunResult:
        from openai_codex import ApprovalMode, Sandbox
        from openai_codex.generated.v2_all import ReasoningEffort

        prompt = investigation_prompt(
            scan,
            task,
            entries,
            evidence,
            platform_context or {},
            direct_tool_access=True,
        )
        if self.settings.codex_isolation == "docker":
            return self._investigate_docker(
                prompt=prompt,
                task_id=task.id,
                workspace=workspace,
                timeout_seconds=timeout_seconds,
                event_callback=event_callback,
                cancel_event=cancel_event,
            )
        if cancel_event is not None and cancel_event.is_set():
            raise AgentCancelledError("Codex investigation was cancelled before dispatch")
        with self._client() as codex:
            thread = codex.thread_start(
                approval_mode=ApprovalMode.deny_all,
                cwd=str(workspace),
                developer_instructions=developer_instructions(direct_tool_access=True),
                ephemeral=False,
                model=self.settings.codex_worker_model,
                sandbox=Sandbox.read_only,
                service_name="apk-scanner",
            )
            emit_agent_event(
                event_callback,
                "model.session.started",
                "Codex SDK 会话已建立",
                {"thread_id": thread.id},
            )
            handle = thread.turn(
                prompt,
                approval_mode=ApprovalMode.deny_all,
                cwd=str(workspace),
                effort=ReasoningEffort.medium,
                model=self.settings.codex_worker_model,
                output_schema=AGENT_RESULT_JSON_SCHEMA,
                sandbox=Sandbox.read_only,
            )

            def consume_turn():  # noqa: ANN202
                from openai_codex.api import _collect_turn_result

                def stream():  # noqa: ANN202
                    for notification in handle.stream():
                        event = normalize_codex_notification(notification)
                        if event is not None and event_callback is not None:
                            with suppress(Exception):
                                event_callback(event)
                        yield notification

                return _collect_turn_result(stream(), turn_id=handle.id)

            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="codex-investigation")
            future = executor.submit(consume_turn)
            effective_timeout = (
                self.settings.task_timeout_seconds
                if timeout_seconds is None
                else timeout_seconds
            )
            deadline = time.monotonic() + effective_timeout
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    with suppress(Exception):
                        handle.interrupt()
                    emit_agent_event(
                        event_callback,
                        "model.turn.cancelled",
                        "Codex 本轮分析已收到停止请求",
                        {"thread_id": thread.id, "turn_id": handle.id},
                    )
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise AgentCancelledError(
                        "Codex investigation was cancelled by the user"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    with suppress(Exception):
                        handle.interrupt()
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise TimeoutError(
                        f"Codex investigation exceeded {timeout_seconds} seconds"
                    )
                try:
                    turn = future.result(timeout=min(0.25, remaining))
                    break
                except FutureTimeoutError:
                    continue
            executor.shutdown(wait=False, cancel_futures=True)
            parsed = self._parse_response(turn.final_response)
            emit_agent_event(
                event_callback,
                "model.output.validated",
                "Codex 结构化输出已通过本地校验",
                {"turn_id": turn.id},
            )
            usage = turn.usage.model_dump(mode="json") if turn.usage else {}
            return CodexRunResult(
                thread_id=thread.id,
                turn_id=turn.id,
                result=parsed,
                usage=usage,
            )

    def _docker_capability(self, capability: dict[str, Any]) -> dict[str, Any]:
        executable = shutil.which("docker")
        if executable is None:
            return {
                **capability,
                "available": False,
                "detail": "Docker isolation was requested but docker is not installed",
            }
        image = self.settings.codex_docker_image
        if not image or image.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_./:@-]+", image):
            return {
                **capability,
                "available": False,
                "detail": "APKSCANNER_CODEX_DOCKER_IMAGE is invalid",
            }
        try:
            inspected = subprocess.run(
                [
                    executable,
                    "image",
                    "inspect",
                    "--format",
                    (
                        '{{ index .Config.Labels "io.apkscanner.sdk-version" }}'
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
                "detail": f"build the worker image first: {image}",
            }
        if inspected.stdout.strip() != "0.144.4|2":
            return {
                **capability,
                "available": False,
                "detail": "worker image is stale or has an incompatible Codex SDK label",
            }
        auth_file = self.settings.codex_auth_file
        if auth_file is not None and not auth_file.is_file():
            return {
                **capability,
                "available": False,
                "detail": "APKSCANNER_CODEX_AUTH_FILE does not exist",
            }
        if auth_file is None and not os.getenv("OPENAI_API_KEY"):
            return {
                **capability,
                "available": False,
                "detail": "Docker mode requires APKSCANNER_CODEX_AUTH_FILE or OPENAI_API_KEY",
            }
        return capability

    def _investigate_docker(
        self,
        *,
        prompt: str,
        task_id: str,
        workspace: Path,
        timeout_seconds: int | None,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
    ) -> CodexRunResult:
        capability = self._docker_capability(
            {
                "available": True,
                "version": importlib.metadata.version("openai-codex"),
                "isolation": "docker",
            }
        )
        if not capability.get("available"):
            raise RuntimeError(str(capability.get("detail")))
        workspace = workspace.resolve()
        if not workspace.is_dir() or "," in str(workspace):
            raise ValueError("scan workspace is unavailable or unsafe for a Docker bind mount")
        executable = shutil.which("docker")
        assert executable is not None
        safe_task = re.sub(r"[^a-z0-9-]", "-", task_id.lower())[:36]
        container_name = f"apk-scanner-{safe_task}-{uuid.uuid4().hex[:8]}"
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
            "--memory=4g",
            "--cpus=2",
            "--network=bridge",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=512m",
            "--tmpfs",
            "/codex-home:rw,nosuid,nodev,size=256m",
            "--mount",
            f"type=bind,source={workspace},target=/workspace,readonly",
            "--workdir",
            "/workspace",
            "--env",
            "CODEX_HOME=/codex-home",
        ]
        auth_file = self.settings.codex_auth_file
        if auth_file is not None:
            if "," in str(auth_file):
                raise ValueError("Codex auth path is unsafe for a Docker bind mount")
            command.extend(
                [
                    "--mount",
                    f"type=bind,source={auth_file},target=/run/secrets/codex-auth,readonly",
                    "--env",
                    "APKSCANNER_CODEX_AUTH_FILE=/run/secrets/codex-auth",
                ]
            )
        if os.getenv("OPENAI_API_KEY"):
            command.extend(["--env", "OPENAI_API_KEY"])
        command.append(self.settings.codex_docker_image)
        payload = {
            "schema_version": "1.0",
            "prompt": prompt,
            "developer_instructions": developer_instructions(direct_tool_access=True),
            "model": self.settings.codex_worker_model,
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
        }
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
            result, _stderr = consume_worker_process(
                process,
                payload=payload,
                timeout_seconds=(
                    self.settings.task_timeout_seconds
                    if timeout_seconds is None
                    else timeout_seconds
                ),
                event_callback=event_callback,
                on_timeout=stop_container,
                cancel_event=cancel_event,
                on_cancel=stop_container,
            )
        except WorkerCancelledError as exc:
            raise AgentCancelledError(
                "containerized Codex investigation was cancelled by the user"
            ) from exc
        except WorkerTimeoutError as exc:
            raise TimeoutError(
                f"containerized Codex investigation exceeded {timeout_seconds} seconds"
            ) from exc
        except RuntimeError as exc:
            raise RuntimeError(f"containerized Codex worker failed: {exc}") from exc
        return CodexRunResult(
            thread_id=str(result["thread_id"]),
            turn_id=str(result["turn_id"]),
            result=AgentInvestigationResult.model_validate(result["result"]),
            usage=result.get("usage") or {},
        )

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, 9)
            return
        process.kill()

    def _client(self):  # noqa: ANN202
        from openai_codex import Codex, CodexConfig

        config = CodexConfig(
            codex_bin=self.settings.codex_bin,
            config_overrides=("agents.max_threads=1",),
        )
        return Codex(config=config)

    @staticmethod
    def _parse_response(response: str | None) -> AgentInvestigationResult:
        if not response:
            raise ValueError("Codex returned no final response")
        text = response.strip()
        fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
        if fence:
            text = fence.group(1)
        return AgentInvestigationResult.model_validate(json.loads(text))

    @staticmethod
    def _developer_instructions() -> str:
        return developer_instructions(direct_tool_access=True)

    @staticmethod
    def _prompt(
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        evidence: list[dict[str, Any]],
        platform_context: dict[str, Any],
    ) -> str:
        return investigation_prompt(
            scan,
            task,
            entries,
            evidence,
            platform_context,
            direct_tool_access=True,
        )
