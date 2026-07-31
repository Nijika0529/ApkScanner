from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import threading
import time
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
from .agent_workspace import AgentWorkspaceManager
from .codex_executor import CodexDockerExecutor
from .codex_protocol import (
    PersistentWorkerCancelled,
    PersistentWorkerClient,
    PersistentWorkerError,
    PersistentWorkerTimeout,
)
from .codex_sdk_baseline import PINNED_SDK_VERSION, runtime_capability
from .config import Settings
from .models import EntryPoint, InvestigationTask, Scan
from .schemas import AGENT_RESULT_JSON_SCHEMA, AgentInvestigationResult


@dataclass(slots=True)
class CodexRunResult:
    thread_id: str
    turn_id: str
    result: AgentInvestigationResult
    usage: dict[str, Any]


@dataclass(slots=True)
class _ActiveDockerSession:
    workspace: Any
    container: Any
    client: PersistentWorkerClient
    role: str


class CodexInvestigator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.workspaces = AgentWorkspaceManager(settings)
        self.executor = CodexDockerExecutor(settings)
        self._deep_capability: dict[str, Any] | None = None
        self._capability_lock = threading.Lock()
        self._session_lock = threading.RLock()
        self._sessions: dict[tuple[str, str, int, str], _ActiveDockerSession] = {}

    def capability(self, *, deep: bool = False) -> dict[str, Any]:
        capability = runtime_capability()
        if not capability.get("available"):
            return capability
        try:
            frozen = self.settings.frozen_agent_configuration()
        except ValueError as exc:
            return {**capability, "available": False, "detail": str(exc)}
        capability.update(
            {
                "provider": frozen.provider.provider,
                "model": frozen.provider.model,
                "reasoning_effort": frozen.provider.reasoning_effort,
                "credential_mode": "development_direct_env",
                "execution_profile": frozen.execution.id,
                "execution_profile_sha256": frozen.execution.fingerprint(),
                "provider_profile_sha256": frozen.provider.fingerprint(),
            }
        )
        if not self.settings.codex_model_catalog.is_file():
            return {
                **capability,
                "available": False,
                "detail": f"Codex model catalog is missing: {self.settings.codex_model_catalog}",
            }
        capability["isolation"] = self.settings.codex_isolation
        if self.settings.codex_isolation not in {"host", "docker"}:
            capability["available"] = False
            capability["detail"] = "APKSCANNER_CODEX_ISOLATION must be host or docker"
            return capability
        if self.settings.codex_isolation == "docker":
            return self._docker_capability(capability)
        if not self.settings.codex_allow_host:
            return {
                **capability,
                "available": False,
                "detail": "host Codex requires APKSCANNER_ALLOW_HOST_CODEX=true",
            }
        if deep:
            with self._capability_lock:
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
        gateway_environment: dict[str, str] | None = None,
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
                scan=scan,
                prompt=prompt,
                task=task,
                workspace=workspace,
                platform_context=platform_context or {},
                timeout_seconds=timeout_seconds,
                event_callback=event_callback,
                cancel_event=cancel_event,
                gateway_environment=gateway_environment,
            )
        if cancel_event is not None and cancel_event.is_set():
            raise AgentCancelledError("Codex investigation was cancelled before dispatch")
        with self._client() as codex:
            thread = codex.thread_start(
                approval_mode=ApprovalMode.deny_all,
                cwd=str(workspace),
                developer_instructions=developer_instructions(direct_tool_access=True),
                ephemeral=False,
                model=self.settings.codex_model,
                model_provider=self.settings.codex_provider,
                sandbox=Sandbox.full_access,
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
                effort=ReasoningEffort(self.settings.codex_reasoning_effort),
                model=self.settings.codex_model,
                output_schema=AGENT_RESULT_JSON_SCHEMA,
                sandbox=Sandbox.full_access,
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
                self.settings.task_timeout_seconds if timeout_seconds is None else timeout_seconds
            )
            effective_timeout = min(
                effective_timeout,
                self.settings.codex_turn_timeout_seconds,
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
                    raise AgentCancelledError("Codex investigation was cancelled by the user")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    with suppress(Exception):
                        handle.interrupt()
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise TimeoutError(f"Codex investigation exceeded {effective_timeout} seconds")
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
        if inspected.stdout.strip() != f"{PINNED_SDK_VERSION}|3":
            return {
                **capability,
                "available": False,
                "detail": "worker image is stale or has an incompatible Codex SDK label",
            }
        if not os.getenv("DEEPSEEK_API_KEY"):
            return {
                **capability,
                "available": False,
                "detail": "Docker mode requires DEEPSEEK_API_KEY in the host process environment",
            }
        return capability

    def _investigate_docker(
        self,
        *,
        scan: Scan,
        prompt: str,
        task: InvestigationTask,
        workspace: Path,
        platform_context: dict[str, Any],
        timeout_seconds: int | None,
        event_callback: AgentEventCallback | None,
        cancel_event: threading.Event | None,
        gateway_environment: dict[str, str] | None,
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
        scan_workspace = (self.settings.data_dir / "workspaces" / scan.id).resolve()
        if not scan_workspace.is_dir() or "," in str(scan_workspace):
            raise ValueError("scan decompiler workspace is unavailable or unsafe")
        phase = str(platform_context.get("phase") or "exploration_round")
        role = (
            "critic"
            if phase == "adversarial_review"
            else "rescue"
            if phase in {"rescue_review", "rescue_exploration"}
            else "primary"
        )
        active = self._prepare_active_session(
            scan=scan,
            task=task,
            source_workspace=workspace,
            phase=phase,
            role=role,
            scan_workspace=scan_workspace,
            gateway_environment=gateway_environment if role == "primary" else None,
        )
        effective_worker_timeout = min(
            (self.settings.task_timeout_seconds if timeout_seconds is None else timeout_seconds),
            self.settings.codex_turn_timeout_seconds,
        )
        try:
            result = active.client.turn(
                prompt=prompt,
                output_schema=AGENT_RESULT_JSON_SCHEMA,
                timeout_seconds=effective_worker_timeout,
                no_event_timeout_seconds=self.settings.codex_no_event_timeout_seconds,
                event_callback=event_callback,
                cancel_event=cancel_event,
            )
        except PersistentWorkerCancelled as exc:
            raise AgentCancelledError(
                "containerized Codex investigation was cancelled by the user"
            ) from exc
        except PersistentWorkerTimeout as exc:
            raise TimeoutError(
                f"containerized Codex investigation exceeded its timeout: {exc}"
            ) from exc
        except PersistentWorkerError as exc:
            self._discard_session(scan.id, task.id, task.attempts, role)
            raise RuntimeError(f"containerized Codex worker failed: {exc}") from exc
        return CodexRunResult(
            thread_id=str(result["thread_id"]),
            turn_id=str(result["turn_id"]),
            result=AgentInvestigationResult.model_validate(result["result"]),
            usage=result.get("usage") or {},
        )

    def prepare_session_workspace(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        workspace: Path,
        phase: str,
    ) -> Path:
        """Prepare and return the writable workspace used by a Docker Agent."""

        if self.settings.codex_isolation != "docker":
            return workspace
        role = self._role_for_phase(phase)
        session = self.workspaces.prepare_session(
            scan_id=scan.id,
            task_id=task.id,
            attempt=task.attempts,
            role=role,
            source_workspace=workspace,
            context={"phase": phase},
        )
        return session.workspace

    def _prepare_active_session(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        source_workspace: Path,
        phase: str,
        role: str,
        scan_workspace: Path,
        gateway_environment: dict[str, str] | None,
    ) -> _ActiveDockerSession:
        key = (scan.id, task.id, task.attempts, role)
        with self._session_lock:
            existing = self._sessions.get(key)
            if existing is not None and existing.client.process.poll() is None:
                self.workspaces.prepare_session(
                    scan_id=scan.id,
                    task_id=task.id,
                    attempt=task.attempts,
                    role=role,
                    source_workspace=source_workspace,
                    context={"phase": phase},
                )
                return existing
            if existing is not None:
                self._sessions.pop(key, None)
                existing.client.kill()
            sessions_root = self.workspaces.prepare_scan(scan.id)
            agent_session = self.workspaces.prepare_session(
                scan_id=scan.id,
                task_id=task.id,
                attempt=task.attempts,
                role=role,
                source_workspace=source_workspace,
                context={"phase": phase},
            )
            container = self.executor.ensure_scan_container(
                scan_id=scan.id,
                scan_workspace=scan_workspace,
                sessions_root=sessions_root,
                apk_path=Path(scan.artifact_path),
            )
            process = self.executor.start_worker(container=container, session=agent_session)

            def stop_session() -> None:
                self._kill_process_group(process)
                self.executor.kill_session(container, agent_session)

            session_id = f"{task.id}:a{task.attempts}:{role}"
            spool = (
                self.settings.data_dir
                / "runtime"
                / "events"
                / f"{agent_session.workspace_key}.ndjson"
            )
            client = PersistentWorkerClient(
                process,
                session_id=session_id,
                event_spool=spool,
                cleanup=stop_session,
            )
            configuration = {
                "developer_instructions": developer_instructions(direct_tool_access=True),
                "model": self.settings.codex_model,
                "model_provider": self.settings.codex_provider,
                "reasoning_effort": self.settings.codex_reasoning_effort,
                "provider_base_url": self.settings.deepseek_base_url,
                "model_catalog_path": "/opt/apk-scanner/config/deepseek-models.json",
                "workspace_path": agent_session.container_workspace,
            }
            thread_file = agent_session.root / "thread.json"
            resume_thread_id = self._read_thread_id(thread_file)
            try:
                thread_id = client.open_session(
                    configuration=configuration,
                    gateway_environment=gateway_environment,
                    resume_thread_id=resume_thread_id,
                )
            except Exception:
                client.kill()
                if resume_thread_id is None:
                    raise
                with suppress(OSError):
                    thread_file.unlink()
                process = self.executor.start_worker(
                    container=container,
                    session=agent_session,
                )

                def stop_replacement_session() -> None:
                    self._kill_process_group(process)
                    self.executor.kill_session(container, agent_session)

                client = PersistentWorkerClient(
                    process,
                    session_id=session_id,
                    event_spool=spool,
                    cleanup=stop_replacement_session,
                )
                try:
                    thread_id = client.open_session(
                        configuration=configuration,
                        gateway_environment=gateway_environment,
                    )
                except Exception:
                    client.kill()
                    raise
            thread_file.write_text(
                json.dumps({"schema_version": "1.0", "thread_id": thread_id}),
                encoding="utf-8",
            )
            thread_file.chmod(0o600)
            active = _ActiveDockerSession(agent_session, container, client, role)
            self._sessions[key] = active
            return active

    def _discard_session(self, scan_id: str, task_id: str, attempt: int, role: str) -> None:
        with self._session_lock:
            active = self._sessions.pop((scan_id, task_id, attempt, role), None)
        if active is not None:
            active.client.kill()

    @staticmethod
    def _read_thread_id(path: Path) -> str | None:
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            thread_id = value.get("thread_id") if isinstance(value, dict) else None
            return thread_id if isinstance(thread_id, str) and thread_id else None
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _role_for_phase(phase: str) -> str:
        return (
            "critic"
            if phase == "adversarial_review"
            else "rescue"
            if phase in {"rescue_review", "rescue_exploration"}
            else "primary"
        )

    def close_scan(self, scan_id: str) -> None:
        with self._session_lock:
            sessions = [
                self._sessions.pop(key) for key in list(self._sessions) if key[0] == scan_id
            ]
        for active in sessions:
            with suppress(Exception):
                active.client.close()
        self.executor.close_scan(scan_id)
        self.workspaces.forget_scan(scan_id)

    def close_task(self, scan_id: str, task_id: str) -> None:
        """Close all Agent roles owned by one terminal task and free its slots."""
        with self._session_lock:
            sessions = [
                self._sessions.pop(key)
                for key in list(self._sessions)
                if key[0] == scan_id and key[1] == task_id
            ]
        for active in sessions:
            with suppress(Exception):
                active.client.close()
        self.workspaces.forget_task(scan_id, task_id)

    def shutdown(self) -> None:
        with self._session_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for active in sessions:
            with suppress(Exception):
                active.client.close()
        self.executor.shutdown()

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
            config_overrides=codex_config_overrides(
                provider=self.settings.codex_provider,
                model=self.settings.codex_model,
                reasoning_effort=self.settings.codex_reasoning_effort,
                base_url=self.settings.deepseek_base_url,
                model_catalog_path=self.settings.codex_model_catalog,
                web_search=self.settings.codex_web_search,
            ),
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
        try:
            value = json.loads(text)
        except json.JSONDecodeError as direct_error:
            value = None
            decoder = json.JSONDecoder()
            # DeepSeek may prepend a short natural-language handoff despite a
            # Responses output schema. Accept only one complete trailing JSON
            # object; Pydantic still enforces the full closed business schema.
            for match in re.finditer(r"\{", text):
                try:
                    candidate, end = decoder.raw_decode(text, match.start())
                except json.JSONDecodeError:
                    continue
                if isinstance(candidate, dict) and text[end:].strip() in {"", "```"}:
                    value = candidate
                    break
            if value is None:
                raise ValueError(
                    "Codex final response did not contain a complete trailing JSON object"
                ) from direct_error
        return AgentInvestigationResult.model_validate(value)

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


def codex_config_overrides(
    *,
    provider: str,
    model: str,
    reasoning_effort: str,
    base_url: str,
    model_catalog_path: str | Path,
    web_search: str,
) -> tuple[str, ...]:
    value = json.dumps
    return (
        f"model={value(model)}",
        f"model_provider={value(provider)}",
        f"model_reasoning_effort={value(reasoning_effort)}",
        f"model_catalog_json={value(str(model_catalog_path))}",
        'preferred_auth_method="apikey"',
        'forced_login_method="api"',
        f"web_search={value(web_search)}",
        # Codex snapshots the worker's login-shell environment before applying
        # shell_environment_policy. Because the provider credential must remain
        # in the worker environment for Responses authentication, an enabled
        # snapshot would persist it under CODEX_HOME/shell_snapshots. Keep the
        # normal per-command environment filter and disable that persistence
        # feature for every ApkScanner session.
        "features.shell_snapshot=false",
        "project_root_markers=[]",
        "project_doc_max_bytes=0",
        "agents.max_threads=1",
        'history.persistence="save-all"',
        f"model_providers.{provider}.name={value(provider)}",
        f"model_providers.{provider}.base_url={value(base_url)}",
        f'model_providers.{provider}.wire_api="responses"',
        f'model_providers.{provider}.env_key="DEEPSEEK_API_KEY"',
        f"model_providers.{provider}.request_max_retries=2",
        f"model_providers.{provider}.stream_max_retries=2",
        f"model_providers.{provider}.stream_idle_timeout_ms=900000",
        'shell_environment_policy.inherit="core"',
        (
            "shell_environment_policy.include_only="
            '["^PATH$","^HOME$","^TMPDIR$","^LANG$","^LC_ALL$","^TERM$",'
            '"^ANDROID_SERIAL$","^APKSCANNER_ADB_.*$","^APKSCANNER_PROOF_.*$",'
            '"^HTTP_PROXY$","^HTTPS_PROXY$","^NO_PROXY$"]'
        ),
        (
            'shell_environment_policy.exclude=["^DEEPSEEK_API_KEY$",'
            '"^OPENAI_API_KEY$","^CODEX_API_KEY$"]'
        ),
    )
