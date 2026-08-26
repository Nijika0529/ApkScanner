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

from pydantic import ValidationError

from ..core.config import Settings
from ..core.models import EntryPoint, InvestigationTask, Scan
from ..core.schemas import (
    ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA,
    AGENT_RESULT_JSON_SCHEMA,
    AdaptiveVerificationResult,
    AgentInvestigationResult,
)
from ..platform.operator_schemas import OPERATOR_RECEIPT_JSON_SCHEMA, OperatorReceipt
from .agent_events import (
    AgentCancelledError,
    AgentEventCallback,
    emit_agent_event,
    normalize_codex_notification,
)
from .agent_prompt import (
    adaptive_verifier_developer_instructions,
    developer_instructions,
    investigation_prompt,
)
from .agent_workspace import AgentWorkspaceManager
from .codex_executor import CodexDockerExecutor
from .codex_protocol import (
    PersistentWorkerCancelled,
    PersistentWorkerClient,
    PersistentWorkerError,
    PersistentWorkerTimeout,
)
from .codex_sdk_baseline import PINNED_SDK_VERSION, WORKER_REVISION, runtime_capability


@dataclass(slots=True)
class CodexRunResult:
    thread_id: str
    turn_id: str
    result: AgentInvestigationResult
    usage: dict[str, Any]


@dataclass(slots=True)
class CodexAdaptiveRunResult:
    thread_id: str
    turn_id: str
    result: AdaptiveVerificationResult
    usage: dict[str, Any]


@dataclass(slots=True)
class CodexOperatorRunResult:
    thread_id: str
    turn_id: str
    result: OperatorReceipt
    usage: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _JsonObjectCandidate:
    value: dict[str, Any]
    start: int
    end: int


@dataclass(slots=True)
class _ActiveDockerSession:
    workspace: Any
    container: Any
    client: PersistentWorkerClient
    role: str
    last_used: float


class CodexInvestigator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.workspaces = AgentWorkspaceManager(settings)
        self.executor = CodexDockerExecutor(settings)
        self._deep_capability: dict[str, Any] | None = None
        self._capability_lock = threading.Lock()
        self._session_lock = threading.RLock()
        self._session_condition = threading.Condition(self._session_lock)
        self._sessions: dict[tuple[str, str, int, str], _ActiveDockerSession] = {}
        self._busy_sessions: set[tuple[str, str, int, str]] = set()

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
                        '|{{ index .Config.Labels "io.apkscanner.worker-revision" }}'
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
        if inspected.stdout.strip() != f"{PINNED_SDK_VERSION}|3|{WORKER_REVISION}":
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
            if phase == "rescue_review"
            else "rescue_explorer"
            if phase == "rescue_exploration"
            else "primary"
        )
        restricted_review = phase in {
            "adversarial_review",
            "rescue_review",
            "final_evaluation",
            "recovery_evaluation",
        }
        device = platform_context.get("device")
        proof_replay = platform_context.get("proof_replay")
        adb_access = bool(
            not restricted_review
            and isinstance(device, dict)
            and device.get("serial")
            and isinstance(proof_replay, dict)
            and proof_replay.get("available") is True
        )
        actual_developer_instructions = developer_instructions(
            direct_tool_access=True,
            shell_access=True,
            workspace_write=not restricted_review,
            adb_access=adb_access,
            network_access=(
                not restricted_review and self.settings.codex_shell_network == "public_egress"
            ),
        )
        active = self._prepare_active_session(
            scan=scan,
            task=task,
            source_workspace=workspace,
            phase=phase,
            role=role,
            scan_workspace=scan_workspace,
            gateway_environment=(
                gateway_environment if role in {"primary", "rescue_explorer"} else None
            ),
            cancel_event=cancel_event,
            developer_instructions_text=actual_developer_instructions,
        )
        session_key = (scan.id, task.id, task.attempts, role)
        effective_worker_timeout = min(
            (self.settings.task_timeout_seconds if timeout_seconds is None else timeout_seconds),
            self.settings.codex_turn_timeout_seconds,
        )
        try:
            result = active.client.turn(
                prompt=prompt,
                result_contract="agent_investigation.v1",
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
            # PersistentWorkerClient has already asked the SDK to interrupt, but
            # an interrupted session is not a reliable starting point for a
            # later corrective exploration turn. Match Adaptive Verifier's
            # timeout recovery and resume from the persisted thread context.
            self._discard_session(scan.id, task.id, task.attempts, role)
            raise TimeoutError(
                f"containerized Codex investigation exceeded its timeout: {exc}"
            ) from exc
        except PersistentWorkerError as exc:
            self._discard_session(scan.id, task.id, task.attempts, role)
            raise RuntimeError(f"containerized Codex worker failed: {exc}") from exc
        finally:
            self._release_active_session(session_key)
        parsed_result = AgentInvestigationResult.model_validate(result["result"])
        parsed_result.apply_model_validation_audit(result.get("model_validation"))
        return CodexRunResult(
            thread_id=str(result["thread_id"]),
            turn_id=str(result["turn_id"]),
            result=parsed_result,
            usage=result.get("usage") or {},
        )

    def verify_batch(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        workspace: Path,
        prompt: str,
        timeout_seconds: int,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
        gateway_environment: dict[str, str] | None = None,
    ) -> CodexAdaptiveRunResult:
        """Run one transport-budgeted batch in an Adaptive Verifier thread."""

        if self.settings.codex_isolation != "docker":
            raise RuntimeError("the Adaptive Verifier requires Docker isolation")
        if len(prompt) > self.settings.adaptive_verifier_prompt_max_chars:
            raise ValueError(
                "Adaptive Verifier prompt exceeds the configured transport-safe limit: "
                f"{len(prompt)} > {self.settings.adaptive_verifier_prompt_max_chars} characters"
            )
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
        ssh_source = self.settings.adaptive_verifier_ssh_source
        ssh_available = bool(
            self.settings.adaptive_verifier_copy_host_ssh
            and ssh_source is not None
            and ssh_source.is_dir()
        )
        role = "verifier"
        phase = "adaptive_verification"
        active = self._prepare_active_session(
            scan=scan,
            task=task,
            source_workspace=workspace,
            phase=phase,
            role=role,
            scan_workspace=scan_workspace,
            gateway_environment=gateway_environment,
            cancel_event=cancel_event,
            developer_instructions_text=adaptive_verifier_developer_instructions(
                ssh_available=ssh_available
            ),
        )
        session_key = (scan.id, task.id, task.attempts, role)
        effective_timeout = min(
            timeout_seconds,
            self.settings.adaptive_verifier_timeout_seconds,
            self.settings.codex_turn_timeout_seconds,
        )
        try:
            result = active.client.turn(
                prompt=prompt,
                output_schema=ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA,
                result_contract="json_object.v1",
                timeout_seconds=effective_timeout,
                no_event_timeout_seconds=self.settings.codex_no_event_timeout_seconds,
                event_callback=event_callback,
                cancel_event=cancel_event,
            )
        except PersistentWorkerCancelled as exc:
            raise AgentCancelledError("Adaptive Verifier was cancelled by the user") from exc
        except PersistentWorkerTimeout as exc:
            self._discard_session(scan.id, task.id, task.attempts, role)
            raise TimeoutError(f"Adaptive Verifier exceeded its timeout: {exc}") from exc
        except PersistentWorkerError as exc:
            self._discard_session(scan.id, task.id, task.attempts, role)
            raise RuntimeError(f"Adaptive Verifier worker failed: {exc}") from exc
        finally:
            self._release_active_session(session_key)
        return CodexAdaptiveRunResult(
            thread_id=str(result["thread_id"]),
            turn_id=str(result["turn_id"]),
            result=AdaptiveVerificationResult.model_validate(result["result"]),
            usage=result.get("usage") or {},
        )

    def operate(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        workspace: Path,
        prompt: str,
        timeout_seconds: int,
        event_callback: AgentEventCallback | None = None,
        cancel_event: threading.Event | None = None,
        gateway_environment: dict[str, str] | None = None,
    ) -> CodexOperatorRunResult:
        """Run or continue a privileged platform Operator conversation."""

        if self.settings.codex_isolation != "docker":
            raise RuntimeError("the Platform Operator requires Docker isolation")
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
        role = "operator"
        active = self._prepare_active_session(
            scan=scan,
            task=task,
            source_workspace=workspace,
            phase="platform_operator",
            role=role,
            scan_workspace=scan_workspace,
            gateway_environment=gateway_environment,
            cancel_event=cancel_event,
            developer_instructions_text=(
                "你是 APKScanner 平台级 Operator Agent。你可以读取当前扫描、Finding、Evidence、"
                "历史 Agent 工作区和 Artifact 索引，在自己的可写工作区使用 Bash、Web Search、"
                "Android SDK、ADB 与 SSH 完成用户明确要求的分析或复现。优先复用已有 PoC 和证据，"
                "设备命令必须通过任务级 adb 网关；不要清除或卸载待测应用的数据。把新产物放到 "
                "output/ 或 poc/。只报告实际完成的动作和观察，并严格按输出 schema 返回简洁中文回执。"
            ),
        )
        session_key = (scan.id, task.id, task.attempts, role)
        effective_timeout = min(timeout_seconds, self.settings.codex_turn_timeout_seconds)
        try:
            result = active.client.turn(
                prompt=prompt,
                output_schema=OPERATOR_RECEIPT_JSON_SCHEMA,
                result_contract="json_object.v1",
                timeout_seconds=effective_timeout,
                no_event_timeout_seconds=self.settings.codex_no_event_timeout_seconds,
                event_callback=event_callback,
                cancel_event=cancel_event,
            )
        except PersistentWorkerCancelled as exc:
            raise AgentCancelledError("Platform Operator was cancelled by the user") from exc
        except PersistentWorkerTimeout as exc:
            raise TimeoutError(f"Platform Operator exceeded its timeout: {exc}") from exc
        except PersistentWorkerError as exc:
            self._discard_session(scan.id, task.id, task.attempts, role)
            raise RuntimeError(f"Platform Operator worker failed: {exc}") from exc
        finally:
            self._release_active_session(session_key)
        return CodexOperatorRunResult(
            thread_id=str(result["thread_id"]),
            turn_id=str(result["turn_id"]),
            result=OperatorReceipt.model_validate(result["result"]),
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
        cancel_event: threading.Event | None,
        developer_instructions_text: str,
    ) -> _ActiveDockerSession:
        key = (scan.id, task.id, task.attempts, role)
        with self._session_condition:
            existing = self._sessions.get(key)
            while existing is not None and key in self._busy_sessions:
                if cancel_event is not None and cancel_event.is_set():
                    raise AgentCancelledError("Codex session wait was cancelled")
                self._session_condition.wait(timeout=0.5)
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
                existing.last_used = time.monotonic()
                self._busy_sessions.add(key)
                return existing
            if existing is not None:
                self._sessions.pop(key, None)
                existing.client.kill()
            self._wait_for_worker_capacity(scan.id, cancel_event=cancel_event)
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
                "developer_instructions": developer_instructions_text,
                "model": self.settings.codex_model,
                "model_provider": self.settings.codex_provider,
                "reasoning_effort": self.settings.codex_reasoning_effort,
                "provider_base_url": self.settings.deepseek_base_url,
                "model_catalog_path": "/opt/apk-scanner/config/deepseek-models.json",
                "workspace_path": agent_session.container_workspace,
                "ida_mcp_url": (
                    self.settings.ida_mcp_url if self.settings.ida_mcp_enabled else None
                ),
                "ida_mcp_tool_timeout_seconds": (self.settings.ida_mcp_tool_timeout_seconds),
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
            active = _ActiveDockerSession(
                agent_session,
                container,
                client,
                role,
                time.monotonic(),
            )
            self._sessions[key] = active
            self._busy_sessions.add(key)
            return active

    def _wait_for_worker_capacity(
        self,
        scan_id: str,
        *,
        cancel_event: threading.Event | None,
    ) -> None:
        """Evict resumable idle workers or wait; capacity pressure never fails a task."""

        while True:
            scan_count = sum(1 for key in self._sessions if key[0] == scan_id)
            global_full = len(self._sessions) >= self.settings.codex_max_sessions
            scan_full = scan_count >= self.settings.codex_max_sessions_per_scan
            if not global_full and not scan_full:
                return
            candidates = [
                (key, active)
                for key, active in self._sessions.items()
                if key not in self._busy_sessions and (not scan_full or key[0] == scan_id)
            ]
            if candidates:
                evicted_key, evicted = min(candidates, key=lambda item: item[1].last_used)
                self._sessions.pop(evicted_key, None)
                with suppress(Exception):
                    evicted.client.close()
                continue
            if cancel_event is not None and cancel_event.is_set():
                raise AgentCancelledError("Codex worker capacity wait was cancelled")
            self._session_condition.wait(timeout=0.5)

    def _release_active_session(self, key: tuple[str, str, int, str]) -> None:
        with self._session_condition:
            active = self._sessions.get(key)
            if active is not None:
                active.last_used = time.monotonic()
            self._busy_sessions.discard(key)
            self._session_condition.notify_all()

    def _discard_session(self, scan_id: str, task_id: str, attempt: int, role: str) -> None:
        key = (scan_id, task_id, attempt, role)
        with self._session_condition:
            active = self._sessions.pop(key, None)
            self._busy_sessions.discard(key)
            self._session_condition.notify_all()
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
            if phase == "rescue_review"
            else "rescue_explorer"
            if phase == "rescue_exploration"
            else "verifier"
            if phase == "adaptive_verification"
            else "operator"
            if phase == "platform_operator"
            else "primary"
        )

    def close_scan(self, scan_id: str) -> None:
        with self._session_condition:
            sessions = [
                self._sessions.pop(key) for key in list(self._sessions) if key[0] == scan_id
            ]
            self._busy_sessions = {key for key in self._busy_sessions if key[0] != scan_id}
            self._session_condition.notify_all()
        for active in sessions:
            with suppress(Exception):
                active.client.close()
        self.executor.close_scan(scan_id)
        self.workspaces.forget_scan(scan_id)

    def close_task(self, scan_id: str, task_id: str) -> None:
        """Close all Agent roles owned by one terminal task and free its slots."""
        with self._session_condition:
            sessions = [
                self._sessions.pop(key)
                for key in list(self._sessions)
                if key[0] == scan_id and key[1] == task_id
            ]
            self._busy_sessions = {
                key for key in self._busy_sessions if not (key[0] == scan_id and key[1] == task_id)
            }
            self._session_condition.notify_all()
        for active in sessions:
            with suppress(Exception):
                active.client.close()
        self.workspaces.forget_task(scan_id, task_id)

    def close_task_role(
        self,
        scan_id: str,
        task_id: str,
        attempt: int,
        role: str,
    ) -> None:
        """Close one role between transport batches without deleting its workspace."""

        key = (scan_id, task_id, attempt, role)
        with self._session_condition:
            active = self._sessions.pop(key, None)
            self._busy_sessions.discard(key)
            self._session_condition.notify_all()
        if active is not None:
            with suppress(Exception):
                active.client.close()

    def shutdown(self) -> None:
        with self._session_condition:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._busy_sessions.clear()
            self._session_condition.notify_all()
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
                ida_mcp_url=(self.settings.ida_mcp_url if self.settings.ida_mcp_enabled else None),
                ida_mcp_tool_timeout_seconds=self.settings.ida_mcp_tool_timeout_seconds,
            ),
        )
        return Codex(config=config)

    @staticmethod
    def _json_object_candidates(
        response: str | None,
    ) -> tuple[str, list[_JsonObjectCandidate]]:
        if not response:
            raise ValueError("Codex returned no final response")
        text = response.strip()
        fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
        if fence:
            text = fence.group(1)
        try:
            value = json.loads(text)
        except json.JSONDecodeError as direct_error:
            decoder = json.JSONDecoder()
            candidates: list[_JsonObjectCandidate] = []
            cursor = 0
            while match := re.search(r"\{", text[cursor:]):
                start = cursor + match.start()
                try:
                    candidate, end = decoder.raw_decode(text, start)
                except json.JSONDecodeError:
                    cursor = start + 1
                    continue
                if isinstance(candidate, dict):
                    # Advancing to the decoded boundary prevents nested objects
                    # from competing with their complete outer result object.
                    candidates.append(_JsonObjectCandidate(candidate, start, end))
                    cursor = end
                else:
                    cursor = start + 1
            if not candidates:
                raise ValueError(
                    "Codex final response did not contain a complete JSON object"
                ) from direct_error
            return text, candidates
        if not isinstance(value, dict):
            raise ValueError("Codex final response must be a JSON object")
        return text, [_JsonObjectCandidate(value, 0, len(text))]

    @classmethod
    def _parse_json_object(
        cls,
        response: str | None,
        *,
        required_keys: set[str] | None = None,
    ) -> dict[str, Any]:
        _text, candidates = cls._json_object_candidates(response)
        if required_keys:
            matching = [
                candidate for candidate in candidates if required_keys.issubset(candidate.value)
            ]
            if matching:
                return matching[-1].value
            # Return the most schema-shaped candidate so the authoritative
            # downstream validator can report its precise missing fields.
            return max(
                candidates,
                key=lambda candidate: (
                    len(required_keys.intersection(candidate.value)),
                    candidate.start,
                ),
            ).value
        return candidates[-1].value

    @classmethod
    def _parse_response(cls, response: str | None) -> AgentInvestigationResult:
        text, candidates = cls._json_object_candidates(response)
        validation_errors: list[tuple[_JsonObjectCandidate, ValidationError]] = []
        for candidate in reversed(candidates):
            try:
                parsed = AgentInvestigationResult.model_validate(candidate.value)
            except ValidationError as exc:
                validation_errors.append((candidate, exc))
                continue

            prefix = text[: candidate.start].strip()
            suffix = text[candidate.end :].strip()
            if prefix or suffix or len(candidates) > 1:
                parsed.apply_model_validation_audit(
                    {
                        "rejected_requested_tests": parsed.rejected_requested_tests,
                        "normalization_repairs": [
                            *parsed.normalization_repairs,
                            {
                                "location": "$response",
                                "repair": "selected_schema_valid_json_from_mixed_response",
                                "top_level_candidate_count": len(candidates),
                                "selected_candidate_ordinal": candidates.index(candidate) + 1,
                                "prefix_characters_ignored": len(prefix),
                                "suffix_characters_ignored": len(suffix),
                            },
                        ],
                    }
                )
            return parsed

        model_fields = set(AgentInvestigationResult.model_fields)
        best_candidate, best_error = max(
            validation_errors,
            key=lambda item: (
                len(model_fields.intersection(item[0].value)),
                item[0].start,
            ),
        )
        del best_candidate
        raise best_error

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
    ida_mcp_url: str | None = None,
    ida_mcp_tool_timeout_seconds: int = 1_800,
) -> tuple[str, ...]:
    value = json.dumps
    overrides = (
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
        # Codex applies `inherit` before `include_only`.  The ADB/Proof/Observation gateway
        # variables are not part of its built-in `core` set, so `core` would
        # discard them before the allowlist can retain them.  Its patterns use
        # shell-style WildMatch (`*`/`?`), not regular expressions.  Start from
        # the worker environment, permit task tokens through the default secret
        # filter, then reduce everything to this explicit narrow allowlist.
        'shell_environment_policy.inherit="all"',
        "shell_environment_policy.ignore_default_excludes=true",
        (
            "shell_environment_policy.include_only="
            '["PATH","HOME","TMPDIR","TMP","TEMP","LANG","LC_ALL","LC_CTYPE",'
            '"TERM","SHELL","USER","LOGNAME","ANDROID_SERIAL","APKSCANNER_ADB_*",'
            '"APKSCANNER_PROOF_*","APKSCANNER_OBSERVATION_*",'
            '"HTTP_PROXY","HTTPS_PROXY","NO_PROXY"]'
        ),
        ('shell_environment_policy.exclude=["DEEPSEEK_API_KEY","OPENAI_API_KEY","CODEX_API_KEY"]'),
    )
    if ida_mcp_url:
        overrides += (
            f"mcp_servers.ida-headless.url={value(ida_mcp_url)}",
            "mcp_servers.ida-headless.required=false",
            "mcp_servers.ida-headless.startup_timeout_sec=20",
            (f"mcp_servers.ida-headless.tool_timeout_sec={int(ida_mcp_tool_timeout_seconds)}"),
        )
    return overrides
