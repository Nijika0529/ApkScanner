from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from contextlib import suppress
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from ..core.enums import FindingStatus
from ..core.models import Evidence, Finding, RuntimeObservation, Scan, ValidationFixture
from ..core.repository import add_event, invalidate_scan_materialized_summary, now
from ..core.schemas import (
    AgentProofReplay,
    AgentRequestedTest,
    AgentRuntimeObservation,
    WebExperimentRequest,
    WebExperimentSnapshotRequest,
)
from ..core.signal_projection import (
    evidence_supports_runtime_observation,
    project_runtime_observation_gap,
)
from ..infrastructure.tools import CommandResult
from .adb_gateway import AdbGatewayRequest, AdbGatewayResponse, quote_dynamic_experiment_adb_args
from .device import AdbDeviceAdapter
from .dynamic_experiments import fixture_state_check
from .external_observations import capture_external_observation
from .live_proof import LiveProofContext
from .poc import PocBuildResult
from .remote_observer_backend import RemoteObserverBackend, RemoteObserverConfig
from .remote_web_observer_adapter import RemoteWebObserverAdapter
from .semantic_proof_policy import CONTROLLED_CANARY_APK_SHA256
from .web_exploit_observer import WebExperiment, WebExploitObserver
from .web_target_observation import assess_target_web_observation

REACHABILITY_ONLY_HYPOTHESIS_CLAIMS = frozenset(
    {
        "A third-party application can launch the activity.",
        "A third-party application can start or bind to the service.",
        "An untrusted application can deliver a broadcast to the receiver.",
    }
)
REACHABILITY_ONLY_CLAIM_FRAGMENTS = (
    " are reachable from an untrusted application",
    " is reachable from an untrusted application",
    " are not strictly validated",
    " is not strictly validated",
)
_CONTROLLED_CANARY_PACKAGE = "io.apkscanner.adaptivecases"
_CONTROLLED_CANARY_URI = (
    "content://io.apkscanner.adaptivecases.fixture/web-canary"
)
_CONTROLLED_CANARY_ROW = re.compile(
    r"^Row: 0 experiment_id=([a-f0-9-]{36}), token_sha256=([a-f0-9]{64}), "
    r"bridge_calls=([0-9]+), bridge_url_sha256=([a-f0-9]{64}|NULL)$"
)


def _is_reachability_only_claim(claim: object) -> bool:
    if not isinstance(claim, str):
        return False
    normalized = " ".join(claim.strip().lower().split())
    return claim in REACHABILITY_ONLY_HYPOTHESIS_CLAIMS or any(
        fragment in normalized for fragment in REACHABILITY_ONLY_CLAIM_FRAGMENTS
    )


class LiveProofGatewayMixin:
    """Task-scoped proof/ADB gateway behavior shared by ScanOrchestrator."""

    def register_live_proof_context(
        self,
        context: LiveProofContext,
    ) -> None:
        with self._live_proof_lock:
            self._live_proof_contexts[context.task_id] = context

    def unregister_live_proof_context(
        self,
        task_id: str,
        token: str,
    ) -> None:
        removed = None
        had_reverse = False
        with self._live_proof_lock:
            current = self._live_proof_contexts.get(task_id)
            if current is not None and secrets.compare_digest(current.token, token):
                removed = self._live_proof_contexts.pop(task_id, None)
                reverse_tasks = getattr(self, "_web_observer_reverse_tasks", set())
                had_reverse = task_id in reverse_tasks
                reverse_tasks.discard(task_id)
        if removed is None:
            return
        # Let an in-flight experiment finish before revoking its owned tunnel.
        with removed.lock:
            canary_state = getattr(self, "_web_canary_state", {})
            for experiment_id, record in tuple(canary_state.items()):
                if record.get("task_id") == task_id:
                    with suppress(Exception):
                        self._clear_controlled_web_canary(removed, experiment_id)
                    canary_state.pop(experiment_id, None)
            with self._live_proof_lock:
                remote_ids = tuple(
                    getattr(self, "_web_observer_remote_tasks", {}).pop(task_id, set())
                )
            adapter = getattr(self, "_web_observer_remote_adapter", None)
            if adapter is not None:
                for experiment_id in remote_ids:
                    with suppress(Exception):
                        adapter.revoke(experiment_id, task_id=task_id)
                        self._persist_remote_web_observer_receipts(removed, experiment_id)
            observer = getattr(self, "_web_exploit_observer", None)
            if observer is not None:
                observer.revoke_task(task_id)
        if had_reverse and removed is not None and removed.device is not None:
            base_url = self._live_proof_base_url
            if base_url is not None:
                # Cleanup is confined to the mapping created by this task.
                removed.device.remove_web_observer_reverse(urlsplit(base_url).port)

    def ensure_live_proof_endpoint(self) -> str:
        with self._live_proof_lock:
            if self._live_proof_base_url is not None:
                return self._live_proof_base_url
            orchestrator = self
            self._web_exploit_observer = WebExploitObserver(self._persist_web_observer_event)
            self._web_observer_reverse_tasks: set[str] = set()
            self._web_observer_remote_tasks: dict[str, set[str]] = {}
            self._web_observer_remote_receipt_ids: set[str] = set()
            self._web_canary_state: dict[str, dict[str, Any]] = {}

            class ProofReplayHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:  # noqa: N802
                    if not self.path.startswith("/web-observer/"):
                        self._respond(404, {"detail": "not found"})
                        return
                    try:
                        status, content_type, body = orchestrator._web_exploit_observer.serve(
                            "GET",
                            self.path,
                            peer=self.client_address[0],
                            user_agent=self.headers.get("User-Agent", ""),
                        )
                    except Exception:
                        self._respond(500, {"detail": "Web observer persistence failed"})
                        return
                    self._respond_observer(status, content_type, body)

                def do_POST(self) -> None:  # noqa: N802
                    if self.path.startswith("/web-observer/"):
                        try:
                            length = int(self.headers.get("Content-Length", "0"))
                        except ValueError:
                            self._respond(400, {"detail": "invalid Content-Length"})
                            return
                        if length <= 0 or length > 16_384:
                            self._respond(413, {"detail": "invalid callback size"})
                            return
                        try:
                            status, content_type, body = orchestrator._web_exploit_observer.serve(
                                "POST",
                                self.path,
                                body=self.rfile.read(length),
                                peer=self.client_address[0],
                                user_agent=self.headers.get("User-Agent", ""),
                            )
                        except Exception:
                            self._respond(500, {"detail": "Web observer persistence failed"})
                            return
                        self._respond_observer(status, content_type, body)
                        return
                    proof_match = re.fullmatch(
                        r"/api/v1/internal/tasks/([a-f0-9-]{36})/proof-replay",
                        self.path,
                    )
                    adb_match = re.fullmatch(
                        r"/api/v1/internal/tasks/([a-f0-9-]{36})/adb",
                        self.path,
                    )
                    observation_match = re.fullmatch(
                        r"/api/v1/internal/tasks/([a-f0-9-]{36})/observations",
                        self.path,
                    )
                    experiment_match = re.fullmatch(
                        r"/api/v1/internal/tasks/([a-f0-9-]{36})/web-experiments",
                        self.path,
                    )
                    snapshot_match = re.fullmatch(
                        r"/api/v1/internal/tasks/([a-f0-9-]{36})/web-experiments/([a-f0-9-]{36})/snapshot",
                        self.path,
                    )
                    if all(match is None for match in (proof_match, adb_match, observation_match, experiment_match, snapshot_match)):
                        self._respond(404, {"detail": "not found"})
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self._respond(400, {"detail": "invalid Content-Length"})
                        return
                    if length <= 0 or length > 2_000_000:
                        self._respond(413, {"detail": "invalid gateway request size"})
                        return
                    try:
                        body = self.rfile.read(length)
                        if proof_match is not None:
                            replay = AgentProofReplay.model_validate_json(body)
                            response = orchestrator.execute_live_proof_replay(
                                proof_match.group(1),
                                self.headers.get("X-APKScanner-Proof-Token", ""),
                                replay,
                            )
                        elif adb_match is not None:
                            assert adb_match is not None
                            request = AdbGatewayRequest.model_validate_json(body)
                            response = orchestrator.execute_live_adb(
                                adb_match.group(1),
                                self.headers.get("X-APKScanner-ADB-Token", ""),
                                request,
                            )
                        elif experiment_match is not None:
                            request = WebExperimentRequest.model_validate_json(body)
                            response = orchestrator.begin_web_experiment(
                                experiment_match.group(1),
                                self.headers.get("X-APKScanner-Proof-Token", ""),
                                request,
                            )
                        elif snapshot_match is not None:
                            request = WebExperimentSnapshotRequest.model_validate_json(body)
                            response = orchestrator.snapshot_web_experiment(
                                snapshot_match.group(1),
                                self.headers.get("X-APKScanner-Proof-Token", ""),
                                snapshot_match.group(2),
                                request,
                            )
                        else:
                            assert observation_match is not None
                            observation = AgentRuntimeObservation.model_validate_json(body)
                            response = orchestrator.record_live_runtime_observation(
                                observation_match.group(1),
                                self.headers.get("X-APKScanner-Proof-Token", ""),
                                observation,
                            )
                    except PermissionError as exc:
                        self._respond(403, {"detail": str(exc)})
                        return
                    except (TimeoutError, ValueError) as exc:
                        self._respond(409, {"detail": str(exc)})
                        return
                    except Exception as exc:  # local task boundary
                        self._respond(500, {"detail": str(exc)})
                        return
                    self._respond(200, response)

                def _respond_observer(self, status: int, content_type: str, body: bytes) -> None:
                    self.send_response(status)
                    if content_type.startswith("Location: "):
                        self.send_header("Location", content_type.removeprefix("Location: "))
                    else:
                        self.send_header("Content-Type", content_type)
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def _respond(self, status: int, payload: dict[str, Any]) -> None:
                    body = json.dumps(
                        payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, _format: str, *args: Any) -> None:
                    return

            server = ThreadingHTTPServer(("0.0.0.0", 0), ProofReplayHandler)
            server.daemon_threads = True
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.1},
                name="apkscanner-proof-replay",
                daemon=True,
            )
            thread.start()
            self._live_proof_server = server
            self._live_proof_server_thread = thread
            self._live_proof_base_url = f"http://127.0.0.1:{server.server_address[1]}"
            return self._live_proof_base_url

    def _ensure_remote_web_observer_adapter(self) -> RemoteWebObserverAdapter:
        local_base_url = self.ensure_live_proof_endpoint()
        port = urlsplit(local_base_url).port
        assert port is not None
        with self._live_proof_lock:
            adapter = getattr(self, "_web_observer_remote_adapter", None)
            if adapter is not None:
                return adapter
            settings = self.settings
            if (
                not settings.web_observer_remote_enabled
                or settings.web_observer_ssh_alias is None
                or settings.web_observer_ssh_config is None
                or settings.web_observer_public_base_url is None
            ):
                raise ValueError("remote Web observer is not configured")
            backend = RemoteObserverBackend(RemoteObserverConfig(
                ssh_alias=settings.web_observer_ssh_alias,
                allowed_ssh_aliases=settings.web_observer_allowed_ssh_aliases,
                ssh_config_path=settings.web_observer_ssh_config,
                public_base_url=settings.web_observer_public_base_url,
                local_observer_port=port,
                remote_loopback_port=settings.web_observer_remote_loopback_port,
            ))
            adapter = RemoteWebObserverAdapter(self._web_exploit_observer, backend)
            self._web_observer_remote_adapter = adapter
            return adapter

    # Compatibility shims for callers on the pre-boundary-cleanup API.
    def _register_live_proof_context(self, context: LiveProofContext) -> None:
        self.register_live_proof_context(context)

    def _unregister_live_proof_context(self, task_id: str, token: str) -> None:
        self.unregister_live_proof_context(task_id, token)

    def _ensure_live_proof_endpoint(self) -> str:
        return self.ensure_live_proof_endpoint()

    def execute_live_adb(
        self,
        task_id: str,
        token: str,
        request: AdbGatewayRequest,
    ) -> dict[str, Any]:
        with self._live_proof_lock:
            context = self._live_proof_contexts.get(task_id)
        if context is None or not secrets.compare_digest(context.token, token):
            raise PermissionError("ADB gateway is not active for this task")
        if context.device is None:
            raise ValueError("this task does not own an ADB device")
        if request.policy != context.adb_policy:
            raise PermissionError("ADB gateway policy does not match this task")
        with context.lock:
            if any(
                item.get("task_id") == task_id
                for item in getattr(self, "_web_canary_state", {}).values()
            ):
                raise PermissionError(
                    "Agent ADB access is paused while the target-only Web canary is active"
                )
            self._raise_if_cancelled(context.cancel_event)
            if context.budget.expired:
                raise TimeoutError("task time budget is exhausted")
            timeout = min(request.timeout_seconds, max(1, context.budget.remaining(120)))
            forwarded_args = list(request.args)
            if (
                self.settings.device_reset_policy == "never"
                and self._adb_command_destroys_target_data(
                    forwarded_args,
                    package_name=context.package_name,
                )
            ):
                raise ValueError(
                    "target application data is protected by APKSCANNER_DEVICE_RESET_POLICY=never"
                )
            if context.adb_policy == "adaptive" and context.container_workspace:
                forwarded_args = self._translate_adaptive_adb_paths(
                    forwarded_args,
                    container_workspace=context.container_workspace,
                    host_workspace=context.workspace,
                )
            result = context.device.execute_gateway(
                forwarded_args,
                timeout=timeout,
                policy=context.adb_policy,
            )
            command_records: list[tuple[str, CommandResult, dict[str, Any]]] = [
                (
                    "agent.adb.gateway",
                    result,
                    {
                        "source": "codex_gateway",
                        "round_index": context.round_index,
                        "gateway_policy": (
                            "adaptive_task_scoped_v1"
                            if context.adb_policy == "adaptive"
                            else "task_scoped_v1"
                        ),
                    },
                )
            ]
            result_record_index = 0
            conflicting_poc = self._adaptive_poc_signature_conflict(
                forwarded_args,
                result,
                target_package=context.package_name,
            )
            if conflicting_poc is not None:
                cleanup = context.device.execute_gateway(
                    ["uninstall", conflicting_poc],
                    timeout=min(90, max(1, context.budget.remaining(90))),
                    policy="adaptive",
                )
                command_records.append(
                    (
                        "agent.adb.gateway.poc_cleanup",
                        cleanup,
                        {
                            "source": "platform",
                            "round_index": context.round_index,
                            "poc_package": conflicting_poc,
                            "reason": "stale_poc_signing_key_mismatch",
                        },
                    )
                )
                if cleanup.exit_code == 0 and not context.budget.expired:
                    result = context.device.execute_gateway(
                        forwarded_args,
                        timeout=min(
                            request.timeout_seconds,
                            max(1, context.budget.remaining(120)),
                        ),
                        policy="adaptive",
                    )
                    command_records.append(
                        (
                            "agent.adb.gateway.poc_install_retry",
                            result,
                            {
                                "source": "platform",
                                "round_index": context.round_index,
                                "poc_package": conflicting_poc,
                                "reason": "retry_after_stale_poc_cleanup",
                            },
                        )
                    )
                    result_record_index = len(command_records) - 1
            normalized_result = self._normalize_adaptive_adb_result(forwarded_args, result)
            if normalized_result is not result:
                kind, _raw_result, metadata = command_records[result_record_index]
                command_records[result_record_index] = (
                    kind,
                    normalized_result,
                    {**metadata, "semantic_exit_normalized": True},
                )
                result = normalized_result
            self._record_commands(
                context.scan_id,
                context.task_id,
                command_records,
                context.evidence_summaries,
            )
            self._materialize_live_evidence(context, context.evidence_summaries)
            self._record_exploration_event(
                context.scan_id,
                context.task_id,
                "model.tool.adb.completed",
                "Codex 通过任务级网关完成一条 ADB 命令",
                {
                    "source": "platform",
                    "round_index": context.round_index,
                    "exit_code": result.exit_code,
                    "command": request.args[:4],
                    "device_serial": context.device.serial,
                },
            )
            return AdbGatewayResponse.from_command(result).model_dump(mode="json")

    @staticmethod
    def _adaptive_poc_signature_conflict(
        args: list[str],
        result: CommandResult,
        *,
        target_package: str,
    ) -> str | None:
        """Return a stale temporary PoC package that may be safely replaced."""

        if not args or args[0] != "install" or result.exit_code == 0:
            return None
        output = "\n".join(value for value in (result.stdout, result.stderr) if value)
        if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" not in output.upper():
            return None
        match = re.search(
            r"Existing package\s+([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\s+"
            r"signatures do not match",
            output,
            flags=re.IGNORECASE,
        )
        if match is None:
            return None
        package_name = match.group(1)
        if package_name == target_package or not package_name.startswith("io.apkscanner.poc."):
            return None
        return package_name

    @staticmethod
    def _normalize_adaptive_adb_result(
        args: list[str],
        result: CommandResult,
    ) -> CommandResult:
        """Turn Android's textual `am start` errors into a real command failure."""

        if len(args) < 3 or args[:3] != ["shell", "am", "start"]:
            return result
        diagnostics = AdbDeviceAdapter._poc_launch_diagnostics(result)
        if diagnostics["launch_accepted"] is not False or result.exit_code != 0:
            return result
        failure_kind = diagnostics["launch_failure_kind"] or "adb_launch_failed"
        suffix = f"APKScanner: semantic am start failure ({failure_kind})"
        stderr = f"{result.stderr.rstrip()}\n{suffix}\n" if result.stderr else f"{suffix}\n"
        return CommandResult(
            argv=result.argv,
            exit_code=1,
            stdout=result.stdout,
            stderr=stderr,
            timed_out=result.timed_out,
            canceled=result.canceled,
        )

    @staticmethod
    def _adb_command_destroys_target_data(
        args: list[str],
        *,
        package_name: str,
    ) -> bool:
        """Recognize normal ADB paths that can erase or rewrite the preserved target profile."""

        normalized = [value.strip().lower() for value in args]
        package = package_name.lower()
        flattened = " ".join(normalized)
        if package not in flattened:
            return False
        if normalized and normalized[0] == "uninstall":
            return True
        if "uninstall" in normalized:
            return True
        if "clear" in normalized and ("pm" in normalized or "package" in normalized):
            return True
        if f"run-as {package}" in flattened:
            return True
        return bool(re.search(r"(?:^|\s)(?:pm\s+clear|cmd\s+package\s+clear)(?:\s|$)", flattened))

    @staticmethod
    def _translate_adaptive_adb_paths(
        args: list[str],
        *,
        container_workspace: str,
        host_workspace: Path,
    ) -> list[str]:
        """Translate verifier-local APK/file paths for the host-owned ADB process."""

        prefix = container_workspace.rstrip("/")
        host_root = host_workspace.resolve()

        def local_path(value: str) -> str:
            if value == prefix or value.startswith(prefix + "/"):
                relative = value[len(prefix) :].lstrip("/")
            elif Path(value).is_absolute():
                absolute = Path(value).resolve()
                if not absolute.is_relative_to(host_root):
                    raise ValueError("ADB local path escapes the verifier workspace")
                return str(absolute)
            else:
                relative = value
            target = (host_root / relative).resolve()
            if not target.is_relative_to(host_root):
                raise ValueError("ADB local path escapes the verifier workspace")
            return str(target)

        translated: list[str] = []
        for value in args:
            if value == prefix or value.startswith(prefix + "/"):
                translated.append(local_path(value))
            else:
                translated.append(value)

        command = translated[0] if translated else ""
        positional = [
            index for index in range(1, len(translated)) if not translated[index].startswith("-")
        ]
        if command == "pull":
            if len(positional) >= 2:
                translated[positional[1]] = local_path(translated[positional[1]])
            elif positional:
                remote_name = Path(translated[positional[0]].rstrip("/")).name or "adb-pull"
                translated.append(local_path(remote_name))
        elif command == "push" and positional:
            translated[positional[0]] = local_path(translated[positional[0]])
        elif command in {
            "install",
            "install-multiple",
            "install-multi-package",
            "install-streaming",
        }:
            for index in positional:
                value = translated[index]
                if value.lower().endswith((".apk", ".apex")):
                    translated[index] = local_path(value)
        elif command == "bugreport" and positional:
            translated[positional[0]] = local_path(translated[positional[0]])
        return translated

    def execute_live_proof_replay(
        self,
        task_id: str,
        token: str,
        replay: AgentProofReplay,
    ) -> dict[str, Any]:
        with self._live_proof_lock:
            context = self._live_proof_contexts.get(task_id)
        if context is None or not secrets.compare_digest(context.token, token):
            raise PermissionError("proof replay is not active for this task")
        signature = hashlib.sha256(
            json.dumps(
                replay.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        with context.lock:
            cached = context.responses.get(signature)
            if cached is not None:
                deduplicated = {
                    key: value for key, value in cached.items() if key != "receipt_signature"
                }
                deduplicated["deduplicated"] = True
                receipt_payload = json.dumps(
                    deduplicated,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                deduplicated["receipt_signature"] = hmac.new(
                    token.encode(),
                    receipt_payload,
                    hashlib.sha256,
                ).hexdigest()
                return deduplicated
            self._raise_if_cancelled(context.cancel_event)
            if context.budget.expired:
                raise TimeoutError("task budget expired before proof replay")
            hypothesis_ids = [str(item["id"]) for item in context.hypotheses]
            hypothesis_id = replay.hypothesis_id
            if hypothesis_id not in hypothesis_ids:
                raise ValueError("proof replay hypothesis is outside this task")
            selected_hypothesis = next(
                item for item in context.hypotheses if str(item["id"]) == hypothesis_id
            )
            if replay.oracle.kind == "log_contains":
                raise ValueError(
                    "a PoC-owned log_contains result is not an independent live harm Oracle; "
                    "use target_uid_log_contains for target-owned effects or report an Oracle gap"
                )
            if replay.oracle.impact == "none":
                raise ValueError(
                    "live proof replay requires a non-none Oracle impact and a concrete "
                    "harm hypothesis; use the ADB gateway for reachability diagnostics"
                )
            if replay.oracle.impact != "none" and _is_reachability_only_claim(
                selected_hypothesis.get("claim")
            ):
                raise ValueError(
                    "an impactful proof replay must target the concrete harm or "
                    "cross-boundary hypothesis, not a reachability-only hypothesis"
                )
            entry_id = replay.entry_point_id
            if entry_id is None:
                entry_id = context.default_entry_id
            if entry_id not in {entry.id for entry in context.entries}:
                raise ValueError("proof replay entry point is outside this task")
            request = AgentRequestedTest(
                hypothesis_id=hypothesis_id,
                entry_point_id=entry_id,
                state="guest",
                uri=None,
                extras=dict(replay.extras),
                operation=replay.operation,
                binder_transaction_code=replay.binder_transaction_code,
                binder_interface_descriptor=replay.binder_interface_descriptor,
                binder_reply_type=replay.binder_reply_type,
                binder_read_exception=replay.binder_read_exception,
                binder_script=(
                    [item.model_dump(mode="json") for item in replay.binder_script]
                    if replay.binder_script is not None
                    else None
                ),
                reset=replay.reset,
                oracle=replay.oracle,
                rationale=replay.rationale,
                poc=replay.poc,
            )
            semantic_strategy_signature = hashlib.sha256(
                json.dumps(
                    {
                        "entry_point_id": entry_id,
                        "extras": replay.extras,
                        "operation": replay.operation,
                        "binder_transaction_code": replay.binder_transaction_code,
                        "binder_interface_descriptor": replay.binder_interface_descriptor,
                        "binder_reply_type": replay.binder_reply_type,
                        "binder_read_exception": replay.binder_read_exception,
                        "binder_script": (
                            [item.model_dump(mode="json") for item in replay.binder_script]
                            if replay.binder_script is not None
                            else None
                        ),
                        "oracle": replay.oracle.model_dump(mode="json"),
                        "rationale": " ".join(replay.rationale.lower().split()),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            prior_proven_strategy = context.proven_semantic_strategies.get(
                semantic_strategy_signature
            )
            if prior_proven_strategy is not None:
                response = {
                    "schema_version": "1.0",
                    "accepted": True,
                    "executed": False,
                    "hypothesis_id": hypothesis_id,
                    "entry_point_id": entry_id,
                    "result": "inconclusive",
                    "evidence_ids": [],
                    "evidence": [],
                    "gaps": [
                        "This PoC package, entry, Oracle, and exploit rationale "
                        "already produced a proven platform replay for hypothesis "
                        f"{prior_proven_strategy['hypothesis_id']}. Do not rewrite "
                        "the same PoC merely to attach it to another hypothesis."
                    ],
                    "deduplicated": False,
                    "deduplicated_strategy": True,
                    "prior_hypothesis_id": prior_proven_strategy["hypothesis_id"],
                    "prior_evidence_ids": prior_proven_strategy["evidence_ids"],
                }
                receipt_payload = json.dumps(
                    response,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                response["receipt_signature"] = hmac.new(
                    token.encode(),
                    receipt_payload,
                    hashlib.sha256,
                ).hexdigest()
                context.responses[signature] = response
                self._record_exploration_event(
                    context.scan_id,
                    context.task_id,
                    "proof_replay.semantic_deduplicated",
                    "已成功的同语义 PoC 不再因换假设或改写源码而重复执行",
                    {
                        "source": "platform",
                        "hypothesis_id": hypothesis_id,
                        "prior_hypothesis_id": prior_proven_strategy["hypothesis_id"],
                        "entry_point_id": entry_id,
                        "semantic_strategy_signature": (semantic_strategy_signature),
                    },
                )
                return response
            prior_executed_strategy = context.executed_semantic_strategies.get(
                semantic_strategy_signature
            )
            if prior_executed_strategy is not None:
                response = {
                    "schema_version": "1.0",
                    "accepted": True,
                    "executed": False,
                    "hypothesis_id": hypothesis_id,
                    "entry_point_id": entry_id,
                    "result": "inconclusive",
                    "evidence_ids": [],
                    "evidence": [],
                    "gaps": [
                        "This entry, input, Oracle, and exploit rationale already ran. "
                        "Changing only the PoC package or rewriting equivalent source is "
                        "not a materially different strategy. Inspect the existing evidence "
                        "and describe the changed security strategy before another replay."
                    ],
                    "deduplicated": False,
                    "deduplicated_strategy": True,
                    "prior_hypothesis_id": prior_executed_strategy["hypothesis_id"],
                    "prior_result": prior_executed_strategy["result"],
                    "prior_evidence_ids": prior_executed_strategy["evidence_ids"],
                }
                receipt_payload = json.dumps(
                    response,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                response["receipt_signature"] = hmac.new(
                    token.encode(),
                    receipt_payload,
                    hashlib.sha256,
                ).hexdigest()
                context.responses[signature] = response
                self._record_exploration_event(
                    context.scan_id,
                    context.task_id,
                    "proof_replay.semantic_deduplicated",
                    "同语义 PoC 已执行，修改包名或等价源码不再重复占用设备",
                    {
                        "source": "platform",
                        "hypothesis_id": hypothesis_id,
                        "prior_hypothesis_id": prior_executed_strategy["hypothesis_id"],
                        "entry_point_id": entry_id,
                        "semantic_strategy_signature": semantic_strategy_signature,
                        "prior_result": prior_executed_strategy["result"],
                    },
                )
                return response
            accepted, validation_gaps = self._validate_requested_tests(
                [request],
                context.entries,
                hypothesis_ids=set(hypothesis_ids),
                permission_profile=self.settings.agent_permission_profile,
            )
            before = len(context.evidence_summaries)
            artifacts: dict[str, PocBuildResult] = {}
            build_gaps: list[str] = []
            if accepted:
                accepted, artifacts, build_gaps = self._build_requested_pocs(
                    scan_id=context.scan_id,
                    task_id=context.task_id,
                    workspace=context.workspace,
                    requests=accepted,
                    evidence_summaries=context.evidence_summaries,
                    cancel_event=context.cancel_event,
                )
            strategy_signature: str | None = None
            if accepted:
                artifact = artifacts.get(self._poc_request_key(accepted[0]))
                if artifact is not None and artifact.ok:
                    strategy_signature = hashlib.sha256(
                        json.dumps(
                            {
                                "entry_point_id": entry_id,
                                "source_sha256": artifact.source_sha256,
                                "apk_sha256": artifact.apk_sha256,
                                "extras": replay.extras,
                                "reset": replay.reset,
                                "oracle": replay.oracle.model_dump(mode="json"),
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()
                    prior_strategy = context.proof_strategies.get(strategy_signature)
                    if prior_strategy is not None:
                        new_evidence = context.evidence_summaries[before:]
                        self._materialize_live_evidence(context, new_evidence)
                        response = {
                            "schema_version": "1.0",
                            "accepted": True,
                            "executed": False,
                            "hypothesis_id": hypothesis_id,
                            "entry_point_id": entry_id,
                            "result": "inconclusive",
                            "evidence_ids": [
                                str(item["id"])
                                for item in new_evidence
                                if isinstance(item.get("id"), str)
                            ],
                            "evidence": new_evidence,
                            "gaps": [
                                "This exact PoC source, entry, input, and Oracle "
                                "strategy already ran for hypothesis "
                                f"{prior_strategy['hypothesis_id']}. Dynamic proof "
                                "ownership is not transferred to a different claim. "
                                "Use the existing evidence for static support or "
                                "submit a materially different claim-specific strategy."
                            ],
                            "deduplicated": False,
                            "deduplicated_strategy": True,
                            "prior_hypothesis_id": prior_strategy["hypothesis_id"],
                            "prior_evidence_ids": prior_strategy["evidence_ids"],
                        }
                        receipt_payload = json.dumps(
                            response,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                        response["receipt_signature"] = hmac.new(
                            token.encode(),
                            receipt_payload,
                            hashlib.sha256,
                        ).hexdigest()
                        context.responses[signature] = response
                        self._record_exploration_event(
                            context.scan_id,
                            context.task_id,
                            "proof_replay.strategy_deduplicated",
                            "相同 PoC 策略已执行，平台拒绝跨假设重复重放",
                            {
                                "source": "platform",
                                "hypothesis_id": hypothesis_id,
                                "prior_hypothesis_id": prior_strategy["hypothesis_id"],
                                "entry_point_id": entry_id,
                                "strategy_signature": strategy_signature,
                            },
                        )
                        return response
            executed: list[dict[str, Any]] = []
            execution_gaps: list[str] = []
            if accepted:
                context.round_index += 1
                executed, execution_gaps = self._execute_requested_tests(
                    scan_id=context.scan_id,
                    task_id=context.task_id,
                    package_name=context.package_name,
                    entries=context.entries,
                    requests=accepted,
                    budget=context.budget,
                    evidence_summaries=context.evidence_summaries,
                    round_index=context.round_index,
                    poc_artifacts=artifacts,
                    device=context.device,
                )
            new_evidence = context.evidence_summaries[before:]
            self._materialize_live_evidence(context, new_evidence)
            proven_hypotheses = self.hypothesis_ledger.task_proven_hypotheses(context.task_id)
            proof_evidence_ids = proven_hypotheses.get(hypothesis_id)
            result = (
                FindingStatus.REPRODUCED_BLACKBOX.value if proof_evidence_ids else "inconclusive"
            )
            replay_gaps = [
                *validation_gaps,
                *build_gaps,
                *execution_gaps,
            ]
            if result == "inconclusive" and executed and not replay_gaps:
                replay_gaps.append(
                    "The platform replay executed, but the correlated Oracle did not "
                    "demonstrate the requested security impact. Inspect the attached "
                    "evidence metadata before changing the PoC or Oracle."
                )
            response = {
                "schema_version": "1.0",
                "accepted": bool(accepted),
                "executed": bool(executed),
                "hypothesis_id": hypothesis_id,
                "entry_point_id": entry_id,
                # A proof attached to another hypothesis in the same task must
                # never make this replay look proven. The task-level aggregate
                # remains useful for terminating exploration, but live receipts
                # are claim-specific security evidence.
                "result": result,
                "evidence_ids": [
                    str(item["id"]) for item in new_evidence if isinstance(item.get("id"), str)
                ],
                "evidence": new_evidence,
                "gaps": replay_gaps,
                "deduplicated": False,
            }
            receipt_payload = json.dumps(
                response,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            response["receipt_signature"] = hmac.new(
                token.encode(),
                receipt_payload,
                hashlib.sha256,
            ).hexdigest()
            # Validation/build rejection has no dynamic side effect and may be
            # fixed by editing the PoC files while keeping the replay JSON
            # unchanged. Caching that receipt would make the corrected source
            # impossible to submit. Executed requests remain idempotent.
            if accepted or executed:
                context.responses[signature] = response
            if strategy_signature is not None and executed:
                context.proof_strategies[strategy_signature] = {
                    "hypothesis_id": hypothesis_id,
                    "evidence_ids": list(response["evidence_ids"]),
                }
            if executed:
                context.executed_semantic_strategies[semantic_strategy_signature] = {
                    "hypothesis_id": hypothesis_id,
                    "result": result,
                    "evidence_ids": list(response["evidence_ids"]),
                }
            if result == FindingStatus.REPRODUCED_BLACKBOX.value:
                context.proven_semantic_strategies[semantic_strategy_signature] = {
                    "hypothesis_id": hypothesis_id,
                    "evidence_ids": list(response["evidence_ids"]),
                }
            self._record_exploration_event(
                context.scan_id,
                context.task_id,
                "proof_replay.completed",
                "Agent 调通的 PoC 已由平台实时重放并完成证据判定",
                {
                    "source": "platform",
                    "hypothesis_id": hypothesis_id,
                    "entry_point_id": entry_id,
                    "result": response["result"],
                    "evidence_ids": response["evidence_ids"],
                    "gaps": response["gaps"],
                },
            )
            return response

    def _web_context(self, task_id: str, token: str) -> LiveProofContext:
        with self._live_proof_lock:
            context = self._live_proof_contexts.get(task_id)
        if context is None or not secrets.compare_digest(context.token, token):
            raise PermissionError("Web experiment is not active for this task")
        self._raise_if_cancelled(context.cancel_event)
        if context.budget.expired:
            raise TimeoutError("task time budget is exhausted")
        if context.device is None or not context.device.serial:
            raise ValueError("a leased ADB device is required for a Web experiment")
        return context

    def _verify_web_fixture_state(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        step: Any,
        fixture_type: str,
    ) -> dict[str, Any]:
        """Execute an active fixture's read-only predicate on the leased device.

        A fixture ID and its setup instructions are never a state observation.
        The plan binds this command receipt; the later policy gate rechecks its
        artifact, scope, result and frozen inclusion before accepting the state.
        """

        assert context.device is not None
        fixture_id = experiment.request.fixture_id
        assert fixture_id is not None
        step_document = step.model_dump(mode="json")
        step_digest = hashlib.sha256(
            json.dumps(step_document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        result = context.device.execute_gateway(
            quote_dynamic_experiment_adb_args(step.adb_args),
            timeout=min(step.timeout_seconds, max(1, context.budget.remaining(step.timeout_seconds))),
            policy="adaptive",
        )
        target_state_source = "unverified"
        if (
            fixture_type == "canary"
            and context.package_name == _CONTROLLED_CANARY_PACKAGE
            and experiment.request.victim_state.strip().lower() == "controlled canary fixture"
        ):
            # The package-path predicate alone is not the canary oracle. The
            # separately pinned seed and target readback establish this state.
            target_state_source = "controlled_canary_seed_pending"
        # Other fixture types may be executable, but a query URI or its name
        # does not establish that the queried state belongs to this target.
        # Keep them as an Oracle gap until an authority-owner and state adapter
        # can attest the observation independently.
        verified = bool(
            result.exit_code == step.expected_exit_code
            and not result.timed_out
            and not result.canceled
            and all(value in result.stdout for value in step.stdout_contains)
            and (step.stdout_regex is None or re.search(step.stdout_regex, result.stdout))
            and target_state_source != "unverified"
        )
        checked_at = now().isoformat()
        before = len(context.evidence_summaries)
        self._record_commands(
            context.scan_id,
            context.task_id,
            [(
                "web.experiment.fixture_state",
                result,
                {
                    "source": "platform_web_observer",
                    "experiment_id": experiment.experiment_id,
                    "nonce": experiment.nonce,
                    "finding_id": experiment.finding_id,
                    "hypothesis_id": experiment.hypothesis_id,
                    "device_serial": experiment.device_serial,
                    "fixture_id": fixture_id,
                    "fixture_type": fixture_type,
                    "victim_state": experiment.request.victim_state,
                    "state_check_digest": step_digest,
                    "expected_exit_code": step.expected_exit_code,
                    "fixture_state_verified": verified,
                    "target_state_source": target_state_source,
                    "checked_at": checked_at,
                    "impact_contract_satisfied": False,
                },
            )],
            context.evidence_summaries,
        )
        if len(context.evidence_summaries) != before + 1:
            raise RuntimeError("Web fixture state receipt was not persisted")
        return {
            "fixture_id": fixture_id,
            "fixture_type": fixture_type,
            "state_check_evidence_id": context.evidence_summaries[-1]["id"],
            "state_check_digest": step_digest,
            "victim_state": experiment.request.victim_state,
            "verified": verified,
            "target_state_source": target_state_source,
            "checked_at": checked_at,
        }

    def _frozen_web_fixture_state(self, experiment: WebExperiment) -> dict[str, Any]:
        """Read the persisted plan, never a caller-supplied fixture label."""

        with self.database.session_factory() as session:
            plans = list(session.scalars(select(Evidence).where(
                Evidence.scan_id == experiment.scan_id,
                Evidence.task_id == experiment.task_id,
                Evidence.kind == "web.experiment.plan",
            )))
        matching = [
            item for item in plans
            if (item.metadata_json or {}).get("experiment_id") == experiment.experiment_id
        ]
        if len(matching) != 1:
            return {}
        try:
            document = self.store.read_json_artifact(
                "evidence", matching[0].path, matching[0].sha256
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        state = document.get("state_fixture") if isinstance(document, dict) else None
        if not isinstance(state, dict):
            return {}
        state_id = state.get("state_check_evidence_id")
        with self.database.session_factory() as session:
            receipt = session.get(Evidence, state_id) if isinstance(state_id, str) else None
        metadata = receipt.metadata_json or {} if receipt is not None else {}
        try:
            raw = (
                self.store.read_json_artifact("evidence", receipt.path, receipt.sha256)
                if receipt is not None else None
            )
        except (OSError, ValueError, json.JSONDecodeError):
            raw = None
        verified = bool(
            receipt is not None
            and receipt.kind == "web.experiment.fixture_state"
            and receipt.scan_id == experiment.scan_id
            and receipt.task_id == experiment.task_id
            and metadata.get("source") == "platform_web_observer"
            and metadata.get("experiment_id") == experiment.experiment_id
            and metadata.get("device_serial") == experiment.device_serial
            and metadata.get("fixture_id") == experiment.request.fixture_id
            and metadata.get("state_check_digest") == state.get("state_check_digest")
            and metadata.get("fixture_state_verified") is True
            and state.get("verified") is True
            and isinstance(raw, dict)
            and raw.get("metadata") == metadata
            and raw.get("exit_code") == metadata.get("expected_exit_code")
            and raw.get("timed_out") is False
            and raw.get("canceled") is False
        )
        return {**state, "verified": verified}

    @staticmethod
    def _controlled_canary_readback(
        stdout: str,
    ) -> tuple[str, str, int, str | None] | None:
        rows = [line.strip() for line in stdout.splitlines() if line.startswith("Row:")]
        if len(rows) != 1:
            return None
        matched = _CONTROLLED_CANARY_ROW.fullmatch(rows[0])
        return (
            matched.group(1),
            matched.group(2),
            int(matched.group(3)),
            None if matched.group(4) == "NULL" else matched.group(4),
        ) if matched else None

    def _seed_controlled_web_canary(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        *,
        target_apk_sha256: str,
        apk_identity_evidence_id: str,
    ) -> dict[str, Any]:
        """Seed a non-debuggable, shell-UID-protected test APK without publishing the secret.

        This is an exact-package fixture capability, not a generic third-party
        app observer. The Agent ADB gateway cannot access this provider URI.
        """

        assert context.device is not None
        if context.package_name != _CONTROLLED_CANARY_PACKAGE:
            raise ValueError("controlled Web canary is only available for the test fixture APK")
        if target_apk_sha256 != CONTROLLED_CANARY_APK_SHA256:
            raise ValueError("controlled Web canary requires the pinned shell-UID-protected APK")
        if any(
            item.get("task_id") == context.task_id
            for item in self._web_canary_state.values()
        ):
            raise ValueError("only one controlled Web canary may be active for a task")
        # Register the guard *before* the insert. A timeout or evidence-store
        # failure can occur after the target has already created its token.
        record = {
            "task_id": context.task_id,
            "token_sha256": None,
            "fixture_id": experiment.request.fixture_id,
            "seed_evidence_id": None,
            "target_apk_sha256": target_apk_sha256,
            "finding_id": experiment.finding_id,
            "hypothesis_id": experiment.hypothesis_id,
            "nonce": experiment.nonce,
            "device_serial": experiment.device_serial,
        }
        self._web_canary_state[experiment.experiment_id] = record
        try:
            return self._perform_controlled_web_canary_seed(
                context, experiment,
                target_apk_sha256=target_apk_sha256,
                apk_identity_evidence_id=apk_identity_evidence_id,
                record=record,
            )
        except Exception:
            if experiment.experiment_id in self._web_canary_state:
                with suppress(Exception):
                    self._clear_controlled_web_canary(context, experiment.experiment_id)
            raise

    def _perform_controlled_web_canary_seed(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        *,
        target_apk_sha256: str,
        apk_identity_evidence_id: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        assert context.device is not None
        seed = context.device._adb(
            [
                "shell", "content", "insert", "--uri", _CONTROLLED_CANARY_URI,
                "--bind", f"experiment_id:s:{experiment.experiment_id}",
            ],
            timeout=min(30, max(1, context.budget.remaining(30))),
        )
        preflight = context.device._adb(
            ["shell", "content", "query", "--uri", _CONTROLLED_CANARY_URI],
            timeout=min(30, max(1, context.budget.remaining(30))),
        )
        observed = self._controlled_canary_readback(preflight.stdout)
        verified = bool(
            seed.exit_code == 0 and not seed.timed_out and not seed.canceled
            and preflight.exit_code == 0 and not preflight.timed_out and not preflight.canceled
            and observed is not None
            and observed[0] == experiment.experiment_id
            and observed[2] == 0
            and observed[3] is None
        )
        token_sha256 = observed[1] if observed is not None else None
        # The target generates its secret internally; shell sees only its hash.
        # Persist a bounded receipt rather than a raw shell transcript.
        receipt = {
            "schema_version": "1.0",
            "experiment_id": experiment.experiment_id,
            "fixture_id": experiment.request.fixture_id,
            "target_package": experiment.target_package,
            "target_apk_sha256": target_apk_sha256,
            "apk_identity_evidence_id": apk_identity_evidence_id,
            "token_sha256": token_sha256,
            "seed_command_exit_code": seed.exit_code,
            "preflight_readback_exit_code": preflight.exit_code,
            "preflight_readback_sha256": hashlib.sha256(preflight.stdout.encode()).hexdigest(),
            "seed_verified": verified,
            "observer": "dump_permission_protected_fixture_provider",
            "checked_at": now().isoformat(),
        }
        with self.database.session_factory() as session:
            evidence = self.evidence.json(
                session,
                scan_id=context.scan_id,
                task_id=context.task_id,
                kind="web.experiment.canary_seed",
                value=receipt,
                summary=f"Controlled target Web canary seed: {experiment.experiment_id}",
                metadata={
                    "source": "platform_web_observer",
                    "experiment_id": experiment.experiment_id,
                    "nonce": experiment.nonce,
                    "finding_id": experiment.finding_id,
                    "hypothesis_id": experiment.hypothesis_id,
                    "device_serial": experiment.device_serial,
                    "fixture_id": experiment.request.fixture_id,
                    "target_package": experiment.target_package,
                    "target_apk_sha256": target_apk_sha256,
                    "apk_identity_evidence_id": apk_identity_evidence_id,
                    "token_sha256": token_sha256,
                    "seed_verified": verified,
                    "impact_contract_satisfied": False,
                },
            )
            session.commit()
        context.evidence_summaries.append(self._evidence_summary(evidence))
        if verified:
            record["token_sha256"] = token_sha256
            record["seed_evidence_id"] = evidence.id
        else:
            record["seed_evidence_id"] = evidence.id
            raise ValueError("controlled Web canary seed preflight failed")
        return {
            "seed_evidence_id": evidence.id,
            "token_sha256": token_sha256,
            "seed_verified": verified,
            "target_apk_sha256": target_apk_sha256,
            "apk_identity_evidence_id": apk_identity_evidence_id,
            "mode": "controlled_dump_protected_fixture_only",
        }

    def _verify_controlled_web_target_identity(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        *,
        artifact_path: Path,
        target_apk_sha256: str,
    ) -> str:
        """Pin the installed fixture bytes, not only its package name."""

        assert context.device is not None
        commands, identity = context.device._verify_installed_apk(
            artifact_path, experiment.target_package, context.budget,
        )
        before = len(context.evidence_summaries)
        scoped_commands = [
            (
                f"web.experiment.apk_identity_{kind.removeprefix('device.apk_identity_')}",
                result,
                {
                    **metadata,
                    "source": "platform_web_observer",
                    "experiment_id": experiment.experiment_id,
                    "nonce": experiment.nonce,
                    "finding_id": experiment.finding_id,
                    "hypothesis_id": experiment.hypothesis_id,
                    "device_serial": experiment.device_serial,
                    "target_package": experiment.target_package,
                },
            )
            for kind, result, metadata in commands
        ]
        if scoped_commands:
            self._record_commands(
                context.scan_id, context.task_id, scoped_commands,
                context.evidence_summaries,
            )
        source_ids = [
            item["id"] for item in context.evidence_summaries[before:]
        ]
        verified = bool(
            identity.get("verified") is True
            and identity.get("expected_sha256") == target_apk_sha256
            and identity.get("installed_sha256") == target_apk_sha256
            and len(source_ids) == 2
        )
        receipt = {
            "schema_version": "1.0",
            "experiment_id": experiment.experiment_id,
            "target_package": experiment.target_package,
            "target_apk_sha256": target_apk_sha256,
            "expected_sha256": identity.get("expected_sha256"),
            "installed_sha256": identity.get("installed_sha256"),
            "installed_apk_path": identity.get("installed_apk_path"),
            "verified": verified,
            "reason": identity.get("reason"),
            "source_evidence_ids": source_ids,
        }
        with self.database.session_factory() as session:
            evidence = self.evidence.json(
                session,
                scan_id=context.scan_id,
                task_id=context.task_id,
                kind="web.experiment.apk_identity",
                value=receipt,
                summary=f"Installed target APK identity: {experiment.experiment_id}",
                metadata={
                    "source": "platform_web_observer",
                    "experiment_id": experiment.experiment_id,
                    "nonce": experiment.nonce,
                    "finding_id": experiment.finding_id,
                    "hypothesis_id": experiment.hypothesis_id,
                    "device_serial": experiment.device_serial,
                    "target_package": experiment.target_package,
                    "target_apk_sha256": target_apk_sha256,
                    "verified": verified,
                },
            )
            session.commit()
        context.evidence_summaries.append(self._evidence_summary(evidence))
        if not verified:
            raise ValueError("installed controlled fixture APK SHA-256 does not match the scan")
        return evidence.id

    def _clear_controlled_web_canary(
        self,
        context: LiveProofContext,
        experiment_id: str,
    ) -> bool:
        record = self._web_canary_state.get(experiment_id)
        if record is None or record.get("task_id") != context.task_id or context.device is None:
            return False
        try:
            deleted = context.device._adb(
                [
                    "shell", "content", "delete", "--uri", _CONTROLLED_CANARY_URI,
                    "--where", f"experiment_id={experiment_id}",
                ],
                timeout=15,
            )
            remaining = context.device._adb(
                ["shell", "content", "query", "--uri", _CONTROLLED_CANARY_URI],
                timeout=15,
            )
            error_type = None
        except Exception as exc:
            deleted = None
            remaining = None
            error_type = type(exc).__name__
        cleared = bool(
            deleted is not None
            and remaining is not None
            and deleted.exit_code == 0
            and remaining.exit_code == 0
            and self._controlled_canary_readback(remaining.stdout) is None
            and "No result found." in remaining.stdout
        )
        receipt = {
            "schema_version": "1.0",
            "experiment_id": experiment_id,
            "fixture_id": record["fixture_id"],
            "seed_evidence_id": record["seed_evidence_id"],
            "target_package": context.package_name,
            "target_apk_sha256": record["target_apk_sha256"],
            "delete_exit_code": deleted.exit_code if deleted is not None else None,
            "post_clear_query_exit_code": remaining.exit_code if remaining is not None else None,
            "error_type": error_type,
            "cleared": cleared,
            "checked_at": now().isoformat(),
        }
        with self.database.session_factory() as session:
            evidence = self.evidence.json(
                session,
                scan_id=context.scan_id,
                task_id=context.task_id,
                kind="web.experiment.canary_cleanup",
                value=receipt,
                summary=f"Controlled Web canary cleanup: {experiment_id}",
                metadata={
                    "source": "platform_web_observer",
                    "experiment_id": experiment_id,
                    "nonce": record["nonce"],
                    "finding_id": record["finding_id"],
                    "hypothesis_id": record["hypothesis_id"],
                    "device_serial": record["device_serial"],
                    "fixture_id": record["fixture_id"],
                    "cleared": cleared,
                    "impact_contract_satisfied": False,
                },
            )
            session.commit()
        context.evidence_summaries.append(self._evidence_summary(evidence))
        if cleared:
            self._web_canary_state.pop(experiment_id, None)
        return cleared

    def _abort_web_experiment(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        remote_adapter: RemoteWebObserverAdapter | None,
    ) -> None:
        """Best-effort cleanup on every post-register begin failure."""

        if remote_adapter is not None:
            with suppress(Exception):
                remote_adapter.revoke(experiment.experiment_id, task_id=context.task_id)
                self._persist_remote_web_observer_receipts(context, experiment.experiment_id)
        if experiment.experiment_id in self._web_canary_state:
            with suppress(Exception):
                self._clear_controlled_web_canary(context, experiment.experiment_id)
        experiment.revoked = True

    def _capture_controlled_web_canary_effect(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        events: list[dict[str, Any]],
    ) -> tuple[str | None, str | None]:
        """Compare an attack callback with a fresh target-only readback."""

        record = self._web_canary_state.get(experiment.experiment_id)
        if record is None:
            with self.database.session_factory() as session:
                existing = list(session.scalars(select(Evidence).where(
                    Evidence.scan_id == context.scan_id,
                    Evidence.task_id == context.task_id,
                    Evidence.kind == "web.experiment.target_effect",
                )))
            matching = [
                item for item in existing
                if (item.metadata_json or {}).get("experiment_id") == experiment.experiment_id
            ]
            return (matching[-1].id, None) if matching else (None, None)
        callbacks = [
            item for item in events
            if item.get("phase") == "attack"
            and item.get("stage") == "callback"
            and item.get("event_type") == "bridge_return"
        ]
        if len(callbacks) != 1:
            cleared = self._clear_controlled_web_canary(context, experiment.experiment_id)
            gap = "controlled canary needs one attack bridge-return callback"
            if not cleared:
                gap += "; canary cleanup failed and Agent ADB remains paused"
            return None, gap
        callback = callbacks[0]
        payload = callback.get("client_payload")
        value = payload.get("value") if isinstance(payload, dict) else None
        assert context.device is not None
        readback = context.device._adb(
            ["shell", "content", "query", "--uri", _CONTROLLED_CANARY_URI],
            timeout=min(30, max(1, context.budget.remaining(30))),
        )
        observed = self._controlled_canary_readback(readback.stdout)
        attack_url = self._web_exploit_observer.url(
            experiment, base_url=experiment.observer_base_url, phase="attack",
        )
        expected_url_sha256 = hashlib.sha256(attack_url.encode()).hexdigest()
        target_readback_verified = bool(
            readback.exit_code == 0
            and not readback.timed_out
            and not readback.canceled
            and observed is not None
            and observed[0] == experiment.experiment_id
            and observed[1] == record["token_sha256"]
        )
        bridge_call_verified = bool(
            experiment.request.frame == "top"
            and observed is not None
            and observed[2] >= 1
            and observed[3] == expected_url_sha256
        )
        callback_digest = hashlib.sha256(value.encode()).hexdigest() if isinstance(value, str) else None
        callback_value_matched = bool(
            callback_digest is not None
            and hmac.compare_digest(callback_digest, record["token_sha256"])
        )
        validated = target_readback_verified and bridge_call_verified and callback_value_matched
        token_sha256 = record["token_sha256"]
        receipt = {
            "schema_version": "1.0",
            "effect_kind": "target_value_match",
            "experiment_id": experiment.experiment_id,
            "fixture_id": record["fixture_id"],
            "target_package": experiment.target_package,
            "target_apk_sha256": record["target_apk_sha256"],
            "seed_evidence_id": record["seed_evidence_id"],
            "callback_evidence_id": callback["evidence_id"],
            "value_sha256": token_sha256,
            "seed_verified": True,
            "target_readback_verified": target_readback_verified,
            "bridge_calls": observed[2] if observed is not None else None,
            "bridge_url_sha256": observed[3] if observed is not None else None,
            "bridge_call_verified": bridge_call_verified,
            "callback_value_matched": callback_value_matched,
            "target_owned_effect_validated": validated,
            "observer": "dump_permission_protected_fixture_provider",
            "readback_stdout_sha256": hashlib.sha256(readback.stdout.encode()).hexdigest(),
            "checked_at": now().isoformat(),
            "limitation": "Only the controlled non-debuggable test APK supports this shell-only canary oracle.",
        }
        with self.database.session_factory() as session:
            evidence = self.evidence.json(
                session,
                scan_id=context.scan_id,
                task_id=context.task_id,
                kind="web.experiment.target_effect",
                value=receipt,
                summary=f"Controlled target-owned Web value comparison: {experiment.experiment_id}",
                metadata={
                    "source": "platform_web_observer",
                    "experiment_id": experiment.experiment_id,
                    "nonce": experiment.nonce,
                    "finding_id": experiment.finding_id,
                    "hypothesis_id": experiment.hypothesis_id,
                    "device_serial": experiment.device_serial,
                    "fixture_id": record["fixture_id"],
                    "target_package": experiment.target_package,
                    "target_apk_sha256": record["target_apk_sha256"],
                    "callback_evidence_id": callback["evidence_id"],
                    "seed_evidence_id": record["seed_evidence_id"],
                    "value_sha256": token_sha256,
                    "effect_kind": "target_value_match",
                    "bridge_call_verified": bridge_call_verified,
                    "bridge_url_sha256": observed[3] if observed is not None else None,
                    "target_owned_effect_validated": validated,
                    "impact_contract_satisfied": False,
                },
            )
            session.commit()
        context.evidence_summaries.append(self._evidence_summary(evidence))
        cleared = self._clear_controlled_web_canary(context, experiment.experiment_id)
        if not cleared:
            return evidence.id, "controlled canary cleanup failed and Agent ADB remains paused"
        return evidence.id, None if validated else "controlled target readback did not match the attack callback"

    def begin_web_experiment(
        self,
        task_id: str,
        token: str,
        request: WebExperimentRequest,
    ) -> dict[str, Any]:
        """Freeze a bridge plan and publish only its attack page to the Agent."""

        context = self._web_context(task_id, token)
        with context.lock:
            if request.hypothesis_id not in {str(item["id"]) for item in context.hypotheses}:
                raise ValueError("Web experiment hypothesis is outside this task")
            fixture_step = None
            fixture_type = None
            target_apk_sha256 = None
            target_artifact_path = None
            with self.database.session_factory() as session:
                finding = session.get(Finding, request.finding_id)
                if finding is None or finding.scan_id != context.scan_id:
                    raise ValueError("Web experiment finding is outside this scan")
                scan = session.get(Scan, context.scan_id)
                if scan is None or scan.package_name != context.package_name:
                    raise ValueError("Web experiment target package is not bound to the scan")
                target_apk_sha256 = scan.artifact_sha256
                target_artifact_path = Path(scan.artifact_path)
                if request.fixture_id is not None:
                    fixture = session.get(ValidationFixture, request.fixture_id)
                    if (
                        fixture is None
                        or fixture.status != "active"
                        or fixture.scan_id != context.scan_id
                        or (fixture.task_id is not None and fixture.task_id != task_id)
                    ):
                        raise ValueError("Web experiment fixture is not active for this scan and task")
                    fixture_step = fixture_state_check(dict(fixture.payload or {}), fixture.id)
                    args = fixture_step.adb_args
                    if (
                        len(args) < 3
                        or args[0] != "shell"
                        or args[1] not in {
                            "dumpsys", "pm", "content", "pidof", "ps", "getprop", "uiautomator",
                        }
                        or (args[1] == "pm" and args[2] not in {"dump", "get-app-links", "path"})
                        or (args[1] == "content" and args[2] != "query")
                        or (args[1] == "uiautomator" and args[2] != "dump")
                    ):
                        raise ValueError("Web fixture state_check must be a read-only device query")
                    fixture_type = fixture.fixture_type
            local_base_url = self.ensure_live_proof_endpoint()
            remote_adapter = (
                self._ensure_remote_web_observer_adapter()
                if self.settings.web_observer_remote_enabled else None
            )
            base_url = (
                self.settings.web_observer_public_base_url
                if remote_adapter is not None else local_base_url
            )
            assert base_url is not None
            port = urlsplit(local_base_url).port
            assert port is not None
            with self._live_proof_lock:
                needs_reverse = (
                    remote_adapter is None
                    and task_id not in self._web_observer_reverse_tasks
                )
            if needs_reverse:
                reverse = context.device.install_web_observer_reverse(port)
                if reverse.exit_code != 0:
                    detail = (reverse.stderr or reverse.stdout).strip()[:300]
                    raise ValueError(
                        "ADB reverse could not expose the platform Web observer"
                        + (f": {detail}" if detail else "")
                    )
                self._record_commands(
                    context.scan_id,
                    task_id,
                    [("web.experiment.device_reverse", reverse, {"source": "platform", "device_serial": context.device.serial, "observer_port": port})],
                    context.evidence_summaries,
                )
                with self._live_proof_lock:
                    self._web_observer_reverse_tasks.add(task_id)
            experiment, public_plan = self._web_exploit_observer.register(
                request,
                scan_id=context.scan_id,
                task_id=task_id,
                device_serial=context.device.serial,
                target_package=context.package_name,
                base_url=base_url,
                lifetime_seconds=min(600, max(1, context.budget.remaining(600))),
            )
            public_plan["target_apk_sha256"] = target_apk_sha256
            if fixture_step is not None:
                try:
                    public_plan["state_fixture"] = self._verify_web_fixture_state(
                        context, experiment, fixture_step, str(fixture_type),
                    )
                except Exception:
                    self._abort_web_experiment(context, experiment, remote_adapter)
                    raise
            if (
                fixture_type == "canary"
                and context.package_name == _CONTROLLED_CANARY_PACKAGE
                and public_plan.get("state_fixture", {}).get("verified") is True
            ):
                try:
                    identity_id = self._verify_controlled_web_target_identity(
                        context, experiment,
                        artifact_path=target_artifact_path,
                        target_apk_sha256=str(target_apk_sha256),
                    )
                    public_plan["apk_identity_evidence_id"] = identity_id
                    public_plan["controlled_canary"] = self._seed_controlled_web_canary(
                        context, experiment,
                        target_apk_sha256=str(target_apk_sha256),
                        apk_identity_evidence_id=identity_id,
                    )
                except Exception:
                    self._abort_web_experiment(context, experiment, remote_adapter)
                    raise
            if remote_adapter is not None:
                try:
                    remote_session = remote_adapter.deploy(experiment, task_id=task_id)
                    public_plan["observer_transport"] = "ssh_reverse_https"
                    public_plan["remote_deployment_id"] = (
                        remote_session.deployment.deployment_id
                    )
                    public_plan["attack_url"] = remote_session.attack_url
                    with self._live_proof_lock:
                        self._web_observer_remote_tasks.setdefault(task_id, set()).add(
                            experiment.experiment_id
                        )
                    self._persist_remote_web_observer_receipts(
                        context, experiment.experiment_id
                    )
                except Exception:
                    self._abort_web_experiment(context, experiment, remote_adapter)
                    raise
            if request.entry_scheme == "https":
                try:
                    app_links = context.device.execute_gateway(
                        ["shell", "pm", "get-app-links", context.package_name],
                        timeout=min(20, max(1, context.budget.remaining(20))),
                        policy=context.adb_policy,
                    )
                    before_app_links = len(context.evidence_summaries)
                    self._record_commands(
                        context.scan_id,
                        task_id,
                        [
                            (
                                "web.experiment.app_link_state",
                                app_links,
                                {
                                    "source": "platform_web_observer",
                                    "experiment_id": experiment.experiment_id,
                                    "nonce": experiment.nonce,
                                    "finding_id": request.finding_id,
                                    "hypothesis_id": request.hypothesis_id,
                                    "device_serial": context.device.serial,
                                    "stage": "app_link_state",
                                    "impact_contract_satisfied": False,
                                },
                            )
                        ],
                        context.evidence_summaries,
                    )
                    if len(context.evidence_summaries) > before_app_links:
                        experiment.app_link_state_evidence_id = context.evidence_summaries[-1]["id"]
                        public_plan["coverage_plan"]["app_link_state_evidence_id"] = (
                            experiment.app_link_state_evidence_id
                        )
                except Exception:
                    self._abort_web_experiment(context, experiment, remote_adapter)
                    raise
            metadata = {
                "source": "platform_web_observer",
                "experiment_id": experiment.experiment_id,
                "nonce": experiment.nonce,
                "finding_id": request.finding_id,
                "hypothesis_id": request.hypothesis_id,
                "device_serial": context.device.serial,
                "stage": "plan",
                "started_at": experiment.created_at.isoformat(),
                "deadline": experiment.deadline.isoformat(),
                "impact_contract_satisfied": False,
            }
            try:
                with self.database.session_factory() as session:
                    evidence = self.evidence.json(
                        session,
                        scan_id=context.scan_id,
                        task_id=task_id,
                        kind="web.experiment.plan",
                        value=public_plan,
                        summary=f"Platform Web experiment plan: {experiment.experiment_id}",
                        metadata=metadata,
                    )
                    session.commit()
            except Exception:
                self._abort_web_experiment(context, experiment, remote_adapter)
                raise
            try:
                context.evidence_summaries.append(self._evidence_summary(evidence))
                self._materialize_live_evidence(context, context.evidence_summaries)
                self._record_exploration_event(
                    context.scan_id,
                    task_id,
                    "web_experiment.planned",
                    "平台已冻结 Web 实验并部署受控页面",
                    {"source": "platform", "experiment_id": experiment.experiment_id, "evidence_id": evidence.id},
                )
                return {**public_plan, "plan_evidence_id": evidence.id}
            except Exception:
                self._abort_web_experiment(context, experiment, remote_adapter)
                raise

    def _persist_web_observer_event(
        self,
        experiment: WebExperiment,
        event: dict[str, Any],
    ) -> str:
        """Persist callback metadata without retaining returned bridge values."""

        persisted = dict(event)
        client_payload = event.get("client_payload")
        if isinstance(client_payload, dict):
            safe_payload = {
                key: client_payload[key]
                for key in (
                    "experiment_id", "nonce", "event_type", "bridge_name",
                    "method", "frame_url", "top_url",
                )
                if key in client_payload
            }
            value = client_payload.get("value")
            if isinstance(value, str):
                safe_payload["value_sha256"] = hashlib.sha256(value.encode()).hexdigest()
                safe_payload["value_length"] = len(value)
            error = client_payload.get("error")
            if isinstance(error, str):
                safe_payload["error_sha256"] = hashlib.sha256(error.encode()).hexdigest()
                safe_payload["error_length"] = len(error)
            persisted["client_payload"] = safe_payload

        metadata = {
            "source": "platform_web_observer",
            "experiment_id": experiment.experiment_id,
            "nonce": experiment.nonce,
            "phase_nonce": event["phase_nonce"],
            "phase": event["phase"],
            "stage": event["stage"],
            "event_type": event["event_type"],
            "finding_id": experiment.finding_id,
            "hypothesis_id": experiment.hypothesis_id,
            "device_serial": experiment.device_serial,
            "received_at": event["received_at"],
            "started_at": experiment.created_at.isoformat(),
            "deadline": experiment.deadline.isoformat(),
            "client_reported": event["client_reported"],
            "impact_contract_satisfied": False,
        }
        with self.database.session_factory() as session:
            evidence = self.evidence.json(
                session,
                scan_id=experiment.scan_id,
                task_id=experiment.task_id,
                kind="web.experiment.event",
                value=persisted,
                summary=f"Web observer {event['phase']} {event['event_type']}: {experiment.experiment_id}",
                metadata=metadata,
            )
            session.commit()
            return evidence.id

    def _persist_remote_web_observer_receipts(
        self,
        context: LiveProofContext,
        experiment_id: str,
    ) -> None:
        adapter = getattr(self, "_web_observer_remote_adapter", None)
        if adapter is None:
            return
        experiment = self._web_exploit_observer.get(
            experiment_id, task_id=context.task_id,
        )
        for receipt in adapter.receipts(experiment_id, task_id=context.task_id):
            if receipt.request_id in self._web_observer_remote_receipt_ids:
                continue
            value = {
                "schema_version": "1.0",
                **asdict(receipt),
                "public_base_url": experiment.observer_base_url,
                "device_serial": experiment.device_serial,
                "warning": "A public route receipt is not proof of target execution or impact.",
            }
            with self.database.session_factory() as session:
                evidence = self.evidence.json(
                    session,
                    scan_id=context.scan_id,
                    task_id=context.task_id,
                    kind="web.experiment.remote_receipt",
                    value=value,
                    summary=(
                        f"Remote Web observer {receipt.action}: "
                        f"{experiment.experiment_id}"
                    ),
                    metadata={
                        "source": "platform_web_observer",
                        "experiment_id": experiment.experiment_id,
                        "nonce": experiment.nonce,
                        "finding_id": experiment.finding_id,
                        "hypothesis_id": experiment.hypothesis_id,
                        "device_serial": experiment.device_serial,
                        "stage": f"remote_{receipt.action}",
                        "deployment_id": receipt.deployment_id,
                        "tunnel_id": receipt.tunnel_id,
                        "public_probe_ok": receipt.public_probe_ok,
                        "impact_contract_satisfied": False,
                    },
                )
                session.commit()
            self._web_observer_remote_receipt_ids.add(receipt.request_id)
            context.evidence_summaries.append(self._evidence_summary(evidence))

    def snapshot_web_experiment(
        self,
        task_id: str,
        token: str,
        experiment_id: str,
        request: WebExperimentSnapshotRequest,
    ) -> dict[str, Any]:
        """Freeze current events and optionally join task-owned PoC execution receipts."""

        context = self._web_context(task_id, token)
        with context.lock:
            experiment = self._web_exploit_observer.get(experiment_id, task_id=task_id)
            if experiment.scan_id != context.scan_id or experiment.device_serial != context.device.serial:
                raise ValueError("Web experiment device or scan does not match the task")
            control_gaps: list[str] = []
            if request.run_controls:
                control_gaps.extend(self._run_web_experiment_controls(context, experiment))
            # Freeze the remote-health receipt after the controls, so the
            # snapshot cannot rely on a probe that predates their execution.
            if self.settings.web_observer_remote_enabled:
                adapter = self._ensure_remote_web_observer_adapter()
                if not adapter.health(experiment_id, task_id=task_id):
                    control_gaps.append("remote HTTPS observer tunnel is unhealthy")
                self._persist_remote_web_observer_receipts(context, experiment_id)
            events = self._web_exploit_observer.events(experiment_id, task_id=task_id)
            has_attack_page = any(item["phase"] == "attack" and item["event_type"] in {"page", "frame"} for item in events)
            has_attack_callback = any(item["phase"] == "attack" and item["stage"] == "callback" for item in events)
            has_control = any(item["phase"] == "control" and item["event_type"] == "bridge_missing" for item in events)
            has_quiet = any(item["phase"] == "quiet" and item["event_type"] == "no_bridge_requested" for item in events)
            controls_validated = bool(
                experiment.control_launch_evidence_id
                and experiment.quiet_launch_evidence_id
                and has_control
                and has_quiet
                and not control_gaps
            )
            receipt_id, execution_gaps = self._web_execution_receipt(context, experiment, request, events)
            try:
                effect_id, effect_gap = self._capture_controlled_web_canary_effect(
                    context, experiment, events,
                )
            except Exception as exc:
                cleared = self._clear_controlled_web_canary(
                    context, experiment.experiment_id,
                )
                effect_id = None
                effect_gap = (
                    f"controlled canary readback failed ({type(exc).__name__}); "
                    + (
                        "canary was cleared"
                        if cleared else "cleanup failed and Agent ADB remains paused"
                    )
                )
            if effect_gap is not None:
                execution_gaps.append(effect_gap)
            target_effect_validated = False
            if effect_id is not None:
                with self.database.session_factory() as session:
                    effect_evidence = session.get(Evidence, effect_id)
                    target_effect_validated = bool(
                        effect_evidence is not None
                        and (effect_evidence.metadata_json or {}).get(
                            "target_owned_effect_validated"
                        ) is True
                    )
            target_observation: dict[str, Any] = {}
            if receipt_id is not None:
                with self.database.session_factory() as session:
                    execution_evidence = session.get(Evidence, receipt_id)
                    if execution_evidence is not None:
                        observed = (execution_evidence.metadata_json or {}).get("target_observation")
                        if isinstance(observed, dict):
                            target_observation = observed
            fixture_state = self._frozen_web_fixture_state(experiment)
            coverage_matrix = self._web_coverage_matrix(
                experiment,
                events,
                execution_correlated=receipt_id is not None,
                controls_validated=controls_validated,
                fixture_state=fixture_state,
                target_observation=target_observation,
                target_effect_validated=target_effect_validated,
            )
            snapshot = {
                "schema_version": "1.0",
                "experiment_id": experiment.experiment_id,
                "nonce": experiment.nonce,
                "captured_at": now().isoformat(),
                "event_evidence_ids": [item["evidence_id"] for item in events],
                "event_count": len(events),
                "attack_page_observed": has_attack_page,
                "attack_callback_observed": has_attack_callback,
                "controls_validated": controls_validated,
                "control_launch_evidence_id": experiment.control_launch_evidence_id,
                "quiet_launch_evidence_id": experiment.quiet_launch_evidence_id,
                "execution_evidence_id": receipt_id,
                "effect_evidence_id": effect_id,
                "fixture_state_evidence_id": fixture_state.get("state_check_evidence_id"),
                "coverage_matrix": coverage_matrix,
                "uncovered_obligations": coverage_matrix["uncovered_obligations"],
                "gaps": execution_gaps,
                "control_gaps": control_gaps,
                "warning": "Callbacks are client reports; their content is not an impact verdict.",
            }
            with self.database.session_factory() as session:
                evidence = self.evidence.json(
                    session,
                    scan_id=context.scan_id,
                    task_id=task_id,
                    kind="web.experiment.snapshot",
                    value=snapshot,
                    summary=f"Web experiment snapshot: {experiment_id}",
                    metadata={
                        "source": "platform_web_observer",
                        "experiment_id": experiment_id,
                        "nonce": experiment.nonce,
                        "device_serial": experiment.device_serial,
                        "finding_id": experiment.finding_id,
                        "hypothesis_id": experiment.hypothesis_id,
                        "stage": "snapshot",
                        "captured_at": snapshot["captured_at"],
                        "controls_validated": controls_validated,
                        "impact_contract_satisfied": False,
                    },
                )
                session.commit()
            new_ids = [item["evidence_id"] for item in events]
            new_ids.extend(item for item in (receipt_id, effect_id, evidence.id, experiment.control_launch_evidence_id, experiment.quiet_launch_evidence_id) if item)
            with self.database.session_factory() as session:
                for item in session.scalars(select(Evidence).where(Evidence.id.in_(new_ids))):
                    summary = self._evidence_summary(item)
                    if summary not in context.evidence_summaries:
                        context.evidence_summaries.append(summary)
            self._materialize_live_evidence(context, context.evidence_summaries)
            return {**snapshot, "snapshot_evidence_id": evidence.id}

    def _web_coverage_matrix(
        self,
        experiment: WebExperiment,
        events: list[dict[str, Any]],
        *,
        execution_correlated: bool,
        controls_validated: bool,
        fixture_state: dict[str, Any],
        target_observation: dict[str, Any],
        target_effect_validated: bool,
    ) -> dict[str, Any]:
        """Report covered and missing route/content/bridge cases without inventing coverage."""

        observed = {(item["phase"], item["event_type"]) for item in events}
        callback = next(
            (
                item for item in events
                if item["phase"] == "attack" and item["stage"] == "callback"
            ),
            None,
        )
        cases: list[dict[str, Any]] = []
        for frame in ("top", "iframe", "redirect"):
            selected = experiment.request.frame == frame
            page_observed = ("attack", "page") in observed
            if frame == "iframe":
                page_observed = page_observed and ("attack", "frame") in observed
            if frame == "redirect":
                page_observed = page_observed and ("attack", "redirect") in observed
            cases.append({
                "case_id": f"attack.{frame}",
                "selected": selected,
                "status": "observed" if selected and page_observed else "unobserved" if selected else "not_selected",
            })
        cases.extend([
            {
                "case_id": "control.chrome_bridge_missing",
                "selected": True,
                "status": "observed" if experiment.control_launch_evidence_id and ("control", "bridge_missing") in observed else "unobserved",
            },
            {
                "case_id": "control.chrome_quiet",
                "selected": True,
                "status": "observed" if experiment.quiet_launch_evidence_id and ("quiet", "no_bridge_requested") in observed else "unobserved",
            },
            {
                "case_id": "execution.ordinary_app",
                "selected": True,
                "status": "correlated" if execution_correlated else "unverified",
            },
            {
                "case_id": "content.target_webview_final_url",
                "selected": True,
                "status": "confirmed" if experiment.final_url else "unverified",
            },
            {
                "case_id": "bridge.callback",
                "selected": True,
                "status": "client_reported" if callback is not None else "unobserved",
            },
            {
                "case_id": "impact.controlled_target_canary",
                "selected": experiment.request.fixture_id is not None,
                "status": "validated" if target_effect_validated else "unverified",
            },
        ])
        obligations: list[str] = []
        if experiment.request.entry_scheme is None or experiment.request.entry_host is None:
            obligations.append("Deep Link scheme/host route has not been recorded")
        if not execution_correlated:
            obligations.append("ordinary-app launch and target WebView final URL are not independently correlated")
        if not controls_validated:
            obligations.append("Chrome bridge-missing and quiet-page controls are incomplete")
        if callback is None:
            obligations.append("no attack-page bridge callback was received")
        fixture_state_verified = bool(
            experiment.request.fixture_id is not None
            and fixture_state.get("fixture_id") == experiment.request.fixture_id
            and fixture_state.get("verified") is True
        )
        if not fixture_state_verified:
            obligations.append("victim session state has no verified platform fixture assertion")
        if experiment.request.entry_scheme == "https" and experiment.app_link_state_evidence_id is None:
            obligations.append("Android App Link verification state was not captured")
        if target_effect_validated:
            obligations.append("target-owned canary was compared, but impact still needs semantic review")
        else:
            obligations.append("callback value or void effect still needs an independent harm Oracle and semantic review")
        attack_url = self._web_exploit_observer.url(
            experiment,
            base_url=experiment.observer_base_url,
            phase="attack",
        )
        parsed = urlsplit(attack_url)
        client_payload = callback.get("client_payload", {}) if callback else {}
        return {
            "schema_version": "1.0",
            "entry_route": {
                "scheme": experiment.request.entry_scheme,
                "host": experiment.request.entry_host,
                "path": experiment.request.entry_path,
                "query_keys": experiment.request.entry_query_keys,
                "source": "agent_planned_unverified",
            },
            "observer_origin": f"{parsed.scheme}://{parsed.netloc}",
            "final_url": experiment.final_url,
            "final_url_source": "target_uid_onPageFinished" if experiment.final_url else None,
            "target_observation": target_observation or {
                "status": "unverified",
                "trust_tier": "none",
                "frame_origin_verified": False,
                "bridge_call_verified": False,
                "gaps": ["No correlated target-side Web observation receipt"],
            },
            "redirect_observed": ("attack", "redirect") in observed,
            "frame_context": experiment.request.frame,
            "client_reported_frame_url": client_payload.get("frame_url"),
            "client_reported_top_url": client_payload.get("top_url"),
            "bridge_method": f"{experiment.request.bridge_name}.{experiment.request.method}",
            "bridge_callback_kind": callback["event_type"] if callback else None,
            "target_effect_validated": target_effect_validated,
            "victim_state": experiment.request.victim_state,
            "fixture_id": experiment.request.fixture_id,
            "fixture_state_verified": fixture_state_verified,
            "fixture_state_evidence_id": fixture_state.get("state_check_evidence_id"),
            "app_link_state_evidence_id": experiment.app_link_state_evidence_id,
            "cases": cases,
            "uncovered_obligations": obligations,
        }

    def _run_web_experiment_controls(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
    ) -> list[str]:
        """Launch both negative controls in Chrome, recording each command."""

        assert context.device is not None
        gaps: list[str] = []
        for phase, attribute in (
            ("control", "control_launch_evidence_id"),
            ("quiet", "quiet_launch_evidence_id"),
        ):
            if getattr(experiment, attribute) is not None or context.budget.expired:
                continue
            url = self._web_exploit_observer.url(
                experiment,
                base_url=experiment.observer_base_url,
                phase=phase,
            )
            if self.settings.web_observer_remote_enabled:
                wake, unlock, result = context.device.launch_web_observer_browser_control(
                    url,
                    allowed_https_origin=self.settings.web_observer_public_base_url,
                )
            else:
                wake, unlock, result = context.device.launch_web_observer_browser_control(url)
            before = len(context.evidence_summaries)
            self._record_commands(
                context.scan_id,
                context.task_id,
                [
                    (
                        "web.experiment.control_wake",
                        wake,
                        {
                            "source": "platform_web_observer",
                            "experiment_id": experiment.experiment_id,
                            "nonce": experiment.nonce,
                            "phase": phase,
                            "phase_nonce": experiment.phase_nonces[phase],
                            "stage": "control_wake",
                            "finding_id": experiment.finding_id,
                            "hypothesis_id": experiment.hypothesis_id,
                            "device_serial": experiment.device_serial,
                            "impact_contract_satisfied": False,
                        },
                    ),
                    (
                        "web.experiment.control_unlock",
                        unlock,
                        {
                            "source": "platform_web_observer",
                            "experiment_id": experiment.experiment_id,
                            "nonce": experiment.nonce,
                            "phase": phase,
                            "phase_nonce": experiment.phase_nonces[phase],
                            "stage": "control_unlock",
                            "finding_id": experiment.finding_id,
                            "hypothesis_id": experiment.hypothesis_id,
                            "device_serial": experiment.device_serial,
                            "impact_contract_satisfied": False,
                        },
                    ),
                    (
                        "web.experiment.control_launch",
                        result,
                        {
                            "source": "platform_web_observer",
                            "experiment_id": experiment.experiment_id,
                            "nonce": experiment.nonce,
                            "phase": phase,
                            "phase_nonce": experiment.phase_nonces[phase],
                            "stage": "control_launch",
                            "finding_id": experiment.finding_id,
                            "hypothesis_id": experiment.hypothesis_id,
                            "device_serial": experiment.device_serial,
                            "browser_package": "com.android.chrome",
                            "launch_accepted": (
                                result.exit_code == 0
                                and wake.exit_code == 0
                                and unlock.exit_code == 0
                                and AdbDeviceAdapter._poc_launch_diagnostics(result)["launch_accepted"] is True
                            ),
                            "impact_contract_satisfied": False,
                        },
                    )
                ],
                context.evidence_summaries,
            )
            if any(item.exit_code != 0 for item in (wake, unlock, result)) or len(context.evidence_summaries) <= before:
                gaps.append(f"Chrome {phase} control launch failed")
                continue
            launch_accepted = AdbDeviceAdapter._poc_launch_diagnostics(result)["launch_accepted"]
            if launch_accepted is not True:
                gaps.append(f"Chrome {phase} control was not accepted by Activity Manager")
                continue
            setattr(experiment, attribute, context.evidence_summaries[-1]["id"])
            until = time.monotonic() + min(6, max(1, context.budget.remaining(6)))
            while time.monotonic() < until:
                current = self._web_exploit_observer.events(
                    experiment.experiment_id,
                    task_id=context.task_id,
                )
                if any(item["phase"] == phase and item["stage"] == "callback" for item in current):
                    break
                time.sleep(0.1)
            else:
                gaps.append(f"Chrome {phase} control produced no callback")
        return gaps

    def _web_execution_receipt(
        self,
        context: LiveProofContext,
        experiment: WebExperiment,
        request: WebExperimentSnapshotRequest,
        events: list[dict[str, Any]],
    ) -> tuple[str | None, list[str]]:
        if experiment.execution_evidence_id is not None:
            return experiment.execution_evidence_id, []
        ids = (
            request.launch_evidence_id,
            request.process_evidence_id,
            request.target_evidence_id,
        )
        if not any(ids):
            return None, ["ordinary-app launch, process, and correlated input receipts were not supplied"]
        if not all(ids):
            return None, ["launch_evidence_id, process_evidence_id, and target_evidence_id must be supplied together"]
        if not any(item["phase"] == "attack" and item["event_type"] in {"page", "frame"} for item in events):
            return None, ["the platform observer did not receive the attack page request"]
        assert context.device is not None
        with self.database.session_factory() as session:
            evidence_by_id = {
                item.id: item
                for item in session.scalars(select(Evidence).where(Evidence.id.in_(ids)))
            }
            if len(evidence_by_id) != 3:
                return None, ["one or more execution receipt IDs do not exist"]
            launch, process, correlated = (evidence_by_id[item] for item in ids)
            if [launch.kind, process.kind] != ["blackbox.poc_launch", "blackbox.poc_process"]:
                return None, ["execution receipts must be a platform PoC launch and process probe"]
            request_id = launch.metadata_json.get("request_id")
            if not isinstance(request_id, str) or not request_id:
                return None, ["PoC launch has no platform request ID"]
            observed_time_fields = (
                (launch, "launch_started_at"),
                (process, "observed_at"),
                (correlated, "observed_at"),
            )
            for item, time_field in observed_time_fields:
                try:
                    observed_at = datetime.fromisoformat(item.metadata_json[time_field])
                except (KeyError, TypeError, ValueError):
                    return None, [f"PoC receipt lacks a trusted {time_field} execution timestamp"]
                if observed_at.tzinfo is None:
                    return None, ["PoC execution timestamp has no timezone"]
                if (
                    item.scan_id != context.scan_id
                    or item.task_id != context.task_id
                    or item.metadata_json.get("device_serial") != experiment.device_serial
                    or item.metadata_json.get("request_id") != request_id
                ):
                    return None, [f"{item.kind} scan, task, device, or request does not match"]
                if not experiment.created_at <= observed_at <= experiment.deadline:
                    return None, [f"{item.kind} execution timestamp is outside the experiment window"]
            poc_package = launch.metadata_json.get("poc_package")
            if (
                launch.exit_code != 0
                or launch.metadata_json.get("launch_accepted") is not True
                or not isinstance(poc_package, str)
                or poc_package == experiment.target_package
                or launch.metadata_json.get("caller_identity") not in {"agent_poc_app", "platform_poc_app"}
                or process.exit_code != 0
                or process.metadata_json.get("poc_package") != poc_package
                or not process.metadata_json.get("process_ids")
            ):
                return None, ["ordinary-app PoC UID execution was not established"]
            try:
                correlated_payload = self.store.read_json_artifact(
                    "evidence", correlated.path, correlated.sha256
                )
            except (OSError, ValueError, json.JSONDecodeError):
                return None, ["correlation evidence artifact could not be verified"]
            target_observation = assess_target_web_observation(
                evidence_kind=correlated.kind,
                stdout=str(correlated_payload.get("stdout", "")),
                oracle=correlated.metadata_json.get("oracle"),
                experiment_id=experiment.experiment_id,
                attack_nonce=experiment.phase_nonces["attack"],
                observer_origin=experiment.observer_base_url,
                frame=experiment.request.frame,
            )
            if target_observation.status != "observed":
                return None, list(target_observation.gaps)
            experiment.final_url = target_observation.main_frame_url
            page_times = [
                datetime.fromisoformat(item["received_at"])
                for item in events
                if item["phase"] == "attack" and item["event_type"] in {"page", "frame"}
            ]
            launch_time = datetime.fromisoformat(launch.metadata_json["launch_started_at"])
            if not any(launch_time <= received_at <= experiment.deadline for received_at in page_times):
                return None, ["attack page was not received after the ordinary-app launch"]
        target_process = context.device.execute_gateway(
            ["shell", "pidof", experiment.target_package],
            timeout=min(15, max(1, context.budget.remaining(15))),
            policy=context.adb_policy,
        )
        before = len(context.evidence_summaries)
        self._record_commands(
            context.scan_id,
            context.task_id,
            [
                (
                    "web.experiment.target_process",
                    target_process,
                    {
                        "source": "platform_web_observer",
                        "experiment_id": experiment.experiment_id,
                        "nonce": experiment.nonce,
                        "stage": "target_process",
                        "finding_id": experiment.finding_id,
                        "hypothesis_id": experiment.hypothesis_id,
                        "device_serial": experiment.device_serial,
                        "target_package": experiment.target_package,
                        "request_id": request_id,
                        "impact_contract_satisfied": False,
                    },
                )
            ],
            context.evidence_summaries,
        )
        target_process_evidence_id = context.evidence_summaries[before]["id"]
        target_process_observed = (
            target_process.exit_code == 0
            and bool(re.fullmatch(r"\s*\d+(?:\s+\d+)*\s*", target_process.stdout))
        )
        if not target_process_observed:
            return None, ["the target process was not independently observed on the leased device"]
        value = {
            "schema_version": "1.0",
            "experiment_id": experiment.experiment_id,
            "nonce": experiment.nonce,
            "device_serial": experiment.device_serial,
            "finding_id": experiment.finding_id,
            "hypothesis_id": experiment.hypothesis_id,
            "request_id": request_id,
            "launch_started_at": launch.metadata_json["launch_started_at"],
            "launch_evidence_id": launch.id,
            "process_evidence_id": process.id,
            "input_correlation_evidence_id": correlated.id,
            "webview_confirmation_evidence_id": correlated.id,
            "target_process_evidence_id": target_process_evidence_id,
            "ordinary_app_uid_verified": True,
            "target_process_observed": True,
            "webview_in_target_confirmed": True,
            "final_url": experiment.final_url,
            "target_observation": target_observation.as_dict(),
            "impact_contract_satisfied": False,
            "limitation": "A target-UID onPageFinished log confirms the URL load; bridge callback content and impact still require semantic review and controls.",
        }
        with self.database.session_factory() as session:
            evidence = self.evidence.json(
                session,
                scan_id=context.scan_id,
                task_id=context.task_id,
                kind="web.experiment.execution",
                value=value,
                summary=f"Correlated ordinary-app Web execution: {experiment.experiment_id}",
                metadata={
                    "source": "platform_web_observer",
                    "experiment_id": experiment.experiment_id,
                    "nonce": experiment.nonce,
                    "stage": "execution",
                    "finding_id": experiment.finding_id,
                    "hypothesis_id": experiment.hypothesis_id,
                    "device_serial": experiment.device_serial,
                    "request_id": request_id,
                    "launch_started_at": launch.metadata_json["launch_started_at"],
                    "launch_evidence_id": launch.id,
                    "process_evidence_id": process.id,
                    "webview_confirmation_evidence_id": correlated.id,
                    "target_process_evidence_id": target_process_evidence_id,
                    "ordinary_app_uid_verified": True,
                    "target_process_observed": True,
                    "webview_in_target_confirmed": True,
                    "final_url": experiment.final_url,
                    "target_observation": target_observation.as_dict(),
                    "impact_contract_satisfied": False,
                },
            )
            session.commit()
        experiment.execution_evidence_id = evidence.id
        return evidence.id, []

    def record_live_runtime_observation(
        self,
        task_id: str,
        token: str,
        observation: AgentRuntimeObservation,
    ) -> dict[str, Any]:
        """Persist a flexible runtime fact without pretending it is a proof verdict."""

        with self._live_proof_lock:
            context = self._live_proof_contexts.get(task_id)
        if context is None or not secrets.compare_digest(context.token, token):
            raise PermissionError("runtime observation intake is not active for this task")
        self._raise_if_cancelled(context.cancel_event)
        budget = getattr(context, "budget", None)
        if budget is not None and budget.expired:
            raise TimeoutError("task time budget is exhausted")
        if observation.capture is not None:
            with context.lock:
                with self.database.session_factory() as session:
                    finding = session.get(Finding, observation.finding_id) if observation.finding_id else None
                    if finding is None or finding.scan_id != context.scan_id:
                        raise ValueError("external capture requires a finding in this scan")
                captured = capture_external_observation(
                    observation.capture,
                    allowed_origins=self.settings.external_observer_origins,
                    timeout=max(1, budget.remaining(20)) if budget is not None else 20,
                )
                observer = getattr(self, "_web_exploit_observer", None)
                registered_experiment = None
                if observer is not None:
                    with suppress(ValueError):
                        registered_experiment = observer.get(
                            observation.capture.experiment_id,
                            task_id=task_id,
                        )
                if registered_experiment is not None and (
                    observation.capture.nonce != registered_experiment.nonce
                    or observation.finding_id != registered_experiment.finding_id
                ):
                    raise ValueError("external capture does not match the registered experiment")
                self._raise_if_cancelled(context.cancel_event)
                if budget is not None and budget.expired:
                    raise TimeoutError("task time budget is exhausted")
                with self.database.session_factory() as session:
                    captured_at = now().isoformat()
                    captured_evidence = self.evidence.json(
                        session,
                        scan_id=context.scan_id,
                        task_id=task_id,
                        kind="external.observation.capture",
                        value={**captured, "captured_at": captured_at},
                        summary=f"External {observation.capture.stage}: {observation.capture.experiment_id}",
                        metadata={
                            "external_observation_captured": True,
                            "finding_id": observation.finding_id,
                            "experiment_id": observation.capture.experiment_id,
                            "nonce": registered_experiment.nonce if registered_experiment else None,
                            "hypothesis_id": (
                                registered_experiment.hypothesis_id
                                if registered_experiment else None
                            ),
                            "device_serial": context.device.serial if context.device else None,
                            "stage": observation.capture.stage,
                            "captured_at": captured_at,
                            "started_at": (
                                registered_experiment.created_at.isoformat()
                                if registered_experiment else None
                            ),
                            "deadline": (
                                registered_experiment.deadline.isoformat()
                                if registered_experiment else None
                            ),
                            "experiment_registered": registered_experiment is not None,
                            "device_execution_verified": False,
                            "source": "platform_http_capture",
                            "impact_contract_satisfied": False,
                        },
                    )
                    session.commit()
                    context.evidence_summaries.append(self._evidence_summary(captured_evidence))
                    observation = observation.model_copy(update={
                        "evidence_ids": [*observation.evidence_ids, captured_evidence.id],
                    })
                self._materialize_live_evidence(context, context.evidence_summaries)
        value = observation.model_dump(mode="json")
        observation_key = hashlib.sha256(
            json.dumps(
                {
                    "scan_id": context.scan_id,
                    "task_id": task_id,
                    **value,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        with self.database.session_factory() as session:
            existing = session.scalar(
                select(RuntimeObservation).where(
                    RuntimeObservation.observation_key == observation_key
                )
            )
            if existing is not None:
                existing_evidence_ids = (
                    [
                        evidence_id
                        for evidence_id in existing.evidence_ids
                        if isinstance(evidence_id, str) and evidence_id
                    ]
                    if isinstance(existing.evidence_ids, list)
                    else []
                )
                finding = (
                    session.get(Finding, existing.finding_id)
                    if existing.finding_id is not None
                    else None
                )
                existing_source_evidence = list(
                    session.scalars(
                        select(Evidence).where(
                            Evidence.scan_id == context.scan_id,
                            Evidence.id.in_(existing_evidence_ids),
                        )
                    )
                )
                if finding is not None and any(
                    evidence_supports_runtime_observation(item)
                    for item in existing_source_evidence
                ):
                    projected = self._project_runtime_observation_gap(
                        finding,
                        observation_id=existing.id,
                        evidence_ids=existing_evidence_ids,
                        task_id=task_id,
                        observation_kind=existing.kind,
                    )
                    if projected:
                        invalidate_scan_materialized_summary(
                            session,
                            context.scan_id,
                            reason="runtime_observation_projection",
                        )
                    session.commit()
                return {
                    "schema_version": "1.0",
                    "id": existing.id,
                    "observation_key": existing.observation_key,
                    "deduplicated": True,
                }
            finding: Finding | None = None
            if observation.finding_id is not None:
                finding = session.get(Finding, observation.finding_id)
                if finding is None or finding.scan_id != context.scan_id:
                    raise ValueError("runtime observation finding is outside this scan")
            known_evidence = (
                list(
                    session.scalars(
                        select(Evidence).where(
                            Evidence.scan_id == context.scan_id,
                            Evidence.id.in_(observation.evidence_ids),
                        )
                    )
                )
                if observation.evidence_ids
                else []
            )
            known_evidence_by_id = {item.id: item for item in known_evidence}
            known_evidence_ids = set(known_evidence_by_id)
            if not set(observation.evidence_ids) <= known_evidence_ids:
                raise ValueError("runtime observation references unknown evidence")
            evidence = self.evidence.json(
                session,
                scan_id=context.scan_id,
                task_id=task_id,
                kind="runtime.observation",
                value={
                    "schema_version": "1.0",
                    "observation_key": observation_key,
                    **value,
                },
                summary=f"Runtime observation: {observation.kind}",
                metadata={
                    "source": observation.source,
                    "kind": observation.kind,
                    "finding_id": observation.finding_id,
                    "platform_runtime_receipt_ids": [
                        evidence_id
                        for evidence_id in observation.evidence_ids
                        if evidence_supports_runtime_observation(
                            known_evidence_by_id[evidence_id]
                        )
                    ],
                },
            )
            record = RuntimeObservation(
                scan_id=context.scan_id,
                task_id=task_id,
                finding_id=observation.finding_id,
                observation_key=observation_key,
                kind=observation.kind,
                source=observation.source,
                evidence_ids=[*observation.evidence_ids, evidence.id],
                payload=observation.payload,
                environment={
                    **observation.environment,
                    "device_serial": context.device.serial if context.device else None,
                    "validation": context.device.capability(non_blocking=False) if context.device else {},
                },
            )
            session.add(record)
            session.flush()
            if finding is not None and any(
                evidence_supports_runtime_observation(
                    known_evidence_by_id[evidence_id]
                )
                for evidence_id in observation.evidence_ids
            ):
                projected = self._project_runtime_observation_gap(
                    finding,
                    observation_id=record.id,
                    evidence_ids=list(record.evidence_ids),
                    task_id=task_id,
                    observation_kind=record.kind,
                )
                if projected:
                    invalidate_scan_materialized_summary(
                        session,
                        context.scan_id,
                        reason="runtime_observation_projection",
                    )
            add_event(
                session,
                context.scan_id,
                "runtime.observation.recorded",
                "Agent 已提交一项标准化运行时观测",
                {
                    "task_id": task_id,
                    "observation_id": record.id,
                    "kind": record.kind,
                    "source": record.source,
                    "finding_id": record.finding_id,
                },
            )
            session.commit()
            context.evidence_summaries.append(self._evidence_summary(evidence))
            self._materialize_live_evidence(context, [context.evidence_summaries[-1]])
            return {
                "schema_version": "1.0",
                "id": record.id,
                "observation_key": observation_key,
                "evidence_id": evidence.id,
                "deduplicated": False,
            }

    @staticmethod
    def _project_runtime_observation_gap(
        finding: Finding,
        *,
        observation_id: str,
        evidence_ids: list[str],
        task_id: str,
        observation_kind: str,
    ) -> bool:
        """Project a durable runtime fact without turning it into a proven vulnerability."""
        return project_runtime_observation_gap(
            finding,
            observation_id=observation_id,
            evidence_ids=evidence_ids,
            task_id=task_id,
            observation_kind=observation_kind,
        )
