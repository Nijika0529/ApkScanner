from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..core.enums import FindingStatus
from ..core.models import Evidence, Finding, RuntimeObservation
from ..core.repository import add_event, invalidate_scan_materialized_summary
from ..core.schemas import AgentProofReplay, AgentRequestedTest, AgentRuntimeObservation
from ..core.signal_projection import (
    evidence_supports_runtime_observation,
    project_runtime_observation_gap,
)
from ..infrastructure.tools import CommandResult
from .adb_gateway import AdbGatewayRequest, AdbGatewayResponse
from .device import AdbDeviceAdapter
from .live_proof import LiveProofContext
from .poc import PocBuildResult

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
        with self._live_proof_lock:
            current = self._live_proof_contexts.get(task_id)
            if current is not None and secrets.compare_digest(current.token, token):
                self._live_proof_contexts.pop(task_id, None)

    def ensure_live_proof_endpoint(self) -> str:
        with self._live_proof_lock:
            if self._live_proof_base_url is not None:
                return self._live_proof_base_url
            orchestrator = self

            class ProofReplayHandler(BaseHTTPRequestHandler):
                def do_POST(self) -> None:  # noqa: N802
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
                    if proof_match is None and adb_match is None and observation_match is None:
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
                    "device_serial": context.device.serial,
                    "validation": context.device.capability(non_blocking=False),
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


