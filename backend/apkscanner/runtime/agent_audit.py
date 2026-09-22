from __future__ import annotations

import uuid
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.db import Database
from ..core.evidence import EvidenceRecorder
from ..core.models import (
    AgentSessionRecord,
    AgentTurnRecord,
    EntryPoint,
    Evidence,
    InvestigationTask,
    Scan,
    ScanContainerRecord,
)
from ..core.repository import now
from ..core.schemas import AGENT_RESULT_JSON_SCHEMA
from ..infrastructure.artifacts import ArtifactStore
from .agent_prompt import developer_instructions, investigation_prompt

AGENT_AUDIT_KINDS = {
    "agent.request",
    "agent.response",
    "agent.events",
    "agent.error",
    "agent.test_validation",
    "agent.validation",
    "agent.cancellation",
}


def rejected_requested_tests(result: Any) -> list[dict[str, Any]]:
    rejected = getattr(result, "rejected_requested_tests", [])
    if not isinstance(rejected, list):
        return []
    return deepcopy([item for item in rejected if isinstance(item, dict)])


def normalization_repairs(result: Any) -> list[dict[str, Any]]:
    repairs = getattr(result, "normalization_repairs", [])
    if not isinstance(repairs, list):
        return []
    return deepcopy([item for item in repairs if isinstance(item, dict)])


def agent_role_for_phase(phase: str) -> str:
    return (
        "critic"
        if phase == "adversarial_review"
        else "rescue"
        if phase == "rescue_review"
        else "rescue_explorer"
        if phase == "rescue_exploration"
        else "verifier"
        if phase == "adaptive_verification"
        else "primary"
    )


class AgentAuditRecorder:
    """Persist immutable Agent exchanges and their runtime lifecycle records."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        evidence: EvidenceRecorder,
    ) -> None:
        self.settings = settings
        self.database = database
        self.evidence = evidence

    def ensure_scan_container(self, scan_id: str) -> None:
        if not self.settings.codex_enabled or self.settings.codex_isolation != "docker":
            return
        container_key = f"{scan_id}:scan-container"
        with self.database.session_factory() as session:
            record = session.scalar(
                select(ScanContainerRecord).where(
                    ScanContainerRecord.container_key == container_key
                )
            )
            if record is None:
                record = ScanContainerRecord(
                    scan_id=scan_id,
                    container_key=container_key,
                    isolation="docker",
                    status="prepared",
                    metadata_json={"session_workspaces": {}},
                )
                session.add(record)
            else:
                record.status = "prepared"
                record.completed_at = None
            session.commit()

    def close_scan_container(self, scan_id: str) -> None:
        with self.database.session_factory() as session:
            record = session.scalar(
                select(ScanContainerRecord).where(
                    ScanContainerRecord.container_key == f"{scan_id}:scan-container"
                )
            )
            if record is None:
                return
            scan = session.get(Scan, scan_id)
            record.status = "failed" if scan is not None and scan.status == "failed" else "closed"
            record.completed_at = now()
            session.execute(
                update(AgentSessionRecord)
                .where(
                    AgentSessionRecord.scan_id == scan_id,
                    AgentSessionRecord.status.in_({"active", "idle"}),
                )
                .values(status=record.status, completed_at=record.completed_at)
            )
            session.commit()

    def start_turn(
        self,
        session: Session,
        *,
        scan_id: str,
        task_id: str,
        attempt: int,
        phase: str,
        audit_id: str,
        request_evidence_id: str,
        round_index: int = 0,
        workspace_path: str = "",
    ) -> AgentTurnRecord:
        role = agent_role_for_phase(phase)
        container_key = f"{scan_id}:scan-container"
        container = session.scalar(
            select(ScanContainerRecord).where(
                ScanContainerRecord.container_key == container_key
            )
        )
        if container is None:
            container = ScanContainerRecord(
                scan_id=scan_id,
                task_id=None,
                container_key=container_key,
                isolation=self.settings.codex_isolation,
                workspace_path=workspace_path,
                status="running",
                metadata_json={"session_workspaces": {}},
            )
            session.add(container)
            session.flush()
        else:
            container.status = "running"
            container.completed_at = None
            if workspace_path:
                container.workspace_path = workspace_path
        container_metadata = dict(container.metadata_json or {})
        session_workspaces = dict(container_metadata.get("session_workspaces") or {})
        session_key = f"{scan_id}:{task_id}:{attempt}:{role}"
        if workspace_path:
            session_workspaces[session_key] = workspace_path
        container.metadata_json = {
            **container_metadata,
            "session_workspaces": session_workspaces,
        }
        agent_session = session.scalar(
            select(AgentSessionRecord).where(AgentSessionRecord.session_key == session_key)
        )
        if agent_session is None:
            agent_session = AgentSessionRecord(
                scan_id=scan_id,
                task_id=task_id,
                container_record_id=container.id,
                session_key=session_key,
                role=role,
                attempt=attempt,
                backend="codex",
                provider=self.settings.codex_provider,
                model=self.settings.codex_model,
                status="active",
            )
            session.add(agent_session)
            session.flush()
        else:
            agent_session.status = "active"
            agent_session.completed_at = None
        turn = AgentTurnRecord(
            scan_id=scan_id,
            task_id=task_id,
            session_record_id=agent_session.id,
            audit_id=audit_id,
            phase=phase,
            round_index=round_index,
            status="running",
            request_evidence_id=request_evidence_id,
        )
        session.add(turn)
        return turn

    @staticmethod
    def finish_turn(
        session: Session,
        *,
        audit_id: str,
        status: str,
        response_evidence_id: str | None = None,
        thread_id: str | None = None,
        turn_id: str | None = None,
        usage: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        turn = session.scalar(
            select(AgentTurnRecord).where(AgentTurnRecord.audit_id == audit_id)
        )
        if turn is None or turn.status != "running":
            return
        turn.status = status
        turn.response_evidence_id = response_evidence_id
        turn.turn_id = turn_id
        turn.usage_json = usage or {}
        turn.error = error
        turn.completed_at = now()
        agent_session = session.get(AgentSessionRecord, turn.session_record_id)
        if agent_session is not None:
            agent_session.status = "idle" if status == "completed" else status
            agent_session.thread_id = thread_id or agent_session.thread_id
            agent_session.completed_at = turn.completed_at
            container = session.get(ScanContainerRecord, agent_session.container_record_id)
            if container is not None:
                # A task turn ending does not imply the shared scan container ended.
                container.status = "running"
                container.completed_at = None

    def record_request(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        evidence: list[dict[str, Any]],
        platform_context: dict[str, Any],
        backend: str,
        phase: str,
        capability: dict[str, Any],
        runtime_workspace: Path | None = None,
    ) -> str:
        if backend != "codex":
            raise ValueError("OpenCode and other agent backends are not executable")
        frozen = self.settings.frozen_agent_configuration()
        provider = frozen.provider
        execution = frozen.execution
        frozen.phase_route.provider_profile_id(phase)
        direct_tool_access = True
        shell_access = execution.bash
        workspace_write = execution.workspace_write
        assigned_device = platform_context.get("device")
        assigned_device_serial = (
            assigned_device.get("serial") if isinstance(assigned_device, dict) else None
        )
        proof_replay = platform_context.get("proof_replay")
        gateway_available = bool(
            isinstance(proof_replay, dict) and proof_replay.get("available") is True
        )
        adb_access = (
            execution.adb == "task_gateway"
            and bool(assigned_device_serial)
            and gateway_available
        )
        network_access = execution.shell_network == "public_egress"
        audit_id = str(uuid.uuid4())
        metadata = {
            "audit_id": audit_id,
            "backend": "codex",
            "provider": provider.provider,
            "model": provider.model,
            "execution_profile_id": execution.id,
            "execution_profile_sha256": execution.fingerprint(),
            "provider_profile_id": provider.id,
            "provider_profile_sha256": provider.fingerprint(),
            "phase_route_sha256": frozen.phase_route.fingerprint(),
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": task.attempts,
        }
        prompt = investigation_prompt(
            scan,
            task,
            entries,
            evidence,
            platform_context,
            direct_tool_access=direct_tool_access,
            shell_access=shell_access,
            workspace_write=workspace_write,
            adb_access=adb_access,
            network_access=network_access,
        )
        request = {
            "schema_version": "1.0",
            "backend": "codex",
            "provider": provider.provider,
            "model": provider.model,
            "sdk_version": capability.get("version"),
            "runtime_version": capability.get("runtime_version"),
            "isolation": self.settings.codex_isolation,
            "provider_base_url": provider.base_url,
            "phase": phase,
            "task_id": task.id,
            "attempt": task.attempts,
            "developer_instructions": developer_instructions(
                direct_tool_access=direct_tool_access,
                shell_access=shell_access,
                workspace_write=workspace_write,
                adb_access=adb_access,
                network_access=network_access,
            ),
            "prompt": prompt,
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
            "tool_boundary": {
                "direct_tool_access": True,
                "model_tools_enabled": True,
                "workspace_tool_profile": "codex_full_access",
                "workspace_tools": ["file", "shell", "apply_patch", "web_search"],
                "shell_enabled": shell_access,
                "write_enabled": workspace_write,
                "native_write_tools_enabled": execution.apply_patch,
                "allowed_write_roots": ["session_workspace", "session_tmp"],
                "shared_scan_workspace_exposed": True,
                "network_enabled": network_access,
                "network_policy": (
                    execution.shell_network if network_access else "disabled"
                ),
                "adb_enabled": adb_access,
                "adb_evidence_policy": (
                    "exploration_only; ordinary-app replay required for proof"
                    if adb_access
                    else "disabled"
                ),
                "subagents_enabled": False,
                "mcp_allowlist": list(execution.mcp_allowlist),
                "structured_output_tool_enabled": False,
                "platform_executes_requested_tests": True,
            },
            "runtime_options": {
                "reasoning_effort": provider.reasoning_effort,
                "output_mode": "json_schema",
                "execution_profile": execution.model_dump(mode="json"),
                "execution_profile_sha256": execution.fingerprint(),
                "provider_profile": provider.model_dump(mode="json"),
                "provider_profile_sha256": provider.fingerprint(),
                "phase_route": frozen.phase_route.model_dump(mode="json"),
                "phase_route_sha256": frozen.phase_route.fingerprint(),
                "max_agent_steps": None,
                "max_provider_requests": None,
                "structured_output_retries": 1,
                "schema_validator": "pydantic@2",
                "semantic_validator": "apkscanner@1.0",
            },
        }
        with self.database.session_factory() as session:
            request_evidence = self.evidence.json(
                session,
                scan_id=scan.id,
                task_id=task.id,
                kind="agent.request",
                value=request,
                summary=f"{backend} {phase} request",
                metadata=metadata,
            )
            self.start_turn(
                session,
                scan_id=scan.id,
                task_id=task.id,
                attempt=task.attempts,
                phase=phase,
                audit_id=audit_id,
                request_evidence_id=request_evidence.id,
                round_index=int(platform_context.get("round_index") or 0),
                workspace_path=str(runtime_workspace or ""),
            )
            session.commit()
        return audit_id

    def record_response(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        result: Any,
    ) -> None:
        metadata = {
            "audit_id": audit_id,
            "backend": backend,
            "provider": self.settings.codex_provider,
            "model": self.settings.codex_model,
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": attempt,
            "thread_id": result.thread_id,
            "turn_id": result.turn_id,
        }
        response = {
            "schema_version": "1.0",
            "thread_id": result.thread_id,
            "turn_id": result.turn_id,
            "structured_output": result.result.model_dump(mode="json"),
            "model_validation": {
                "rejected_requested_tests": rejected_requested_tests(result.result),
                "normalization_repairs": normalization_repairs(result.result),
            },
            "usage": result.usage,
            "output_transport": getattr(result, "output_transport", {}),
        }
        with self.database.session_factory() as session:
            response_evidence = self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.response",
                value=response,
                summary=f"{backend} {phase} structured response",
                metadata=metadata,
            )
            self.finish_turn(
                session,
                audit_id=audit_id,
                status="completed",
                response_evidence_id=response_evidence.id,
                thread_id=result.thread_id,
                turn_id=result.turn_id,
                usage=result.usage,
            )
            session.commit()

    def record_runtime_events(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        events: list[dict[str, Any]],
    ) -> None:
        metadata = self._metadata(
            audit_id=audit_id,
            backend=backend,
            phase=phase,
            attempt=attempt,
        )
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.events",
                value={"schema_version": "1.0", "events": events},
                summary=f"{backend} {phase} normalized runtime events",
                metadata=metadata,
            )
            session.commit()

    def record_error(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        error: Exception | str,
    ) -> None:
        metadata = self._metadata(
            audit_id=audit_id,
            backend=backend,
            phase=phase,
            attempt=attempt,
        )
        error_message = str(error)
        audit_details = getattr(error, "audit_details", None)
        value: dict[str, Any] = {"schema_version": "1.0", "error": error_message}
        if isinstance(audit_details, dict) and audit_details:
            value["details"] = audit_details
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.error",
                value=value,
                summary=f"{backend} {phase} failed",
                metadata=metadata,
            )
            self.finish_turn(
                session,
                audit_id=audit_id,
                status="failed",
                error=error_message,
            )
            session.commit()

    def record_cancellation(
        self,
        *,
        scan_id: str,
        task_id: str,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
        error: Exception | str,
    ) -> None:
        metadata = self._metadata(
            audit_id=audit_id,
            backend=backend,
            phase=phase,
            attempt=attempt,
        )
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=scan_id,
                task_id=task_id,
                kind="agent.cancellation",
                value={
                    "schema_version": "1.0",
                    "requested_by": "local_console_user",
                    "acknowledged": True,
                    "reason": str(error),
                },
                summary=f"{backend} {phase} cancelled by user",
                metadata=metadata,
            )
            self.finish_turn(
                session,
                audit_id=audit_id,
                status="canceled",
                error=str(error),
            )
            session.commit()

    def record_test_validation(
        self,
        *,
        task_id: str,
        turn_id: str,
        submitted: list[dict[str, Any]],
        accepted: list[dict[str, Any]],
        executed: list[dict[str, Any]],
        gaps: list[str],
        model_rejected: list[dict[str, Any]] | None = None,
    ) -> None:
        match = self.response_for_turn(task_id, turn_id)
        if match is None:
            return
        response, metadata = match
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=response.scan_id,
                task_id=task_id,
                kind="agent.test_validation",
                value={
                    "schema_version": "1.0",
                    "submitted": submitted,
                    "accepted": accepted,
                    "executed": executed,
                    "gaps": gaps,
                    "model_rejected": model_rejected or [],
                },
                summary="Platform validation of AI-requested tests",
                metadata=metadata,
            )
            session.commit()

    def record_validation(
        self,
        *,
        task_id: str,
        turn_id: str,
        raw_payload: dict[str, Any],
        validated_payload: dict[str, Any],
    ) -> None:
        match = self.response_for_turn(task_id, turn_id)
        if match is None:
            return
        response, metadata = match
        claimed_evidence = list(raw_payload.get("evidence_ids", []))
        accepted_evidence = list(validated_payload.get("evidence_ids", []))
        with self.database.session_factory() as session:
            self.evidence.json(
                session,
                scan_id=response.scan_id,
                task_id=task_id,
                kind="agent.validation",
                value={
                    "schema_version": "1.0",
                    "claimed_result": raw_payload.get("result"),
                    "final_result": validated_payload.get("result"),
                    "claimed_severity": raw_payload.get("severity_proposal"),
                    "final_severity": validated_payload.get("platform_severity"),
                    "severity_disposition": validated_payload.get(
                        "severity_disposition", "accepted"
                    ),
                    "downgraded": (
                        raw_payload.get("result") != validated_payload.get("result")
                    ),
                    "claimed_evidence_ids": claimed_evidence,
                    "accepted_evidence_ids": accepted_evidence,
                    "rejected_evidence_ids": sorted(
                        set(claimed_evidence) - set(accepted_evidence)
                    ),
                    "raw_structured_output": raw_payload,
                    "validated_output": validated_payload,
                },
                summary="Platform evidence validation of AI result",
                metadata=metadata,
            )
            session.commit()

    def response_for_turn(
        self,
        task_id: str,
        turn_id: str,
    ) -> tuple[Evidence, dict[str, Any]] | None:
        with self.database.session_factory() as session:
            responses = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task_id,
                        Evidence.kind == "agent.response",
                    )
                    .order_by(Evidence.created_at.desc())
                )
            )
            for response in responses:
                if response.metadata_json.get("turn_id") == turn_id:
                    return response, dict(response.metadata_json)
        return None

    def _metadata(
        self,
        *,
        audit_id: str,
        backend: str,
        phase: str,
        attempt: int,
    ) -> dict[str, Any]:
        return {
            "audit_id": audit_id,
            "backend": backend,
            "provider": self.settings.codex_provider,
            "model": self.settings.codex_model,
            "isolation": self.settings.codex_isolation,
            "phase": phase,
            "attempt": attempt,
        }


def build_agent_audits(
    session: Session,
    store: ArtifactStore,
    scan_id: str,
    *,
    include_artifacts: bool = True,
    audit_id: str | None = None,
) -> list[dict[str, Any]]:
    evidence = list(
        session.scalars(
            select(Evidence)
            .where(
                Evidence.scan_id == scan_id,
                Evidence.kind.in_(AGENT_AUDIT_KINDS),
            )
            .order_by(Evidence.created_at, Evidence.id)
        )
    )
    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        item_audit_id = item.metadata_json.get("audit_id")
        if isinstance(item_audit_id, str) and (
            audit_id is None or item_audit_id == audit_id
        ):
            grouped[item_audit_id].append(item)

    audits = [
        _build_audit(
            store,
            audit_id,
            items,
            include_artifacts=include_artifacts,
        )
        for audit_id, items in grouped.items()
    ]
    return sorted(audits, key=lambda item: (item["started_at"], item["id"]))


def _build_audit(
    store: ArtifactStore,
    audit_id: str,
    evidence: list[Evidence],
    *,
    include_artifacts: bool,
) -> dict[str, Any]:
    first = evidence[0]
    metadata = first.metadata_json
    artifacts: dict[str, dict[str, Any]] = {}
    integrity_errors: list[str] = []
    for item in evidence:
        label = item.kind.removeprefix("agent.")
        content = None
        if include_artifacts:
            try:
                content = store.read_json_artifact("evidence", item.path, item.sha256)
            except (OSError, ValueError, TypeError) as exc:
                integrity_errors.append(f"{item.id}: {exc}")
        artifacts[label] = {
            "evidence_id": item.id,
            "sha256": item.sha256,
            "content": content,
            "created_at": item.created_at.isoformat(),
        }

    request = artifacts.get("request", {}).get("content")
    request_object = request if isinstance(request, dict) else {}
    response = artifacts.get("response", {}).get("content")
    status = (
        "cancelled"
        if "cancellation" in artifacts
        else "failed"
        if "error" in artifacts
        else "completed"
        if "response" in artifacts
        else "running"
    )
    terminal = next(
        (
            item.created_at
            for item in reversed(evidence)
            if item.kind
            in {
                "agent.response",
                "agent.error",
                "agent.validation",
                "agent.cancellation",
            }
        ),
        None,
    )
    response_object = response if isinstance(response, dict) else {}
    return {
        "id": audit_id,
        "scan_id": first.scan_id,
        # A completed task may be removed from the operational queue. Its
        # immutable request artifact still carries the original task ID.
        "task_id": first.task_id or request_object.get("task_id"),
        "attempt": int(metadata.get("attempt", 0)),
        "phase": str(metadata.get("phase", "unknown")),
        "backend": str(metadata.get("backend", "unknown")),
        "provider": str(metadata.get("provider", "unknown")),
        "model": str(metadata.get("model", "unknown")),
        "isolation": str(metadata.get("isolation", "unknown")),
        "status": status,
        "thread_id": response_object.get("thread_id"),
        "turn_id": response_object.get("turn_id"),
        "usage": response_object.get("usage") or {},
        "artifacts": artifacts,
        "integrity": (
            "failed"
            if integrity_errors
            else "verified"
            if include_artifacts
            else "not_checked"
        ),
        "integrity_errors": integrity_errors,
        "started_at": first.created_at.isoformat(),
        "completed_at": terminal.isoformat() if terminal else None,
    }
