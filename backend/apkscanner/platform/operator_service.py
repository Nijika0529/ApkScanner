from __future__ import annotations

import hashlib
import json
import secrets
import threading
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import desc, select

from ..core.db import Database
from ..core.enums import FindingStatus, TaskStatus
from ..core.models import (
    EntryPoint,
    Evidence,
    Finding,
    IndexedArtifact,
    InvestigationTask,
    OperatorSession,
    OperatorTurn,
    Scan,
    SecurityHypothesis,
)
from ..core.permissions import ensure_private_directory
from ..runtime.finding_reports import FindingReport, render_finding_description
from ..runtime.orchestrator import ScanOrchestrator, _LiveProofContext
from ..runtime.runtime_contracts import task_gateway_environment
from .artifacts import ArtifactStore
from .operator_schemas import OperatorReceipt, OperatorSessionCreate
from .tools import TimeBudget

_ARTIFACT_SUFFIXES = {".apk", ".apks", ".zip", ".json", ".html", ".js", ".py", ".sh", ".md", ".txt"}
_ARTIFACT_DIRS = {"poc", "pocs", "output", "outputs", "artifacts", "reports"}
_ARTIFACT_INPUT_DIRS = {"imports", "evidence"}


def _utcnow() -> datetime:
    return datetime.now(UTC)


class PlatformOperatorService:
    """Natural-language control surface over existing scan, Agent, artifact and ADB primitives."""

    def __init__(
        self,
        database: Database,
        store: ArtifactStore,
        orchestrator: ScanOrchestrator,
    ) -> None:
        self.database = database
        self.store = store
        self.orchestrator = orchestrator
        self.settings = orchestrator.settings
        self._cancel_events: dict[str, threading.Event] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.RLock()

    def create_session(self, request: OperatorSessionCreate) -> tuple[str, str]:
        with self.database.session_factory() as db:
            findings = list(
                db.scalars(select(Finding).where(Finding.id.in_(request.finding_ids)))
            ) if request.finding_ids else []
            if len(findings) != len(set(request.finding_ids)):
                raise ValueError("one or more selected findings do not exist")
            scan_ids = {finding.scan_id for finding in findings}
            if request.scan_id:
                scan_ids.add(request.scan_id)
            if len(scan_ids) > 1:
                raise ValueError("one Operator session currently targets one APK scan")
            scan = db.get(Scan, next(iter(scan_ids))) if scan_ids else db.scalar(
                select(Scan).order_by(desc(Scan.created_at)).limit(1)
            )
            if scan is None:
                raise ValueError("create or select an APK scan before starting the Operator")
            target_entry_ids = list(
                dict.fromkeys(
                    entry_id for finding in findings for entry_id in finding.entry_point_ids
                )
            )
            task = InvestigationTask(
                scan_id=scan.id,
                task_type="operator",
                status=TaskStatus.QUEUED.value,
                priority=100,
                target_entry_ids=target_entry_ids,
                hypotheses=[finding.title for finding in findings],
                preconditions={"source": "platform_operator"},
                allowed_side_effects=["workspace_write", "poc_build", "adb", "ssh", "web_search"],
                attempts=1,
            )
            db.add(task)
            db.flush()
            title = request.title or " ".join(request.instruction.split())[:80]
            operator_session = OperatorSession(
                primary_scan_id=scan.id,
                task_id=task.id,
                title=title,
                instruction=request.instruction,
                status="queued",
                scope_json={
                    "scan_ids": [scan.id],
                    "finding_ids": [finding.id for finding in findings],
                },
            )
            db.add(operator_session)
            db.flush()
            turn = OperatorTurn(
                session_id=operator_session.id,
                instruction=request.instruction,
                status="queued",
                device_mode=request.device_mode,
            )
            db.add(turn)
            db.commit()
            return operator_session.id, turn.id

    def add_turn(self, session_id: str, instruction: str, device_mode: str) -> str:
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            if operator_session is None:
                raise KeyError(session_id)
            if operator_session.status in {"queued", "running", "canceling"}:
                raise ValueError("the Operator session already has an active turn")
            turn = OperatorTurn(
                session_id=session_id,
                instruction=instruction,
                status="queued",
                device_mode=device_mode,
            )
            operator_session.status = "queued"
            operator_session.cancel_requested = False
            operator_session.error = None
            db.add(turn)
            db.commit()
            return turn.id

    def cancel(self, session_id: str) -> bool:
        with self._guard:
            event = self._cancel_events.get(session_id)
            if event is not None:
                event.set()
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            if operator_session is None:
                return False
            operator_session.cancel_requested = True
            operator_session.status = "canceling" if event is not None else "canceled"
            db.commit()
        self.orchestrator.device_pool.wake_waiters()
        return True

    def run_turn(self, session_id: str, turn_id: str) -> None:
        lock = self._session_lock(session_id)
        with lock:
            with self.database.session_factory() as db:
                queued_session = db.get(OperatorSession, session_id)
                queued_turn = db.get(OperatorTurn, turn_id)
                if queued_session is None or queued_turn is None:
                    return
                if queued_session.cancel_requested:
                    queued_turn.status = "canceled"
                    queued_turn.error = "canceled before dispatch"
                    queued_turn.completed_at = _utcnow()
                    queued_session.status = "canceled"
                    queued_session.completed_at = _utcnow()
                    db.commit()
                    return
            cancel_event = threading.Event()
            with self._guard:
                self._cancel_events[session_id] = cancel_event
            try:
                self._run_turn(session_id, turn_id, cancel_event)
            except Exception as exc:
                with self.database.session_factory() as db:
                    operator_session = db.get(OperatorSession, session_id)
                    turn = db.get(OperatorTurn, turn_id)
                    if turn is not None:
                        turn.status = "canceled" if cancel_event.is_set() else "failed"
                        turn.error = str(exc)
                        turn.completed_at = _utcnow()
                    if operator_session is not None:
                        operator_session.status = turn.status if turn is not None else "failed"
                        operator_session.error = str(exc)
                        operator_session.completed_at = _utcnow()
                    db.commit()
            finally:
                with self._guard:
                    self._cancel_events.pop(session_id, None)

    def _run_turn(
        self,
        session_id: str,
        turn_id: str,
        cancel_event: threading.Event,
    ) -> None:
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            turn = db.get(OperatorTurn, turn_id)
            if operator_session is None or turn is None or turn.session_id != session_id:
                raise ValueError("Operator session or turn is unavailable")
            scan = db.get(Scan, operator_session.primary_scan_id)
            task = db.get(InvestigationTask, operator_session.task_id)
            if scan is None or task is None:
                raise ValueError("Operator scan context is unavailable")
            operator_session.status = "running"
            operator_session.completed_at = None
            turn.status = "running"
            turn.started_at = _utcnow()
            task.status = TaskStatus.RUNNING.value
            task.started_at = task.started_at or _utcnow()
            db.commit()

        source_workspace = self._prepare_source_workspace(session_id, scan.id)
        indexed = self.index_artifacts(session_id)
        context = self._write_context_manifest(session_id, source_workspace, indexed)
        runtime_workspace = self.orchestrator.codex.prepare_session_workspace(
            scan=scan,
            task=task,
            workspace=source_workspace,
            phase="platform_operator",
        )
        with self.database.session_factory() as db:
            current = db.get(OperatorSession, session_id)
            if current is not None:
                current.workspace_path = str(runtime_workspace)
                db.commit()

        lease_context = nullcontext(None)
        if turn.device_mode == "required":
            lease_context = self.orchestrator.device_pool.task_lease(
                task.id,
                priority=100,
                cancel_event=cancel_event,
            )
        elif turn.device_mode == "auto":
            capability = self.orchestrator.device_pool.capability(non_blocking=True)
            if capability.get("available") and not capability.get("busy"):
                lease_context = self.orchestrator.device_pool.task_lease(
                    task.id,
                    priority=100,
                    cancel_event=cancel_event,
                )

        gateway_token: str | None = None
        gateway_environment: dict[str, str] | None = None
        evidence_summaries: list[dict[str, Any]] = []
        with lease_context as lease:
            device = lease.get("device") if isinstance(lease, dict) else None
            if device is not None:
                endpoint = self.orchestrator._ensure_live_proof_endpoint()
                port = urlsplit(endpoint).port
                if port is None:
                    raise RuntimeError("internal Operator gateway has no TCP port")
                gateway_token = secrets.token_urlsafe(48)
                with self.database.session_factory() as db:
                    entries = list(
                        db.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan.id))
                    )
                    hypotheses = [
                        {
                            "id": item.id,
                            "claim": item.claim,
                            "impact": item.impact,
                            "entry_point_ids": item.entry_point_ids,
                        }
                        for item in db.scalars(
                            select(SecurityHypothesis).where(SecurityHypothesis.scan_id == scan.id)
                        )
                    ]
                agent_session = self.orchestrator.codex.workspaces.prepare_session(
                    scan_id=scan.id,
                    task_id=task.id,
                    attempt=task.attempts,
                    role="operator",
                    source_workspace=source_workspace,
                    context={"phase": "platform_operator", "operator_session_id": session_id},
                )
                self.orchestrator._register_live_proof_context(
                    _LiveProofContext(
                        token=gateway_token,
                        scan_id=scan.id,
                        task_id=task.id,
                        package_name=scan.package_name or "",
                        workspace=runtime_workspace,
                        entries=entries,
                        default_entry_id=entries[0].id if entries else "",
                        hypotheses=hypotheses,
                        budget=TimeBudget.from_seconds(self.settings.task_timeout_seconds),
                        evidence_summaries=evidence_summaries,
                        cancel_event=cancel_event,
                        round_index=0,
                        device=device,
                        adb_policy="adaptive",
                        container_workspace=agent_session.container_workspace,
                    )
                )
                gateway_environment = task_gateway_environment(
                    task_id=task.id,
                    base_url=f"http://apkscanner-host:{port}",
                    token=gateway_token,
                    adb_policy="adaptive",
                    proof_replay=False,
                )
            try:
                prompt = self._operator_prompt(turn.instruction, context, device is not None)
                result = self.orchestrator.codex.operate(
                    scan=scan,
                    task=task,
                    workspace=source_workspace,
                    prompt=prompt,
                    timeout_seconds=self.settings.task_timeout_seconds,
                    cancel_event=cancel_event,
                    gateway_environment=gateway_environment,
                )
            finally:
                # The logical Codex Thread stays in thread.json, while the worker is
                # reopened next turn with a fresh task-scoped ADB token/device lease.
                self.orchestrator.codex.close_task_role(
                    scan.id,
                    task.id,
                    task.attempts,
                    "operator",
                )
                if gateway_token is not None:
                    self.orchestrator._unregister_live_proof_context(task.id, gateway_token)

        receipt = result.result
        receipt_evidence_id = self._persist_receipt(scan.id, task.id, session_id, turn_id, receipt)
        artifacts = self.index_artifacts(session_id, runtime_workspace=runtime_workspace)
        self._apply_finding_updates(session_id, receipt, receipt_evidence_id)
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            current_turn = db.get(OperatorTurn, turn_id)
            current_task = db.get(InvestigationTask, task.id)
            assert operator_session is not None and current_turn is not None
            payload = receipt.model_dump(mode="json")
            payload["receipt_evidence_id"] = receipt_evidence_id
            payload["indexed_artifact_ids"] = [item.id for item in artifacts]
            current_turn.status = "completed"
            current_turn.thread_id = result.thread_id
            current_turn.turn_id = result.turn_id
            current_turn.receipt_json = payload
            current_turn.completed_at = _utcnow()
            operator_session.status = "idle"
            operator_session.thread_id = result.thread_id
            operator_session.result_json = payload
            operator_session.error = None
            operator_session.completed_at = _utcnow()
            if current_task is not None:
                current_task.status = TaskStatus.COMPLETED.value
                current_task.thread_id = result.thread_id
                current_task.turn_id = result.turn_id
                current_task.result = payload
                current_task.completed_at = _utcnow()
            db.commit()

    def _prepare_source_workspace(self, session_id: str, scan_id: str) -> Path:
        root = self.settings.data_dir / "operator-sessions" / session_id
        workspace = root / "workspace"
        ensure_private_directory(root)
        ensure_private_directory(workspace)
        ensure_private_directory(workspace / "imports")
        ensure_private_directory(workspace / "evidence")
        ensure_private_directory(workspace / "output")
        ensure_private_directory(workspace / "poc")
        scan_context = self.settings.data_dir / "workspaces" / scan_id
        (workspace / "SCAN_INPUT.txt").write_text(
            f"完整反编译输入在容器 /scan-input；宿主路径为 {scan_context}\n",
            encoding="utf-8",
        )
        return workspace

    def _write_context_manifest(
        self,
        session_id: str,
        workspace: Path,
        artifacts: list[IndexedArtifact],
    ) -> dict[str, Any]:
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            assert operator_session is not None
            finding_ids = list((operator_session.scope_json or {}).get("finding_ids") or [])
            findings = list(db.scalars(select(Finding).where(Finding.id.in_(finding_ids))))
            evidence_ids = list(
                dict.fromkeys(evidence_id for finding in findings for evidence_id in finding.evidence_ids)
            )
            evidence = list(db.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids))))
            evidence_rows: list[dict[str, Any]] = []
            for item in evidence:
                local_path = workspace / "evidence" / f"{item.id}.json"
                if not local_path.exists():
                    source = self.store.verify_content_addressed(
                        "evidence", item.path, item.sha256
                    )
                    local_path.write_bytes(source.read_bytes())
                evidence_rows.append(
                    {
                        "id": item.id,
                        "kind": item.kind,
                        "summary": item.summary,
                        "workspace_path": f"evidence/{item.id}.json",
                    }
                )
            artifact_rows: list[dict[str, Any]] = []
            for item in artifacts:
                local_name = f"{item.id[:8]}-{Path(item.name).name}"
                local_path = workspace / "imports" / local_name
                if not local_path.exists():
                    source = self.store.verify_content_addressed(
                        "operator_artifacts", item.stored_path, item.sha256
                    )
                    local_path.write_bytes(source.read_bytes())
                artifact_rows.append(
                    {
                        "id": item.id,
                        "type": item.artifact_type,
                        "name": item.name,
                        "sha256": item.sha256,
                        "workspace_path": f"imports/{local_name}",
                        "source_path": item.source_path,
                    }
                )
            payload = {
                "schema_version": "1.0",
                "operator_session_id": session_id,
                "scan_id": operator_session.primary_scan_id,
                "findings": [
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "status": finding.status,
                        "severity": finding.severity,
                        "description": finding.description,
                        "remediation": finding.remediation,
                        "entry_point_ids": finding.entry_point_ids,
                        "evidence_ids": finding.evidence_ids,
                        "report": (finding.metadata_json or {}).get("report"),
                    }
                    for finding in findings
                ],
                "evidence": evidence_rows,
                "artifacts": artifact_rows,
            }
        path = workspace / "platform-context.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return payload

    @staticmethod
    def _operator_prompt(instruction: str, context: dict[str, Any], device_available: bool) -> str:
        finding_ids = [item["id"] for item in context.get("findings", [])]
        return (
            "执行用户的平台操作命令。完整上下文在 ./platform-context.json，反编译结果在 "
            "/scan-input，历史 PoC 的不可变索引见上下文，当前工作区可写。"
            f"当前 Finding: {finding_ids or '未限定'}；ADB: {'可用' if device_available else '本轮不可用'}。\n"
            "若要更新 Finding，必须在 finding_updates 中引用对应 finding_id 和实际 Evidence ID；"
            "动态观察可 POST 到 $APKSCANNER_OBSERVATION_URL，使用头 "
            "X-APKScanner-Proof-Token:$APKSCANNER_OBSERVATION_TOKEN，响应会返回可引用的 evidence_id；"
            "新 APK/报告/脚本放到 poc/ 或 output/，并在 artifact_paths 中列出相对路径。\n"
            f"用户命令：{instruction}"
        )

    def index_artifacts(
        self,
        session_id: str,
        *,
        runtime_workspace: Path | None = None,
    ) -> list[IndexedArtifact]:
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            if operator_session is None:
                raise KeyError(session_id)
            scan_id = operator_session.primary_scan_id
            finding_ids = list((operator_session.scope_json or {}).get("finding_ids") or [])
            findings = list(db.scalars(select(Finding).where(Finding.id.in_(finding_ids))))
            task_ids = {
                task_id
                for finding in findings
                for task_id in self._finding_task_ids(finding.metadata_json or {})
            }
        candidates: list[tuple[Path, str | None, str | None]] = []
        sessions_root = self.settings.data_dir / "agent-sessions" / str(scan_id)
        for task_id in task_ids:
            compact = task_id.replace("-", "")[:16]
            for root in sessions_root.glob(f"{compact}-a*-*") if sessions_root.is_dir() else []:
                candidates.extend((path, task_id, None) for path in self._artifact_files(root))
        if runtime_workspace is not None:
            candidates.extend((path, None, session_id) for path in self._artifact_files(runtime_workspace))
        indexed: list[IndexedArtifact] = []
        with self.database.session_factory() as db:
            for source, task_id, producer_session_id in candidates:
                sha256, stored, size = self.store.put_file("operator_artifacts", source)
                finding_id = findings[0].id if len(findings) == 1 else None
                key_payload = f"{sha256}\0{scan_id}\0{task_id}\0{finding_id}\0{source.resolve()}"
                index_key = hashlib.sha256(key_payload.encode()).hexdigest()
                record = db.scalar(
                    select(IndexedArtifact).where(IndexedArtifact.index_key == index_key)
                )
                if record is None:
                    record = IndexedArtifact(
                        index_key=index_key,
                        sha256=sha256,
                        artifact_type=self._artifact_type(source),
                        name=source.name,
                        stored_path=str(stored),
                        source_path=str(source),
                        size_bytes=size,
                        scan_id=scan_id,
                        task_id=task_id,
                        finding_id=finding_id,
                        operator_session_id=producer_session_id,
                        metadata_json={"indexed_by": "platform_operator"},
                    )
                    db.add(record)
                    db.flush()
                indexed.append(record)
            db.commit()
            return indexed

    @staticmethod
    def _finding_task_ids(metadata: dict[str, Any]) -> set[str]:
        """Return every Agent task that may have produced artifacts for a Finding."""
        task_ids: set[str] = set()

        def add(value: Any) -> None:
            if isinstance(value, str) and value.strip():
                task_ids.add(value.strip())

        add(metadata.get("task_id"))
        proof_backlog = metadata.get("proof_backlog")
        if isinstance(proof_backlog, dict):
            add(proof_backlog.get("task_id"))
            add(proof_backlog.get("verifier_task_id"))
        adaptive = metadata.get("adaptive_verification")
        if isinstance(adaptive, dict):
            add(adaptive.get("task_id"))
        history = metadata.get("adaptive_verification_history")
        if isinstance(history, list):
            for item in history:
                if isinstance(item, dict):
                    add(item.get("task_id"))
        return task_ids

    @staticmethod
    def _artifact_files(root: Path) -> list[Path]:
        if not root.is_dir():
            return []
        result: list[Path] = []
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in _ARTIFACT_SUFFIXES:
                continue
            relative_path = path.relative_to(root)
            relative_parts = {part.lower() for part in relative_path.parts[:-1]}
            if relative_parts & _ARTIFACT_INPUT_DIRS:
                continue
            if path.suffix.lower() in {".apk", ".apks"} or relative_parts & _ARTIFACT_DIRS:
                result.append(path)
        return result

    @staticmethod
    def _artifact_type(path: Path) -> str:
        if path.suffix.lower() in {".apk", ".apks"}:
            return "poc_apk"
        if path.suffix.lower() in {".html", ".js"}:
            return "web_payload"
        if path.suffix.lower() in {".py", ".sh"}:
            return "script"
        if path.suffix.lower() in {".json", ".md", ".txt"}:
            return "report"
        return "artifact"

    def _persist_receipt(
        self,
        scan_id: str,
        task_id: str,
        session_id: str,
        turn_id: str,
        receipt: OperatorReceipt,
    ) -> str:
        payload = receipt.model_dump(mode="json")
        sha256, path = self.store.put_json("evidence", payload)
        with self.database.session_factory() as db:
            evidence = Evidence(
                scan_id=scan_id,
                task_id=task_id,
                kind="operator.receipt",
                sha256=sha256,
                path=str(path),
                summary=receipt.summary,
                metadata_json={"operator_session_id": session_id, "operator_turn_id": turn_id},
            )
            db.add(evidence)
            db.commit()
            return evidence.id

    def _apply_finding_updates(
        self,
        session_id: str,
        receipt: OperatorReceipt,
        receipt_evidence_id: str,
    ) -> None:
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            assert operator_session is not None
            allowed_ids = set((operator_session.scope_json or {}).get("finding_ids") or [])
            for update in receipt.finding_updates:
                if update.finding_id not in allowed_ids:
                    continue
                finding = db.get(Finding, update.finding_id)
                if finding is None:
                    continue
                valid_evidence_ids = set(
                    db.scalars(
                        select(Evidence.id).where(
                            Evidence.id.in_(update.evidence_ids),
                            Evidence.scan_id == finding.scan_id,
                        )
                    )
                )
                combined_evidence = list(
                    dict.fromkeys([*finding.evidence_ids, *valid_evidence_ids, receipt_evidence_id])
                )
                metadata = dict(finding.metadata_json or {})
                report_payload = metadata.get("report")
                if isinstance(report_payload, dict):
                    report = FindingReport.model_validate(report_payload)
                    report.conclusion = update.conclusion[:600]
                    report.verification.established_facts = receipt.observations[:3]
                    report.verification.evidence_ids = list(valid_evidence_ids)[:64]
                    report.verification.missing_proof = update.remaining_gap
                    report.verification.next_step = (
                        None if update.remaining_gap is None else "根据剩余缺口继续补充动态实验。"
                    )
                    if update.verdict == "reproduced_blackbox" and valid_evidence_ids:
                        report.kind = "finding"
                        report.verification.status = "confirmed"
                        report.title = report.title.replace("待验证：", "已复现：", 1)
                        finding.status = FindingStatus.REPRODUCED_BLACKBOX.value
                        metadata["harm_demonstrated"] = True
                    elif update.verdict == "refuted_static":
                        report.verification.status = "refuted"
                        finding.status = FindingStatus.REFUTED_STATIC.value
                    elif update.verdict in {"not_reproduced", "inconclusive"}:
                        report.verification.status = "inconclusive"
                        finding.status = update.verdict
                    metadata["report"] = report.model_dump(mode="json")
                    finding.title = report.title
                    finding.description = render_finding_description(report)
                history = list(metadata.get("operator_history") or [])
                history.append(
                    {
                        "session_id": session_id,
                        "verdict": update.verdict,
                        "conclusion": update.conclusion,
                        "evidence_ids": list(valid_evidence_ids),
                        "receipt_evidence_id": receipt_evidence_id,
                        "at": _utcnow().isoformat(),
                    }
                )
                metadata["operator_history"] = history[-20:]
                finding.metadata_json = metadata
                finding.evidence_ids = combined_evidence
            db.commit()

    def get_session(self, session_id: str) -> tuple[OperatorSession, list[OperatorTurn]]:
        with self.database.session_factory() as db:
            operator_session = db.get(OperatorSession, session_id)
            if operator_session is None:
                raise KeyError(session_id)
            turns = list(
                db.scalars(
                    select(OperatorTurn)
                    .where(OperatorTurn.session_id == session_id)
                    .order_by(OperatorTurn.created_at)
                )
            )
            db.expunge(operator_session)
            for turn in turns:
                db.expunge(turn)
            return operator_session, turns

    def list_sessions(self, *, limit: int = 50) -> list[OperatorSession]:
        with self.database.session_factory() as db:
            values = list(
                db.scalars(select(OperatorSession).order_by(desc(OperatorSession.created_at)).limit(limit))
            )
            for value in values:
                db.expunge(value)
            return values

    def list_artifacts(
        self,
        *,
        scan_id: str | None = None,
        finding_id: str | None = None,
        operator_session_id: str | None = None,
    ) -> list[IndexedArtifact]:
        with self.database.session_factory() as db:
            query = select(IndexedArtifact)
            if scan_id:
                query = query.where(IndexedArtifact.scan_id == scan_id)
            if finding_id:
                query = query.where(IndexedArtifact.finding_id == finding_id)
            if operator_session_id:
                query = query.where(IndexedArtifact.operator_session_id == operator_session_id)
            values = list(db.scalars(query.order_by(desc(IndexedArtifact.created_at)).limit(500)))
            for value in values:
                db.expunge(value)
            return values

    def artifact_path(self, artifact_id: str) -> Path:
        with self.database.session_factory() as db:
            record = db.get(IndexedArtifact, artifact_id)
            if record is None:
                raise KeyError(artifact_id)
            return self.store.verify_content_addressed(
                "operator_artifacts", record.stored_path, record.sha256
            )

    def _session_lock(self, session_id: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(session_id, threading.Lock())
