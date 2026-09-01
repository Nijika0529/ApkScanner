from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update

from ..core.db import Database
from ..core.evidence import EvidenceRecorder
from ..core.models import (
    DynamicExperimentCapsule,
    DynamicExperimentReceipt,
    Finding,
    RuntimeObservation,
)
from ..core.repository import add_event, invalidate_scan_materialized_summary
from ..core.schemas import DynamicExperimentStepSpec
from .adb_gateway import (
    quote_dynamic_experiment_adb_args,
    validate_dynamic_experiment_adb_args,
    validate_dynamic_experiment_adb_template,
)
from .device import AdbDeviceAdapter, AdbDevicePool, DeviceLeaseCancelledError
from .signal_projection import project_runtime_observation_gap

_STATE_REFERENCE = re.compile(r"\$\{([A-Za-z][A-Za-z0-9_.-]{0,127})\}")


def _now() -> datetime:
    return datetime.now(UTC)


class DynamicExperimentPolicyError(ValueError):
    """A persisted Capsule violates the platform-owned command policy."""


class DynamicExperimentService:
    """Execute and checkpoint stateful, multi-command Android experiments."""

    def __init__(
        self,
        database: Database,
        evidence: EvidenceRecorder,
        device_pool: AdbDevicePool,
    ) -> None:
        self.database = database
        self.evidence = evidence
        self.device_pool = device_pool
        self._lock = threading.Lock()
        self._cancellations: dict[str, threading.Event] = {}
        self._recover_interrupted()

    def _recover_interrupted(self) -> None:
        """A running receipt is a durable resume point after a control-plane restart."""

        recovered_at = _now()
        with self.database.session_factory() as session:
            capsules = list(
                session.scalars(
                    select(DynamicExperimentCapsule).where(
                        DynamicExperimentCapsule.status == "running"
                    )
                )
            )
            if not capsules:
                return
            capsule_ids = [item.id for item in capsules]
            session.execute(
                update(DynamicExperimentReceipt)
                .where(
                    DynamicExperimentReceipt.capsule_id.in_(capsule_ids),
                    DynamicExperimentReceipt.status == "running",
                )
                .values(
                    status="failed",
                    error="control plane restarted during this step",
                    completed_at=recovered_at,
                )
            )
            for capsule in capsules:
                capsule.status = "paused"
                capsule.error = "control plane restarted; resume from the last completed step"
                add_event(
                    session,
                    capsule.scan_id,
                    "dynamic_experiment.recovered",
                    "动态实验在服务重启后已从最近完成步骤恢复为可继续状态",
                    {"capsule_id": capsule.id},
                )
            session.commit()

    def run(
        self,
        capsule_id: str,
        *,
        preferred_serial: str | None = None,
    ) -> DynamicExperimentCapsule:
        cancel_event = threading.Event()
        with self._lock:
            if capsule_id in self._cancellations:
                raise RuntimeError("dynamic experiment is already running")
            self._cancellations[capsule_id] = cancel_event
        try:
            try:
                capsule = self._prepare_run(capsule_id, preferred_serial)
            except DynamicExperimentPolicyError as exc:
                self._mark_preparation_error(capsule_id, str(exc))
                return self.get(capsule_id)
            try:
                with self.device_pool.task_lease(
                    f"dynamic:{capsule_id}",
                    priority=110,
                    cancel_event=cancel_event,
                    preferred_serial=capsule.preferred_serial,
                    on_queued=lambda position: self._record_queue(capsule_id, position),
                    on_acquired=lambda waited, adapter: self._record_acquired(
                        capsule_id, waited, adapter
                    ),
                    on_released=lambda held, adapter: self._record_released(
                        capsule_id, held, adapter
                    ),
                ) as lease:
                    adapter = lease["device"]
                    assert isinstance(adapter, AdbDeviceAdapter)
                    self._execute_pending_steps(capsule_id, adapter, cancel_event)
            except DeviceLeaseCancelledError:
                self._mark_canceled(capsule_id)
            except Exception as exc:
                self._mark_execution_error(capsule_id, str(exc))
            return self.get(capsule_id)
        finally:
            with self._lock:
                self._cancellations.pop(capsule_id, None)

    def run_on_leased_device(
        self,
        capsule_id: str,
        adapter: AdbDeviceAdapter,
    ) -> DynamicExperimentCapsule:
        """Run a Capsule on a device already leased by its investigation task."""

        cancel_event = threading.Event()
        with self._lock:
            if capsule_id in self._cancellations:
                raise RuntimeError("dynamic experiment is already running")
            self._cancellations[capsule_id] = cancel_event
        try:
            try:
                self._prepare_run(capsule_id, adapter.serial)
            except DynamicExperimentPolicyError as exc:
                self._mark_preparation_error(capsule_id, str(exc))
                return self.get(capsule_id)
            self._record_acquired(capsule_id, 0.0, adapter)
            try:
                self._execute_pending_steps(capsule_id, adapter, cancel_event)
            except Exception as exc:
                self._mark_execution_error(capsule_id, str(exc))
            return self.get(capsule_id)
        finally:
            with self._lock:
                self._cancellations.pop(capsule_id, None)

    def cancel(self, capsule_id: str) -> DynamicExperimentCapsule:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                raise LookupError(capsule_id)
            capsule.cancel_requested = True
            if capsule.status in {"queued", "paused"}:
                capsule.status = "canceled"
                capsule.completed_at = _now()
                capsule.error = "dynamic experiment was canceled"
            session.commit()
        with self._lock:
            event = self._cancellations.get(capsule_id)
        if event is not None:
            event.set()
        return self.get(capsule_id)

    def get(self, capsule_id: str) -> DynamicExperimentCapsule:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                raise LookupError(capsule_id)
            session.expunge(capsule)
            return capsule

    def _prepare_run(
        self,
        capsule_id: str,
        preferred_serial: str | None,
    ) -> DynamicExperimentCapsule:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                raise LookupError(capsule_id)
            if capsule.status == "completed":
                raise ValueError("dynamic experiment is already complete")
            try:
                all_steps = [
                    DynamicExperimentStepSpec.model_validate(item)
                    for item in [*capsule.steps, *capsule.cleanup_steps]
                ]
                for step in all_steps:
                    validate_dynamic_experiment_adb_template(step.adb_args)
            except ValueError as exc:
                raise DynamicExperimentPolicyError(str(exc)) from exc
            if preferred_serial is not None:
                capsule.preferred_serial = preferred_serial
            capsule.status = "running"
            capsule.cancel_requested = False
            capsule.error = None
            capsule.completed_at = None
            capsule.started_at = capsule.started_at or _now()
            add_event(
                session,
                capsule.scan_id,
                "dynamic_experiment.started",
                "状态化动态实验已开始或从断点继续",
                {"capsule_id": capsule.id, "name": capsule.name},
            )
            session.commit()
            session.refresh(capsule)
            session.expunge(capsule)
            return capsule

    def _execute_pending_steps(
        self,
        capsule_id: str,
        adapter: AdbDeviceAdapter,
        cancel_event: threading.Event,
    ) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            assert capsule is not None
            main_steps = [DynamicExperimentStepSpec.model_validate(item) for item in capsule.steps]
            cleanup_steps = [
                DynamicExperimentStepSpec.model_validate(item) for item in capsule.cleanup_steps
            ]

        failures: list[str] = []
        for step in main_steps:
            if cancel_event.is_set() or self._cancel_requested(capsule_id):
                self._mark_canceled(capsule_id)
                return
            if self._step_passed(capsule_id, step.id):
                continue
            passed = self._execute_step(capsule_id, step, adapter)
            if not passed:
                failures.append(step.id)
                if not step.continue_on_failure:
                    self._mark_paused(capsule_id, failures)
                    return

        if failures:
            self._mark_paused(capsule_id, failures)
            return

        cleanup_failures: list[str] = []
        for step in cleanup_steps:
            if cancel_event.is_set() or self._cancel_requested(capsule_id):
                self._mark_canceled(capsule_id)
                return
            if self._step_passed(capsule_id, step.id):
                continue
            if not self._execute_step(capsule_id, step, adapter):
                cleanup_failures.append(step.id)
                if not step.continue_on_failure:
                    break
        self._mark_completed(capsule_id, cleanup_failures)

    def _execute_step(
        self,
        capsule_id: str,
        step: DynamicExperimentStepSpec,
        adapter: AdbDeviceAdapter,
    ) -> bool:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            assert capsule is not None
            state = dict(capsule.state_json or {})
            args = [self._render_argument(value, state) for value in step.adb_args]
            validate_dynamic_experiment_adb_args(args)
            prior_attempts = list(
                session.scalars(
                    select(DynamicExperimentReceipt).where(
                        DynamicExperimentReceipt.capsule_id == capsule_id,
                        DynamicExperimentReceipt.step_id == step.id,
                    )
                )
            )
            receipt = DynamicExperimentReceipt(
                capsule_id=capsule_id,
                step_id=step.id,
                attempt=max((item.attempt for item in prior_attempts), default=0) + 1,
                phase=step.phase,
                status="running",
                command=args,
            )
            session.add(receipt)
            session.commit()
            receipt_id = receipt.id

        result = adapter.execute_gateway(
            quote_dynamic_experiment_adb_args(args),
            timeout=step.timeout_seconds,
            policy="adaptive",
        )
        checks: dict[str, Any] = {
            "exit_code": {
                "expected": step.expected_exit_code,
                "actual": result.exit_code,
                "matched": result.exit_code == step.expected_exit_code,
            },
            "stdout_contains": {value: value in result.stdout for value in step.stdout_contains},
        }
        if step.stdout_regex is not None:
            checks["stdout_regex"] = {
                "pattern": step.stdout_regex,
                "matched": re.search(step.stdout_regex, result.stdout) is not None,
            }
        passed = bool(checks["exit_code"]["matched"])
        passed = passed and all(checks["stdout_contains"].values())
        if "stdout_regex" in checks:
            passed = passed and bool(checks["stdout_regex"]["matched"])

        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            receipt = session.get(DynamicExperimentReceipt, receipt_id)
            assert capsule is not None and receipt is not None
            contract = dict(capsule.impact_contract or {})
            assertion_step_ids = {
                str(value)
                for value in contract.get("assertion_step_ids", [])
                if isinstance(value, str)
            }
            observation_kinds = {
                str(value)
                for value in contract.get("observation_kinds", [])
                if isinstance(value, str)
            }
            required_assertion = step.id in assertion_step_ids
            other_assertions_passed = all(
                other_id == step.id or self._step_passed(capsule_id, other_id)
                for other_id in assertion_step_ids
            )
            agent_assertion_matched = bool(
                passed
                and required_assertion
                and step.phase == "assert"
                and step.observation_kind in observation_kinds
                and other_assertions_passed
                and contract.get("contract_id")
                and contract.get("impact")
                and contract.get("observed_fact")
            )
            agent_assertion_failed = bool(
                not passed and required_assertion and contract.get("refute_on_failure") is True
            )
            runtime_metadata = {
                key: value
                for key, value in dict(contract.get("runtime_verdict_metadata") or {}).items()
                if key
                in {
                    "validation_profile",
                    "android16_verdict_eligible",
                    "dynamic_verdict_eligible",
                    "release_gate_eligible",
                    "compatibility_smoke_only",
                    "verdict_scope",
                }
            }
            evidence_metadata = {
                "capsule_id": capsule.id,
                "step_id": step.id,
                "attempt": receipt.attempt,
                "phase": step.phase,
                "test_case_id": contract.get("test_case_id"),
                "proof_attempt_id": contract.get("proof_attempt_id"),
                "hypothesis_id": contract.get("hypothesis_id"),
                "entry_point_id": contract.get("entry_point_id"),
                "device_serial": capsule.device_serial,
                "dynamic_experiment_execution_demonstrated": bool(
                    passed and step.phase in {"action", "observe", "assert"}
                ),
                "impact_contract_id": contract.get("contract_id"),
                # Generic Agent-authored stdout predicates are useful runtime
                # observations, but they are not an independent platform Oracle.
                # A typed platform observer must mint verdict-bearing metadata.
                "agent_assertion_contract_matched": agent_assertion_matched,
                "agent_assertion_failed": agent_assertion_failed,
                "platform_oracle_validated": False,
                "impact_contract_satisfied": False,
                "oracle_refuted": False,
                "agent_claimed_oracle": (
                    {
                        "observed_fact": {
                            "kind": step.observation_kind,
                            "fact": contract.get("observed_fact"),
                            "impact": contract.get("impact"),
                            "capsule_id": capsule.id,
                            "step_id": step.id,
                        }
                    }
                    if agent_assertion_matched
                    else {}
                ),
                **runtime_metadata,
            }
            evidence = self.evidence.command(
                session,
                scan_id=capsule.scan_id,
                task_id=capsule.task_id,
                kind="dynamic_experiment.adb",
                result=result,
                metadata=evidence_metadata,
            )
            observation_ids: list[str] = []
            if step.observation_kind is not None:
                observation_key = hashlib.sha256(
                    json.dumps(
                        {
                            "capsule_id": capsule.id,
                            "step_id": step.id,
                            "attempt": receipt.attempt,
                            "evidence_id": evidence.id,
                            "kind": step.observation_kind,
                        },
                        sort_keys=True,
                    ).encode()
                ).hexdigest()
                observation = RuntimeObservation(
                    scan_id=capsule.scan_id,
                    task_id=capsule.task_id,
                    finding_id=capsule.finding_id,
                    observation_key=observation_key,
                    kind=step.observation_kind,
                    source="adb",
                    evidence_ids=[evidence.id],
                    payload={
                        "capsule_id": capsule.id,
                        "step_id": step.id,
                        "exit_code": result.exit_code,
                        "matched": passed,
                        "stdout": result.stdout[-50_000:],
                        "stderr": result.stderr[-10_000:],
                    },
                    environment={"device_serial": capsule.device_serial},
                )
                session.add(observation)
                session.flush()
                observation_ids.append(observation.id)
                finding = (
                    session.get(Finding, capsule.finding_id)
                    if capsule.finding_id is not None
                    else None
                )
                if finding is not None and passed:
                    projected = project_runtime_observation_gap(
                        finding,
                        observation_id=observation.id,
                        evidence_ids=[evidence.id],
                        task_id=str(capsule.task_id or "dynamic_experiment"),
                        observation_kind=observation.kind,
                    )
                    if projected:
                        invalidate_scan_materialized_summary(
                            session,
                            capsule.scan_id,
                            reason="dynamic_experiment_runtime_observation",
                        )
            if step.capture_stdout_as is not None:
                capsule.state_json = {
                    **dict(capsule.state_json or {}),
                    step.capture_stdout_as: result.stdout.strip()[-50_000:],
                }
            receipt.status = "passed" if passed else "failed"
            receipt.evidence_ids = [evidence.id]
            receipt.observation_ids = observation_ids
            receipt.result_json = {
                "checks": checks,
                "timed_out": result.timed_out,
                "canceled": result.canceled,
            }
            receipt.error = None if passed else self._failure_message(result, checks)
            receipt.completed_at = _now()
            add_event(
                session,
                capsule.scan_id,
                "dynamic_experiment.step_completed",
                f"动态实验步骤{'通过' if passed else '未通过'}：{step.title}",
                {
                    "capsule_id": capsule.id,
                    "step_id": step.id,
                    "phase": step.phase,
                    "status": receipt.status,
                    "evidence_id": evidence.id,
                },
            )
            session.commit()
        return passed

    @staticmethod
    def _failure_message(result: Any, checks: dict[str, Any]) -> str:
        if result.timed_out:
            return "ADB step timed out"
        if result.canceled:
            return "ADB step was canceled"
        if not checks["exit_code"]["matched"]:
            return f"unexpected exit code {result.exit_code}"
        return "ADB output did not satisfy the declared assertion"

    @staticmethod
    def _render_argument(value: str, state: dict[str, Any]) -> str:
        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in state:
                raise ValueError(f"dynamic experiment state value is unavailable: {key}")
            item = state[key]
            return item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))

        return _STATE_REFERENCE.sub(replace, value)

    def _step_passed(self, capsule_id: str, step_id: str) -> bool:
        with self.database.session_factory() as session:
            return (
                session.scalar(
                    select(DynamicExperimentReceipt.id).where(
                        DynamicExperimentReceipt.capsule_id == capsule_id,
                        DynamicExperimentReceipt.step_id == step_id,
                        DynamicExperimentReceipt.status == "passed",
                    )
                )
                is not None
            )

    def _cancel_requested(self, capsule_id: str) -> bool:
        with self.database.session_factory() as session:
            value = session.scalar(
                select(DynamicExperimentCapsule.cancel_requested).where(
                    DynamicExperimentCapsule.id == capsule_id
                )
            )
            return bool(value)

    def _mark_paused(self, capsule_id: str, failures: list[str]) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            assert capsule is not None
            capsule.status = "paused"
            capsule.error = f"step requires retry: {failures[0]}"
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "verdict": "inconclusive",
                "failed_step_ids": failures,
                "resumable": True,
            }
            add_event(
                session,
                capsule.scan_id,
                "dynamic_experiment.paused",
                "动态实验未满足断言，已保留现场和断点供继续执行",
                {"capsule_id": capsule.id, "failed_step_ids": failures},
            )
            session.commit()

    def _mark_completed(self, capsule_id: str, cleanup_failures: list[str]) -> None:
        agent_assertion_matched = self._contract_satisfied(capsule_id)
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            assert capsule is not None
            capsule.status = "completed"
            capsule.completed_at = _now()
            capsule.error = (
                f"cleanup incomplete: {', '.join(cleanup_failures)}" if cleanup_failures else None
            )
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "verdict": "passed",
                "agent_assertion_contract_matched": agent_assertion_matched,
                "platform_oracle_validated": False,
                "harm_demonstrated": False,
                "cleanup_complete": not cleanup_failures,
                "cleanup_failed_step_ids": cleanup_failures,
            }
            add_event(
                session,
                capsule.scan_id,
                "dynamic_experiment.completed",
                "状态化动态实验已完成",
                {
                    "capsule_id": capsule.id,
                    "cleanup_complete": not cleanup_failures,
                },
            )
            session.commit()

    def _contract_satisfied(self, capsule_id: str) -> bool:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return False
            contract = dict(capsule.impact_contract or {})
            assertion_step_ids = [
                str(value)
                for value in contract.get("assertion_step_ids", [])
                if isinstance(value, str)
            ]
            observation_kinds = {
                str(value)
                for value in contract.get("observation_kinds", [])
                if isinstance(value, str)
            }
            steps_by_id = {
                str(item.get("id")): item
                for item in capsule.steps
                if isinstance(item, dict) and item.get("id")
            }
            if not (
                assertion_step_ids
                and observation_kinds
                and contract.get("contract_id")
                and contract.get("impact")
                and contract.get("observed_fact")
                and all(
                    isinstance(step := steps_by_id.get(step_id), dict)
                    and step.get("phase") == "assert"
                    and step.get("observation_kind") in observation_kinds
                    for step_id in assertion_step_ids
                )
            ):
                return False
            passed = set(
                session.scalars(
                    select(DynamicExperimentReceipt.step_id).where(
                        DynamicExperimentReceipt.capsule_id == capsule_id,
                        DynamicExperimentReceipt.status == "passed",
                        DynamicExperimentReceipt.step_id.in_(assertion_step_ids),
                    )
                )
            )
            return set(assertion_step_ids) <= passed

    def _mark_canceled(self, capsule_id: str) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return
            capsule.status = "canceled"
            capsule.cancel_requested = True
            capsule.completed_at = _now()
            capsule.error = "dynamic experiment was canceled"
            session.commit()

    def _mark_execution_error(self, capsule_id: str, error: str) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return
            capsule.status = "paused"
            capsule.error = error
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "verdict": "inconclusive",
                "resumable": True,
                "platform_error": error,
            }
            add_event(
                session,
                capsule.scan_id,
                "dynamic_experiment.paused",
                "动态实验因执行错误暂停，已保留断点",
                {"capsule_id": capsule.id, "error": error},
            )
            session.commit()

    def _mark_preparation_error(self, capsule_id: str, error: str) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return
            capsule.status = "failed"
            capsule.completed_at = _now()
            capsule.error = error
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "verdict": "inconclusive",
                "resumable": False,
                "failure_stage": "policy_validation",
                "platform_error": error,
            }
            add_event(
                session,
                capsule.scan_id,
                "dynamic_experiment.failed",
                "动态实验未通过平台命令策略校验",
                {"capsule_id": capsule.id, "error": error},
            )
            session.commit()

    def _record_queue(self, capsule_id: str, position: int) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "device_queue_position": position,
            }
            session.commit()

    def _record_acquired(
        self,
        capsule_id: str,
        waited_seconds: float,
        adapter: AdbDeviceAdapter,
    ) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return
            capsule.device_serial = adapter.serial
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "device_wait_seconds": round(waited_seconds, 3),
            }
            session.commit()

    def _record_released(
        self,
        capsule_id: str,
        held_seconds: float,
        _adapter: AdbDeviceAdapter,
    ) -> None:
        with self.database.session_factory() as session:
            capsule = session.get(DynamicExperimentCapsule, capsule_id)
            if capsule is None:
                return
            capsule.result_json = {
                **dict(capsule.result_json or {}),
                "device_held_seconds": round(held_seconds, 3),
            }
            session.commit()
