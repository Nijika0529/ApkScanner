from __future__ import annotations

from copy import deepcopy
from typing import Any

from ..core.db import Database
from ..core.investigation_loop import InvestigationLoopDecision
from ..core.models import InvestigationTask
from ..core.repository import add_event, now


class TaskExecutionStateMixin:
    """Persist task-stage and feedback-loop projections beside the task result."""

    database: Database

    @staticmethod
    def _default_execution_dag() -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "nodes": {
                "seed_analysis": {
                    "status": "pending",
                    "depends_on": [],
                    "resources": ["analysis"],
                },
                "adversarial_review": {
                    "status": "optional",
                    "depends_on": ["seed_analysis"],
                    "resources": ["analysis"],
                },
                "rescue_review": {
                    "status": "optional",
                    "depends_on": ["seed_analysis"],
                    "resources": ["analysis"],
                },
                "poc_build": {
                    "status": "pending",
                    "depends_on": ["seed_analysis"],
                    "resources": ["build"],
                },
                "device_execution": {
                    "status": "pending",
                    "depends_on": ["poc_build"],
                    "resources": ["device"],
                },
                "adaptive_analysis": {
                    "status": "optional",
                    "depends_on": ["device_execution"],
                    "resources": ["analysis"],
                },
                "impact_evaluation": {
                    "status": "pending",
                    "depends_on": ["device_execution", "adaptive_analysis"],
                    "resources": ["platform"],
                },
                "final_synthesis": {
                    "status": "pending",
                    "depends_on": ["impact_evaluation"],
                    "resources": ["analysis"],
                },
            },
        }

    @classmethod
    def _ensure_task_execution_dag(cls, task: InvestigationTask) -> dict[str, Any]:
        result = dict(task.result or {})
        dag = result.get("execution_dag")
        if not isinstance(dag, dict) or not isinstance(dag.get("nodes"), dict):
            dag = cls._default_execution_dag()
            result["execution_dag"] = dag
            task.result = result
        return dag

    def _set_task_stage(
        self,
        scan_id: str,
        task_id: str,
        stage: str,
        status: str,
        **metadata: Any,
    ) -> None:
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None or task.scan_id != scan_id:
                return
            dag = deepcopy(self._ensure_task_execution_dag(task))
            nodes = dag["nodes"]
            node = dict(nodes.get(stage) or {})
            node["status"] = status
            if status == "running" and not node.get("started_at"):
                node["started_at"] = now().isoformat()
            if status in {"completed", "failed", "skipped", "inconclusive"}:
                node["completed_at"] = now().isoformat()
            if metadata:
                node["metadata"] = {**dict(node.get("metadata") or {}), **metadata}
            nodes[stage] = node
            dag["current_stage"] = stage
            dag["updated_at"] = now().isoformat()
            task.result = {**dict(task.result or {}), "execution_dag": dag}
            add_event(
                session,
                scan_id,
                "task.stage.updated",
                f"任务阶段 {stage} 更新为 {status}",
                {
                    "task_id": task_id,
                    "stage": stage,
                    "status": status,
                    "resources": node.get("resources", []),
                    **metadata,
                },
            )
            session.commit()

    def _set_task_investigation_loop(
        self,
        scan_id: str,
        task_id: str,
        *,
        phase: str,
        round_index: int,
        no_progress_rounds: int,
        budget_remaining_seconds: int,
        decision: InvestigationLoopDecision | None = None,
    ) -> None:
        """Persist control state while leaving detailed facts in their existing ledgers."""

        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None or task.scan_id != scan_id:
                return
            result = dict(task.result or {})
            previous = dict(result.get("investigation_loop") or {})
            if previous.get("attempt") != task.attempts:
                previous = {}
            closed = bool(decision is not None and not decision.should_execute)
            timestamp = now().isoformat()
            loop = {
                **previous,
                "schema_version": "1.0",
                "mode": "platform_controlled",
                "status": "closed" if closed else "running",
                "phase": "closed" if closed else phase,
                "attempt": task.attempts,
                "round_index": round_index,
                "no_progress_rounds": no_progress_rounds,
                "budget_remaining_seconds": max(0, budget_remaining_seconds),
                "started_at": previous.get("started_at") or timestamp,
                "updated_at": timestamp,
            }
            if decision is not None:
                loop["decision"] = decision.directive.value
                loop["termination_reason"] = (
                    decision.reason.value if decision.reason is not None else None
                )
            if closed:
                loop["completed_at"] = timestamp
            else:
                loop.pop("completed_at", None)
                loop.pop("termination_reason", None)
            result["investigation_loop"] = loop
            task.result = result
            session.commit()
