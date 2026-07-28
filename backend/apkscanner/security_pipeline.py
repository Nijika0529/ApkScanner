from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Database
from .enums import FindingStatus, HypothesisStatus, ProofAttemptStatus
from .models import (
    HypothesisArgument,
    InvestigationTask,
    ProofAttempt,
    SecurityHypothesis,
)
from .repository import now
from .schemas import AgentRequestedTest


class HypothesisLedger:
    """Persistent claim, counterargument, and proof lineage for AI investigations."""

    def __init__(self, database: Database):
        self.database = database

    def ensure_task_hypotheses(self, task: InvestigationTask) -> list[SecurityHypothesis]:
        claims = list(task.hypotheses) or [
            "The assigned Android entry point may expose security-sensitive behavior."
        ]
        with self.database.session_factory() as session:
            existing = list(
                session.scalars(
                    select(SecurityHypothesis).where(SecurityHypothesis.task_id == task.id)
                )
            )
            by_fingerprint = {item.fingerprint: item for item in existing}
            by_semantic_key = {
                self._semantic_key(
                    item.category,
                    list(item.entry_point_ids),
                    item.claim,
                ): item
                for item in existing
            }
            for claim in claims:
                category = self._category(task.task_type)
                semantic_key = self._semantic_key(
                    category,
                    list(task.target_entry_ids),
                    claim,
                )
                if semantic_key in by_semantic_key:
                    continue
                fingerprint = self._fingerprint(
                    task.scan_id,
                    task.id,
                    category,
                    list(task.target_entry_ids),
                    claim,
                )
                if fingerprint in by_fingerprint:
                    continue
                item = SecurityHypothesis(
                    scan_id=task.scan_id,
                    task_id=task.id,
                    fingerprint=fingerprint,
                    category=category,
                    claim=claim,
                    attacker_model={
                        "identity": "untrusted_third_party_app",
                        "device_access": "local_android_ipc_or_declared_deep_link",
                        "authentication": "guest",
                    },
                    preconditions=[
                        str(value)
                        for value in (task.preconditions or {}).get("items", [])
                        if isinstance(value, str)
                    ],
                    impact="Must be demonstrated by platform-issued evidence.",
                    entry_point_ids=list(task.target_entry_ids),
                    proof_obligations=[
                        {
                            "kind": "reachability",
                            "description": "Show that the declared entry is reachable by the attacker.",
                        },
                        {
                            "kind": "security_impact",
                            "description": (
                                "Show an unauthorized state change, sensitive disclosure, "
                                "privilege boundary bypass, or equivalent concrete impact."
                            ),
                        },
                    ],
                )
                session.add(item)
                by_fingerprint[fingerprint] = item
                by_semantic_key[semantic_key] = item
            session.commit()
            return list(by_fingerprint.values())

    def task_context(self, task_id: str) -> list[dict[str, Any]]:
        with self.database.session_factory() as session:
            items = list(
                session.scalars(
                    select(SecurityHypothesis)
                    .where(SecurityHypothesis.task_id == task_id)
                    .order_by(SecurityHypothesis.created_at)
                )
            )
            return [
                {
                    "id": item.id,
                    "category": item.category,
                    "claim": item.claim,
                    "status": item.status,
                    "attacker_model": item.attacker_model,
                    "preconditions": item.preconditions,
                    "impact": item.impact,
                    "proof_obligations": item.proof_obligations,
                    "support_evidence_ids": item.support_evidence_ids,
                    "refute_evidence_ids": item.refute_evidence_ids,
                }
                for item in items
            ]

    def record_argument(
        self,
        *,
        task_id: str,
        role: str,
        phase: str,
        backend: str,
        model: str | None,
        payload: dict[str, Any],
    ) -> None:
        evidence_ids = [
            value for value in payload.get("evidence_ids", []) if isinstance(value, str)
        ]
        position = {
            "hunter": "support",
            "advocate": "support",
            "critic": "refute",
            "arbiter": "decision",
            "platform": "decision",
        }.get(role, "observation")
        with self.database.session_factory() as session:
            hypotheses = list(
                session.scalars(
                    select(SecurityHypothesis).where(SecurityHypothesis.task_id == task_id)
                )
            )
            for hypothesis in hypotheses:
                session.add(
                    HypothesisArgument(
                        scan_id=hypothesis.scan_id,
                        task_id=task_id,
                        hypothesis_id=hypothesis.id,
                        role=role,
                        position=position,
                        phase=phase,
                        backend=backend,
                        model=model,
                        payload=payload,
                        evidence_ids=evidence_ids,
                    )
                )
                if role == "critic":
                    hypothesis.status = HypothesisStatus.CHALLENGED.value
                    hypothesis.refute_evidence_ids = self._merge_ids(
                        hypothesis.refute_evidence_ids,
                        evidence_ids,
                    )
                elif role in {"hunter", "advocate"}:
                    hypothesis.support_evidence_ids = self._merge_ids(
                        hypothesis.support_evidence_ids,
                        evidence_ids,
                    )
            session.commit()

    def validate_hypothesis_id(self, task_id: str, hypothesis_id: str | None) -> bool:
        if hypothesis_id is None:
            return True
        with self.database.session_factory() as session:
            return (
                session.scalar(
                    select(SecurityHypothesis.id).where(
                        SecurityHypothesis.id == hypothesis_id,
                        SecurityHypothesis.task_id == task_id,
                    )
                )
                is not None
            )

    def plan_proof(
        self,
        *,
        task_id: str,
        test_case_id: str,
        request: AgentRequestedTest,
    ) -> str | None:
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            if task is None or request.entry_point_id not in set(task.target_entry_ids):
                return None
            hypothesis = None
            if request.hypothesis_id:
                hypothesis = session.get(SecurityHypothesis, request.hypothesis_id)
                if (
                    hypothesis is None
                    or hypothesis.task_id != task_id
                    or hypothesis.scan_id != task.scan_id
                ):
                    return None
            else:
                hypothesis = session.scalar(
                    select(SecurityHypothesis)
                    .where(SecurityHypothesis.task_id == task_id)
                    .order_by(SecurityHypothesis.created_at)
                    .limit(1)
                )
            if hypothesis is None:
                return None
            attempt = ProofAttempt(
                scan_id=hypothesis.scan_id,
                task_id=task_id,
                hypothesis_id=hypothesis.id,
                test_case_id=test_case_id,
                prover="android_entry_probe",
                status=ProofAttemptStatus.PLANNED.value,
                plan=request.model_dump(mode="json"),
            )
            if hypothesis.status != HypothesisStatus.PROVEN.value:
                hypothesis.status = HypothesisStatus.PROOF_PLANNED.value
            session.add(attempt)
            session.commit()
            return attempt.id

    def start_proof(self, proof_attempt_id: str | None) -> None:
        if proof_attempt_id is None:
            return
        with self.database.session_factory() as session:
            attempt = session.get(ProofAttempt, proof_attempt_id)
            if attempt is None:
                return
            attempt.status = ProofAttemptStatus.EXECUTING.value
            attempt.started_at = now()
            hypothesis = session.get(SecurityHypothesis, attempt.hypothesis_id)
            if (
                hypothesis is not None
                and hypothesis.status != HypothesisStatus.PROVEN.value
            ):
                hypothesis.status = HypothesisStatus.EXECUTING.value
            session.commit()

    def complete_proof(
        self,
        proof_attempt_id: str | None,
        evidence: list[dict[str, Any]],
        *,
        error: str | None = None,
    ) -> None:
        if proof_attempt_id is None:
            return
        evidence_ids = [
            item["id"] for item in evidence if isinstance(item.get("id"), str)
        ]
        request_ids = {
            item.get("metadata", {}).get("request_id")
            for item in evidence
            if item.get("kind") == "blackbox.probe_app"
            and item.get("exit_code") == 0
        }
        observed_ids = {
            item.get("metadata", {}).get("request_id")
            for item in evidence
            if item.get("kind") == "blackbox.logcat"
            and item.get("metadata", {}).get("request_observed")
        }
        poc_request_ids = {
            item.get("metadata", {}).get("request_id")
            for item in evidence
            if item.get("kind") == "blackbox.poc_launch"
            and item.get("exit_code") == 0
        }
        poc_observed_ids = {
            item.get("metadata", {}).get("request_id")
            for item in evidence
            if item.get("kind") == "blackbox.poc_logcat"
            and item.get("metadata", {}).get("request_observed")
        }
        correlated = bool((request_ids & observed_ids) - {None})
        poc_correlated = bool((poc_request_ids & poc_observed_ids) - {None})
        probe_succeeded = correlated and any(
            item.get("kind") == "blackbox.logcat"
            and item.get("metadata", {}).get("request_id") in request_ids
            and item.get("metadata", {}).get("probe_success")
            for item in evidence
        )
        poc_succeeded = poc_correlated and any(
            item.get("kind") == "blackbox.poc_logcat"
            and item.get("metadata", {}).get("request_id") in poc_request_ids
            and item.get("metadata", {}).get("poc_success")
            for item in evidence
        )
        poc_claimed_impact = any(
            item.get("kind") == "blackbox.poc_logcat"
            and item.get("metadata", {}).get("poc_claimed_security_impact") is True
            for item in evidence
        )
        instrumented = any(
            item.get("kind") == "instrumented.frida"
            and item.get("metadata", {}).get("capture_success")
            and item.get("metadata", {}).get("observation_count", 0) > 0
            for item in evidence
        )
        execution_demonstrated = probe_succeeded or poc_succeeded or instrumented
        impact_observed = any(
            item.get("metadata", {}).get("security_impact_observed") is True
            for item in evidence
        )
        oracle_refuted = any(
            item.get("metadata", {}).get("oracle_refuted") is True
            for item in evidence
        )
        harm_demonstrated = execution_demonstrated and impact_observed
        status = (
            ProofAttemptStatus.FAILED.value
            if error
            else ProofAttemptStatus.PROVEN.value
            if harm_demonstrated
            else ProofAttemptStatus.REFUTED.value
            if oracle_refuted
            else ProofAttemptStatus.INCONCLUSIVE.value
        )
        with self.database.session_factory() as session:
            attempt = session.get(ProofAttempt, proof_attempt_id)
            if attempt is None:
                return
            attempt.status = status
            attempt.oracle = {
                "schema_version": "1.0",
                "correlated_probe_result": correlated,
                "probe_succeeded": probe_succeeded,
                "correlated_poc_result": poc_correlated,
                "poc_succeeded": poc_succeeded,
                "poc_claimed_security_impact": poc_claimed_impact,
                "instrumented_observation": instrumented,
                "execution_demonstrated": execution_demonstrated,
                "security_impact_observed": impact_observed,
                "oracle_refuted": oracle_refuted,
                "harm_demonstrated": harm_demonstrated,
                "policy": (
                    "A model claim and successful reachability test are not proof of harm. "
                    "Harm requires both demonstrated execution and a platform Prover's "
                    "security_impact_observed signal."
                ),
            }
            attempt.evidence_ids = evidence_ids
            attempt.harm_demonstrated = harm_demonstrated
            attempt.error = error
            attempt.completed_at = now()
            hypothesis = session.get(SecurityHypothesis, attempt.hypothesis_id)
            if hypothesis is not None:
                if harm_demonstrated:
                    hypothesis.status = HypothesisStatus.PROVEN.value
                    hypothesis.support_evidence_ids = self._merge_ids(
                        hypothesis.support_evidence_ids,
                        evidence_ids,
                    )
                elif (
                    oracle_refuted
                    and hypothesis.status != HypothesisStatus.PROVEN.value
                ):
                    hypothesis.status = HypothesisStatus.CHALLENGED.value
                    hypothesis.refute_evidence_ids = self._merge_ids(
                        hypothesis.refute_evidence_ids,
                        evidence_ids,
                    )
                elif hypothesis.status != HypothesisStatus.PROVEN.value:
                    hypothesis.status = HypothesisStatus.INCONCLUSIVE.value
            session.commit()

    def finalize(
        self,
        *,
        task_id: str,
        payload: dict[str, Any],
        result_value: str,
        backend: str,
        model: str | None,
        session: Session | None = None,
    ) -> None:
        if session is None:
            with self.database.session_factory() as owned_session:
                self._finalize(
                    owned_session,
                    task_id=task_id,
                    payload=payload,
                    result_value=result_value,
                    backend=backend,
                    model=model,
                )
                owned_session.commit()
            return
        self._finalize(
            session,
            task_id=task_id,
            payload=payload,
            result_value=result_value,
            backend=backend,
            model=model,
        )

    @staticmethod
    def _finalize(
        session: Session,
        *,
        task_id: str,
        payload: dict[str, Any],
        result_value: str,
        backend: str,
        model: str | None,
    ) -> None:
        if result_value in {
            FindingStatus.SUPPORTED_STATIC.value,
            FindingStatus.REPRODUCED_BLACKBOX.value,
            FindingStatus.OBSERVED_INSTRUMENTED.value,
        }:
            status = HypothesisStatus.ACCEPTED_FOR_PROOF.value
        elif result_value == FindingStatus.NOT_REPRODUCED.value:
            status = HypothesisStatus.REFUTED.value
        else:
            status = HypothesisStatus.INCONCLUSIVE.value
        confidence = {"high": 90, "medium": 65, "low": 35}.get(
            str(payload.get("confidence")),
            0,
        )
        evidence_ids = [
            value for value in payload.get("evidence_ids", []) if isinstance(value, str)
        ]
        hypotheses = list(
            session.scalars(
                select(SecurityHypothesis).where(SecurityHypothesis.task_id == task_id)
            )
        )
        argument_payload = {**payload, "platform_result": result_value}
        for hypothesis in hypotheses:
            session.add(
                HypothesisArgument(
                    scan_id=hypothesis.scan_id,
                    task_id=task_id,
                    hypothesis_id=hypothesis.id,
                    role="arbiter",
                    position="decision",
                    phase="platform_validation",
                    backend=backend,
                    model=model,
                    payload=argument_payload,
                    evidence_ids=evidence_ids,
                )
            )
            harm_demonstrated = session.scalar(
                select(ProofAttempt.id)
                .where(
                    ProofAttempt.hypothesis_id == hypothesis.id,
                    ProofAttempt.harm_demonstrated.is_(True),
                )
                .limit(1)
            )
            hypothesis.status = (
                HypothesisStatus.PROVEN.value
                if harm_demonstrated is not None
                else status
            )
            hypothesis.confidence_score = confidence
            hypothesis.impact = str(
                payload.get("summary")
                or "No concrete security impact was established."
            )
            if status in {
                HypothesisStatus.PROVEN.value,
                HypothesisStatus.ACCEPTED_FOR_PROOF.value,
            }:
                hypothesis.support_evidence_ids = HypothesisLedger._merge_ids(
                    hypothesis.support_evidence_ids,
                    evidence_ids,
                )
            elif status == HypothesisStatus.REFUTED.value:
                hypothesis.refute_evidence_ids = HypothesisLedger._merge_ids(
                    hypothesis.refute_evidence_ids,
                    evidence_ids,
                )
            hypothesis.metadata_json = {
                **dict(hypothesis.metadata_json or {}),
                "platform_result": result_value,
                "severity_proposal": payload.get("severity_proposal"),
                "platform_severity": payload.get("platform_severity"),
            }

    def task_harm_demonstrated(self, task_id: str) -> bool:
        with self.database.session_factory() as session:
            return (
                session.scalar(
                    select(ProofAttempt.id)
                    .where(
                        ProofAttempt.task_id == task_id,
                        ProofAttempt.harm_demonstrated.is_(True),
                    )
                    .limit(1)
                )
                is not None
            )

    def task_proof_result(self, task_id: str) -> tuple[str, list[str]] | None:
        """Return the strongest platform proof independently of the model's conclusion."""
        with self.database.session_factory() as session:
            attempts = list(
                session.scalars(
                    select(ProofAttempt)
                    .where(
                        ProofAttempt.task_id == task_id,
                        ProofAttempt.harm_demonstrated.is_(True),
                    )
                    .order_by(ProofAttempt.created_at)
                )
            )
            if not attempts:
                return None
            instrumented = any(
                bool((attempt.oracle or {}).get("instrumented_observation"))
                for attempt in attempts
            )
            evidence_ids = list(
                dict.fromkeys(
                    evidence_id
                    for attempt in attempts
                    for evidence_id in attempt.evidence_ids
                )
            )
            return (
                FindingStatus.OBSERVED_INSTRUMENTED.value
                if instrumented
                else FindingStatus.REPRODUCED_BLACKBOX.value,
                evidence_ids,
            )

    @staticmethod
    def _fingerprint(
        scan_id: str,
        task_id: str,
        category: str,
        entry_point_ids: list[str],
        claim: str,
    ) -> str:
        value = json.dumps(
            {
                "scan_id": scan_id,
                "task_id": task_id,
                "category": category,
                "entry_point_ids": sorted(entry_point_ids),
                "claim": " ".join(claim.lower().split()),
            },
            sort_keys=True,
        )
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def _semantic_key(
        category: str,
        entry_point_ids: list[str],
        claim: str,
    ) -> str:
        return json.dumps(
            {
                "category": category,
                "entry_point_ids": sorted(entry_point_ids),
                "claim": " ".join(claim.lower().split()),
            },
            sort_keys=True,
        )

    @staticmethod
    def _category(task_type: str) -> str:
        return {
            "deep_link": "android.deep_link",
            "component": "android.exported_component",
            "static_review": "android.static_review",
        }.get(task_type, f"android.{task_type}")

    @staticmethod
    def _merge_ids(existing: list[str], added: list[str]) -> list[str]:
        return list(dict.fromkeys([*existing, *added]))
