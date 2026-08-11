from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .db import Database
from .enums import FindingStatus, HypothesisStatus, ProofAttemptStatus
from .models import (
    EntryPoint,
    Finding,
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
            proven_hypothesis_ids = set(
                session.scalars(
                    select(ProofAttempt.hypothesis_id).where(
                        ProofAttempt.task_id == task_id,
                        ProofAttempt.harm_demonstrated.is_(True),
                    )
                )
            )
            hypothesis_ids = {hypothesis.id for hypothesis in hypotheses}
            scoped_ids = {
                value
                for value in payload.get("hypotheses_tested", [])
                if isinstance(value, str) and value in hypothesis_ids
            }
            for assessment in payload.get("hypothesis_assessments", []):
                if not isinstance(assessment, dict):
                    continue
                hypothesis_id = assessment.get("hypothesis_id")
                if isinstance(hypothesis_id, str) and hypothesis_id in hypothesis_ids:
                    scoped_ids.add(hypothesis_id)
            for objection in payload.get("review_objections", []):
                if not isinstance(objection, dict):
                    continue
                hypothesis_id = objection.get("hypothesis_id")
                if isinstance(hypothesis_id, str) and hypothesis_id in hypothesis_ids:
                    scoped_ids.add(hypothesis_id)
            selected = (
                [hypothesis for hypothesis in hypotheses if hypothesis.id in scoped_ids]
                if scoped_ids
                else hypotheses
            )
            for hypothesis in selected:
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
                    # A Critic is an advisory model argument. It may challenge
                    # model reasoning, but it can never downgrade a platform
                    # harm proof or relabel its evidence as refutation.
                    if (
                        hypothesis.id not in proven_hypothesis_ids
                        and hypothesis.status != HypothesisStatus.PROVEN.value
                    ):
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
            requested_entry = session.get(EntryPoint, request.entry_point_id)
            if task is None:
                return None
            assigned_seed = request.entry_point_id in set(task.target_entry_ids)
            if not assigned_seed and (
                requested_entry is None
                or requested_entry.scan_id != task.scan_id
                or not requested_entry.exported
                or (requested_entry.metadata_json or {}).get("effective_enabled") is False
            ):
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
            if attempt is None or attempt.status != ProofAttemptStatus.PLANNED.value:
                return
            started_at = now()
            changed = session.execute(
                update(ProofAttempt)
                .where(
                    ProofAttempt.id == proof_attempt_id,
                    ProofAttempt.status == ProofAttemptStatus.PLANNED.value,
                )
                .values(
                    status=ProofAttemptStatus.EXECUTING.value,
                    started_at=started_at,
                )
            )
            if changed.rowcount != 1:
                session.rollback()
                return
            hypothesis = session.get(SecurityHypothesis, attempt.hypothesis_id)
            if hypothesis is not None and hypothesis.status != HypothesisStatus.PROVEN.value:
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
        evidence_ids = [item["id"] for item in evidence if isinstance(item.get("id"), str)]
        request_ids = {
            item.get("metadata", {}).get("request_id")
            for item in evidence
            if item.get("kind") == "blackbox.probe_app" and item.get("exit_code") == 0
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
            if item.get("kind") == "blackbox.poc_launch" and item.get("exit_code") == 0
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
        platform_observed_poc_effect = any(
            item.get("kind") == "blackbox.poc_ui_dump"
            and item.get("metadata", {}).get("request_id") in poc_request_ids
            and item.get("metadata", {}).get("impact_contract_satisfied") is True
            for item in evidence
        )
        execution_demonstrated = (
            probe_succeeded or poc_succeeded or platform_observed_poc_effect
        )
        observed_facts: list[dict[str, Any]] = []
        for item in evidence:
            metadata = item.get("metadata", {})
            oracle_metadata = metadata.get("oracle")
            if not isinstance(oracle_metadata, dict):
                continue
            fact = oracle_metadata.get("observed_fact")
            if not isinstance(fact, dict):
                continue
            observed_facts.append(
                {
                    **fact,
                    "evidence_ids": (
                        [str(item["id"])] if isinstance(item.get("id"), str) else []
                    ),
                }
            )
        impact_observed = any(
            item.get("metadata", {}).get("impact_contract_satisfied") is True
            for item in evidence
        )
        oracle_refuted = any(
            item.get("metadata", {}).get("oracle_refuted") is True for item in evidence
        )
        android16_verdict_eligible = not any(
            item.get("metadata", {}).get("android16_verdict_eligible") is False
            for item in evidence
        )
        dynamic_verdict_eligible = not any(
            item.get("metadata", {}).get(
                "dynamic_verdict_eligible",
                item.get("metadata", {}).get("android16_verdict_eligible", True),
            )
            is False
            for item in evidence
        )
        release_gate_eligible = not any(
            item.get("metadata", {}).get(
                "release_gate_eligible",
                item.get("metadata", {}).get("android16_verdict_eligible", True),
            )
            is False
            for item in evidence
        )
        verdict_scopes = list(
            dict.fromkeys(
                str(item.get("metadata", {}).get("verdict_scope"))
                for item in evidence
                if item.get("metadata", {}).get("verdict_scope")
            )
        )
        verdict_scope = (
            "android16_release"
            if release_gate_eligible
            else "development_legacy"
            if dynamic_verdict_eligible
            else "non_verdict_smoke"
        )
        if verdict_scopes:
            verdict_scope = verdict_scopes[0]
        compatibility_smoke_only = not dynamic_verdict_eligible
        harm_demonstrated = (
            dynamic_verdict_eligible
            and execution_demonstrated
            and impact_observed
        )
        status = (
            ProofAttemptStatus.FAILED.value
            if error
            else ProofAttemptStatus.PROVEN.value
            if harm_demonstrated
            else ProofAttemptStatus.REFUTED.value
            if oracle_refuted and dynamic_verdict_eligible
            else ProofAttemptStatus.INCONCLUSIVE.value
        )
        with self.database.session_factory() as session:
            attempt = session.get(ProofAttempt, proof_attempt_id)
            if attempt is None or attempt.status not in {
                ProofAttemptStatus.PLANNED.value,
                ProofAttemptStatus.EXECUTING.value,
            }:
                return
            oracle = {
                "schema_version": "1.0",
                "correlated_probe_result": correlated,
                "probe_succeeded": probe_succeeded,
                "correlated_poc_result": poc_correlated,
                "poc_succeeded": poc_succeeded,
                "poc_claimed_security_impact": poc_claimed_impact,
                "platform_observed_poc_effect": platform_observed_poc_effect,
                "execution_demonstrated": execution_demonstrated,
                "security_impact_observed": impact_observed,
                "impact_contract_ids": list(
                    dict.fromkeys(
                        str(contract_id)
                        for item in evidence
                        if (
                            contract_id := item.get("metadata", {}).get(
                                "impact_contract_id"
                            )
                        )
                    )
                ),
                "observed_facts": observed_facts,
                "oracle_refuted": oracle_refuted,
                "android16_verdict_eligible": android16_verdict_eligible,
                "dynamic_verdict_eligible": dynamic_verdict_eligible,
                "release_gate_eligible": release_gate_eligible,
                "compatibility_smoke_only": compatibility_smoke_only,
                "verdict_scope": verdict_scope,
                "harm_demonstrated": harm_demonstrated,
                "policy": (
                    "A model claim and successful reachability test are not proof of harm. "
                    "Harm requires both demonstrated execution and a platform Prover's "
                    "satisfied ImpactContract on a device eligible for the selected "
                    "validation profile. Development legacy verdicts become Findings but "
                    "remain ineligible for the Android 16 release gate."
                ),
            }
            completed_at = now()
            changed = session.execute(
                update(ProofAttempt)
                .where(
                    ProofAttempt.id == proof_attempt_id,
                    ProofAttempt.status.in_(
                        [
                            ProofAttemptStatus.PLANNED.value,
                            ProofAttemptStatus.EXECUTING.value,
                        ]
                    ),
                )
                .values(
                    status=status,
                    oracle=oracle,
                    evidence_ids=evidence_ids,
                    harm_demonstrated=harm_demonstrated,
                    error=error,
                    completed_at=completed_at,
                )
            )
            if changed.rowcount != 1:
                session.rollback()
                return
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
                    and dynamic_verdict_eligible
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
        task_evidence_ids = [
            value for value in payload.get("evidence_ids", []) if isinstance(value, str)
        ]
        hypotheses = list(
            session.scalars(select(SecurityHypothesis).where(SecurityHypothesis.task_id == task_id))
        )
        hypothesis_ids = {hypothesis.id for hypothesis in hypotheses}
        tested_ids = {
            value
            for value in payload.get("hypotheses_tested", [])
            if isinstance(value, str) and value in hypothesis_ids
        }
        assessments = {
            str(item["hypothesis_id"]): item
            for item in payload.get("hypothesis_assessments", [])
            if isinstance(item, dict)
            and isinstance(item.get("hypothesis_id"), str)
            and item["hypothesis_id"] in hypothesis_ids
        }
        tested_ids.update(assessments)
        legacy_blanket = not assessments and not tested_ids
        for hypothesis in hypotheses:
            assessment = assessments.get(hypothesis.id)
            assessment_result = (
                str(assessment.get("verdict"))
                if assessment is not None
                else result_value
                if legacy_blanket or hypothesis.id in tested_ids
                else ""
            )
            model_status = HypothesisLedger._status_for_verdict(assessment_result)
            confidence_value = (
                assessment.get("confidence")
                if assessment is not None
                else payload.get("confidence")
            )
            confidence = {"high": 90, "medium": 65, "low": 35}.get(
                str(confidence_value),
                0,
            )
            evidence_ids = (
                [
                    value
                    for value in assessment.get("evidence_ids", [])
                    if isinstance(value, str) and value in set(task_evidence_ids)
                ]
                if assessment is not None
                else task_evidence_ids
                if legacy_blanket or hypothesis.id in tested_ids
                else []
            )
            model_disposition = (
                "assessed"
                if assessment is not None
                else "legacy_task_verdict"
                if legacy_blanket
                else "tested_without_structured_assessment"
                if hypothesis.id in tested_ids
                else "not_assessed_by_agent"
            )
            proven_attempts = list(
                session.scalars(
                    select(ProofAttempt).where(
                        ProofAttempt.hypothesis_id == hypothesis.id,
                        ProofAttempt.harm_demonstrated.is_(True),
                    )
                )
            )
            proof_evidence_ids = list(
                dict.fromkeys(
                    evidence_id
                    for attempt in proven_attempts
                    for evidence_id in attempt.evidence_ids
                )
            )
            platform_proven = bool(proven_attempts)
            effective_status = HypothesisStatus.PROVEN.value if platform_proven else model_status
            effective_verdict = (
                FindingStatus.REPRODUCED_BLACKBOX.value
                if platform_proven
                else assessment_result or None
            )
            effective_evidence_ids = HypothesisLedger._merge_ids(
                evidence_ids,
                proof_evidence_ids,
            )
            disposition = "platform_proven" if platform_proven else model_disposition
            effective_assessment = (
                {
                    **dict(assessment or {}),
                    "hypothesis_id": hypothesis.id,
                    "verdict": FindingStatus.REPRODUCED_BLACKBOX.value,
                    "evidence_ids": effective_evidence_ids,
                    "confidence": "high",
                }
                if platform_proven
                else assessment
            )
            closure_receipt = {
                "schema_version": "1.0",
                "hypothesis_id": hypothesis.id,
                "disposition": disposition,
                "verdict": effective_verdict,
                "evidence_ids": effective_evidence_ids,
                "proof_gaps": (
                    []
                    if platform_proven
                    else list(assessment.get("proof_gaps", []))
                    if assessment is not None
                    else []
                ),
            }
            argument_payload = {
                "platform_result": (
                    FindingStatus.REPRODUCED_BLACKBOX.value if platform_proven else result_value
                ),
                "assessment": effective_assessment,
                "model_assessment": assessment,
                "platform_proof_override": platform_proven,
                "closure_receipt": closure_receipt,
            }
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
                    evidence_ids=effective_evidence_ids,
                )
            )
            hypothesis.status = effective_status
            hypothesis.confidence_score = 100 if platform_proven else confidence
            if not platform_proven or not hypothesis.impact:
                hypothesis.impact = str(
                    (
                        assessment.get("sink") or assessment.get("reachable_path")
                        if assessment is not None
                        else None
                    )
                    or payload.get("summary")
                    or "No concrete security impact was established."
                )
            if effective_status in {
                HypothesisStatus.PROVEN.value,
                HypothesisStatus.ACCEPTED_FOR_PROOF.value,
            }:
                hypothesis.support_evidence_ids = HypothesisLedger._merge_ids(
                    hypothesis.support_evidence_ids,
                    effective_evidence_ids,
                )
            elif effective_status == HypothesisStatus.REFUTED.value:
                hypothesis.refute_evidence_ids = HypothesisLedger._merge_ids(
                    hypothesis.refute_evidence_ids,
                    effective_evidence_ids,
                )
            hypothesis.metadata_json = {
                **dict(hypothesis.metadata_json or {}),
                "platform_result": argument_payload["platform_result"],
                "assessment": effective_assessment,
                "model_assessment": assessment,
                "platform_proof_override": platform_proven,
                "closure_receipt": closure_receipt,
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
            evidence_ids = list(
                dict.fromkeys(
                    evidence_id for attempt in attempts for evidence_id in attempt.evidence_ids
                )
            )
            return FindingStatus.REPRODUCED_BLACKBOX.value, evidence_ids

    def task_proven_hypotheses(self, task_id: str) -> dict[str, list[str]]:
        """Return immutable platform harm receipts grouped by hypothesis."""

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
            receipts: dict[str, list[str]] = {}
            for attempt in attempts:
                receipts[attempt.hypothesis_id] = self._merge_ids(
                    receipts.get(attempt.hypothesis_id, []),
                    attempt.evidence_ids,
                )
            return receipts

    def task_hypothesis_progress(self, task_id: str) -> dict[str, Any]:
        """Return proof progress without making one proven claim task-terminal.

        Platform harm receipts are the only facts that close a hypothesis during
        live exploration. Model verdicts are persisted later by ``finalize`` and
        must not cause the device loop to skip a different, still-open claim.
        """

        with self.database.session_factory() as session:
            hypotheses = list(
                session.scalars(
                    select(SecurityHypothesis)
                    .where(SecurityHypothesis.task_id == task_id)
                    .order_by(SecurityHypothesis.created_at)
                )
            )
            attempts = list(
                session.scalars(
                    select(ProofAttempt)
                    .where(ProofAttempt.task_id == task_id)
                    .order_by(ProofAttempt.created_at)
                )
            )
        hypothesis_ids = [item.id for item in hypotheses]
        proven_ids = {item.hypothesis_id for item in attempts if item.harm_demonstrated}
        attempts_by_hypothesis: dict[str, list[ProofAttempt]] = {}
        for attempt in attempts:
            attempts_by_hypothesis.setdefault(attempt.hypothesis_id, []).append(attempt)
        proven = [item for item in hypothesis_ids if item in proven_ids]
        unresolved = [item for item in hypothesis_ids if item not in proven_ids]
        stages: dict[str, dict[str, Any]] = {}
        for hypothesis in hypotheses:
            owned_attempts = attempts_by_hypothesis.get(hypothesis.id, [])
            if hypothesis.id in proven_ids:
                stage = "impact_reproduced"
            elif any(item.status == ProofAttemptStatus.REFUTED.value for item in owned_attempts):
                stage = "case_refuted"
            elif any(
                bool((item.oracle or {}).get("execution_demonstrated"))
                for item in owned_attempts
            ):
                stage = "ordinary_uid_reachable"
            elif owned_attempts:
                stage = "oracle_gap"
            elif hypothesis.status in {
                HypothesisStatus.ACCEPTED_FOR_PROOF.value,
                HypothesisStatus.PROOF_PLANNED.value,
                HypothesisStatus.EXECUTING.value,
                HypothesisStatus.INCONCLUSIVE.value,
            }:
                stage = "static_path_supported"
            elif hypothesis.status == HypothesisStatus.REFUTED.value:
                stage = "refuted_static"
            else:
                stage = "untriaged"
            stages[hypothesis.id] = {
                "stage": stage,
                "hypothesis_status": hypothesis.status,
                "proof_attempt_count": len(owned_attempts),
                "latest_attempt_status": (
                    owned_attempts[-1].status if owned_attempts else None
                ),
                "latest_error": owned_attempts[-1].error if owned_attempts else None,
            }
        return {
            "schema_version": "1.0",
            "total": len(hypothesis_ids),
            "proven_count": len(proven),
            "unresolved_count": len(unresolved),
            "proven_hypothesis_ids": proven,
            "unresolved_hypothesis_ids": unresolved,
            "proof_stage_by_hypothesis": stages,
            "all_platform_proven": bool(hypothesis_ids) and not unresolved,
        }

    def task_all_hypotheses_proven(self, task_id: str) -> bool:
        """Return true only when every issued hypothesis has a harm receipt."""

        return bool(self.task_hypothesis_progress(task_id)["all_platform_proven"])

    def task_proven_severity(self, task_id: str) -> str | None:
        """Return the strongest persisted severity backed by a platform proof."""

        severity_rank = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        with self.database.session_factory() as session:
            severities = list(
                session.scalars(
                    select(Finding.severity)
                    .join(
                        SecurityHypothesis,
                        SecurityHypothesis.final_finding_id == Finding.id,
                    )
                    .join(
                        ProofAttempt,
                        ProofAttempt.hypothesis_id == SecurityHypothesis.id,
                    )
                    .where(
                        SecurityHypothesis.task_id == task_id,
                        ProofAttempt.task_id == task_id,
                        ProofAttempt.harm_demonstrated.is_(True),
                    )
                )
            )
        valid = [value for value in severities if value in severity_rank]
        if not valid:
            return None
        return max(valid, key=severity_rank.__getitem__)

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

    @staticmethod
    def _status_for_verdict(verdict: str) -> str:
        if verdict in {
            FindingStatus.SUPPORTED_STATIC.value,
            FindingStatus.REPRODUCED_BLACKBOX.value,
            "needs_dynamic_proof",
        }:
            return HypothesisStatus.ACCEPTED_FOR_PROOF.value
        if verdict in {
            FindingStatus.REFUTED_STATIC.value,
            FindingStatus.NOT_REPRODUCED.value,
        }:
            return HypothesisStatus.REFUTED.value
        return HypothesisStatus.INCONCLUSIVE.value
