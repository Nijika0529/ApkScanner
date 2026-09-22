from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import uuid
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select, update

from ..core.enums import (
    FINDING_STATUS_RANK,
    FindingStatus,
    ScanStatus,
    TaskStatus,
    TaskType,
)
from ..core.finding_policy import (
    build_static_refutation_gate,
    evidence_backed_signal_tier,
    static_refutation_is_evidence_backed,
)
from ..core.models import (
    AdaptiveVerificationCheckpoint,
    DynamicExperimentCapsule,
    EntryPoint,
    Evidence,
    Finding,
    IndexedArtifact,
    InvestigationTask,
    ProofAttempt,
    RuntimeObservation,
    Scan,
    SecurityHypothesis,
)
from ..core.proof_receipts import (
    attributable_harm_attempts,
    attributable_refutation_attempts,
)
from ..core.repository import add_event, now
from ..core.schemas import (
    ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA,
    AdaptiveVerificationResult,
    AdaptiveVerifierAssessment,
)
from ..core.signal_projection import (
    evidence_supports_runtime_observation,
)
from ..core.verdicts import valid_static_support_gate
from ..infrastructure.tools import TimeBudget
from .agent_events import AgentCancelledError, AgentRuntimeEvent
from .agent_prompt import (
    adaptive_verification_prompt,
    adaptive_verifier_developer_instructions,
)
from .attacker_templates import attacker_template_catalog
from .device import AdbDeviceAdapter
from .finding_reports import (
    FindingReport,
    render_finding_description,
)
from .live_proof import LiveProofContext
from .runtime_contracts import task_gateway_environment


class AdaptiveVerificationMixin:
    """Adaptive verification, consolidation, and platform verdict projection."""

    def _run_adaptive_verifier(self, scan_id: str) -> None:
        """Batch the strongest unresolved findings into one terminal Codex thread."""

        # This method is also the post-investigation barrier. Run deterministic consolidation even
        # when the optional Adaptive Verifier is disabled, so concurrent task commits cannot leave
        # exact semantic duplicates in the final report.
        with self.database.session_factory() as session:
            self._consolidate_findings(session, scan_id=scan_id)
            scan = session.get(Scan, scan_id)
            control = (scan.stats or {}).get("agent_control") if scan is not None else None
            agent_enabled = (
                bool(control.get("enabled", True)) if isinstance(control, dict) else True
            )
            session.commit()
        if (
            not self.settings.adaptive_verifier_enabled
            or not self.settings.codex_enabled
            or self.settings.codex_isolation != "docker"
            or not agent_enabled
        ):
            return
        severity_rank = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        minimum_rank = severity_rank[self.settings.adaptive_verifier_min_severity]
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            candidates = [
                finding
                for finding in session.scalars(
                    select(Finding).where(
                        Finding.scan_id == scan_id,
                        Finding.status.in_(
                            [
                                FindingStatus.SUPPORTED_STATIC.value,
                                FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
                                "static_path_supported",
                                "oracle_gap",
                            ]
                        ),
                    )
                )
                if evidence_backed_signal_tier(session, finding)
                in {"static_chain", "runtime_oracle_gap"}
                if severity_rank.get(finding.severity, 0) >= minimum_rank
            ]
            candidates.sort(
                key=lambda item: (
                    -severity_rank.get(item.severity, 0),
                    item.created_at,
                    item.id,
                )
            )
            if not candidates:
                scan.stats = {
                    **dict(scan.stats or {}),
                    "adaptive_verification": {
                        "enabled": True,
                        "candidate_count": 0,
                        "status": "not_needed",
                    },
                }
                session.commit()
                return
            fingerprint_payload = [
                {
                    "id": item.id,
                    "status": item.status,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "evidence_ids": sorted(
                        evidence_id
                        for evidence_id in item.evidence_ids
                        if evidence_id
                        not in {
                            str(history_item.get("response_evidence_id"))
                            for history_item in (
                                (item.metadata_json or {}).get("adaptive_verification_history")
                                or []
                            )
                            if isinstance(history_item, dict)
                            and history_item.get("response_evidence_id")
                        }
                    ),
                }
                for item in candidates
            ]
            fingerprint = hashlib.sha256(
                json.dumps(
                    fingerprint_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            previous = session.scalar(
                select(InvestigationTask)
                .where(
                    InvestigationTask.scan_id == scan_id,
                    InvestigationTask.task_type == TaskType.ADAPTIVE_VERIFICATION.value,
                )
                .order_by(InvestigationTask.created_at.desc())
                .limit(1)
            )
            if (
                previous is not None
                and (previous.preconditions or {}).get("candidate_fingerprint") == fingerprint
                and previous.status
                in {
                    TaskStatus.COMPLETED.value,
                    TaskStatus.NOT_REPRODUCED.value,
                }
            ):
                session.commit()
                return
            candidate_ids = [item.id for item in candidates]
            entry_ids = list(
                dict.fromkeys(entry_id for item in candidates for entry_id in item.entry_point_ids)
            )
            if (
                previous is not None
                and (previous.preconditions or {}).get("candidate_fingerprint") == fingerprint
                and previous.status != TaskStatus.DELETED.value
            ):
                task = previous
                task.status = TaskStatus.RUNNING.value
                task.target_entry_ids = entry_ids
                task.hypotheses = [item.title for item in candidates]
                task.attempts += 1
                task.started_at = now()
                task.completed_at = None
                task.error = None
                task.preconditions = {
                    **dict(task.preconditions or {}),
                    "candidate_finding_ids": candidate_ids,
                    "candidate_fingerprint": fingerprint,
                    "batch_policy": "transport_budgeted_candidate_checkpoint_resume",
                }
            else:
                task = InvestigationTask(
                    scan_id=scan_id,
                    task_type=TaskType.ADAPTIVE_VERIFICATION.value,
                    status=TaskStatus.RUNNING.value,
                    priority=100,
                    target_entry_ids=entry_ids,
                    hypotheses=[item.title for item in candidates],
                    preconditions={
                        "candidate_finding_ids": candidate_ids,
                        "candidate_fingerprint": fingerprint,
                        "batch_policy": "transport_budgeted_candidate_checkpoint_resume",
                    },
                    allowed_side_effects=[
                        "build_and_install_poc",
                        "adb_on_leased_device",
                        "public_network",
                        "ssh_authorized_hosts",
                        "deploy_remote_test_fixture",
                    ],
                    device_profile={
                        "adaptive_verifier": True,
                        "android_api_minimum": self.settings.device_min_api,
                    },
                    attempts=1,
                    started_at=now(),
                )
                session.add(task)
            scan.status = ScanStatus.INVESTIGATING.value
            scan.stats = {
                **dict(scan.stats or {}),
                "adaptive_verification": {
                    "enabled": True,
                    "candidate_count": len(candidate_ids),
                    "candidate_finding_ids": candidate_ids,
                    "status": "running",
                },
            }
            session.flush()
            task_id = task.id
            add_event(
                session,
                scan_id,
                "adaptive_verification.started",
                f"高权限验证 Agent 开始批量检查 {len(candidate_ids)} 个待验证风险",
                {
                    "task_id": task_id,
                    "candidate_count": len(candidate_ids),
                    "candidate_finding_ids": candidate_ids,
                    "thread_policy": "transport_budgeted_candidate_checkpoint_resume",
                },
            )
            session.commit()

        cancel_event = threading.Event()
        with self._task_cancellations_lock:
            self._task_cancellations[task_id] = cancel_event
        try:
            for resume_index in range(self.settings.adaptive_verifier_resume_attempts + 1):
                try:
                    self._run_adaptive_verifier_impl(scan_id, task_id, cancel_event)
                except AgentCancelledError:
                    raise
                except Exception as exc:
                    if (
                        resume_index >= self.settings.adaptive_verifier_resume_attempts
                        or self._shutting_down.is_set()
                        or not self._prepare_adaptive_verifier_resume(
                            scan_id,
                            task_id,
                            reason=f"worker_failure: {exc}",
                        )
                    ):
                        raise
                    continue
                with self.database.session_factory() as session:
                    persisted_task = session.get(InvestigationTask, task_id)
                    missing = (
                        list(
                            (persisted_task.result or {}).get("missing_candidate_assessments") or []
                        )
                        if persisted_task is not None
                        else []
                    )
                    partial = bool(
                        persisted_task is not None
                        and persisted_task.status == TaskStatus.INCONCLUSIVE.value
                        and missing
                    )
                if not partial or resume_index >= self.settings.adaptive_verifier_resume_attempts:
                    break
                if not self._prepare_adaptive_verifier_resume(
                    scan_id,
                    task_id,
                    reason=(
                        "missing_candidate_assessments: "
                        + ",".join(str(value) for value in missing)
                    ),
                ):
                    break
        except AgentCancelledError:
            if self._shutting_down.is_set():
                self._mark_adaptive_verifier_interrupted(scan_id, task_id)
            else:
                self._mark_task_canceled(scan_id, task_id)
        except Exception as exc:
            with self.database.session_factory() as session:
                task = session.get(InvestigationTask, task_id)
                scan = session.get(Scan, scan_id)
                if task is not None:
                    task.status = TaskStatus.FAILED.value
                    task.error = str(exc)
                    task.completed_at = now()
                if scan is not None:
                    scan.stats = {
                        **dict(scan.stats or {}),
                        "adaptive_verification": {
                            **dict((scan.stats or {}).get("adaptive_verification") or {}),
                            "status": "failed",
                            "error": str(exc)[:2000],
                        },
                    }
                add_event(
                    session,
                    scan_id,
                    "adaptive_verification.failed",
                    "高权限验证 Agent 未完成；保留原有静态风险结论",
                    {"task_id": task_id, "error": str(exc)[:2000]},
                )
                session.commit()
        finally:
            self.codex.close_task(scan_id, task_id)
            with self._task_cancellations_lock:
                if self._task_cancellations.get(task_id) is cancel_event:
                    self._task_cancellations.pop(task_id, None)

    def _prepare_adaptive_verifier_resume(
        self,
        scan_id: str,
        task_id: str,
        *,
        reason: str,
    ) -> bool:
        """Start a fresh verifier attempt while retaining candidate checkpoints."""

        if self._shutting_down.is_set():
            return False
        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            scan = session.get(Scan, scan_id)
            if task is None or scan is None:
                return False
            old_attempt = task.attempts
            checkpoint_count = len(
                list(
                    session.scalars(
                        select(AdaptiveVerificationCheckpoint.id).where(
                            AdaptiveVerificationCheckpoint.task_id == task_id
                        )
                    )
                )
            )
            recovery_history = list((task.result or {}).get("adaptive_resume_history") or [])
            recovery_history.append(
                {
                    "from_attempt": old_attempt,
                    "to_attempt": old_attempt + 1,
                    "reason": reason[:2000],
                    "checkpoint_count": checkpoint_count,
                    "created_at": now().isoformat(),
                }
            )
            task.attempts = old_attempt + 1
            task.status = TaskStatus.RUNNING.value
            task.started_at = now()
            task.completed_at = None
            task.error = None
            task.result = {
                **dict(task.result or {}),
                "adaptive_resume_history": recovery_history[-10:],
            }
            scan.stats = {
                **dict(scan.stats or {}),
                "adaptive_verification": {
                    **dict((scan.stats or {}).get("adaptive_verification") or {}),
                    "status": "resuming",
                    "task_id": task_id,
                    "attempt": task.attempts,
                    "restored_checkpoint_count": checkpoint_count,
                    "resume_reason": reason[:2000],
                },
            }
            add_event(
                session,
                scan_id,
                "adaptive_verification.resuming",
                (f"高权限验证将恢复 {checkpoint_count} 个候选断点，仅补跑未完成候选"),
                {
                    "task_id": task_id,
                    "from_attempt": old_attempt,
                    "attempt": task.attempts,
                    "restored_checkpoint_count": checkpoint_count,
                    "reason": reason[:2000],
                },
            )
            session.commit()
        self.codex.close_task_role(
            scan_id,
            task_id,
            old_attempt,
            "verifier",
        )
        return True

    def _mark_adaptive_verifier_interrupted(self, scan_id: str, task_id: str) -> None:
        """Leave a shutdown-interrupted verifier resumable instead of cancelling the scan."""

        with self.database.session_factory() as session:
            task = session.get(InvestigationTask, task_id)
            scan = session.get(Scan, scan_id)
            if task is not None:
                task.status = TaskStatus.INCONCLUSIVE.value
                task.error = "service shutdown interrupted Adaptive Verifier; checkpoints retained"
                task.completed_at = now()
            if scan is not None:
                scan.stats = {
                    **dict(scan.stats or {}),
                    "adaptive_verification": {
                        **dict((scan.stats or {}).get("adaptive_verification") or {}),
                        "status": "interrupted_resumable",
                        "task_id": task_id,
                    },
                }
            add_event(
                session,
                scan_id,
                "adaptive_verification.interrupted",
                "服务停止中断了高权限验证；已保存候选断点并等待恢复",
                {"task_id": task_id, "resumable": True},
            )
            session.commit()

    @staticmethod
    def _finding_semantic_identity(finding: Finding) -> str | None:
        metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
        identity = metadata.get("identity")
        if not isinstance(identity, dict):
            return None
        for key in ("semantic_fingerprint", "finding_id"):
            value = identity.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _ordered_union(*groups: list[str]) -> list[str]:
        return list(
            dict.fromkeys(
                value for group in groups for value in group if isinstance(value, str) and value
            )
        )

    def _consolidate_findings(
        self,
        session,  # noqa: ANN001
        *,
        scan_id: str,
        explicit_duplicates: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Merge cross-task occurrences while retaining each original record for audit.

        Exact ``finding_identity`` matches are deterministic. The terminal Adaptive Verifier may
        additionally relate semantically identical attack chains that have different ingress
        wording. Only links between active findings in the same scan are accepted.
        """

        findings = list(
            session.scalars(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.created_at, Finding.id)
            )
        )

        def finding_metadata(finding: Finding) -> dict[str, Any]:
            return (
                dict(finding.metadata_json)
                if isinstance(finding.metadata_json, dict)
                else {}
            )

        def finding_string_list(value: Any) -> list[str]:
            return (
                [item for item in value if isinstance(item, str) and item]
                if isinstance(value, list)
                else []
            )

        active = [
            finding
            for finding in findings
            if not isinstance(finding_metadata(finding).get("merged_into_finding_id"), str)
        ]
        by_id = {finding.id: finding for finding in active}
        adjacency: dict[str, set[str]] = {finding.id: set() for finding in active}
        harm_attempts_by_finding = {
            finding.id: attributable_harm_attempts(session, finding)
            for finding in active
            if finding.status
            in {
                FindingStatus.REPRODUCED_BLACKBOX.value,
                FindingStatus.ACCEPTED.value,
            }
            or finding_metadata(finding).get("harm_demonstrated") is True
        }
        refuting_attempts_by_finding = {
            finding.id: attributable_refutation_attempts(session, finding)
            for finding in active
            if finding.status == FindingStatus.NOT_REPRODUCED.value
            or bool(finding_metadata(finding).get("refutation_attempt_ids"))
        }
        proof_signature_by_finding: dict[str, set[str]] = defaultdict(set)
        identity_groups: dict[str, list[str]] = defaultdict(list)
        for finding in active:
            identity = self._finding_semantic_identity(finding)
            if identity:
                identity_groups[identity].append(finding.id)
        for finding_ids in identity_groups.values():
            if len(finding_ids) < 2:
                continue
            first = finding_ids[0]
            for duplicate_id in finding_ids[1:]:
                adjacency[first].add(duplicate_id)
                adjacency[duplicate_id].add(first)

        proof_signature_groups: dict[str, list[str]] = defaultdict(list)
        for finding in active:
            for attempt in harm_attempts_by_finding.get(finding.id, []):
                plan = attempt.plan if isinstance(attempt.plan, dict) else {}
                oracle = plan.get("oracle") if isinstance(plan.get("oracle"), dict) else {}
                poc = plan.get("poc") if isinstance(plan.get("poc"), dict) else {}
                signature = json.dumps(
                    {
                        "task_id": attempt.task_id,
                        "entry_point_ids": sorted(
                            set(finding_string_list(finding.entry_point_ids))
                        ),
                        "operation": plan.get("operation"),
                        "binder_transaction_code": plan.get("binder_transaction_code"),
                        "binder_interface_descriptor": plan.get("binder_interface_descriptor"),
                        "binder_reply_type": plan.get("binder_reply_type"),
                        "binder_script": plan.get("binder_script"),
                        "poc_project_path": poc.get("project_path"),
                        "poc_attack_class": poc.get("attack_class"),
                        "oracle": {
                            key: oracle.get(key)
                            for key in (
                                "kind",
                                "impact",
                                "impact_contract_id",
                                "expected_text",
                                "match_mode",
                                "reply_index",
                                "target_path",
                            )
                        },
                    },
                    sort_keys=True,
                    ensure_ascii=False,
                )
                proof_signature_by_finding[finding.id].add(signature)
                proof_signature_groups[signature].append(finding.id)
        for finding_ids in proof_signature_groups.values():
            finding_ids = list(dict.fromkeys(finding_ids))
            if len(finding_ids) < 2:
                continue
            first = finding_ids[0]
            for duplicate_id in finding_ids[1:]:
                adjacency[first].add(duplicate_id)
                adjacency[duplicate_id].add(first)

        valid_explicit: dict[str, str] = {}
        for duplicate_id, canonical_id in (explicit_duplicates or {}).items():
            if (
                duplicate_id == canonical_id
                or duplicate_id not in by_id
                or canonical_id not in by_id
            ):
                continue
            valid_explicit[duplicate_id] = canonical_id
            adjacency[duplicate_id].add(canonical_id)
            adjacency[canonical_id].add(duplicate_id)

        status_rank = FINDING_STATUS_RANK
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        confidence_rank = {"low": 0, "medium": 1, "high": 2}
        valid_scan_evidence_ids = set(
            session.scalars(
                select(Evidence.id).where(Evidence.scan_id == scan_id)
            )
        )

        def effective_status_rank(item: Finding) -> int:
            if (
                item.status
                in {
                    FindingStatus.FALSE_POSITIVE.value,
                    FindingStatus.ACCEPTED.value,
                }
                and isinstance(item.review_note, str)
                and item.review_note.strip()
            ):
                return max(FINDING_STATUS_RANK.values()) + 1
            if (
                item.status
                in {
                    FindingStatus.REPRODUCED_BLACKBOX.value,
                    FindingStatus.ACCEPTED.value,
                }
                and not harm_attempts_by_finding.get(item.id)
            ):
                tier = evidence_backed_signal_tier(session, item)
                return {
                    "raw_candidate": FINDING_STATUS_RANK[FindingStatus.CANDIDATE.value],
                    "static_chain": FINDING_STATUS_RANK[
                        FindingStatus.SUPPORTED_STATIC.value
                    ],
                    "runtime_oracle_gap": FINDING_STATUS_RANK[
                        FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                    ],
                }[tier]
            if item.status == FindingStatus.NOT_REPRODUCED.value:
                return (
                    FINDING_STATUS_RANK[FindingStatus.FALSE_POSITIVE.value]
                    if refuting_attempts_by_finding.get(item.id)
                    else FINDING_STATUS_RANK[FindingStatus.CANDIDATE.value]
                )
            if item.status == FindingStatus.REFUTED_STATIC.value:
                return (
                    FINDING_STATUS_RANK[FindingStatus.REFUTED_STATIC.value]
                    if static_refutation_is_evidence_backed(session, item)
                    else FINDING_STATUS_RANK[FindingStatus.CANDIDATE.value]
                )
            if item.status in {
                FindingStatus.SUPPORTED_STATIC.value,
                FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
                "static_path_supported",
                "oracle_gap",
            } and evidence_backed_signal_tier(session, item) == "raw_candidate":
                return FINDING_STATUS_RANK[FindingStatus.CANDIDATE.value]
            return status_rank.get(item.status, -1)
        merged_map: dict[str, str] = {}
        visited: set[str] = set()

        hypothesis_ids = {
            hypothesis_id
            for finding in active
            if isinstance(hypothesis_id := finding_metadata(finding).get("hypothesis_id"), str)
        }
        hypothesis_claim_length = {
            hypothesis.id: len(" ".join(hypothesis.claim.split()))
            for hypothesis in (
                session.scalars(
                    select(SecurityHypothesis).where(SecurityHypothesis.id.in_(hypothesis_ids))
                )
                if hypothesis_ids
                else []
            )
        }

        def merge_basis(duplicate: Finding, canonical: Finding) -> str:
            if duplicate.id in valid_explicit:
                return "adaptive_verifier_semantic_duplicate"
            if self._finding_semantic_identity(duplicate) == self._finding_semantic_identity(
                canonical
            ):
                return "exact_finding_identity"
            if proof_signature_by_finding[duplicate.id] & proof_signature_by_finding[canonical.id]:
                return "shared_platform_proof_oracle"
            return "transitive_semantic_duplicate"

        for start_id in adjacency:
            if start_id in visited or not adjacency[start_id]:
                continue
            stack = [start_id]
            component_ids: list[str] = []
            while stack:
                current_id = stack.pop()
                if current_id in visited:
                    continue
                visited.add(current_id)
                component_ids.append(current_id)
                stack.extend(adjacency[current_id] - visited)
            if len(component_ids) < 2:
                continue

            component = [by_id[finding_id] for finding_id in component_ids]
            component.sort(key=lambda item: (item.created_at, item.id))
            # Honor the verifier's direction when it has one unambiguous terminal target.
            terminal_targets: set[str] = set()
            for duplicate_id in component_ids:
                if duplicate_id not in valid_explicit:
                    continue
                cursor = duplicate_id
                chain_seen: set[str] = set()
                while cursor in valid_explicit and cursor not in chain_seen:
                    chain_seen.add(cursor)
                    cursor = valid_explicit[cursor]
                if cursor in by_id and cursor not in chain_seen:
                    terminal_targets.add(cursor)
            representative = max(
                component,
                key=lambda item: (
                    effective_status_rank(item),
                    int(
                        item.status
                        in {
                            FindingStatus.FALSE_POSITIVE.value,
                            FindingStatus.ACCEPTED.value,
                        }
                        and bool(item.review_note)
                    ),
                    severity_rank.get(item.severity, -1),
                    confidence_rank.get(item.confidence, -1),
                    hypothesis_claim_length.get(
                        str(finding_metadata(item).get("hypothesis_id")), 0
                    ),
                    -component.index(item),
                ),
            )
            canonical = (
                by_id[next(iter(terminal_targets))]
                if len(terminal_targets) == 1
                else representative
            )
            duplicates = [item for item in component if item.id != canonical.id]

            canonical.title = representative.title
            canonical.description = representative.description
            canonical.remediation = representative.remediation
            canonical.masvs = representative.masvs
            canonical.cwe = representative.cwe
            canonical.rule_id = representative.rule_id
            canonical.source = representative.source
            canonical.status = representative.status
            canonical.review_note = representative.review_note
            canonical.severity = max(
                (item.severity for item in component),
                key=lambda value: severity_rank.get(value, -1),
            )
            canonical.confidence = max(
                (item.confidence for item in component),
                key=lambda value: confidence_rank.get(value, -1),
            )
            canonical.entry_point_ids = self._ordered_union(
                *(finding_string_list(item.entry_point_ids) for item in component)
            )
            canonical.evidence_ids = [
                evidence_id
                for evidence_id in self._ordered_union(
                    *(
                        list(item.evidence_ids)
                        if isinstance(item.evidence_ids, list)
                        else []
                        for item in component
                    )
                )
                if evidence_id in valid_scan_evidence_ids
            ]
            location_keys: set[str] = set()
            merged_locations: list[dict[str, Any]] = []
            for item in component:
                for location in item.locations or []:
                    if not isinstance(location, dict):
                        continue
                    key = json.dumps(location, sort_keys=True, ensure_ascii=False)
                    if key in location_keys:
                        continue
                    location_keys.add(key)
                    merged_locations.append(location)
            canonical.locations = merged_locations

            all_metadata = [finding_metadata(item) for item in component]

            def metadata_list(metadata: dict[str, Any], key: str) -> list[Any]:
                value = metadata.get(key)
                return list(value) if isinstance(value, list) else []

            histories = [
                history_item
                for metadata in all_metadata
                for history_item in metadata_list(
                    metadata, "adaptive_verification_history"
                )
                if isinstance(history_item, dict)
            ]
            component_harm_attempts = [
                attempt
                for item in component
                for attempt in harm_attempts_by_finding.get(item.id, [])
            ]
            # An OEM app-jump guard that had to be allowed makes the runtime
            # result user-assisted rather than silent. Carry that external
            # control (and its precondition) into the Finding instead of
            # presenting the chain as a no-interaction exploit.
            component_external_controls: list[dict[str, Any]] = []
            seen_external_controls: set[tuple[Any, Any]] = set()
            for attempt in component_harm_attempts:
                attempt_oracle = attempt.oracle if isinstance(attempt.oracle, dict) else {}
                for control in attempt_oracle.get("external_controls") or []:
                    if not isinstance(control, dict):
                        continue
                    key = (control.get("type"), control.get("vendor_package"))
                    if key in seen_external_controls:
                        continue
                    seen_external_controls.add(key)
                    component_external_controls.append(control)
            component_refuting_attempts = [
                attempt
                for item in component
                for attempt in refuting_attempts_by_finding.get(item.id, [])
            ]
            proof_attempt_ids = self._ordered_union(
                [attempt.id for attempt in component_harm_attempts]
            )
            refutation_attempt_ids = self._ordered_union(
                [attempt.id for attempt in component_refuting_attempts]
            )
            coverage_gaps = self._ordered_union(
                *[metadata_list(metadata, "coverage_gaps") for metadata in all_metadata]
            )
            identities = [
                identity
                for metadata in all_metadata
                if isinstance((identity := metadata.get("identity")), dict)
            ]
            occurrence_history = list(
                finding_metadata(canonical).get("merged_occurrences") or []
            )
            occurrence_history.extend(
                {
                    "finding_id": duplicate.id,
                    "dedupe_key": duplicate.dedupe_key,
                    "title": duplicate.title,
                    "status": duplicate.status,
                    "task_id": finding_metadata(duplicate).get("task_id"),
                    "hypothesis_id": finding_metadata(duplicate).get("hypothesis_id"),
                    "entry_point_ids": finding_string_list(duplicate.entry_point_ids),
                    "evidence_ids": finding_string_list(duplicate.evidence_ids),
                    "merge_basis": merge_basis(duplicate, canonical),
                }
                for duplicate in duplicates
            )
            canonical_metadata = finding_metadata(canonical)
            representative_metadata = finding_metadata(representative)
            representative_tier = evidence_backed_signal_tier(session, representative)
            receipt_keys = (
                "signal_tier",
                "platform_static_support_gate",
                "platform_static_refutation_gate",
                "chain_receipt",
                "security_impact",
                "missing_control",
                "oracle_gap",
                "proof_gap_code",
                "proof_backlog",
                "adaptive_verification",
                "verification_mode",
                "release_gate_eligible",
                "dynamic_verdict_eligible",
                "android16_verdict_eligible",
                "verdict_scope",
            )
            for key in receipt_keys:
                canonical_metadata.pop(key, None)
                if key in representative_metadata:
                    canonical_metadata[key] = deepcopy(representative_metadata[key])
            canonical_metadata.update(
                {
                    "harm_demonstrated": bool(component_harm_attempts),
                    "requires_user_interaction": bool(component_external_controls),
                    "external_controls": component_external_controls,
                    "merged_finding_ids": self._ordered_union(
                        list(canonical_metadata.get("merged_finding_ids") or []),
                        [item.id for item in duplicates],
                    ),
                    "merged_occurrences": occurrence_history[-50:],
                    "equivalent_identities": identities,
                    "coverage_gaps": coverage_gaps,
                    "proof_attempt_ids": proof_attempt_ids,
                    "refutation_attempt_ids": refutation_attempt_ids,
                }
            )
            if representative_tier == "runtime_oracle_gap":
                canonical_metadata["signal_tier"] = "runtime_oracle_gap"
                canonical_metadata["proof_gap_code"] = "missing_platform_harm_oracle"
                canonical_metadata["oracle_gap"] = {
                    **dict(canonical_metadata.get("oracle_gap") or {}),
                    "schema_version": "1.0",
                    "status": "open",
                    "runtime_observed": True,
                }
                canonical_metadata.pop("platform_static_support_gate", None)
                canonical_metadata.pop("chain_receipt", None)
            elif representative_tier == "static_chain" and valid_static_support_gate(
                representative_metadata
            ):
                canonical_metadata["signal_tier"] = "static_chain"
                canonical_metadata.pop("oracle_gap", None)
                canonical_metadata.pop("proof_gap_code", None)
            else:
                canonical_metadata.pop("signal_tier", None)
                canonical_metadata.pop("oracle_gap", None)
                canonical_metadata.pop("proof_gap_code", None)
                if representative.status != FindingStatus.SUPPORTED_STATIC.value:
                    canonical_metadata.pop("platform_static_support_gate", None)
                    canonical_metadata.pop("chain_receipt", None)
            if canonical.status != FindingStatus.REFUTED_STATIC.value:
                canonical_metadata.pop("platform_static_refutation_gate", None)
            if histories:
                canonical_metadata["adaptive_verification_history"] = histories[-10:]
            representative_adaptive = representative_metadata.get(
                "adaptive_verification"
            )
            if isinstance(representative_adaptive, dict):
                canonical_metadata["adaptive_verification"] = deepcopy(
                    representative_adaptive
                )
            else:
                canonical_metadata.pop("adaptive_verification", None)
            if canonical_metadata["harm_demonstrated"]:
                canonical_metadata["proof_backlog"] = {
                    **dict(canonical_metadata.get("proof_backlog") or {}),
                    "status": "verified",
                }
            elif isinstance(canonical_metadata.get("proof_backlog"), dict):
                canonical_metadata["proof_backlog"] = {
                    **dict(canonical_metadata["proof_backlog"]),
                    "status": (
                        "oracle_gap"
                        if representative_tier == "runtime_oracle_gap"
                        else "proof_required"
                    ),
                }
            canonical.metadata_json = canonical_metadata
            if (
                canonical.status == FindingStatus.REFUTED_STATIC.value
                and not static_refutation_is_evidence_backed(session, canonical)
            ):
                reported_gate = canonical_metadata.pop(
                    "platform_static_refutation_gate", None
                )
                canonical.status = FindingStatus.INCONCLUSIVE.value
                canonical_metadata["static_refutation_reconciliation"] = {
                    "previous_status": FindingStatus.REFUTED_STATIC.value,
                    "reason": (
                        "merged static refutation lacked a same-scan usable evidence receipt "
                        "with concrete counterevidence and blocked edge"
                    ),
                    "reported_gate": reported_gate,
                }
                canonical.metadata_json = canonical_metadata

            for duplicate in duplicates:
                original_metadata = finding_metadata(duplicate)
                duplicate.status = FindingStatus.INCONCLUSIVE.value
                duplicate.metadata_json = {
                    **original_metadata,
                    "previous_review_note": duplicate.review_note,
                    "harm_demonstrated": False,
                    "merged_duplicate": True,
                    "merged_into_finding_id": canonical.id,
                    "merge_basis": merge_basis(duplicate, canonical),
                    "proof_backlog": {
                        **dict(original_metadata.get("proof_backlog") or {}),
                        "status": "merged",
                    },
                }
                duplicate.review_note = (
                    f"该记录已跨任务归并到 finding {canonical.id}；原始证据与事件仍保留供审计。"
                )
                session.execute(
                    update(SecurityHypothesis)
                    .where(SecurityHypothesis.final_finding_id == duplicate.id)
                    .values(final_finding_id=canonical.id)
                )
                for model in (
                    RuntimeObservation,
                    DynamicExperimentCapsule,
                    IndexedArtifact,
                ):
                    session.execute(
                        update(model)
                        .where(model.finding_id == duplicate.id)
                        .values(finding_id=canonical.id)
                    )
                merged_map[duplicate.id] = canonical.id

        return merged_map

    @staticmethod
    def _adaptive_prompt_candidate(
        candidate: dict[str, Any],
        *,
        context_file: str,
    ) -> dict[str, Any]:
        """Keep routing facts inline and leave unbounded details in the workspace."""

        hypotheses = candidate.get("security_hypotheses")
        if not isinstance(hypotheses, list):
            hypotheses = []
        entry_points = candidate.get("entry_points")
        if not isinstance(entry_points, list):
            entry_points = []
        evidence_ids = candidate.get("evidence_ids")
        if not isinstance(evidence_ids, list):
            evidence_ids = []
        coverage_gaps = candidate.get("coverage_gaps")
        if not isinstance(coverage_gaps, list):
            coverage_gaps = []
        proof_backlog = candidate.get("proof_backlog")
        return {
            "finding_id": candidate.get("finding_id"),
            "title": str(candidate.get("title") or "")[:2000],
            "description": str(candidate.get("description") or "")[:8000],
            "severity": candidate.get("severity"),
            "confidence": candidate.get("confidence"),
            "status": candidate.get("status"),
            "entry_point_ids": candidate.get("entry_point_ids") or [],
            "entry_points": [
                {
                    key: entry.get(key)
                    for key in ("id", "kind", "name", "owner_component", "exported", "permission")
                    if entry.get(key) is not None
                }
                for entry in entry_points
                if isinstance(entry, dict)
            ],
            "evidence_ids": evidence_ids[:64],
            "evidence_id_count": len(evidence_ids),
            "source_task_ids": candidate.get("source_task_ids") or [],
            "proof_backlog_status": (
                proof_backlog.get("status") if isinstance(proof_backlog, dict) else None
            ),
            "coverage_gaps": [str(value)[:1200] for value in coverage_gaps[:12]],
            "security_hypotheses": [
                {
                    "id": hypothesis.get("id"),
                    "category": hypothesis.get("category"),
                    "claim": str(hypothesis.get("claim") or "")[:3000],
                    "impact": str(hypothesis.get("impact") or "")[:2000],
                    "status": hypothesis.get("status"),
                }
                for hypothesis in hypotheses[:12]
                if isinstance(hypothesis, dict)
            ],
            "full_context_file": context_file,
        }

    @staticmethod
    def _adaptive_batch_evidence(
        evidence: list[dict[str, Any]],
        candidates: list[dict[str, Any]],
        *,
        verifier_task_id: str,
    ) -> list[dict[str, Any]]:
        explicit_ids = {
            str(evidence_id)
            for candidate in candidates
            for evidence_id in (candidate.get("evidence_ids") or [])
            if isinstance(evidence_id, str)
        }
        source_task_ids = {
            str(source_task_id)
            for candidate in candidates
            for source_task_id in (candidate.get("source_task_ids") or [])
            if isinstance(source_task_id, str)
        }
        for candidate in candidates:
            for hypothesis in candidate.get("security_hypotheses") or []:
                if not isinstance(hypothesis, dict):
                    continue
                explicit_ids.update(
                    str(evidence_id)
                    for field_name in ("support_evidence_ids", "refute_evidence_ids")
                    for evidence_id in (hypothesis.get(field_name) or [])
                    if isinstance(evidence_id, str)
                )
        return [
            item
            for item in evidence
            if item.get("task_id") is None
            or item.get("task_id") == verifier_task_id
            or item.get("task_id") in source_task_ids
            or item.get("id") in explicit_ids
        ]

    def _build_adaptive_verifier_batches(
        self,
        *,
        scan: Scan,
        task_id: str,
        candidates: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        base_platform_context: dict[str, Any],
        entries_by_id: dict[str, EntryPoint],
    ) -> list[dict[str, Any]]:
        if not candidates:
            return []
        prompt_limit = self.settings.adaptive_verifier_prompt_max_chars
        count_hint = len(candidates)
        code_context_cache: dict[tuple[str, ...], dict[str, Any]] = {}

        def build(
            values: list[dict[str, Any]],
            *,
            index: int,
            count: int,
        ) -> dict[str, Any]:
            context_file = f"adaptive_verification/batch-{index:03d}.json"
            entry_ids = list(
                dict.fromkeys(
                    str(entry_id)
                    for candidate in values
                    for entry_id in (candidate.get("entry_point_ids") or [])
                    if isinstance(entry_id, str)
                )
            )
            batch_entries = [
                entries_by_id[entry_id] for entry_id in entry_ids if entry_id in entries_by_id
            ]
            code_context_key = tuple(entry_ids)
            target_code_context = code_context_cache.get(code_context_key)
            if target_code_context is None:
                target_code_context = self._target_code_context(scan.id, batch_entries)
                code_context_cache[code_context_key] = target_code_context
            batch_evidence = self._adaptive_batch_evidence(
                evidence,
                values,
                verifier_task_id=task_id,
            )
            context = {
                **deepcopy(base_platform_context),
                "candidate_count": len(values),
                "candidate_finding_ids": [str(value["finding_id"]) for value in values],
                "total_candidate_count": len(candidates),
                "target_code_context": deepcopy(target_code_context),
                "batch": {
                    "index": index,
                    "count": count,
                    "candidate_context_file": context_file,
                    "all_candidate_catalog_file": ("adaptive_verification/candidate-catalog.json"),
                    "prompt_transport_limit_characters": prompt_limit,
                },
            }
            prompt_candidates = [
                self._adaptive_prompt_candidate(value, context_file=context_file)
                for value in values
            ]
            prompt = adaptive_verification_prompt(
                scan,
                prompt_candidates,
                batch_evidence,
                context,
            )
            return {
                "index": index,
                "count": count,
                "candidate_ids": [str(value["finding_id"]) for value in values],
                "candidates": values,
                "evidence": batch_evidence,
                "platform_context": context,
                "context_file": context_file,
                "prompt": prompt,
                "prompt_characters": len(prompt),
            }

        groups: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        for candidate in candidates:
            trial = [*current, candidate]
            trial_batch = build(
                trial,
                index=len(groups) + 1,
                count=count_hint,
            )
            if current and trial_batch["prompt_characters"] > prompt_limit:
                groups.append(current)
                current = [candidate]
            else:
                current = trial
        if current:
            groups.append(current)

        batches = [
            build(values, index=index, count=len(groups))
            for index, values in enumerate(groups, start=1)
        ]
        oversized = [batch for batch in batches if batch["prompt_characters"] > prompt_limit]
        if oversized:
            batch = oversized[0]
            raise ValueError(
                "one Adaptive Verifier candidate exceeds the transport-safe prompt budget: "
                f"batch={batch['index']} characters={batch['prompt_characters']} "
                f"limit={prompt_limit}"
            )
        return batches

    def _run_adaptive_verifier_impl(
        self,
        scan_id: str,
        task_id: str,
        cancel_event: threading.Event,
    ) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            task = session.get(InvestigationTask, task_id)
            if scan is None or task is None:
                raise LookupError("Adaptive Verifier scan task disappeared")
            candidate_ids = list((task.preconditions or {}).get("candidate_finding_ids") or [])
            findings = list(
                session.scalars(
                    select(Finding).where(
                        Finding.scan_id == scan_id,
                        Finding.id.in_(candidate_ids),
                    )
                )
            )
            findings_by_id = {item.id: item for item in findings}
            findings = [findings_by_id[value] for value in candidate_ids if value in findings_by_id]
            if not findings:
                raise ValueError("Adaptive Verifier has no persisted candidate findings")
            entry_ids = list(
                dict.fromkeys(
                    entry_id for finding in findings for entry_id in finding.entry_point_ids
                )
            )
            entries_by_id = {
                item.id: item
                for item in session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan_id))
            }
            entries = [entries_by_id[value] for value in entry_ids if value in entries_by_id]
            source_task_ids_by_finding: dict[str, list[str]] = {}
            for finding in findings:
                metadata = dict(finding.metadata_json or {})
                occurrence_task_ids = [
                    str(occurrence["task_id"])
                    for occurrence in metadata.get("merged_occurrences", [])
                    if isinstance(occurrence, dict) and isinstance(occurrence.get("task_id"), str)
                ]
                source_task_ids_by_finding[finding.id] = self._ordered_union(
                    [metadata["task_id"]] if isinstance(metadata.get("task_id"), str) else [],
                    occurrence_task_ids,
                )
            source_task_ids = {
                source_task_id
                for values in source_task_ids_by_finding.values()
                for source_task_id in values
            }
            hypotheses_by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
            if source_task_ids:
                for hypothesis in session.scalars(
                    select(SecurityHypothesis).where(
                        SecurityHypothesis.task_id.in_(source_task_ids)
                    )
                ):
                    hypotheses_by_task[hypothesis.task_id].append(
                        {
                            "id": hypothesis.id,
                            "category": hypothesis.category,
                            "claim": hypothesis.claim,
                            "impact": hypothesis.impact,
                            "status": hypothesis.status,
                            "proof_obligations": hypothesis.proof_obligations,
                            "support_evidence_ids": hypothesis.support_evidence_ids,
                            "refute_evidence_ids": hypothesis.refute_evidence_ids,
                        }
                    )
            all_evidence = list(
                session.scalars(select(Evidence).where(Evidence.scan_id == scan_id))
            )
            prior_adaptive_evidence = [item for item in all_evidence if item.task_id == task_id]
            checkpoint_records = list(
                session.scalars(
                    select(AdaptiveVerificationCheckpoint).where(
                        AdaptiveVerificationCheckpoint.task_id == task_id,
                        AdaptiveVerificationCheckpoint.finding_id.in_(candidate_ids),
                    )
                )
            )
            checkpoint_assessments = [
                AdaptiveVerifierAssessment.model_validate(item.assessment_json)
                for item in checkpoint_records
            ]
            checkpoint_finding_ids = {item.finding_id for item in checkpoint_records}
            checkpoint_evidence_ids_by_finding = {
                item.finding_id: item.response_evidence_id for item in checkpoint_records
            }
            checkpoint_receipts = [
                {
                    "index": item.batch_index,
                    "candidate_finding_ids": [item.finding_id],
                    "status": "restored_checkpoint",
                    "audit_id": item.audit_id,
                    "thread_id": item.thread_id,
                    "turn_id": item.turn_id,
                    "response_evidence_id": item.response_evidence_id,
                    "assessment_count": 1,
                    **dict(item.environment_json or {}),
                }
                for item in checkpoint_records
            ]
            explicit_evidence_ids = {
                evidence_id for finding in findings for evidence_id in finding.evidence_ids
            }
            selected_evidence = [
                item
                for item in all_evidence
                if item.task_id is None
                or item.task_id in source_task_ids
                or item.task_id == task_id
                or item.id in explicit_evidence_ids
            ]
            evidence_summaries = [
                {
                    **self._evidence_summary(item),
                    "task_id": item.task_id,
                }
                for item in selected_evidence
            ]
            candidate_payload = [
                {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "entry_point_ids": finding.entry_point_ids,
                    "locations": finding.locations,
                    "evidence_ids": finding.evidence_ids,
                    "source_task_id": (finding.metadata_json or {}).get("task_id"),
                    "source_task_ids": source_task_ids_by_finding.get(finding.id, []),
                    "proof_backlog": (finding.metadata_json or {}).get("proof_backlog"),
                    "coverage_gaps": (finding.metadata_json or {}).get("coverage_gaps", []),
                    "security_hypotheses": [
                        hypothesis
                        for source_task_id in source_task_ids_by_finding.get(finding.id, [])
                        for hypothesis in hypotheses_by_task.get(source_task_id, [])
                    ],
                    "entry_points": [
                        {
                            "id": entry_id,
                            "kind": entries_by_id[entry_id].kind,
                            "name": entries_by_id[entry_id].name,
                            "owner_component": entries_by_id[entry_id].owner_component,
                            "exported": entries_by_id[entry_id].exported,
                            "permission": entries_by_id[entry_id].permission,
                            "deep_links": entries_by_id[entry_id].deep_links,
                            "code_anchors": entries_by_id[entry_id].code_anchors,
                            "metadata": entries_by_id[entry_id].metadata_json,
                        }
                        for entry_id in finding.entry_point_ids
                        if entry_id in entries_by_id
                    ],
                }
                for finding in findings
                if finding.id not in checkpoint_finding_ids
            ]

        capability = self.codex.capability(deep=True)
        if not capability.get("available"):
            raise RuntimeError(str(capability.get("detail") or "Codex is unavailable"))
        budget = TimeBudget.from_seconds(self.settings.adaptive_verifier_timeout_seconds)
        device_session = None
        task_device: AdbDeviceAdapter | None = None
        if self.device_pool.capacity > 0:
            device_session = self._task_device_session(
                scan_id,
                task_id,
                priority=100,
                cancel_event=cancel_event,
            )
            lease_metadata = device_session.__enter__()
            task_device = lease_metadata["device"]
            budget = budget.extend(lease_metadata["wait_seconds"])
        try:
            device_context = (
                task_device.capability(non_blocking=False)
                if task_device is not None
                else self.device_pool.capability(non_blocking=True)
            )
            if task_device is not None:
                health_commands = []
                for kind, args in (
                    ("adaptive.device.health", ["get-state"]),
                    (
                        "adaptive.device.package_status",
                        ["shell", "pm", "path", scan.package_name or ""],
                    ),
                ):
                    result = task_device.execute_gateway(
                        args,
                        timeout=min(45, max(1, budget.remaining(45))),
                    )
                    health_commands.append((kind, result, {"adaptive_verifier": True}))
                self._record_commands(
                    scan_id,
                    task_id,
                    health_commands,
                    evidence_summaries,
                )
            base_platform_context = {
                "phase": "adaptive_verification",
                "output_language": "zh-CN",
                "device": device_context,
                "adb_gateway": {
                    "available": task_device is not None,
                    "mode": "adaptive_task_scoped_fixed_serial",
                    "command": "adb <arguments>",
                    "policy": "adaptive",
                },
                "ssh": {
                    "available": bool(
                        self.settings.adaptive_verifier_copy_host_ssh
                        and self.settings.adaptive_verifier_ssh_source is not None
                        and self.settings.adaptive_verifier_ssh_source.is_dir()
                    ),
                    "path": "~/.ssh",
                    "mode": "host_copy_in_private_verifier_home",
                    "client": "OpenSSH direct ssh/scp",
                },
                "workspace": {
                    "writable_root": ".",
                    "output_root": "output",
                    "poc_root": "poc",
                    "complete_decompiler_roots": [
                        "/scan-input/jadx",
                        "/scan-input/apktool",
                        "/scan-input/archive",
                        "/scan-input/artifacts",
                        "/scan-input/native",
                    ],
                    "artifact_graph": "/scan-input/artifact_graph.json",
                    "target_apk": "/scan-input/target.apk",
                },
                "proof_policy": {
                    "mode": "model_semantic_judgment",
                    "fixed_oracle_required": False,
                    "runtime_evidence_required_for_reproduced_blackbox": True,
                },
                "attacker_templates": {
                    "catalog_path": "attacker-templates/catalog.json",
                    "templates": attacker_template_catalog(),
                },
                "validation_fixtures": self._validation_fixture_context(scan_id, task_id),
                "recovery": {
                    "is_retry": task.attempts > 1 and bool(prior_adaptive_evidence),
                    "attempt": task.attempts,
                    "previous_attempt_evidence_count": len(prior_adaptive_evidence),
                    "restored_candidate_checkpoints": sorted(checkpoint_finding_ids),
                    "instruction": (
                        "Per-candidate checkpoints were restored. Do not repeat those "
                        "completed candidates; finalize only the candidates in this batch."
                        if task.attempts > 1 and prior_adaptive_evidence
                        else "No previous Adaptive Verifier evidence is available."
                    ),
                },
            }
            batches = self._build_adaptive_verifier_batches(
                scan=scan,
                task_id=task_id,
                candidates=candidate_payload,
                evidence=evidence_summaries,
                base_platform_context=base_platform_context,
                entries_by_id=entries_by_id,
            )
            platform_context = {
                **base_platform_context,
                "candidate_count": len(candidate_payload),
                "candidate_finding_ids": candidate_ids,
                "batching": {
                    "policy": "transport_character_budget",
                    "batch_count": len(batches),
                    "prompt_max_characters": (self.settings.adaptive_verifier_prompt_max_chars),
                    "batches": [
                        {
                            "index": batch["index"],
                            "candidate_finding_ids": batch["candidate_ids"],
                            "prompt_characters": batch["prompt_characters"],
                            "candidate_context_file": batch["context_file"],
                        }
                        for batch in batches
                    ],
                },
            }
            source_workspace = self._materialize_agent_evidence(
                scan_id,
                task_id,
                task.attempts,
                evidence_summaries,
                platform_context=platform_context,
            )
            batch_context_root = source_workspace / "adaptive_verification"
            batch_context_root.mkdir(parents=True, exist_ok=True)
            (batch_context_root / "candidate-catalog.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "candidate_count": len(candidate_payload),
                        "candidates": [
                            {
                                "finding_id": candidate["finding_id"],
                                "title": candidate["title"],
                                "severity": candidate["severity"],
                                "entry_point_ids": candidate["entry_point_ids"],
                            }
                            for candidate in candidate_payload
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            for batch in batches:
                (source_workspace / batch["context_file"]).write_text(
                    json.dumps(
                        {
                            "schema_version": "1.0",
                            "batch": {
                                "index": batch["index"],
                                "count": batch["count"],
                                "candidate_finding_ids": batch["candidate_ids"],
                            },
                            "candidates": batch["candidates"],
                            "evidence": batch["evidence"],
                        },
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            runtime_workspace = self.codex.prepare_session_workspace(
                scan=scan,
                task=task,
                workspace=source_workspace,
                phase="adaptive_verification",
            )
            gateway_token: str | None = None
            gateway_environment: dict[str, str] | None = None
            if task_device is not None:
                endpoint = self.ensure_live_proof_endpoint()
                port = urlsplit(endpoint).port
                if port is None:
                    raise RuntimeError("internal Adaptive Verifier gateway has no TCP port")
                gateway_token = secrets.token_urlsafe(48)
                source_hypotheses = [
                    hypothesis for values in hypotheses_by_task.values() for hypothesis in values
                ]
                self.register_live_proof_context(
                    LiveProofContext(
                        token=gateway_token,
                        scan_id=scan_id,
                        task_id=task_id,
                        package_name=scan.package_name or "",
                        workspace=runtime_workspace,
                        entries=entries,
                        default_entry_id=entries[0].id if entries else "",
                        hypotheses=source_hypotheses,
                        budget=budget,
                        evidence_summaries=evidence_summaries,
                        cancel_event=cancel_event,
                        round_index=0,
                        device=task_device,
                        adb_policy="adaptive",
                        container_workspace=self.codex.workspaces.prepare_session(
                            scan_id=scan.id,
                            task_id=task.id,
                            attempt=task.attempts,
                            role="verifier",
                            source_workspace=source_workspace,
                            context={"phase": "adaptive_verification"},
                        ).container_workspace,
                    )
                )
                docker_base = f"http://apkscanner-host:{port}"
                gateway_environment = task_gateway_environment(
                    task_id=task_id,
                    base_url=docker_base,
                    token=gateway_token,
                    adb_policy="adaptive",
                    proof_replay=False,
                )
            successful_results: list[Any] = []
            batch_receipts: list[dict[str, Any]] = list(checkpoint_receipts)
            response_evidence_ids_by_finding: dict[str, str] = dict(
                checkpoint_evidence_ids_by_finding
            )

            def close_batch_thread_for_next_turn() -> None:
                self.codex.close_task_role(
                    scan_id,
                    task_id,
                    task.attempts,
                    "verifier",
                )
                (runtime_workspace.parent / "thread.json").unlink(missing_ok=True)

            try:
                for batch in batches:
                    self._raise_if_cancelled(cancel_event)
                    if budget.expired:
                        batch_receipts.append(
                            {
                                "index": batch["index"],
                                "candidate_finding_ids": batch["candidate_ids"],
                                "prompt_characters": batch["prompt_characters"],
                                "status": "timed_out_before_dispatch",
                            }
                        )
                        break
                    audit_id = str(uuid.uuid4())
                    with self.database.session_factory() as session:
                        request_evidence = self.evidence.json(
                            session,
                            scan_id=scan_id,
                            task_id=task_id,
                            kind="agent.request",
                            value={
                                "schema_version": "1.0",
                                "audit_id": audit_id,
                                "phase": "adaptive_verification",
                                "batch": {
                                    "index": batch["index"],
                                    "count": batch["count"],
                                    "prompt_characters": batch["prompt_characters"],
                                    "prompt_limit_characters": (
                                        self.settings.adaptive_verifier_prompt_max_chars
                                    ),
                                },
                                "developer_instructions": (
                                    adaptive_verifier_developer_instructions(
                                        ssh_available=base_platform_context["ssh"]["available"],
                                        public_port_range=(
                                            self.settings.ssh_public_port_range
                                        ),
                                    )
                                ),
                                "prompt": batch["prompt"],
                                "output_schema": ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA,
                                "candidate_finding_ids": batch["candidate_ids"],
                            },
                            summary=(
                                "Codex scan-level Adaptive Verifier request "
                                f"batch {batch['index']}/{batch['count']}"
                            ),
                            metadata={
                                "audit_id": audit_id,
                                "phase": "adaptive_verification",
                                "attempt": task.attempts,
                                "batch_index": batch["index"],
                                "batch_count": batch["count"],
                                "backend": "codex",
                                "provider": self.settings.codex_provider,
                                "model": self.settings.codex_model,
                                "isolation": self.settings.codex_isolation,
                            },
                        )
                        self.agent_audits.start_turn(
                            session,
                            scan_id=scan_id,
                            task_id=task_id,
                            attempt=task.attempts,
                            phase="adaptive_verification",
                            audit_id=audit_id,
                            request_evidence_id=request_evidence.id,
                            round_index=int(batch["index"]) - 1,
                            workspace_path=str(runtime_workspace),
                        )
                        add_event(
                            session,
                            scan_id,
                            "adaptive_verification.batch_started",
                            (
                                f"高权限验证开始第 {batch['index']}/{batch['count']} 批，"
                                f"包含 {len(batch['candidate_ids'])} 个候选"
                            ),
                            {
                                "task_id": task_id,
                                "batch_index": batch["index"],
                                "batch_count": batch["count"],
                                "candidate_finding_ids": batch["candidate_ids"],
                                "prompt_characters": batch["prompt_characters"],
                            },
                        )
                        session.commit()

                    runtime_events: list[dict[str, Any]] = []

                    def on_runtime_event(
                        event: AgentRuntimeEvent,
                        *,
                        batch_index: int = int(batch["index"]),
                        event_sink: list[dict[str, Any]] = runtime_events,
                    ) -> None:
                        if not self._record_agent_runtime_event(
                            scan_id,
                            task_id,
                            event,
                            phase="adaptive_verification",
                            round_index=batch_index - 1,
                            agent_backend="codex",
                        ):
                            return
                        event_sink.append(
                            {
                                "schema_version": "1.0",
                                "sequence": len(event_sink) + 1,
                                "dedupe_key": event.dedupe_key,
                                "event_type": event.event_type,
                                "message": event.message,
                                "data": event.data,
                                "created_at": datetime.now(UTC).isoformat(),
                            }
                        )

                    try:
                        result = self.codex.verify_batch(
                            scan=scan,
                            task=task,
                            workspace=source_workspace,
                            prompt=batch["prompt"],
                            timeout_seconds=max(1, budget.remaining()),
                            event_callback=on_runtime_event,
                            cancel_event=cancel_event,
                            gateway_environment=gateway_environment,
                        )
                    except AgentCancelledError as exc:
                        self.agent_audits.record_cancellation(
                            scan_id=scan_id,
                            task_id=task_id,
                            audit_id=audit_id,
                            backend="codex",
                            phase="adaptive_verification",
                            attempt=task.attempts,
                            error=exc,
                        )
                        raise
                    except Exception as exc:
                        self.agent_audits.record_error(
                            scan_id=scan_id,
                            task_id=task_id,
                            audit_id=audit_id,
                            backend="codex",
                            phase="adaptive_verification",
                            attempt=task.attempts,
                            error=exc,
                        )
                        self.agent_audits.record_runtime_events(
                            scan_id=scan_id,
                            task_id=task_id,
                            audit_id=audit_id,
                            backend="codex",
                            phase="adaptive_verification",
                            attempt=task.attempts,
                            events=runtime_events,
                        )
                        batch_receipts.append(
                            {
                                "index": batch["index"],
                                "candidate_finding_ids": batch["candidate_ids"],
                                "prompt_characters": batch["prompt_characters"],
                                "status": "failed",
                                "error": str(exc)[:2000],
                            }
                        )
                        with self.database.session_factory() as session:
                            add_event(
                                session,
                                scan_id,
                                "adaptive_verification.batch_failed",
                                (
                                    f"高权限验证第 {batch['index']}/{batch['count']} 批失败，"
                                    "其余批次将继续"
                                ),
                                {
                                    "task_id": task_id,
                                    "batch_index": batch["index"],
                                    "batch_count": batch["count"],
                                    "candidate_finding_ids": batch["candidate_ids"],
                                    "error": str(exc)[:2000],
                                },
                            )
                            session.commit()
                        if batch["index"] < batch["count"]:
                            close_batch_thread_for_next_turn()
                        continue

                    with self.database.session_factory() as session:
                        response_evidence = self.evidence.json(
                            session,
                            scan_id=scan_id,
                            task_id=task_id,
                            kind="agent.response",
                            value={
                                "schema_version": "1.0",
                                "audit_id": audit_id,
                                "batch": {
                                    "index": batch["index"],
                                    "count": batch["count"],
                                },
                                "thread_id": result.thread_id,
                                "turn_id": result.turn_id,
                                "structured_output": result.result.model_dump(mode="json"),
                                "usage": result.usage,
                            },
                            summary=(
                                "Codex scan-level Adaptive Verifier semantic result "
                                f"batch {batch['index']}/{batch['count']}"
                            ),
                            metadata={
                                "audit_id": audit_id,
                                "phase": "adaptive_verification",
                                "attempt": task.attempts,
                                "batch_index": batch["index"],
                                "batch_count": batch["count"],
                                "backend": "codex",
                                "provider": self.settings.codex_provider,
                                "model": self.settings.codex_model,
                                "isolation": self.settings.codex_isolation,
                                "thread_id": result.thread_id,
                                "turn_id": result.turn_id,
                                "verification_mode": "adaptive_agent",
                            },
                        )
                        add_event(
                            session,
                            scan_id,
                            "adaptive_verification.batch_completed",
                            (
                                f"高权限验证第 {batch['index']}/{batch['count']} 批完成，"
                                f"返回 {len(result.result.assessments)} 项判断"
                            ),
                            {
                                "task_id": task_id,
                                "batch_index": batch["index"],
                                "batch_count": batch["count"],
                                "candidate_count": len(batch["candidate_ids"]),
                                "assessment_count": len(result.result.assessments),
                            },
                        )
                        response_evidence_id = response_evidence.id
                        self.agent_audits.finish_turn(
                            session,
                            audit_id=audit_id,
                            status="completed",
                            response_evidence_id=response_evidence.id,
                            thread_id=result.thread_id,
                            turn_id=result.turn_id,
                            usage=result.usage,
                        )
                        assessments_by_finding = {
                            assessment.finding_id: assessment
                            for assessment in result.result.assessments
                            if assessment.finding_id in set(batch["candidate_ids"])
                        }
                        for finding_id, assessment in assessments_by_finding.items():
                            checkpoint = session.scalar(
                                select(AdaptiveVerificationCheckpoint).where(
                                    AdaptiveVerificationCheckpoint.task_id == task_id,
                                    AdaptiveVerificationCheckpoint.finding_id == finding_id,
                                )
                            )
                            if checkpoint is None:
                                checkpoint = AdaptiveVerificationCheckpoint(
                                    scan_id=scan_id,
                                    task_id=task_id,
                                    finding_id=finding_id,
                                    batch_index=int(batch["index"]),
                                    audit_id=audit_id,
                                    response_evidence_id=response_evidence.id,
                                    thread_id=result.thread_id,
                                    turn_id=result.turn_id,
                                    assessment_json=assessment.model_dump(mode="json"),
                                    environment_json={
                                        key: device_context.get(key)
                                        for key in (
                                            "validation_profile",
                                            "android16_verdict_eligible",
                                            "dynamic_verdict_eligible",
                                            "release_gate_eligible",
                                            "compatibility_smoke_only",
                                            "verdict_scope",
                                        )
                                    },
                                )
                                session.add(checkpoint)
                            else:
                                checkpoint.batch_index = int(batch["index"])
                                checkpoint.audit_id = audit_id
                                checkpoint.response_evidence_id = response_evidence.id
                                checkpoint.thread_id = result.thread_id
                                checkpoint.turn_id = result.turn_id
                                checkpoint.assessment_json = assessment.model_dump(mode="json")
                                checkpoint.environment_json = {
                                    key: device_context.get(key)
                                    for key in (
                                        "validation_profile",
                                        "android16_verdict_eligible",
                                        "dynamic_verdict_eligible",
                                        "release_gate_eligible",
                                        "compatibility_smoke_only",
                                        "verdict_scope",
                                    )
                                }
                        session.commit()
                    self.agent_audits.record_runtime_events(
                        scan_id=scan_id,
                        task_id=task_id,
                        audit_id=audit_id,
                        backend="codex",
                        phase="adaptive_verification",
                        attempt=task.attempts,
                        events=runtime_events,
                    )
                    successful_results.append(result)
                    assessed_finding_ids = [
                        assessment.finding_id
                        for assessment in result.result.assessments
                        if assessment.finding_id in set(batch["candidate_ids"])
                    ]
                    response_evidence_ids_by_finding.update(
                        {finding_id: response_evidence_id for finding_id in assessed_finding_ids}
                    )
                    missing_batch_ids = [
                        finding_id
                        for finding_id in batch["candidate_ids"]
                        if finding_id not in set(assessed_finding_ids)
                    ]
                    batch_receipts.append(
                        {
                            "index": batch["index"],
                            "candidate_finding_ids": batch["candidate_ids"],
                            "prompt_characters": batch["prompt_characters"],
                            "status": "partial" if missing_batch_ids else "completed",
                            "audit_id": audit_id,
                            "thread_id": result.thread_id,
                            "turn_id": result.turn_id,
                            "response_evidence_id": response_evidence_id,
                            "assessment_count": len(result.result.assessments),
                            "missing_candidate_finding_ids": missing_batch_ids,
                            **{
                                key: device_context.get(key)
                                for key in (
                                    "validation_profile",
                                    "android16_verdict_eligible",
                                    "dynamic_verdict_eligible",
                                    "release_gate_eligible",
                                    "compatibility_smoke_only",
                                    "verdict_scope",
                                )
                            },
                        }
                    )
                    if batch["index"] < batch["count"]:
                        close_batch_thread_for_next_turn()
            finally:
                if gateway_token is not None:
                    self.unregister_live_proof_context(task_id, gateway_token)

            if not successful_results and not checkpoint_assessments:
                errors = [
                    str(receipt.get("error")) for receipt in batch_receipts if receipt.get("error")
                ]
                raise RuntimeError(
                    "all Adaptive Verifier prompt batches failed"
                    + (f": {errors[-1]}" if errors else "")
                )
            combined_result = AdaptiveVerificationResult(
                summary=(
                    (
                        f"已恢复 {len(checkpoint_assessments)} 个候选断点；"
                        if checkpoint_assessments
                        else ""
                    )
                    + "高权限批量验证已按传输字符预算分批完成。"
                    + "；".join(item.result.summary for item in successful_results)
                )[:12_000],
                assessments=[
                    *checkpoint_assessments,
                    *(
                        assessment
                        for item in successful_results
                        for assessment in item.result.assessments
                    ),
                ],
                shared_observations=list(
                    dict.fromkeys(
                        observation
                        for item in successful_results
                        for observation in item.result.shared_observations
                    )
                ),
                cleanup_actions=list(
                    dict.fromkeys(
                        action
                        for item in successful_results
                        for action in item.result.cleanup_actions
                    )
                ),
                coverage_gaps=list(
                    dict.fromkeys(
                        [gap for item in successful_results for gap in item.result.coverage_gaps]
                        + [
                            (
                                f"Adaptive Verifier batch {receipt['index']} failed: "
                                f"{receipt.get('error')}"
                            )
                            for receipt in batch_receipts
                            if receipt.get("status") == "failed"
                        ]
                    )
                ),
            )
            last_result = successful_results[-1] if successful_results else None
            last_checkpoint = checkpoint_records[-1] if checkpoint_records else None
            response_evidence_id = str(
                next(
                    receipt["response_evidence_id"]
                    for receipt in reversed(batch_receipts)
                    if receipt.get("response_evidence_id")
                )
            )
            self._apply_adaptive_verifier_result(
                scan_id=scan_id,
                task_id=task_id,
                candidate_ids=candidate_ids,
                result=combined_result,
                thread_id=(
                    last_result.thread_id
                    if last_result is not None
                    else str(last_checkpoint.thread_id if last_checkpoint else "checkpoint")
                ),
                turn_id=(
                    last_result.turn_id
                    if last_result is not None
                    else str(last_checkpoint.turn_id if last_checkpoint else "checkpoint")
                ),
                response_evidence_id=response_evidence_id,
                response_evidence_ids_by_finding=response_evidence_ids_by_finding,
                batch_receipts=batch_receipts,
                android16_verdict_eligible=bool(device_context.get("android16_verdict_eligible")),
                dynamic_verdict_eligible=bool(device_context.get("dynamic_verdict_eligible")),
                release_gate_eligible=bool(device_context.get("release_gate_eligible")),
                verdict_scope=str(device_context.get("verdict_scope") or "non_verdict_smoke"),
            )
        finally:
            if device_session is not None:
                device_session.__exit__(None, None, None)

    @staticmethod
    def _proven_attempts_for_finding(session, finding: Finding) -> list[ProofAttempt]:  # noqa: ANN001
        """Resolve only platform-owned harm receipts attributable to one finding."""
        return attributable_harm_attempts(session, finding)

    @staticmethod
    def _refuting_attempts_for_finding(
        session, finding: Finding  # noqa: ANN001
    ) -> list[ProofAttempt]:
        """Resolve attributable platform Oracle receipts that disproved an attempt."""
        return attributable_refutation_attempts(session, finding)

    def _apply_adaptive_verifier_result(
        self,
        *,
        scan_id: str,
        task_id: str,
        candidate_ids: list[str],
        result: AdaptiveVerificationResult,
        thread_id: str,
        turn_id: str,
        response_evidence_id: str,
        android16_verdict_eligible: bool,
        dynamic_verdict_eligible: bool | None = None,
        release_gate_eligible: bool | None = None,
        verdict_scope: str | None = None,
        response_evidence_ids_by_finding: dict[str, str] | None = None,
        batch_receipts: list[dict[str, Any]] | None = None,
    ) -> None:
        response_evidence_ids_by_finding = response_evidence_ids_by_finding or {}
        batch_receipts = batch_receipts or []
        if dynamic_verdict_eligible is None:
            dynamic_verdict_eligible = android16_verdict_eligible
        if release_gate_eligible is None:
            release_gate_eligible = android16_verdict_eligible
        if verdict_scope is None:
            verdict_scope = (
                "android16_release"
                if release_gate_eligible
                else "development_legacy"
                if dynamic_verdict_eligible
                else "non_verdict_smoke"
            )
        batch_execution_by_finding = {
            finding_id: receipt
            for receipt in batch_receipts
            if receipt.get("status") in {"completed", "restored_checkpoint", "partial"}
            for finding_id in receipt.get("candidate_finding_ids", [])
            if isinstance(finding_id, str)
        }
        candidate_set = set(candidate_ids)
        assessments: dict[str, Any] = {}
        ignored: list[str] = []
        for assessment in result.assessments:
            if assessment.finding_id not in candidate_set or assessment.finding_id in assessments:
                ignored.append(assessment.finding_id)
                continue
            assessments[assessment.finding_id] = assessment
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            task = session.get(InvestigationTask, task_id)
            if scan is None or task is None:
                raise LookupError("Adaptive Verifier result target disappeared")
            evidence_records = list(
                session.scalars(select(Evidence).where(Evidence.scan_id == scan_id))
            )
            evidence_by_id = {item.id: item for item in evidence_records}
            verdict_counts: Counter[str] = Counter()
            model_verdict_counts: Counter[str] = Counter()
            verdict_overrides: list[dict[str, str]] = []
            for finding_id in candidate_ids:
                finding = session.get(Finding, finding_id)
                assessment = assessments.get(finding_id)
                if finding is None or assessment is None:
                    continue
                existing_status = finding.status
                preserve_human_closure = (
                    existing_status
                    in {
                        FindingStatus.FALSE_POSITIVE.value,
                        FindingStatus.ACCEPTED.value,
                    }
                    and isinstance(finding.review_note, str)
                    and bool(finding.review_note.strip())
                )
                existing_signal_tier = evidence_backed_signal_tier(session, finding)
                proven_attempts = self._proven_attempts_for_finding(session, finding)
                proven_attempt_ids = [attempt.id for attempt in proven_attempts]
                proven_evidence_ids = self._ordered_union(
                    *(list(attempt.evidence_ids or []) for attempt in proven_attempts)
                )
                refuting_attempts = self._refuting_attempts_for_finding(session, finding)
                refuting_attempt_ids = [attempt.id for attempt in refuting_attempts]
                refuting_evidence_ids = self._ordered_union(
                    *(list(attempt.evidence_ids or []) for attempt in refuting_attempts)
                )
                model_verdict = assessment.verdict
                model_verdict_counts[model_verdict] += 1
                raw_finding_evidence_ids = (
                    finding.evidence_ids if isinstance(finding.evidence_ids, list) else []
                )
                finding_evidence_ids = {
                    value
                    for value in raw_finding_evidence_ids
                    if isinstance(value, str) and value
                }
                linked_runtime_observations = list(
                    session.scalars(
                        select(RuntimeObservation).where(
                            RuntimeObservation.scan_id == finding.scan_id,
                            RuntimeObservation.finding_id == finding.id,
                        )
                    )
                )
                linked_runtime_evidence_ids = {
                    evidence_id
                    for observation in linked_runtime_observations
                    for evidence_id in (
                        observation.evidence_ids
                        if isinstance(observation.evidence_ids, list)
                        else []
                    )
                    if isinstance(evidence_id, str) and evidence_id
                }

                def evidence_is_bound_to_finding(
                    evidence: Evidence,
                    *,
                    current_finding_id: str = finding.id,
                    current_finding_evidence_ids: set[str] = finding_evidence_ids,
                    current_runtime_evidence_ids: set[str] = linked_runtime_evidence_ids,
                ) -> bool:
                    metadata = (
                        evidence.metadata_json
                        if isinstance(evidence.metadata_json, dict)
                        else {}
                    )
                    candidate_finding_ids = metadata.get("candidate_finding_ids")
                    return (
                        evidence.id in current_finding_evidence_ids
                        or metadata.get("finding_id") == current_finding_id
                        or (
                            isinstance(candidate_finding_ids, list)
                            and current_finding_id in candidate_finding_ids
                        )
                        or evidence.id in current_runtime_evidence_ids
                    )

                accepted_assessment_evidence = [
                    evidence_by_id[evidence_id]
                    for evidence_id in assessment.evidence_ids
                    if evidence_id in evidence_by_id
                    and evidence_is_bound_to_finding(evidence_by_id[evidence_id])
                ]
                accepted_evidence_ids = [
                    evidence.id for evidence in accepted_assessment_evidence
                ]
                platform_runtime_observed = any(
                    evidence_supports_runtime_observation(evidence)
                    for evidence in evidence_records
                    if evidence.id in linked_runtime_evidence_ids
                )
                static_refutation_gate = build_static_refutation_gate(
                    evidence_by_id={
                        evidence.id: evidence
                        for evidence in accepted_assessment_evidence
                    },
                    evidence_ids=assessment.evidence_ids,
                    counterevidence=assessment.counterevidence,
                    blocked_edge=assessment.attack_chain,
                )
                candidate_execution = batch_execution_by_finding.get(finding_id, {})
                candidate_android16_eligible = bool(
                    candidate_execution.get(
                        "android16_verdict_eligible",
                        android16_verdict_eligible,
                    )
                )
                candidate_dynamic_eligible = bool(
                    candidate_execution.get(
                        "dynamic_verdict_eligible",
                        dynamic_verdict_eligible,
                    )
                )
                candidate_release_eligible = bool(
                    candidate_execution.get(
                        "release_gate_eligible",
                        release_gate_eligible,
                    )
                )
                candidate_verdict_scope = str(
                    candidate_execution.get("verdict_scope") or verdict_scope
                )
                verdict = model_verdict
                verdict_override_reason: str | None = None
                negative_verdict = model_verdict in {
                    FindingStatus.REFUTED_STATIC.value,
                    FindingStatus.NOT_REPRODUCED.value,
                }
                runtime_context = (
                    platform_runtime_observed
                    or existing_signal_tier == "runtime_oracle_gap"
                )
                if preserve_human_closure:
                    verdict = existing_status
                    verdict_override_reason = (
                        "The finding was explicitly dispositioned by a human while adaptive "
                        "verification was running; the late Agent result is retained for audit "
                        "and requires an explicit human review to replace."
                    )
                elif proven_attempts:
                    verdict = FindingStatus.REPRODUCED_BLACKBOX.value
                    if model_verdict != verdict:
                        verdict_override_reason = (
                            "An existing platform ProofAttempt demonstrated harm; the adaptive "
                            "model verdict cannot downgrade that immutable receipt."
                        )
                elif negative_verdict and refuting_attempts:
                    verdict = FindingStatus.NOT_REPRODUCED.value
                    if model_verdict != verdict:
                        verdict_override_reason = (
                            "An attributable platform Oracle receipt refuted the runtime attempt; "
                            "the applied verdict is dynamic, not a model-only static refutation."
                        )
                elif negative_verdict and runtime_context and not refuting_attempts:
                    verdict = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                    verdict_override_reason = (
                        "A runtime observation cannot be closed by a model-only negative verdict; "
                        "an attributable platform Oracle refutation receipt is required."
                    )
                elif (
                    model_verdict == FindingStatus.NOT_REPRODUCED.value
                    and not refuting_attempts
                ):
                    verdict = FindingStatus.INCONCLUSIVE.value
                    verdict_override_reason = (
                        "The adaptive model cannot claim a negative runtime result without an "
                        "attributable platform Oracle refutation receipt."
                    )
                elif (
                    model_verdict == FindingStatus.REFUTED_STATIC.value
                    and static_refutation_gate["eligible"] is not True
                ):
                    verdict = FindingStatus.INCONCLUSIVE.value
                    verdict_override_reason = (
                        "A static refutation requires usable static platform evidence attributable "
                        "to this finding and concrete counterevidence naming the guard or blocked "
                        "edge."
                    )
                elif (
                    existing_signal_tier == "runtime_oracle_gap"
                    and not refuting_attempts
                    and model_verdict
                    not in {
                        FindingStatus.REFUTED_STATIC.value,
                        FindingStatus.NOT_REPRODUCED.value,
                    }
                ):
                    verdict = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                    verdict_override_reason = (
                        "A later model-only assessment cannot erase an existing runtime Oracle "
                        "gap; platform proof or refutation is still required."
                    )
                elif platform_runtime_observed:
                    verdict = FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                    verdict_override_reason = (
                        "A linked platform runtime observation exists, but no attributable "
                        "harm-demonstrating ProofAttempt exists; the observation remains an "
                        "Oracle gap."
                    )
                elif model_verdict == FindingStatus.REPRODUCED_BLACKBOX.value:
                    verdict = FindingStatus.INCONCLUSIVE.value
                    verdict_override_reason = (
                        "The adaptive assessment claimed reproduction without a linked platform "
                        "runtime observation or an attributable harm-demonstrating ProofAttempt."
                    )
                elif assessment.runtime_observed:
                    verdict_override_reason = (
                        "The model-reported runtime observation was retained only as a claim "
                        "because no finding-linked platform runtime receipt supports it."
                    )
                if verdict_override_reason is not None:
                    verdict_overrides.append(
                        {
                            "finding_id": finding_id,
                            "model_verdict": model_verdict,
                            "applied_verdict": verdict,
                            "reason": verdict_override_reason,
                        }
                    )
                verdict_counts[verdict] += 1
                accepted_evidence_ids.extend(proven_evidence_ids)
                accepted_evidence_ids.extend(refuting_evidence_ids)
                candidate_response_evidence_id = response_evidence_ids_by_finding.get(
                    finding_id,
                    response_evidence_id,
                )
                candidate_thread_id = str(candidate_execution.get("thread_id") or thread_id)
                candidate_turn_id = str(candidate_execution.get("turn_id") or turn_id)
                accepted_evidence_ids.append(candidate_response_evidence_id)
                raw_history = (finding.metadata_json or {}).get(
                    "adaptive_verification_history"
                )
                history = [
                    dict(item)
                    for item in raw_history
                    if isinstance(item, dict)
                ] if isinstance(raw_history, list) else []
                history_entry = {
                    "schema_version": "1.0",
                    "task_id": task_id,
                    "thread_id": candidate_thread_id,
                    "turn_id": candidate_turn_id,
                    "verification_mode": "adaptive_agent",
                    "model_verdict": model_verdict,
                    "verdict": verdict,
                    "verdict_override_reason": verdict_override_reason,
                    "android16_verdict_eligible": candidate_android16_eligible,
                    "dynamic_verdict_eligible": candidate_dynamic_eligible,
                    "release_gate_eligible": candidate_release_eligible,
                    "compatibility_smoke_only": not candidate_dynamic_eligible,
                    "verdict_scope": candidate_verdict_scope,
                    "confidence": assessment.confidence,
                    "runtime_observed": bool(
                        platform_runtime_observed
                        or existing_signal_tier == "runtime_oracle_gap"
                    ),
                    "model_runtime_observed": assessment.runtime_observed,
                    "runtime_claim_accepted": platform_runtime_observed,
                    "duplicate_of_finding_id": assessment.duplicate_of_finding_id,
                    "summary": assessment.summary,
                    "attack_chain": assessment.attack_chain,
                    "security_impact": assessment.security_impact,
                    "counterevidence": assessment.counterevidence,
                    "remaining_gaps": assessment.remaining_gaps,
                    "experiments": [
                        experiment.model_dump(mode="json") for experiment in assessment.experiments
                    ],
                    "proof_attempt_ids": proven_attempt_ids,
                    "refutation_attempt_ids": refuting_attempt_ids,
                    "response_evidence_id": candidate_response_evidence_id,
                    "previous_status": existing_status,
                }
                if model_verdict == FindingStatus.REFUTED_STATIC.value:
                    history_entry["platform_static_refutation_gate"] = (
                        static_refutation_gate
                    )
                if (
                    history
                    and history[-1].get("task_id") == task_id
                    and history[-1].get("response_evidence_id") == candidate_response_evidence_id
                ):
                    history[-1] = history_entry
                else:
                    history.append(history_entry)
                if not preserve_human_closure:
                    finding.status = verdict
                    finding.confidence = assessment.confidence
                    finding.review_note = (
                        f"{assessment.summary}\n平台判定限制：{verdict_override_reason}"
                        if verdict_override_reason
                        else assessment.summary
                    )
                finding.evidence_ids = list(
                    dict.fromkeys([*raw_finding_evidence_ids, *accepted_evidence_ids])
                )
                finding_metadata = {
                    **dict(finding.metadata_json or {}),
                    "harm_demonstrated": bool(proven_attempts),
                    "proof_attempt_ids": proven_attempt_ids,
                    "refutation_attempt_ids": refuting_attempt_ids,
                    "android16_verdict_eligible": candidate_android16_eligible,
                    "dynamic_verdict_eligible": candidate_dynamic_eligible,
                    "release_gate_eligible": bool(
                        proven_attempts
                        and any(
                            bool((attempt.oracle or {}).get("release_gate_eligible"))
                            for attempt in proven_attempts
                        )
                    ),
                    "verdict_scope": candidate_verdict_scope,
                    "verification_mode": "adaptive_agent",
                    "adaptive_verification": history[-1],
                    "adaptive_verification_history": history[-10:],
                    "proof_backlog": {
                        **dict((finding.metadata_json or {}).get("proof_backlog") or {}),
                        "status": (
                            "verified"
                            if proven_attempts
                            else "closed"
                            if preserve_human_closure
                            else "oracle_gap"
                            if verdict == FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value
                            else "closed"
                            if verdict
                            in {
                                FindingStatus.REFUTED_STATIC.value,
                                FindingStatus.NOT_REPRODUCED.value,
                            }
                            else "proof_required"
                        ),
                        "verification_mode": "adaptive_agent",
                        "verifier_task_id": task_id,
                    },
                }
                if preserve_human_closure:
                    finding_metadata["latest_agent_reanalysis"] = {
                        **history_entry,
                        "human_closure_preserved": True,
                    }
                if verdict == FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value:
                    finding_metadata["signal_tier"] = "runtime_oracle_gap"
                    finding_metadata["proof_gap_code"] = "missing_platform_harm_oracle"
                    finding_metadata["oracle_gap"] = {
                        "schema_version": "1.0",
                        "status": "open",
                        "reason": "missing_harm_demonstrated_proof_attempt",
                        "runtime_observed": bool(
                            platform_runtime_observed
                            or existing_signal_tier == "runtime_oracle_gap"
                        ),
                        "proof_attempt_ids": proven_attempt_ids,
                        "verifier_task_id": task_id,
                    }
                elif verdict == FindingStatus.SUPPORTED_STATIC.value:
                    finding_metadata["signal_tier"] = "static_chain"
                    finding_metadata.pop("oracle_gap", None)
                    finding_metadata.pop("proof_gap_code", None)
                else:
                    finding_metadata.pop("signal_tier", None)
                    finding_metadata.pop("oracle_gap", None)
                    finding_metadata.pop("proof_gap_code", None)
                if (
                    verdict == FindingStatus.REFUTED_STATIC.value
                    and static_refutation_gate["eligible"] is True
                ):
                    finding_metadata["platform_static_refutation_gate"] = (
                        static_refutation_gate
                    )
                elif not preserve_human_closure:
                    finding_metadata.pop("platform_static_refutation_gate", None)
                report_payload = finding_metadata.get("report")
                if isinstance(report_payload, dict) and not preserve_human_closure:
                    report = FindingReport.model_validate(report_payload)
                    report.conclusion = (assessment.security_impact or assessment.summary)[:600]
                    if assessment.attack_chain:
                        chain = [
                            item.strip()
                            for item in re.split(r"\s*(?:→|->|\n)\s*", assessment.attack_chain)
                            if item.strip()
                        ]
                        report.attack_chain = chain[:5]
                    report.verification.status = (
                        "confirmed"
                        if verdict == FindingStatus.REPRODUCED_BLACKBOX.value
                        else "refuted"
                        if verdict == FindingStatus.REFUTED_STATIC.value
                        else "inconclusive"
                        if verdict
                        in {
                            FindingStatus.NOT_REPRODUCED.value,
                            FindingStatus.INCONCLUSIVE.value,
                        }
                        else "pending"
                    )
                    report.verification.established_facts = list(
                        dict.fromkeys(
                            value
                            for value in [assessment.summary, assessment.security_impact]
                            if value
                        )
                    )[:3]
                    report.verification.missing_proof = (
                        assessment.remaining_gaps[0] if assessment.remaining_gaps else None
                    )
                    report.verification.next_step = (
                        "根据剩余缺口继续补充动态实验。" if assessment.remaining_gaps else None
                    )
                    report.verification.evidence_ids = list(dict.fromkeys(accepted_evidence_ids))[
                        :64
                    ]
                    report.verification.proof_attempt_ids = self._ordered_union(
                        proven_attempt_ids,
                        refuting_attempt_ids,
                    )[:64]
                    report.kind = (
                        "finding"
                        if verdict == FindingStatus.REPRODUCED_BLACKBOX.value
                        else "pending_risk"
                    )
                    if verdict == FindingStatus.REPRODUCED_BLACKBOX.value:
                        report.title = re.sub(r"^(?:待验证|已复现)：", "已复现：", report.title)
                    elif report.title.startswith("已复现："):
                        report.title = f"待验证：{report.title.removeprefix('已复现：')}"
                    finding_metadata["report"] = report.model_dump(mode="json")
                    finding.title = report.title
                    finding.description = render_finding_description(report)
                finding.metadata_json = finding_metadata
            ignored_duplicate_relations: list[dict[str, str]] = []
            explicit_duplicates: dict[str, str] = {}
            for finding_id, assessment in assessments.items():
                canonical_id = assessment.duplicate_of_finding_id
                if canonical_id is None:
                    continue
                if canonical_id not in candidate_set or canonical_id not in assessments:
                    ignored_duplicate_relations.append(
                        {
                            "finding_id": finding_id,
                            "duplicate_of_finding_id": canonical_id,
                            "reason": "canonical finding is not an assessed candidate",
                        }
                    )
                    continue
                explicit_duplicates[finding_id] = canonical_id
            merged_findings = self._consolidate_findings(
                session,
                scan_id=scan_id,
                explicit_duplicates=explicit_duplicates,
            )
            session.flush()
            effective_finding_ids = {
                merged_findings.get(finding_id, finding_id) for finding_id in assessments
            }
            effective_verdict_counts: Counter[str] = Counter()
            for finding_id in effective_finding_ids:
                effective_finding = session.get(Finding, finding_id)
                if effective_finding is not None:
                    effective_verdict_counts[effective_finding.status] += 1
            missing = [value for value in candidate_ids if value not in assessments]
            output = result.model_dump(mode="json")
            output["verification_mode"] = "adaptive_agent"
            output["response_evidence_id"] = response_evidence_id
            output["response_evidence_ids"] = list(
                dict.fromkeys(response_evidence_ids_by_finding.values())
            ) or [response_evidence_id]
            output["adaptive_batches"] = deepcopy(batch_receipts)
            output["missing_candidate_assessments"] = missing
            output["ignored_assessment_finding_ids"] = ignored
            output["ignored_duplicate_relations"] = ignored_duplicate_relations
            output["merged_finding_map"] = merged_findings
            output["android16_verdict_eligible"] = android16_verdict_eligible
            output["dynamic_verdict_eligible"] = dynamic_verdict_eligible
            output["release_gate_eligible"] = release_gate_eligible
            output["verdict_scope"] = verdict_scope
            output["verdict_overrides"] = verdict_overrides
            resume_history = list((task.result or {}).get("adaptive_resume_history") or [])
            if resume_history:
                output["adaptive_resume_history"] = resume_history[-10:]
            task.thread_id = thread_id
            task.turn_id = turn_id
            task.result = output
            task.status = TaskStatus.INCONCLUSIVE.value if missing else TaskStatus.COMPLETED.value
            task.completed_at = now()
            scan.stats = {
                **dict(scan.stats or {}),
                "adaptive_verification": {
                    **dict((scan.stats or {}).get("adaptive_verification") or {}),
                    "status": "partial" if missing else "completed",
                    "task_id": task_id,
                    "thread_id": thread_id,
                    "turn_id": turn_id,
                    "response_evidence_id": response_evidence_id,
                    "response_evidence_ids": output["response_evidence_ids"],
                    "batch_count": len(batch_receipts) or 1,
                    "failed_batch_count": sum(
                        receipt.get("status") not in {"completed", "restored_checkpoint"}
                        for receipt in batch_receipts
                    ),
                    "assessment_count": len(assessments),
                    "missing_assessment_count": len(missing),
                    "verdict_counts": dict(effective_verdict_counts),
                    "assessment_verdict_counts": dict(verdict_counts),
                    "model_verdict_counts": dict(model_verdict_counts),
                    "compatibility_override_count": len(verdict_overrides),
                    "oracle_gap_count": effective_verdict_counts.get(
                        FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
                        0,
                    ),
                    "resume_count": len(resume_history),
                    "verdict_scope": verdict_scope,
                    "release_gate_eligible": release_gate_eligible,
                    "merged_duplicate_count": len(merged_findings),
                },
            }
            add_event(
                session,
                scan_id,
                ("adaptive_verification.partial" if missing else "adaptive_verification.completed"),
                (
                    f"高权限验证 Agent 已完成 {len(assessments)} 个候选，"
                    f"仍有 {len(missing)} 个候选待补充"
                    if missing
                    else f"高权限验证 Agent 已完成 {len(assessments)} 个候选的语义判断"
                ),
                {
                    "task_id": task_id,
                    "candidate_count": len(candidate_ids),
                    "assessment_count": len(assessments),
                    "missing_assessment_count": len(missing),
                    "verdict_counts": dict(effective_verdict_counts),
                    "assessment_verdict_counts": dict(verdict_counts),
                    "model_verdict_counts": dict(model_verdict_counts),
                    "compatibility_override_count": len(verdict_overrides),
                    "oracle_gap_count": effective_verdict_counts.get(
                        FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
                        0,
                    ),
                    "merged_duplicate_count": len(merged_findings),
                    "android16_verdict_eligible": android16_verdict_eligible,
                    "dynamic_verdict_eligible": dynamic_verdict_eligible,
                    "release_gate_eligible": release_gate_eligible,
                    "verdict_scope": verdict_scope,
                    "batch_count": len(batch_receipts) or 1,
                    "failed_batch_count": sum(
                        receipt.get("status") not in {"completed", "restored_checkpoint"}
                        for receipt in batch_receipts
                    ),
                    "thread_id": thread_id,
                    "turn_id": turn_id,
                },
            )
            session.commit()
