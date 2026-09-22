from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import Database
from ..core.enums import FindingStatus, ScanStatus
from ..core.evidence import EvidenceRecorder
from ..core.finding_policy import evidence_backed_signal_tiers, project_findings
from ..core.models import (
    CoverageItem,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    Scan,
)
from ..core.repository import add_event, now
from .disposition import (
    disposition_coverage_rate,
    disposition_summary,
    resolve_entry_dispositions,
)
from .planner import InvestigationPlanner

if TYPE_CHECKING:
    from ..core.config import Settings
    from .device import AdbDevicePool


class ScanFinalizer:
    """Own the final scan projection, entry dispositions, and immutable seal."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        evidence: EvidenceRecorder,
        device_pool: AdbDevicePool,
        resolve_task_investigator: Callable[[Scan, InvestigationTask], str],
    ):
        self.settings = settings
        self.database = database
        self.evidence = evidence
        self.device_pool = device_pool
        self.resolve_task_investigator = resolve_task_investigator

    def create_scan_seal(
        self,
        session: Session,
        scan: Scan,
        finding_records: list[Finding],
    ) -> Evidence:
        tasks = list(
            session.scalars(
                select(InvestigationTask)
                .where(InvestigationTask.scan_id == scan.id)
                .order_by(InvestigationTask.id)
            )
        )
        evidence_records = list(
            session.scalars(
                select(Evidence)
                .where(Evidence.scan_id == scan.id, Evidence.kind != "scan.seal")
                .order_by(Evidence.id)
            )
        )
        coverage_records = list(
            session.scalars(
                select(CoverageItem)
                .where(CoverageItem.scan_id == scan.id)
                .order_by(CoverageItem.control_id, CoverageItem.id)
            )
        )
        entry_records = list(
            session.scalars(
                select(EntryPoint)
                .where(EntryPoint.scan_id == scan.id)
                .order_by(EntryPoint.id)
            )
        )
        seal_payload = {
            "schema_version": "1.0",
            "scan_id": scan.id,
            "artifact_sha256": scan.artifact_sha256,
            "package": scan.package_name,
            "threat_model_digest": (((scan.stats or {}).get("threat_model") or {}).get("digest")),
            "tasks": [
                {
                    "id": task.id,
                    "status": task.status,
                    "result_sha256": hashlib.sha256(
                        json.dumps(
                            task.result or {},
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest(),
                }
                for task in tasks
            ],
            "findings": [
                {
                    "record_id": finding.id,
                    "finding_id": (
                        (finding.metadata_json or {}).get("identity", {}).get("finding_id")
                    ),
                    "occurrence_id": (
                        (finding.metadata_json or {}).get("identity", {}).get("occurrence_id")
                    ),
                    "status": finding.status,
                    "evidence_ids": sorted(finding.evidence_ids),
                }
                for finding in sorted(finding_records, key=lambda item: item.id)
            ],
            "evidence": [
                {
                    "id": item.id,
                    "task_id": item.task_id,
                    "kind": item.kind,
                    "sha256": item.sha256,
                }
                for item in evidence_records
            ],
            "coverage": [
                {
                    "control_id": item.control_id,
                    "entry_point_id": item.entry_point_id,
                    "status": item.status,
                }
                for item in coverage_records
            ],
            "entry_dispositions": [
                {
                    "entry_point_id": item.id,
                    "disposition": item.disposition,
                }
                for item in entry_records
            ],
        }
        return self.evidence.json(
            session,
            scan_id=scan.id,
            task_id=None,
            kind="scan.seal",
            value=seal_payload,
            summary=(
                "Immutable receipt over the APK digest, threat model, tasks, "
                "findings, evidence, and coverage ledger"
            ),
            metadata={
                "schema_version": "1.0",
                "threat_model_digest": seal_payload["threat_model_digest"],
            },
        )

    def assign_entry_dispositions(
        self,
        session: Session,
        scan: Scan,
        finding_records: list[Finding],
        confirmed_finding_ids: set[str],
    ) -> dict[str, str]:
        entries = list(
            session.scalars(
                select(EntryPoint)
                .where(EntryPoint.scan_id == scan.id)
                .order_by(EntryPoint.id)
            )
        )
        tasks = list(
            session.scalars(
                select(InvestigationTask)
                .where(InvestigationTask.scan_id == scan.id)
                .order_by(InvestigationTask.id)
            )
        )
        entry_payloads = [
            {
                "id": entry.id,
                "kind": entry.kind,
                "name": entry.name,
                "owner_component": entry.owner_component,
                "exported": entry.exported,
                "permission": entry.permission,
                "permission_protection": entry.permission_protection,
                "metadata_json": entry.metadata_json,
                "static_closure_evaluated": True,
                "static_closure": (
                    closure.as_dict()
                    if (closure := InvestigationPlanner._static_closure(entry)) is not None
                    else None
                ),
            }
            for entry in entries
        ]
        task_payloads = [
            {
                "id": task.id,
                "target_entry_ids": task.target_entry_ids,
                "status": task.status,
                "task_type": task.task_type,
                "attempts": task.attempts,
                "recency": (task.completed_at or task.started_at or task.created_at).timestamp(),
                "agent_enabled": (
                    (backend := self.resolve_task_investigator(scan, task)) != "none"
                    and self.settings.investigator_enabled(backend)
                ),
                "capability_gap": bool((task.result or {}).get("capability_gap"))
                or (task.result or {}).get("failure_category")
                in {"agent_unavailable", "device_unavailable"},
            }
            for task in tasks
        ]
        signal_tiers = evidence_backed_signal_tiers(session, finding_records)
        finding_payloads = [
            {
                "id": finding.id,
                "entry_point_ids": finding.entry_point_ids,
                "status": finding.status,
                "task_id": (finding.metadata_json or {}).get("task_id"),
                "proof_backed": finding.id in confirmed_finding_ids,
                "signal_tier": signal_tiers[finding.id],
                "active": not isinstance(
                    (finding.metadata_json or {}).get("merged_into_finding_id"), str
                ),
            }
            for finding in finding_records
        ]
        attack_chains: list[dict[str, Any]] = []
        for finding in finding_records:
            finding_metadata = finding.metadata_json or {}
            if (
                isinstance(finding_metadata.get("merged_into_finding_id"), str)
                or finding.status
                not in {
                    FindingStatus.CANDIDATE.value,
                    FindingStatus.SUPPORTED_STATIC.value,
                    FindingStatus.RUNTIME_OBSERVED_UNVERIFIED.value,
                    FindingStatus.ACCEPTED.value,
                    FindingStatus.REPRODUCED_BLACKBOX.value,
                }
                or (
                    finding.status == FindingStatus.REPRODUCED_BLACKBOX.value
                    and finding.id not in confirmed_finding_ids
                )
            ):
                continue
            for chain in (finding.metadata_json or {}).get("attack_chains", []) or []:
                if not isinstance(chain, dict):
                    continue
                attack_chains.append(
                    {
                        **chain,
                        "entry_point_ids": list(
                            dict.fromkeys(
                                [
                                    *(chain.get("entry_point_ids", []) or []),
                                    *(finding.entry_point_ids or []),
                                ]
                            )
                        ),
                        "task_id": finding_metadata.get("task_id"),
                    }
                )
        for entry in entries:
            for chain in (entry.metadata_json or {}).get("static_review_attack_chains", []) or []:
                if not isinstance(chain, dict):
                    continue
                attack_chains.append(
                    {
                        **chain,
                        "entry_point_ids": list(
                            dict.fromkeys(
                                [*(chain.get("entry_point_ids", []) or []), entry.id]
                            )
                        ),
                    }
                )

        dispositions = resolve_entry_dispositions(
            entry_payloads,
            task_payloads,
            finding_payloads,
            attack_chains,
            codex_enabled=any(
                task_payload.get("agent_enabled") is True for task_payload in task_payloads
            ),
            device_available=self.device_pool.configured,
        )
        for entry in entries:
            entry.disposition = dispositions[entry.id]
        return dispositions

    def finish(self, scan_id: str) -> None:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise KeyError(scan_id)
            counts: dict[str, int] = defaultdict(int)
            for status in session.scalars(
                select(InvestigationTask.status).where(InvestigationTask.scan_id == scan_id)
            ):
                counts[status] += 1
            finding_records = list(
                session.scalars(select(Finding).where(Finding.scan_id == scan_id))
            )
            projections = project_findings(session, finding_records)
            confirmed_findings = [item.finding for item in projections if item.is_confirmed]
            signals = [item.finding for item in projections if not item.is_confirmed]
            entry_dispositions = self.assign_entry_dispositions(
                session,
                scan,
                finding_records,
                {finding.id for finding in confirmed_findings},
            )
            entry_disposition_counts = disposition_summary(entry_dispositions)
            entry_disposition_rate = disposition_coverage_rate(entry_dispositions)
            seal = self.create_scan_seal(session, scan, finding_records)
            execution_control = dict((scan.stats or {}).get("execution_control") or {})
            stopped_by_user = execution_control.get("state") == "stopping"
            if stopped_by_user:
                execution_control = {
                    **execution_control,
                    "state": "stopped",
                    "completed_at": now().isoformat(),
                }
            scan.status = ScanStatus.FINAL.value
            scan.completed_at = datetime.now(UTC)
            scan.stats = {
                **scan.stats,
                "task_status_counts": dict(counts),
                "finding_count": len(confirmed_findings),
                "signal_count": len(signals),
                "entry_disposition_counts": entry_disposition_counts,
                "entry_disposition_coverage_rate": entry_disposition_rate,
                "unresolved_entry_disposition_count": entry_disposition_counts.get(
                    "uninvestigated", 0
                ),
                **({"execution_control": execution_control} if execution_control else {}),
                "seal": {
                    "schema_version": "1.0",
                    "evidence_id": seal.id,
                    "sha256": seal.sha256,
                    "current": True,
                },
                "materialized_summary": {
                    "schema_version": "1.0",
                    "current": True,
                    "generated_at": now().isoformat(),
                },
            }
            add_event(
                session,
                scan_id,
                "scan.final",
                "Final report is ready",
                {
                    "task_status_counts": dict(counts),
                    "findings": len(confirmed_findings),
                    "signals": len(signals),
                    "entry_disposition_counts": entry_disposition_counts,
                    "entry_disposition_coverage_rate": entry_disposition_rate,
                    "seal_evidence_id": seal.id,
                    "seal_sha256": seal.sha256,
                    "stopped_by_user": stopped_by_user,
                },
            )
            session.commit()
