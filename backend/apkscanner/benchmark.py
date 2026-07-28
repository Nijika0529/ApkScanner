from __future__ import annotations

from typing import Any

from sqlalchemy import select

from .config import Settings
from .db import Database
from .enums import FindingStatus, ScanStatus
from .models import BenchmarkEvaluation, EntryPoint, Finding, Scan
from .schemas import BenchmarkSpec, GroundTruthVulnerability

_PROOF_RANK = {
    FindingStatus.SUPPORTED_STATIC.value: 1,
    FindingStatus.REPRODUCED_BLACKBOX.value: 2,
}
_MINIMUM_PROOF_RANK = {"static": 1, "dynamic": 2}


class BenchmarkEvaluator:
    """Scores only platform-confirmed findings against an explicit private ground truth."""

    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database

    def evaluate(self, scan_id: str, spec: BenchmarkSpec) -> BenchmarkEvaluation:
        with self.database.session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise ValueError("scan not found")
            if scan.status != ScanStatus.FINAL.value:
                raise ValueError("benchmark evaluation requires a completed final scan")
            if spec.apk_sha256 and spec.apk_sha256 != scan.artifact_sha256:
                raise ValueError("ground truth APK SHA-256 does not match the selected scan")
            entries = list(
                session.scalars(select(EntryPoint).where(EntryPoint.scan_id == scan_id))
            )
            findings = list(
                session.scalars(
                    select(Finding)
                    .where(Finding.scan_id == scan_id)
                    .order_by(Finding.created_at)
                )
            )
            result = self._score(spec, findings, entries)
            control = scan.stats.get("agent_control")
            if not isinstance(control, dict):
                control = {}
            attributed_findings = [
                finding
                for finding in findings
                if finding.source in {"codex", "opencode"}
                and self._confirmed(finding)
            ]
            observed_backends = sorted(
                {finding.source for finding in attributed_findings}
            )
            configured_backend = str(
                control.get("backend")
                or scan.stats.get("investigator")
                or self.settings.investigator_backend
            )
            backend = (
                observed_backends[0]
                if len(observed_backends) == 1
                else f"mixed:{','.join(observed_backends)}"
                if observed_backends
                else configured_backend
            )
            observed_models = sorted(
                {
                    str(finding.metadata_json.get("model"))
                    for finding in attributed_findings
                    if finding.metadata_json.get("model")
                }
            )
            model = (
                observed_models[0]
                if len(observed_models) == 1
                else f"mixed:{','.join(observed_models)}"
                if observed_models
                else self.settings.codex_worker_model
                if backend == "codex"
                else self.settings.opencode_model
                if backend == "opencode"
                else None
            )
            result["model_attribution"] = {
                "backend": backend,
                "backends": observed_backends or [configured_backend],
                "models": observed_models or ([model] if model else []),
                "source": (
                    "finding_metadata"
                    if observed_backends or observed_models
                    else "scan_configuration_fallback"
                ),
            }
            evaluation = BenchmarkEvaluation(
                scan_id=scan_id,
                name=spec.name,
                artifact_sha256=scan.artifact_sha256,
                investigator_backend=backend,
                model=model,
                ground_truth=spec.model_dump(mode="json"),
                result=result,
            )
            session.add(evaluation)
            session.commit()
            return evaluation

    @classmethod
    def _score(
        cls,
        spec: BenchmarkSpec,
        findings: list[Finding],
        entries: list[EntryPoint],
    ) -> dict[str, Any]:
        entry_names = {entry.id: entry.name for entry in entries}
        confirmed = [finding for finding in findings if cls._confirmed(finding)]
        ai_noise = [
            finding
            for finding in findings
            if finding.source in {"codex", "opencode"}
            and not cls._confirmed(finding)
        ]
        findings_by_id = {finding.id: finding for finding in confirmed}
        candidate_ids_by_truth: list[list[str]] = []
        for truth in spec.vulnerabilities:
            candidates = [
                finding
                for finding in confirmed
                if cls._matches(truth, finding, entry_names)
            ]
            candidates.sort(
                key=lambda finding: (
                    _PROOF_RANK.get(finding.status, 0),
                    len(finding.evidence_ids),
                    finding.id,
                ),
                reverse=True,
            )
            candidate_ids_by_truth.append([finding.id for finding in candidates])

        finding_assignment: dict[str, int] = {}

        def assign(truth_index: int, seen: set[str]) -> bool:
            for finding_id in candidate_ids_by_truth[truth_index]:
                if finding_id in seen:
                    continue
                seen.add(finding_id)
                previous_truth = finding_assignment.get(finding_id)
                if previous_truth is None or assign(previous_truth, seen):
                    finding_assignment[finding_id] = truth_index
                    return True
            return False

        for truth_index in sorted(
            range(len(spec.vulnerabilities)),
            key=lambda value: (
                len(candidate_ids_by_truth[value]),
                spec.vulnerabilities[value].id,
            ),
        ):
            assign(truth_index, set())

        truth_assignment = {
            truth_index: finding_id
            for finding_id, truth_index in finding_assignment.items()
        }
        unmatched_finding_ids = set(findings_by_id) - set(finding_assignment)
        matches: list[dict[str, Any]] = []
        missed: list[dict[str, Any]] = []
        for truth_index, truth in enumerate(spec.vulnerabilities):
            finding_id = truth_assignment.get(truth_index)
            if finding_id is None:
                missed.append(
                    {
                        "ground_truth_id": truth.id,
                        "title": truth.title,
                        "harm": truth.harm,
                        "minimum_proof": truth.minimum_proof,
                    }
                )
                continue
            finding = findings_by_id[finding_id]
            matches.append(
                {
                    "ground_truth_id": truth.id,
                    "ground_truth_title": truth.title,
                    "finding_id": finding.id,
                    "finding_title": finding.title,
                    "finding_status": finding.status,
                    "finding_severity": finding.severity,
                    "evidence_ids": list(finding.evidence_ids),
                }
            )
        false_positives = [
            {
                "finding_id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "status": finding.status,
                "severity": finding.severity,
                "source": finding.source,
                "entry_names": [
                    entry_names[value]
                    for value in finding.entry_point_ids
                    if value in entry_names
                ],
                "evidence_ids": list(finding.evidence_ids),
            }
            for finding in confirmed
            if finding.id in unmatched_finding_ids
        ]
        true_positives = len(matches)
        false_positive_count = len(false_positives)
        false_negatives = len(missed)
        precision = cls._ratio(
            true_positives,
            true_positives + false_positive_count,
        )
        recall = cls._ratio(true_positives, true_positives + false_negatives)
        f_half = (
            0.0
            if precision == 0.0 or recall == 0.0
            else (1.25 * precision * recall) / ((0.25 * precision) + recall)
        )
        return {
            "schema_version": "1.0",
            "score_policy": {
                "primary_metric": "f0.5",
                "reason": (
                    "Precision is weighted twice as strongly as recall so unsupported or "
                    "non-harmful claims are expensive."
                ),
                "confirmed_statuses": sorted(_PROOF_RANK),
                "candidate_or_inconclusive_counts_as_discovery": False,
                "manual_review_acceptance_counts_as_model_discovery": False,
            },
            "metrics": {
                "ground_truth_count": len(spec.vulnerabilities),
                "confirmed_finding_count": len(confirmed),
                "true_positives": true_positives,
                "false_positives": false_positive_count,
                "false_negatives": false_negatives,
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "f0_5": round(f_half, 6),
                "score_100": round(f_half * 100, 2),
                "unproven_ai_noise": len(ai_noise),
            },
            "matches": matches,
            "missed": missed,
            "false_positives": false_positives,
            "unproven_ai_noise": [
                {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "status": finding.status,
                    "severity": finding.severity,
                }
                for finding in ai_noise
            ],
        }

    @staticmethod
    def _confirmed(finding: Finding) -> bool:
        if finding.status == FindingStatus.SUPPORTED_STATIC.value:
            return True
        if finding.status == FindingStatus.REPRODUCED_BLACKBOX.value:
            return finding.metadata_json.get("harm_demonstrated") is True
        return False

    @staticmethod
    def _matches(
        truth: GroundTruthVulnerability,
        finding: Finding,
        entry_names: dict[str, str],
    ) -> bool:
        required_rank = _MINIMUM_PROOF_RANK[truth.minimum_proof]
        if _PROOF_RANK.get(finding.status, 0) < required_rank:
            return False
        if truth.minimum_proof == "dynamic" and not bool(
            finding.metadata_json.get("harm_demonstrated")
        ):
            return False
        selector = truth.match
        if selector.rule_ids and finding.rule_id not in selector.rule_ids:
            return False
        if selector.cwes and finding.cwe not in selector.cwes:
            return False
        actual_entries = {
            entry_names[value] for value in finding.entry_point_ids if value in entry_names
        }
        if selector.entry_names and not actual_entries.intersection(selector.entry_names):
            return False
        searchable = f"{finding.title}\n{finding.description}".lower()
        return not selector.title_contains or all(
            token.lower() in searchable for token in selector.title_contains
        )

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return 0.0 if denominator == 0 else numerator / denominator
