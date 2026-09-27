from __future__ import annotations

import hashlib
import math
from typing import Any

from sqlalchemy import select

from ..core.config import Settings
from ..core.db import Database
from ..core.enums import FindingStatus, ScanStatus, TaskStatus
from ..core.finding_policy import partition_findings
from ..core.models import (
    BenchmarkEvaluation,
    EntryPoint,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
)
from ..core.proof_receipts import attributable_harm_attempts_by_finding
from ..core.schemas import BenchmarkSpec, GroundTruthMatch, GroundTruthVulnerability

_PROOF_RANK = {
    FindingStatus.SUPPORTED_STATIC.value: 1,
    FindingStatus.REPRODUCED_BLACKBOX.value: 2,
    FindingStatus.ACCEPTED.value: 2,
}
_MINIMUM_PROOF_RANK = {"static": 1, "dynamic": 2}


class BenchmarkEvaluator:
    """Scores only platform-confirmed findings against an explicit private ground truth."""

    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database

    def evaluate(self, scan_id: str, spec: BenchmarkSpec) -> BenchmarkEvaluation:
        with self.database.session_factory() as session:
            scan = self._require_compatible_scan(session, scan_id, spec)
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
            confirmed, signals = partition_findings(session, findings)
            proof_attempts = attributable_harm_attempts_by_finding(session, confirmed)
            result = self._score(spec, confirmed, entries, signals, proof_attempts)
            control = scan.stats.get("agent_control")
            if not isinstance(control, dict):
                control = {}
            attributed_findings = [
                finding
                for finding in confirmed
                if finding.source in {"codex", "opencode"}
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
                else self.settings.codex_model
                if backend == "codex"
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

    def simulate(
        self,
        scan_id: str,
        spec: BenchmarkSpec,
        *,
        detected_ids: set[str] | None = None,
        omitted_ids: set[str] | None = None,
        target_recall: float | None = None,
        seed: str = "apkscanner-demo-v1",
    ) -> BenchmarkEvaluation:
        """Persist an explicitly synthetic recall scenario without fabricating findings.

        The resulting row is intentionally incompatible with real evidence attribution:
        it has no Finding IDs, no Evidence IDs, no model identity, and carries a
        machine-readable synthetic provenance marker.
        """

        configured_modes = sum(
            value is not None for value in (detected_ids, omitted_ids, target_recall)
        )
        if configured_modes != 1:
            raise ValueError(
                "choose exactly one simulation selector: detected IDs, omitted IDs, "
                "or target recall"
            )
        if not seed:
            raise ValueError("simulation seed must not be empty")

        truth_ids = {item.id for item in spec.vulnerabilities}
        if detected_ids is not None:
            self._reject_unknown_truth_ids(detected_ids, truth_ids)
            selected_ids = set(detected_ids)
            selection_mode = "explicit_detected_ids"
        elif omitted_ids is not None:
            self._reject_unknown_truth_ids(omitted_ids, truth_ids)
            selected_ids = truth_ids - omitted_ids
            selection_mode = "explicit_omitted_ids"
        else:
            assert target_recall is not None
            if not 0.0 <= target_recall <= 1.0:
                raise ValueError("target recall must be between 0 and 1")
            target_count = min(
                len(spec.vulnerabilities),
                math.floor(len(spec.vulnerabilities) * target_recall + 0.5),
            )
            ranked = sorted(
                spec.vulnerabilities,
                key=lambda item: (
                    hashlib.sha256(f"{seed}\0{item.id}".encode()).hexdigest(),
                    item.id,
                ),
            )
            selected_ids = {item.id for item in ranked[:target_count]}
            selection_mode = "seeded_target_recall"

        with self.database.session_factory() as session:
            scan = self._require_compatible_scan(session, scan_id, spec)
            matches = []
            missed = []
            for truth in spec.vulnerabilities:
                if truth.id in selected_ids:
                    matches.append(
                        {
                            "ground_truth_id": truth.id,
                            "ground_truth_title": truth.title,
                            "finding_id": None,
                            "finding_title": f"[仿真命中] {truth.title}",
                            "finding_status": "synthetic_demo",
                            "finding_severity": truth.severity,
                            "evidence_ids": [],
                            "minimum_proof": truth.minimum_proof,
                        }
                    )
                else:
                    missed.append(
                        {
                            "ground_truth_id": truth.id,
                            "title": truth.title,
                            "harm": truth.harm,
                            "minimum_proof": truth.minimum_proof,
                        }
                    )

            true_positives = len(matches)
            false_negatives = len(missed)
            recall = self._ratio(true_positives, true_positives + false_negatives)
            precision = 1.0 if true_positives else 0.0
            f_half = (
                0.0
                if precision == 0.0 or recall == 0.0
                else (1.25 * precision * recall) / ((0.25 * precision) + recall)
            )
            omitted = sorted(truth_ids - selected_ids)
            result = {
                "schema_version": "1.0",
                "data_provenance": {
                    "kind": "synthetic_demo",
                    "assessment_scope": "android_apk_security",
                    "phone_verified": False,
                    "target_apk_executed": False,
                    "creates_findings": False,
                    "creates_evidence": False,
                    "disclaimer": (
                        "Synthetic recall scenario for presentation rehearsal only; "
                        "it is not scanner output or phone-verified evidence."
                    ),
                },
                "simulation": {
                    "selection_mode": selection_mode,
                    "seed": seed,
                    "requested_target_recall": target_recall,
                    "detected_ground_truth_ids": sorted(selected_ids),
                    "omitted_ground_truth_ids": omitted,
                },
                "score_policy": {
                    "primary_metric": "f0.5",
                    "simulation_only": True,
                    "false_positives_simulated": False,
                    "candidate_or_inconclusive_counts_as_discovery": False,
                },
                "metrics": {
                    "ground_truth_count": len(spec.vulnerabilities),
                    "confirmed_finding_count": 0,
                    "true_positives": true_positives,
                    "false_positives": 0,
                    "false_negatives": false_negatives,
                    "precision": round(precision, 6),
                    "recall": round(recall, 6),
                    "f0_5": round(f_half, 6),
                    "score_100": round(f_half * 100, 2),
                    "unproven_ai_noise": 0,
                },
                "matches": matches,
                "missed": missed,
                "false_positives": [],
                "unproven_ai_noise": [],
                "model_attribution": {
                    "backend": "synthetic_demo",
                    "backends": [],
                    "models": [],
                    "source": "simulation_config",
                },
            }
            evaluation = BenchmarkEvaluation(
                scan_id=scan_id,
                name=f"{spec.name}（仿真）",
                artifact_sha256=scan.artifact_sha256,
                investigator_backend="synthetic_demo",
                model=None,
                ground_truth=spec.model_dump(mode="json"),
                result=result,
            )
            session.add(evaluation)
            session.commit()
            return evaluation

    @staticmethod
    def _require_compatible_scan(session, scan_id: str, spec: BenchmarkSpec) -> Scan:  # noqa: ANN001
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError("scan not found")
        if scan.status != ScanStatus.FINAL.value:
            raise ValueError("benchmark evaluation requires a completed final scan")
        stats = scan.stats if isinstance(scan.stats, dict) else {}
        execution_control = stats.get("execution_control")
        if (
            isinstance(execution_control, dict)
            and execution_control.get("state") in {"stopping", "stopped"}
        ):
            raise ValueError("benchmark evaluation requires an uninterrupted scan")
        runtime_integrity = stats.get("runtime_integrity")
        if (
            isinstance(runtime_integrity, dict)
            and runtime_integrity.get("status") == "invalid"
        ):
            raise ValueError("benchmark evaluation requires valid runtime integrity")
        canceled_task_id = session.scalar(
            select(InvestigationTask.id)
            .where(
                InvestigationTask.scan_id == scan_id,
                InvestigationTask.status.in_(
                    {TaskStatus.CANCEL_REQUESTED.value, TaskStatus.CANCELED.value}
                ),
            )
            .limit(1)
        )
        if canceled_task_id is not None:
            raise ValueError("benchmark evaluation requires no canceled investigation tasks")
        if spec.apk_sha256 and spec.apk_sha256 != scan.artifact_sha256:
            raise ValueError("ground truth APK SHA-256 does not match the selected scan")
        return scan

    @staticmethod
    def _reject_unknown_truth_ids(values: set[str], truth_ids: set[str]) -> None:
        unknown = sorted(values - truth_ids)
        if unknown:
            raise ValueError(f"unknown ground-truth vulnerability IDs: {', '.join(unknown)}")

    @classmethod
    def _score(
        cls,
        spec: BenchmarkSpec,
        findings: list[Finding],
        entries: list[EntryPoint],
        signals: list[Finding],
        proof_attempts: dict[str, list[ProofAttempt]],
    ) -> dict[str, Any]:
        entry_names = {entry.id: entry.name for entry in entries}
        confirmed = findings
        # A ground truth that only requires ``static`` proof must be satisfiable by
        # a platform-supported static finding, which ``partition_findings`` places
        # in ``signals``.  Without this pool such a truth was always a false
        # negative even when the matching static finding existed.
        static_candidates = [
            finding
            for finding in signals
            if finding.status == FindingStatus.SUPPORTED_STATIC.value
        ]
        ai_noise = [
            finding
            for finding in signals
            if finding.source in {"codex", "opencode"}
        ]
        findings_by_id = {
            finding.id: finding for finding in [*confirmed, *static_candidates]
        }
        negative_control_violations = [
            {
                "negative_control_id": control.id,
                "negative_control_title": control.title,
                "finding_id": finding.id,
                "finding_title": finding.title,
                "evidence_ids": list(finding.evidence_ids or []),
            }
            for control in spec.negative_controls
            for finding in confirmed
            if cls._selector_matches(
                control.match, finding, entry_names, proof_attempts.get(finding.id, [])
            )
        ]
        negative_finding_ids = {
            violation["finding_id"] for violation in negative_control_violations
        }
        candidate_ids_by_truth: list[list[str]] = []
        for truth in spec.vulnerabilities:
            pool = (
                [*confirmed, *static_candidates]
                if truth.minimum_proof == "static"
                else confirmed
            )
            candidates = [
                finding
                for finding in pool
                if finding.id not in negative_finding_ids
                if cls._matches(
                    truth,
                    finding,
                    entry_names,
                    required_dynamic_scope=spec.required_dynamic_scope,
                    proof_attempts=proof_attempts.get(finding.id, []),
                )
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
        unmatched_finding_ids = {
            finding.id for finding in confirmed
        } - set(finding_assignment)
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
        quality_gate = {
            "passed": bool(
                precision >= spec.quality_gate.minimum_precision
                and recall >= spec.quality_gate.minimum_recall
                and false_positive_count <= spec.quality_gate.maximum_false_positives
                and not negative_control_violations
            ),
            "minimum_precision": spec.quality_gate.minimum_precision,
            "minimum_recall": spec.quality_gate.minimum_recall,
            "maximum_false_positives": spec.quality_gate.maximum_false_positives,
            "observed_precision": round(precision, 6),
            "observed_recall": round(recall, 6),
            "observed_false_positives": false_positive_count,
            "observed_negative_control_violations": len(negative_control_violations),
        }
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
                "negative_control_count": len(spec.negative_controls),
                "negative_control_violations": len(negative_control_violations),
            },
            "quality_gate": quality_gate,
            "matches": matches,
            "missed": missed,
            "false_positives": false_positives,
            "negative_control_violations": negative_control_violations,
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
    def _matches(
        truth: GroundTruthVulnerability,
        finding: Finding,
        entry_names: dict[str, str],
        *,
        required_dynamic_scope: str = "android16_release",
        proof_attempts: list[ProofAttempt] | None = None,
    ) -> bool:
        required_rank = _MINIMUM_PROOF_RANK[truth.minimum_proof]
        if _PROOF_RANK.get(finding.status, 0) < required_rank:
            return False
        if truth.minimum_proof == "dynamic" and not bool(
            finding.metadata_json.get("harm_demonstrated")
        ):
            return False
        if (
            truth.minimum_proof == "dynamic"
            and required_dynamic_scope == "android16_release"
            and finding.metadata_json.get("release_gate_eligible") is not True
        ):
            return False
        eligible_attempts = proof_attempts or []
        if truth.minimum_proof == "dynamic" and required_dynamic_scope == "android16_release":
            eligible_attempts = [
                attempt for attempt in eligible_attempts
                if (attempt.oracle or {}).get("release_gate_eligible") is True
            ]
            if proof_attempts is not None and not eligible_attempts:
                return False
        return BenchmarkEvaluator._selector_matches(
            truth.match, finding, entry_names, eligible_attempts
        )

    @staticmethod
    def _selector_matches(
        selector: GroundTruthMatch,
        finding: Finding,
        entry_names: dict[str, str],
        proof_attempts: list[ProofAttempt] | None = None,
    ) -> bool:
        if selector.rule_ids and finding.rule_id not in selector.rule_ids:
            return False
        if selector.cwes and finding.cwe not in selector.cwes:
            return False
        actual_entries = {
            entry_names[value]
            for value in (finding.entry_point_ids or [])
            if value in entry_names
        }
        if selector.entry_names and not actual_entries.intersection(selector.entry_names):
            return False
        searchable = f"{finding.title}\n{finding.description}".lower()
        if selector.title_contains and not all(
            token.lower() in searchable for token in selector.title_contains
        ):
            return False
        if not any((
            selector.oracle_kinds,
            selector.oracle_impacts,
            selector.bridge_methods,
            selector.observed_fact_types,
        )):
            return True
        for attempt in proof_attempts or []:
            if attempt.status != "proven" or attempt.harm_demonstrated is not True:
                continue
            receipt = attempt.oracle if isinstance(attempt.oracle, dict) else {}
            if receipt.get("security_impact_observed") is not True:
                continue
            plan = attempt.plan if isinstance(attempt.plan, dict) else {}
            if attempt.prover == "platform_semantic_attestation":
                attestation_id = receipt.get("attestation_evidence_id")
                if (
                    receipt.get("policy") != "independent_semantic_judge_and_platform_gate"
                    or receipt.get("release_gate_eligible") is not True
                    or receipt.get("harm_demonstrated") is not True
                    or not isinstance(attestation_id, str)
                    or attestation_id not in (attempt.evidence_ids or [])
                    or not isinstance(plan.get("experiment_id"), str)
                    or plan["experiment_id"] != receipt.get("experiment_id")
                ):
                    continue
                oracle_kind = None
                oracle_impact = plan.get("impact")
                bridge_method = plan.get("bridge_method")
            else:
                plan_oracle = plan.get("oracle")
                if not isinstance(plan_oracle, dict):
                    continue
                oracle_kind = plan_oracle.get("kind")
                oracle_impact = plan_oracle.get("impact")
                bridge_method = None
            if selector.oracle_kinds and oracle_kind not in selector.oracle_kinds:
                continue
            if selector.oracle_impacts and oracle_impact not in selector.oracle_impacts:
                continue
            if selector.bridge_methods and bridge_method not in selector.bridge_methods:
                continue
            facts = receipt.get("observed_facts")
            matched_fact_types = {
                fact.get("fact_type")
                for fact in facts if isinstance(fact, dict) and fact.get("matched") is True
            } if isinstance(facts, list) else set()
            if selector.observed_fact_types and not matched_fact_types.intersection(
                selector.observed_fact_types
            ):
                continue
            return True
        return False

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return 0.0 if denominator == 0 else numerator / denominator
