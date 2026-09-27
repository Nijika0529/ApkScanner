from __future__ import annotations

from pathlib import Path

import pytest
from apkscanner.core.db import Database
from apkscanner.core.models import (
    BenchmarkEvaluation,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.core.schemas import BenchmarkSpec
from apkscanner.runtime.benchmark import BenchmarkEvaluator
from pydantic import ValidationError
from sqlalchemy import select


def _platform_proof(
    session,
    *,
    scan: Scan,
    evidence_ids: list[str],
    fingerprint: str,
    claim: str,
) -> tuple[SecurityHypothesis, ProofAttempt]:  # noqa: ANN001
    task = InvestigationTask(scan=scan, task_type="component", status="completed")
    session.add(task)
    session.flush()
    hypothesis = SecurityHypothesis(
        scan_id=scan.id,
        task_id=task.id,
        fingerprint=fingerprint,
        category="android.exported_component",
        claim=claim,
    )
    session.add(hypothesis)
    session.flush()
    proof = ProofAttempt(
        scan_id=scan.id,
        task_id=task.id,
        hypothesis_id=hypothesis.id,
        test_case_id=f"benchmark-{fingerprint[:8]}",
        status="proven",
        oracle={"release_gate_eligible": True},
        evidence_ids=evidence_ids,
        harm_demonstrated=True,
    )
    session.add(proof)
    session.flush()
    return hypothesis, proof


def test_private_benchmark_rewards_proven_harm_and_penalizes_confirmed_noise(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="private.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "private.apk"),
            stats={"investigator": "opencode"},
        )
        vulnerable_entry = EntryPoint(
            scan=scan,
            kind="deep_link",
            name="demo://example.test/open",
            exported=True,
        )
        static_only_entry = EntryPoint(
            scan=scan,
            kind="provider",
            name="com.example.DataProvider",
            exported=True,
        )
        session.add_all([scan, vulnerable_entry, static_only_entry])
        session.flush()
        proof_one = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="1" * 64,
            path="proof-one.json",
        )
        proof_two = Evidence(
            scan_id=scan.id,
            kind="dynamic.log",
            sha256="2" * 64,
            path="proof-two.json",
        )
        session.add_all([proof_one, proof_two])
        session.flush()
        hypothesis, proof = _platform_proof(
            session,
            scan=scan,
            evidence_ids=[proof_one.id, proof_two.id],
            fingerprint="5" * 64,
            claim="The deep link triggers a protected action.",
        )
        session.add_all(
            [
                Finding(
                    scan=scan,
                    dedupe_key="agent:dynamic",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Agent investigation: deep link",
                    description="Unauthenticated route triggers the protected action.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    entry_point_ids=[vulnerable_entry.id],
                    evidence_ids=[proof_one.id, proof_two.id],
                    metadata_json={
                        "harm_demonstrated": True,
                        "release_gate_eligible": True,
                        "model": "deepseek-v4-pro",
                        "hypothesis_id": hypothesis.id,
                        "proof_attempt_ids": [proof.id],
                    },
                ),
                Finding(
                    scan=scan,
                    dedupe_key="agent:static",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Agent investigation: provider",
                    description="Provider looks exported but no harmful operation was demonstrated.",
                    masvs="MASVS-PLATFORM",
                    severity="medium",
                    status="supported_static",
                    entry_point_ids=[static_only_entry.id],
                    evidence_ids=["static-1"],
                ),
                Finding(
                    scan=scan,
                    dedupe_key="agent:noise",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Unproven AI theory",
                    description="No evidence.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="inconclusive",
                ),
                Finding(
                    scan=scan,
                    dedupe_key="agent:reachability-only",
                    rule_id="AGENT-ENTRY-INVESTIGATION",
                    source="opencode",
                    title="Reachable but no actual impact",
                    description="The route opened but no security harm was observed.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    status="reproduced_blackbox",
                    metadata_json={"harm_demonstrated": False},
                ),
            ]
        )
        session.commit()
        scan_id = scan.id

    spec = BenchmarkSpec.model_validate(
        {
            "schema_version": "1.0",
            "name": "private-truth",
            "apk_sha256": "a" * 64,
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Deep-link auth bypass",
                    "harm": "Guest triggers a protected action.",
                    "severity": "high",
                    "minimum_proof": "dynamic",
                    "match": {
                        "rule_ids": ["AGENT-ENTRY-INVESTIGATION"],
                        "entry_names": ["demo://example.test/open"],
                        "title_contains": ["unauthenticated"],
                    },
                },
                {
                    "id": "GT-2",
                    "title": "Provider data modification",
                    "harm": "An untrusted app modifies protected provider data.",
                    "severity": "high",
                    "minimum_proof": "dynamic",
                    "match": {
                        "rule_ids": ["AGENT-ENTRY-INVESTIGATION"],
                        "entry_names": ["com.example.DataProvider"],
                    },
                },
            ],
        }
    )
    evaluation = BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)
    metrics = evaluation.result["metrics"]
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 1
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.5
    assert metrics["score_100"] == 83.33
    assert metrics["unproven_ai_noise"] == 3
    assert evaluation.result["quality_gate"]["passed"] is False
    assert evaluation.result["matches"][0]["ground_truth_id"] == "GT-1"
    assert evaluation.result["missed"][0]["ground_truth_id"] == "GT-2"
    assert evaluation.investigator_backend == "opencode"
    assert evaluation.model == "deepseek-v4-pro"
    assert evaluation.result["model_attribution"]["source"] == "finding_metadata"

    with database.session_factory() as session:
        local_only = session.scalar(
            select(Finding).where(Finding.dedupe_key == "agent:dynamic")
        )
        assert local_only is not None
        local_only.metadata_json = {
            **local_only.metadata_json,
            "release_gate_eligible": False,
            "verdict_scope": "development_legacy",
        }
        session.commit()
    formal = BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)
    assert formal.result["metrics"]["true_positives"] == 0
    development = BenchmarkEvaluator(settings, database).evaluate(
        scan_id,
        spec.model_copy(update={"required_dynamic_scope": "any_dynamic"}),
    )
    assert development.result["metrics"]["true_positives"] == 1


def test_benchmark_uses_maximum_matching_instead_of_truth_file_order(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="ambiguous.apk",
            artifact_sha256="c" * 64,
            artifact_path=str(settings.data_dir / "ambiguous.apk"),
        )
        session.add(scan)
        session.flush()
        specific_evidence = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="3" * 64,
            path="specific.json",
        )
        generic_evidence = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="4" * 64,
            path="generic.json",
        )
        session.add_all([specific_evidence, generic_evidence])
        session.flush()
        specific_hypothesis, specific_proof = _platform_proof(
            session,
            scan=scan,
            evidence_ids=[specific_evidence.id],
            fingerprint="6" * 64,
            claim="A specific authorization bypass is reproducible.",
        )
        generic_hypothesis, generic_proof = _platform_proof(
            session,
            scan=scan,
            evidence_ids=[generic_evidence.id],
            fingerprint="7" * 64,
            claim="A generic impact is reproducible.",
        )
        specific = Finding(
            scan=scan,
            dedupe_key="specific",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="opencode",
            title="Generic issue with a specific authorization bypass",
            description="generic specific",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            evidence_ids=[specific_evidence.id],
            metadata_json={
                "harm_demonstrated": True,
                "release_gate_eligible": True,
                "hypothesis_id": specific_hypothesis.id,
                "proof_attempt_ids": [specific_proof.id],
            },
        )
        generic = Finding(
            scan=scan,
            dedupe_key="generic",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="opencode",
            title="Generic issue",
            description="generic",
            masvs="MASVS-PLATFORM",
            severity="medium",
            status="reproduced_blackbox",
            evidence_ids=[generic_evidence.id],
            metadata_json={
                "harm_demonstrated": True,
                "release_gate_eligible": True,
                "hypothesis_id": generic_hypothesis.id,
                "proof_attempt_ids": [generic_proof.id],
            },
        )
        session.add_all([specific, generic])
        session.commit()
        scan_id = scan.id

    spec = BenchmarkSpec.model_validate(
        {
            "name": "ambiguous-matching",
            "vulnerabilities": [
                {
                    "id": "GT-GENERIC",
                    "title": "Generic issue",
                    "harm": "Generic impact",
                    "severity": "medium",
                    "minimum_proof": "dynamic",
                    "match": {"title_contains": ["generic"]},
                },
                {
                    "id": "GT-SPECIFIC",
                    "title": "Specific bypass",
                    "harm": "Authorization bypass",
                    "severity": "high",
                    "minimum_proof": "dynamic",
                    "match": {"title_contains": ["specific"]},
                },
            ],
        }
    )
    evaluation = BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)
    assert evaluation.result["metrics"]["true_positives"] == 2
    assert evaluation.result["metrics"]["false_negatives"] == 0
    assert evaluation.result["quality_gate"]["passed"] is True
    assert {
        item["ground_truth_id"]: item["finding_id"]
        for item in evaluation.result["matches"]
    } == {
        "GT-GENERIC": generic.id,
        "GT-SPECIFIC": specific.id,
    }


def test_formal_dynamic_scope_requires_explicit_release_receipt() -> None:
    truth = BenchmarkSpec.model_validate(
        {
            "name": "formal-scope",
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Protected action",
                    "harm": "Unauthorized operation",
                    "severity": "high",
                    "match": {"rule_ids": ["RULE"]},
                }
            ],
        }
    ).vulnerabilities[0]
    finding = Finding(
        scan_id="scan",
        dedupe_key="dynamic",
        rule_id="RULE",
        source="opencode",
        title="Protected action",
        description="Unauthorized operation",
        masvs="MASVS-PLATFORM",
        severity="high",
        status="reproduced_blackbox",
        metadata_json={"harm_demonstrated": True},
    )
    assert BenchmarkEvaluator._matches(truth, finding, {}) is False
    assert BenchmarkEvaluator._matches(
        truth, finding, {}, required_dynamic_scope="any_dynamic"
    ) is True
    finding.metadata_json = {"harm_demonstrated": True, "release_gate_eligible": True}
    assert BenchmarkEvaluator._matches(truth, finding, {}) is True
    attempt = ProofAttempt(
        scan_id="scan",
        task_id="task",
        hypothesis_id="hypothesis",
        test_case_id="test",
        status="proven",
        harm_demonstrated=True,
        oracle={"release_gate_eligible": False},
    )
    assert BenchmarkEvaluator._matches(truth, finding, {}, proof_attempts=[attempt]) is False
    attempt.oracle = {"release_gate_eligible": True}
    assert BenchmarkEvaluator._matches(truth, finding, {}, proof_attempts=[attempt]) is True


def test_benchmark_oracle_selector_distinguishes_impacts_at_the_same_entry() -> None:
    truth = BenchmarkSpec.model_validate(
        {
            "name": "impact-selector",
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Credential disclosure",
                    "harm": "Provider returns private credential rows.",
                    "severity": "high",
                    "match": {
                        "entry_names": ["com.example.Provider"],
                        "oracle_kinds": ["provider_rows"],
                        "oracle_impacts": ["unauthorized_data_access"],
                        "observed_fact_types": ["provider_rows_returned"],
                    },
                }
            ],
        }
    ).vulnerabilities[0]
    finding = Finding(
        scan_id="scan",
        dedupe_key="same-entry",
        rule_id="RULE",
        source="opencode",
        title="Different harm at provider",
        description="A mutation changed an unrelated state.",
        masvs="MASVS-PLATFORM",
        severity="high",
        status="reproduced_blackbox",
        entry_point_ids=["entry"],
        metadata_json={"harm_demonstrated": True, "release_gate_eligible": True},
    )
    receipt = {
        "release_gate_eligible": True,
        "security_impact_observed": True,
        "observed_facts": [{"fact_type": "provider_rows_returned", "matched": True}],
    }
    attempt = ProofAttempt(
        scan_id="scan",
        task_id="task",
        hypothesis_id="hypothesis",
        test_case_id="test",
        status="proven",
        harm_demonstrated=True,
        plan={"oracle": {"kind": "provider_rows", "impact": "unauthorized_state_change"}},
        oracle=receipt,
    )
    entries = {"entry": "com.example.Provider"}
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[attempt]
    ) is False
    attempt.plan = {"oracle": {"kind": "provider_rows", "impact": "unauthorized_data_access"}}
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[attempt]
    ) is True
    attempt.oracle = {**receipt, "observed_facts": []}
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[attempt]
    ) is False
    attempt.oracle = {**receipt, "release_gate_eligible": False}
    release_attempt = ProofAttempt(
        scan_id="scan",
        task_id="task",
        hypothesis_id="hypothesis",
        test_case_id="release-only",
        status="proven",
        harm_demonstrated=True,
        plan={"oracle": {"kind": "ui_text", "impact": "privileged_action"}},
        oracle={"release_gate_eligible": True, "security_impact_observed": True},
    )
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[attempt, release_attempt]
    ) is False


def test_bridge_ground_truth_requires_matching_platform_semantic_method_and_impact() -> None:
    fixture = Path(__file__).resolve().parents[2] / "testapk/adaptivecases-ground-truth.json"
    spec = BenchmarkSpec.model_validate_json(fixture.read_text(encoding="utf-8"))
    truth = next(item for item in spec.vulnerabilities if item.id == "AC-005")
    entries = {"bridge-entry": "io.apkscanner.adaptivecases.BridgeActivity"}
    finding = Finding(
        scan_id="scan",
        dedupe_key="bridge-description",
        rule_id="AGENT-ENTRY-INVESTIGATION",
        source="opencode",
        title="AccountBridge was reached",
        description="AccountBridge.getSessionToken may leak data; transfer state also changed.",
        masvs="MASVS-PLATFORM",
        severity="critical",
        status="reproduced_blackbox",
        entry_point_ids=["bridge-entry"],
        metadata_json={"harm_demonstrated": True, "release_gate_eligible": True},
    )
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[]
    ) is False
    ui_attempt = ProofAttempt(
        scan_id="scan",
        task_id="task",
        hypothesis_id="hypothesis",
        test_case_id="ui-state-change",
        status="proven",
        harm_demonstrated=True,
        plan={
            "oracle": {"kind": "ui_text", "impact": "unauthorized_state_change"},
            "bridge_method": "AccountBridge.getSessionToken",
        },
        oracle={
            "release_gate_eligible": True,
            "security_impact_observed": True,
        },
    )
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[ui_attempt]
    ) is False

    semantic = ProofAttempt(
        scan_id="scan",
        task_id="task",
        hypothesis_id="hypothesis",
        test_case_id="semantic:web-exp-12345678",
        prover="platform_semantic_attestation",
        status="proven",
        harm_demonstrated=True,
        plan={
            "experiment_id": "web-exp-12345678",
            "impact": "unauthorized_data_access",
            "bridge_method": "AccountBridge.getSessionToken",
        },
        oracle={
            "policy": "independent_semantic_judge_and_platform_gate",
            "experiment_id": "web-exp-12345678",
            "attestation_evidence_id": "attestation-id",
            "security_impact_observed": True,
            "harm_demonstrated": True,
            "release_gate_eligible": True,
        },
        evidence_ids=["attestation-id"],
    )
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[semantic]
    ) is True
    semantic.plan = {**semantic.plan, "bridge_method": "AccountBridge.setTransferEnabled"}
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[semantic]
    ) is False
    semantic.plan = {**semantic.plan, "bridge_method": "AccountBridge.getSessionToken"}
    semantic.prover = "agent_claim"
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[semantic]
    ) is False
    semantic.prover = "platform_semantic_attestation"
    semantic.oracle = {**semantic.oracle, "release_gate_eligible": False}
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[semantic]
    ) is False
    semantic.oracle = {**semantic.oracle, "release_gate_eligible": True}
    semantic.harm_demonstrated = False
    assert BenchmarkEvaluator._matches(
        truth, finding, entries, proof_attempts=[semantic]
    ) is False


def test_negative_control_violations_are_false_positives_even_with_broad_positive_selector(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="controls.apk",
            artifact_sha256="f" * 64,
            artifact_path=str(settings.data_dir / "controls.apk"),
        )
        session.add(scan)
        session.flush()
        evidence = Evidence(
            scan_id=scan.id,
            kind="dynamic.oracle",
            sha256="5" * 64,
            path="control.json",
        )
        session.add(evidence)
        session.flush()
        hypothesis, proof = _platform_proof(
            session,
            scan=scan,
            evidence_ids=[evidence.id],
            fingerprint="8" * 64,
            claim="Safe route appears unsafe.",
        )
        finding = Finding(
            scan=scan,
            dedupe_key="safe-route",
            rule_id="RULE",
            source="opencode",
            title="Safe route appears unsafe",
            description="No protected action occurred.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            evidence_ids=[evidence.id],
            metadata_json={
                "harm_demonstrated": True,
                "release_gate_eligible": True,
                "hypothesis_id": hypothesis.id,
                "proof_attempt_ids": [proof.id],
            },
        )
        session.add(finding)
        session.commit()
        scan_id = scan.id
    spec = BenchmarkSpec.model_validate(
        {
            "name": "safe-control",
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Protected action",
                    "harm": "Unauthorized operation",
                    "severity": "high",
                    "match": {"rule_ids": ["RULE"]},
                }
            ],
            "negative_controls": [
                {
                    "id": "SAFE-1",
                    "title": "Safe route",
                    "match": {"title_contains": ["Safe route"]},
                }
            ],
            "quality_gate": {"maximum_false_positives": 1},
        }
    )
    result = BenchmarkEvaluator(settings, database).evaluate(scan_id, spec).result
    assert result["metrics"]["true_positives"] == 0
    assert result["metrics"]["false_positives"] == 1
    assert result["metrics"]["negative_control_violations"] == 1
    assert result["quality_gate"]["passed"] is False
    assert result["negative_control_violations"][0]["negative_control_id"] == "SAFE-1"


def test_ground_truth_requires_selectors_and_unique_ids() -> None:
    base = {
        "id": "GT-1",
        "title": "Issue",
        "harm": "Impact",
        "severity": "high",
        "minimum_proof": "dynamic",
        "match": {},
    }
    with pytest.raises(ValidationError, match="matching selector"):
        BenchmarkSpec.model_validate(
            {"name": "invalid-selector", "vulnerabilities": [base]}
        )
    with pytest.raises(ValidationError, match="must be unique"):
        BenchmarkSpec.model_validate(
            {
                "name": "duplicate-ids",
                "vulnerabilities": [
                    {**base, "match": {"rule_ids": ["RULE"]}},
                    {**base, "match": {"cwes": ["CWE-200"]}},
                ],
            }
        )
    with pytest.raises(ValidationError, match="must be unique"):
        BenchmarkSpec.model_validate(
            {
                "name": "duplicate-control-id",
                "vulnerabilities": [{**base, "match": {"rule_ids": ["RULE"]}}],
                "negative_controls": [
                    {"id": "GT-1", "title": "Safe route", "match": {"rule_ids": ["SAFE"]}}
                ],
            }
        )


def test_benchmark_rejects_nonfinal_scan(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="running.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "running.apk"),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    spec = BenchmarkSpec.model_validate(
        {
            "name": "too-early",
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Issue",
                    "harm": "Impact",
                    "severity": "high",
                    "match": {"rule_ids": ["RULE"]},
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="completed final scan"):
        BenchmarkEvaluator(settings, database).evaluate(scan_id, spec)


@pytest.mark.parametrize(
    ("stats", "task_status", "error"),
    [
        ({"execution_control": {"state": "stopping"}}, None, "uninterrupted scan"),
        ({"execution_control": {"state": "stopped"}}, None, "uninterrupted scan"),
        (
            {"runtime_integrity": {"status": "invalid", "reason": "device_framework_unavailable"}},
            None,
            "valid runtime integrity",
        ),
        ({}, "canceled", "no canceled investigation tasks"),
        ({}, "cancel_requested", "no canceled investigation tasks"),
    ],
)
def test_benchmark_rejects_interrupted_or_invalid_scan_without_persisting_evaluation(
    settings, stats, task_status, error
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="interrupted.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "interrupted.apk"),
            stats=stats,
        )
        session.add(scan)
        session.flush()
        if task_status is not None:
            session.add(
                InvestigationTask(scan=scan, task_type="component", status=task_status)
            )
        session.commit()
        scan_id = scan.id
    spec = BenchmarkSpec.model_validate(
        {
            "name": "interrupted-scan",
            "apk_sha256": "d" * 64,
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Issue",
                    "harm": "Impact",
                    "severity": "high",
                    "match": {"rule_ids": ["RULE"]},
                }
            ],
        }
    )
    evaluator = BenchmarkEvaluator(settings, database)
    with pytest.raises(ValueError, match=error):
        evaluator.evaluate(scan_id, spec)
    with pytest.raises(ValueError, match=error):
        evaluator.simulate(scan_id, spec, detected_ids={"GT-1"})
    with database.session_factory() as session:
        assert session.scalar(
            select(BenchmarkEvaluation.id).where(BenchmarkEvaluation.scan_id == scan_id)
        ) is None


def test_synthetic_recall_scenario_is_deterministic_and_creates_no_findings(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="rehearsal.apk",
            artifact_sha256="e" * 64,
            artifact_path=str(settings.data_dir / "rehearsal.apk"),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    spec = BenchmarkSpec.model_validate(
        {
            "name": "report-rehearsal",
            "apk_sha256": "e" * 64,
            "vulnerabilities": [
                {
                    "id": f"GT-{index}",
                    "title": f"Known issue {index}",
                    "harm": f"Known impact {index}",
                    "severity": "high",
                    "match": {"rule_ids": [f"RULE-{index}"]},
                }
                for index in range(1, 6)
            ],
        }
    )
    evaluator = BenchmarkEvaluator(settings, database)
    first = evaluator.simulate(
        scan_id,
        spec,
        target_recall=0.6,
        seed="stable-report",
    )
    second = evaluator.simulate(
        scan_id,
        spec,
        target_recall=0.6,
        seed="stable-report",
    )

    assert first.result["data_provenance"] == {
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
    }
    assert first.result["metrics"]["true_positives"] == 3
    assert first.result["metrics"]["false_negatives"] == 2
    assert first.result["metrics"]["recall"] == 0.6
    assert first.result["simulation"]["detected_ground_truth_ids"] == second.result[
        "simulation"
    ]["detected_ground_truth_ids"]
    assert all(item["finding_id"] is None for item in first.result["matches"])
    assert all(not item["evidence_ids"] for item in first.result["matches"])
    assert first.investigator_backend == "synthetic_demo"
    assert first.model is None

    with database.session_factory() as session:
        assert list(session.query(Finding)) == []
        assert list(session.query(Evidence)) == []
        assert len(list(session.query(BenchmarkEvaluation))) == 2


def test_synthetic_recall_scenario_supports_explicit_omissions_and_rejects_unknown_ids(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="explicit.apk",
            artifact_sha256="f" * 64,
            artifact_path=str(settings.data_dir / "explicit.apk"),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    spec = BenchmarkSpec.model_validate(
        {
            "name": "explicit-omission",
            "vulnerabilities": [
                {
                    "id": "GT-1",
                    "title": "Detected issue",
                    "harm": "Detected impact",
                    "severity": "high",
                    "match": {"rule_ids": ["RULE-1"]},
                },
                {
                    "id": "GT-2",
                    "title": "Missed issue",
                    "harm": "Missed impact",
                    "severity": "medium",
                    "match": {"rule_ids": ["RULE-2"]},
                },
            ],
        }
    )
    evaluator = BenchmarkEvaluator(settings, database)
    evaluation = evaluator.simulate(scan_id, spec, omitted_ids={"GT-2"})
    assert evaluation.result["simulation"]["detected_ground_truth_ids"] == ["GT-1"]
    assert evaluation.result["simulation"]["omitted_ground_truth_ids"] == ["GT-2"]
    assert evaluation.result["metrics"]["recall"] == 0.5

    with pytest.raises(ValueError, match="unknown ground-truth"):
        evaluator.simulate(scan_id, spec, omitted_ids={"GT-404"})
    with pytest.raises(ValueError, match="between 0 and 1"):
        evaluator.simulate(scan_id, spec, target_recall=1.1)
