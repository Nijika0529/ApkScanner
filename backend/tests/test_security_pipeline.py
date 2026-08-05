from __future__ import annotations

import pytest
from apkscanner.db import Database
from apkscanner.models import (
    EntryPoint,
    Finding,
    HypothesisArgument,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.schemas import AgentRequestedTest
from apkscanner.security_pipeline import HypothesisLedger
from sqlalchemy import select


def test_hypothesis_ledger_tracks_arguments_and_concrete_proof(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="ledger.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(settings.data_dir / "ledger.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="deep_link",
            target_entry_ids=["00000000-0000-0000-0000-000000000001"],
            hypotheses=["Guest deep link may bypass route authorization."],
        )
        session.add_all([scan, task])
        session.commit()
        task_id = task.id

    ledger = HypothesisLedger(database)
    hypotheses = ledger.ensure_task_hypotheses(task)
    assert len(hypotheses) == 1
    hypothesis_id = hypotheses[0].id
    ledger.record_argument(
        task_id=task_id,
        role="hunter",
        phase="test_planning",
        backend="opencode",
        model="deepseek-v4-pro",
        payload={"summary": "Candidate route bypass.", "evidence_ids": ["static-1"]},
    )
    ledger.record_argument(
        task_id=task_id,
        role="critic",
        phase="adversarial_review",
        backend="opencode",
        model="deepseek-v4-pro",
        payload={"summary": "Authentication guard may stop it.", "evidence_ids": []},
    )
    request = AgentRequestedTest(
        hypothesis_id=hypothesis_id,
        entry_point_id="00000000-0000-0000-0000-000000000001",
        state="guest",
        uri="demo://example.test/open",
        extras={},
        rationale="Resolve the critic's authentication objection.",
    )
    proof_id = ledger.plan_proof(
        task_id=task_id,
        test_case_id="agent-1",
        request=request,
    )
    assert proof_id is not None
    ledger.start_proof(proof_id)
    ledger.complete_proof(
        proof_id,
        [
            {
                "id": "probe-1",
                "kind": "blackbox.probe_app",
                "exit_code": 0,
                "metadata": {"request_id": "request-1"},
            },
            {
                "id": "log-1",
                "kind": "blackbox.logcat",
                "exit_code": 0,
                "metadata": {
                    "request_id": "request-1",
                    "request_observed": True,
                    "probe_success": True,
                    "security_impact_observed": True,
                },
            },
        ],
    )
    # A delayed duplicate completion cannot overwrite the first terminal receipt.
    ledger.complete_proof(proof_id, [])
    with database.session_factory() as session:
        completed_once = session.get(ProofAttempt, proof_id)
        assert completed_once is not None
        assert completed_once.status == "proven"
        assert completed_once.harm_demonstrated is True
    reachability_only_id = ledger.plan_proof(
        task_id=task_id,
        test_case_id="agent-2",
        request=request,
    )
    ledger.start_proof(reachability_only_id)
    ledger.complete_proof(
        reachability_only_id,
        [
            {
                "id": "probe-2",
                "kind": "blackbox.probe_app",
                "exit_code": 0,
                "metadata": {"request_id": "request-2"},
            },
            {
                "id": "log-2",
                "kind": "blackbox.logcat",
                "exit_code": 0,
                "metadata": {
                    "request_id": "request-2",
                    "request_observed": True,
                    "probe_success": True,
                },
            },
        ],
    )
    ui_proof_id = ledger.plan_proof(
        task_id=task_id,
        test_case_id="agent-ui",
        request=request,
    )
    ledger.start_proof(ui_proof_id)
    ledger.complete_proof(
        ui_proof_id,
        [
            {
                "id": "poc-launch-ui",
                "kind": "blackbox.poc_launch",
                "exit_code": 0,
                "metadata": {"request_id": "request-ui"},
            },
            {
                "id": "poc-ui",
                "kind": "blackbox.poc_ui_dump",
                "exit_code": 0,
                "metadata": {
                    "request_id": "request-ui",
                    "security_impact_observed": True,
                    "oracle": {
                        "matched": True,
                        "observation": {"target_text_transition": True},
                    },
                },
            },
        ],
    )
    with database.session_factory() as session:
        hypothesis = session.get(SecurityHypothesis, hypothesis_id)
        proof = session.get(ProofAttempt, proof_id)
        reachability_only = session.get(ProofAttempt, reachability_only_id)
        ui_proof = session.get(ProofAttempt, ui_proof_id)
        assert hypothesis is not None
        assert proof is not None
        assert reachability_only is not None
        assert hypothesis.status == "proven"
        assert proof.status == "proven"
        assert proof.harm_demonstrated is True
        assert proof.evidence_ids == ["probe-1", "log-1"]
        assert reachability_only.status == "inconclusive"
        assert reachability_only.harm_demonstrated is False
        assert reachability_only.oracle["execution_demonstrated"] is True
        assert ui_proof is not None
        assert ui_proof.status == "proven"
        assert ui_proof.harm_demonstrated is True
        assert ui_proof.oracle["poc_succeeded"] is False
        assert ui_proof.oracle["platform_observed_poc_effect"] is True
        arguments = list(
            session.scalars(
                select(HypothesisArgument).where(
                    HypothesisArgument.hypothesis_id == hypothesis_id
                )
            )
        )
        assert [argument.role for argument in arguments] == ["hunter", "critic"]


def test_critic_and_arbiter_cannot_downgrade_platform_proven_hypothesis(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    entry_id = "00000000-0000-0000-0000-000000000081"
    with database.session_factory() as session:
        scan = Scan(
            filename="immutable-proof.apk",
            artifact_sha256="8" * 64,
            artifact_path=str(settings.data_dir / "immutable-proof.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="deep_link",
            target_entry_ids=[entry_id],
            hypotheses=["A deep link executes attacker-controlled WebView JavaScript."],
        )
        session.add_all([scan, task])
        session.commit()
        scan_id = scan.id

    ledger = HypothesisLedger(database)
    hypothesis = ledger.ensure_task_hypotheses(task)[0]
    request = AgentRequestedTest(
        hypothesis_id=hypothesis.id,
        entry_point_id=entry_id,
        state="guest",
        uri="demo://example.test/web",
        extras={},
        rationale="Reproduce JavaScript execution from an ordinary app.",
    )
    proof_id = ledger.plan_proof(
        task_id=task.id,
        test_case_id="webview-proof",
        request=request,
    )
    assert proof_id is not None
    ledger.start_proof(proof_id)
    ledger.complete_proof(
        proof_id,
        [
            {
                "id": "probe-webview",
                "kind": "blackbox.probe_app",
                "exit_code": 0,
                "metadata": {
                    "caller_identity": "probe_app",
                    "request_id": "request-webview",
                },
            },
            {
                "id": "log-webview",
                "kind": "blackbox.logcat",
                "exit_code": 0,
                "metadata": {
                    "request_id": "request-webview",
                    "request_observed": True,
                    "probe_success": True,
                    "security_impact_observed": True,
                },
            },
        ],
    )

    refuting_payload = {
        "summary": "Critic claims the static path is blocked.",
        "result": "refuted_static",
        "confidence": "high",
        "severity_proposal": "info",
        "hypotheses_tested": [hypothesis.id],
        "hypothesis_assessments": [
            {
                "hypothesis_id": hypothesis.id,
                "verdict": "refuted_static",
                "evidence_ids": [],
                "confidence": "high",
            }
        ],
        "review_objections": [
            {
                "objection_id": "OBJ-1",
                "hypothesis_id": hypothesis.id,
                "claim": "Static code does not show execution.",
                "basis": "Static-only review.",
                "evidence_ids": [],
            }
        ],
        "evidence_ids": [],
    }
    ledger.record_argument(
        task_id=task.id,
        role="critic",
        phase="adversarial_review",
        backend="opencode",
        model="deepseek-v4-pro",
        payload=refuting_payload,
    )
    ledger.finalize(
        task_id=task.id,
        payload=refuting_payload,
        result_value="refuted_static",
        backend="opencode",
        model="deepseek-v4-flash",
    )

    with database.session_factory() as session:
        persisted = session.get(SecurityHypothesis, hypothesis.id)
        assert persisted is not None
        finding = Finding(
            scan_id=scan_id,
            dedupe_key="immutable-proof-webview",
            rule_id="agent.webview.javascript",
            source="opencode",
            title="WebView JavaScript execution",
            description="Platform-reproduced WebView JavaScript execution.",
            remediation="Restrict untrusted WebView input.",
            masvs="MASVS-PLATFORM",
            severity="high",
            confidence="high",
            status="reproduced_blackbox",
            entry_point_ids=[entry_id],
            evidence_ids=["probe-webview", "log-webview"],
        )
        session.add(finding)
        session.flush()
        persisted.final_finding_id = finding.id
        session.commit()

    assert ledger.task_proven_severity(task.id) == "high"
    with database.session_factory() as session:
        persisted = session.get(SecurityHypothesis, hypothesis.id)
        assert persisted is not None
        assert persisted.status == "proven"
        assert persisted.confidence_score == 100
        assert persisted.refute_evidence_ids == []
        assert persisted.support_evidence_ids == [
            "probe-webview",
            "log-webview",
        ]
        assert persisted.metadata_json["platform_proof_override"] is True
        assert (
            persisted.metadata_json["assessment"]["verdict"]
            == "reproduced_blackbox"
        )
        assert (
            persisted.metadata_json["model_assessment"]["verdict"]
            == "refuted_static"
        )
        assert (
            persisted.metadata_json["closure_receipt"]["disposition"]
            == "platform_proven"
        )


def test_identical_claims_in_separate_tasks_do_not_collide(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    entry_id = "00000000-0000-0000-0000-000000000010"
    with database.session_factory() as session:
        scan = Scan(
            filename="duplicate-claims.apk",
            artifact_sha256="c" * 64,
            artifact_path=str(settings.data_dir / "duplicate-claims.apk"),
        )
        first = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[entry_id],
            hypotheses=["The same claim."],
        )
        second = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[entry_id],
            hypotheses=["The same claim."],
        )
        session.add_all([scan, first, second])
        session.commit()

    ledger = HypothesisLedger(database)
    first_hypothesis = ledger.ensure_task_hypotheses(first)[0]
    second_hypothesis = ledger.ensure_task_hypotheses(second)[0]
    assert first_hypothesis.id != second_hypothesis.id
    assert first_hypothesis.fingerprint != second_hypothesis.fingerprint
    assert ledger.ensure_task_hypotheses(first)[0].id == first_hypothesis.id


def test_plan_proof_rejects_cross_task_hypothesis_without_fallback(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    first_entry_id = "00000000-0000-0000-0000-000000000011"
    second_entry_id = "00000000-0000-0000-0000-000000000012"
    with database.session_factory() as session:
        scan = Scan(
            filename="proof-isolation.apk",
            artifact_sha256="e" * 64,
            artifact_path=str(settings.data_dir / "proof-isolation.apk"),
        )
        first = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[first_entry_id],
            hypotheses=["First task hypothesis."],
        )
        second = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[second_entry_id],
            hypotheses=["Second task hypothesis."],
        )
        session.add_all([scan, first, second])
        session.commit()

    ledger = HypothesisLedger(database)
    first_hypothesis = ledger.ensure_task_hypotheses(first)[0]
    second_hypothesis = ledger.ensure_task_hypotheses(second)[0]
    cross_task_request = AgentRequestedTest(
        hypothesis_id=second_hypothesis.id,
        entry_point_id=first_entry_id,
        state="guest",
        uri=None,
        extras={},
        rationale="This must not fall back to the first task's hypothesis.",
    )
    assert (
        ledger.plan_proof(
            task_id=first.id,
            test_case_id="cross-task",
            request=cross_task_request,
        )
        is None
    )

    outside_entry_request = AgentRequestedTest(
        hypothesis_id=first_hypothesis.id,
        entry_point_id=second_entry_id,
        state="guest",
        uri=None,
        extras={},
        rationale="This entry point belongs to another task.",
    )
    assert (
        ledger.plan_proof(
            task_id=first.id,
            test_case_id="outside-entry",
            request=outside_entry_request,
        )
        is None
    )
    with database.session_factory() as session:
        attempts = list(
            session.scalars(select(ProofAttempt).where(ProofAttempt.task_id == first.id))
        )
        assert attempts == []


def test_plan_proof_allows_related_exported_entry_in_same_scan(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="chain-proof.apk",
            artifact_sha256="f" * 64,
            artifact_path=str(settings.data_dir / "chain-proof.apk"),
        )
        seed = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.SeedActivity",
            exported=True,
        )
        related = EntryPoint(
            scan=scan,
            kind="service",
            name="com.example.RelatedService",
            exported=True,
        )
        session.add_all([scan, seed, related])
        session.flush()
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[seed.id],
            hypotheses=["The seed can delegate attacker input to the related service."],
        )
        session.add(task)
        session.commit()
        related_id = related.id

    ledger = HypothesisLedger(database)
    hypothesis = ledger.ensure_task_hypotheses(task)[0]
    proof_id = ledger.plan_proof(
        task_id=task.id,
        test_case_id="cross-entry-chain",
        request=AgentRequestedTest(
            hypothesis_id=hypothesis.id,
            entry_point_id=related_id,
            uri=None,
            extras={},
            rationale="Validate a same-scan cross-component chain.",
        ),
    )

    assert proof_id is not None
    with database.session_factory() as session:
        proof = session.get(ProofAttempt, proof_id)
        assert proof is not None
        assert proof.plan["entry_point_id"] == related_id


def test_platform_proof_result_is_independent_from_model_verdict(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="platform-proof.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "platform-proof.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=["00000000-0000-0000-0000-000000000020"],
            hypotheses=["A harmful operation is reachable."],
        )
        session.add_all([scan, task])
        session.commit()

    ledger = HypothesisLedger(database)
    hypothesis = ledger.ensure_task_hypotheses(task)[0]
    request = AgentRequestedTest(
        hypothesis_id=hypothesis.id,
        entry_point_id=task.target_entry_ids[0],
        state="guest",
        uri=None,
        extras={},
        rationale="Run the platform oracle.",
    )
    proof_id = ledger.plan_proof(
        task_id=task.id,
        test_case_id="agent-r1-1",
        request=request,
    )
    ledger.start_proof(proof_id)
    ledger.complete_proof(
        proof_id,
        [
            {
                "id": "probe-proof",
                "kind": "blackbox.probe_app",
                "exit_code": 0,
                "metadata": {
                    "caller_identity": "probe_app",
                    "request_id": "request-proof",
                },
            },
            {
                "id": "log-proof",
                "kind": "blackbox.logcat",
                "exit_code": 0,
                "metadata": {
                    "request_id": "request-proof",
                    "request_observed": True,
                    "probe_success": True,
                    "security_impact_observed": True,
                },
            },
        ],
    )
    assert ledger.task_proof_result(task.id) == (
        "reproduced_blackbox",
        ["probe-proof", "log-proof"],
    )


def test_one_platform_proof_does_not_close_other_hypotheses(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    entry_id = "00000000-0000-0000-0000-000000000090"
    with database.session_factory() as session:
        scan = Scan(
            filename="multi-hypothesis.apk",
            artifact_sha256="9" * 64,
            artifact_path=str(settings.data_dir / "multi-hypothesis.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[entry_id],
            hypotheses=[
                "External input reaches the first sensitive sink.",
                "External input independently reaches a second sensitive sink.",
            ],
        )
        session.add_all([scan, task])
        session.commit()

    ledger = HypothesisLedger(database)
    hypotheses = ledger.ensure_task_hypotheses(task)
    proof_id = ledger.plan_proof(
        task_id=task.id,
        test_case_id="first-hypothesis-proof",
        request=AgentRequestedTest(
            hypothesis_id=hypotheses[0].id,
            entry_point_id=entry_id,
            state="guest",
            uri=None,
            extras={},
            rationale="Prove only the first independent sink.",
        ),
    )
    ledger.start_proof(proof_id)
    ledger.complete_proof(
        proof_id,
        [
            {
                "id": "probe-first",
                "kind": "blackbox.probe_app",
                "exit_code": 0,
                "metadata": {"request_id": "request-first"},
            },
            {
                "id": "log-first",
                "kind": "blackbox.logcat",
                "exit_code": 0,
                "metadata": {
                    "request_id": "request-first",
                    "request_observed": True,
                    "probe_success": True,
                    "security_impact_observed": True,
                },
            },
        ],
    )

    progress = ledger.task_hypothesis_progress(task.id)
    assert progress["proven_hypothesis_ids"] == [hypotheses[0].id]
    assert progress["unresolved_hypothesis_ids"] == [hypotheses[1].id]
    assert progress["proof_stage_by_hypothesis"][hypotheses[0].id]["stage"] == (
        "impact_reproduced"
    )
    assert progress["proof_stage_by_hypothesis"][hypotheses[1].id]["stage"] == "untriaged"
    assert progress["all_platform_proven"] is False
    assert ledger.task_all_hypotheses_proven(task.id) is False
    assert ledger.task_proof_result(task.id) is not None


@pytest.mark.parametrize(
    ("dynamic_eligible", "expected_proof", "expected_hypothesis"),
    [
        (False, "inconclusive", "inconclusive"),
        (True, "proven", "proven"),
    ],
)
def test_legacy_device_verdict_depends_on_selected_validation_profile(
    settings,
    dynamic_eligible,
    expected_proof,
    expected_hypothesis,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    entry_id = "00000000-0000-0000-0000-000000000091"
    with database.session_factory() as session:
        scan = Scan(
            filename="legacy-smoke.apk",
            artifact_sha256="8" * 64,
            artifact_path=str(settings.data_dir / "legacy-smoke.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[entry_id],
            hypotheses=["External input reaches a harmful sink on Android 16."],
        )
        session.add_all([scan, task])
        session.commit()

    ledger = HypothesisLedger(database)
    hypothesis = ledger.ensure_task_hypotheses(task)[0]
    proof_id = ledger.plan_proof(
        task_id=task.id,
        test_case_id="legacy-smoke",
        request=AgentRequestedTest(
            hypothesis_id=hypothesis.id,
            entry_point_id=entry_id,
            state="guest",
            uri=None,
            extras={},
            rationale="Exercise the compatibility toolchain only.",
        ),
    )
    ledger.start_proof(proof_id)
    ledger.complete_proof(
        proof_id,
        [
            {
                "id": "legacy-probe",
                "kind": "blackbox.probe_app",
                "exit_code": 0,
                "metadata": {
                    "request_id": "legacy-request",
                    "android16_verdict_eligible": False,
                    "dynamic_verdict_eligible": dynamic_eligible,
                    "release_gate_eligible": False,
                    "verdict_scope": (
                        "development_legacy" if dynamic_eligible else "non_verdict_smoke"
                    ),
                },
            },
            {
                "id": "legacy-log",
                "kind": "blackbox.logcat",
                "exit_code": 0,
                "metadata": {
                    "request_id": "legacy-request",
                    "request_observed": True,
                    "probe_success": True,
                    "security_impact_observed": True,
                    "oracle_refuted": True,
                    "android16_verdict_eligible": False,
                    "dynamic_verdict_eligible": dynamic_eligible,
                    "release_gate_eligible": False,
                    "verdict_scope": (
                        "development_legacy" if dynamic_eligible else "non_verdict_smoke"
                    ),
                },
            },
        ],
    )

    with database.session_factory() as session:
        proof = session.get(ProofAttempt, proof_id)
        persisted_hypothesis = session.get(SecurityHypothesis, hypothesis.id)
        assert proof is not None
        assert persisted_hypothesis is not None
        assert proof.status == expected_proof
        assert proof.harm_demonstrated is dynamic_eligible
        assert proof.oracle["android16_verdict_eligible"] is False
        assert proof.oracle["dynamic_verdict_eligible"] is dynamic_eligible
        assert proof.oracle["release_gate_eligible"] is False
        assert proof.oracle["compatibility_smoke_only"] is (not dynamic_eligible)
        assert persisted_hypothesis.status == expected_hypothesis


def test_database_recovery_closes_stale_executing_proof(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="interrupted.apk",
            artifact_sha256="9" * 64,
            artifact_path="interrupted.apk",
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=[],
            hypotheses=["Interrupted proof"],
        )
        session.add_all([scan, task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="a" * 64,
            category="test",
            claim="Interrupted proof",
            status="executing",
        )
        session.add(hypothesis)
        session.flush()
        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="interrupted",
            status="executing",
        )
        session.add(proof)
        session.commit()
        proof_id = proof.id
        hypothesis_id = hypothesis.id

    database._recover_interrupted_runtime_records()
    with database.session_factory() as session:
        recovered = session.get(ProofAttempt, proof_id)
        recovered_hypothesis = session.get(SecurityHypothesis, hypothesis_id)
        assert recovered is not None
        assert recovered.status == "inconclusive"
        assert recovered.completed_at is not None
        assert recovered_hypothesis is not None
        assert recovered_hypothesis.status == "inconclusive"


def test_finalize_closes_each_hypothesis_from_its_own_receipt(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="closure-receipts.apk",
            artifact_sha256="f" * 64,
            artifact_path=str(settings.data_dir / "closure-receipts.apk"),
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            target_entry_ids=["00000000-0000-0000-0000-000000000030"],
            hypotheses=[
                "A caller check blocks the path.",
                "A separate exported action reaches a sensitive sink.",
                "A third path was not assessed.",
            ],
        )
        session.add_all([scan, task])
        session.commit()

    ledger = HypothesisLedger(database)
    hypotheses = ledger.ensure_task_hypotheses(task)
    by_claim = {hypothesis.claim: hypothesis for hypothesis in hypotheses}
    blocked_id = by_claim["A caller check blocks the path."].id
    supported_id = by_claim[
        "A separate exported action reaches a sensitive sink."
    ].id
    unassessed_id = by_claim["A third path was not assessed."].id

    ledger.finalize(
        task_id=task.id,
        payload={
            "summary": "The task contains paths with different outcomes.",
            "confidence": "high",
            "severity_proposal": "high",
            "platform_severity": "high",
            "evidence_ids": ["static-block", "static-sink"],
            "hypotheses_tested": [blocked_id, supported_id],
            "hypothesis_assessments": [
                {
                    "hypothesis_id": blocked_id,
                    "verdict": "refuted_static",
                    "control": "Signature permission check",
                    "reachable_path": "External call stops at the permission check.",
                    "proof_gaps": [],
                    "evidence_ids": ["static-block"],
                    "confidence": "high",
                },
                {
                    "hypothesis_id": supported_id,
                    "verdict": "supported_static",
                    "sink": "Sensitive preference mutation",
                    "reachable_path": (
                        "Exported receiver reaches the mutation without a guard."
                    ),
                    "proof_gaps": [
                        "Ordinary-app replay remains required for a Finding."
                    ],
                    "evidence_ids": ["static-sink"],
                    "confidence": "medium",
                },
            ],
        },
        result_value="supported_static",
        backend="opencode",
        model="test-model",
    )

    with database.session_factory() as session:
        blocked = session.get(SecurityHypothesis, blocked_id)
        supported = session.get(SecurityHypothesis, supported_id)
        unassessed = session.get(SecurityHypothesis, unassessed_id)
        assert blocked is not None
        assert supported is not None
        assert unassessed is not None
        assert blocked.status == "refuted"
        assert blocked.refute_evidence_ids == ["static-block"]
        assert supported.status == "accepted_for_proof"
        assert supported.support_evidence_ids == ["static-sink"]
        assert unassessed.status == "inconclusive"
        assert (
            unassessed.metadata_json["closure_receipt"]["disposition"]
            == "not_assessed_by_agent"
        )
        arguments = list(
            session.scalars(
                select(HypothesisArgument)
                .where(HypothesisArgument.task_id == task.id)
                .order_by(HypothesisArgument.hypothesis_id)
            )
        )
        assert len(arguments) == 3
        evidence_by_hypothesis = {
            argument.hypothesis_id: argument.evidence_ids for argument in arguments
        }
        assert evidence_by_hypothesis[blocked_id] == ["static-block"]
        assert evidence_by_hypothesis[supported_id] == ["static-sink"]
        assert evidence_by_hypothesis[unassessed_id] == []
