from __future__ import annotations

from apkscanner.db import Database
from apkscanner.models import (
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
    with database.session_factory() as session:
        hypothesis = session.get(SecurityHypothesis, hypothesis_id)
        proof = session.get(ProofAttempt, proof_id)
        reachability_only = session.get(ProofAttempt, reachability_only_id)
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
        arguments = list(
            session.scalars(
                select(HypothesisArgument).where(
                    HypothesisArgument.hypothesis_id == hypothesis_id
                )
            )
        )
        assert [argument.role for argument in arguments] == ["hunter", "critic"]


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
