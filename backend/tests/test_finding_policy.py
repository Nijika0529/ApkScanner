from __future__ import annotations

import pytest
from apkscanner.core.db import Database
from apkscanner.core.models import (
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    RuntimeObservation,
    Scan,
    SecurityHypothesis,
)
from apkscanner.runtime.finding_policy import evidence_backed_signal_tier, partition_findings


@pytest.mark.parametrize(
    ("proof_scope", "expected_confirmed"),
    [
        ("target_hypothesis", True),
        ("other_hypothesis", False),
        ("other_scan", False),
        ("empty_receipt", False),
        ("cross_scan_evidence", False),
        ("failed_harm", False),
        ("malformed_receipt", False),
    ],
)
def test_partition_requires_a_same_scan_attributable_harm_receipt(
    settings,  # noqa: ANN001
    proof_scope: str,
    expected_confirmed: bool,
) -> None:
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="target.apk",
            artifact_sha256="1" * 64,
            artifact_path="target.apk",
        )
        other_scan = Scan(
            filename="other.apk",
            artifact_sha256="2" * 64,
            artifact_path="other.apk",
        )
        target_task = InvestigationTask(scan=scan, task_type="component", status="completed")
        other_task = InvestigationTask(
            scan=other_scan,
            task_type="component",
            status="completed",
        )
        session.add_all([scan, other_scan, target_task, other_task])
        session.flush()
        target_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=target_task.id,
            fingerprint="3" * 64,
            category="component",
            claim="Target hypothesis.",
        )
        same_scan_other_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=target_task.id,
            fingerprint="4" * 64,
            category="component",
            claim="Unrelated same-scan hypothesis.",
        )
        other_scan_hypothesis = SecurityHypothesis(
            scan_id=other_scan.id,
            task_id=other_task.id,
            fingerprint="5" * 64,
            category="component",
            claim="Unrelated other-scan hypothesis.",
        )
        session.add_all(
            [target_hypothesis, same_scan_other_hypothesis, other_scan_hypothesis]
        )
        session.flush()
        evidence = Evidence(
            scan_id=scan.id,
            task_id=target_task.id,
            kind="blackbox.oracle_result",
            sha256="6" * 64,
            path="target-proof.json",
        )
        other_scan_evidence = Evidence(
            scan_id=other_scan.id,
            task_id=other_task.id,
            kind="blackbox.oracle_result",
            sha256="7" * 64,
            path="other-proof.json",
        )
        session.add_all([evidence, other_scan_evidence])
        session.flush()
        proof_hypothesis = {
            "target_hypothesis": target_hypothesis,
            "other_hypothesis": same_scan_other_hypothesis,
            "other_scan": other_scan_hypothesis,
            "empty_receipt": target_hypothesis,
            "cross_scan_evidence": target_hypothesis,
            "failed_harm": target_hypothesis,
            "malformed_receipt": target_hypothesis,
        }[proof_scope]
        proof = ProofAttempt(
            scan_id=proof_hypothesis.scan_id,
            task_id=proof_hypothesis.task_id,
            hypothesis_id=proof_hypothesis.id,
            test_case_id=f"proof-{proof_scope}",
            status="failed" if proof_scope == "failed_harm" else "proven",
            evidence_ids=(
                []
                if proof_scope == "empty_receipt"
                else [{}]
                if proof_scope == "malformed_receipt"
                else [other_scan_evidence.id]
                if proof_scope == "cross_scan_evidence"
                else [evidence.id]
            ),
            harm_demonstrated=True,
        )
        finding = Finding(
            scan=scan,
            dedupe_key=f"finding-{proof_scope}",
            rule_id="AGENT",
            title="Claimed reproduced finding",
            description="Only an attributable platform receipt may confirm this.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            evidence_ids=[evidence.id],
            metadata_json={
                "hypothesis_id": target_hypothesis.id,
                "proof_attempt_ids": [],
                "harm_demonstrated": True,
            },
        )
        session.add_all([proof, finding])
        session.flush()
        finding.metadata_json = {
            **dict(finding.metadata_json or {}),
            "proof_attempt_ids": [proof.id],
        }
        target_hypothesis.final_finding_id = finding.id
        session.commit()

        confirmed, signals = partition_findings(session, [finding])

        assert bool(confirmed) is expected_confirmed
        assert bool(signals) is not expected_confirmed


def test_partition_accepts_proof_from_another_hypothesis_merged_into_the_finding(
    settings,  # noqa: ANN001
) -> None:
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="merged-proof.apk",
            artifact_sha256="7" * 64,
            artifact_path="merged-proof.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, task])
        session.flush()
        first = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="8" * 64,
            category="component",
            claim="Canonical hypothesis.",
        )
        merged = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="9" * 64,
            category="component",
            claim="Equivalent hypothesis carrying the proof.",
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="a" * 64,
            path="merged-proof.json",
        )
        session.add_all([first, merged, evidence])
        session.flush()
        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=merged.id,
            test_case_id="merged-proof",
            status="proven",
            evidence_ids=[evidence.id],
            harm_demonstrated=True,
        )
        finding = Finding(
            scan=scan,
            dedupe_key="merged-proof",
            rule_id="AGENT",
            title="Merged proven finding",
            description="The proof belongs to an equivalent merged hypothesis.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            evidence_ids=[evidence.id],
            metadata_json={
                "hypothesis_id": first.id,
                "harm_demonstrated": True,
            },
        )
        session.add_all([proof, finding])
        session.flush()
        first.final_finding_id = finding.id
        merged.final_finding_id = finding.id
        finding.metadata_json = {
            **dict(finding.metadata_json or {}),
            "proof_attempt_ids": [proof.id],
        }
        session.commit()

        confirmed, signals = partition_findings(session, [finding])

        assert [item.id for item in confirmed] == [finding.id]
        assert signals == []


def test_legacy_accepted_status_still_requires_an_attributable_proof(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="legacy-accepted.apk",
            artifact_sha256="b" * 64,
            artifact_path="legacy-accepted.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="c" * 64,
            category="component",
            claim="A stale accepted row has no proof receipt yet.",
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="d" * 64,
            path="legacy-accepted.json",
        )
        session.add_all([hypothesis, evidence])
        session.flush()
        finding = Finding(
            scan=scan,
            dedupe_key="legacy-accepted",
            rule_id="AGENT",
            title="Legacy accepted row",
            description="The status alone cannot replace a platform proof.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="accepted",
            evidence_ids=[evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "harm_demonstrated": True,
            },
        )
        session.add(finding)
        session.flush()
        hypothesis.final_finding_id = finding.id

        confirmed, signals = partition_findings(session, [finding])
        assert confirmed == []
        assert [item.id for item in signals] == [finding.id]

        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="legacy-accepted-proof",
            status="proven",
            evidence_ids=[evidence.id],
            harm_demonstrated=True,
        )
        session.add(proof)
        session.flush()

        confirmed, signals = partition_findings(session, [finding])
        assert [item.id for item in confirmed] == [finding.id]
        assert signals == []


def test_public_runtime_tier_requires_a_linked_positive_platform_receipt(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="runtime-tier.apk",
            artifact_sha256="e" * 64,
            artifact_path="runtime-tier.apk",
        )
        finding = Finding(
            scan=scan,
            dedupe_key="runtime-tier",
            rule_id="AGENT",
            title="Claimed runtime signal",
            description="The status needs a linked platform observation.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="oracle_gap",
            metadata_json={"signal_tier": "runtime_oracle_gap"},
        )
        session.add_all([scan, finding])
        session.flush()

        assert evidence_backed_signal_tier(session, finding) == "raw_candidate"

        evidence = Evidence(
            scan_id=scan.id,
            kind="blackbox.logcat",
            sha256="f" * 64,
            path="runtime-tier.log",
            metadata_json={"request_observed": True},
        )
        session.add(evidence)
        session.flush()
        session.add(
            RuntimeObservation(
                scan_id=scan.id,
                finding_id=finding.id,
                observation_key=f"runtime-tier:{finding.id}",
                kind="request.observed",
                source="adb",
                evidence_ids=[evidence.id],
                payload={"request_observed": True},
            )
        )
        session.flush()

        assert evidence_backed_signal_tier(session, finding) == "runtime_oracle_gap"


def test_public_static_tier_rejects_an_explicitly_unusable_tool_receipt(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="failed-static-tool.apk",
            artifact_sha256="0" * 64,
            artifact_path="failed-static-tool.apk",
        )
        session.add(scan)
        session.flush()
        evidence = Evidence(
            scan_id=scan.id,
            kind="static.jadx",
            sha256="1" * 64,
            path="failed-jadx.json",
            metadata_json={
                "static_output_usable": False,
                "static_tool_status": "tool_failed",
                "static_tool_exit_code": 1,
            },
        )
        session.add(evidence)
        session.flush()
        finding = Finding(
            scan=scan,
            dedupe_key="failed-static-tool",
            rule_id="AGENT",
            title="Model cited failed decompiler output",
            description="Failed output must not support a public static chain.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
            evidence_ids=[evidence.id],
            metadata_json={
                "signal_tier": "static_chain",
                "platform_static_support_gate": {
                    "eligible": True,
                    "static_evidence_ids": [evidence.id],
                },
            },
        )
        session.add(finding)
        session.flush()

        assert evidence_backed_signal_tier(session, finding) == "raw_candidate"
