from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from apkscanner.core.db import Base, Database
from apkscanner.core.models import (
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    OperatorSession,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.runtime.finding_policy import partition_findings
from sqlalchemy import MetaData, UniqueConstraint, inspect, select, text


def _finding(scan: Scan, key: str, status: str, metadata: dict) -> Finding:  # noqa: ANN401
    return Finding(
        scan=scan,
        dedupe_key=key,
        rule_id="AGENT-ENTRY-INVESTIGATION",
        source="codex",
        title=key,
        description="Legacy candidate",
        masvs="MASVS-PLATFORM",
        severity="high",
        status=status,
        evidence_ids=[f"evidence-{key}"],
        metadata_json=metadata,
    )


def test_legacy_proof_reconciliation_rejects_cross_hypothesis_receipt_ids(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="proof-attribution.apk",
            artifact_sha256="3" * 64,
            artifact_path="proof-attribution.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, task])
        session.flush()
        target = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="4" * 64,
            category="component",
            claim="Target hypothesis",
        )
        other = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="5" * 64,
            category="component",
            claim="Other hypothesis",
        )
        session.add_all([target, other])
        session.flush()
        proof_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="6" * 64,
            path="proof.json",
        )
        session.add(proof_evidence)
        session.flush()
        target_proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=target.id,
            test_case_id="target-proof",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
        )
        other_proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=other.id,
            test_case_id="other-proof",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
        )
        session.add_all([target_proof, other_proof])
        session.flush()
        finding = _finding(
            scan,
            "attributed",
            "reproduced_blackbox",
            {
                "hypothesis_id": target.id,
                "proof_attempt_ids": [other_proof.id],
            },
        )
        finding.evidence_ids = [proof_evidence.id]
        session.add(finding)
        session.commit()
        finding_id = finding.id
        target_proof_id = target_proof.id

    database._reconcile_unproven_dynamic_findings()

    with database.session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        assert finding.status == "reproduced_blackbox"
        assert finding.metadata_json["proof_attempt_ids"] == [target_proof_id]
        assert finding.metadata_json["harm_demonstrated"] is True


def _create_legacy_schema_without_finding_uniqueness(database: Database) -> None:
    """Create the pre-uniqueness schema that an in-place upgrade must reconcile."""

    legacy_metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        table.to_metadata(legacy_metadata)
    legacy_findings = legacy_metadata.tables["findings"]
    for constraint in list(legacy_findings.constraints):
        if isinstance(constraint, UniqueConstraint) and set(constraint.columns.keys()) == {
            "scan_id",
            "dedupe_key",
        }:
            legacy_findings.constraints.remove(constraint)
    legacy_metadata.create_all(database.engine)


def test_legacy_duplicate_upgrade_sanitizes_malformed_json(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    _create_legacy_schema_without_finding_uniqueness(database)
    baseline = datetime(2025, 1, 1, tzinfo=UTC)

    with database.session_factory() as session:
        scan = Scan(
            filename="malformed-legacy-json.apk",
            artifact_sha256="7" * 64,
            artifact_path="malformed-legacy-json.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, task])
        session.flush()
        entry = EntryPoint(
            scan_id=scan.id,
            kind="activity",
            name="com.example.MalformedLegacyActivity",
            exported=True,
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="8" * 64,
            path="malformed-legacy-static.json",
        )
        session.add_all([entry, evidence])
        session.flush()
        canonical = Finding(
            scan=scan,
            dedupe_key="malformed-legacy-duplicate",
            rule_id="LEGACY",
            title="Human-reviewed canonical record",
            description="The canonical row contains scalar legacy JSON fields.",
            masvs="MASVS-PLATFORM",
            severity="info",
            status="false_positive",
            review_note="人工确认该记录应保留。",
            evidence_ids="legacy-evidence-scalar",
            entry_point_ids=17,
            locations="legacy-location-scalar",
            metadata_json=23,
            created_at=baseline,
        )
        duplicate = Finding(
            scan=scan,
            dedupe_key="malformed-legacy-duplicate",
            rule_id="LEGACY",
            title="Malformed duplicate",
            description="Object and numeric JSON members must not survive ID cleanup.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="candidate",
            evidence_ids=[
                evidence.id,
                {"malformed": evidence.id},
                42,
                "missing-evidence-id",
                evidence.id,
            ],
            entry_point_ids=[entry.id, {"malformed": entry.id}, 42, entry.id],
            locations=[{"path": "src/Main.java", "line": 7}, "bad-location", 42],
            metadata_json=["legacy-list", {"malformed": True}],
            created_at=baseline + timedelta(seconds=1),
        )
        session.add_all([canonical, duplicate])
        session.flush()
        canonical_id = canonical.id
        duplicate_id = duplicate.id
        task.preconditions = {
            "candidate_finding_ids": [
                duplicate_id,
                {"malformed": duplicate_id},
                42,
                canonical_id,
                duplicate_id,
            ],
            "nested": {"finding_id": duplicate_id},
        }
        task.result = {
            "missing_candidate_assessments": [
                {"malformed": duplicate_id},
                duplicate_id,
                42,
            ],
            "missing_finding_ids": [duplicate_id, 42, canonical_id],
        }
        operator_session = OperatorSession(
            primary_scan_id=scan.id,
            title="Malformed legacy references",
            instruction="Resume the canonical finding.",
            scope_json={
                "finding_ids": [duplicate_id, {"bad": duplicate_id}, 42, canonical_id]
            },
            result_json={"finding_id": duplicate_id},
        )
        session.add(operator_session)
        scan.stats = {
            "adaptive_verification": {
                "candidate_finding_ids": [
                    {"malformed": duplicate_id},
                    duplicate_id,
                    42,
                    canonical_id,
                ]
            }
        }
        session.commit()
        scan_id = scan.id
        task_id = task.id
        operator_session_id = operator_session.id
        evidence_id = evidence.id
        entry_id = entry.id

    database.create_all()

    with database.session_factory() as session:
        records = list(
            session.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.dedupe_key == "malformed-legacy-duplicate",
                )
            )
        )
        assert [record.id for record in records] == [canonical_id]
        canonical = records[0]
        assert canonical.status == "false_positive"
        assert canonical.evidence_ids == [evidence_id]
        assert canonical.entry_point_ids == [entry_id]
        assert canonical.locations == [{"path": "src/Main.java", "line": 7}]
        assert isinstance(canonical.metadata_json, dict)

        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.preconditions["candidate_finding_ids"] == [canonical_id]
        assert task.preconditions["nested"]["finding_id"] == canonical_id
        assert task.result["missing_candidate_assessments"] == [canonical_id]
        assert task.result["missing_finding_ids"] == [canonical_id]

        operator_session = session.get(OperatorSession, operator_session_id)
        assert operator_session is not None
        assert operator_session.scope_json["finding_ids"] == [canonical_id]
        assert operator_session.result_json["finding_id"] == canonical_id

        migrated_scan = session.get(Scan, scan_id)
        assert migrated_scan is not None
        assert migrated_scan.stats["adaptive_verification"][
            "candidate_finding_ids"
        ] == [canonical_id]

    inspector = inspect(database.engine)
    assert any(
        bool(index.get("unique"))
        and set(index.get("column_names") or []) == {"scan_id", "dedupe_key"}
        for index in inspector.get_indexes("findings")
    )


def test_startup_reconciliation_replaces_malformed_scan_stats(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="malformed-stats.apk",
            artifact_sha256="9" * 64,
            artifact_path="malformed-stats.apk",
            stats=17,
        )
        finding = Finding(
            scan=scan,
            dedupe_key="legacy-direct-reachability",
            rule_id="LEGACY",
            title="Legacy direct reachability closure",
            description="This legacy closure must be reopened safely.",
            masvs="MASVS-PLATFORM",
            severity="low",
            status="false_positive",
            metadata_json={
                "closed_by_static_reachability": {
                    "threat_model": "ordinary_app_uid"
                }
            },
        )
        session.add_all([scan, finding])
        session.commit()
        scan_id = scan.id
        finding_id = finding.id

    database.create_all()

    with database.session_factory() as session:
        scan = session.get(Scan, scan_id)
        finding = session.get(Finding, finding_id)
        assert scan is not None
        assert scan.stats["materialized_summary"]["current"] is False
        assert finding is not None and finding.status == "candidate"


def test_read_only_legacy_schema_without_finding_guard_requires_writable_migration(
    settings,  # noqa: ANN001
) -> None:
    database = Database(settings)
    _create_legacy_schema_without_finding_uniqueness(database)
    database.engine.dispose()

    database_path = settings.data_dir / "test.db"
    read_only = Database(
        replace(
            settings,
            database_url=f"sqlite:///file:{database_path}?mode=ro&uri=true",
        )
    )

    with pytest.raises(RuntimeError) as error:
        read_only.create_all()
    assert "reopen it writable" in str(error.value)
    assert "findings.unique(scan_id,dedupe_key)" in str(error.value)
    read_only.engine.dispose()


@pytest.mark.parametrize(
    "conflicting_index_sql",
    [
        "CREATE INDEX uq_findings_scan_dedupe ON findings (scan_id, dedupe_key)",
        "CREATE UNIQUE INDEX uq_findings_scan_dedupe ON findings (dedupe_key)",
    ],
    ids=["non-unique", "wrong-columns"],
)
def test_legacy_finding_guard_rejects_conflicting_reserved_index(
    settings,  # noqa: ANN001
    conflicting_index_sql: str,
) -> None:
    database = Database(settings)
    _create_legacy_schema_without_finding_uniqueness(database)
    with database.engine.begin() as connection:
        connection.execute(text(conflicting_index_sql))

    with pytest.raises(RuntimeError, match="database schema guard conflict") as error:
        database.create_all()
    assert "not a unique guard over findings(scan_id, dedupe_key)" in str(error.value)


def test_legacy_duplicate_upgrade_ranks_aliases_and_discards_bogus_evidence(
    settings,  # noqa: ANN001
) -> None:
    database = Database(settings)
    _create_legacy_schema_without_finding_uniqueness(database)
    baseline = datetime(2025, 1, 1, tzinfo=UTC)

    with database.session_factory() as session:
        scan = Scan(
            filename="legacy-target.apk",
            artifact_sha256="a" * 64,
            artifact_path="legacy-target.apk",
        )
        foreign_scan = Scan(
            filename="foreign.apk",
            artifact_sha256="b" * 64,
            artifact_path="foreign.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, foreign_scan, task])
        session.flush()
        static_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="static.jadx",
            sha256="c" * 64,
            path="static.json",
        )
        runtime_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.logcat",
            sha256="d" * 64,
            path="runtime.log",
        )
        proof_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="e" * 64,
            path="proof.json",
        )
        foreign_evidence = Evidence(
            scan_id=foreign_scan.id,
            kind="static.jadx",
            sha256="f" * 64,
            path="foreign-static.json",
        )
        hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="1" * 64,
            category="component",
            claim="Ordinary app input reaches the privileged sink.",
        )
        session.add_all(
            [
                static_evidence,
                runtime_evidence,
                proof_evidence,
                foreign_evidence,
                hypothesis,
            ]
        )
        session.flush()
        proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="legacy-proof",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
        )
        alias_static = Finding(
            scan=scan,
            dedupe_key="legacy-alias",
            rule_id="LEGACY",
            title="Legacy static path",
            description="Legacy static alias.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="static_path_supported",
            evidence_ids=[static_evidence.id],
            created_at=baseline,
        )
        alias_oracle_gap = Finding(
            scan=scan,
            dedupe_key="legacy-alias",
            rule_id="LEGACY",
            title="Legacy Oracle gap",
            description="Runtime was observed without a harm receipt.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="oracle_gap",
            evidence_ids=[runtime_evidence.id, "bogus-evidence-id", foreign_evidence.id],
            created_at=baseline + timedelta(seconds=1),
        )
        proven = Finding(
            scan=scan,
            dedupe_key="legacy-proven",
            rule_id="LEGACY",
            title="Legacy proven issue",
            description="An attributable platform Oracle demonstrated harm.",
            masvs="MASVS-PLATFORM",
            severity="critical",
            status="reproduced_blackbox",
            evidence_ids=[proof_evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "harm_demonstrated": True,
            },
            created_at=baseline,
        )
        noisy_duplicate = Finding(
            scan=scan,
            dedupe_key="legacy-proven",
            rule_id="LEGACY",
            title="Noisy legacy duplicate",
            description="Carries stale evidence references.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="static_path_supported",
            evidence_ids=["bogus-evidence-id", foreign_evidence.id],
            created_at=baseline + timedelta(seconds=1),
        )
        manual_closure = Finding(
            scan=scan,
            dedupe_key="legacy-human-closure",
            rule_id="LEGACY",
            title="Human reviewed false positive",
            description="A human explicitly closed this issue.",
            masvs="MASVS-PLATFORM",
            severity="info",
            status="false_positive",
            review_note="人工确认业务校验有效。",
            created_at=baseline,
        )
        stale_reproduced = Finding(
            scan=scan,
            dedupe_key="legacy-human-closure",
            rule_id="LEGACY",
            title="Unproven reproduced claim",
            description="A stale model verdict has no proof receipt.",
            masvs="MASVS-PLATFORM",
            severity="critical",
            status="reproduced_blackbox",
            metadata_json={"harm_demonstrated": True},
            created_at=baseline + timedelta(seconds=1),
        )
        session.add_all(
            [
                proof,
                alias_static,
                alias_oracle_gap,
                proven,
                noisy_duplicate,
                manual_closure,
                stale_reproduced,
            ]
        )
        session.flush()
        hypothesis.final_finding_id = proven.id
        proven.metadata_json = {
            **dict(proven.metadata_json or {}),
            "proof_attempt_ids": [proof.id],
        }
        task.preconditions = {
            "candidate_finding_ids": [noisy_duplicate.id],
        }
        task.result = {
            "missing_candidate_assessments": [noisy_duplicate.id],
            "missing_finding_ids": [noisy_duplicate.id],
        }
        operator_session = OperatorSession(
            primary_scan_id=scan.id,
            title="Resume duplicate review",
            instruction="Continue the prior review.",
            scope_json={"finding_ids": [noisy_duplicate.id]},
            result_json={"finding_id": noisy_duplicate.id},
        )
        session.add(operator_session)
        scan.stats = {
            "finding_count": 99,
            "signal_count": 99,
            "seal": {
                "evidence_id": "legacy-seal",
                "sha256": "2" * 64,
                "current": True,
            },
            "adaptive_verification": {
                "candidate_finding_ids": [noisy_duplicate.id]
            },
        }
        session.commit()
        scan_id = scan.id
        task_id = task.id
        operator_session_id = operator_session.id
        canonical_proven_id = proven.id
        noisy_duplicate_id = noisy_duplicate.id

    # Exercise the real writable startup migration order, including the uniqueness guard.
    database.create_all()

    with database.session_factory() as session:
        alias_records = list(
            session.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.dedupe_key == "legacy-alias",
                )
            )
        )
        assert len(alias_records) == 1
        assert alias_records[0].status == "oracle_gap"
        assert set(alias_records[0].evidence_ids) == {
            static_evidence.id,
            runtime_evidence.id,
        }

        proven_records = list(
            session.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.dedupe_key == "legacy-proven",
                )
            )
        )
        assert len(proven_records) == 1
        canonical = proven_records[0]
        assert canonical.status == "reproduced_blackbox"
        assert canonical.evidence_ids == [proof_evidence.id]
        discarded_occurrence = next(
            item
            for item in canonical.metadata_json["legacy_duplicate_occurrences"]
            if item["record_id"] == noisy_duplicate_id
        )
        assert discarded_occurrence["title"] == "Noisy legacy duplicate"
        assert discarded_occurrence["description"] == "Carries stale evidence references."
        assert discarded_occurrence["status"] == "static_path_supported"
        assert discarded_occurrence["evidence_ids"] == [
            "bogus-evidence-id",
            foreign_evidence.id,
        ]
        assert len(discarded_occurrence["metadata_sha256"]) == 64
        confirmed, signals = partition_findings(session, [canonical])
        assert [item.id for item in confirmed] == [canonical.id]
        assert signals == []
        human_closure = session.scalar(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.dedupe_key == "legacy-human-closure",
            )
        )
        assert human_closure is not None
        assert human_closure.status == "false_positive"
        assert human_closure.review_note == "人工确认业务校验有效。"
        task = session.get(InvestigationTask, task_id)
        assert task is not None
        assert task.preconditions["candidate_finding_ids"] == [canonical_proven_id]
        assert task.result["missing_candidate_assessments"] == [canonical_proven_id]
        assert task.result["missing_finding_ids"] == [canonical_proven_id]
        operator_session = session.get(OperatorSession, operator_session_id)
        assert operator_session is not None
        assert operator_session.scope_json["finding_ids"] == [canonical_proven_id]
        assert operator_session.result_json["finding_id"] == canonical_proven_id
        reconciled_scan = session.get(Scan, scan_id)
        assert reconciled_scan is not None
        assert reconciled_scan.stats["seal"]["current"] is False
        assert "finding_count" not in reconciled_scan.stats
        assert "signal_count" not in reconciled_scan.stats
        assert reconciled_scan.stats["adaptive_verification"][
            "candidate_finding_ids"
        ] == [canonical_proven_id]


def test_startup_recovers_proof_committed_before_finding_materialization(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="proof-crash-boundary.apk",
            artifact_sha256="7" * 64,
            artifact_path="proof-crash-boundary.apk",
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="inconclusive",
            result={"platform_severity": "critical"},
        )
        session.add_all([scan, task])
        session.flush()
        linked_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="8" * 64,
            category="component",
            claim="A committed proof should promote the existing candidate.",
        )
        orphan_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="9" * 64,
            category="component",
            claim="A committed proof should recreate its interrupted Finding.",
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="0" * 64,
            path="proof-crash-boundary.json",
        )
        session.add_all([linked_hypothesis, orphan_hypothesis, evidence])
        session.flush()
        linked_proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=linked_hypothesis.id,
            test_case_id="linked-proof-before-crash",
            status="proven",
            evidence_ids=[evidence.id],
            harm_demonstrated=True,
        )
        orphan_proof = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=orphan_hypothesis.id,
            test_case_id="orphan-proof-before-crash",
            status="proven",
            evidence_ids=[evidence.id],
            harm_demonstrated=True,
        )
        existing = Finding(
            scan=scan,
            dedupe_key="proof-crash-existing",
            rule_id="AGENT",
            title="Existing candidate",
            description="The proof commit won the race with the Finding update.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="candidate",
            evidence_ids=[evidence.id],
            metadata_json={"hypothesis_id": linked_hypothesis.id},
        )
        session.add_all([linked_proof, orphan_proof, existing])
        session.commit()
        scan_id = scan.id
        existing_id = existing.id
        linked_hypothesis_id = linked_hypothesis.id
        orphan_hypothesis_id = orphan_hypothesis.id

    database.create_all()

    with database.session_factory() as session:
        findings = list(
            session.scalars(select(Finding).where(Finding.scan_id == scan_id))
        )
        confirmed, signals = partition_findings(session, findings)
        assert len(findings) == 2
        assert {item.id for item in confirmed} == {item.id for item in findings}
        assert signals == []
        assert session.get(Finding, existing_id).status == "reproduced_blackbox"
        linked = session.get(SecurityHypothesis, linked_hypothesis_id)
        orphan = session.get(SecurityHypothesis, orphan_hypothesis_id)
        assert linked is not None and linked.final_finding_id == existing_id
        assert orphan is not None and orphan.final_finding_id is not None
        recovered = session.get(Finding, orphan.final_finding_id)
        assert recovered is not None
        assert recovered.rule_id == "PLATFORM-PROOF-RECOVERY"
        assert recovered.severity == "critical"


def test_startup_requires_an_evidence_backed_oracle_for_not_reproduced(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="negative-receipts.apk",
            artifact_sha256="3" * 64,
            artifact_path="negative-receipts.apk",
            stats={
                "finding_count": 0,
                "signal_count": 2,
                "seal": {"evidence_id": "old-seal", "sha256": "4" * 64},
            },
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        session.add_all([scan, task])
        session.flush()
        valid_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="5" * 64,
            category="component",
            claim="The platform Oracle definitively rejected this path.",
        )
        stale_hypothesis = SecurityHypothesis(
            scan_id=scan.id,
            task_id=task.id,
            fingerprint="6" * 64,
            category="component",
            claim="A model-only negative verdict must be reopened.",
        )
        evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="7" * 64,
            path="negative-oracle.json",
        )
        session.add_all([valid_hypothesis, stale_hypothesis, evidence])
        session.flush()
        receipt = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=valid_hypothesis.id,
            test_case_id="negative-oracle",
            status="refuted",
            oracle={
                "oracle_refuted": True,
                "execution_demonstrated": True,
                "dynamic_verdict_eligible": True,
            },
            evidence_ids=[evidence.id],
            harm_demonstrated=False,
        )
        malformed_receipt = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=stale_hypothesis.id,
            test_case_id="malformed-negative-oracle",
            status="refuted",
            oracle=["legacy-malformed-oracle"],
            evidence_ids=[evidence.id],
            harm_demonstrated=False,
        )
        session.add_all([receipt, malformed_receipt])
        session.flush()
        valid = Finding(
            scan=scan,
            dedupe_key="valid-negative",
            rule_id="AGENT",
            title="Evidence-backed negative",
            description="The platform Oracle rejected the hypothesis.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="not_reproduced",
            evidence_ids=[evidence.id],
            metadata_json={"hypothesis_id": valid_hypothesis.id},
        )
        stale = Finding(
            scan=scan,
            dedupe_key="stale-negative",
            rule_id="AGENT",
            title="Model-only negative",
            description="No platform refutation receipt exists.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="not_reproduced",
            metadata_json={
                "hypothesis_id": stale_hypothesis.id,
                "refutation_attempt_ids": [malformed_receipt.id, "missing-proof"],
            },
        )
        session.add_all([valid, stale])
        session.flush()
        valid_hypothesis.final_finding_id = valid.id
        stale_hypothesis.final_finding_id = stale.id
        session.commit()
        scan_id = scan.id
        valid_id = valid.id
        stale_id = stale.id

    database.create_all()

    with database.session_factory() as session:
        valid = session.get(Finding, valid_id)
        stale = session.get(Finding, stale_id)
        scan = session.get(Scan, scan_id)
        assert valid is not None and valid.status == "not_reproduced"
        assert valid.metadata_json["refutation_attempt_ids"] == [receipt.id]
        assert valid.metadata_json["proof_backlog"]["status"] == "refuted"
        assert stale is not None and stale.status == "inconclusive"
        assert stale.metadata_json["refutation_attempt_ids"] == []
        assert stale.metadata_json["negative_verdict_reconciliation"][
            "previous_status"
        ] == "not_reproduced"
        assert scan is not None and scan.stats["seal"]["current"] is False


def test_startup_reopens_static_refutations_without_a_complete_receipt(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="static-refutation-receipts.apk",
            artifact_sha256="8" * 64,
            artifact_path="static-refutation-receipts.apk",
            stats={
                "finding_count": 0,
                "signal_count": 3,
                "seal": {"evidence_id": "old-seal", "sha256": "9" * 64},
            },
        )
        session.add(scan)
        session.flush()
        usable = Evidence(
            scan_id=scan.id,
            kind="static.jadx",
            sha256="a" * 64,
            path="usable-static.json",
            metadata_json={"static_output_usable": True},
        )
        failed = Evidence(
            scan_id=scan.id,
            kind="static.jadx",
            sha256="b" * 64,
            path="failed-static.json",
            exit_code=1,
            metadata_json={"static_output_usable": False},
        )
        session.add_all([usable, failed])
        session.flush()
        complete_gate = {
            "schema_version": "1.0",
            "eligible": True,
            "static_evidence_ids": [usable.id],
            "counterevidence": [
                "静态控制流显示调用者 UID 不匹配时在敏感操作之前抛出 SecurityException。"
            ],
            "blocked_edge": (
                "untrusted Binder caller -> UID equality guard -> privileged sink blocked"
            ),
            "suppression_reasons": [],
        }
        valid = Finding(
            scan=scan,
            dedupe_key="valid-static-refutation",
            rule_id="AGENT",
            title="Evidence-backed static refutation",
            description="A concrete caller guard blocks the sink.",
            masvs="MASVS-PLATFORM",
            severity="info",
            status="refuted_static",
            evidence_ids=[usable.id],
            metadata_json={"platform_static_refutation_gate": complete_gate},
        )
        vague = Finding(
            scan=scan,
            dedupe_key="vague-static-refutation",
            rule_id="AGENT",
            title="Vague static refutation",
            description="A model-only conclusion has no blocked edge receipt.",
            masvs="MASVS-PLATFORM",
            severity="info",
            status="refuted_static",
            evidence_ids=[usable.id],
            metadata_json={
                "platform_static_refutation_gate": {
                    **complete_gate,
                    "blocked_edge": "safe",
                }
            },
        )
        unusable = Finding(
            scan=scan,
            dedupe_key="failed-tool-static-refutation",
            rule_id="AGENT",
            title="Failed-tool static refutation",
            description="A failed tool output cannot close the candidate.",
            masvs="MASVS-PLATFORM",
            severity="info",
            status="refuted_static",
            evidence_ids=[failed.id],
            metadata_json={
                "platform_static_refutation_gate": {
                    **complete_gate,
                    "static_evidence_ids": [failed.id],
                }
            },
        )
        session.add_all([valid, vague, unusable])
        session.commit()
        scan_id = scan.id
        finding_ids = [valid.id, vague.id, unusable.id]

    database.create_all()

    with database.session_factory() as session:
        valid = session.get(Finding, finding_ids[0])
        vague = session.get(Finding, finding_ids[1])
        unusable = session.get(Finding, finding_ids[2])
        scan = session.get(Scan, scan_id)
        assert valid is not None and valid.status == "refuted_static"
        assert vague is not None and vague.status == "inconclusive"
        assert unusable is not None and unusable.status == "inconclusive"
        assert vague.metadata_json["static_refutation_reconciliation"][
            "previous_status"
        ] == "refuted_static"
        assert unusable.metadata_json["static_refutation_reconciliation"][
            "reported_gate"
        ]["static_evidence_ids"] == [failed.id]
        assert scan is not None and scan.stats["seal"]["current"] is False
