from __future__ import annotations

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
from apkscanner.platform.reports import ReportBuilder
from apkscanner.runtime.quality_metrics import build_scan_quality_summary
from sqlalchemy import event


def test_report_counts_only_evidence_backed_platform_harm(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            filename="report.apk",
            artifact_sha256="1" * 64,
            artifact_path="report.apk",
        )
        other_scan = Scan(
            filename="other.apk",
            artifact_sha256="2" * 64,
            artifact_path="other.apk",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="completed")
        other_task = InvestigationTask(
            scan=other_scan,
            task_type="component",
            status="completed",
        )
        session.add_all([scan, other_scan, task, other_task])
        session.flush()
        hypothesis = SecurityHypothesis(
            scan=scan,
            task_id=task.id,
            fingerprint="3" * 64,
            category="component",
            claim="A platform Oracle can demonstrate unauthorized impact.",
        )
        valid_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="4" * 64,
            path="valid-oracle.json",
        )
        cross_scan_evidence = Evidence(
            scan_id=other_scan.id,
            task_id=other_task.id,
            kind="blackbox.oracle_result",
            sha256="5" * 64,
            path="cross-scan-oracle.json",
        )
        session.add_all([hypothesis, valid_evidence, cross_scan_evidence])
        session.flush()
        attempts = [
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="valid-proof",
                status="proven",
                evidence_ids=[valid_evidence.id],
                harm_demonstrated=True,
            ),
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="failed-claim",
                status="failed",
                evidence_ids=[valid_evidence.id],
                harm_demonstrated=True,
            ),
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="missing-receipt",
                status="proven",
                evidence_ids=["00000000-0000-0000-0000-000000000099"],
                harm_demonstrated=True,
            ),
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="cross-scan-receipt",
                status="proven",
                evidence_ids=[cross_scan_evidence.id],
                harm_demonstrated=True,
            ),
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="no-harm",
                status="proven",
                evidence_ids=[valid_evidence.id],
                harm_demonstrated=False,
            ),
        ]
        session.add_all(attempts)
        session.flush()

        report = ReportBuilder().build(session, scan)
        serialized = report["security_hypotheses"][0]["proof_attempts"]
        trusted = {
            item["test_case_id"]
            for item in serialized
            if item["platform_harm_proven"]
        }

        assert trusted == {"valid-proof"}
        assert sum(item["harm_demonstrated"] for item in serialized) == 4
        assert "<td>5</td><td>1</td>" in ReportBuilder().html(report)


def test_signal_tiering_queries_do_not_scale_with_finding_count(settings) -> None:  # noqa: ANN001
    database = Database(settings)
    database.create_all()

    def seed_runtime_signals(session, *, label: str, count: int) -> Scan:  # noqa: ANN001
        scan = Scan(
            filename=f"{label}.apk",
            artifact_sha256=("1" if label == "one" else "2") * 64,
            artifact_path=f"{label}.apk",
        )
        session.add(scan)
        session.flush()
        records: list[object] = []
        for index in range(count):
            evidence_id = f"{label}-evidence-{index}"
            finding_id = f"{label}-finding-{index}"
            records.extend(
                [
                    Evidence(
                        id=evidence_id,
                        scan_id=scan.id,
                        kind="blackbox.logcat",
                        sha256=f"{index + 1:064x}",
                        path=f"{label}-runtime-{index}.log",
                        metadata_json={"request_observed": True},
                    ),
                    Finding(
                        id=finding_id,
                        scan_id=scan.id,
                        dedupe_key=f"{label}-runtime-{index}",
                        rule_id="AGENT",
                        title=f"Runtime signal {index}",
                        description="Runtime behavior observed without a harm Oracle.",
                        masvs="MASVS-PLATFORM",
                        severity="medium",
                        status="runtime_observed_unverified",
                        evidence_ids=[evidence_id],
                        metadata_json={"signal_tier": "runtime_oracle_gap"},
                    ),
                    RuntimeObservation(
                        scan_id=scan.id,
                        finding_id=finding_id,
                        observation_key=f"{label}:runtime:{index}",
                        kind="request.observed",
                        source="adb",
                        evidence_ids=[evidence_id],
                        payload={"request_observed": True},
                    ),
                ]
            )
        session.add_all(records)
        session.flush()
        return scan

    with database.session_factory() as session:
        one_scan = seed_runtime_signals(session, label="one", count=1)
        many_scan = seed_runtime_signals(session, label="many", count=100)
        session.commit()

        def measured_selects(callback):  # noqa: ANN202, ANN001
            select_count = 0

            def count_select(
                _connection,  # noqa: ANN001
                _cursor,  # noqa: ANN001
                statement,  # noqa: ANN001
                _parameters,  # noqa: ANN001
                _context,  # noqa: ANN001
                _executemany,  # noqa: ANN001
            ) -> None:
                nonlocal select_count
                if statement.lstrip().upper().startswith("SELECT"):
                    select_count += 1

            event.listen(database.engine, "before_cursor_execute", count_select)
            try:
                result = callback()
            finally:
                event.remove(database.engine, "before_cursor_execute", count_select)
            return select_count, result

        one_quality_queries, one_quality = measured_selects(
            lambda: build_scan_quality_summary(session, one_scan.id)
        )
        many_quality_queries, many_quality = measured_selects(
            lambda: build_scan_quality_summary(session, many_scan.id)
        )
        one_report_queries, one_report = measured_selects(
            lambda: ReportBuilder().build(session, one_scan)
        )
        many_report_queries, many_report = measured_selects(
            lambda: ReportBuilder().build(session, many_scan)
        )

    assert many_quality_queries == one_quality_queries
    assert many_report_queries == one_report_queries
    assert next(
        item
        for item in many_quality["funnel"]
        if item["key"] == "runtime_observed_unverified"
    )["count"] == 100
    assert len(one_report["signals"]) == 1
    assert len(many_report["signals"]) == 100
    assert {item["signal_tier"] for item in many_report["signals"]} == {
        "runtime_oracle_gap"
    }
