from __future__ import annotations

import hashlib
import threading
import zipfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from apkscanner.core.db import Database
from apkscanner.core.models import (
    ApplicationRecord,
    ApplicationRelease,
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
    VulnerabilityCase,
    VulnerabilityOccurrence,
)
from apkscanner.core.schemas import AgentOracleSpec, AgentRequestedTest
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.platform.tools import TimeBudget
from apkscanner.platform.versioning import SecurityEvolutionService
from apkscanner.runtime.orchestrator import ScanOrchestrator
from apkscanner.runtime.proof_recipes import plan_with_proof_recipe
from sqlalchemy import select


def _scan(version: str, artifact: str) -> Scan:
    return Scan(
        filename=f"version-{version}.apk",
        artifact_sha256=artifact * 64,
        artifact_path=f"/tmp/version-{version}.apk",
        package_name="io.apkscanner.versiontest",
        version_name=version,
        version_code=version,
        signing={"certificate_sha256": ["11:22:33"]},
    )


def _entry(scan: Scan, *, guarded: bool = False) -> EntryPoint:
    return EntryPoint(
        scan=scan,
        kind="provider",
        name="io.apkscanner.versiontest.SecretProvider",
        owner_component="io.apkscanner.versiontest.SecretProvider",
        exported=True,
        permission=("io.apkscanner.versiontest.SIGNATURE_ACCESS" if guarded else None),
        permission_protection="signature" if guarded else None,
        metadata_json={"authorities": "io.apkscanner.versiontest.secrets"},
    )


def _code_index(guarded: bool = False) -> dict:
    guard = (
        "invoke-virtual {p0}, "
        "Landroid/content/Context;->enforceCallingPermission(Ljava/lang/String;Ljava/lang/String;)V"
        if guarded
        else ""
    )
    return {
        "io.apkscanner.versiontest.SecretProvider": {
            "status": "available",
            "anchors": [
                {
                    "content": (
                        ".line 10\n"
                        f"{guard}\n"
                        "invoke-virtual {p0, p1}, "
                        "Landroid/database/sqlite/SQLiteDatabase;->"
                        "query(Ljava/lang/String;)Landroid/database/Cursor;"
                    )
                }
            ],
        }
    }


def test_snapshot_diff_migrates_only_proven_poc(settings, tmp_path) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    service = SecurityEvolutionService()
    source_zip = tmp_path / "old-poc.zip"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest package="io.apkscanner.poc.replay"/>',
        )
        archive.writestr("src/io/apkscanner/poc/replay/Main.java", "class Main {}")
    source_sha = hashlib.sha256(source_zip.read_bytes()).hexdigest()

    with database.session_factory() as session:
        baseline = _scan("1", "a")
        baseline.created_at = datetime.now(UTC) - timedelta(seconds=5)
        old_entry = _entry(baseline)
        old_task = InvestigationTask(
            scan=baseline,
            task_type="provider",
            target_entry_ids=[],
            hypotheses=["Third-party caller can read provider rows."],
        )
        session.add_all([baseline, old_entry, old_task])
        session.flush()
        old_task.target_entry_ids = [old_entry.id]
        hypothesis = SecurityHypothesis(
            scan=baseline,
            task_id=old_task.id,
            fingerprint="f" * 64,
            category="provider_access",
            claim="Third-party caller can read provider rows.",
            entry_point_ids=[old_entry.id],
        )
        session.add(hypothesis)
        session.flush()
        proof_evidence = Evidence(
            scan_id=baseline.id,
            task_id=old_task.id,
            kind="blackbox.oracle_result",
            sha256="d" * 64,
            path=str(tmp_path / "oracle-result.json"),
            summary="Platform Oracle observed one target-owned row.",
            metadata_json={"hypothesis_id": hypothesis.id},
        )
        session.add(proof_evidence)
        session.flush()
        attempt = ProofAttempt(
            scan_id=baseline.id,
            task_id=old_task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="old-proof",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
            plan={
                "hypothesis_id": hypothesis.id,
                "entry_point_id": old_entry.id,
                "state": "guest",
                "uri": "content://io.apkscanner.versiontest.secrets/items",
                "extras": {},
                "operation": "query",
                "oracle": {
                    "kind": "provider_rows",
                    "minimum_rows": 1,
                    "impact": "unauthorized_data_access",
                    "refute_on_miss": True,
                },
                "rationale": "Read one secret row.",
                "poc": {
                    "project_path": "poc/old",
                    "package_name": "io.apkscanner.poc.replay",
                    "launch_component": ".MainActivity",
                    "log_tag": "APKSCANNER_POC",
                    "timeout_seconds": 60,
                },
            },
            oracle={"impact": "unauthorized_data_access"},
        )
        session.add(attempt)
        session.flush()
        finding = Finding(
            scan=baseline,
            dedupe_key="proven-old",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="opencode",
            title="Unauthorized provider read",
            description="A third-party app read a secret row.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            entry_point_ids=[old_entry.id],
            evidence_ids=[proof_evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "proof_attempt_ids": [attempt.id],
            },
        )
        session.add_all(
            [
                finding,
                Evidence(
                    scan_id=baseline.id,
                    task_id=old_task.id,
                    kind="poc.build_artifact",
                    sha256="e" * 64,
                    path=str(tmp_path / "evidence.json"),
                    metadata_json={
                        "source_path": str(source_zip),
                        "poc_source_sha256": source_sha,
                        "hypothesis_id": hypothesis.id,
                    },
                ),
            ]
        )
        session.flush()
        hypothesis.final_finding_id = finding.id
        for suffix, proof_status, proof_evidence_ids in (
            ("failed", "failed", [proof_evidence.id]),
            (
                "missing-evidence",
                "proven",
                ["00000000-0000-0000-0000-000000000099"],
            ),
        ):
            rejected_hypothesis = SecurityHypothesis(
                scan=baseline,
                task_id=old_task.id,
                fingerprint=hashlib.sha256(suffix.encode()).hexdigest(),
                category="provider_access",
                claim=f"Untrusted historical claim: {suffix}.",
                entry_point_ids=[old_entry.id],
            )
            session.add(rejected_hypothesis)
            session.flush()
            rejected_request = AgentRequestedTest(
                hypothesis_id=rejected_hypothesis.id,
                entry_point_id=old_entry.id,
                uri="content://io.apkscanner.versiontest.secrets/items",
                extras={},
                operation="query",
                oracle=AgentOracleSpec(
                    kind="provider_rows",
                    minimum_rows=1,
                    impact="unauthorized_data_access",
                ),
                rationale="This historical claim must not be replayed without a valid receipt.",
            )
            rejected_attempt = ProofAttempt(
                scan_id=baseline.id,
                task_id=old_task.id,
                hypothesis_id=rejected_hypothesis.id,
                test_case_id=f"rejected-{suffix}",
                prover="platform_ephemeral_harness",
                status=proof_status,
                evidence_ids=proof_evidence_ids,
                harm_demonstrated=True,
                plan=plan_with_proof_recipe(rejected_request),
                oracle=rejected_request.oracle.model_dump(mode="json"),
            )
            rejected_finding = Finding(
                scan=baseline,
                dedupe_key=f"rejected-{suffix}",
                rule_id="AGENT-ENTRY-INVESTIGATION",
                title=f"Untrusted historical finding: {suffix}",
                description="Status or harm flags alone are not proof.",
                masvs="MASVS-PLATFORM",
                severity="high",
                status="reproduced_blackbox",
                entry_point_ids=[old_entry.id],
            )
            session.add_all([rejected_attempt, rejected_finding])
            session.flush()
            rejected_hypothesis.final_finding_id = rejected_finding.id
            rejected_finding.metadata_json = {
                "hypothesis_id": rejected_hypothesis.id,
                "proof_attempt_ids": [rejected_attempt.id],
            }
        old_snapshot = service.build_snapshot(
            session,
            scan=baseline,
            entries=[old_entry],
            code_index=_code_index(),
        )
        session.commit()

        target = _scan("2", "b")
        new_entry = _entry(target, guarded=True)
        session.add_all([target, new_entry])
        session.flush()
        new_snapshot = service.build_snapshot(
            session,
            scan=target,
            entries=[new_entry],
            code_index=_code_index(guarded=True),
        )
        diff = service.build_version_diff(
            session,
            scan=target,
            snapshot=new_snapshot,
        )
        assert diff is not None
        assert diff.baseline_scan_id == old_snapshot.scan_id
        assert diff.summary["replay_candidate_count"] == 1
        assert diff.deltas[0]["category"] == "security_hardened"
        assert attempt.proof_recipe["execution_mode"] == "agent_source"
        replay_tasks: list[InvestigationTask] = []
        service.apply_diff_and_patterns(
            session,
            scan=target,
            entries=[new_entry],
            tasks=replay_tasks,
            diff=diff,
        )
        assert len(replay_tasks) == 1
        task = replay_tasks[0]
        assert task.task_type == "version_replay"
        assert task.priority == 100
        replay = task.preconditions["version_replays"][0]
        assert replay["source_finding_id"] == finding.id
        assert replay["target_entry_id"] == new_entry.id


def test_snapshot_diff_regenerates_platform_harness_without_source_archive(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    service = SecurityEvolutionService()
    with database.session_factory() as session:
        baseline = _scan("1", "d")
        baseline.created_at = datetime.now(UTC) - timedelta(seconds=5)
        old_entry = _entry(baseline)
        old_task = InvestigationTask(
            scan=baseline,
            task_type="provider",
            target_entry_ids=[],
            hypotheses=["Third-party caller can read provider rows."],
        )
        session.add_all([baseline, old_entry, old_task])
        session.flush()
        old_task.target_entry_ids = [old_entry.id]
        hypothesis = SecurityHypothesis(
            scan=baseline,
            task_id=old_task.id,
            fingerprint="8" * 64,
            category="provider_access",
            claim="Third-party caller can read provider rows.",
            entry_point_ids=[old_entry.id],
        )
        session.add(hypothesis)
        session.flush()
        proof_evidence = Evidence(
            scan_id=baseline.id,
            task_id=old_task.id,
            kind="blackbox.oracle_result",
            sha256="9" * 64,
            path="platform-harness-oracle.json",
            summary="Platform Harness observed one target-owned row.",
            metadata_json={"hypothesis_id": hypothesis.id},
        )
        session.add(proof_evidence)
        session.flush()
        request = AgentRequestedTest(
            hypothesis_id=hypothesis.id,
            entry_point_id=old_entry.id,
            uri="content://io.apkscanner.versiontest.secrets/items",
            extras={},
            operation="query",
            oracle=AgentOracleSpec(
                kind="provider_rows",
                minimum_rows=1,
                impact="unauthorized_data_access",
            ),
            rationale="Read one secret row with a generated ordinary-app Harness.",
        )
        attempt = ProofAttempt(
            scan_id=baseline.id,
            task_id=old_task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="platform-harness-proof",
            prover="platform_ephemeral_harness",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
            plan=plan_with_proof_recipe(request),
            oracle=request.oracle.model_dump(mode="json"),
        )
        session.add(attempt)
        session.flush()
        finding = Finding(
            scan=baseline,
            dedupe_key="platform-harness-proof",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            title="Unauthorized provider read",
            description="A generated Harness read one target-owned row.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            entry_point_ids=[old_entry.id],
            evidence_ids=[proof_evidence.id],
            metadata_json={
                "hypothesis_id": hypothesis.id,
                "proof_attempt_ids": [attempt.id],
            },
        )
        session.add(finding)
        session.flush()
        hypothesis.final_finding_id = finding.id
        service.build_snapshot(
            session,
            scan=baseline,
            entries=[old_entry],
            code_index=_code_index(),
        )
        session.commit()

        target = _scan("2", "e")
        new_entry = _entry(target)
        session.add_all([target, new_entry])
        session.flush()
        target_snapshot = service.build_snapshot(
            session,
            scan=target,
            entries=[new_entry],
            code_index=_code_index(),
        )
        diff = service.build_version_diff(session, scan=target, snapshot=target_snapshot)
        assert diff is not None
        assert len(diff.replay_candidates) == 1
        replay = diff.replay_candidates[0]
        assert replay["proof_recipe"]["execution_mode"] == "platform_harness"
        assert replay["source_archive_path"] is None
        replay_tasks: list[InvestigationTask] = []
        service.apply_diff_and_patterns(
            session,
            scan=target,
            entries=[new_entry],
            tasks=replay_tasks,
            diff=diff,
        )
        session.commit()
        replay_task = replay_tasks[0]

    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    target_hypothesis = orchestrator.hypothesis_ledger.ensure_task_hypotheses(replay_task)[0]
    captured: list[AgentRequestedTest] = []

    def build(*, requests, **_kwargs):  # noqa: ANN001
        return requests, {}, []

    def execute(*, requests, **_kwargs):  # noqa: ANN001
        captured.extend(requests)
        return [{"test_case_id": "version-replay"}], []

    monkeypatch.setattr(orchestrator, "_build_requested_pocs", build)
    monkeypatch.setattr(orchestrator, "_execute_requested_tests", execute)
    executed, gaps = orchestrator._execute_version_replays(
        scan_id=target.id,
        task_id=replay_task.id,
        package_name=target.package_name or "",
        attempt=1,
        replay_candidates=[replay],
        entries=[new_entry],
        hypothesis_context=[
            {
                "id": target_hypothesis.id,
                "claim": target_hypothesis.claim,
                "category": target_hypothesis.category,
                "entry_point_ids": target_hypothesis.entry_point_ids,
            }
        ],
        hypothesis_ids={target_hypothesis.id},
        budget=TimeBudget.from_seconds(30),
        evidence_summaries=[],
        cancel_event=threading.Event(),
        device=SimpleNamespace(serial="test-device"),
    )

    assert executed == [{"test_case_id": "version-replay"}]
    assert gaps == []
    assert len(captured) == 1
    assert captured[0].poc is None
    assert captured[0].entry_point_id == new_entry.id
    assert captured[0].hypothesis_id == target_hypothesis.id


def test_proven_finding_becomes_pattern_but_match_stays_candidate(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    service = SecurityEvolutionService()
    with database.session_factory() as session:
        scan = _scan("1", "c")
        source_entry = _entry(scan)
        similar_entry = EntryPoint(
            scan=scan,
            kind="provider",
            name="io.apkscanner.versiontest.SimilarProvider",
            owner_component="io.apkscanner.versiontest.SimilarProvider",
            exported=True,
        )
        session.add_all([scan, source_entry, similar_entry])
        session.flush()
        service.build_snapshot(
            session,
            scan=scan,
            entries=[source_entry, similar_entry],
            code_index={
                **_code_index(),
                "io.apkscanner.versiontest.SimilarProvider": _code_index()[
                    "io.apkscanner.versiontest.SecretProvider"
                ],
            },
        )
        finding = Finding(
            scan=scan,
            dedupe_key="pattern-source",
            rule_id="AGENT-ENTRY-INVESTIGATION",
            source="opencode",
            title="Unauthorized provider read",
            description="Phone verified.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="reproduced_blackbox",
            entry_point_ids=[source_entry.id],
        )
        session.add(finding)
        session.flush()
        assert (
            service.create_pattern_from_finding(
                session,
                scan=scan,
                finding=finding,
            )
            is None
        )
        task = InvestigationTask(
            scan=scan,
            task_type="provider",
            target_entry_ids=[source_entry.id],
            hypotheses=["Third-party caller can read provider rows."],
        )
        session.add(task)
        session.flush()
        hypothesis = SecurityHypothesis(
            scan=scan,
            task_id=task.id,
            fingerprint="7" * 64,
            category="provider_access",
            claim="Third-party caller can read provider rows.",
            entry_point_ids=[source_entry.id],
            final_finding_id=finding.id,
        )
        session.add(hypothesis)
        session.flush()
        proof_evidence = Evidence(
            scan_id=scan.id,
            task_id=task.id,
            kind="blackbox.oracle_result",
            sha256="6" * 64,
            path="pattern-oracle-result.json",
            summary="Platform Oracle observed an unauthorized provider row.",
            metadata_json={"hypothesis_id": hypothesis.id},
        )
        session.add(proof_evidence)
        session.flush()
        rejected_attempts = [
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="pattern-failed-claim",
                status="failed",
                evidence_ids=[proof_evidence.id],
                harm_demonstrated=True,
            ),
            ProofAttempt(
                scan_id=scan.id,
                task_id=task.id,
                hypothesis_id=hypothesis.id,
                test_case_id="pattern-missing-receipt",
                status="proven",
                evidence_ids=["00000000-0000-0000-0000-000000000098"],
                harm_demonstrated=True,
            ),
        ]
        session.add_all(rejected_attempts)
        session.flush()
        finding.metadata_json = {
            "hypothesis_id": hypothesis.id,
            "proof_attempt_ids": [item.id for item in rejected_attempts],
        }
        assert (
            service.create_pattern_from_finding(
                session,
                scan=scan,
                finding=finding,
            )
            is None
        )
        attempt = ProofAttempt(
            scan_id=scan.id,
            task_id=task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="pattern-source-proof",
            status="proven",
            evidence_ids=[proof_evidence.id],
            harm_demonstrated=True,
            plan={
                "entry_point_id": source_entry.id,
                "oracle": {"impact": "unauthorized_data_access"},
            },
            oracle={"impact": "unauthorized_data_access"},
        )
        session.add(attempt)
        session.flush()
        finding.evidence_ids = [proof_evidence.id]
        finding.metadata_json = {
            "hypothesis_id": hypothesis.id,
            "proof_attempt_ids": [attempt.id],
        }
        pattern = service.create_pattern_from_finding(
            session,
            scan=scan,
            finding=finding,
        )
        assert pattern is not None
        matches = service.search_patterns(
            session,
            scan=scan,
            entries=[similar_entry],
        )
        assert len(matches) == 1
        assert matches[0].status == "candidate_match"
        assert session.query(Finding).count() == 1


def test_version_diff_tracks_security_resources_and_ignores_exact_reruns(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    service = SecurityEvolutionService()
    with database.session_factory() as session:
        baseline = _scan("10", "d")
        baseline.created_at = datetime.now(UTC) - timedelta(seconds=10)
        baseline.stats = {
            "analysis_profile": "profile-1",
            "archive_fingerprint": "old-archive",
            "security_resources": [
                {
                    "path": "assets/security_rules.json",
                    "size": 10,
                    "crc32": "11111111",
                    "content_sha256": "1" * 64,
                }
            ],
        }
        old_entry = _entry(baseline)
        session.add_all([baseline, old_entry])
        session.flush()
        service.build_snapshot(
            session,
            scan=baseline,
            entries=[old_entry],
            code_index=_code_index(),
        )

        target = _scan("11", "e")
        target.stats = {
            "analysis_profile": "profile-1",
            "archive_fingerprint": "new-archive",
            "security_resources": [
                {
                    "path": "assets/security_rules.json",
                    "size": 12,
                    "crc32": "22222222",
                    "content_sha256": "2" * 64,
                },
                {
                    "path": "res/xml/network_security_config.xml",
                    "size": 20,
                    "crc32": "33333333",
                    "content_sha256": "3" * 64,
                },
            ],
        }
        new_entry = _entry(target)
        session.add_all([target, new_entry])
        session.flush()
        target_snapshot = service.build_snapshot(
            session,
            scan=target,
            entries=[new_entry],
            code_index=_code_index(),
        )
        diff = service.build_version_diff(
            session,
            scan=target,
            snapshot=target_snapshot,
        )
        assert diff is not None
        resource_deltas = [
            item for item in diff.deltas if item.get("surface") == "security_resource"
        ]
        assert {item["category"] for item in resource_deltas} == {
            "security_resource_added",
            "security_resource_changed",
        }
        assert diff.summary["resource_delta_count"] == 2

        exact_rerun = _scan("11", "e")
        exact_entry = _entry(exact_rerun)
        session.add_all([exact_rerun, exact_entry])
        session.flush()
        exact_snapshot = service.build_snapshot(
            session,
            scan=exact_rerun,
            entries=[exact_entry],
            code_index=_code_index(),
        )
        assert (
            service.build_version_diff(
                session,
                scan=exact_rerun,
                snapshot=exact_snapshot,
            )
            is None
        )


def test_version_diff_prioritizes_new_candidate_attack_chains(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    service = SecurityEvolutionService()

    def surface(scan: Scan, fingerprints: list[str]) -> EntryPoint:
        return EntryPoint(
            scan=scan,
            kind="static_surface",
            name="static://capability_delegation_boundary",
            owner_component="static://capability_delegation_boundary",
            exported=False,
            metadata_json={
                "static_review_family": "capability_delegation_boundary",
                "static_review_rule_ids": ["CHAIN-ANDROID-CAPABILITY-DELEGATION"],
                "static_review_attack_chains": [
                    {
                        "fingerprint": fingerprint,
                        "chain_kind": "nested_intent_redirection",
                    }
                    for fingerprint in fingerprints
                ],
            },
        )

    code_index = {
        "static://capability_delegation_boundary": {
            "status": "static_signal_source_available",
            "anchors": [{"content": "Intent nested; startActivity(nested);"}],
        }
    }
    with database.session_factory() as session:
        baseline = _scan("20", "f")
        old_surface = surface(baseline, [])
        session.add_all([baseline, old_surface])
        session.flush()
        service.build_snapshot(
            session,
            scan=baseline,
            entries=[old_surface],
            code_index=code_index,
        )

        target = _scan("21", "0")
        new_surface = surface(target, ["a" * 64])
        session.add_all([target, new_surface])
        session.flush()
        snapshot = service.build_snapshot(
            session,
            scan=target,
            entries=[new_surface],
            code_index=code_index,
        )
        diff = service.build_version_diff(session, scan=target, snapshot=snapshot)

        assert diff is not None
        delta = next(item for item in diff.deltas if item.get("target_entry_id"))
        assert delta["category"] == "security_surface_expanded"
        assert delta["changes"] == ["candidate_attack_chains_added"]
        assert delta["added_chain_fingerprints"] == ["a" * 64]


def test_attack_chain_engine_upgrade_is_not_an_app_security_regression() -> None:
    def fact(entry_id: str, engine: str, fingerprint: str) -> dict:
        return {
            "entry_id": entry_id,
            "stable_key": "static_surface:static://web_content_boundary",
            "manifest": {
                "kind": "static_surface",
                "name": "static://web_content_boundary",
                "owner_component": "static://web_content_boundary",
                "exported": False,
                "permission": None,
                "permission_protection": None,
                "static_surface": {
                    "chain_fingerprints": [fingerprint],
                    "chain_engine_versions": [engine],
                },
            },
            "code": {"direct_hash": "same", "guards": [], "sinks": []},
        }

    deltas = SecurityEvolutionService._diff_entries(
        [fact("old", "bounded-android-chain-v1", "a" * 64)],
        [fact("new", "bounded-android-chain-v2", "b" * 64)],
        [
            {
                "baseline_entry_id": "old",
                "target_entry_id": "new",
                "baseline_key": "static_surface:static://web_content_boundary",
                "target_key": "static_surface:static://web_content_boundary",
                "reason": "stable_entry_identity",
                "score": 100,
            }
        ],
    )

    assert deltas[0]["category"] == "implementation_changed"
    assert deltas[0]["changes"] == ["attack_chain_engine_changed"]
    assert deltas[0]["added_chain_fingerprints"] == []
    assert deltas[0]["removed_chain_fingerprints"] == []


def test_application_release_and_regression_occurrence_are_stable_across_scans(
    settings,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    service = SecurityEvolutionService()
    with database.session_factory() as session:
        baseline = _scan("30", "1")
        baseline_entry = _entry(baseline)
        session.add_all([baseline, baseline_entry])
        session.flush()
        baseline_snapshot = service.build_snapshot(
            session,
            scan=baseline,
            entries=[baseline_entry],
            code_index=_code_index(),
        )
        release = session.scalar(
            select(ApplicationRelease).where(ApplicationRelease.scan_id == baseline.id)
        )
        assert release is not None
        assert release.identity_status == "verified"
        stable_key = baseline_snapshot.payload["entries"][0]["stable_key"]
        case = VulnerabilityCase(
            application_id=release.application_id,
            case_key="LOCAL-30",
            fingerprint="a" * 64,
            identity_json={"entry_stable_keys": [stable_key]},
            title="Provider authorization bypass",
            harm="An untrusted app can read protected data.",
            severity="high",
            minimum_proof="dynamic",
        )
        session.add(case)
        session.flush()

        target = _scan("31", "2")
        target_entry = _entry(target)
        session.add_all([target, target_entry])
        session.flush()
        service.build_snapshot(
            session,
            scan=target,
            entries=[target_entry],
            code_index=_code_index(),
        )
        occurrence = session.scalar(
            select(VulnerabilityOccurrence).where(
                VulnerabilityOccurrence.case_id == case.id,
                VulnerabilityOccurrence.scan_id == target.id,
            )
        )
        assert occurrence is not None
        assert occurrence.analysis_status == "pending_revalidation"
        assert occurrence.proof_level == "none"
        assert occurrence.match_quality == "strong"
        applications = list(session.scalars(select(ApplicationRecord)))
        releases = list(session.scalars(select(ApplicationRelease)))
        assert len(applications) == 1
        assert len(releases) == 2
