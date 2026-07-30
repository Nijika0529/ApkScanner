from __future__ import annotations

import hashlib
import zipfile
from datetime import UTC, datetime, timedelta

from apkscanner.db import Database
from apkscanner.models import (
    EntryPoint,
    Evidence,
    Finding,
    InvestigationTask,
    ProofAttempt,
    Scan,
    SecurityHypothesis,
)
from apkscanner.versioning import SecurityEvolutionService


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
        attempt = ProofAttempt(
            scan_id=baseline.id,
            task_id=old_task.id,
            hypothesis_id=hypothesis.id,
            test_case_id="old-proof",
            status="proven",
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
            metadata_json={"proof_attempt_ids": [attempt.id]},
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
