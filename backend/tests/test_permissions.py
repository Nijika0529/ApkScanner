from __future__ import annotations

import os
import stat
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest
from apkscanner.core import permissions
from apkscanner.core.db import Database
from apkscanner.core.models import Finding, Scan
from apkscanner.platform.artifacts import ArtifactStore
from fastapi import UploadFile
from sqlalchemy import select, text


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable")
def test_existing_data_directories_and_artifacts_are_hardened(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    configured_directories = [
        settings.data_dir,
        settings.data_dir / "artifacts",
        settings.data_dir / "workspaces",
        settings.data_dir / "evidence",
        settings.data_dir / "reports",
    ]
    for directory in configured_directories:
        directory.chmod(0o755)

    settings.ensure_directories()
    assert {_mode(directory) for directory in configured_directories} == {0o700}

    preexisting_directory = settings.data_dir / "evidence" / "aa"
    preexisting_directory.mkdir()
    preexisting_path = preexisting_directory / f"{'a' * 64}.json"
    preexisting_path.write_text('{"private": true}', encoding="utf-8")
    preexisting_directory.chmod(0o755)
    preexisting_path.chmod(0o644)
    existing_workspace = settings.data_dir / "workspaces" / "existing-scan"
    existing_workspace.mkdir()
    existing_workspace.chmod(0o755)

    store = ArtifactStore(settings)
    assert _mode(preexisting_directory) == 0o700
    assert _mode(preexisting_path) == 0o600
    assert _mode(existing_workspace) == 0o700

    digest, path = store.put_json("evidence", {"private": "proof"})
    path.parent.chmod(0o755)
    path.chmod(0o644)
    settings.data_dir.joinpath("evidence").chmod(0o755)

    repeated_digest, repeated_path = store.put_json("evidence", {"private": "proof"})

    assert repeated_digest == digest
    assert repeated_path == path
    assert _mode(settings.data_dir / "evidence") == 0o700
    assert _mode(path.parent) == 0o700
    assert _mode(path) == 0o600


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable")
async def test_uploaded_apk_is_stored_with_private_permissions(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    upload = UploadFile(file=BytesIO(b"private-apk"), filename="private.apk")

    _digest, path, _size = await ArtifactStore(settings).save_upload(upload)

    assert _mode(path.parent) == 0o700
    assert _mode(path) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable")
def test_existing_sqlite_database_and_sidecars_are_hardened(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    database_path = settings.data_dir / "test.db"
    database_path.chmod(0o644)

    reopened = Database(settings)
    reopened.create_all()

    assert _mode(database_path) == 0o600
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{database_path}{suffix}")
        if sidecar.exists():
            assert _mode(sidecar) == 0o600
    database.engine.dispose()
    reopened.engine.dispose()


@pytest.mark.skipif(os.name != "posix", reason="symbolic-link behavior is platform-specific")
def test_private_paths_reject_symbolic_links(settings, tmp_path: Path) -> None:  # noqa: ANN001
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    outside_directory = tmp_path / "outside-workspaces"
    outside_directory.mkdir()
    workspace_link = settings.data_dir / "workspaces"
    workspace_link.symlink_to(outside_directory, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        settings.ensure_directories()

    outside_database = tmp_path / "outside.db"
    outside_database.write_bytes(b"")
    database_link = settings.data_dir / "linked.db"
    database_link.symlink_to(outside_database)
    linked_settings = replace(
        settings,
        database_url=f"sqlite:///{database_link}",
    )
    with pytest.raises(ValueError, match="regular file"):
        Database(linked_settings)


def test_sqlite_read_only_uri_does_not_request_wal(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    writable = Database(settings)
    writable.create_all()
    writable.engine.dispose()

    database_path = settings.data_dir / "test.db"
    read_only = Database(
        replace(
            settings,
            database_url=f"sqlite:///file:{database_path}?mode=ro&uri=true",
        )
    )
    with read_only.engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1
    read_only.engine.dispose()


def test_database_reopens_only_legacy_auto_closed_findings(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    legacy_metadata = {
        "closed_by_static_reachability": {
            "threat_model": "ordinary_app_uid",
            "entry_decisions": [{"reason_code": "strong_permission_guard"}],
        }
    }
    with database.session_factory() as session:
        scan = Scan(
            status="final",
            filename="legacy.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "legacy.apk"),
        )
        session.add(scan)
        session.flush()
        session.add_all(
            [
                Finding(
                    scan_id=scan.id,
                    dedupe_key="auto-closed",
                    rule_id="TEST-AUTO",
                    source="builtin",
                    title="Auto closed",
                    description="Legacy platform disposition.",
                    remediation="Review the complete chain.",
                    masvs="MASVS-PLATFORM",
                    severity="high",
                    confidence="medium",
                    status="false_positive",
                    metadata_json=legacy_metadata,
                ),
                Finding(
                    scan_id=scan.id,
                    dedupe_key="user-reviewed",
                    rule_id="TEST-REVIEWED",
                    source="builtin",
                    title="User reviewed",
                    description="Explicit user disposition.",
                    remediation="No action.",
                    masvs="MASVS-PLATFORM",
                    severity="info",
                    confidence="high",
                    status="false_positive",
                    review_note="人工确认误报",
                    metadata_json=legacy_metadata,
                ),
            ]
        )
        session.commit()

    database.create_all()

    with database.session_factory() as session:
        findings = {
            finding.dedupe_key: finding
            for finding in session.scalars(select(Finding))
        }
    reopened = findings["auto-closed"]
    reviewed = findings["user-reviewed"]
    assert reopened.status == "candidate"
    assert "closed_by_static_reachability" not in reopened.metadata_json
    assessment = reopened.metadata_json["direct_reachability_assessment"]
    assert assessment["scope"] == "ordinary_app_direct_invocation_only"
    assert assessment["indirect_chain_paths_evaluated"] is False
    assert reviewed.status == "false_positive"
    assert reviewed.review_note == "人工确认误报"


def test_unsupported_permission_hardening_degrades_without_failure(
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    target = tmp_path / "private"
    target.mkdir()

    def unsupported(*_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
        raise NotImplementedError

    monkeypatch.setattr(permissions.os, "chmod", unsupported)
    permissions.harden_permissions(target, permissions.PRIVATE_DIRECTORY_MODE)
