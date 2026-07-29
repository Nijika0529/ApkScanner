from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.models import EntryPoint, InvestigationTask, ProofAttempt, Scan
from apkscanner.orchestrator import ScanOrchestrator
from apkscanner.poc import PocBuilder, PocBuildResult
from apkscanner.schemas import AgentPocSpec, AgentRequestedTest
from apkscanner.tools import CommandResult, TimeBudget, ToolRunner


def poc_spec() -> AgentPocSpec:
    return AgentPocSpec(
        project_path="poc/provider_probe",
        package_name="io.apkscanner.poc.providerprobe",
        launch_component=".MainActivity",
        log_tag="APKSCANNER_POC",
        timeout_seconds=30,
    )


def write_poc_project(workspace: Path) -> Path:
    project = workspace / "poc" / "provider_probe"
    source = project / "src" / "io" / "apkscanner" / "poc" / "providerprobe"
    source.mkdir(parents=True)
    (project / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="io.apkscanner.poc.providerprobe">
<application>
<activity android:name=".MainActivity" android:exported="true" />
</application>
</manifest>""",
        encoding="utf-8",
    )
    (source / "MainActivity.java").write_text(
        """package io.apkscanner.poc.providerprobe;
public final class MainActivity extends android.app.Activity {}""",
        encoding="utf-8",
    )
    return project


def test_poc_builder_accepts_only_source_projects_under_workspace(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))
    validated, sources, manifest = builder._validate_project(workspace, poc_spec())
    assert validated == project
    assert manifest.name == "AndroidManifest.xml"
    assert [item.name for item in sources] == ["MainActivity.java"]

    (project / "build.gradle").write_text("ignored build hook", encoding="utf-8")
    (project / "build").mkdir()
    (project / "build" / "MainActivity.class").write_bytes(b"ignored")
    validated, sources, manifest = builder._validate_project(workspace, poc_spec())
    assert validated == project
    assert manifest.name == "AndroidManifest.xml"
    assert [item.name for item in sources] == ["MainActivity.java"]


def test_poc_builder_recovers_a_unique_project_path_by_package(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))
    stale_spec = poc_spec().model_copy(
        update={"project_path": "poc/model_wrote_the_wrong_directory"}
    )

    validated, sources, manifest = builder._validate_project(workspace, stale_spec)

    assert validated == project
    assert manifest == project / "AndroidManifest.xml"
    assert [item.name for item in sources] == ["MainActivity.java"]


def test_poc_build_failure_includes_tool_diagnostic() -> None:
    result = CommandResult(
        ["aapt2", "link"],
        1,
        "",
        "AndroidManifest.xml:7: error: resource style/Missing not found.",
    )

    assert PocBuilder._command_failure("poc.build.aapt2", result) == (
        "poc.build.aapt2 failed with exit 1: "
        "AndroidManifest.xml:7: error: resource style/Missing not found."
    )


def test_poc_builder_uses_legacy_dx_when_d8_is_unavailable(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    sdk = tmp_path / "android-sdk"
    build_tools = sdk / "build-tools" / "debian"
    platform = sdk / "platforms" / "android-23"
    build_tools.mkdir(parents=True)
    platform.mkdir(parents=True)
    dx = build_tools / "dx"
    dx.write_text("#!/bin/sh\n", encoding="utf-8")
    (platform / "android.jar").write_bytes(b"android")
    configured = replace(
        settings,
        android_sdk_root=sdk,
        device_android_api=23,
    )

    builder = PocBuilder(configured, ToolRunner(), ArtifactStore(configured))

    assert builder._dex_tool() == ("dx", dx)


def test_personal_lab_ingests_an_agent_built_prebuilt_apk(
    settings,
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    workspace = tmp_path / "workspace"
    apk = workspace / "poc" / "provider_probe" / "build" / "probe.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"signed-agent-apk")

    class VerifyingRunner:
        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001, ANN205
            stdout = (
                "package: name='io.apkscanner.poc.providerprobe'\n"
                "launchable-activity: name='io.apkscanner.poc.providerprobe.MainActivity'\n"
                if "badging" in argv
                else "Verified"
            )
            return CommandResult(argv, 0, stdout, "")

    builder = PocBuilder(
        settings,
        VerifyingRunner(),  # type: ignore[arg-type]
        ArtifactStore(settings),
    )
    monkeypatch.setattr(
        builder,
        "capability",
        lambda: {
            "available": True,
            "source_build_available": True,
        },
    )
    monkeypatch.setattr(builder, "_required_tool", lambda name: name)
    spec = poc_spec().model_copy(
        update={"prebuilt_apk_path": "poc/provider_probe/build/probe.apk"}
    )

    result = builder.build(workspace, spec)

    assert result.ok is True
    assert result.apk_path is not None and result.apk_path.is_file()
    assert result.metadata["platform_managed_build"] is False
    assert [kind for kind, _result, _metadata in result.commands] == [
        "poc.prebuilt.verify_signature",
        "poc.prebuilt.inspect_manifest",
    ]


def test_platform_builds_poc_before_device_queue_and_records_artifact(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    workspace = settings.data_dir / "workspaces" / "scan" / "agent"
    workspace.mkdir(parents=True)
    write_poc_project(workspace)
    apk_path = settings.data_dir / "built.apk"
    apk_path.write_bytes(b"APK")
    source_path = settings.data_dir / "source.zip"
    source_path.write_bytes(b"source")
    with database.session_factory() as session:
        scan = Scan(
            id="00000000-0000-0000-0000-000000000101",
            status="investigating",
            filename="poc.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "target.apk"),
        )
        entry = EntryPoint(
            id="00000000-0000-0000-0000-000000000102",
            scan=scan,
            kind="provider",
            name="com.example.Provider",
            exported=True,
        )
        task = InvestigationTask(
            id="00000000-0000-0000-0000-000000000103",
            scan=scan,
            task_type="component",
            status="running",
            target_entry_ids=[entry.id],
            hypotheses=["A provider operation has unauthorized impact."],
        )
        session.add_all([scan, entry, task])
        session.commit()

    orchestrator = ScanOrchestrator(settings, database, store)
    hypothesis = orchestrator.hypothesis_ledger.ensure_task_hypotheses(task)[0]
    request = AgentRequestedTest(
        hypothesis_id=hypothesis.id,
        entry_point_id=entry.id,
        state="guest",
        uri=None,
        extras={},
        rationale="A custom ordinary-UID caller is required.",
        poc=poc_spec(),
    )
    monkeypatch.setattr(
        orchestrator.poc_builder,
        "build",
        lambda *_args, **_kwargs: PocBuildResult(
            ok=True,
            apk_sha256="b" * 64,
            apk_path=apk_path,
            source_sha256="c" * 64,
            source_path=source_path,
            metadata={
                "apk_sha256": "b" * 64,
                "apk_path": str(apk_path),
                "source_sha256": "c" * 64,
                "source_path": str(source_path),
            },
        ),
    )
    evidence: list[dict] = []
    accepted, artifacts, gaps = orchestrator._build_requested_pocs(
        scan_id=scan.id,
        task_id=task.id,
        workspace=workspace,
        requests=[request],
        evidence_summaries=evidence,
        cancel_event=threading.Event(),
    )
    assert accepted == [request]
    assert not gaps
    assert artifacts[orchestrator._poc_request_key(request)].apk_sha256 == "b" * 64
    assert any(item["kind"] == "poc.build_artifact" for item in evidence)


def test_poc_execution_is_correlated_into_the_hypothesis_proof(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="target.apk",
            artifact_sha256="d" * 64,
            artifact_path=str(settings.data_dir / "target.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="provider",
            name="com.example.Provider",
            exported=True,
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="running",
            hypotheses=["A provider operation has unauthorized impact."],
        )
        session.add_all([scan, entry, task])
        session.flush()
        task.target_entry_ids = [entry.id]
        session.commit()

    orchestrator = ScanOrchestrator(settings, database, store)
    hypothesis = orchestrator.hypothesis_ledger.ensure_task_hypotheses(task)[0]
    request = AgentRequestedTest(
        hypothesis_id=hypothesis.id,
        entry_point_id=entry.id,
        state="guest",
        uri=None,
        extras={},
        rationale="Execute the custom caller.",
        poc=poc_spec(),
    )
    apk_path = settings.data_dir / "agent-poc.apk"
    apk_path.write_bytes(b"APK")
    artifact = PocBuildResult(
        ok=True,
        apk_sha256="e" * 64,
        apk_path=apk_path,
        source_sha256="f" * 64,
        source_path=settings.data_dir / "source.zip",
        metadata={"build_evidence_id": "build-evidence"},
    )
    monkeypatch.setattr(
        orchestrator.device,
        "reset_session",
        lambda *_args, **_kwargs: [
            ("device.clear", CommandResult(["adb"], 0, "", ""), {})
        ],
    )
    monkeypatch.setattr(
        orchestrator.device,
        "execute_poc",
        lambda *_args, test_case_id=None, **_kwargs: SimpleNamespace(
            commands=[
                (
                    "blackbox.poc_launch",
                    CommandResult(["adb"], 0, "", ""),
                    {"request_id": "nonce", "test_case_id": test_case_id},
                ),
                (
                    "blackbox.poc_logcat",
                    CommandResult(["adb"], 0, "result", ""),
                    {
                        "request_id": "nonce",
                        "request_observed": True,
                        "poc_success": True,
                        "poc_claimed_security_impact": True,
                        "test_case_id": test_case_id,
                    },
                ),
            ]
        ),
    )
    evidence: list[dict] = []
    executed, gaps = orchestrator._execute_requested_tests(
        scan_id=scan.id,
        task_id=task.id,
        package_name="com.example.target",
        entries=[entry],
        requests=[request],
        budget=TimeBudget.from_seconds(30),
        evidence_summaries=evidence,
        round_index=1,
        poc_artifacts={orchestrator._poc_request_key(request): artifact},
    )
    assert not gaps
    assert len(executed) == 1
    with database.session_factory() as session:
        proof = session.get(ProofAttempt, executed[0]["proof_attempt_id"])
        assert proof is not None
        assert proof.status == "inconclusive"
        assert proof.oracle["poc_succeeded"] is True
        assert proof.harm_demonstrated is False
