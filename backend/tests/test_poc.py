from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest
from apkscanner.artifacts import ArtifactStore
from apkscanner.db import Database
from apkscanner.models import EntryPoint, InvestigationTask, ProofAttempt, Scan
from apkscanner.orchestrator import ScanOrchestrator, _LiveProofContext
from apkscanner.poc import PocBuilder, PocBuildResult
from apkscanner.schemas import (
    AgentOracleSpec,
    AgentPocSpec,
    AgentProofReplay,
    AgentRequestedTest,
)
from apkscanner.tools import CommandResult, TimeBudget, ToolRunner


def poc_spec() -> AgentPocSpec:
    return AgentPocSpec(
        project_path="poc/provider_probe",
        package_name="io.apkscanner.poc.providerprobe",
        launch_component=".MainActivity",
        log_tag="APKSCANNER_POC",
        timeout_seconds=30,
    )


def test_live_proof_replay_requires_an_explicit_hypothesis() -> None:
    with pytest.raises(ValueError, match="hypothesis_id"):
        AgentProofReplay.model_validate(
            {
                "oracle": {
                    "kind": "log_contains",
                    "expected_text": "impact",
                    "impact": "unauthorized_data_access",
                },
                "rationale": "The platform must not guess proof ownership.",
                "poc": poc_spec().model_dump(mode="json"),
            }
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


def test_poc_builder_falls_back_to_highest_installed_compile_platform(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    sdk = tmp_path / "sdk"
    for api in (23, 34):
        platform = sdk / "platforms" / f"android-{api}"
        platform.mkdir(parents=True)
        (platform / "android.jar").write_bytes(str(api).encode())
    builder = PocBuilder(
        replace(settings, android_sdk_root=sdk, poc_compile_api=36),
        ToolRunner(),
        ArtifactStore(settings),
    )

    assert builder._android_jar() == sdk / "platforms" / "android-34" / "android.jar"


def test_poc_builder_accepts_only_source_projects_under_workspace(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))
    validated, sources, manifest, effective = builder._validate_project(
        workspace,
        poc_spec(),
    )
    assert validated == project
    assert manifest.name == "AndroidManifest.xml"
    assert [item.name for item in sources] == ["MainActivity.java"]
    assert effective == poc_spec()

    (project / "build.gradle").write_text("ignored build hook", encoding="utf-8")
    (project / "build").mkdir()
    (project / "build" / "MainActivity.class").write_bytes(b"ignored")
    validated, sources, manifest, effective = builder._validate_project(
        workspace,
        poc_spec(),
    )
    assert validated == project
    assert manifest.name == "AndroidManifest.xml"
    assert [item.name for item in sources] == ["MainActivity.java"]
    assert effective == poc_spec()


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

    validated, sources, manifest, effective = builder._validate_project(
        workspace,
        stale_spec,
    )

    assert validated == project
    assert manifest == project / "AndroidManifest.xml"
    assert [item.name for item in sources] == ["MainActivity.java"]
    assert effective.package_name == "io.apkscanner.poc.providerprobe"


def test_poc_builder_uses_safe_manifest_package_as_source_of_truth(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    write_poc_project(workspace)
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))
    mismatched = poc_spec().model_copy(
        update={"package_name": "io.apkscanner.poc.modelguess"}
    )

    _project, _sources, _manifest, effective = builder._validate_project(
        workspace,
        mismatched,
    )

    assert effective.package_name == "io.apkscanner.poc.providerprobe"


def test_poc_builder_uses_unique_manifest_launcher_as_source_of_truth(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    manifest = project / "AndroidManifest.xml"
    manifest.write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="io.apkscanner.poc.providerprobe">
<application>
<activity android:name=".MainActivity" android:exported="true">
<intent-filter>
<action android:name="android.intent.action.MAIN" />
<category android:name="android.intent.category.LAUNCHER" />
</intent-filter>
</activity>
</application>
</manifest>""",
        encoding="utf-8",
    )
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))
    mismatched = poc_spec().model_copy(
        update={"launch_component": ".ModelGuessActivity"}
    )

    _project, _sources, _manifest, effective = builder._validate_project(
        workspace,
        mismatched,
    )

    assert (
        effective.launch_component
        == "io.apkscanner.poc.providerprobe.MainActivity"
    )


def test_poc_builder_repairs_manifest_launcher_to_match_java_activity(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    source = next((project / "src").rglob("MainActivity.java"))
    source.write_text(
        """package io.apkscanner.poc.actual;
public final class MainActivity extends android.app.Activity {}""",
        encoding="utf-8",
    )
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))

    _project, _sources, manifest, effective = builder._validate_project(
        workspace,
        poc_spec(),
    )
    output = tmp_path / "output"
    output.mkdir()
    built_manifest = builder._build_manifest(
        manifest,
        output,
        package_name=effective.package_name,
        launch_component=effective.launch_component,
    )
    activity = ElementTree.parse(built_manifest).getroot().find(
        "application/activity"
    )

    assert effective.launch_component == "io.apkscanner.poc.actual.MainActivity"
    assert activity is not None
    assert (
        activity.get("{http://schemas.android.com/apk/res/android}name")
        == "io.apkscanner.poc.actual.MainActivity"
    )


def test_poc_builder_allows_launcher_in_a_sibling_controlled_poc_package(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    manifest = project / "AndroidManifest.xml"
    manifest.write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="io.apkscanner.poc.commandservice">
<application>
<activity android:name="io.apkscanner.poc.providerprobe.MainActivity"
android:exported="true">
<intent-filter>
<action android:name="android.intent.action.MAIN" />
<category android:name="android.intent.category.LAUNCHER" />
</intent-filter>
</activity>
</application>
</manifest>""",
        encoding="utf-8",
    )
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))

    _project, _sources, _manifest, effective = builder._validate_project(
        workspace,
        poc_spec(),
    )

    assert effective.package_name == "io.apkscanner.poc.commandservice"
    assert (
        effective.launch_component
        == "io.apkscanner.poc.providerprobe.MainActivity"
    )


def test_poc_builder_uses_unique_java_log_tag_as_source_of_truth(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = write_poc_project(workspace)
    source = next((project / "src").rglob("MainActivity.java"))
    source.write_text(
        """package io.apkscanner.poc.providerprobe;
public final class MainActivity extends android.app.Activity {
private static final String TAG = "PROVIDER_RESULT";
}""",
        encoding="utf-8",
    )
    builder = PocBuilder(settings, ToolRunner(), ArtifactStore(settings))
    requested = poc_spec().model_copy(update={"log_tag": "MODEL_GUESS"})

    _project, _sources, _manifest, effective = builder._validate_project(
        workspace,
        requested,
    )

    assert effective.log_tag == "PROVIDER_RESULT"


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


def test_source_build_drops_package_visibility_queries_from_legacy_manifest(
    tmp_path,
) -> None:
    source = tmp_path / "source.xml"
    source.write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="io.apkscanner.poc.providerprobe">
<queries><package android:name="io.apkscanner.vulntest" /></queries>
<application><activity android:name=".MainActivity" /></application>
</manifest>""",
        encoding="utf-8",
    )
    output = tmp_path / "build"
    output.mkdir()

    normalized = PocBuilder._build_manifest(source, output, compile_api=23)

    text = normalized.read_text(encoding="utf-8")
    assert "<queries>" not in text
    assert "MainActivity" in text


def test_source_build_keeps_queries_and_exports_launcher_on_modern_android(
    tmp_path,
) -> None:
    source = tmp_path / "source.xml"
    source.write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="io.apkscanner.poc.providerprobe">
<queries><package android:name="io.apkscanner.vulntest" /></queries>
<application><activity android:name=".MainActivity" android:exported="false" /></application>
</manifest>""",
        encoding="utf-8",
    )
    output = tmp_path / "build"
    output.mkdir()

    normalized = PocBuilder._build_manifest(
        source,
        output,
        compile_api=36,
        package_name="io.apkscanner.poc.providerprobe",
        launch_component=".MainActivity",
    )

    root = ElementTree.parse(normalized).getroot()
    activity = root.find("application/activity")
    assert root.find("queries") is not None
    assert activity is not None
    assert (
        activity.get(
            "{http://schemas.android.com/apk/res/android}exported"
        )
        == "true"
    )


def test_source_build_drops_override_annotations_for_legacy_android_jar(
    tmp_path,
) -> None:
    source = tmp_path / "MainActivity.java"
    source.write_text(
        """class MainActivity {
    @Override
    public void onNullBinding() {}
}""",
        encoding="utf-8",
    )
    output = tmp_path / "build"
    output.mkdir()

    normalized = PocBuilder._build_sources([source], output)

    text = normalized[0].read_text(encoding="utf-8")
    assert "@Override" not in text
    assert "onNullBinding" in text


def test_source_build_makes_fallback_request_id_effectively_final(
    tmp_path,
) -> None:
    source = tmp_path / "MainActivity.java"
    source.write_text(
        """class MainActivity {
    void run() {
        String requestId = getIntentValue();
        if (requestId == null) {
            requestId = "unknown";
        }
        new Thread(() -> use(requestId)).start();
    }
}""",
        encoding="utf-8",
    )
    output = tmp_path / "build"
    output.mkdir()

    normalized = PocBuilder._build_sources([source], output)

    text = normalized[0].read_text(encoding="utf-8")
    assert "String requestIdCandidate = getIntentValue();" in text
    assert "requestIdCandidate = \"unknown\";" in text
    assert "final String requestId = requestIdCandidate;" in text


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


def test_poc_builder_sorts_build_tools_as_versions_and_honors_pin(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    sdk = tmp_path / "android-sdk"
    for version in ("9.0.0", "34.0.0"):
        tool = sdk / "build-tools" / version / "aapt2"
        tool.parent.mkdir(parents=True)
        tool.write_text("#!/bin/sh\n", encoding="utf-8")

    configured = replace(settings, android_sdk_root=sdk)
    builder = PocBuilder(configured, ToolRunner(), ArtifactStore(configured))
    assert builder._tool_candidates("aapt2")[0].parent.name == "34.0.0"

    pinned = replace(configured, android_build_tools_version="9.0.0")
    pinned_builder = PocBuilder(pinned, ToolRunner(), ArtifactStore(pinned))
    assert pinned_builder._tool_candidates("aapt2") == [
        sdk / "build-tools" / "9.0.0" / "aapt2"
    ]


def test_poc_sdk_roles_are_separate_and_legacy_dx_raises_minimum(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    sdk = tmp_path / "android-sdk"
    tool_dir = sdk / "build-tools" / "34.0.0"
    platform = sdk / "platforms" / "android-36"
    tool_dir.mkdir(parents=True)
    platform.mkdir(parents=True)
    for name in ("aapt2", "apksigner", "zipalign", "dx"):
        (tool_dir / name).write_text("#!/bin/sh\n", encoding="utf-8")
    (platform / "android.jar").write_bytes(b"android")
    configured = replace(
        settings,
        android_sdk_root=sdk,
        device_android_api=36,
        poc_compile_api=36,
        poc_min_api=21,
        poc_target_api=35,
    )

    builder = PocBuilder(configured, ToolRunner(), ArtifactStore(configured))

    assert builder._compile_api() == 36
    assert builder._target_api() == 35
    assert builder._effective_min_api() == 26


def test_poc_builder_retries_only_aapt2_resource_table_compatibility_errors(
    settings,
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    write_poc_project(workspace)
    android_jar = tmp_path / "android.jar"
    android_jar.write_bytes(b"android")
    first = tmp_path / "aapt2-36"
    second = tmp_path / "aapt2-34"
    dx = tmp_path / "dx"
    for tool in (first, second, dx):
        tool.write_text("#!/bin/sh\n", encoding="utf-8")

    class RetryRunner:
        calls: list[list[str]] = []

        def run(self, argv, **_kwargs):  # noqa: ANN001
            self.calls.append(argv)
            if argv[0] == str(first):
                return CommandResult(
                    argv,
                    1,
                    "",
                    "LoadedArsc.cpp:94 RES_TABLE_TYPE_TYPE entry offsets "
                    "overlap actual entry data",
                )
            if argv[0] == str(second):
                return CommandResult(argv, 0, "", "")
            return CommandResult(argv, 1, "", "javac source error")

    runner = RetryRunner()
    builder = PocBuilder(settings, runner, ArtifactStore(settings))  # type: ignore[arg-type]
    monkeypatch.setattr(
        builder,
        "capability",
        lambda: {"available": True, "source_build_available": True},
    )
    monkeypatch.setattr(builder, "_android_jar", lambda: android_jar)
    monkeypatch.setattr(builder, "_compile_api", lambda: 36)
    monkeypatch.setattr(builder, "_dex_tool", lambda: ("dx", dx))
    original_candidates = builder._tool_candidates
    monkeypatch.setattr(
        builder,
        "_tool_candidates",
        lambda name: [first, second] if name == "aapt2" else original_candidates(name),
    )
    monkeypatch.setattr(builder, "_required_tool", lambda name: name)

    result = builder.build(workspace, poc_spec())

    assert result.ok is False
    assert [kind for kind, _result, _metadata in result.commands[:2]] == [
        "poc.build.aapt2",
        "poc.build.aapt2",
    ]
    assert result.commands[0][2]["tool_path"] == str(first)
    assert result.commands[1][2]["tool_path"] == str(second)
    assert result.commands[1][2]["compile_api"] == 36
    assert result.error is not None and "poc.build.javac" in result.error


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


def test_live_proof_replay_requires_harm_hypothesis_and_deduplicates(
    settings,
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    store = ArtifactStore(settings)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    write_poc_project(workspace)
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="target.apk",
            package_name="com.example.target",
            artifact_sha256="1" * 64,
            artifact_path=str(tmp_path / "target.apk"),
        )
        entry = EntryPoint(
            scan=scan,
            kind="activity",
            name="com.example.target.MainActivity",
            exported=True,
        )
        task = InvestigationTask(
            scan=scan,
            task_type="component",
            status="running",
            target_entry_ids=[],
            hypotheses=["An ordinary app can trigger unauthorized behavior."],
        )
        session.add_all([scan, entry, task])
        session.flush()
        task.target_entry_ids = [entry.id]
        session.commit()
        scan_id, task_id, entry_id = scan.id, task.id, entry.id

    orchestrator = ScanOrchestrator(settings, database, store)
    hypothesis = orchestrator.hypothesis_ledger.ensure_task_hypotheses(task)[0]
    built_apk = tmp_path / "poc.apk"
    built_apk.write_bytes(b"APK")
    artifact = PocBuildResult(
        ok=True,
        apk_sha256="2" * 64,
        apk_path=built_apk,
        source_sha256="3" * 64,
        source_path=tmp_path / "source.zip",
        metadata={},
    )
    captured: list[AgentRequestedTest] = []

    def build(*, requests, **_kwargs):  # noqa: ANN001
        captured.extend(requests)
        return requests, {
            orchestrator._poc_request_key(requests[0]): artifact
        }, []

    def execute(**kwargs):  # noqa: ANN003, ANN202
        kwargs["evidence_summaries"].append(
            {"id": "evidence-live", "kind": "blackbox.poc_logcat"}
        )
        return [{"test_case_id": "agent-r1-1"}], []

    monkeypatch.setattr(orchestrator, "_build_requested_pocs", build)
    monkeypatch.setattr(orchestrator, "_execute_requested_tests", execute)
    monkeypatch.setattr(
        orchestrator.hypothesis_ledger,
        "task_proven_hypotheses",
        lambda _task_id: {hypothesis.id: ["evidence-live"]},
    )
    evidence: list[dict] = []
    context = _LiveProofContext(
        token="secret-token",
        scan_id=scan_id,
        task_id=task_id,
        package_name="com.example.target",
        workspace=workspace,
        entries=[entry],
        default_entry_id=entry.id,
        hypotheses=[
            {
                "id": hypothesis.id,
                "claim": hypothesis.claim,
                "impact": hypothesis.impact,
            }
        ],
        budget=TimeBudget.from_seconds(30),
        evidence_summaries=evidence,
        cancel_event=threading.Event(),
        round_index=0,
    )
    orchestrator._register_live_proof_context(context)
    replay = AgentProofReplay(
        hypothesis_id=hypothesis.id,
        poc=poc_spec(),
        oracle=AgentOracleSpec(
            kind="log_contains",
            expected_text="security_impact_observed",
            impact="unauthorized_state_change",
        ),
        rationale="Replay the final working ordinary-app PoC.",
    )

    context.hypotheses[0]["claim"] = (
        "A third-party application can launch the activity."
    )
    with pytest.raises(ValueError, match="reachability-only"):
        orchestrator.execute_live_proof_replay(
            task_id,
            "secret-token",
            replay,
        )
    context.hypotheses[0]["claim"] = hypothesis.claim
    first = orchestrator.execute_live_proof_replay(
        task_id, "secret-token", replay
    )
    second = orchestrator.execute_live_proof_replay(
        task_id, "secret-token", replay
    )
    unrelated_hypothesis_id = "11111111-2222-4333-8444-555555555555"
    context.hypotheses.append(
        {
            "id": unrelated_hypothesis_id,
            "claim": "A separate attacker-controlled path may reach another sensitive sink.",
            "impact": None,
        }
    )
    unrelated = orchestrator.execute_live_proof_replay(
        task_id,
        "secret-token",
        replay.model_copy(
            update={"hypothesis_id": unrelated_hypothesis_id}
        ),
    )

    assert captured[0].hypothesis_id == hypothesis.id
    assert captured[0].entry_point_id == entry_id
    assert first["result"] == "reproduced_blackbox"
    assert first["evidence_ids"] == ["evidence-live"]
    assert first["deduplicated"] is False
    first_unsigned = {
        key: value
        for key, value in first.items()
        if key != "receipt_signature"
    }
    assert first["receipt_signature"] == hmac.new(
        b"secret-token",
        json.dumps(
            first_unsigned,
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert second["deduplicated"] is True
    assert unrelated["result"] == "inconclusive"
    assert len(captured) == 2


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
