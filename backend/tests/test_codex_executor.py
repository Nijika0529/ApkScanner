from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.agent_workspace import AgentWorkspaceManager
from apkscanner.codex_executor import CodexDockerExecutor, ScanContainer
from apkscanner.codex_protocol import PersistentWorkerClient

SCAN_ID = "00000000-0000-0000-0000-000000000101"
TASK_ID = "00000000-0000-0000-0000-000000000102"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_workspace_manager_reuses_role_session_and_isolates_critic_uid(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_uid_min=21_100,
        codex_uid_max=21_110,
        codex_max_sessions=4,
        codex_max_sessions_per_scan=3,
    )
    source = configured.data_dir / "source"
    source.mkdir()
    (source / "context.json").write_text('{"safe": true}', encoding="utf-8")
    manager = AgentWorkspaceManager(configured)

    primary = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
        context={"phase": "exploration_round"},
    )
    resumed = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
        context={"phase": "final_evaluation"},
    )
    critic = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="critic",
        source_workspace=source,
        context={"phase": "adversarial_review"},
    )

    assert resumed == primary
    assert primary.uid == 21_100
    assert critic.uid == 21_101
    assert primary.uid != critic.uid
    assert _mode(primary.root) == 0o711
    assert _mode(primary.workspace) == 0o700
    assert _mode(primary.codex_home) == 0o700
    assert _mode(primary.context) == 0o550
    assert _mode(primary.context / "session.json") == 0o440
    assert primary.workspace.stat().st_uid == primary.uid
    assert critic.workspace.stat().st_uid == critic.uid
    assert json.loads((primary.context / "session.json").read_text(encoding="utf-8"))[
        "context"
    ] == {"phase": "final_evaluation"}


def test_scan_container_command_has_scan_scope_and_no_provider_secret(settings) -> None:  # noqa: ANN001
    configured = replace(settings, codex_docker_image="test-worker:fixed")
    scan_workspace = configured.data_dir / "workspaces" / SCAN_ID
    for name in ("jadx", "apktool", "archive"):
        (scan_workspace / name).mkdir(parents=True, exist_ok=True)
    sessions_root = configured.data_dir / "agent-sessions" / SCAN_ID
    sessions_root.mkdir(parents=True)
    executor = CodexDockerExecutor(configured)

    command = executor.build_run_command(
        scan_id=SCAN_ID,
        generation=1,
        name="apk-scanner-test",
        scan_workspace=scan_workspace,
        sessions_root=sessions_root,
    )
    rendered = " ".join(command)

    assert "--detach" in command
    assert "--rm" not in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "io.apkscanner.role=codex-scan" in command
    assert "target=/agent-workspaces" in rendered
    assert "target=/scan-input/jadx,readonly" in rendered
    assert "DEEPSEEK_API_KEY" not in rendered
    assert "docker.sock" not in rendered


def test_worker_exec_injects_only_key_name_for_one_uid(
    settings, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-secret-must-not-enter-argv")
    configured = replace(settings, codex_uid_min=21_200, codex_uid_max=21_210)
    source = configured.data_dir / "source"
    source.mkdir()
    session = AgentWorkspaceManager(configured).prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
    )
    container = ScanContainer(
        scan_id=SCAN_ID,
        generation=1,
        container_id="a" * 64,
        name="apk-scanner-test",
        scan_workspace=configured.data_dir,
        sessions_root=session.root.parent,
    )

    command = CodexDockerExecutor(configured).build_worker_command(
        container=container,
        session=session,
    )
    rendered = " ".join(command)

    assert f"{session.uid}:{session.gid}" in command
    assert f"HOME={session.container_home}" in command
    assert f"CODEX_HOME={session.container_codex_home}" in command
    assert f"TMPDIR={session.container_tmp}" in command
    assert "DEEPSEEK_API_KEY" in command
    assert "unit-test-secret-must-not-enter-argv" not in rendered


@pytest.mark.skipif(
    os.getenv("APKSCANNER_RUN_DOCKER_TESTS") != "1"
    or os.geteuid() != 0
    or shutil.which("docker") is None,
    reason="requires APKSCANNER_RUN_DOCKER_TESTS=1, root, and Docker",
)
def test_real_scan_container_shares_input_but_isolates_session_uids(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_docker_image="apk-scanner-codex-worker:0.2.0",
        codex_uid_min=21_300,
        codex_uid_max=21_310,
    )
    source = configured.data_dir / "source"
    source.mkdir()
    (source / "seed.txt").write_text("session seed", encoding="utf-8")
    scan_workspace = configured.data_dir / "workspaces" / SCAN_ID
    (scan_workspace / "jadx").mkdir(parents=True)
    (scan_workspace / "jadx" / "Shared.java").write_text(
        "class Shared {}", encoding="utf-8"
    )

    manager = AgentWorkspaceManager(configured)
    primary = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
    )
    critic = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="critic",
        source_workspace=source,
    )
    executor = CodexDockerExecutor(configured)
    container = executor.ensure_scan_container(
        scan_id=SCAN_ID,
        scan_workspace=scan_workspace,
        sessions_root=primary.root.parent,
    )
    docker = shutil.which("docker")
    assert docker is not None

    try:
        subprocess.run(
            [
                docker,
                "exec",
                "--user",
                f"{primary.uid}:{primary.gid}",
                "--workdir",
                primary.container_workspace,
                container.container_id,
                "/bin/sh",
                "-c",
                "test -r /scan-input/jadx/Shared.java && "
                "printf primary > primary.txt",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        subprocess.run(
            [
                docker,
                "exec",
                "--user",
                f"{critic.uid}:{critic.gid}",
                "--workdir",
                critic.container_workspace,
                container.container_id,
                "/bin/sh",
                "-c",
                "printf critic > critic.txt && "
                f"test ! -r {primary.container_workspace}/primary.txt",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        inspected = subprocess.run(
            [docker, "inspect", "--format", "{{json .Config.Env}}", container.container_id],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "DEEPSEEK_API_KEY" not in inspected.stdout
        assert (primary.workspace / "primary.txt").read_text(encoding="utf-8") == "primary"
        assert (critic.workspace / "critic.txt").read_text(encoding="utf-8") == "critic"
    finally:
        executor.close_scan(SCAN_ID)


@pytest.mark.skipif(
    os.getenv("APKSCANNER_RUN_DOCKER_TESTS") != "1"
    or os.geteuid() != 0
    or shutil.which("docker") is None,
    reason="requires APKSCANNER_RUN_DOCKER_TESTS=1, root, and Docker",
)
def test_real_worker_protocol_opens_persistent_codex_thread(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only-key-without-provider-request")
    configured = replace(
        settings,
        codex_docker_image="apk-scanner-codex-worker:0.2.0",
        codex_uid_min=21_400,
        codex_uid_max=21_410,
    )
    source = configured.data_dir / "source"
    source.mkdir()
    scan_workspace = configured.data_dir / "workspaces" / SCAN_ID
    (scan_workspace / "jadx").mkdir(parents=True)
    manager = AgentWorkspaceManager(configured)
    session = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
    )
    executor = CodexDockerExecutor(configured)
    container = executor.ensure_scan_container(
        scan_id=SCAN_ID,
        scan_workspace=scan_workspace,
        sessions_root=session.root.parent,
    )
    process = executor.start_worker(container=container, session=session)

    def cleanup() -> None:
        executor.kill_session(container, session)

    client = PersistentWorkerClient(
        process,
        session_id=f"{TASK_ID}:a1:primary",
        event_spool=configured.data_dir / "runtime" / "events" / "real.ndjson",
        cleanup=cleanup,
    )
    try:
        thread_id = client.open_session(
            configuration={
                "developer_instructions": "Analyze only the assigned APK.",
                "model": "deepseek-v4-flash",
                "model_provider": "deepseek",
                "reasoning_effort": "high",
                "provider_base_url": "https://api.deepseek.com/",
                "model_catalog_path": "/opt/apk-scanner/config/deepseek-models.json",
                "workspace_path": session.container_workspace,
            },
            gateway_environment={},
        )
        assert thread_id
        assert process.poll() is None
    finally:
        client.close()
        executor.close_scan(SCAN_ID)
