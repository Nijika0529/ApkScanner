from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from apkscanner.agent_workspace import AgentWorkspaceManager
from apkscanner.codex_executor import CodexDockerExecutor, ScanContainer
from apkscanner.codex_protocol import PersistentWorkerClient, PersistentWorkerError
from apkscanner.codex_runner import CodexInvestigator, _ActiveDockerSession
from apkscanner.codex_worker import WorkerConfiguration
from pydantic import ValidationError

SCAN_ID = "00000000-0000-0000-0000-000000000101"
TASK_ID = "00000000-0000-0000-0000-000000000102"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _valid_agent_result() -> dict:
    return {
        "schema_version": "1.0",
        "summary": "该入口没有发现可利用路径。",
        "result": "refuted_static",
        "hypotheses_tested": [],
        "hypothesis_assessments": [],
        "review_objections": [],
        "objection_resolutions": [],
        "test_cases": [],
        "evidence_ids": [],
        "severity_proposal": "info",
        "confidence": "medium",
        "coverage_gaps": [],
        "followups": [],
        "requested_tests": [],
    }


def test_codex_response_accepts_one_schema_valid_trailing_json_object() -> None:
    payload = _valid_agent_result()

    parsed = CodexInvestigator._parse_response(
        "平台验证已完成，现返回结构化结论。\n\n" + json.dumps(payload)
    )

    assert parsed.result == "refuted_static"
    assert parsed.summary == payload["summary"]
    assert parsed.normalization_repairs[-1]["repair"] == (
        "selected_schema_valid_json_from_mixed_response"
    )
    assert parsed.normalization_repairs[-1]["prefix_characters_ignored"] > 0


def test_codex_response_accepts_natural_language_after_valid_json() -> None:
    payload = _valid_agent_result()

    parsed = CodexInvestigator._parse_response(
        json.dumps(payload, ensure_ascii=False) + "\n以上是分析结果。"
    )

    assert parsed.summary == payload["summary"]
    repair = parsed.normalization_repairs[-1]
    assert repair["top_level_candidate_count"] == 1
    assert repair["selected_candidate_ordinal"] == 1
    assert repair["suffix_characters_ignored"] == len("以上是分析结果。")


def test_codex_response_selects_schema_valid_object_instead_of_later_partial_json() -> None:
    payload = _valid_agent_result()
    partial = {"schema_version": "1.0", "note": "这不是最终业务结果"}

    parsed = CodexInvestigator._parse_response(
        "结果如下：\n"
        + json.dumps(payload, ensure_ascii=False)
        + "\n附注："
        + json.dumps(partial, ensure_ascii=False)
    )

    assert parsed.summary == payload["summary"]
    repair = parsed.normalization_repairs[-1]
    assert repair["top_level_candidate_count"] == 2
    assert repair["selected_candidate_ordinal"] == 1


def test_codex_response_prefers_latest_of_multiple_schema_valid_objects() -> None:
    first = _valid_agent_result()
    second = {**_valid_agent_result(), "summary": "第二个完整结论应当胜出。"}

    parsed = CodexInvestigator._parse_response(
        json.dumps(first, ensure_ascii=False)
        + "\n修订后的最终结果：\n"
        + json.dumps(second, ensure_ascii=False)
    )

    assert parsed.summary == second["summary"]
    assert parsed.normalization_repairs[-1]["selected_candidate_ordinal"] == 2


def test_codex_response_rejects_complete_but_schema_invalid_object() -> None:
    with pytest.raises(ValidationError, match="summary"):
        CodexInvestigator._parse_response('说明 {"schema_version":"1.0"} trailing')


def test_codex_response_rejects_text_without_any_complete_object() -> None:
    with pytest.raises(ValueError, match="complete JSON object"):
        CodexInvestigator._parse_response('说明 {"schema_version":"1.0" trailing')


def test_generic_json_parser_prefers_candidate_with_required_schema_keys() -> None:
    expected = {"ok": True, "summary": "完成"}
    response = (
        json.dumps(expected, ensure_ascii=False)
        + "\n补充说明："
        + json.dumps({"note": "不是主结果"}, ensure_ascii=False)
    )

    parsed = CodexInvestigator._parse_json_object(
        response,
        required_keys={"ok", "summary"},
    )

    assert parsed == expected


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


def test_workspace_manager_restores_persistent_session_after_process_restart(settings) -> None:  # noqa: ANN001
    configured = replace(settings, codex_uid_min=21_100, codex_uid_max=21_110)
    source = configured.data_dir / "persistent-source"
    source.mkdir()
    first_manager = AgentWorkspaceManager(configured)
    first = first_manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="operator",
        source_workspace=source,
        context={"phase": "platform_operator"},
    )
    (first.workspace / "poc").mkdir()
    (first.workspace / "poc" / "retained.apk").write_bytes(b"retained")
    (first.root / "thread.json").write_text(
        json.dumps({"schema_version": "1.0", "thread_id": "thread-persistent"}),
        encoding="utf-8",
    )

    restored = AgentWorkspaceManager(configured).prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="operator",
        source_workspace=source,
        context={"phase": "platform_operator", "resumed": True},
    )

    assert restored.uid == first.uid
    assert restored.root == first.root
    assert (restored.workspace / "poc" / "retained.apk").read_bytes() == b"retained"
    assert json.loads((restored.root / "thread.json").read_text(encoding="utf-8"))[
        "thread_id"
    ] == "thread-persistent"


def test_workspace_manager_canonicalizes_snake_case_roles_for_worker_paths(settings) -> None:  # noqa: ANN001
    configured = replace(settings, codex_uid_min=21_100, codex_uid_max=21_110)
    source = configured.data_dir / "source"
    source.mkdir()

    workspace = AgentWorkspaceManager(configured).prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="rescue_explorer",
        source_workspace=source,
    )

    assert workspace.role == "rescue_explorer"
    assert workspace.workspace_key.endswith("-rescue-explorer")
    configuration = WorkerConfiguration(
        developer_instructions="Analyze the assigned APK.",
        model="deepseek-v4-flash",
        model_provider="deepseek",
        reasoning_effort="high",
        provider_base_url="https://api.deepseek.com/",
        model_catalog_path="/opt/apk-scanner/config/deepseek-models.json",
        workspace_path=workspace.container_workspace,
    )
    assert configuration.workspace_path == workspace.container_workspace


def test_workspace_manager_releases_terminal_task_slot_without_reusing_uid(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_uid_min=21_120,
        codex_uid_max=21_125,
        codex_max_sessions=1,
        codex_max_sessions_per_scan=1,
    )
    source = configured.data_dir / "source"
    source.mkdir()
    manager = AgentWorkspaceManager(configured)
    first = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
    )
    snapshots = first.codex_home / "shell_snapshots"
    snapshots.mkdir()
    (snapshots / "environment.sh").write_text(
        'declare -x DEEPSEEK_API_KEY="test-only-secret"',
        encoding="utf-8",
    )

    manager.forget_task(SCAN_ID, TASK_ID)
    second = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id="11111111-0000-0000-0000-000000000103",
        attempt=1,
        role="primary",
        source_workspace=source,
    )

    assert first.root.is_dir()
    assert not snapshots.exists()
    assert second.uid != first.uid


def test_only_verifier_receives_a_private_copy_of_host_ssh(settings) -> None:  # noqa: ANN001
    host_ssh = settings.data_dir / "host-ssh"
    host_ssh.mkdir(mode=0o700)
    (host_ssh / "config").write_text("Host aliyun\n  HostName 192.0.2.10\n", encoding="utf-8")
    (host_ssh / "id_ed25519").write_text("test-private-key", encoding="utf-8")
    configured = replace(
        settings,
        adaptive_verifier_copy_host_ssh=True,
        adaptive_verifier_ssh_source=host_ssh,
        codex_uid_min=21_115,
        codex_uid_max=21_119,
    )
    source = configured.data_dir / "verifier-source"
    source.mkdir()
    manager = AgentWorkspaceManager(configured)

    primary = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id=TASK_ID,
        attempt=1,
        role="primary",
        source_workspace=source,
    )
    verifier = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id="11111111-0000-0000-0000-000000000104",
        attempt=1,
        role="verifier",
        source_workspace=source,
    )

    assert not (primary.home / ".ssh").exists()
    assert (verifier.home / ".ssh" / "config").read_text(encoding="utf-8").startswith(
        "Host aliyun"
    )
    assert (verifier.home / ".ssh" / "id_ed25519").read_text(encoding="utf-8") == (
        "test-private-key"
    )
    assert _mode(verifier.home / ".ssh") == 0o700
    assert _mode(verifier.home / ".ssh" / "id_ed25519") == 0o600
    assert (verifier.home / ".ssh" / "id_ed25519").stat().st_uid == verifier.uid

    manager.forget_task(verifier.scan_id, verifier.task_id)
    assert not (verifier.home / ".ssh").exists()


def test_retained_audit_workspaces_do_not_consume_active_worker_limit(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_uid_min=21_130,
        codex_uid_max=21_140,
        codex_max_sessions=1,
        codex_max_sessions_per_scan=1,
    )
    source = configured.data_dir / "source-many-roles"
    source.mkdir()
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

    assert primary.uid != critic.uid
    assert primary.root.is_dir()
    assert critic.root.is_dir()


def test_worker_capacity_evicts_an_idle_resumable_session_instead_of_failing(settings) -> None:  # noqa: ANN001
    configured = replace(
        settings,
        codex_max_sessions=1,
        codex_max_sessions_per_scan=1,
    )
    investigator = CodexInvestigator(configured)

    class FakeClient:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    client = FakeClient()
    key = (SCAN_ID, TASK_ID, 1, "primary")
    investigator._sessions[key] = _ActiveDockerSession(
        workspace=SimpleNamespace(),
        container=SimpleNamespace(),
        client=client,  # type: ignore[arg-type]
        role="primary",
        last_used=1.0,
    )

    with investigator._session_condition:
        investigator._wait_for_worker_capacity(SCAN_ID, cancel_event=None)

    assert client.closed is True
    assert investigator._sessions == {}


def test_scan_container_command_has_scan_scope_and_no_provider_secret(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    monkeypatch.setattr(CodexDockerExecutor, "_docker", staticmethod(lambda: "docker"))
    configured = replace(settings, codex_docker_image="test-worker:fixed")
    scan_workspace = configured.data_dir / "workspaces" / SCAN_ID
    for name in ("jadx", "apktool", "archive", "native", "artifacts"):
        (scan_workspace / name).mkdir(parents=True, exist_ok=True)
    (scan_workspace / "artifact_graph.json").write_text("{}", encoding="utf-8")
    sessions_root = configured.data_dir / "agent-sessions" / SCAN_ID
    sessions_root.mkdir(parents=True)
    apk_path = configured.data_dir / "target.apk"
    apk_path.write_bytes(b"test apk mount")
    executor = CodexDockerExecutor(configured)

    command = executor.build_run_command(
        scan_id=SCAN_ID,
        generation=1,
        name="apk-scanner-test",
        scan_workspace=scan_workspace,
        sessions_root=sessions_root,
        apk_path=apk_path,
    )
    rendered = " ".join(command)

    assert "--detach" in command
    assert "--rm" not in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "io.apkscanner.role=codex-scan" in command
    assert "target=/agent-workspaces" in rendered
    assert "target=/scan-input/target.apk,readonly" in rendered
    assert "target=/scan-input/jadx,readonly" in rendered
    assert "target=/scan-input/native,readonly" in rendered
    assert "target=/scan-input/artifacts,readonly" in rendered
    assert "target=/scan-input/artifact_graph.json,readonly" in rendered
    assert "DEEPSEEK_API_KEY" not in rendered
    assert "docker.sock" not in rendered


def test_worker_exec_injects_only_key_name_for_one_uid(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(CodexDockerExecutor, "_docker", staticmethod(lambda: "docker"))
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
    host_ssh = settings.data_dir / "integration-host-ssh"
    host_ssh.mkdir(mode=0o700)
    (host_ssh / "config").write_text(
        "Host aliyun-test\n  HostName 192.0.2.20\n",
        encoding="utf-8",
    )
    configured = replace(
        settings,
        codex_docker_image="apk-scanner-codex-worker:0.2.0",
        codex_uid_min=21_300,
        codex_uid_max=21_310,
        adaptive_verifier_copy_host_ssh=True,
        adaptive_verifier_ssh_source=host_ssh,
    )
    source = configured.data_dir / "source"
    source.mkdir()
    (source / "seed.txt").write_text("session seed", encoding="utf-8")
    scan_workspace = configured.data_dir / "workspaces" / SCAN_ID
    (scan_workspace / "jadx").mkdir(parents=True)
    (scan_workspace / "jadx" / "Shared.java").write_text("class Shared {}", encoding="utf-8")
    apk_path = configured.data_dir / "target.apk"
    apk_path.write_bytes(b"read-only apk input")

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
    verifier = manager.prepare_session(
        scan_id=SCAN_ID,
        task_id="11111111-0000-0000-0000-000000000105",
        attempt=1,
        role="verifier",
        source_workspace=source,
    )
    executor = CodexDockerExecutor(configured)
    container = executor.ensure_scan_container(
        scan_id=SCAN_ID,
        scan_workspace=scan_workspace,
        sessions_root=primary.root.parent,
        apk_path=apk_path,
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
                "test -r /scan-input/target.apk && "
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
                f"{verifier.uid}:{verifier.gid}",
                "--env",
                f"HOME={verifier.container_home}",
                "--workdir",
                verifier.container_workspace,
                container.container_id,
                "/bin/sh",
                "-c",
                "test -x /usr/bin/ssh && test -r \"$HOME/.ssh/config\" && "
                f"test ! -r {primary.container_workspace}/primary.txt",
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
        assert not (primary.home / ".ssh").exists()
        assert (verifier.home / ".ssh" / "config").is_file()
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
                "provider_base_url": "http://127.0.0.1:9/",
                "model_catalog_path": "/opt/apk-scanner/config/deepseek-models.json",
                "workspace_path": session.container_workspace,
            },
            gateway_environment={},
        )
        assert thread_id
        assert process.poll() is None
        with pytest.raises(PersistentWorkerError):
            client.turn(
                prompt="Return a JSON object with ok=true.",
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                timeout_seconds=30,
                no_event_timeout_seconds=30,
                event_callback=None,
                cancel_event=None,
            )
        assert not (session.codex_home / "shell_snapshots").exists()
    finally:
        client.close()
        executor.close_scan(SCAN_ID)
