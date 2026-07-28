from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.models import EntryPoint, InvestigationTask, Scan
from apkscanner.opencode_runner import (
    AJV_VERSION,
    OPENCODE_CLI_VERSION,
    OPENCODE_OUTPUT_MODE_EXPLORE_THEN_FINALIZE,
    OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
    OPENCODE_PROFILE_STRUCTURED_FINALIZER,
    OPENCODE_PROFILE_THINKING_EXPLORER,
    OPENCODE_PROVIDER_KEY_FIELD,
    OPENCODE_SDK_VERSION,
    OpenCodeInvestigationError,
    OpenCodeInvestigator,
    opencode_execution_profile,
    opencode_output_mode,
    opencode_prompt_for_model,
)


def _worker_tree(root: Path) -> Path:
    worker = root / "opencode-worker"
    (worker / "node_modules" / "@opencode-ai" / "sdk").mkdir(parents=True)
    (worker / "node_modules" / "opencode-ai").mkdir(parents=True)
    (worker / "node_modules" / "ajv").mkdir(parents=True)
    (worker / "node_modules" / ".bin").mkdir(parents=True)
    (worker / "bin").mkdir(parents=True)
    (worker / "worker.mjs").write_text("// test worker\n", encoding="utf-8")
    (worker / "node_modules" / "@opencode-ai" / "sdk" / "package.json").write_text(
        json.dumps({"version": OPENCODE_SDK_VERSION}),
        encoding="utf-8",
    )
    (worker / "node_modules" / "opencode-ai" / "package.json").write_text(
        json.dumps({"version": OPENCODE_CLI_VERSION}),
        encoding="utf-8",
    )
    (worker / "node_modules" / "ajv" / "package.json").write_text(
        json.dumps({"version": AJV_VERSION}),
        encoding="utf-8",
    )
    (worker / "node_modules" / ".bin" / "opencode").write_text(
        "#!/bin/sh\n",
        encoding="utf-8",
    )
    (worker / "node_modules" / ".bin" / "opencode").chmod(0o755)
    for helper in ("adb", "bash"):
        path = worker / "bin" / helper
        path.write_text("#!/bin/sh\nexit 126\n", encoding="utf-8")
        path.chmod(0o755)
    return worker


def test_host_capability_requires_key_and_pinned_packages(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    worker = _worker_tree(tmp_path)
    configured = replace(
        settings,
        opencode_enabled=True,
        opencode_isolation="host",
        opencode_node_bin=shutil.which("node"),
        opencode_worker_dir=worker,
    )
    investigator = OpenCodeInvestigator(configured)

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    missing_key = investigator.capability()
    assert missing_key["available"] is False
    assert "DEEPSEEK_API_KEY" in missing_key["detail"]

    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-only")
    available = investigator.capability()
    assert available["available"] is True
    assert available["provider"] == "deepseek"
    assert available["model"] == "deepseek-v4-flash"
    assert available["output_mode"] == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
    assert available["max_steps"] == 1_000
    assert available["max_provider_requests"] == 1_100

    package = worker / "node_modules" / "@opencode-ai" / "sdk" / "package.json"
    package.write_text(json.dumps({"version": "0.0.0"}), encoding="utf-8")
    incompatible = investigator.capability()
    assert incompatible["available"] is False
    assert "expected SDK/CLI/Ajv" in incompatible["detail"]

    package.write_text(json.dumps({"version": OPENCODE_SDK_VERSION}), encoding="utf-8")
    (worker / "node_modules" / "ajv" / "package.json").unlink()
    missing_ajv = investigator.capability()
    assert missing_ajv["available"] is False
    assert "missing" in missing_ajv["detail"]

    (worker / "node_modules" / "ajv" / "package.json").write_text(
        json.dumps({"version": AJV_VERSION}),
        encoding="utf-8",
    )
    (worker / "bin" / "bash").unlink()
    missing_boundary = investigator.capability()
    assert missing_boundary["available"] is False
    assert "boundary helper" in missing_boundary["detail"]


def test_capability_rejects_credential_bearing_base_url(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-only")
    configured = replace(
        settings,
        opencode_isolation="host",
        opencode_node_bin="/usr/bin/node",
        opencode_worker_dir=_worker_tree(tmp_path),
        deepseek_base_url="https://user:secret@example.test/v1",
    )
    capability = OpenCodeInvestigator(configured).capability()
    assert capability["available"] is False
    assert "without credentials" in capability["detail"]

    query_secret = replace(
        configured,
        deepseek_base_url="https://example.test/v1?api_key=secret",
    )
    capability = OpenCodeInvestigator(query_secret).capability()
    assert capability["available"] is False
    assert "query parameters" in capability["detail"]

    remote_plaintext = replace(
        configured,
        deepseek_base_url="http://example.test/v1",
    )
    capability = OpenCodeInvestigator(remote_plaintext).capability()
    assert capability["available"] is False
    assert "only on loopback" in capability["detail"]

    official_v1 = replace(
        configured,
        deepseek_base_url="https://api.deepseek.com/v1",
    )
    capability = OpenCodeInvestigator(official_v1).capability()
    assert capability["available"] is False
    assert "must not append /v1" in capability["detail"]


@pytest.mark.parametrize("model", ["deepseek-chat", "deepseek-reasoner"])
def test_capability_rejects_retired_deepseek_aliases(
    settings, tmp_path, monkeypatch, model
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-only")
    configured = replace(
        settings,
        opencode_model=model,
        opencode_isolation="host",
        opencode_node_bin="/usr/bin/node",
        opencode_worker_dir=_worker_tree(tmp_path),
    )
    capability = OpenCodeInvestigator(configured).capability()
    assert capability["available"] is False
    assert "retired" in capability["detail"]


def test_capability_rejects_text_only_v4_pro(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-only")
    configured = replace(
        settings,
        opencode_model="deepseek-v4-pro",
        opencode_isolation="host",
        opencode_node_bin="/usr/bin/node",
        opencode_worker_dir=_worker_tree(tmp_path),
    )

    capability = OpenCodeInvestigator(configured).capability()

    assert capability["available"] is False
    assert "text-only" in capability["detail"]
    assert "deepseek-v4-flash" in capability["detail"]


def test_capability_rejects_invalid_reasoning_effort(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-only")
    configured = replace(
        settings,
        opencode_reasoning_effort="medium",
        opencode_isolation="host",
        opencode_node_bin="/usr/bin/node",
        opencode_worker_dir=_worker_tree(tmp_path),
    )
    capability = OpenCodeInvestigator(configured).capability()
    assert capability["available"] is False
    assert "must be high or max" in capability["detail"]


def test_provider_key_is_sent_in_one_shot_payload_not_worker_environment(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-provider-secret")
    configured = replace(
        settings,
        opencode_isolation="host",
        opencode_worker_dir=_worker_tree(tmp_path),
    )
    investigator = OpenCodeInvestigator(configured)
    original = {"schema_version": "1.0", "action": "capability"}

    worker_payload = investigator._worker_payload(original)
    worker_environment = investigator._worker_environment(tmp_path / "runtime")

    assert original == {"schema_version": "1.0", "action": "capability"}
    assert worker_payload[OPENCODE_PROVIDER_KEY_FIELD] == "unit-test-provider-secret"
    assert "DEEPSEEK_API_KEY" not in worker_environment


@pytest.mark.skipif(not hasattr(os, "chown"), reason="requires POSIX ownership")
def test_root_docker_workspace_is_prepared_for_image_node_user(
    settings,
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    nested = workspace / "nested"
    nested.mkdir(parents=True)
    evidence = nested / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    ownership: list[tuple[Path, int, int, bool]] = []

    monkeypatch.setattr(
        "apkscanner.opencode_runner.os.chown",
        lambda path, uid, gid, *, follow_symlinks: ownership.append(
            (Path(path), uid, gid, follow_symlinks)
        ),
    )
    OpenCodeInvestigator(settings)._prepare_root_owned_docker_workspace(workspace)

    assert {item[0] for item in ownership} == {workspace, nested, evidence}
    assert all(item[1:] == (1000, 1000, False) for item in ownership)


def test_worker_response_must_be_a_json_object() -> None:
    assert OpenCodeInvestigator._parse_worker_response('{"ok": true}') == {"ok": True}


def test_shutdown_terminates_registered_worker_process(settings) -> None:  # noqa: ANN001
    investigator = OpenCodeInvestigator(settings)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    investigator._register_process(
        process,
        lambda: investigator._kill_process_group(process),
    )

    investigator.shutdown()
    process.wait(timeout=3)

    assert process.returncode is not None


def test_structured_output_is_default_and_thinking_explorer_requires_opt_in() -> None:
    assert (
        opencode_output_mode("deepseek-v4-pro")
        == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
    )
    assert (
        opencode_output_mode("deepseek-v4-flash")
        == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
    )
    static = opencode_execution_profile("static_only")
    assert static.name == OPENCODE_PROFILE_STRUCTURED_FINALIZER
    assert static.output_mode == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
    assert [stage.thinking_mode for stage in static.stages] == ["disabled"]
    thinking = opencode_execution_profile(
        "exploration_round",
        reasoning_effort="max",
        enable_thinking_explorer=True,
    )
    assert thinking.name == OPENCODE_PROFILE_THINKING_EXPLORER
    assert thinking.output_mode == OPENCODE_OUTPUT_MODE_EXPLORE_THEN_FINALIZE
    assert thinking.stages[0].thinking_mode == "enabled"
    assert thinking.stages[0].reasoning_effort == "max"
    assert thinking.stages[1].thinking_mode == "disabled"
    finalizer = opencode_execution_profile("final_evaluation")
    assert finalizer.name == OPENCODE_PROFILE_STRUCTURED_FINALIZER
    assert finalizer.output_mode == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
    assert finalizer.stages[0].workspace_tools is False
    prompt = opencode_prompt_for_model(
        "base prompt",
        model="deepseek-v4-pro",
        output_schema={
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        },
    )
    assert prompt == "base prompt"
    assert (
        opencode_prompt_for_model(
            "base prompt",
            model="deepseek-v4-flash",
            output_schema={"type": "object"},
        )
        == "base prompt"
    )


def test_investigate_builds_a_single_structured_prompt_and_validates_result(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    configured = replace(settings, opencode_isolation="host")
    investigator = OpenCodeInvestigator(configured)
    monkeypatch.setattr(
        investigator,
        "capability",
        lambda **_kwargs: {"available": True},
    )

    def valid_worker_response() -> dict:  # noqa: ANN401
        return {
            "thread_id": "session-test",
            "turn_id": "message-test",
            "result": {
                "schema_version": "1.0",
                "summary": "No platform evidence was supplied.",
                "result": "inconclusive",
                "hypotheses_tested": [],
                "test_cases": [],
                "evidence_ids": [],
                "severity_proposal": "info",
                "confidence": "low",
                "coverage_gaps": ["No evidence"],
                "followups": [],
                "requested_tests": [],
            },
            "usage": {"tokens": {"input": 10, "output": 5}},
        }

    def invoke(payload, *, timeout_seconds, workspace):  # noqa: ANN001
        assert timeout_seconds == configured.task_timeout_seconds + 15
        assert workspace == expected_workspace
        assert payload["action"] == "investigate"
        assert payload["model"] == "deepseek-v4-flash"
        assert payload["phase"] == "static_only"
        assert "cannot inspect files or execute commands directly" in payload["prompt"]
        assert "explorer_prompt" not in payload
        assert "explorer_instructions" not in payload
        assert payload["tool_profile"] == "workspace_shell"
        assert payload["execution_profile"]["name"] == OPENCODE_PROFILE_STRUCTURED_FINALIZER
        assert payload["execution_profile"]["output_mode"] == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
        assert payload["execution_profile"]["stages"][0]["thinking_mode"] == "disabled"
        assert payload["execution_profile"]["stages"][0]["wire_tool_choice"] == "required"
        assert payload["allowed_entry_point_ids"] == [
            "00000000-0000-0000-0000-000000000003"
        ]
        assert payload["allowed_hypothesis_ids"] == []
        assert payload["output_schema"]["title"] == "AgentInvestigationResult"
        assert payload["output_schema"]["additionalProperties"] is False
        assert payload["output_schema"]["properties"]["requested_tests"]["maxItems"] == 1_000
        requested_test_schema = payload["output_schema"]["properties"][
            "requested_tests"
        ]["items"]
        assert "hypothesis_id" in requested_test_schema["required"]
        serialized_schema = json.dumps(payload["output_schema"])
        assert '"$defs"' not in serialized_schema
        assert '"$ref"' not in serialized_schema
        return valid_worker_response()

    monkeypatch.setattr(investigator, "_invoke", invoke)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    expected_workspace = workspace
    scan = Scan(
        id="00000000-0000-0000-0000-000000000001",
        filename="sample.apk",
        artifact_sha256="a" * 64,
        artifact_path=str(tmp_path / "sample.apk"),
        package_name="com.example.app",
        stats={},
    )
    task = InvestigationTask(
        id="00000000-0000-0000-0000-000000000002",
        scan_id=scan.id,
        task_type="component",
        target_entry_ids=[],
        hypotheses=["Check exported reachability"],
    )
    entry = EntryPoint(
        id="00000000-0000-0000-0000-000000000003",
        scan_id=scan.id,
        kind="activity",
        name="com.example.app.ExportedActivity",
        exported=True,
    )
    result = investigator.investigate(
        scan=scan,
        task=task,
        entries=[entry],
        workspace=workspace,
        evidence=[],
    )
    assert result.thread_id == "session-test"
    assert result.turn_id == "message-test"
    assert result.result.result == "inconclusive"
    assert result.output_transport["worker_transport_attempts"] == 1

    transport_calls = 0
    runtime_events = []

    def flaky_transport(_payload, **_kwargs):  # noqa: ANN001, ANN003
        nonlocal transport_calls
        transport_calls += 1
        if transport_calls == 1:
            raise RuntimeError(
                "OpenCode worker failed: TypeError: fetch failed\n"
                "Caused by [ECONNRESET]: socket closed"
            )
        return valid_worker_response()

    monkeypatch.setattr(investigator, "_invoke", flaky_transport)
    retried = investigator.investigate(
        scan=scan,
        task=task,
        entries=[entry],
        workspace=workspace,
        evidence=[],
        timeout_seconds=30,
        event_callback=runtime_events.append,
    )
    assert transport_calls == 2
    assert retried.output_transport["worker_transport_attempts"] == 2
    assert retried.output_transport["worker_retry_history"][0]["kind"] == (
        "worker_transport_exception"
    )
    assert any(event.event_type == "model.worker.retry" for event in runtime_events)

    response_calls = 0

    def retryable_response(_payload, **_kwargs):  # noqa: ANN001, ANN003
        nonlocal response_calls
        response_calls += 1
        if response_calls == 1:
            return {
                "thread_id": "session-provider-failed",
                "turn_id": "message-provider-failed",
                "error": {
                    "type": "provider_unavailable",
                    "message": "upstream connection reset",
                    "status_code": 502,
                    "retryable": True,
                },
                "usage": {"calls": 1},
                "output_transport": {
                    "provider_wire_requests": [{"status_code": 502}],
                },
            }
        return valid_worker_response()

    monkeypatch.setattr(investigator, "_invoke", retryable_response)
    recovered = investigator.investigate(
        scan=scan,
        task=task,
        entries=[entry],
        workspace=workspace,
        evidence=[],
        timeout_seconds=30,
    )
    assert response_calls == 2
    assert recovered.output_transport["worker_transport_attempts"] == 2
    response_history = recovered.output_transport["worker_retry_history"][0]
    assert response_history["kind"] == "retryable_worker_response"
    assert response_history["error"]["status_code"] == 502
    assert response_history["output_transport"]["provider_wire_requests"] == [
        {"status_code": 502}
    ]

    monkeypatch.setattr(
        investigator,
        "_invoke",
        lambda *_args, **_kwargs: {
            "thread_id": "session-failed",
            "turn_id": "message-failed",
            "error": {
                "type": "schema_validation_error",
                "message": "output did not satisfy schema",
            },
            "usage": {"calls": 3},
            "output_transport": {
                "mode": OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
                "model_calls": [{"attempt": 1, "accepted": False}],
            },
        },
    )
    with pytest.raises(OpenCodeInvestigationError) as raised:
        investigator.investigate(
            scan=scan,
            task=task,
            entries=[entry],
            workspace=workspace,
            evidence=[],
        )
    assert raised.value.audit_details["usage"] == {"calls": 3}
    assert (
        raised.value.audit_details["output_transport"]["model_calls"][0]["accepted"]
        is False
    )
