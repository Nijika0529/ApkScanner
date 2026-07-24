from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.models import EntryPoint, InvestigationTask, Scan
from apkscanner.opencode_runner import (
    AJV_VERSION,
    OPENCODE_CLI_VERSION,
    OPENCODE_OUTPUT_MODE_PROMPTED_JSON,
    OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL,
    OPENCODE_SDK_VERSION,
    OpenCodeInvestigationError,
    OpenCodeInvestigator,
    opencode_output_mode,
    opencode_prompt_for_model,
)


def _worker_tree(root: Path) -> Path:
    worker = root / "opencode-worker"
    (worker / "node_modules" / "@opencode-ai" / "sdk").mkdir(parents=True)
    (worker / "node_modules" / "opencode-ai").mkdir(parents=True)
    (worker / "node_modules" / "ajv").mkdir(parents=True)
    (worker / "node_modules" / ".bin").mkdir(parents=True)
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
    assert available["model"] == "deepseek-v4-pro"
    assert available["output_mode"] == OPENCODE_OUTPUT_MODE_PROMPTED_JSON

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


def test_worker_response_must_be_a_json_object() -> None:
    assert OpenCodeInvestigator._parse_worker_response('{"ok": true}') == {"ok": True}


def test_output_mode_keeps_pro_toolless_and_flash_structured() -> None:
    assert opencode_output_mode("deepseek-v4-pro") == OPENCODE_OUTPUT_MODE_PROMPTED_JSON
    assert (
        opencode_output_mode("deepseek-v4-pro-202607")
        == OPENCODE_OUTPUT_MODE_PROMPTED_JSON
    )
    assert (
        opencode_output_mode("deepseek-v4-flash")
        == OPENCODE_OUTPUT_MODE_STRUCTURED_TOOL
    )
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
    assert prompt.startswith("base prompt")
    assert "DEEPSEEK_THINKING_OUTPUT_ADAPTER" in prompt
    assert "OUTPUT_JSON_SCHEMA" in prompt
    assert '"answer": "string"' in prompt
    assert (
        opencode_prompt_for_model(
            "base prompt",
            model="deepseek-v4-flash",
            output_schema={"type": "object"},
        )
        == "base prompt"
    )


def test_investigate_builds_a_toolless_prompt_and_validates_result(
    settings, tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    configured = replace(settings, opencode_isolation="host")
    investigator = OpenCodeInvestigator(configured)
    monkeypatch.setattr(
        investigator,
        "capability",
        lambda **_kwargs: {"available": True},
    )

    def invoke(payload, *, timeout_seconds):  # noqa: ANN001
        assert timeout_seconds == configured.task_timeout_seconds + 15
        assert payload["action"] == "investigate"
        assert payload["model"] == "deepseek-v4-pro"
        assert "cannot inspect files or execute commands directly" in payload["prompt"]
        assert "DEEPSEEK_THINKING_OUTPUT_ADAPTER" in payload["prompt"]
        assert "OUTPUT_JSON_SCHEMA" in payload["prompt"]
        assert payload["output_schema"]["title"] == "AgentInvestigationResult"
        assert payload["output_schema"]["additionalProperties"] is False
        serialized_schema = json.dumps(payload["output_schema"])
        assert '"$defs"' not in serialized_schema
        assert '"$ref"' not in serialized_schema
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

    monkeypatch.setattr(investigator, "_invoke", invoke)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
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
                "mode": "prompted_json",
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
