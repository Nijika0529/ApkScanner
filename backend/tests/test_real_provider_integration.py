from __future__ import annotations

import os
import shutil
from dataclasses import replace

import pytest
from apkscanner.core.models import EntryPoint, InvestigationTask, Scan
from apkscanner.runtime.codex_runner import CodexInvestigator


@pytest.mark.skipif(
    os.getenv("APKSCANNER_RUN_REAL_PROVIDER_TESTS") != "1"
    or not os.getenv("DEEPSEEK_API_KEY")
    or shutil.which("docker") is None,
    reason="requires explicit paid-provider opt-in, DEEPSEEK_API_KEY, and Docker",
)
def test_real_deepseek_codex_structured_turn(settings) -> None:  # noqa: ANN001
    """Paid smoke: Docker SDK -> DeepSeek Responses -> validated platform contract."""
    configured = replace(
        settings,
        codex_enabled=True,
        codex_isolation="docker",
        codex_docker_image="apk-scanner-codex-worker:0.2.0",
        codex_uid_min=21_850,
        codex_uid_max=21_860,
        codex_turn_timeout_seconds=300,
        codex_no_event_timeout_seconds=120,
        task_timeout_seconds=300,
    )
    configured.ensure_directories()
    scan_id = "00000000-0000-0000-0000-000000000851"
    task_id = "00000000-0000-0000-0000-000000000852"
    entry_id = "00000000-0000-0000-0000-000000000853"
    artifact = configured.data_dir / "provider-smoke.apk"
    artifact.write_bytes(b"provider-smoke-fixture")
    scan_workspace = configured.data_dir / "workspaces" / scan_id
    source = scan_workspace / "jadx" / "sources" / "com" / "example"
    source.mkdir(parents=True)
    target_source = source / "SmokeActivity.java"
    target_source.write_text(
        """package com.example;
public final class SmokeActivity {
  public String exportedValue(String caller) {
    return caller == null ? "public-smoke-value" : caller;
  }
}
""",
        encoding="utf-8",
    )
    task_workspace = configured.data_dir / "task-input"
    task_workspace.mkdir()
    (task_workspace / "context.json").write_text(
        '{"target_source":["/scan-input/jadx/sources/com/example/SmokeActivity.java"]}',
        encoding="utf-8",
    )
    scan = Scan(
        id=scan_id,
        filename="provider-smoke.apk",
        artifact_sha256="8" * 64,
        artifact_path=str(artifact),
        package_name="com.example.provider.smoke",
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=36,
    )
    task = InvestigationTask(
        id=task_id,
        scan_id=scan_id,
        task_type="component",
        target_entry_ids=[entry_id],
        hypotheses=[
            "An exported activity may return a non-sensitive constant without authorization."
        ],
        attempts=1,
    )
    entry = EntryPoint(
        id=entry_id,
        scan_id=scan_id,
        kind="activity",
        name="com.example.SmokeActivity",
        exported=True,
        exported_reason="explicit",
        code_anchors=[{"path": str(target_source), "line": 2}],
    )
    events = []
    investigator = CodexInvestigator(configured)
    try:
        result = investigator.investigate(
            scan=scan,
            task=task,
            entries=[entry],
            workspace=task_workspace,
            evidence=[],
            platform_context={
                "phase": "static_only",
                "device": {"available": False},
                "smoke_test": True,
            },
            timeout_seconds=300,
            event_callback=events.append,
        )
        assert result.thread_id
        assert result.turn_id
        assert result.result.schema_version == "1.0"
        assert result.result.summary
        assert events

        credential = os.environ["DEEPSEEK_API_KEY"].encode()
        for path in configured.data_dir.rglob("*"):
            if (
                path.is_file()
                and path.stat().st_size <= 16 * 1024 * 1024
                and credential in path.read_bytes()
            ):
                pytest.fail(f"provider credential persisted in smoke artifact: {path}")
    finally:
        investigator.shutdown()
