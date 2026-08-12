from __future__ import annotations

from pathlib import Path

from apkscanner.codex_runner import codex_config_overrides
from apkscanner.codex_sdk_baseline import (
    PINNED_SDK_VERSION,
    VERIFIED_SOURCE_COMMIT,
    collect_sdk_baseline,
    load_checked_baseline,
    runtime_capability,
)
from openai_codex import Codex, CodexConfig


def test_checked_sdk_baseline_matches_runtime_and_reviewed_protocol() -> None:
    checked = load_checked_baseline(Path("config/codex-sdk-baseline.json"))
    runtime = collect_sdk_baseline()

    assert checked.sdk_version == PINNED_SDK_VERSION
    assert checked.runtime_version == PINNED_SDK_VERSION
    assert checked.source_commit == VERIFIED_SOURCE_COMMIT
    assert runtime.sdk_version == PINNED_SDK_VERSION
    assert runtime.runtime_version == PINNED_SDK_VERSION
    # /work/codex is intentionally updated when reviewing upstream changes. The
    # installed distributions and generated protocol must remain pinned, while the
    # checked baseline retains the exact source commit that was reviewed.
    assert runtime.generated_protocol_sha256 == checked.generated_protocol_sha256
    assert runtime_capability()["available"] is True


def test_codex_overrides_use_responses_env_key_and_filter_secrets() -> None:
    overrides = codex_config_overrides(
        provider="deepseek",
        model="deepseek-v4-flash",
        reasoning_effort="high",
        base_url="https://api.deepseek.com/",
        model_catalog_path="/opt/apk-scanner/config/deepseek-models.json",
        web_search="live",
        ida_mcp_url="http://apkscanner-host:8745/mcp",
        ida_mcp_tool_timeout_seconds=1_800,
    )
    rendered = "\n".join(overrides)

    assert 'model_provider="deepseek"' in rendered
    assert 'model_providers.deepseek.wire_api="responses"' in rendered
    assert 'model_providers.deepseek.env_key="DEEPSEEK_API_KEY"' in rendered
    assert "experimental_bearer_token" not in rendered
    assert "project_doc_max_bytes=0" in rendered
    assert 'web_search="live"' in rendered
    assert "features.shell_snapshot=false" in rendered
    assert 'shell_environment_policy.inherit="all"' in rendered
    assert "shell_environment_policy.ignore_default_excludes=true" in rendered
    assert '"APKSCANNER_ADB_*"' in rendered
    assert '"APKSCANNER_PROOF_*"' in rendered
    assert '"APKSCANNER_OBSERVATION_*"' in rendered
    assert '"DEEPSEEK_API_KEY"' in rendered
    assert 'mcp_servers.ida-headless.url="http://apkscanner-host:8745/mcp"' in rendered
    assert "mcp_servers.ida-headless.required=false" in rendered
    assert "mcp_servers.ida-headless.tool_timeout_sec=1800" in rendered
    assert "^APKSCANNER" not in rendered
    assert not any("sk-" in item for item in overrides)


def test_official_deepseek_catalog_loads_through_pinned_codex_runtime(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-placeholder")
    catalog = Path("config/deepseek-models.json").resolve()
    config = CodexConfig(
        config_overrides=codex_config_overrides(
            provider="deepseek",
            model="deepseek-v4-flash",
            reasoning_effort="high",
            base_url="https://api.deepseek.com/",
            model_catalog_path=catalog,
            web_search="live",
        )
    )

    with Codex(config) as codex:
        models = {model.id: model for model in codex.models().data}

    assert models["deepseek-v4-flash"].is_default is True
    assert [
        option.reasoning_effort
        for option in models["deepseek-v4-flash"].supported_reasoning_efforts
    ] == ["low", "high", "max"]
