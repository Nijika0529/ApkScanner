from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.agent_execution import (
    PHASE_NAMES,
    AgentExecutionProfile,
    PhaseRoute,
    ProviderProfile,
    WorkspaceManifest,
    WorkspaceMount,
    default_phase_route,
)
from pydantic import ValidationError


def test_default_profiles_are_frozen_versioned_and_hashable(settings) -> None:  # noqa: ANN001
    frozen = settings.frozen_agent_configuration()

    assert frozen.execution.sandbox == "full_access"
    assert frozen.execution.container_scope == "scan"
    assert frozen.execution.workspace_write is True
    assert frozen.execution.web_search == "live"
    assert frozen.execution.adb == "disabled"
    assert frozen.execution.proof_replay == "disabled"
    assert frozen.provider.backend == "codex"
    assert frozen.provider.provider == "deepseek"
    assert frozen.provider.model == "deepseek-v4-flash"
    assert frozen.provider.wire_api == "responses"
    assert set(frozen.phase_route.routes) == PHASE_NAMES
    assert len(frozen.fingerprint()) == 64
    assert frozen.fingerprint() == settings.frozen_agent_configuration().fingerprint()


def test_phase_routes_reject_opencode_and_unknown_phases() -> None:
    routes = default_phase_route("deepseek_codex_flash_v1").routes
    routes["adversarial_review"] = "opencode:legacy"
    with pytest.raises(ValidationError, match="codex"):
        PhaseRoute(routes=routes)

    routes = default_phase_route("deepseek_codex_flash_v1").routes
    routes["invented_phase"] = "codex:deepseek_codex_flash_v1"
    with pytest.raises(ValidationError, match="unknown agent phases"):
        PhaseRoute(routes=routes)


def test_provider_profile_rejects_unsupported_model_and_unsafe_url(tmp_path: Path) -> None:
    catalog = tmp_path / "models.json"
    catalog.write_text('{"models": []}', encoding="utf-8")
    with pytest.raises(ValidationError, match="deepseek-v4-flash"):
        ProviderProfile(model="deepseek-v4-pro", model_catalog_path=catalog)
    with pytest.raises(ValidationError, match="credentials"):
        ProviderProfile(
            model_catalog_path=catalog,
            base_url="https://user:secret@api.deepseek.com/?token=bad",
        )


def test_workspace_manifest_rejects_duplicate_or_relative_mounts() -> None:
    with pytest.raises(ValidationError, match="absolute"):
        WorkspaceMount(logical_name="workspace", container_path="relative", access="rw")

    mount = WorkspaceMount(
        logical_name="workspace",
        container_path="/agent-workspaces/session/workspace",
        access="rw",
    )
    with pytest.raises(ValidationError, match="unique"):
        WorkspaceManifest(
            scan_id="scan",
            workspace_key="task-attempt-primary",
            uid=21_001,
            gid=21_001,
            mounts=(mount, mount),
        )


def test_settings_reject_host_without_explicit_diagnostic_override(settings) -> None:  # noqa: ANN001
    configured = replace(settings, codex_isolation="host", codex_allow_host=False)
    with pytest.raises(ValueError, match="APKSCANNER_ALLOW_HOST_CODEX"):
        configured.validate_codex_configuration()


def test_execution_contract_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        AgentExecutionProfile.model_validate(
            {**AgentExecutionProfile().model_dump(), "legacy_opencode": True}
        )
