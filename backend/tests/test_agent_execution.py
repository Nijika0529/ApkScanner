from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from apkscanner.runtime.agent_execution import (
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
    assert frozen.execution.adb == "task_gateway"
    assert frozen.execution.proof_replay == "task_gateway"
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


def test_validation_profiles_separate_local_legacy_proof_from_release_gate(settings) -> None:  # noqa: ANN001
    replace(
        settings,
        validation_profile="development",
        device_min_api=33,
        allow_legacy_device_smoke=True,
    ).validate_codex_configuration()
    with pytest.raises(ValueError, match="ALLOW_LEGACY_DEVICE_SMOKE"):
        replace(
            settings,
            validation_profile="development",
            device_min_api=33,
            allow_legacy_device_smoke=False,
        ).validate_codex_configuration()

    local_low = replace(settings, validation_profile="development").verdict_metadata(33)
    assert local_low["dynamic_verdict_eligible"] is True
    assert local_low["release_gate_eligible"] is False
    assert local_low["verdict_scope"] == "development_legacy"
    local_high = replace(settings, validation_profile="development").verdict_metadata(36)
    assert local_high["dynamic_verdict_eligible"] is True
    assert local_high["release_gate_eligible"] is False
    assert local_high["verdict_scope"] == "development_android16"
    formal = replace(
        settings,
        validation_profile="android16_release",
        device_min_api=36,
        allow_legacy_device_smoke=False,
    ).verdict_metadata(36)
    assert formal["release_gate_eligible"] is True
    assert formal["verdict_scope"] == "android16_release"
    with pytest.raises(ValueError, match="android16_release"):
        replace(
            settings,
            validation_profile="android16_release",
            device_min_api=33,
        ).validate_codex_configuration()


def test_execution_contract_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        AgentExecutionProfile.model_validate(
            {**AgentExecutionProfile().model_dump(), "legacy_opencode": True}
        )
