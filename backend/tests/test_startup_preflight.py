from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

from apkscanner.runtime import startup_preflight


class _Runner:
    def __init__(self, **_kwargs):  # noqa: ANN003
        pass

    def available(self, _name: str) -> bool:
        return True


def _base_settings(settings):  # noqa: ANN001, ANN202
    return replace(
        settings,
        investigator_backend="none",
        codex_enabled=False,
        poc_enabled=False,
        adb_serial=None,
        adb_serials=(),
    )


def test_development_without_a_device_remains_static_only(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(startup_preflight, "ToolRunner", _Runner)

    result = startup_preflight.check_runtime_readiness(_base_settings(settings))

    assert result["ready"] is True
    assert result["checks"]["devices"] == {}


def test_release_requires_an_api_36_device(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(startup_preflight, "ToolRunner", _Runner)

    result = startup_preflight.check_runtime_readiness(
        replace(_base_settings(settings), validation_profile="android16_release")
    )

    assert result["ready"] is False
    assert any("requires a configured" in item for item in result["issues"])


def test_explicit_unavailable_device_blocks_even_development(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(startup_preflight, "ToolRunner", _Runner)

    class OfflineDevice:
        def __init__(self, _settings, _runner, *, serial):  # noqa: ANN001
            self.serial = serial

        def capability(self):  # noqa: ANN201
            return {"available": False, "detail": "offline"}

    monkeypatch.setattr(startup_preflight, "AdbDeviceAdapter", OfflineDevice)
    result = startup_preflight.check_runtime_readiness(
        replace(_base_settings(settings), adb_serial="test-phone")
    )

    assert result["ready"] is False
    assert result["checks"]["devices"] == {"test-phone": False}
    assert any("test-phone is unavailable" in item for item in result["issues"])


def test_missing_docker_never_falls_back_to_host(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(startup_preflight, "ToolRunner", _Runner)
    monkeypatch.setattr(startup_preflight.shutil, "which", lambda _name: None)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only")

    result = startup_preflight.check_runtime_readiness(
        replace(_base_settings(settings), investigator_backend="codex", codex_enabled=True)
    )

    assert result["ready"] is False
    assert result["checks"]["docker_daemon"] is False
    assert any("Docker is unavailable" in item for item in result["issues"])


def test_stale_worker_image_blocks_launch(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(startup_preflight, "ToolRunner", _Runner)
    monkeypatch.setattr(startup_preflight.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        startup_preflight.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "24.0", ""),
    )
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only")

    class StaleWorker:
        def __init__(self, _settings):  # noqa: ANN001
            pass

        def capability(self):  # noqa: ANN201
            return {"available": False, "detail": "stale image label"}

    monkeypatch.setattr(startup_preflight, "CodexInvestigator", StaleWorker)
    result = startup_preflight.check_runtime_readiness(
        replace(_base_settings(settings), investigator_backend="codex", codex_enabled=True)
    )

    assert result["ready"] is False
    assert result["checks"]["docker_daemon"] is True
    assert result["checks"]["codex_worker"] is False
    assert any("stale image label" in item for item in result["issues"])


def test_missing_android_source_sdk_blocks_launch(settings, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(startup_preflight, "ToolRunner", _Runner)
    monkeypatch.setattr(startup_preflight, "ArtifactStore", lambda _settings: object())

    class IncompleteBuilder:
        def __init__(self, _settings, _runner, _store):  # noqa: ANN001
            pass

        def capability(self):  # noqa: ANN201
            return {
                "available": True,
                "source_build_available": False,
                "source_build_missing": ["Android SDK platform android.jar"],
            }

    monkeypatch.setattr(startup_preflight, "PocBuilder", IncompleteBuilder)
    result = startup_preflight.check_runtime_readiness(
        replace(_base_settings(settings), poc_enabled=True)
    )

    assert result["ready"] is False
    assert result["checks"]["poc_source_build"] is False
    assert any("android.jar" in item for item in result["issues"])


def test_start_script_checks_readiness_before_stopping_existing_service() -> None:
    script = Path("start.sh").read_text(encoding="utf-8")

    assert script.index("-m apkscanner.runtime.startup_preflight") < script.index(
        "\nstop_existing\n\nnohup"
    )
    assert "/api/v1/ready" in script
    assert "/api/v1/health" not in script
