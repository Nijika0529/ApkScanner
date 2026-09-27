"""Fail closed on release capabilities before replacing a running API process.

The same command is used by ``start.sh`` and the dedicated Android release CI.
It never starts a scan or contacts a model provider; the Codex check validates
only the local SDK/runtime and the pinned Docker worker image.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any

from ..core.config import Settings
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.tools import ToolRunner
from .codex_runner import CodexInvestigator
from .device import AdbDeviceAdapter
from .poc import PocBuilder

_CORE_TOOLS = ("aapt2", "apksigner", "apktool", "jadx")


def check_runtime_readiness(settings: Settings) -> dict[str, Any]:
    """Return the launch gate without stopping the service or modifying a device."""

    issues: list[str] = []
    checks: dict[str, Any] = {}
    runner = ToolRunner(
        timeout_seconds=settings.tool_timeout_seconds,
        executable_overrides={"adb": settings.host_adb_executable},
    )

    tools = {name: runner.available(name) for name in _CORE_TOOLS}
    checks["core_tools"] = tools
    issues.extend(f"required host tool is unavailable: {name}" for name, found in tools.items() if not found)

    if settings.investigator_backend == "codex":
        checks["codex_worker"] = False
        if not settings.codex_enabled:
            issues.append("configured Codex investigator is disabled")
        if settings.codex_isolation != "docker":
            issues.append("start and release CI require Docker-isolated Codex; host mode is diagnostics only")
        if not os.getenv("DEEPSEEK_API_KEY"):
            issues.append("DEEPSEEK_API_KEY is missing for the configured Codex investigator")

        docker = shutil.which("docker")
        if docker is None:
            issues.append("Docker is unavailable")
            checks["docker_daemon"] = False
        else:
            try:
                probe = subprocess.run(
                    [docker, "info", "--format", "{{.ServerVersion}}"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                issues.append(f"Docker daemon probe failed: {exc}")
                checks["docker_daemon"] = False
            else:
                checks["docker_daemon"] = probe.returncode == 0
                if probe.returncode != 0:
                    detail = probe.stderr.strip() or probe.stdout.strip() or "docker info failed"
                    issues.append(f"Docker daemon is unavailable: {detail[-300:]}")
        if (
            settings.codex_enabled
            and settings.codex_isolation == "docker"
            and checks.get("docker_daemon") is True
        ):
            capability = CodexInvestigator(settings).capability()
            checks["codex_worker"] = bool(capability.get("available"))
            if not capability.get("available"):
                issues.append(f"Codex worker is unavailable: {capability.get('detail')}")
    else:
        checks["codex_worker"] = "not_configured"

    if settings.poc_enabled:
        capability = PocBuilder(settings, runner, ArtifactStore(settings)).capability()
        checks["poc_source_build"] = bool(capability.get("source_build_available"))
        if not capability.get("available"):
            issues.append(f"PoC builder is unavailable: {capability.get('detail')}")
        elif not capability.get("source_build_available"):
            missing = ", ".join(str(item) for item in capability.get("source_build_missing", []))
            issues.append(f"PoC source-build SDK is unavailable: {missing or 'unknown toolchain gap'}")
    else:
        checks["poc_source_build"] = "disabled"

    serials = settings.configured_adb_serials
    checks["devices"] = {}
    if not serials and settings.validation_profile == "android16_release":
        issues.append("android16_release requires a configured API 36+ ADB device")
    for serial in serials:
        capability = AdbDeviceAdapter(settings, runner, serial=serial).capability()
        checks["devices"][serial] = bool(capability.get("available"))
        if not capability.get("available"):
            issues.append(f"configured ADB device {serial} is unavailable: {capability.get('detail')}")

    return {"ready": not issues, "checks": checks, "issues": issues}


def main() -> int:
    try:
        result = check_runtime_readiness(Settings.from_env())
    except (OSError, ValueError) as exc:
        result = {"ready": False, "checks": {}, "issues": [f"runtime configuration: {exc}"]}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
