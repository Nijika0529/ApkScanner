from __future__ import annotations

import importlib
import json
import re
import sys
import tomllib
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

from apkscanner.cli import serve_command
from apkscanner.runtime.codex_sdk_baseline import WORKER_REVISION

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_configured_console_script_targets_are_importable() -> None:
    configuration = tomllib.loads(
        (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    for target in configuration["project"]["scripts"].values():
        module_name, attribute_name = target.split(":", 1)
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attribute_name))


def test_worker_entrypoint_targets_an_importable_module() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
    match = re.search(r"^ENTRYPOINT\s+(\[.*\])$", dockerfile, flags=re.MULTILINE)

    assert match is not None
    argv = json.loads(match.group(1))
    assert argv[:2] == ["python", "-m"]
    importlib.import_module(argv[2])


def test_worker_revision_matches_the_host_capability_gate() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")

    assert f'io.apkscanner.worker-revision="{WORKER_REVISION}"' in dockerfile


def test_worker_dockerfile_has_only_documented_vendor_inputs() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
    copy_sources = re.findall(r"^COPY\s+(docker/vendor/\S+)", dockerfile, flags=re.MULTILINE)

    # These inputs are deliberately operator-provided and gitignored. Compare
    # their declarations, not their machine-local existence.
    assert copy_sources == [
        "docker/vendor/jadx",
        "docker/vendor/apktool/apktool.jar",
    ]


def test_worker_dockerfile_downloads_android_sdk_with_pinned_sha256() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")

    # JADX and Apktool are intentionally gitignored, operator-provided assets. The
    # Android SDK, however, must remain buildable from a clean checkout and every
    # remote archive must be pinned independently of local vendor state.
    assert "COPY docker/vendor/android-sdk/" not in dockerfile
    for archive_arg, digest_arg, destination in (
        (
            "ANDROID_PLATFORM_ARCHIVE",
            "ANDROID_PLATFORM_SHA256",
            "/tmp/android-platform.zip",
        ),
        (
            "ANDROID_BUILD_TOOLS_ARCHIVE",
            "ANDROID_BUILD_TOOLS_SHA256",
            "/tmp/android-build-tools.zip",
        ),
    ):
        digest_match = re.search(
            rf'^ARG {digest_arg}="([a-f0-9]{{64}})"$',
            dockerfile,
            flags=re.MULTILINE,
        )
        assert digest_match is not None
        assert (
            f'"https://dl.google.com/android/repository/${{{archive_arg}}}"'
            in dockerfile
        )
        assert f'"${{{digest_arg}}}  {destination}" | sha256sum -c -' in dockerfile


def test_package_restructure_bumps_the_worker_revision() -> None:
    assert WORKER_REVISION != "20260812.1"
    assert re.fullmatch(r"20\d{6}\.\d+", WORKER_REVISION)


def test_serve_command_defaults_to_loopback(monkeypatch) -> None:  # noqa: ANN001
    calls: list[dict[str, object]] = []
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda *args, **kwargs: calls.append({"args": args, **kwargs})),
    )

    assert serve_command(Namespace(port=8000, reload=False)) == 0
    assert calls == [
        {
            "args": ("apkscanner.main:app",),
            "host": "127.0.0.1",
            "port": 8000,
            "reload": False,
        }
    ]
