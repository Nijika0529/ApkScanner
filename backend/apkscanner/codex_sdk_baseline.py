from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SDK_DISTRIBUTION = "openai-codex"
RUNTIME_DISTRIBUTION = "openai-codex-cli-bin"
PINNED_SDK_VERSION = "0.144.4"
MINIMUM_DEEPSEEK_CODEX_VERSION = "0.144.0"
VERIFIED_SOURCE_COMMIT = "6751b54cae32b23786001e2414d749a9916201e1"
# Bump whenever the host/worker protocol implementation changes without a
# third-party SDK version change. The image capability gate prevents a stale
# locally cached worker from silently speaking an older command schema.
WORKER_REVISION = "20260802.1"


class SdkBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    language: Literal["python"] = "python"
    sdk_distribution: Literal["openai-codex"] = SDK_DISTRIBUTION
    sdk_version: str
    runtime_distribution: Literal["openai-codex-cli-bin"] = RUNTIME_DISTRIBUTION
    runtime_version: str
    source_commit: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    source_commit_time: str | None = None
    generated_protocol_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    verified_at: str

    @property
    def compatible(self) -> bool:
        return self.sdk_version == PINNED_SDK_VERSION and self.runtime_version == PINNED_SDK_VERSION


def collect_sdk_baseline(source_root: Path = Path("/work/codex")) -> SdkBaseline:
    source_commit: str | None = None
    source_commit_time: str | None = None
    protocol_hash: str | None = None
    if (source_root / ".git").is_dir():
        completed = subprocess.run(
            ["git", "-C", str(source_root), "show", "-s", "--format=%H%n%cI"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        lines = completed.stdout.splitlines() if completed.returncode == 0 else []
        if len(lines) >= 2:
            source_commit, source_commit_time = lines[0], lines[1]
        generated = source_root / "sdk/python/src/openai_codex/generated/v2_all.py"
        if generated.is_file():
            protocol_hash = hashlib.sha256(generated.read_bytes()).hexdigest()
    return SdkBaseline(
        sdk_version=importlib.metadata.version(SDK_DISTRIBUTION),
        runtime_version=importlib.metadata.version(RUNTIME_DISTRIBUTION),
        source_commit=source_commit,
        source_commit_time=source_commit_time,
        generated_protocol_sha256=protocol_hash,
        verified_at=datetime.now(UTC).isoformat(),
    )


def load_checked_baseline(path: Path) -> SdkBaseline:
    return SdkBaseline.model_validate(json.loads(path.read_text(encoding="utf-8")))


def runtime_capability() -> dict[str, object]:
    try:
        baseline = collect_sdk_baseline(Path("/__source_not_available__"))
    except importlib.metadata.PackageNotFoundError:
        return {
            "available": False,
            "detail": f"{SDK_DISTRIBUTION}=={PINNED_SDK_VERSION} is not installed",
        }
    if not baseline.compatible:
        return {
            "available": False,
            "version": baseline.sdk_version,
            "runtime_version": baseline.runtime_version,
            "detail": (
                f"expected SDK/runtime {PINNED_SDK_VERSION}, found "
                f"{baseline.sdk_version}/{baseline.runtime_version}"
            ),
        }
    return {
        "available": True,
        "version": baseline.sdk_version,
        "runtime_version": baseline.runtime_version,
        "language": baseline.language,
        "minimum_deepseek_codex_version": MINIMUM_DEEPSEEK_CODEX_VERSION,
    }
