from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from ..core.models import ScanEvent


class CapabilityManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=2000)
    runtime: Literal["builtin_python", "python_script", "mcp"]
    permissions: tuple[str, ...] = ()
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    script_path: str | None = None
    script_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    mcp_server: str | None = None
    mcp_tool: str | None = None

    @model_validator(mode="after")
    def validate_runtime_fields(self) -> CapabilityManifest:
        if self.runtime == "python_script" and not (self.script_path and self.script_sha256):
            raise ValueError("python_script requires script_path and script_sha256")
        if self.runtime == "mcp" and not (self.mcp_server and self.mcp_tool):
            raise ValueError("mcp requires mcp_server and mcp_tool")
        return self


class CapabilityInvocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: dict[str, Any] = Field(default_factory=dict)


class CapabilityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    ok: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class CapabilityAdapter(Protocol):
    def __call__(self, value: dict[str, Any]) -> dict[str, Any]: ...


class CapabilityRegistry:
    """Allowlisted extension surface for built-ins, signed Python scripts and MCP tools."""

    def __init__(self, orchestrator) -> None:  # noqa: ANN001
        self.orchestrator = orchestrator
        self.settings = orchestrator.settings
        self.manifest_dir = self.settings.data_dir / "capabilities"
        self.script_root = self.settings.data_dir / "capability-scripts"
        self._lock = threading.RLock()
        self._manifests: dict[str, CapabilityManifest] = {}
        self._adapters: dict[str, CapabilityAdapter] = {}
        self._install_builtins()
        self.reload()

    def catalog(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    **manifest.model_dump(mode="json"),
                    "available": self._available(manifest),
                }
                for manifest in sorted(self._manifests.values(), key=lambda item: item.id)
            ]

    def reload(self) -> None:
        self.manifest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.script_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.manifest_dir.chmod(0o700)
        self.script_root.chmod(0o700)
        loaded: dict[str, CapabilityManifest] = {}
        for path in sorted(self.manifest_dir.glob("*.json")):
            if path.is_symlink() or path.stat().st_size > 1_000_000:
                continue
            manifest = CapabilityManifest.model_validate_json(path.read_bytes())
            if manifest.runtime == "builtin_python":
                raise ValueError("external manifests cannot claim the builtin_python runtime")
            if manifest.id in loaded or manifest.id in self._adapters:
                raise ValueError(f"duplicate capability ID: {manifest.id}")
            if manifest.runtime == "python_script":
                self._resolve_script(manifest)
            loaded[manifest.id] = manifest
        with self._lock:
            builtin_ids = set(self._adapters)
            self._manifests = {
                **{key: value for key, value in self._manifests.items() if key in builtin_ids},
                **loaded,
            }

    def bind_mcp(self, capability_id: str, adapter: CapabilityAdapter) -> None:
        with self._lock:
            manifest = self._manifests.get(capability_id)
            if manifest is None or manifest.runtime != "mcp":
                raise ValueError("MCP capability manifest is not registered")
            self._adapters[capability_id] = adapter

    def invoke(self, capability_id: str, value: dict[str, Any]) -> CapabilityResult:
        encoded = json.dumps(value, ensure_ascii=False).encode()
        if len(encoded) > 1_000_000:
            raise ValueError("capability input exceeds 1 MB")
        with self._lock:
            manifest = self._manifests.get(capability_id)
            adapter = self._adapters.get(capability_id)
        if manifest is None:
            raise KeyError(capability_id)
        try:
            if adapter is not None:
                output = adapter(value)
            elif manifest.runtime == "python_script":
                output = self._invoke_script(manifest, encoded)
            else:
                raise RuntimeError("MCP capability is declared but no adapter is bound")
            if not isinstance(output, dict):
                raise ValueError("capability output must be a JSON object")
            return CapabilityResult(capability_id=capability_id, ok=True, output=output)
        except Exception as exc:
            return CapabilityResult(
                capability_id=capability_id,
                ok=False,
                error=str(exc)[:3000],
            )

    def _install_builtins(self) -> None:
        builtins: tuple[tuple[CapabilityManifest, CapabilityAdapter], ...] = (
            (
                CapabilityManifest(
                    id="platform.devices.snapshot",
                    title="设备队列快照",
                    description="读取设备池、当前 lease 和等待队列；不执行设备命令。",
                    runtime="builtin_python",
                    permissions=("device.read",),
                ),
                lambda _value: self.orchestrator.device_pool.snapshot(),
            ),
            (
                CapabilityManifest(
                    id="platform.codex.runtime",
                    title="Codex 运行时快照",
                    description="读取活动 scan 容器和会话隔离运行时状态。",
                    runtime="builtin_python",
                    permissions=("runtime.read",),
                ),
                lambda _value: {
                    "containers": self.orchestrator.codex.executor.snapshot(),
                },
            ),
            (
                CapabilityManifest(
                    id="platform.scan.timeline",
                    title="扫描事件线",
                    description="按 scan_id 读取结构化事件，供监督 Agent 观察进度。",
                    runtime="builtin_python",
                    permissions=("scan.read",),
                    input_schema={"required": ["scan_id"]},
                ),
                self._scan_timeline,
            ),
        )
        for manifest, adapter in builtins:
            self._manifests[manifest.id] = manifest
            self._adapters[manifest.id] = adapter

    def _scan_timeline(self, value: dict[str, Any]) -> dict[str, Any]:
        scan_id = value.get("scan_id")
        if not isinstance(scan_id, str) or not re.fullmatch(r"[a-f0-9-]{36}", scan_id):
            raise ValueError("scan_id is required")
        limit = value.get("limit", 200)
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be within 1..1000")
        with self.orchestrator.database.session_factory() as session:
            events = list(
                session.scalars(
                    select(ScanEvent)
                    .where(ScanEvent.scan_id == scan_id)
                    .order_by(ScanEvent.id.desc())
                    .limit(limit)
                )
            )
        return {
            "scan_id": scan_id,
            "events": [
                {
                    "id": event.id,
                    "type": event.event_type,
                    "message": event.message,
                    "data": event.data,
                    "created_at": event.created_at.isoformat(),
                }
                for event in reversed(events)
            ],
        }

    def _resolve_script(self, manifest: CapabilityManifest) -> Path:
        assert manifest.script_path is not None and manifest.script_sha256 is not None
        if Path(manifest.script_path).is_absolute():
            raise ValueError("capability script_path must be relative")
        path = (self.script_root / manifest.script_path).resolve()
        root = self.script_root.resolve()
        if (
            path.is_symlink()
            or not path.is_relative_to(root)
            or not path.is_file()
            or "," in str(path)
        ):
            raise ValueError("capability script is outside the configured script root")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != manifest.script_sha256:
            raise ValueError("capability script hash does not match its manifest")
        return path

    def _invoke_script(self, manifest: CapabilityManifest, encoded: bytes) -> dict[str, Any]:
        path = self._resolve_script(manifest)
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("Docker is required for Python capability isolation")
        image = self.settings.codex_docker_image
        if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", image):
            raise ValueError("capability runner image is invalid")
        network = "bridge" if "network.public" in manifest.permissions else "none"
        completed = subprocess.run(
            [
                docker,
                "run",
                "--rm",
                "--interactive",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--network",
                network,
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=64m",
                "--mount",
                f"type=bind,source={path},target=/capability/main.py,readonly",
                "--entrypoint",
                "python",
                image,
                "/capability/main.py",
            ],
            input=encoded.decode(),
            capture_output=True,
            text=True,
            timeout=manifest.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr[-3000:] or "capability script failed")
        if len(completed.stdout.encode()) > 2_000_000:
            raise ValueError("capability output exceeds 2 MB")
        output = json.loads(completed.stdout)
        if not isinstance(output, dict):
            raise ValueError("capability script output must be a JSON object")
        return output

    def _available(self, manifest: CapabilityManifest) -> bool:
        if manifest.runtime == "python_script":
            try:
                self._resolve_script(manifest)
                return shutil.which("docker") is not None
            except ValueError:
                return False
        if manifest.runtime == "mcp":
            return manifest.id in self._adapters
        return True
