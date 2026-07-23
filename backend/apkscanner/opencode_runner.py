from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .agent_prompt import developer_instructions, investigation_prompt
from .config import Settings
from .models import EntryPoint, InvestigationTask, Scan
from .schemas import AGENT_RESULT_JSON_SCHEMA, AgentInvestigationResult

OPENCODE_SDK_VERSION = "1.18.4"
OPENCODE_CLI_VERSION = "1.18.4"
OPENCODE_PROVIDER = "deepseek"


@dataclass(slots=True)
class OpenCodeRunResult:
    thread_id: str
    turn_id: str
    result: AgentInvestigationResult
    usage: dict[str, Any]


class OpenCodeInvestigator:
    name = "opencode"

    def __init__(self, settings: Settings):
        self.settings = settings
        self.worker_dir = settings.opencode_worker_dir or (
            Path(__file__).resolve().parents[2] / "opencode-worker"
        )
        self._deep_capability: dict[str, Any] | None = None

    def capability(self, *, deep: bool = False) -> dict[str, Any]:
        capability: dict[str, Any] = {
            "available": True,
            "version": OPENCODE_SDK_VERSION,
            "provider": OPENCODE_PROVIDER,
            "model": self.settings.opencode_model,
            "isolation": self.settings.opencode_isolation,
        }
        detail = self._configuration_error()
        if detail:
            return {**capability, "available": False, "detail": detail}
        if self.settings.opencode_isolation == "docker":
            capability = self._docker_capability(capability)
        else:
            capability = self._host_capability(capability)
        if not deep or not capability.get("available"):
            return capability
        if self._deep_capability is not None:
            return dict(self._deep_capability)
        try:
            probe = self._invoke(
                {
                    "schema_version": "1.0",
                    "action": "capability",
                    "model": self.settings.opencode_model,
                    "base_url": self.settings.deepseek_base_url,
                    "timeout_ms": 30_000,
                },
                timeout_seconds=45,
            )
            models = [str(item) for item in probe.get("models", [])]
            capability["server_version"] = str(probe.get("server_version", ""))
            capability["models"] = models
            if self.settings.opencode_model not in models:
                capability["available"] = False
                capability["detail"] = (
                    f"DeepSeek model {self.settings.opencode_model!r} is not exposed by OpenCode"
                )
        except Exception as exc:
            capability["available"] = False
            capability["detail"] = f"OpenCode capability probe failed: {exc}"
        if capability.get("available"):
            self._deep_capability = dict(capability)
        return capability

    def investigate(
        self,
        *,
        scan: Scan,
        task: InvestigationTask,
        entries: list[EntryPoint],
        workspace: Path,
        evidence: list[dict[str, Any]],
        platform_context: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
    ) -> OpenCodeRunResult:
        if not workspace.is_dir():
            raise ValueError("scan workspace is unavailable")
        capability = self.capability(deep=False)
        if not capability.get("available"):
            raise RuntimeError(str(capability.get("detail")))
        timeout = timeout_seconds or self.settings.task_timeout_seconds
        payload = {
            "schema_version": "1.0",
            "action": "investigate",
            "prompt": investigation_prompt(
                scan,
                task,
                entries,
                evidence,
                platform_context or {},
                direct_tool_access=False,
            ),
            "developer_instructions": developer_instructions(direct_tool_access=False),
            "model": self.settings.opencode_model,
            "base_url": self.settings.deepseek_base_url,
            "output_schema": AGENT_RESULT_JSON_SCHEMA,
            "timeout_ms": max(1, timeout) * 1000,
        }
        response = self._invoke(payload, timeout_seconds=timeout + 15)
        return OpenCodeRunResult(
            thread_id=str(response["thread_id"]),
            turn_id=str(response["turn_id"]),
            result=AgentInvestigationResult.model_validate(response["result"]),
            usage=dict(response.get("usage") or {}),
        )

    def _configuration_error(self) -> str | None:
        if self.settings.opencode_isolation not in {"host", "docker"}:
            return "APKSCANNER_OPENCODE_ISOLATION must be host or docker"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.settings.opencode_model):
            return "APKSCANNER_OPENCODE_MODEL contains unsupported characters"
        if self.settings.deepseek_base_url:
            parsed = urlsplit(self.settings.deepseek_base_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                return (
                    "APKSCANNER_DEEPSEEK_BASE_URL must be an HTTP(S) URL without credentials, "
                    "query parameters, or fragments"
                )
            if parsed.scheme == "http" and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                return "plain HTTP DeepSeek gateways are allowed only on loopback"
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key or not api_key.strip():
            return "DEEPSEEK_API_KEY is not configured"
        return None

    def _host_capability(self, capability: dict[str, Any]) -> dict[str, Any]:
        node = self.settings.opencode_node_bin or shutil.which("node")
        if node is None:
            return {
                **capability,
                "available": False,
                "detail": "Node.js 22 or newer is required for the OpenCode worker",
            }
        try:
            node_version = subprocess.run(
                [node, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {
                **capability,
                "available": False,
                "detail": "Node.js 22 or newer is required for the OpenCode worker",
            }
        match = re.fullmatch(
            r"v?(?P<major>\d+)(?:\.\d+){0,2}", node_version.stdout.strip()
        )
        if node_version.returncode != 0 or match is None or int(match.group("major")) < 22:
            return {
                **capability,
                "available": False,
                "detail": "Node.js 22 or newer is required for the OpenCode worker",
            }
        worker = self.worker_dir / "worker.mjs"
        if not worker.is_file():
            return {
                **capability,
                "available": False,
                "detail": f"OpenCode worker is missing: {worker}",
            }
        sdk_version = self._installed_package_version("@opencode-ai/sdk")
        cli_version = self._installed_package_version("opencode-ai")
        if sdk_version != OPENCODE_SDK_VERSION or cli_version != OPENCODE_CLI_VERSION:
            return {
                **capability,
                "available": False,
                "detail": (
                    f"run npm ci --prefix {self.worker_dir}; expected SDK/CLI "
                    f"{OPENCODE_SDK_VERSION}, found {sdk_version or 'missing'}/"
                    f"{cli_version or 'missing'}"
                ),
            }
        opencode_bin = self.worker_dir / "node_modules" / ".bin" / "opencode"
        if not opencode_bin.is_file() or not os.access(opencode_bin, os.X_OK):
            return {
                **capability,
                "available": False,
                "detail": "the pinned OpenCode CLI executable is missing or not executable",
            }
        return capability

    def _docker_capability(self, capability: dict[str, Any]) -> dict[str, Any]:
        executable = shutil.which("docker")
        if executable is None:
            return {
                **capability,
                "available": False,
                "detail": "Docker isolation was requested but docker is not installed",
            }
        image = self.settings.opencode_docker_image
        if not image or not re.fullmatch(r"[A-Za-z0-9_./:@-]+", image):
            return {
                **capability,
                "available": False,
                "detail": "APKSCANNER_OPENCODE_DOCKER_IMAGE is invalid",
            }
        try:
            inspected = subprocess.run(
                [
                    executable,
                    "image",
                    "inspect",
                    "--format",
                    (
                        '{{ index .Config.Labels "io.apkscanner.opencode-sdk-version" }}'
                        '|{{ index .Config.Labels "io.apkscanner.opencode-version" }}'
                    ),
                    image,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {**capability, "available": False, "detail": f"Docker probe failed: {exc}"}
        if inspected.returncode != 0:
            return {
                **capability,
                "available": False,
                "detail": f"build the OpenCode worker image first: {image}",
            }
        expected = f"{OPENCODE_SDK_VERSION}|{OPENCODE_CLI_VERSION}"
        if inspected.stdout.strip() != expected:
            return {
                **capability,
                "available": False,
                "detail": "OpenCode worker image is stale or has incompatible SDK/CLI labels",
            }
        return capability

    def _installed_package_version(self, package: str) -> str | None:
        package_path = self.worker_dir / "node_modules"
        for part in package.split("/"):
            package_path /= part
        package_path /= "package.json"
        try:
            value = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        version = value.get("version")
        return str(version) if version else None

    def _invoke(self, payload: dict[str, Any], *, timeout_seconds: int) -> dict[str, Any]:
        if self.settings.opencode_isolation == "docker":
            return self._invoke_docker(payload, timeout_seconds=timeout_seconds)
        return self._invoke_host(payload, timeout_seconds=timeout_seconds)

    def _invoke_host(
        self, payload: dict[str, Any], *, timeout_seconds: int
    ) -> dict[str, Any]:
        node = self.settings.opencode_node_bin or shutil.which("node")
        if node is None:
            raise RuntimeError("Node.js is not installed")
        worker = self.worker_dir / "worker.mjs"
        with tempfile.TemporaryDirectory(prefix="apkscanner-opencode-") as temporary:
            root = Path(temporary)
            env = self._worker_environment(root)
            process = subprocess.Popen(
                [node, str(worker)],
                cwd=root,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(
                    json.dumps(payload, ensure_ascii=False),
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                self._kill_process_group(process)
                process.communicate()
                raise TimeoutError(
                    f"OpenCode investigation exceeded {timeout_seconds} seconds"
                ) from exc
        if process.returncode != 0:
            detail = stderr.strip()[-3000:] or "worker returned no diagnostic"
            raise RuntimeError(f"OpenCode worker failed: {detail}")
        return self._parse_worker_response(stdout)

    def _worker_environment(self, root: Path) -> dict[str, str]:
        allowed = {
            "DEEPSEEK_API_KEY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "all_proxy",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
        }
        env = {key: value for key, value in os.environ.items() if key in allowed}
        bin_dir = self.worker_dir / "node_modules" / ".bin"
        env["PATH"] = os.pathsep.join(
            value for value in (str(bin_dir), os.environ.get("PATH")) if value
        )
        env.update(
            {
                "HOME": str(root / "home"),
                "XDG_DATA_HOME": str(root / "data"),
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_CACHE_HOME": str(root / "cache"),
                "XDG_STATE_HOME": str(root / "state"),
                "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                "OPENCODE_DISABLE_CLAUDE_CODE": "1",
                "OPENCODE_DISABLE_MODELS_FETCH": "1",
                "OPENCODE_DISABLE_AUTOUPDATE": "1",
                "OPENCODE_PURE": "1",
            }
        )
        return env

    def _invoke_docker(
        self, payload: dict[str, Any], *, timeout_seconds: int
    ) -> dict[str, Any]:
        executable = shutil.which("docker")
        if executable is None:
            raise RuntimeError("Docker is not installed")
        safe_action = re.sub(r"[^a-z0-9-]", "-", str(payload.get("action", "run")).lower())[:24]
        container_name = f"apk-scanner-opencode-{safe_action}-{uuid.uuid4().hex[:8]}"
        command = [
            executable,
            "run",
            "--rm",
            "--name",
            container_name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=3g",
            "--cpus=2",
            "--network=bridge",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=256m",
            "--tmpfs",
            "/home/node:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700",
            "--workdir",
            "/sandbox",
            "--env",
            "HOME=/home/node",
            "--env",
            "XDG_DATA_HOME=/home/node/data",
            "--env",
            "XDG_CONFIG_HOME=/home/node/config",
            "--env",
            "XDG_CACHE_HOME=/home/node/cache",
            "--env",
            "XDG_STATE_HOME=/home/node/state",
            "--env",
            "DEEPSEEK_API_KEY",
        ]
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "all_proxy",
        ):
            if os.getenv(name):
                command.extend(["--env", name])
        command.append(self.settings.opencode_docker_image)
        try:
            completed = subprocess.run(
                command,
                input=json.dumps(payload, ensure_ascii=False),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            subprocess.run(
                [executable, "rm", "-f", container_name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=20,
                check=False,
            )
            raise TimeoutError(
                f"containerized OpenCode investigation exceeded {timeout_seconds} seconds"
            ) from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip()[-3000:] or "worker returned no diagnostic"
            raise RuntimeError(f"containerized OpenCode worker failed: {detail}")
        return self._parse_worker_response(completed.stdout)

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
            return
        process.kill()

    @staticmethod
    def _parse_worker_response(stdout: str) -> dict[str, Any]:
        try:
            value = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("OpenCode worker returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeError("OpenCode worker returned a non-object response")
        return value
