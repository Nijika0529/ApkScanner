from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent_workspace import SessionWorkspace
from .config import Settings

_SCAN_ID = re.compile(r"^[a-f0-9-]{36}$")


@dataclass(frozen=True, slots=True)
class ScanContainer:
    scan_id: str
    generation: int
    container_id: str
    name: str
    scan_workspace: Path
    sessions_root: Path


class CodexDockerExecutor:
    """Own one keyless keeper container per active scan and UID-scoped exec sessions."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.RLock()
        self._containers: dict[str, ScanContainer] = {}
        self._generations: dict[str, int] = {}

    def ensure_scan_container(
        self,
        *,
        scan_id: str,
        scan_workspace: Path,
        sessions_root: Path,
    ) -> ScanContainer:
        self._validate_scan(scan_id)
        scan_workspace = self._safe_directory(scan_workspace, "scan workspace")
        sessions_root = self._safe_directory(sessions_root, "Agent sessions root")
        with self._lock:
            existing = self._containers.get(scan_id)
            if existing is not None and self._is_running(existing):
                return existing
            if existing is not None:
                self._containers.pop(scan_id, None)
                self._remove_container(existing.container_id)
            if len(self._containers) >= self.settings.codex_max_containers:
                raise RuntimeError("global Codex scan-container limit is exhausted")
            generation = self._generations.get(scan_id, 0) + 1
            self._generations[scan_id] = generation
            name = f"apk-scanner-{scan_id.replace('-', '')[:12]}-{uuid.uuid4().hex[:8]}"
            command = self.build_run_command(
                scan_id=scan_id,
                generation=generation,
                name=name,
                scan_workspace=scan_workspace,
                sessions_root=sessions_root,
            )
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                text=True,
                timeout=120,
            )
            if completed.returncode != 0:
                detail = completed.stderr.strip()[-3000:] or "docker returned no diagnostic"
                raise RuntimeError(f"could not start Codex scan container: {detail}")
            container_id = completed.stdout.strip()
            if not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
                raise RuntimeError("Docker returned an invalid scan container ID")
            container = ScanContainer(
                scan_id=scan_id,
                generation=generation,
                container_id=container_id,
                name=name,
                scan_workspace=scan_workspace,
                sessions_root=sessions_root,
            )
            self._containers[scan_id] = container
            return container

    def build_run_command(
        self,
        *,
        scan_id: str,
        generation: int,
        name: str,
        scan_workspace: Path,
        sessions_root: Path,
    ) -> list[str]:
        executable = self._docker()
        command = [
            executable,
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            "io.apkscanner.role=codex-scan",
            "--label",
            f"io.apkscanner.scan-id={scan_id}",
            "--label",
            f"io.apkscanner.generation={generation}",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit",
            str(self.settings.codex_pids_limit),
            "--memory",
            self.settings.codex_memory_limit,
            "--cpus",
            str(self.settings.codex_cpu_limit),
            "--network=bridge",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,size={self.settings.codex_tmpfs_size}",
            "--mount",
            f"type=bind,source={sessions_root},target=/agent-workspaces",
        ]
        for name in ("jadx", "apktool", "archive"):
            source = scan_workspace / name
            if source.is_dir():
                command.extend(
                    [
                        "--mount",
                        f"type=bind,source={source},target=/scan-input/{name},readonly",
                    ]
                )
        command.extend(
            [
                "--entrypoint",
                "python",
                self.settings.codex_docker_image,
                "-m",
                "apkscanner.container_keeper",
            ]
        )
        return command

    def start_worker(
        self,
        *,
        container: ScanContainer,
        session: SessionWorkspace,
    ) -> subprocess.Popen[str]:
        command = self.build_worker_command(container=container, session=session)
        return subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

    def build_worker_command(
        self,
        *,
        container: ScanContainer,
        session: SessionWorkspace,
    ) -> list[str]:
        if container.scan_id != session.scan_id:
            raise ValueError("Agent session does not belong to the scan container")
        command = [
            self._docker(),
            "exec",
            "--interactive",
            "--user",
            f"{session.uid}:{session.gid}",
            "--workdir",
            session.container_workspace,
            "--env",
            f"HOME={session.container_home}",
            "--env",
            f"CODEX_HOME={session.container_codex_home}",
            "--env",
            f"TMPDIR={session.container_tmp}",
            "--env",
            "LANG=C.UTF-8",
        ]
        if os.getenv("DEEPSEEK_API_KEY"):
            # The value is read by the Docker client and never placed in argv.
            command.extend(["--env", "DEEPSEEK_API_KEY"])
        command.extend(
            [
                container.container_id,
                "python",
                "-m",
                "apkscanner.codex_worker",
            ]
        )
        return command

    def kill_session(self, container: ScanContainer, session: SessionWorkspace) -> None:
        with suppress(Exception):
            subprocess.run(
                [
                    self._docker(),
                    "exec",
                    "--user",
                    "0:0",
                    container.container_id,
                    "python",
                    "-m",
                    "apkscanner.session_control",
                    "kill",
                    "--uid",
                    str(session.uid),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=20,
            )

    def close_scan(self, scan_id: str) -> None:
        with self._lock:
            container = self._containers.pop(scan_id, None)
        if container is None:
            return
        self._remove_container(container.container_id)

    def _remove_container(self, container_id: str) -> None:
        subprocess.run(
            [self._docker(), "rm", "-f", container_id],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def shutdown(self) -> None:
        with self._lock:
            scan_ids = list(self._containers)
        for scan_id in scan_ids:
            with suppress(Exception):
                self.close_scan(scan_id)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "scan_id": item.scan_id,
                    "generation": item.generation,
                    "container_id": item.container_id[:12],
                    "name": item.name,
                }
                for item in self._containers.values()
            ]

    def _is_running(self, container: ScanContainer) -> bool:
        completed = subprocess.run(
            [self._docker(), "inspect", "--format", "{{.State.Running}}", container.container_id],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
        return completed.returncode == 0 and completed.stdout.strip() == "true"

    @staticmethod
    def _safe_directory(path: Path, label: str) -> Path:
        if path.is_symlink():
            raise ValueError(f"{label} cannot be a symbolic link")
        resolved = path.resolve()
        if not resolved.is_dir() or "," in str(resolved):
            raise ValueError(f"{label} is unavailable or unsafe for a Docker bind mount")
        return resolved

    @staticmethod
    def _validate_scan(scan_id: str) -> None:
        if not _SCAN_ID.fullmatch(scan_id):
            raise ValueError("scan ID is unsafe for a Docker container")

    @staticmethod
    def _docker() -> str:
        executable = shutil.which("docker")
        if executable is None:
            raise RuntimeError("Docker is required for Codex execution")
        return executable
