from __future__ import annotations

import json
import os
import re
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.config import Settings
from ..core.permissions import ensure_private_directory
from .agent_execution import WorkspaceManifest, WorkspaceMount

_IDENTIFIER = re.compile(r"^[a-f0-9-]{8,64}$")
_ROLE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


@dataclass(frozen=True, slots=True)
class SessionWorkspace:
    scan_id: str
    task_id: str
    attempt: int
    role: str
    workspace_key: str
    uid: int
    gid: int
    root: Path
    workspace: Path
    home: Path
    codex_home: Path
    tmp: Path
    cache: Path
    context: Path
    manifest: WorkspaceManifest

    @property
    def container_root(self) -> str:
        return f"/agent-workspaces/{self.workspace_key}"

    @property
    def container_workspace(self) -> str:
        return f"{self.container_root}/workspace"

    @property
    def container_home(self) -> str:
        return f"{self.container_root}/home"

    @property
    def container_codex_home(self) -> str:
        return f"{self.container_root}/codex-home"

    @property
    def container_tmp(self) -> str:
        return f"{self.container_root}/tmp"


class AgentWorkspaceManager:
    """Own scan/session paths and a non-reused UID pool for scan-scoped containers."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.RLock()
        self._leases: dict[tuple[str, str, int, str], SessionWorkspace] = {}
        self._used_uids: dict[str, set[int]] = {}

    def scan_sessions_root(self, scan_id: str) -> Path:
        self._validate_identifier(scan_id, "scan")
        return self.settings.data_dir / "agent-sessions" / scan_id

    def prepare_scan(self, scan_id: str) -> Path:
        root = self.scan_sessions_root(scan_id)
        ensure_private_directory(root.parent)
        root.mkdir(mode=0o711, parents=True, exist_ok=True)
        self._reject_symlink(root)
        root.chmod(0o711)
        return root

    def prepare_session(
        self,
        *,
        scan_id: str,
        task_id: str,
        attempt: int,
        role: str,
        source_workspace: Path,
        context: dict[str, Any] | None = None,
    ) -> SessionWorkspace:
        if os.geteuid() != 0:
            raise PermissionError(
                "scan-scoped Unix UID isolation currently requires a root control process"
            )
        self._validate_identifier(scan_id, "scan")
        self._validate_identifier(task_id, "task")
        if attempt < 1 or attempt > 10_000:
            raise ValueError("attempt must be within 1..10000")
        if not _ROLE.fullmatch(role):
            raise ValueError("session role is invalid")
        source_workspace = source_workspace.resolve()
        if not source_workspace.is_dir():
            raise ValueError("source Agent workspace does not exist")
        key = (scan_id, task_id, attempt, role)
        with self._lock:
            existing = self._leases.get(key)
            if existing is not None:
                self._copy_bounded_workspace(source_workspace, existing.workspace)
                if context is not None:
                    self._write_context(existing, context)
                if role in {"verifier", "operator"} and not (existing.home / ".ssh").is_dir():
                    self._copy_verifier_ssh(existing)
                return existing
            workspace_key = self._workspace_key(task_id, attempt, role)
            scan_root = self.prepare_scan(scan_id)
            self._reserve_retained_uids(scan_id, scan_root)
            root = scan_root / workspace_key
            if root.exists():
                restored = self._restore_session(
                    scan_id=scan_id,
                    task_id=task_id,
                    attempt=attempt,
                    role=role,
                    workspace_key=workspace_key,
                    root=root,
                )
                self._copy_bounded_workspace(source_workspace, restored.workspace)
                if context is not None:
                    self._write_context(restored, context)
                if role in {"verifier", "operator"} and not (
                    restored.home / ".ssh"
                ).is_dir():
                    self._copy_verifier_ssh(restored)
                self._leases[key] = restored
                return restored
            # Retained role workspaces are audit state, not active Codex workers. Do not make a
            # fourth task fail merely because earlier primary/critic directories still exist.
            # Runtime worker capacity is queued by CodexInvestigator and these UIDs remain unique.
            uid = self._allocate_uid(scan_id)
            root.mkdir(mode=0o711)
            root.chmod(0o711)
            paths = {
                name: root / name
                for name in ("workspace", "home", "codex-home", "tmp", "cache", "context")
            }
            for name, path in paths.items():
                path.mkdir(mode=0o700)
                if name == "context":
                    os.chown(path, 0, uid, follow_symlinks=False)
                    path.chmod(0o550)
                else:
                    os.chown(path, uid, uid, follow_symlinks=False)
                    path.chmod(0o700)
            manifest = WorkspaceManifest(
                scan_id=scan_id,
                workspace_key=workspace_key,
                uid=uid,
                gid=uid,
                mounts=(
                    WorkspaceMount(
                        logical_name="session_workspace",
                        container_path=f"/agent-workspaces/{workspace_key}/workspace",
                        access="rw",
                    ),
                    WorkspaceMount(
                        logical_name="scan_input",
                        container_path="/scan-input",
                        access="ro",
                    ),
                ),
            )
            session = SessionWorkspace(
                scan_id=scan_id,
                task_id=task_id,
                attempt=attempt,
                role=role,
                workspace_key=workspace_key,
                uid=uid,
                gid=uid,
                root=root,
                workspace=paths["workspace"],
                home=paths["home"],
                codex_home=paths["codex-home"],
                tmp=paths["tmp"],
                cache=paths["cache"],
                context=paths["context"],
                manifest=manifest,
            )
            self._copy_bounded_workspace(source_workspace, session.workspace)
            self._write_context(session, context or {})
            if role in {"verifier", "operator"}:
                self._copy_verifier_ssh(session)
            self._leases[key] = session
            return session

    def _reserve_retained_uids(self, scan_id: str, scan_root: Path) -> None:
        used = self._used_uids.setdefault(scan_id, set())
        for context_file in scan_root.glob("*/context/session.json"):
            if context_file.is_symlink() or not context_file.is_file():
                continue
            try:
                payload = json.loads(context_file.read_text(encoding="utf-8"))
                uid = int(payload["uid"])
            except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
                continue
            if self.settings.codex_uid_min <= uid <= self.settings.codex_uid_max:
                used.add(uid)

    def _restore_session(
        self,
        *,
        scan_id: str,
        task_id: str,
        attempt: int,
        role: str,
        workspace_key: str,
        root: Path,
    ) -> SessionWorkspace:
        self._reject_symlink(root)
        context_file = root / "context" / "session.json"
        try:
            payload = json.loads(context_file.read_text(encoding="utf-8"))
            uid = int(payload["uid"])
            manifest = WorkspaceManifest.model_validate(payload["workspace_manifest"])
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("retained Agent session metadata is invalid") from exc
        if (
            payload.get("scan_id") != scan_id
            or payload.get("task_id") != task_id
            or payload.get("attempt") != attempt
            or payload.get("role") != role
            or manifest.scan_id != scan_id
            or manifest.workspace_key != workspace_key
            or manifest.uid != uid
            or manifest.gid != uid
            or not self.settings.codex_uid_min <= uid <= self.settings.codex_uid_max
        ):
            raise RuntimeError("retained Agent session identity does not match the request")
        paths = {
            name: root / name
            for name in ("workspace", "home", "codex-home", "tmp", "cache", "context")
        }
        for path in paths.values():
            if path.is_symlink() or not path.is_dir():
                raise RuntimeError("retained Agent session directory is unavailable")
        self._used_uids.setdefault(scan_id, set()).add(uid)
        return SessionWorkspace(
            scan_id=scan_id,
            task_id=task_id,
            attempt=attempt,
            role=role,
            workspace_key=workspace_key,
            uid=uid,
            gid=uid,
            root=root,
            workspace=paths["workspace"],
            home=paths["home"],
            codex_home=paths["codex-home"],
            tmp=paths["tmp"],
            cache=paths["cache"],
            context=paths["context"],
            manifest=manifest,
        )

    def forget_scan(self, scan_id: str) -> None:
        """Forget in-memory leases after the container is gone; keep files for audit/ingestion."""
        with self._lock:
            terminal = [value for key, value in self._leases.items() if key[0] == scan_id]
            self._leases = {key: value for key, value in self._leases.items() if key[0] != scan_id}
            self._used_uids.pop(scan_id, None)
            for session in terminal:
                self._purge_runtime_credentials(session)

    def forget_task(self, scan_id: str, task_id: str) -> None:
        """Release a terminal task's active-session slots while retaining its audit files.

        UIDs remain reserved until the scan container is removed. Reusing a UID
        inside the same container could let a later task read processes or files
        that survived an imperfect cleanup.
        """
        with self._lock:
            terminal = [
                value
                for key, value in self._leases.items()
                if key[0] == scan_id and key[1] == task_id
            ]
            self._leases = {
                key: value
                for key, value in self._leases.items()
                if not (key[0] == scan_id and key[1] == task_id)
            }
            for session in terminal:
                self._purge_runtime_credentials(session)

    @staticmethod
    def _purge_runtime_credentials(session: SessionWorkspace) -> None:
        """Remove transient provider snapshots and copied verifier SSH material."""

        snapshots = session.codex_home / "shell_snapshots"
        if snapshots.is_symlink() or snapshots.is_file():
            snapshots.unlink(missing_ok=True)
        elif snapshots.is_dir():
            shutil.rmtree(snapshots)
        ssh_copy = session.home / ".ssh"
        if ssh_copy.is_symlink() or ssh_copy.is_file():
            ssh_copy.unlink(missing_ok=True)
        elif ssh_copy.is_dir():
            shutil.rmtree(ssh_copy)

    def _copy_verifier_ssh(self, session: SessionWorkspace) -> None:
        """Copy the host's OpenSSH material into only the verifier's private HOME."""

        source = self.settings.adaptive_verifier_ssh_source
        if (
            not self.settings.adaptive_verifier_copy_host_ssh
            or source is None
            or not source.is_dir()
        ):
            return
        source = source.resolve()
        destination = session.home / ".ssh"
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(mode=0o700)
        os.chown(destination, session.uid, session.gid, follow_symlinks=False)
        destination.chmod(0o700)
        for item in source.rglob("*"):
            relative = item.relative_to(source)
            target = destination / relative
            if item.is_dir() and not item.is_symlink():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chown(target, session.uid, session.gid, follow_symlinks=False)
                target.chmod(0o700)
                continue
            if not item.is_file():
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(item, target, follow_symlinks=True)
            os.chown(target, session.uid, session.gid, follow_symlinks=False)
            target.chmod(0o600)

    def _allocate_uid(self, scan_id: str) -> int:
        used = self._used_uids.setdefault(scan_id, set())
        for uid in range(self.settings.codex_uid_min, self.settings.codex_uid_max + 1):
            if uid not in used:
                used.add(uid)
                return uid
        raise RuntimeError("Codex UID pool is exhausted for this scan container")

    @staticmethod
    def _workspace_key(task_id: str, attempt: int, role: str) -> str:
        compact = task_id.replace("-", "")[:16]
        # Logical role names use snake_case, while the worker deliberately
        # accepts only a narrow, shell-safe path alphabet.  Keep the logical
        # role on SessionWorkspace, but canonicalize its path component here so
        # roles such as ``rescue_explorer`` cannot create a workspace that the
        # worker later rejects.
        path_role = role.replace("_", "-")
        return f"{compact}-a{attempt}-{path_role}"

    def _write_context(self, session: SessionWorkspace, value: dict[str, Any]) -> None:
        target = session.context / "session.json"
        target.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "scan_id": session.scan_id,
                    "task_id": session.task_id,
                    "attempt": session.attempt,
                    "role": session.role,
                    "uid": session.uid,
                    "workspace_manifest": session.manifest.model_dump(mode="json"),
                    "context": value,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        os.chown(target, 0, session.gid, follow_symlinks=False)
        target.chmod(0o440)

    def _copy_bounded_workspace(self, source: Path, target: Path) -> None:
        for item in source.rglob("*"):
            if item.is_symlink():
                raise ValueError("Agent context cannot contain symbolic links")
            relative = item.relative_to(source)
            destination = target / relative
            if item.is_dir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chown(destination, target.stat().st_uid, target.stat().st_gid)
                destination.chmod(0o700)
                continue
            if not item.is_file():
                raise ValueError("Agent context contains an unsupported filesystem entry")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(item, destination)
            os.chown(destination, target.stat().st_uid, target.stat().st_gid)
            destination.chmod(0o600)

    @staticmethod
    def _validate_identifier(value: str, kind: str) -> None:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"{kind} ID is unsafe for an Agent workspace")

    @staticmethod
    def _reject_symlink(path: Path) -> None:
        if path.is_symlink():
            raise ValueError("Agent workspace root cannot be a symbolic link")
