from __future__ import annotations

import atexit
import http.client
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

_ALIAS = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}\Z")
_UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_PHASES = frozenset({"attack", "control", "quiet"})
_SSH_DIRECTIVES = frozenset({
    "host", "hostname", "user", "port", "identityfile", "identitiesonly",
    "userknownhostsfile", "stricthostkeychecking", "serveraliveinterval",
    "serveralivecountmax", "hostkeyalgorithms", "pubkeyacceptedalgorithms",
    "preferredauthentications", "batchmode", "addressfamily", "connecttimeout",
})
_SWEEP_MAX_INTERVAL_SECONDS = 30.0
_SWEEP_CLEANUP_RETRIES = 3


def _validate_ssh_config(path: Path, alias: str) -> None:
    """Require a dedicated, inert SSH config; no ProxyCommand/Include/Match."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("an explicit regular SSH config file is required")
    details = path.stat()
    if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or details.st_size > 32 * 1024:
        raise ValueError("SSH config is writable by others or too large")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (UnicodeError, OSError) as exc:
        raise ValueError("SSH config could not be read") from exc
    host_seen = False
    hostname_seen = False
    user_seen = False
    for line in lines:
        try:
            fields = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ValueError("SSH config contains invalid quoting") from exc
        if not fields:
            continue
        directive = fields[0].lower()
        if directive not in _SSH_DIRECTIVES:
            raise ValueError(f"SSH config directive {directive!r} is not allowed")
        if directive == "host":
            if host_seen or fields[1:] != [alias]:
                raise ValueError("SSH config must contain exactly one literal allowlisted Host")
            host_seen = True
        elif not host_seen:
            raise ValueError("SSH config must begin with the allowlisted Host")
        elif len(fields) < 2:
            raise ValueError("SSH config directive is missing a value")
        elif directive == "hostname":
            hostname_seen = True
        elif directive == "user":
            user_seen = True
    if not (host_seen and hostname_seen and user_seen):
        raise ValueError("SSH config needs Host, HostName and User")


@dataclass(frozen=True, slots=True)
class RemoteObserverConfig:
    ssh_alias: str
    allowed_ssh_aliases: tuple[str, ...]
    ssh_config_path: Path
    public_base_url: str
    local_observer_port: int
    remote_loopback_port: int = 15880
    ssh_connect_timeout_seconds: int = 10
    public_probe_timeout_seconds: int = 4
    startup_timeout_seconds: int = 12

    def __post_init__(self) -> None:
        if (
            _ALIAS.fullmatch(self.ssh_alias) is None
            or self.ssh_alias not in self.allowed_ssh_aliases
            or any(_ALIAS.fullmatch(item) is None for item in self.allowed_ssh_aliases)
        ):
            raise ValueError("SSH alias must be explicitly allowlisted")
        _validate_ssh_config(self.ssh_config_path, self.ssh_alias)
        parsed = urlsplit(self.public_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("remote observer public base URL must be an HTTPS origin")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("remote observer public base URL has an invalid port") from exc
        if not all(1 <= port <= 65535 for port in (
            self.local_observer_port, self.remote_loopback_port,
        )):
            raise ValueError("observer ports must be explicit TCP ports")
        if not 1 <= self.ssh_connect_timeout_seconds <= 60:
            raise ValueError("SSH connect timeout is invalid")
        if not 1 <= self.public_probe_timeout_seconds <= 30:
            raise ValueError("public probe timeout is invalid")
        if not 1 <= self.startup_timeout_seconds <= 60:
            raise ValueError("tunnel startup timeout is invalid")


@dataclass(frozen=True, slots=True)
class RemoteActionReceipt:
    action: str
    experiment_id: str
    deployment_id: str
    tunnel_id: str
    root_nonce: str
    request_id: str
    status: str
    received_at: str
    public_probe_ok: bool | None = None


@dataclass(frozen=True, slots=True)
class RemoteDeployment:
    experiment_id: str
    deployment_id: str
    tunnel_id: str
    base_url: str
    status: str
    expires_at: str


@dataclass(slots=True)
class _DeploymentState:
    experiment_id: str
    deployment_id: str
    root_nonce: str
    phase_nonces: dict[str, str]
    expires_at: datetime
    tunnel_id: str = ""
    status: str = "deploying"
    receipts: list[RemoteActionReceipt] = field(default_factory=list)


class TunnelHandle(Protocol):
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...
    def kill(self) -> None: ...


class ReverseTunnelTransport(Protocol):
    def start(self, config: RemoteObserverConfig) -> TunnelHandle: ...


class SSHReverseTunnelTransport:
    """Only opens a loopback-bound reverse forwarding; runs no remote command."""

    def start(self, config: RemoteObserverConfig) -> TunnelHandle:
        argv = [
            "ssh", "-F", str(config.ssh_config_path.resolve()),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "ForwardAgent=no",
            "-o", "GatewayPorts=no",
            "-o", f"ConnectTimeout={config.ssh_connect_timeout_seconds}",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=2",
            "-N", "-T", "-R",
            f"127.0.0.1:{config.remote_loopback_port}:127.0.0.1:{config.local_observer_port}",
            config.ssh_alias,
        ]
        environment = {
            key: value for key, value in os.environ.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "SSH_AUTH_SOCK"}
        }
        return subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )


def _public_probe(url: str, expected: dict[str, str], timeout_seconds: int) -> bool:
    """Verify TLS and a nonce-bound local response without recording a page event."""

    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port, timeout=timeout_seconds,
    )
    try:
        connection.request("GET", f"{parsed.path}?{parsed.query}", headers={
            "User-Agent": "APKScanner-Observer-Health/1.0",
        })
        response = connection.getresponse()
        body = response.read(1025)
        if (
            response.status != 200
            or len(body) > 1024
            or not response.getheader("Content-Type", "").startswith("application/json")
            or "no-store" not in response.getheader("Cache-Control", "")
        ):
            return False
        payload = json.loads(body)
        return isinstance(payload, dict) and payload == expected
    except (OSError, http.client.HTTPException, ValueError, UnicodeError):
        return False
    finally:
        connection.close()


class RemoteObserverBackend:
    """Lease one SSH reverse tunnel across task-scoped Web experiments.

    The remote host needs an operator-managed, path-limited HTTPS reverse proxy
    to its loopback port. This backend never uploads files, executes a remote
    helper, alters Nginx, or exposes SSH credentials to the Agent workspace.
    """

    def __init__(
        self,
        config: RemoteObserverConfig,
        *,
        transport: ReverseTunnelTransport | None = None,
        probe: Callable[[str, dict[str, str], int], bool] | None = None,
    ) -> None:
        self.config = config
        self.transport = transport or SSHReverseTunnelTransport()
        self._probe = probe or _public_probe
        self._lock = threading.RLock()
        self._sweep_condition = threading.Condition(self._lock)
        self._sweep_stop = False
        self._sweeper: threading.Thread | None = None
        self._sweeper_active = False
        self._closed = False
        self._tunnel: TunnelHandle | None = None
        self._tunnel_id: str | None = None
        self._deployments: dict[str, _DeploymentState] = {}
        atexit.register(_close_at_exit, weakref.ref(self))

    def _ensure_sweeper(self) -> None:
        """Start one daemon per backend; all callers already hold ``_lock``."""

        if self._closed:
            raise RuntimeError("remote observer backend is closed")
        if not self._sweeper_active:
            self._sweep_stop = False
            self._sweeper_active = True
            self._sweeper = threading.Thread(
                target=self._sweep_loop,
                name=f"apkscanner-observer-lease-{id(self):x}",
                daemon=True,
            )
            self._sweeper.start()
        self._sweep_condition.notify_all()

    def _sweep_loop(self) -> None:
        """Expire leases without gateway traffic; never loop forever on bad cleanup."""

        failed_cleanups = 0
        with self._sweep_condition:
            try:
                while not self._sweep_stop:
                    self._expire_leases()
                    if self._tunnel is None:
                        return
                    active = [
                        state.expires_at for state in self._deployments.values()
                        if state.status == "healthy"
                    ]
                    if active:
                        failed_cleanups = 0
                        wait_seconds = min(
                            _SWEEP_MAX_INTERVAL_SECONDS,
                            max(0.0, (min(active) - datetime.now(UTC)).total_seconds()),
                        )
                    else:
                        failed_cleanups += 1
                        if failed_cleanups >= _SWEEP_CLEANUP_RETRIES:
                            return
                        wait_seconds = 1.0
                    self._sweep_condition.wait(timeout=wait_seconds)
            finally:
                self._sweeper_active = False

    @staticmethod
    def _validate_identity(
        experiment_id: str, root_nonce: str, phase_nonces: dict[str, str],
    ) -> None:
        if _UUID.fullmatch(experiment_id) is None or _NONCE.fullmatch(root_nonce) is None:
            raise ValueError("experiment ID or root nonce is invalid")
        if (
            set(phase_nonces) != _PHASES
            or any(not isinstance(value, str) or _NONCE.fullmatch(value) is None
                   for value in phase_nonces.values())
            or len({root_nonce, *phase_nonces.values()}) != 4
        ):
            raise ValueError("three distinct phase nonces are required")

    def _receipt(
        self, state: _DeploymentState, action: str, status: str,
        *, public_probe_ok: bool | None = None,
    ) -> None:
        state.receipts.append(RemoteActionReceipt(
            action=action,
            experiment_id=state.experiment_id,
            deployment_id=state.deployment_id,
            tunnel_id=state.tunnel_id,
            root_nonce=state.root_nonce,
            request_id=secrets.token_urlsafe(18),
            status=status,
            received_at=datetime.now(UTC).isoformat(),
            public_probe_ok=public_probe_ok,
        ))

    def _probe_url(self, state: _DeploymentState) -> str:
        # WebExploitObserver's health route has no Event/Evidence side effect.
        return (
            f"{self.config.public_base_url.rstrip('/')}/web-observer/"
            f"{state.experiment_id}/attack/health?"
            f"nonce={state.phase_nonces['attack']}"
        )

    def _probe_public(self, state: _DeploymentState) -> bool:
        try:
            return bool(self._probe(
                self._probe_url(state),
                {
                    "schema_version": "1.0",
                    "experiment_id": state.experiment_id,
                    "nonce": state.root_nonce,
                    "phase_nonce": state.phase_nonces["attack"],
                    "status": "healthy",
                },
                self.config.public_probe_timeout_seconds,
            ))
        except Exception:
            return False

    def _stop_tunnel_if_idle(self) -> bool:
        if any(state.status == "healthy" for state in self._deployments.values()):
            return True
        tunnel = self._tunnel
        if tunnel is None:
            return True
        try:
            if tunnel.poll() is None:
                try:
                    tunnel.terminate()
                except OSError:
                    tunnel.kill()
                try:
                    tunnel.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tunnel.kill()
                    tunnel.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return False
        self._tunnel = None
        self._tunnel_id = None
        return True

    def _expire_leases(self) -> None:
        now = datetime.now(UTC)
        expired: list[_DeploymentState] = []
        for state in self._deployments.values():
            if state.status == "healthy" and now >= state.expires_at:
                state.status = "expired"
                self._receipt(state, "expire", "expired")
                expired.append(state)
        if not self._stop_tunnel_if_idle():
            for state in expired:
                state.status = "cleanup_pending"
                self._receipt(state, "cleanup", "cleanup_pending")

    def deploy(
        self,
        experiment_id: str,
        root_nonce: str,
        phase_nonces: dict[str, str],
        ttl_seconds: int,
    ) -> RemoteDeployment:
        self._validate_identity(experiment_id, root_nonce, phase_nonces)
        if not 30 <= ttl_seconds <= 1800:
            raise ValueError("remote observer TTL must be between 30 and 1800 seconds")
        with self._lock:
            if self._closed:
                raise RuntimeError("remote observer backend is closed")
            self._expire_leases()
            if any(
                state.status == "cleanup_pending" for state in self._deployments.values()
            ):
                raise RuntimeError("previous SSH tunnel cleanup is pending")
            existing = self._deployments.get(experiment_id)
            if existing is not None:
                if (
                    existing.status == "healthy"
                    and existing.root_nonce == root_nonce
                    and existing.phase_nonces == phase_nonces
                ):
                    return self._deployment(existing)
                raise ValueError("experiment ID already owns a remote observer lease")
            state = _DeploymentState(
                experiment_id=experiment_id,
                deployment_id=str(uuid4()),
                root_nonce=root_nonce,
                phase_nonces=dict(phase_nonces),
                expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            )
            self._deployments[experiment_id] = state
            try:
                if self._tunnel is not None and self._tunnel.poll() is not None:
                    for other in self._deployments.values():
                        if other.status == "healthy":
                            other.status = "unhealthy"
                            self._receipt(other, "health", "unhealthy", public_probe_ok=False)
                    self._tunnel = None
                    self._tunnel_id = None
                if self._tunnel is None:
                    self._tunnel = self.transport.start(self.config)
                    self._tunnel_id = str(uuid4())
                state.tunnel_id = self._tunnel_id or ""
                deadline = time.monotonic() + self.config.startup_timeout_seconds
                healthy = False
                while time.monotonic() < deadline:
                    if self._tunnel.poll() is not None:
                        break
                    if self._probe_public(state):
                        healthy = True
                        break
                    time.sleep(0.2)
                if not healthy:
                    raise RuntimeError("SSH tunnel or public HTTPS observer probe failed")
                state.status = "healthy"
                self._receipt(state, "deploy", "healthy", public_probe_ok=True)
                self._ensure_sweeper()
                return self._deployment(state)
            except Exception:
                state.status = "rolled_back"
                if not self._stop_tunnel_if_idle():
                    state.status = "cleanup_pending"
                self._receipt(state, "rollback", state.status, public_probe_ok=False)
                if self._tunnel is not None:
                    self._ensure_sweeper()
                raise

    def health(self, experiment_id: str) -> bool:
        with self._lock:
            self._expire_leases()
            state = self._owned(experiment_id)
            if state.status != "healthy":
                return False
            alive = self._tunnel is not None and self._tunnel.poll() is None
            public_ok = alive and self._probe_public(state)
            if not public_ok:
                state.status = "unhealthy"
                self._stop_tunnel_if_idle()
                self._sweep_condition.notify_all()
            self._receipt(state, "health", state.status, public_probe_ok=public_ok)
            return public_ok

    def revoke(self, experiment_id: str) -> bool:
        with self._lock:
            self._expire_leases()
            state = self._owned(experiment_id)
            if state.status in {"revoked", "rolled_back"}:
                return True
            state.status = "revoking"
            stopped = self._stop_tunnel_if_idle()
            state.status = "revoked" if stopped else "cleanup_pending"
            self._receipt(state, "revoke", state.status)
            self._sweep_condition.notify_all()
            return stopped

    def close(self) -> bool:
        """Revoke all leases and close only the SSH process owned by this backend."""

        with self._sweep_condition:
            self._closed = True
            self._sweep_stop = True
            self._sweep_condition.notify_all()
            for state in self._deployments.values():
                if state.status not in {"revoked", "rolled_back"}:
                    state.status = "revoking"
            stopped = self._stop_tunnel_if_idle()
            for state in self._deployments.values():
                if state.status == "revoking":
                    state.status = "revoked" if stopped else "cleanup_pending"
                    self._receipt(state, "close", state.status)
            sweeper = self._sweeper
        if sweeper is not None and sweeper is not threading.current_thread():
            sweeper.join(timeout=6)
        return stopped and (sweeper is None or not sweeper.is_alive())

    def receipts(self, experiment_id: str) -> tuple[RemoteActionReceipt, ...]:
        with self._lock:
            return tuple(self._owned(experiment_id).receipts)

    def status(self, experiment_id: str) -> str:
        with self._lock:
            self._expire_leases()
            return self._owned(experiment_id).status

    def sweep_expired(self) -> None:
        with self._lock:
            self._expire_leases()

    def _owned(self, experiment_id: str) -> _DeploymentState:
        state = self._deployments.get(experiment_id)
        if state is None:
            raise KeyError("remote observer experiment was not deployed by this backend")
        return state

    def _deployment(self, state: _DeploymentState) -> RemoteDeployment:
        return RemoteDeployment(
            experiment_id=state.experiment_id,
            deployment_id=state.deployment_id,
            tunnel_id=state.tunnel_id,
            base_url=self.config.public_base_url,
            status=state.status,
            expires_at=state.expires_at.isoformat(),
        )


def _close_at_exit(reference: weakref.ReferenceType[RemoteObserverBackend]) -> None:
    backend = reference()
    if backend is not None:
        with suppress(Exception):
            backend.close()
