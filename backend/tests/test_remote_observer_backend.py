from __future__ import annotations

import http.client
import json
import subprocess
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from apkscanner.core.db import Database
from apkscanner.core.models import Evidence, Finding, InvestigationTask, Scan
from apkscanner.core.schemas import WebExperimentRequest
from apkscanner.infrastructure.artifacts import ArtifactStore
from apkscanner.infrastructure.tools import TimeBudget
from apkscanner.runtime import remote_observer_smoke
from apkscanner.runtime.live_proof import LiveProofContext
from apkscanner.runtime.orchestrator import ScanOrchestrator
from apkscanner.runtime.remote_observer_backend import (
    RemoteActionReceipt,
    RemoteDeployment,
    RemoteObserverBackend,
    RemoteObserverConfig,
    SSHReverseTunnelTransport,
    _public_probe,
)
from apkscanner.runtime.remote_web_observer_adapter import (
    RemoteWebObserverAdapter,
    RemoteWebObserverSession,
)
from apkscanner.runtime.web_exploit_observer import WebExploitObserver
from sqlalchemy import select


class FakeProcess:
    def __init__(
        self, *, terminate_fails: bool = False, kill_fails: bool = False,
    ) -> None:
        self.alive = True
        self.terminations = 0
        self.kills = 0
        self.terminate_fails = terminate_fails
        self.kill_fails = kill_fails
        self.ended = threading.Event()

    def poll(self) -> int | None:
        return None if self.alive else 0

    def terminate(self) -> None:
        self.terminations += 1
        if self.terminate_fails:
            raise OSError("cannot terminate owned SSH process")
        self.alive = False
        self.ended.set()

    def wait(self, timeout: float | None = None) -> int:  # noqa: ARG002
        return 0 if not self.alive else 1

    def kill(self) -> None:
        self.kills += 1
        if self.kill_fails:
            raise OSError("cannot kill owned SSH process")
        self.alive = False
        self.ended.set()


class FakeTransport:
    def __init__(
        self, *, terminate_fails: bool = False, kill_fails: bool = False,
    ) -> None:
        self.started: list[FakeProcess] = []
        self.terminate_fails = terminate_fails
        self.kill_fails = kill_fails

    def start(self, _config: RemoteObserverConfig) -> FakeProcess:
        process = FakeProcess(
            terminate_fails=self.terminate_fails,
            kill_fails=self.kill_fails,
        )
        self.started.append(process)
        return process


def _config(tmp_path: Path, **overrides: object) -> RemoteObserverConfig:
    config_file = tmp_path / "observer-ssh-config"
    config_file.write_text(
        "Host observer-test\n"
        "  HostName 203.0.113.10\n"
        "  User observer\n"
        "  IdentityFile /tmp/operator-owned-key\n",
        encoding="utf-8",
    )
    values = {
        "ssh_alias": "observer-test",
        "allowed_ssh_aliases": ("observer-test",),
        "ssh_config_path": config_file,
        "public_base_url": "https://ci-proof.example.test",
        "local_observer_port": 47777,
        "startup_timeout_seconds": 1,
    }
    values.update(overrides)
    return RemoteObserverConfig(**values)


def _identity() -> tuple[str, str, dict[str, str]]:
    return (
        str(uuid4()),
        "RootNonce_1234567890abc",
        {
            "attack": "AttackNonce_1234567890abc",
            "control": "ControlNonce_1234567890ab",
            "quiet": "QuietNonce_1234567890abc",
        },
    )


def test_ssh_config_requires_exact_host_allowlist_and_no_executable_directives(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        _config(tmp_path, allowed_ssh_aliases=("other",))
    with pytest.raises(ValueError, match="HTTPS origin"):
        _config(tmp_path, public_base_url="http://ci-proof.example.test")
    config_file = tmp_path / "observer-ssh-config"
    config_file.write_text(
        "Host observer-test\nHostName 203.0.113.10\nUser observer\n"
        "ProxyCommand sh -c 'unexpected command'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not allowed"):
        RemoteObserverConfig(
            "observer-test",
            ("observer-test",),
            config_file,
            "https://observer.example.test",
            47777,
        )
    config_file.write_text(
        "Host observer-test\nHostName 203.0.113.10\nUser observer\n"
        "RemoteForward 15881 127.0.0.1:1234\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not allowed"):
        RemoteObserverConfig(
            "observer-test",
            ("observer-test",),
            config_file,
            "https://observer.example.test",
            47777,
        )


def test_deploy_shares_one_tunnel_and_revokes_only_own_lease(tmp_path: Path) -> None:
    transport = FakeTransport()
    seen_urls: list[str] = []

    def probe(url: str, expected: dict[str, str], timeout: int) -> bool:
        assert timeout == 4
        assert expected["status"] == "healthy"
        assert expected["experiment_id"] in url
        seen_urls.append(url)
        return True

    backend = RemoteObserverBackend(_config(tmp_path), transport=transport, probe=probe)
    first_id, first_nonce, first_phases = _identity()
    second_id, second_nonce, second_phases = _identity()
    first = backend.deploy(first_id, first_nonce, first_phases, 120)
    second = backend.deploy(second_id, second_nonce, second_phases, 120)
    assert len(transport.started) == 1
    assert first.tunnel_id == second.tunnel_id
    assert first.deployment_id != second.deployment_id
    assert first.base_url == "https://ci-proof.example.test"
    assert backend.deploy(first_id, first_nonce, first_phases, 120) == first
    assert all("/attack/health?nonce=" in url for url in seen_urls)
    assert all("/web-observer/" in url for url in seen_urls)
    assert backend.revoke(first_id) is True
    assert transport.started[0].terminations == 0
    assert backend.health(second_id) is True
    assert backend.revoke(second_id) is True
    assert transport.started[0].terminations == 1
    assert backend.status(first_id) == "revoked"
    assert backend.status(second_id) == "revoked"
    assert backend.receipts(first_id)[0].root_nonce == first_nonce
    assert backend.receipts(first_id)[0].public_probe_ok is True


def test_failed_public_probe_rolls_back_only_started_tunnel(tmp_path: Path) -> None:
    transport = FakeTransport()
    backend = RemoteObserverBackend(_config(tmp_path), transport=transport, probe=lambda *_: False)
    experiment_id, nonce, phase_nonces = _identity()
    with pytest.raises(RuntimeError, match="public HTTPS observer probe failed"):
        backend.deploy(experiment_id, nonce, phase_nonces, 120)
    assert transport.started[0].terminations == 1
    assert backend.status(experiment_id) == "rolled_back"
    assert backend.receipts(experiment_id)[0].status == "rolled_back"


def test_failed_rollback_remains_cleanup_pending_and_is_retryable(tmp_path: Path) -> None:
    transport = FakeTransport(terminate_fails=True, kill_fails=True)
    backend = RemoteObserverBackend(_config(tmp_path), transport=transport, probe=lambda *_: False)
    experiment_id, nonce, phase_nonces = _identity()
    with pytest.raises(RuntimeError, match="public HTTPS observer probe failed"):
        backend.deploy(experiment_id, nonce, phase_nonces, 120)
    assert backend.status(experiment_id) == "cleanup_pending"
    transport.started[0].terminate_fails = False
    transport.started[0].kill_fails = False
    assert backend.revoke(experiment_id) is True
    assert backend.status(experiment_id) == "revoked"


def test_expiry_and_close_release_only_the_owned_tunnel(tmp_path: Path) -> None:
    transport = FakeTransport()
    backend = RemoteObserverBackend(_config(tmp_path), transport=transport, probe=lambda *_: True)
    first_id, first_nonce, first_phases = _identity()
    second_id, second_nonce, second_phases = _identity()
    backend.deploy(first_id, first_nonce, first_phases, 120)
    backend.deploy(second_id, second_nonce, second_phases, 120)
    backend._deployments[first_id].expires_at = datetime.now(UTC) - timedelta(seconds=1)
    backend.sweep_expired()
    assert backend.status(first_id) == "expired"
    assert transport.started[0].alive is True  # The second lease still owns it.
    assert backend.close() is True
    assert backend.status(second_id) == "revoked"
    assert transport.started[0].terminations == 1
    assert backend._sweeper is not None and not backend._sweeper.is_alive()
    with pytest.raises(RuntimeError, match="closed"):
        experiment_id, nonce, phases = _identity()
        backend.deploy(experiment_id, nonce, phases, 120)


def test_background_sweeper_expires_lease_without_gateway_calls(tmp_path: Path) -> None:
    transport = FakeTransport()
    backend = RemoteObserverBackend(_config(tmp_path), transport=transport, probe=lambda *_: True)
    experiment_id, nonce, phase_nonces = _identity()
    backend.deploy(experiment_id, nonce, phase_nonces, 120)
    sweeper = backend._sweeper
    assert sweeper is not None and sweeper.is_alive()
    with backend._sweep_condition:
        backend._deployments[experiment_id].expires_at = (
            datetime.now(UTC) - timedelta(seconds=1)
        )
        backend._sweep_condition.notify_all()
    assert transport.started[0].ended.wait(timeout=2)
    sweeper.join(timeout=2)
    assert not sweeper.is_alive()
    assert backend.status(experiment_id) == "expired"
    assert [receipt.action for receipt in backend.receipts(experiment_id)] == [
        "deploy", "expire",
    ]
    assert backend.close() is True


def test_ssh_command_is_fixed_reverse_forward_with_no_remote_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    seen: dict[str, object] = {}

    def fake_popen(argv: list[str], **kwargs: object) -> FakeProcess:
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    SSHReverseTunnelTransport().start(config)
    argv = seen["argv"]
    assert isinstance(argv, list)
    assert argv[-1] == "observer-test"
    assert "-N" in argv and "-T" in argv
    assert argv[argv.index("-R") + 1] == "127.0.0.1:15880:127.0.0.1:47777"
    assert "ExitOnForwardFailure=yes" in argv
    assert "ClearAllForwardings=yes" not in argv
    assert "ProxyCommand" not in " ".join(argv)
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stdout"] == subprocess.DEVNULL


def test_public_probe_requires_nonce_bound_uncached_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "schema_version": "1.0",
        "experiment_id": str(uuid4()),
        "nonce": "RootNonce_1234567890abc",
        "phase_nonce": "AttackNonce_1234567890abc",
        "status": "healthy",
    }

    class FakeResponse:
        status = 200
        body = json.dumps(expected).encode()
        cache_control = "no-store"

        def read(self, _limit: int) -> bytes:
            return self.body

        def getheader(self, name: str, _default: str = "") -> str:
            return (
                "application/json; charset=utf-8" if name == "Content-Type"
                else self.cache_control
            )

    class FakeConnection:
        def __init__(self, host: str, port: int | None, *, timeout: int) -> None:
            assert host == "ci-proof.example.test"
            assert port is None
            assert timeout == 4

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            assert method == "GET"
            assert path.endswith("/health?nonce=AttackNonce_1234567890abc")
            assert "User-Agent" in headers

        def getresponse(self) -> FakeResponse:
            return response

        def close(self) -> None:
            return

    response = FakeResponse()
    monkeypatch.setattr(
        "apkscanner.runtime.remote_observer_backend.http.client.HTTPSConnection",
        FakeConnection,
    )
    url = (
        "https://ci-proof.example.test/web-observer/"
        f"{expected['experiment_id']}/attack/health?nonce={expected['phase_nonce']}"
    )
    assert _public_probe(url, expected, 4) is True
    response.body = json.dumps({**expected, "nonce": "wrong"}).encode()
    assert _public_probe(url, expected, 4) is False
    response.body = json.dumps(expected).encode()
    response.cache_control = "public, max-age=60"
    assert _public_probe(url, expected, 4) is False


def test_adapter_uses_local_web_observer_without_importing_client_claims(tmp_path: Path) -> None:
    recorded: list[dict] = []

    def persist(_experiment, event):  # noqa: ANN001, ANN202
        recorded.append(dict(event))
        return f"event-{len(recorded)}"

    observer = WebExploitObserver(persist)
    experiment, _plan = observer.register(
        WebExperimentRequest(
            finding_id=str(uuid4()),
            hypothesis_id=str(uuid4()),
            bridge_name="AccountBridge",
            method="getSessionToken",
        ),
        scan_id="scan-1",
        task_id="task-1",
        device_serial="device-1",
        target_package="io.example.target",
        base_url="http://127.0.0.1:47777",
        lifetime_seconds=120,
    )

    def probe(url: str, expected: dict[str, str], _timeout: int) -> bool:
        parsed = urlsplit(url)
        status, _kind, body = observer.serve("GET", f"{parsed.path}?{parsed.query}")
        return status == 200 and json.loads(body) == expected

    backend = RemoteObserverBackend(_config(tmp_path), transport=FakeTransport(), probe=probe)
    adapter = RemoteWebObserverAdapter(observer, backend)
    session = adapter.deploy(experiment, task_id="task-1")
    assert session.attack_url.startswith("https://ci-proof.example.test/web-observer/")
    assert backend.health(experiment.experiment_id) is True
    assert adapter.events(experiment.experiment_id, task_id="task-1") == []
    assert recorded == []  # The public health probe is deliberately non-evidence.
    with pytest.raises(ValueError, match="unavailable"):
        adapter.events(experiment.experiment_id, task_id="other-task")
    observer.revoke_task("task-1")
    assert adapter.revoke(experiment.experiment_id, task_id="task-1") is True
    assert adapter.receipts(experiment.experiment_id, task_id="task-1")[-1].status == "revoked"


def test_diagnostic_smoke_exercises_local_handler_and_always_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    backends: list[object] = []

    class FakeBackend:
        def __init__(self, runtime_config: RemoteObserverConfig) -> None:
            self.config = runtime_config
            self.closed = False
            self.revoked = False
            backends.append(self)

        def deploy(
            self, experiment_id: str, _root_nonce: str,
            _phase_nonces: dict[str, str], _ttl: int,
        ) -> RemoteDeployment:
            return RemoteDeployment(
                experiment_id, str(uuid4()), str(uuid4()),
                self.config.public_base_url, "healthy", datetime.now(UTC).isoformat(),
            )

        def health(self, _experiment_id: str) -> bool:
            return True

        def revoke(self, _experiment_id: str) -> bool:
            self.revoked = True
            return True

        def receipts(self, _experiment_id: str) -> tuple:
            return ()

        def close(self) -> bool:
            self.closed = True
            return True

    def local_request(
        url: str, *, method: str = "GET", body: bytes | None = None,
    ) -> tuple[int, str, bytes]:
        parsed = urlsplit(url)
        backend = backends[0]
        connection = http.client.HTTPConnection(
            "127.0.0.1", backend.config.local_observer_port, timeout=3,
        )
        try:
            connection.request(
                method, parsed.path + f"?{parsed.query}", body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type", ""), response.read()
        finally:
            connection.close()

    monkeypatch.setattr(remote_observer_smoke, "RemoteObserverBackend", FakeBackend)
    monkeypatch.setattr(remote_observer_smoke, "_https_request", local_request)
    result = remote_observer_smoke.run_smoke(
        ssh_alias="observer-test",
        allowed_ssh_aliases=("observer-test",),
        ssh_config_path=config.ssh_config_path,
        public_base_url=config.public_base_url,
    )
    assert result["transport_ok"] is True
    assert result["proof_attempt_created"] is False
    assert result["target_app_executed"] is False
    assert result["event_count"] == 2
    assert backends[0].revoked is True
    assert backends[0].closed is True


def test_gateway_remote_mode_skips_adb_reverse_and_persists_lifecycle_receipts(
    settings, tmp_path: Path,
) -> None:  # noqa: ANN001
    remote_settings = replace(
        settings,
        web_observer_remote_enabled=True,
        web_observer_public_base_url="https://ci-proof.example.test",
    )
    remote_settings.ensure_directories()
    database = Database(remote_settings)
    database.create_all()
    with database.session_factory() as session:
        scan = Scan(
            status="investigating",
            filename="remote-web.apk",
            artifact_sha256="b" * 64,
            artifact_path="remote-web.apk",
            package_name="io.example.remote",
        )
        task = InvestigationTask(scan=scan, task_type="component", status="running")
        finding = Finding(
            scan=scan,
            dedupe_key="remote-web",
            rule_id="AGENT",
            title="Remote observer candidate",
            description="Remote Web callback candidate.",
            masvs="MASVS-PLATFORM",
            severity="high",
            status="supported_static",
        )
        session.add_all([scan, task, finding])
        session.commit()
        scan_id, task_id, finding_id = scan.id, task.id, finding.id

    class NoReverseDevice:
        serial = "remote-fixture-device"

        def install_web_observer_reverse(self, _port: int) -> None:
            raise AssertionError("remote HTTPS mode must not install ADB reverse")

        def remove_web_observer_reverse(self, _port: int) -> None:
            raise AssertionError("remote HTTPS mode must not remove ADB reverse")

    orchestrator = ScanOrchestrator(
        remote_settings, database, ArtifactStore(remote_settings),
    )
    orchestrator._materialize_live_evidence = lambda *_args: None
    orchestrator.ensure_live_proof_endpoint()

    class FakeRemoteAdapter:
        def __init__(self) -> None:
            self.receipt_list: list[RemoteActionReceipt] = []
            self.revoked = False

        def deploy(self, experiment, *, task_id: str):  # noqa: ANN001, ANN202
            assert task_id == context.task_id
            self.experiment = experiment
            self.receipt_list.append(self._receipt("deploy", "healthy"))
            base_url = "https://ci-proof.example.test"
            return RemoteWebObserverSession(
                deployment=RemoteDeployment(
                    experiment.experiment_id, str(uuid4()), str(uuid4()),
                    base_url, "healthy", experiment.deadline.isoformat(),
                ),
                attack_url=orchestrator._web_exploit_observer.url(
                    experiment, base_url=base_url, phase="attack",
                ),
                control_url=orchestrator._web_exploit_observer.url(
                    experiment, base_url=base_url, phase="control",
                ),
                quiet_url=orchestrator._web_exploit_observer.url(
                    experiment, base_url=base_url, phase="quiet",
                ),
            )

        def _receipt(self, action: str, status: str) -> RemoteActionReceipt:
            return RemoteActionReceipt(
                action=action,
                experiment_id=self.experiment.experiment_id,
                deployment_id="deployment-1",
                tunnel_id="tunnel-1",
                root_nonce=self.experiment.nonce,
                request_id=str(uuid4()),
                status=status,
                received_at=datetime.now(UTC).isoformat(),
                public_probe_ok=action == "deploy",
            )

        def receipts(self, _experiment_id: str, *, task_id: str):  # noqa: ANN001, ANN202
            assert task_id == context.task_id
            return tuple(self.receipt_list)

        def revoke(self, _experiment_id: str, *, task_id: str) -> bool:
            assert task_id == context.task_id
            self.revoked = True
            self.receipt_list.append(self._receipt("revoke", "revoked"))
            return True

    adapter = FakeRemoteAdapter()
    orchestrator._web_observer_remote_adapter = adapter
    orchestrator._ensure_remote_web_observer_adapter = lambda: adapter
    workspace = tmp_path / "remote-context"
    workspace.mkdir()
    hypothesis_id = str(uuid4())
    context = LiveProofContext(
        token="remote-token",
        scan_id=scan_id,
        task_id=task_id,
        package_name="io.example.remote",
        workspace=workspace,
        entries=[],
        default_entry_id="",
        hypotheses=[{"id": hypothesis_id}],
        budget=TimeBudget.from_seconds(120),
        evidence_summaries=[],
        cancel_event=threading.Event(),
        round_index=0,
        device=NoReverseDevice(),
    )
    orchestrator.register_live_proof_context(context)
    try:
        plan = orchestrator.begin_web_experiment(
            task_id,
            "remote-token",
            WebExperimentRequest(
                finding_id=finding_id,
                hypothesis_id=hypothesis_id,
                bridge_name="AccountBridge",
                method="getSessionToken",
            ),
        )
        assert plan["observer_transport"] == "ssh_reverse_https"
        assert plan["attack_url"].startswith("https://ci-proof.example.test/")
        with database.session_factory() as session:
            kinds = list(session.scalars(select(Evidence.kind)))
            assert "web.experiment.remote_receipt" in kinds
            assert "web.experiment.plan" in kinds
            assert "web.experiment.device_reverse" not in kinds
    finally:
        orchestrator.unregister_live_proof_context(task_id, "remote-token")
        orchestrator._live_proof_server.shutdown()
        orchestrator._live_proof_server.server_close()
    assert adapter.revoked is True
    with database.session_factory() as session:
        receipts = list(session.scalars(select(Evidence).where(
            Evidence.kind == "web.experiment.remote_receipt",
        )))
        assert [item.metadata_json["stage"] for item in receipts] == [
            "remote_deploy", "remote_revoke",
        ]
        assert all(item.metadata_json["impact_contract_satisfied"] is False for item in receipts)
