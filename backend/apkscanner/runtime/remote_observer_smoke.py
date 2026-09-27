"""Operator-only HTTPS tunnel diagnostic; never a vulnerability ProofAttempt.

Run with ``python -m apkscanner.runtime.remote_observer_smoke --help`` after
the scoped remote Nginx route has been separately reviewed and deployed.
"""

from __future__ import annotations

import argparse
import http.client
import json
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ..core.schemas import WebExperimentRequest
from .remote_observer_backend import RemoteObserverBackend, RemoteObserverConfig
from .remote_web_observer_adapter import RemoteWebObserverAdapter
from .web_exploit_observer import WebExploitObserver

_TASK_ID = "remote-observer-smoke"


def _handler_for(observer: WebExploitObserver) -> type[BaseHTTPRequestHandler]:
    class SmokeHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._serve("POST")

        def _serve(self, method: str) -> None:
            if not self.path.startswith("/web-observer/"):
                self.send_error(404)
                return
            body = b""
            if method == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if not 0 < length <= 16_384:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
            status, content_type, response = observer.serve(
                method,
                self.path,
                body=body,
                peer=self.client_address[0],
                user_agent=self.headers.get("User-Agent", "")[:512],
            )
            self.send_response(status)
            if content_type.startswith("Location: "):
                self.send_header("Location", content_type.removeprefix("Location: "))
            else:
                self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    return SmokeHandler


def _https_request(
    url: str, *, method: str = "GET", body: bytes | None = None,
) -> tuple[int, str, bytes]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("diagnostic request requires an HTTPS URL")
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        headers = {"User-Agent": "APKScanner-Observer-Diagnostic/1.0"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(
            method,
            parsed.path + (f"?{parsed.query}" if parsed.query else ""),
            body=body,
            headers=headers,
        )
        response = connection.getresponse()
        payload = response.read(65_537)
        if len(payload) > 65_536:
            raise ValueError("diagnostic response is too large")
        return response.status, response.getheader("Content-Type", ""), payload
    finally:
        connection.close()


def run_smoke(
    *, ssh_alias: str, allowed_ssh_aliases: tuple[str, ...],
    ssh_config_path: Path, public_base_url: str,
    remote_loopback_port: int = 15880,
) -> dict[str, Any]:
    """Exercise public health/page/callback, then always close the owned tunnel."""

    events: list[dict[str, Any]] = []

    def persist(_experiment: Any, event: dict[str, Any]) -> str:
        events.append(dict(event))
        return f"diagnostic-event-{len(events)}"

    observer = WebExploitObserver(persist)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(observer))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    backend: RemoteObserverBackend | None = None
    experiment_id: str | None = None
    try:
        config = RemoteObserverConfig(
            ssh_alias=ssh_alias,
            allowed_ssh_aliases=allowed_ssh_aliases,
            ssh_config_path=ssh_config_path,
            public_base_url=public_base_url,
            local_observer_port=server.server_address[1],
            remote_loopback_port=remote_loopback_port,
        )
        backend = RemoteObserverBackend(config)
        adapter = RemoteWebObserverAdapter(observer, backend)
        experiment, _plan = observer.register(
            WebExperimentRequest(
                finding_id=str(uuid4()),
                hypothesis_id=str(uuid4()),
                bridge_name="DiagnosticBridge",
                method="ping",
            ),
            scan_id="remote-observer-smoke",
            task_id=_TASK_ID,
            device_serial="no-device-diagnostic",
            target_package="io.apkscanner.transportdiagnostic",
            base_url=public_base_url,
            lifetime_seconds=180,
        )
        experiment_id = experiment.experiment_id
        session = adapter.deploy(experiment, task_id=_TASK_ID)
        if not adapter.health(experiment_id, task_id=_TASK_ID):
            raise RuntimeError("public nonce-bound observer health check failed")

        page_status, page_type, page_body = _https_request(session.attack_url)
        if (
            page_status != 200
            or not page_type.startswith("text/html")
            or experiment.nonce.encode() not in page_body
        ):
            raise RuntimeError("public attack page did not match the frozen experiment")

        callback_url = session.attack_url.replace("/page?", "/callback?", 1)
        callback = {
            "experiment_id": experiment_id,
            "nonce": experiment.phase_nonces["attack"],
            "event_type": "bridge_missing",
            "bridge_name": "DiagnosticBridge",
            "method": "ping",
            "frame_url": session.attack_url,
        }
        callback_status, callback_type, _callback_body = _https_request(
            callback_url, method="POST", body=json.dumps(callback).encode(),
        )
        if callback_status != 200 or not callback_type.startswith("application/json"):
            raise RuntimeError("public callback was not accepted by the local observer")

        observed = adapter.events(experiment_id, task_id=_TASK_ID)
        if (
            len(observed) != 2
            or [event["event_type"] for event in observed] != ["page", "bridge_missing"]
            or observed[1]["client_reported"] is not True
        ):
            raise RuntimeError("diagnostic HTTP events were not attributed to this experiment")
        if not adapter.revoke(experiment_id, task_id=_TASK_ID):
            raise RuntimeError("diagnostic SSH tunnel cleanup is pending")
        return {
            "transport_ok": True,
            "proof_attempt_created": False,
            "target_app_executed": False,
            "experiment_id": experiment_id,
            "deployment_id": session.deployment.deployment_id,
            "tunnel_id": session.deployment.tunnel_id,
            "public_origin": session.deployment.base_url,
            "page_status": page_status,
            "callback_status": callback_status,
            "event_count": len(observed),
            "receipt_actions": [
                receipt.action for receipt in adapter.receipts(experiment_id, task_id=_TASK_ID)
            ],
        }
    finally:
        try:
            if backend is not None:
                if experiment_id is not None:
                    with suppress(KeyError, OSError):
                        backend.revoke(experiment_id)
                if not backend.close():
                    raise RuntimeError("diagnostic SSH tunnel cleanup is pending")
        finally:
            observer.revoke_task(_TASK_ID)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-alias", required=True)
    parser.add_argument("--allowed-ssh-alias", action="append", required=True)
    parser.add_argument("--ssh-config", required=True, type=Path)
    parser.add_argument("--public-base-url", required=True)
    parser.add_argument("--remote-loopback-port", type=int, default=15880)
    args = parser.parse_args()
    result = run_smoke(
        ssh_alias=args.ssh_alias,
        allowed_ssh_aliases=tuple(args.allowed_ssh_alias),
        ssh_config_path=args.ssh_config,
        public_base_url=args.public_base_url,
        remote_loopback_port=args.remote_loopback_port,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
