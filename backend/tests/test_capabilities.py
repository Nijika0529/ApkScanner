from __future__ import annotations

import hashlib
import shutil

import pytest
from apkscanner.core.models import Scan
from apkscanner.core.repository import add_event
from apkscanner.main import create_app
from apkscanner.platform.capabilities import CapabilityManifest, CapabilityRegistry
from fastapi.testclient import TestClient


@pytest.mark.skipif(shutil.which("docker") is None, reason="requires Docker capability isolation")
def test_registry_invokes_hash_pinned_python_script_without_inheriting_secrets(
    settings,
    monkeypatch,
) -> None:  # noqa: ANN001
    scripts = settings.data_dir / "capability-scripts"
    manifests = settings.data_dir / "capabilities"
    scripts.mkdir()
    manifests.mkdir()
    script = scripts / "echo.py"
    script.write_text(
        "import json, os, sys\n"
        "value=json.load(sys.stdin)\n"
        "print(json.dumps({'value': value, 'secret_visible': bool(os.getenv('DEEPSEEK_API_KEY'))}))\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    manifest = CapabilityManifest(
        id="custom.python.echo",
        title="Echo",
        description="Test adapter",
        runtime="python_script",
        script_path="echo.py",
        script_sha256=digest,
    )
    (manifests / "echo.json").write_text(manifest.model_dump_json(), encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "must-not-be-inherited")
    app = create_app(settings)
    registry: CapabilityRegistry = app.state.capability_registry

    result = registry.invoke("custom.python.echo", {"hello": "world"})

    assert result.ok is True
    assert result.output == {"value": {"hello": "world"}, "secret_visible": False}


def test_registry_exposes_timeline_and_bindable_mcp_interface(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    registry: CapabilityRegistry = app.state.capability_registry
    with app.state.database.session_factory() as session:
        scan = Scan(
            filename="target.apk",
            artifact_sha256="a" * 64,
            artifact_path=str(settings.data_dir / "target.apk"),
        )
        session.add(scan)
        session.flush()
        add_event(session, scan.id, "scan.test", "event", {"safe": True})
        session.commit()
        scan_id = scan.id

    timeline = registry.invoke("platform.scan.timeline", {"scan_id": scan_id})

    assert timeline.ok is True
    assert timeline.output["events"][0]["type"] == "scan.test"
    manifest = CapabilityManifest(
        id="custom.mcp.sample",
        title="MCP sample",
        description="Bound during application integration",
        runtime="mcp",
        mcp_server="ida",
        mcp_tool="analyze_function",
    )
    registry._manifests[manifest.id] = manifest
    assert next(item for item in registry.catalog() if item["id"] == manifest.id)["available"] is False
    registry.bind_mcp(manifest.id, lambda value: {"received": value})
    assert registry.invoke(manifest.id, {"address": "0x1000"}).output["received"]["address"] == "0x1000"


def test_supervisor_api_exposes_snapshot_catalog_and_plan_validation(settings) -> None:  # noqa: ANN001
    app = create_app(settings)
    with TestClient(app) as client:
        snapshot = client.get("/api/v1/supervisor/snapshot")
        catalog = client.get("/api/v1/capabilities/catalog")
        invalid = client.post(
            "/api/v1/supervisor/campaigns/validate",
            headers={"X-APKScanner-Request": "console"},
            json={
                "name": "monitor generated tests",
                "entries": [
                    {
                        "id": "missing_scan",
                        "kind": "scan_clone",
                        "scan_id": "00000000-0000-0000-0000-000000000099",
                    }
                ],
            },
        )

    assert snapshot.status_code == 200
    assert "devices" in snapshot.json()
    assert catalog.status_code == 200
    assert {item["id"] for item in catalog.json()} >= {
        "platform.devices.snapshot",
        "platform.scan.timeline",
    }
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
