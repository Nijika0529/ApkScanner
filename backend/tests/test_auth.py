from __future__ import annotations

import json

import pytest
from apkscanner.auth import load_auth_flow
from apkscanner.device import AdbDeviceAdapter


def test_auth_flow_loads_secret_references_without_secret_values(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "profile": "release-test",
                "package": "com.example.app",
                "steps": [
                    {"action": "start"},
                    {"action": "text", "secret": "username"},
                    {"action": "tap", "x": 10, "y": 20},
                ],
            }
        ),
        encoding="utf-8",
    )
    flow = load_auth_flow(path)
    assert flow is not None
    assert flow.required_secrets == {"username"}
    assert "secret-value" not in path.read_text(encoding="utf-8")


def test_adb_text_rejects_remote_shell_metacharacters() -> None:
    assert AdbDeviceAdapter._safe_input_text("user name@example.test") == (
        "user%sname@example.test"
    )
    with pytest.raises(ValueError, match="unsafe"):
        AdbDeviceAdapter._safe_input_text("unsafe;command")
