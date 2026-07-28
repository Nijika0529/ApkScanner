from __future__ import annotations

import json
from dataclasses import replace

import pytest
from apkscanner.auth import load_auth_flow
from apkscanner.device import AdbDeviceAdapter
from apkscanner.tools import ToolRunner


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


@pytest.mark.parametrize("assertion", ["", "   ", "\t"])
def test_auth_flow_rejects_blank_success_assertions(tmp_path, assertion: str) -> None:  # noqa: ANN001
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "steps": [{"action": "assert_text", "value": assertion}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing required fields"):
        load_auth_flow(path)


def test_adb_text_rejects_remote_shell_metacharacters() -> None:
    assert AdbDeviceAdapter._safe_input_text("user name@example.test") == (
        "user%sname@example.test"
    )
    with pytest.raises(ValueError, match="unsafe"):
        AdbDeviceAdapter._safe_input_text("unsafe;command")
    with pytest.raises(ValueError, match="space escape sequence"):
        AdbDeviceAdapter._safe_input_text("literal%svalue")


def test_auth_flow_must_end_with_success_assertion(settings, tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "steps": [
                    {"action": "assert_text", "value": "Sign in"},
                    {"action": "wait", "seconds": 1},
                ],
            }
        ),
        encoding="utf-8",
    )
    adapter = AdbDeviceAdapter(
        replace(settings, auth_flow_path=path),
        ToolRunner(),
    )

    capability = adapter.auth_capability()

    assert capability["available"] is False
    assert "must end with an assert_text" in capability["detail"]
