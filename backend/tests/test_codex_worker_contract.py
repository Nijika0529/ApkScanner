from __future__ import annotations

import os

import pytest
from apkscanner.codex_worker import PersistentCodexWorker, TurnCommand
from apkscanner.schemas import AGENT_RESULT_JSON_SCHEMA
from pydantic import ValidationError


def _command(**overrides):  # noqa: ANN003, ANN202
    payload = {
        "schema_version": "3.0",
        "type": "turn.start",
        "request_id": "request-1",
        "session_id": "session-1",
        "prompt": "Inspect the assigned target.",
    }
    payload.update(overrides)
    return payload


def test_agent_contract_owns_its_output_schema() -> None:
    command = TurnCommand.model_validate(_command())
    assert command.result_contract == "agent_investigation.v1"
    assert command.resolved_output_schema() == AGENT_RESULT_JSON_SCHEMA

    with pytest.raises(ValidationError, match="does not accept an arbitrary output schema"):
        TurnCommand.model_validate(
            _command(output_schema={"type": "object", "properties": {"ok": {}}})
        )


def test_json_object_contract_requires_an_explicit_schema() -> None:
    with pytest.raises(ValidationError, match="requires an explicit output schema"):
        TurnCommand.model_validate(_command(result_contract="json_object.v1"))

    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"ok": {"type": "boolean"}},
        "required": ["ok"],
    }
    command = TurnCommand.model_validate(
        _command(result_contract="json_object.v1", output_schema=schema)
    )
    assert command.resolved_output_schema() == schema


def test_gateway_environment_accepts_only_known_adb_policy(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("APKSCANNER_ADB_POLICY", raising=False)

    PersistentCodexWorker._install_gateway_environment(
        {"APKSCANNER_ADB_POLICY": "adaptive"}
    )

    assert os.environ["APKSCANNER_ADB_POLICY"] == "adaptive"
    with pytest.raises(ValueError, match="gateway ADB policy is invalid"):
        PersistentCodexWorker._install_gateway_environment(
            {"APKSCANNER_ADB_POLICY": "unrestricted"}
        )


def test_gateway_environment_accepts_runtime_observation_endpoint(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("APKSCANNER_OBSERVATION_URL", raising=False)
    monkeypatch.delenv("APKSCANNER_OBSERVATION_TOKEN", raising=False)
    token = "o" * 48

    PersistentCodexWorker._install_gateway_environment(
        {
            "APKSCANNER_OBSERVATION_URL": (
                "http://apkscanner-host:8000/api/v1/internal/tasks/task-1/observations"
            ),
            "APKSCANNER_OBSERVATION_TOKEN": token,
        }
    )

    assert os.environ["APKSCANNER_OBSERVATION_URL"].endswith("/observations")
    assert os.environ["APKSCANNER_OBSERVATION_TOKEN"] == token
