from __future__ import annotations

import pytest
from apkscanner.codex_worker import TurnCommand
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
