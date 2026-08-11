from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .schemas import responses_output_schema


class OperatorFindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    verdict: Literal[
        "reproduced_blackbox",
        "supported_static",
        "refuted_static",
        "not_reproduced",
        "inconclusive",
        "unchanged",
    ] = "unchanged"
    conclusion: str = Field(min_length=1, max_length=1200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)
    remaining_gap: str | None = Field(default=None, max_length=1200)


class OperatorReceipt(BaseModel):
    """Compact result contract for a platform-level Operator turn."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    result: Literal[
        "reproduced",
        "still_pending",
        "refuted",
        "inconclusive",
        "completed",
    ]
    summary: str = Field(min_length=1, max_length=2000)
    actions: list[str] = Field(default_factory=list, max_length=32)
    observations: list[str] = Field(default_factory=list, max_length=32)
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    artifact_paths: list[str] = Field(default_factory=list, max_length=128)
    finding_updates: list[OperatorFindingUpdate] = Field(default_factory=list, max_length=32)
    remaining_gap: str | None = Field(default=None, max_length=2000)


OPERATOR_RECEIPT_JSON_SCHEMA = responses_output_schema(
    OperatorReceipt.model_json_schema()
)


class OperatorSessionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str = Field(min_length=1, max_length=20_000)
    title: str | None = Field(default=None, max_length=512)
    scan_id: str | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    finding_ids: list[str] = Field(default_factory=list, max_length=64)
    device_mode: Literal["auto", "none", "required"] = "auto"


class OperatorTurnCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str = Field(min_length=1, max_length=20_000)
    device_mode: Literal["auto", "none", "required"] = "auto"


class OperatorTurnOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    instruction: str
    status: str
    device_mode: str
    thread_id: str | None
    turn_id: str | None
    receipt_json: dict[str, Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class OperatorSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    primary_scan_id: str | None
    task_id: str | None
    title: str
    instruction: str
    status: str
    workspace_path: str
    thread_id: str | None
    scope_json: dict[str, Any]
    result_json: dict[str, Any]
    error: str | None
    cancel_requested: bool
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    turns: list[OperatorTurnOut] = Field(default_factory=list)


class IndexedArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sha256: str
    artifact_type: str
    name: str
    source_path: str
    size_bytes: int
    scan_id: str | None
    task_id: str | None
    finding_id: str | None
    operator_session_id: str | None
    metadata_json: dict[str, Any]
    created_at: datetime
