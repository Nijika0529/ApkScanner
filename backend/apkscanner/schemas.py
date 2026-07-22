from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ScanSummary(ApiModel):
    id: str
    schema_version: str
    status: str
    filename: str
    artifact_sha256: str
    package_name: str | None
    version_name: str | None
    version_code: str | None
    min_sdk: int | None
    target_sdk: int | None
    stats: dict[str, Any]
    error: str | None
    preliminary_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanDetail(ScanSummary):
    signing: dict[str, Any]
    tool_versions: dict[str, Any]


class EntryPointOut(ApiModel):
    id: str
    schema_version: str
    kind: str
    name: str
    owner_component: str | None
    exported: bool
    exported_reason: str
    permission: str | None
    permission_protection: str | None
    intent_filters: list[dict[str, Any]]
    deep_links: list[dict[str, Any]]
    code_anchors: list[dict[str, Any]]
    metadata_json: dict[str, Any]


class FindingOut(ApiModel):
    id: str
    schema_version: str
    rule_id: str
    source: str
    title: str
    description: str
    remediation: str
    masvs: str
    cwe: str | None
    severity: str
    confidence: str
    status: str
    entry_point_ids: list[str]
    locations: list[dict[str, Any]]
    evidence_ids: list[str]
    metadata_json: dict[str, Any]
    review_note: str | None
    created_at: datetime
    updated_at: datetime


class FindingReview(BaseModel):
    status: Literal["accepted", "false_positive", "candidate"]
    note: str = Field(min_length=1, max_length=4000)


class InvestigationTaskOut(ApiModel):
    id: str
    schema_version: str
    task_type: str
    status: str
    priority: int
    target_entry_ids: list[str]
    hypotheses: list[str]
    preconditions: dict[str, Any]
    allowed_side_effects: list[str]
    device_profile: dict[str, Any]
    result: dict[str, Any]
    thread_id: str | None
    turn_id: str | None
    attempts: int
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class CoverageItemOut(ApiModel):
    id: str
    schema_version: str
    control_id: str
    domain: str
    title: str
    status: str
    stages: dict[str, Any]
    gap_reason: str | None
    entry_point_id: str | None


class EvidenceOut(ApiModel):
    id: str
    schema_version: str
    scan_id: str
    task_id: str | None
    kind: str
    sha256: str
    command: list[str]
    exit_code: int | None
    summary: str
    metadata_json: dict[str, Any]
    created_at: datetime


class EventOut(ApiModel):
    id: int
    event_type: str
    message: str
    data: dict[str, Any]
    created_at: datetime


class Capability(BaseModel):
    name: str
    available: bool
    version: str | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    capabilities: list[Capability]


class AgentRequestedTest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_point_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    state: Literal["guest", "authenticated"]
    uri: str | None = Field(max_length=4096)
    extras: dict[str, StrictStr | StrictInt | StrictBool] = Field(max_length=16)
    rationale: str = Field(min_length=1, max_length=1000)


class AgentInvestigationResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    summary: str
    result: Literal[
        "supported_static",
        "reproduced_blackbox",
        "observed_instrumented",
        "not_reproduced",
        "inconclusive",
    ]
    hypotheses_tested: list[str]
    test_cases: list[dict[str, Any]]
    evidence_ids: list[str]
    severity_proposal: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    coverage_gaps: list[str]
    followups: list[str]
    requested_tests: list[AgentRequestedTest] = Field(max_length=12)


AGENT_RESULT_JSON_SCHEMA = AgentInvestigationResult.model_json_schema()
