from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator


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


class ScanAgentControl(BaseModel):
    enabled: StrictBool
    backend: Literal["codex", "opencode", "none"] | None = None


class TaskAgentControl(BaseModel):
    enabled: StrictBool


class ScanRerunResult(BaseModel):
    scan_id: StrictStr
    queued_task_ids: list[StrictStr]
    queued_count: StrictInt


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


class AgentAuditArtifact(BaseModel):
    evidence_id: str
    sha256: str
    content: dict[str, Any] | list[Any] | str | int | float | bool | None
    created_at: datetime


class AgentAuditOut(BaseModel):
    id: str
    scan_id: str
    task_id: str | None
    attempt: int
    phase: str
    backend: str
    provider: str
    model: str
    isolation: str
    status: Literal["running", "completed", "failed", "cancelled"]
    thread_id: str | None
    turn_id: str | None
    usage: dict[str, Any]
    artifacts: dict[str, AgentAuditArtifact]
    integrity: Literal["verified", "failed"]
    integrity_errors: list[str]
    started_at: datetime
    completed_at: datetime | None


class Capability(BaseModel):
    name: str
    available: bool
    version: str | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    max_upload_bytes: int = Field(gt=0)
    default_investigator: Literal["codex", "opencode", "none"] = "codex"
    enabled_investigators: list[Literal["codex", "opencode"]] = Field(default_factory=list)
    capabilities: list[Capability]


class ScanDeleteResult(BaseModel):
    id: str
    deleted: Literal[True] = True
    files_removed: int
    cleanup_warnings: list[str]


class TaskDeleteResult(BaseModel):
    id: str
    deleted: Literal[True] = True
    audit_artifacts_preserved: int


class AgentPocSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_path: str = Field(
        pattern=r"^poc/[A-Za-z0-9][A-Za-z0-9._/-]{0,191}$",
        max_length=196,
    )
    package_name: str = Field(
        pattern=r"^io\.apkscanner\.poc\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$",
        max_length=200,
    )
    launch_component: str = Field(
        pattern=r"^(?:\.[A-Za-z][A-Za-z0-9_.$]*|[A-Za-z][A-Za-z0-9_.$]*(?:\.[A-Za-z][A-Za-z0-9_.$]*)+)$",
        max_length=300,
    )
    log_tag: str = Field(
        default="APKSCANNER_POC",
        pattern=r"^[A-Z][A-Z0-9_]{2,31}$",
    )
    timeout_seconds: int = Field(default=60, ge=5, le=120)
    prebuilt_apk_path: str | None = Field(
        default=None,
        pattern=r"^poc/[A-Za-z0-9][A-Za-z0-9._/-]{0,220}\.apk$",
        max_length=256,
    )


class AgentOracleSpec(BaseModel):
    """An objective observation the platform can evaluate after a requested test."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "reachability",
        "provider_rows",
        "ui_text",
        "log_contains",
        "process_crash",
    ] = "reachability"
    expected_text: str | None = Field(default=None, min_length=1, max_length=500)
    minimum_rows: int | None = Field(default=None, ge=1, le=1_000_000)
    impact: Literal[
        "none",
        "unauthorized_data_access",
        "unauthorized_state_change",
        "privileged_action",
        "denial_of_service",
    ] = "none"
    refute_on_miss: bool = False

    @model_validator(mode="after")
    def validate_predicate(self) -> Self:
        if self.kind in {"ui_text", "log_contains"} and not self.expected_text:
            raise ValueError(f"{self.kind} requires expected_text")
        if self.kind == "provider_rows" and self.minimum_rows is None:
            self.minimum_rows = 1
        if self.kind == "process_crash" and self.impact not in {
            "none",
            "denial_of_service",
        }:
            raise ValueError("process_crash only supports denial_of_service impact")
        if self.kind == "reachability" and self.impact != "none":
            raise ValueError("reachability alone cannot claim security impact")
        return self


class AgentRequestedTest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    entry_point_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    state: Literal["guest"] = "guest"
    uri: str | None = Field(max_length=4096)
    extras: dict[str, StrictStr | StrictInt | StrictBool] = Field(max_length=16)
    operation: Literal[
        "auto",
        "query",
        "call",
        "insert",
        "update",
        "delete",
    ] = "auto"
    method: str | None = Field(default=None, min_length=1, max_length=200)
    argument: str | None = Field(default=None, max_length=1000)
    intent_action: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_.]{0,254}$",
    )
    categories: list[str] = Field(default_factory=list, max_length=8)
    reset: Literal["inherit", "clean", "preserve"] = "inherit"
    oracle: AgentOracleSpec = Field(default_factory=AgentOracleSpec)
    rationale: str = Field(min_length=1, max_length=1000)
    poc: AgentPocSpec | None = None

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        if self.operation == "call" and not self.method:
            raise ValueError("provider call requires method")
        if self.operation != "call" and (self.method is not None or self.argument is not None):
            raise ValueError("method and argument are only valid for provider call")
        if any(
            not 1 <= len(category) <= 255
            or not category[0].isalpha()
            or any(not (character.isalnum() or character in "_.") for character in category)
            for category in self.categories
        ):
            raise ValueError("intent category is unsafe")
        return self


class AgentHypothesisAssessment(BaseModel):
    """A hypothesis-specific closure receipt instead of a task-wide blanket verdict."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    verdict: Literal[
        "supported_static",
        "refuted_static",
        "reproduced_blackbox",
        "not_reproduced",
    ]
    source: str = Field(default="", max_length=2000)
    control: str = Field(default="", max_length=2000)
    sink: str = Field(default="", max_length=2000)
    reachable_path: str = Field(default="", max_length=4000)
    boundary: str = Field(default="", max_length=2000)
    counterevidence: list[str] = Field(default_factory=list, max_length=50)
    proof_gaps: list[str] = Field(default_factory=list, max_length=50)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    confidence: Literal["high", "medium", "low"] = "medium"


class AgentInvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    summary: str = Field(
        min_length=1,
        max_length=8000,
        pattern=r"[\u3400-\u9fff]",
        description=(
            "Simplified-Chinese conclusion summary. Technical identifiers remain verbatim."
        ),
    )
    result: Literal[
        "supported_static",
        "refuted_static",
        "reproduced_blackbox",
        "not_reproduced",
    ]
    hypotheses_tested: list[str] = Field(max_length=100)
    hypothesis_assessments: list[AgentHypothesisAssessment] = Field(
        default_factory=list,
        max_length=100,
    )
    test_cases: list[dict[str, Any]] = Field(max_length=200)
    evidence_ids: list[str] = Field(max_length=500)
    severity_proposal: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    coverage_gaps: list[str] = Field(max_length=100)
    followups: list[str] = Field(max_length=100)
    requested_tests: list[AgentRequestedTest] = Field(max_length=1000)

    @model_validator(mode="after")
    def validate_explicit_verdict(self) -> Self:
        if self.result == "refuted_static" and self.severity_proposal != "info":
            raise ValueError("refuted_static must use info severity")
        return self


class HypothesisArgumentOut(ApiModel):
    id: str
    role: str
    position: str
    phase: str
    backend: str
    model: str | None
    payload: dict[str, Any]
    evidence_ids: list[str]
    created_at: datetime


class ProofAttemptOut(ApiModel):
    id: str
    test_case_id: str
    prover: str
    status: str
    plan: dict[str, Any]
    oracle: dict[str, Any]
    evidence_ids: list[str]
    harm_demonstrated: bool
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class SecurityHypothesisOut(ApiModel):
    id: str
    task_id: str
    fingerprint: str
    category: str
    claim: str
    attacker_model: dict[str, Any]
    preconditions: list[str]
    impact: str
    status: str
    confidence_score: int
    source_role: str
    entry_point_ids: list[str]
    support_evidence_ids: list[str]
    refute_evidence_ids: list[str]
    proof_obligations: list[dict[str, Any]]
    final_finding_id: str | None
    metadata_json: dict[str, Any]
    arguments: list[HypothesisArgumentOut] = Field(default_factory=list)
    proof_attempts: list[ProofAttemptOut] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class GroundTruthMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_ids: list[str] = Field(default_factory=list, max_length=32)
    cwes: list[str] = Field(default_factory=list, max_length=32)
    entry_names: list[str] = Field(default_factory=list, max_length=64)
    title_contains: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def require_selector(self) -> Self:
        if not any((self.rule_ids, self.cwes, self.entry_names, self.title_contains)):
            raise ValueError("at least one ground-truth matching selector is required")
        return self


class GroundTruthVulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=1000)
    harm: str = Field(min_length=1, max_length=4000)
    severity: Literal["critical", "high", "medium", "low", "info"]
    minimum_proof: Literal["static", "dynamic"] = "dynamic"
    match: GroundTruthMatch


class BenchmarkSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    name: str = Field(min_length=1, max_length=256)
    apk_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    vulnerabilities: list[GroundTruthVulnerability] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def require_unique_vulnerability_ids(self) -> Self:
        identifiers = [item.id for item in self.vulnerabilities]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("ground-truth vulnerability IDs must be unique")
        return self


class BenchmarkEvaluationOut(ApiModel):
    id: str
    scan_id: str
    schema_version: str
    name: str
    artifact_sha256: str
    investigator_backend: str
    model: str | None
    ground_truth: dict[str, Any]
    result: dict[str, Any]
    created_at: datetime


def _inline_local_json_schema_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline Pydantic's local definitions for provider-compatible tool schemas."""
    definitions = schema.pop("$defs", {})

    def inline(value: Any, stack: tuple[str, ...] = ()) -> Any:
        if isinstance(value, list):
            return [inline(item, stack) for item in value]
        if not isinstance(value, dict):
            return value

        ref = value.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            name = ref.removeprefix("#/$defs/")
            if name not in definitions:
                raise ValueError(f"unknown local JSON Schema reference: {ref}")
            if name in stack:
                raise ValueError(f"recursive JSON Schema reference is unsupported: {ref}")
            merged = {
                **definitions[name],
                **{key: item for key, item in value.items() if key != "$ref"},
            }
            return inline(merged, (*stack, name))

        return {
            key: inline(item, stack)
            for key, item in value.items()
            if key not in {"$defs", "$schema"}
        }

    result = inline(schema)
    if not isinstance(result, dict):
        raise TypeError("root JSON Schema must be an object")
    return result


AGENT_RESULT_JSON_SCHEMA = _inline_local_json_schema_refs(
    AgentInvestigationResult.model_json_schema()
)
