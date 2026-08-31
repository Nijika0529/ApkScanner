from __future__ import annotations

import base64
import re
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)


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


class ScanQualityFunnelStage(BaseModel):
    key: str
    label: str
    count: int = Field(ge=0)


class ScanQualityFailure(BaseModel):
    kind: str
    label: str
    count: int = Field(ge=1)
    examples: list[str] = Field(default_factory=list)


class ScanQualityPhaseUsage(BaseModel):
    phase: str
    calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    duration_seconds: float = Field(ge=0)


class ScanQualitySummary(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    generated_at: datetime
    funnel: list[ScanQualityFunnelStage]
    task_statuses: dict[str, int]
    proof_statuses: dict[str, int]
    failure_reasons: list[ScanQualityFailure]
    cost: dict[str, int | float]
    efficiency: dict[str, int | float | None]
    phase_usage: list[ScanQualityPhaseUsage]


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
    disposition: str | None = None


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


class SecuritySnapshotOut(ApiModel):
    id: str
    scan_id: str
    schema_version: str
    package_name: str
    signer_digest: str | None
    version_name: str | None
    version_code: str | None
    snapshot_hash: str
    payload: dict[str, Any]
    created_at: datetime


class VersionDiffOut(ApiModel):
    id: str
    baseline_scan_id: str
    target_scan_id: str
    schema_version: str
    status: str
    summary: dict[str, Any]
    entry_mapping: list[dict[str, Any]]
    deltas: list[dict[str, Any]]
    replay_candidates: list[dict[str, Any]]
    created_at: datetime


class RegressionCaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_key: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    harm: StrictStr = Field(min_length=1, max_length=10_000)
    minimum_proof: Literal["static", "dynamic"] = "dynamic"


class VulnerabilityOccurrenceOut(ApiModel):
    id: str
    case_id: str
    scan_id: str
    finding_id: str | None
    analysis_status: str
    proof_level: str
    match_quality: str
    match_reason: str
    observed_identity_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class VulnerabilityCaseOut(ApiModel):
    id: str
    application_id: str
    case_key: str
    fingerprint_version: str
    fingerprint: str
    identity_json: dict[str, Any]
    title: str
    description: str
    harm: str
    severity: str
    cwe: str | None
    masvs: str
    minimum_proof: str
    lifecycle: str
    source_scan_id: str | None
    source_finding_id: str | None
    created_at: datetime
    updated_at: datetime


class VulnerabilityPatternOut(ApiModel):
    id: str
    schema_version: str
    fingerprint: str
    status: str
    source_finding_id: str | None
    source_scan_id: str | None
    vulnerability_class: str
    title: str
    attacker_model: dict[str, Any]
    entry_signature: dict[str, Any]
    code_signature: dict[str, Any]
    missing_guards: list[str]
    exclusion_conditions: list[str]
    proof_recipe: dict[str, Any]
    metadata_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class PatternMatchOut(ApiModel):
    id: str
    schema_version: str
    pattern_id: str
    scan_id: str
    entry_point_id: str
    status: str
    score: int
    reasons: list[str]
    metadata_json: dict[str, Any]
    created_at: datetime


class FindingReview(BaseModel):
    status: Literal["accepted", "false_positive", "candidate"]
    note: str = Field(min_length=1, max_length=4000)


class ScanAgentControl(BaseModel):
    enabled: StrictBool
    backend: Literal["codex", "none"] | None = None


class ScanExecutionControl(BaseModel):
    action: Literal["pause", "resume", "stop"]


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


class TaskReanalysisRequest(BaseModel):
    context_mode: Literal["continue", "independent"]


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
    integrity: Literal["verified", "failed", "not_checked"]
    integrity_errors: list[str]
    started_at: datetime
    completed_at: datetime | None


class Capability(BaseModel):
    name: str
    available: bool
    busy: bool = False
    version: str | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    max_upload_bytes: int = Field(gt=0)
    default_investigator: Literal["codex", "none"] = "codex"
    enabled_investigators: list[Literal["codex"]] = Field(default_factory=list)
    capabilities: list[Capability]


class AdbDeviceConnectRequest(BaseModel):
    serial: StrictStr = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    label: StrictStr | None = Field(default=None, max_length=255)
    connect: StrictBool = True


class AdbDeviceOut(BaseModel):
    id: str
    serial: str
    label: str | None
    state: str
    enabled: bool
    api_level: int | None
    android_version: str | None
    available: bool
    android16_verdict_eligible: bool
    dynamic_verdict_eligible: bool
    release_gate_eligible: bool
    compatibility_smoke_only: bool
    validation_profile: str
    verdict_scope: str
    busy: bool
    active_task_id: str | None
    last_error: str | None
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


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
        pattern=r"^io\.apkscanner\.poc(?:\.[a-z][a-z0-9_]*)*$",
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
    harness_mode: Literal["platform_generated", "custom"] = "custom"
    attack_class: str | None = Field(
        default=None,
        pattern=(r"^[A-Za-z][A-Za-z0-9_$]*(?:\.[A-Za-z][A-Za-z0-9_$]*)+$"),
        max_length=300,
    )
    attack_method: str = Field(
        default="runAttack",
        pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$",
    )
    prebuilt_apk_path: str | None = Field(
        default=None,
        pattern=r"^poc/[A-Za-z0-9][A-Za-z0-9._/-]{0,220}\.apk$",
        max_length=256,
    )

    @model_validator(mode="after")
    def validate_harness(self) -> Self:
        if self.harness_mode == "platform_generated":
            if self.prebuilt_apk_path is not None:
                raise ValueError("platform_generated harness requires a source project")
            if self.attack_class is None:
                raise ValueError("platform_generated harness requires attack_class")
        elif self.attack_class is not None:
            raise ValueError("attack_class is valid only for platform_generated harness")
        return self


class AgentBinderScriptStep(BaseModel):
    """One bounded primitive Parcel write/read performed by a platform proof Harness."""

    model_config = ConfigDict(extra="forbid")

    operation: Literal[
        "write_string",
        "write_integer",
        "write_long",
        "write_boolean",
        "write_bytes_base64",
        "read_string",
        "read_integer",
        "read_long",
        "read_boolean",
        "read_bytes_base64",
    ]
    string_value: str | None = Field(default=None, max_length=16_384)
    integer_value: StrictInt | None = None
    boolean_value: StrictBool | None = None

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        write_field = {
            "write_string": "string_value",
            "write_bytes_base64": "string_value",
            "write_integer": "integer_value",
            "write_long": "integer_value",
            "write_boolean": "boolean_value",
        }.get(self.operation)
        populated = {
            "string_value": self.string_value is not None,
            "integer_value": self.integer_value is not None,
            "boolean_value": self.boolean_value is not None,
        }
        if write_field is None:
            if any(populated.values()):
                raise ValueError("Binder read steps cannot include a value")
            return self
        if not populated[write_field] or sum(populated.values()) != 1:
            raise ValueError(f"{self.operation} requires only {write_field}")
        if self.operation == "write_integer" and not -(2**31) <= self.integer_value < 2**31:
            raise ValueError("write_integer requires a signed 32-bit value")
        if self.operation == "write_long" and not -(2**63) <= self.integer_value < 2**63:
            raise ValueError("write_long requires a signed 64-bit value")
        if self.operation == "write_bytes_base64":
            try:
                decoded = base64.b64decode(self.string_value or "", validate=True)
            except ValueError as exc:
                raise ValueError("write_bytes_base64 requires canonical base64") from exc
            if base64.b64encode(decoded).decode("ascii") != self.string_value:
                raise ValueError("write_bytes_base64 requires canonical base64")
        return self


def _validate_binder_script(steps: list[AgentBinderScriptStep]) -> None:
    seen_read = False
    for step in steps:
        is_read = step.operation.startswith("read_")
        if seen_read and not is_read:
            raise ValueError("Binder write steps must precede all read steps")
        seen_read = seen_read or is_read
    if not seen_read:
        raise ValueError("binder_script requires at least one read step")


class AgentOracleSpec(BaseModel):
    """An objective observation the platform can evaluate after a requested test."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "reachability",
        "provider_rows",
        "ui_text",
        "log_contains",
        "target_uid_log_contains",
        "target_file_sha256",
        "process_crash",
        "binder_reply",
    ] = "reachability"
    expected_text: str | None = Field(default=None, min_length=1, max_length=500)
    match_mode: Literal["exact", "contains", "regex", "sha256", "non_empty"] = "exact"
    reply_index: int = Field(default=0, ge=0, le=31)
    minimum_rows: int | None = Field(default=None, ge=1, le=1_000_000)
    target_path: str | None = Field(default=None, min_length=1, max_length=512)
    impact: Literal[
        "none",
        "unauthorized_data_access",
        "unauthorized_state_change",
        "privileged_action",
        "denial_of_service",
    ] = "none"
    impact_contract_id: str | None = Field(
        default=None,
        pattern=r"^(?:builtin|semantic):[a-z0-9_.:-]{3,160}$",
        max_length=192,
    )
    refute_on_miss: bool = False

    @model_validator(mode="after")
    def validate_predicate(self) -> Self:
        if (
            self.kind
            in {
                "ui_text",
                "log_contains",
                "target_uid_log_contains",
                "binder_reply",
            }
            and self.match_mode != "non_empty"
            and not self.expected_text
        ):
            raise ValueError(f"{self.kind} requires expected_text")
        if self.kind != "binder_reply" and (self.match_mode != "exact" or self.reply_index != 0):
            raise ValueError("match_mode and reply_index are supported only by binder_reply")
        if self.kind == "binder_reply" and self.match_mode == "non_empty" and self.impact != "none":
            raise ValueError("a non-empty Binder reply alone cannot prove security impact")
        if self.kind == "binder_reply" and self.match_mode == "regex" and self.expected_text:
            try:
                re.compile(self.expected_text)
            except re.error as exc:
                raise ValueError("binder_reply regex expected_text is invalid") from exc
        if (
            self.kind == "binder_reply"
            and self.match_mode == "sha256"
            and (not self.expected_text or not re.fullmatch(r"[a-f0-9]{64}", self.expected_text))
        ):
            raise ValueError("binder_reply sha256 requires a lowercase SHA-256 expected_text")
        if self.kind == "provider_rows" and self.minimum_rows is None:
            self.minimum_rows = 1
        if self.kind == "target_file_sha256":
            if not self.target_path:
                raise ValueError("target_file_sha256 requires target_path")
            normalized_path = self.target_path.strip()
            path_parts = normalized_path.split("/")
            if (
                normalized_path != self.target_path
                or normalized_path.startswith("/")
                or "\\" in normalized_path
                or any(part in {"", ".", ".."} for part in path_parts)
                or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in path_parts)
            ):
                raise ValueError(
                    "target_file_sha256 target_path must be a safe app-data-relative path"
                )
        elif self.target_path is not None:
            raise ValueError("target_path is supported only by target_file_sha256")
        allowed_impacts = {
            "reachability": {"none"},
            "provider_rows": {"none", "unauthorized_data_access"},
            "ui_text": {
                "none",
                "unauthorized_data_access",
                "unauthorized_state_change",
            },
            "log_contains": {
                "none",
                "unauthorized_data_access",
                "unauthorized_state_change",
                "privileged_action",
            },
            # A target-owned log line proves provenance and reachability, not the
            # security meaning of the message. Privileged effects must be attested
            # by a separate semantic proof receipt bound to concrete observations.
            "target_uid_log_contains": {"none"},
            "target_file_sha256": {"unauthorized_state_change"},
            "process_crash": {"none", "denial_of_service"},
            "binder_reply": {"none", "unauthorized_data_access"},
        }
        if self.impact not in allowed_impacts[self.kind]:
            supported = ", ".join(sorted(allowed_impacts[self.kind]))
            raise ValueError(f"{self.kind} Oracle supports only these impacts: {supported}")
        if self.impact == "none":
            if self.impact_contract_id is not None:
                raise ValueError("impact_contract_id requires a non-none impact")
        elif self.impact_contract_id is None:
            self.impact_contract_id = f"builtin:{self.kind}:{self.impact}"
        return self


class AgentExperimentStepSpec(BaseModel):
    """A bounded ADB step proposed by an Agent for a platform-owned experiment."""

    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    title: StrictStr = Field(min_length=1, max_length=512)
    phase: Literal["prepare", "action", "observe", "assert", "cleanup"] = "action"
    adb_args: list[StrictStr] = Field(min_length=1, max_length=64)
    timeout_seconds: StrictInt = Field(default=30, ge=1, le=120)
    expected_exit_code: StrictInt = Field(default=0, ge=0, le=255)
    stdout_contains: list[StrictStr] = Field(default_factory=list, max_length=32)
    stdout_regex: StrictStr | None = Field(default=None, min_length=1, max_length=2000)
    capture_stdout_as: StrictStr | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
    )
    observation_kind: StrictStr | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_.-]{2,127}$",
    )
    continue_on_failure: StrictBool = False


class AgentExperimentProofSpec(BaseModel):
    """The exact assertion receipts that may satisfy a semantic impact contract."""

    model_config = ConfigDict(extra="forbid")

    contract_id: StrictStr = Field(
        pattern=r"^semantic:[a-z0-9_.:-]{3,160}$",
        max_length=192,
    )
    impact: Literal[
        "unauthorized_data_access",
        "unauthorized_state_change",
        "privileged_action",
        "denial_of_service",
    ]
    observed_fact: StrictStr = Field(min_length=1, max_length=1000)
    assertion_step_ids: list[StrictStr] = Field(min_length=1, max_length=16)
    observation_kinds: list[StrictStr] = Field(min_length=1, max_length=16)
    refute_on_failure: StrictBool = False


class AgentExperimentPlan(BaseModel):
    """A stateful platform experiment embedded in an Agent proof request."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    name: StrictStr = Field(min_length=1, max_length=256)
    objective: StrictStr = Field(min_length=1, max_length=4000)
    preconditions: list[StrictStr] = Field(default_factory=list, max_length=32)
    steps: list[AgentExperimentStepSpec] = Field(min_length=1, max_length=32)
    cleanup_steps: list[AgentExperimentStepSpec] = Field(default_factory=list, max_length=16)
    proof: AgentExperimentProofSpec

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        all_steps = [*self.steps, *self.cleanup_steps]
        identifiers = [item.id for item in all_steps]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("experiment step IDs must be unique")
        if any(item.phase == "cleanup" for item in self.steps):
            raise ValueError("cleanup steps belong in cleanup_steps")
        if any(item.phase != "cleanup" for item in self.cleanup_steps):
            raise ValueError("every cleanup_steps item must use phase=cleanup")
        if not any(item.phase == "action" for item in self.steps):
            raise ValueError("dynamic experiments require at least one action step")
        assertion_steps = {item.id: item for item in self.steps if item.phase == "assert"}
        required_ids = set(self.proof.assertion_step_ids)
        if len(required_ids) != len(self.proof.assertion_step_ids) or not required_ids:
            raise ValueError("assertion_step_ids must be unique and non-empty")
        if not required_ids <= set(assertion_steps):
            raise ValueError("every assertion_step_id must reference an assert step")
        required_kinds = set(self.proof.observation_kinds)
        if len(required_kinds) != len(self.proof.observation_kinds):
            raise ValueError("observation_kinds must be unique")
        for step_id in required_ids:
            observation_kind = assertion_steps[step_id].observation_kind
            if observation_kind is None or observation_kind not in required_kinds:
                raise ValueError(
                    "proof assertion steps must emit a declared observation_kind"
                )
        return self


class AgentRequestedTest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    entry_point_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    state: Literal["guest"] = "guest"
    uri: str | None = Field(default=None, max_length=4096)
    extras: dict[str, StrictStr | StrictInt | StrictBool] = Field(
        default_factory=dict,
        max_length=16,
    )
    operation: Literal[
        "auto",
        "query",
        "call",
        "insert",
        "update",
        "delete",
        "binder_transact",
        "binder_script",
    ] = "auto"
    method: str | None = Field(default=None, min_length=1, max_length=200)
    argument: str | None = Field(default=None, max_length=1000)
    binder_transaction_code: int | None = Field(
        default=None,
        ge=1,
        le=0x00FFFFFF,
    )
    binder_interface_descriptor: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
    )
    binder_reply_type: Literal["string", "integer", "long", "boolean"] | None = None
    binder_read_exception: StrictBool | None = None
    binder_script: list[AgentBinderScriptStep] | None = Field(
        default=None,
        min_length=1,
        max_length=32,
    )
    intent_action: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_.]{0,254}$",
    )
    categories: list[str] = Field(default_factory=list, max_length=8)
    reset: Literal["inherit", "clean", "preserve"] = "preserve"
    oracle: AgentOracleSpec = Field(default_factory=AgentOracleSpec)
    rationale: str = Field(min_length=1, max_length=1000)
    poc: AgentPocSpec | None = None
    experiment: AgentExperimentPlan | None = None

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        if self.experiment is not None:
            if self.operation != "auto":
                raise ValueError("dynamic experiments require operation=auto")
            if self.poc is not None:
                raise ValueError("dynamic experiments cannot include a PoC project")
            if any(
                (
                    self.uri is not None,
                    bool(self.extras),
                    self.method is not None,
                    self.argument is not None,
                    self.intent_action is not None,
                    bool(self.categories),
                    self.reset != "preserve",
                )
            ):
                raise ValueError(
                    "dynamic experiment actions belong in experiment.steps, not legacy fields"
                )
            if any(
                value is not None
                for value in (
                    self.binder_transaction_code,
                    self.binder_interface_descriptor,
                    self.binder_reply_type,
                    self.binder_read_exception,
                    self.binder_script,
                )
            ):
                raise ValueError("dynamic experiments cannot include legacy Binder fields")
            if self.oracle.kind != "reachability" or self.oracle.impact != "none":
                raise ValueError(
                    "dynamic experiment proof semantics belong in experiment.proof"
                )
            return self
        if self.operation == "call" and not self.method:
            raise ValueError("provider call requires method")
        if self.operation != "call" and (self.method is not None or self.argument is not None):
            raise ValueError("method and argument are only valid for provider call")
        binder_fields = (
            self.binder_transaction_code,
            self.binder_interface_descriptor,
            self.binder_reply_type,
            self.binder_read_exception,
            self.binder_script,
        )
        if self.operation in {"binder_transact", "binder_script"}:
            if self.binder_transaction_code is None:
                raise ValueError(f"{self.operation} requires binder_transaction_code")
            if self.operation == "binder_transact" and self.binder_reply_type is None:
                raise ValueError("binder_transact requires binder_reply_type")
            if self.operation == "binder_script" and not self.binder_script:
                raise ValueError("binder_script requires at least one script step")
            if self.operation == "binder_script" and self.binder_script:
                _validate_binder_script(self.binder_script)
            if self.operation == "binder_transact" and self.binder_script is not None:
                raise ValueError("binder_script steps require operation=binder_script")
            if self.poc is not None:
                raise ValueError(
                    f"{self.operation} uses a platform-generated proof Harness and cannot include poc"
                )
            if self.binder_read_exception is None:
                self.binder_read_exception = True
            if self.oracle.kind != "binder_reply":
                raise ValueError(f"{self.operation} requires a binder_reply Oracle")
        elif any(value is not None for value in binder_fields):
            raise ValueError("Binder fields are valid only for Binder operations")
        if self.binder_interface_descriptor is not None and any(
            character in self.binder_interface_descriptor for character in "\r\n\x00"
        ):
            raise ValueError("binder_interface_descriptor contains a control character")
        if any(
            not 1 <= len(category) <= 255
            or not category[0].isalpha()
            or any(not (character.isalnum() or character in "_.") for character in category)
            for category in self.categories
        ):
            raise ValueError("intent category is unsafe")
        return self


class AgentProofReplay(BaseModel):
    """One final platform-attested replay after free Agent exploration."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str = Field(
        pattern=r"^[a-f0-9-]{36}$",
    )
    entry_point_id: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9-]{36}$",
    )
    extras: dict[str, StrictStr | StrictInt | StrictBool] = Field(
        default_factory=dict,
        max_length=16,
    )
    operation: Literal["auto", "binder_transact", "binder_script"] = "auto"
    binder_transaction_code: int | None = Field(
        default=None,
        ge=1,
        le=0x00FFFFFF,
    )
    binder_interface_descriptor: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
    )
    binder_reply_type: Literal["string", "integer", "long", "boolean"] | None = None
    binder_read_exception: StrictBool | None = None
    binder_script: list[AgentBinderScriptStep] | None = Field(
        default=None,
        min_length=1,
        max_length=32,
    )
    reset: Literal["inherit", "clean", "preserve"] = "preserve"
    oracle: AgentOracleSpec
    rationale: str = Field(min_length=1, max_length=1000)
    poc: AgentPocSpec | None = None

    @model_validator(mode="after")
    def validate_replay_action(self) -> Self:
        binder_fields = (
            self.binder_transaction_code,
            self.binder_interface_descriptor,
            self.binder_reply_type,
            self.binder_read_exception,
            self.binder_script,
        )
        if self.operation in {"binder_transact", "binder_script"}:
            if self.poc is not None:
                raise ValueError(f"{self.operation} replay cannot include poc")
            if self.binder_transaction_code is None:
                raise ValueError(f"{self.operation} requires binder_transaction_code")
            if self.operation == "binder_transact" and self.binder_reply_type is None:
                raise ValueError("binder_transact requires binder_reply_type")
            if self.operation == "binder_script" and not self.binder_script:
                raise ValueError("binder_script requires at least one script step")
            if self.operation == "binder_script" and self.binder_script:
                _validate_binder_script(self.binder_script)
            if self.operation == "binder_transact" and self.binder_script is not None:
                raise ValueError("binder_script steps require operation=binder_script")
            if self.binder_read_exception is None:
                self.binder_read_exception = True
            if self.oracle.kind != "binder_reply":
                raise ValueError(f"{self.operation} requires a binder_reply Oracle")
        else:
            if self.poc is None:
                raise ValueError("a non-Binder proof replay requires poc")
            if any(value is not None for value in binder_fields):
                raise ValueError("Binder fields are valid only for Binder operations")
        if self.binder_interface_descriptor is not None and any(
            character in self.binder_interface_descriptor for character in "\r\n\x00"
        ):
            raise ValueError("binder_interface_descriptor contains a control character")
        return self


class AgentRuntimeObservation(BaseModel):
    """A normalized semantic fact collected during free-form Agent validation."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    source: Literal[
        "adb",
        "poc",
        "webview_callback",
        "network_callback",
        "localhost_client",
        "unix_socket_client",
        "ssh_remote",
        "agent",
    ]
    finding_id: str | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)


class AgentHypothesisAssessment(BaseModel):
    """A hypothesis-specific closure receipt instead of a task-wide blanket verdict."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    verdict: Literal[
        "supported_static",
        "refuted_static",
        "reproduced_blackbox",
        "not_reproduced",
        "needs_dynamic_proof",
    ]
    source: str = Field(default="", max_length=2000)
    control: str = Field(default="", max_length=2000)
    sink: str = Field(default="", max_length=2000)
    reachable_path: str = Field(default="", max_length=4000)
    boundary: str = Field(default="", max_length=2000)
    counterevidence: list[str] = Field(default_factory=list)
    proof_gaps: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"


class AgentReviewObjection(BaseModel):
    """A concrete Critic objection that the terminal evaluator must resolve."""

    model_config = ConfigDict(extra="forbid")

    objection_id: str = Field(pattern=r"^OBJ-[A-Za-z0-9_-]{1,32}$")
    hypothesis_id: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9-]{36}$",
    )
    claim: str = Field(min_length=1, max_length=2000)
    basis: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list)


class AgentObjectionResolution(BaseModel):
    """The final evaluator's explicit disposition of one Critic objection."""

    model_config = ConfigDict(extra="forbid")

    objection_id: str = Field(pattern=r"^OBJ-[A-Za-z0-9_-]{1,32}$")
    disposition: Literal["sustained", "overruled", "partially_sustained"]
    rationale: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list)


class AgentTestCaseSummary(BaseModel):
    """A model-authored summary; platform ProofAttempt rows remain authoritative."""

    model_config = ConfigDict(extra="forbid")

    test_case_id: str = Field(min_length=1, max_length=128)
    hypothesis_id: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9-]{36}$",
    )
    description: str = Field(min_length=1, max_length=2000)
    status: Literal["planned", "executed", "passed", "failed", "inconclusive"]
    evidence_ids: list[str] = Field(default_factory=list)


def _normalize_wire_extras(request: dict[str, Any]) -> dict[str, Any]:
    """Convert the closed Responses wire representation into Android extras."""

    wire_extras = request.get("extras")
    if not isinstance(wire_extras, list):
        return request
    extras: dict[str, StrictStr | StrictInt | StrictBool] = {}
    for item in wire_extras:
        if not isinstance(item, dict):
            return {**request, "extras": {"wire_extras": item}}
        key = item.get("key")
        value_type = item.get("value_type")
        value_key = f"{value_type}_value"
        value = item.get(value_key)
        value_matches_type = (
            (value_type == "string" and isinstance(value, str))
            or (value_type == "integer" and type(value) is int)
            or (value_type == "boolean" and type(value) is bool)
        )
        unused_values_are_null = all(
            item.get(name) is None
            for name in ("string_value", "integer_value", "boolean_value")
            if name != value_key
        )
        if (
            not isinstance(key, str)
            or key in extras
            or value_type not in {"string", "integer", "boolean"}
            or not value_matches_type
            or not unused_values_are_null
        ):
            return {**request, "extras": {"wire_extras": item}}
        extras[key] = value
    return {**request, "extras": extras}


class AgentInvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    _rejected_requested_tests: list[dict[str, Any]] = PrivateAttr(default_factory=list)
    _normalization_repairs: list[dict[str, Any]] = PrivateAttr(default_factory=list)

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
    hypotheses_tested: list[str]
    hypothesis_assessments: list[AgentHypothesisAssessment] = Field(default_factory=list)
    review_objections: list[AgentReviewObjection] = Field(default_factory=list)
    objection_resolutions: list[AgentObjectionResolution] = Field(default_factory=list)
    test_cases: list[AgentTestCaseSummary]
    evidence_ids: list[str]
    severity_proposal: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    coverage_gaps: list[str]
    followups: list[str]
    requested_tests: list[AgentRequestedTest] = Field(default_factory=list)

    @model_validator(mode="wrap")
    @classmethod
    def isolate_invalid_requested_tests(cls, value: Any, handler):  # noqa: ANN001, ANN206
        """Repair unambiguous wire variance and retain malformed optional actions."""

        if not isinstance(value, dict):
            return handler(value)
        normalized = dict(value)
        repairs: list[dict[str, Any]] = []

        assessments = normalized.get("hypothesis_assessments")
        if isinstance(assessments, list):
            normalized_assessments: list[Any] = []
            for index, assessment in enumerate(assessments):
                if not isinstance(assessment, dict):
                    normalized_assessments.append(assessment)
                    continue
                normalized_assessment = dict(assessment)
                for field_name in ("counterevidence", "proof_gaps"):
                    field_value = normalized_assessment.get(field_name)
                    if not isinstance(field_value, str):
                        continue
                    stripped = field_value.strip()
                    normalized_assessment[field_name] = [stripped] if stripped else []
                    repairs.append(
                        {
                            "location": f"hypothesis_assessments.{index}.{field_name}",
                            "repair": "string_wrapped_as_list",
                            "original_type": "string",
                        }
                    )
                normalized_assessments.append(normalized_assessment)
            normalized["hypothesis_assessments"] = normalized_assessments

        if (
            normalized.get("result") == "refuted_static"
            and normalized.get("severity_proposal") != "info"
        ):
            repairs.append(
                {
                    "location": "severity_proposal",
                    "repair": "forced_info_for_refuted_static",
                    "original_value": normalized.get("severity_proposal"),
                }
            )
            normalized["severity_proposal"] = "info"

        requested_tests = normalized.get("requested_tests")
        if not isinstance(requested_tests, list):
            result = handler(normalized)
            result._normalization_repairs = repairs
            return result
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for index, request in enumerate(requested_tests):
            normalized_request = (
                _normalize_wire_extras(request) if isinstance(request, dict) else request
            )
            if isinstance(normalized_request, dict):
                oracle = normalized_request.get("oracle")
                if isinstance(oracle, dict):
                    repaired_oracle = dict(oracle)
                    oracle_repaired = False
                    if (
                        repaired_oracle.get("kind") != "binder_reply"
                        and repaired_oracle.get("match_mode", "exact") != "exact"
                    ):
                        repairs.append(
                            {
                                "location": f"requested_tests.{index}.oracle.match_mode",
                                "repair": "removed_binder_only_field",
                                "original_value": repaired_oracle.get("match_mode"),
                            }
                        )
                        repaired_oracle["match_mode"] = "exact"
                        oracle_repaired = True
                    if (
                        repaired_oracle.get("kind") != "binder_reply"
                        and repaired_oracle.get("reply_index", 0) != 0
                    ):
                        repairs.append(
                            {
                                "location": f"requested_tests.{index}.oracle.reply_index",
                                "repair": "removed_binder_only_field",
                                "original_value": repaired_oracle.get("reply_index"),
                            }
                        )
                        repaired_oracle["reply_index"] = 0
                        oracle_repaired = True
                    if (
                        repaired_oracle.get("kind") != "target_file_sha256"
                        and repaired_oracle.get("target_path") is not None
                    ):
                        repairs.append(
                            {
                                "location": f"requested_tests.{index}.oracle.target_path",
                                "repair": "cleared_target_file_only_field",
                                "original_value": repaired_oracle.get("target_path"),
                            }
                        )
                        # The provider wire schema requires this nullable field even
                        # when its semantic use is forbidden. Preserve that shape while
                        # repairing the unambiguous cross-field mismatch.
                        repaired_oracle["target_path"] = None
                        oracle_repaired = True
                    if oracle_repaired:
                        normalized_request = {
                            **normalized_request,
                            "oracle": repaired_oracle,
                        }
                poc = normalized_request.get("poc")
                if (
                    isinstance(poc, dict)
                    and poc.get("harness_mode", "custom") == "custom"
                    and poc.get("attack_class") is not None
                ):
                    repaired_poc = dict(poc)
                    attack_class = repaired_poc.pop("attack_class")
                    repairs.append(
                        {
                            "location": f"requested_tests.{index}.poc.attack_class",
                            "repair": "removed_platform_harness_only_field",
                            "original_value": attack_class,
                        }
                    )
                    normalized_request = {
                        **normalized_request,
                        "poc": repaired_poc,
                    }
                uri = normalized_request.get("uri")
                if (
                    isinstance(uri, str)
                    and uri.startswith("content://")
                    and normalized_request.get("operation") != "call"
                    and (
                        normalized_request.get("method") is not None
                        or normalized_request.get("argument") is not None
                    )
                ):
                    normalized_request = {
                        **normalized_request,
                        "operation": "call",
                    }
                request_for_oracle = normalized_request
                oracle = request_for_oracle.get("oracle")
                if (
                    isinstance(oracle, dict)
                    and oracle.get("kind") == "log_contains"
                    and not oracle.get("expected_text")
                    and isinstance(request_for_oracle.get("poc"), dict)
                ):
                    # Every platform-built PoC emits the structured result key.
                    # Recover this harmless model omission instead of discarding
                    # an otherwise executable app-UID proof request.
                    normalized_request = {
                        **request_for_oracle,
                        "oracle": {
                            **oracle,
                            "expected_text": "security_impact_observed",
                        },
                    }
            try:
                accepted.append(
                    AgentRequestedTest.model_validate(normalized_request).model_dump(mode="python")
                )
            except ValidationError as exc:
                rejected.append(
                    {
                        "index": index,
                        "request": (
                            dict(request)
                            if isinstance(request, dict)
                            else {"unparsed_value": repr(request)}
                        ),
                        "errors": [
                            {
                                "location": ".".join(str(part) for part in error["loc"]),
                                "message": error["msg"],
                                "type": error["type"],
                            }
                            for error in exc.errors(
                                include_url=False,
                                include_context=False,
                                include_input=False,
                            )
                        ],
                    }
                )
        normalized["requested_tests"] = accepted
        if rejected:
            gaps = normalized.get("coverage_gaps")
            normalized["coverage_gaps"] = [
                *(gaps if isinstance(gaps, list) else []),
                (
                    f"平台拒绝了 {len(rejected)} 个格式或能力不受支持的补充测试请求；"
                    "具体校验错误已保留，下一轮必须修正或改用其他验证策略。"
                ),
            ]
        result = handler(normalized)
        result._rejected_requested_tests = rejected
        result._normalization_repairs = repairs
        return result

    @property
    def rejected_requested_tests(self) -> list[dict[str, Any]]:
        """Malformed model actions excluded from execution but retained for audit."""

        return [dict(item) for item in self._rejected_requested_tests]

    @property
    def normalization_repairs(self) -> list[dict[str, Any]]:
        """Unambiguous model-output repairs retained for response auditing."""

        return [dict(item) for item in self._normalization_repairs]

    def apply_model_validation_audit(self, audit: Any) -> Self:
        """Restore validation receipts transported across the worker boundary."""

        if not isinstance(audit, dict):
            return self
        rejected = audit.get("rejected_requested_tests")
        if isinstance(rejected, list):
            self._rejected_requested_tests = [
                dict(item) for item in rejected if isinstance(item, dict)
            ]
        repairs = audit.get("normalization_repairs")
        if isinstance(repairs, list):
            self._normalization_repairs = [dict(item) for item in repairs if isinstance(item, dict)]
        return self

    @model_validator(mode="after")
    def validate_explicit_verdict(self) -> Self:
        if self.result == "refuted_static" and self.severity_proposal != "info":
            raise ValueError("refuted_static must use info severity")
        objection_ids = [item.objection_id for item in self.review_objections]
        if len(objection_ids) != len(set(objection_ids)):
            raise ValueError("review_objections must use unique objection_id values")
        resolution_ids = [item.objection_id for item in self.objection_resolutions]
        if len(resolution_ids) != len(set(resolution_ids)):
            raise ValueError("objection_resolutions must use unique objection_id values")
        return self


class AdaptiveVerifierExperiment(BaseModel):
    """One free-form, model-operated verification experiment."""

    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=1, max_length=4000)
    actions: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    artifact_paths: list[str] = Field(default_factory=list)
    conclusion: str = Field(min_length=1, max_length=8000)


class AdaptiveVerifierAssessment(BaseModel):
    """A semantic verdict for one previously persisted candidate finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    duplicate_of_finding_id: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9-]{36}$",
    )
    verdict: Literal[
        "reproduced_blackbox",
        "supported_static",
        "refuted_static",
        "not_reproduced",
        "inconclusive",
    ]
    confidence: Literal["high", "medium", "low"]
    runtime_observed: bool
    summary: str = Field(min_length=1, max_length=8000)
    attack_chain: str = Field(default="", max_length=12_000)
    security_impact: str = Field(default="", max_length=8000)
    counterevidence: list[str] = Field(default_factory=list)
    remaining_gaps: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    experiments: list[AdaptiveVerifierExperiment] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_runtime_verdict(self) -> Self:
        if self.duplicate_of_finding_id == self.finding_id:
            raise ValueError("duplicate_of_finding_id cannot reference the same finding")
        if self.verdict == "reproduced_blackbox" and not self.runtime_observed:
            raise ValueError("reproduced_blackbox requires an actual runtime observation")
        if self.verdict == "not_reproduced" and not self.runtime_observed:
            raise ValueError("not_reproduced requires a relevant runtime attempt")
        return self


class AdaptiveVerificationResult(BaseModel):
    """Scan-level terminal output from the privileged adaptive verifier."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    summary: str = Field(
        min_length=1,
        max_length=12_000,
        pattern=r"[\u3400-\u9fff]",
    )
    assessments: list[AdaptiveVerifierAssessment]
    shared_observations: list[str] = Field(default_factory=list)
    cleanup_actions: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)


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
    proof_recipe: dict[str, Any] = Field(default_factory=dict)
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


class BenchmarkQualityGate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    minimum_precision: float = Field(default=1.0, ge=0.0, le=1.0)
    minimum_recall: float = Field(default=1.0, ge=0.0, le=1.0)
    maximum_false_positives: int = Field(default=0, ge=0, le=10_000)


class BenchmarkSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    name: str = Field(min_length=1, max_length=256)
    apk_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    required_dynamic_scope: Literal["android16_release", "any_dynamic"] = "android16_release"
    vulnerabilities: list[GroundTruthVulnerability] = Field(min_length=1, max_length=500)
    quality_gate: BenchmarkQualityGate = Field(default_factory=BenchmarkQualityGate)

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


class EvaluationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success_criteria: list[StrictStr] = Field(min_length=1, max_length=64)
    required_evidence_kinds: list[StrictStr] = Field(default_factory=list, max_length=64)
    inconclusive_conditions: list[StrictStr] = Field(min_length=1, max_length=64)
    forbidden_shortcuts: list[StrictStr] = Field(default_factory=list, max_length=64)


class InvestigationBriefCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: StrictStr | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    name: StrictStr = Field(min_length=1, max_length=256)
    objective: StrictStr = Field(min_length=1, max_length=10_000)
    scope: dict[str, Any] = Field(default_factory=dict)
    attacker_model: dict[str, Any] = Field(default_factory=dict)
    preconditions: list[StrictStr] = Field(default_factory=list, max_length=64)
    plan: dict[str, Any]
    evaluation_contract: EvaluationContract


class InvestigationBriefOut(ApiModel):
    id: str
    scan_id: str | None
    schema_version: str
    name: str
    objective: str
    status: str
    scope: dict[str, Any]
    attacker_model: dict[str, Any]
    preconditions: list[str]
    plan: dict[str, Any]
    evaluation_contract: dict[str, Any]
    result: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ValidationFixtureCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: StrictStr = Field(pattern=r"^[a-f0-9-]{36}$")
    task_id: StrictStr | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    name: StrictStr = Field(min_length=1, max_length=128)
    fixture_type: Literal["account", "session", "canary", "app_state"]
    payload: dict[str, Any] = Field(default_factory=dict)
    setup_instructions: list[StrictStr] = Field(default_factory=list, max_length=64)
    cleanup_instructions: list[StrictStr] = Field(default_factory=list, max_length=64)


class ValidationFixtureOut(ApiModel):
    id: str
    scan_id: str
    task_id: str | None
    name: str
    fixture_type: str
    status: str
    payload: dict[str, Any]
    setup_instructions: list[str]
    cleanup_instructions: list[str]
    created_at: datetime
    updated_at: datetime


class DynamicExperimentStepSpec(BaseModel):
    """One deterministic ADB step in a stateful runtime experiment."""

    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    title: StrictStr = Field(min_length=1, max_length=512)
    phase: Literal["prepare", "action", "observe", "assert", "cleanup"] = "action"
    adb_args: list[StrictStr] = Field(min_length=1, max_length=64)
    timeout_seconds: StrictInt = Field(default=30, ge=1, le=120)
    expected_exit_code: StrictInt = Field(default=0, ge=0, le=255)
    stdout_contains: list[StrictStr] = Field(default_factory=list, max_length=32)
    stdout_regex: StrictStr | None = Field(default=None, min_length=1, max_length=2000)
    capture_stdout_as: StrictStr | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
    )
    observation_kind: StrictStr | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_.-]{2,127}$",
    )
    continue_on_failure: StrictBool = False


class DynamicExperimentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: StrictStr | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    finding_id: StrictStr | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    name: StrictStr = Field(min_length=1, max_length=256)
    objective: StrictStr = Field(min_length=1, max_length=10_000)
    preferred_serial: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    fixture_ids: list[StrictStr] = Field(default_factory=list, max_length=64)
    preconditions: list[StrictStr] = Field(default_factory=list, max_length=64)
    impact_contract: dict[str, Any] = Field(default_factory=dict)
    steps: list[DynamicExperimentStepSpec] = Field(min_length=1, max_length=128)
    cleanup_steps: list[DynamicExperimentStepSpec] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def require_unique_step_ids(self) -> Self:
        all_steps = [*self.steps, *self.cleanup_steps]
        identifiers = [item.id for item in all_steps]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("dynamic experiment step IDs must be unique")
        if any(item.phase == "cleanup" for item in self.steps):
            raise ValueError("cleanup steps belong in cleanup_steps")
        if any(item.phase != "cleanup" for item in self.cleanup_steps):
            raise ValueError("every cleanup_steps item must use phase=cleanup")
        return self


class DynamicExperimentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preferred_serial: StrictStr | None = Field(default=None, min_length=1, max_length=255)


class DynamicExperimentReceiptOut(ApiModel):
    id: str
    capsule_id: str
    step_id: str
    attempt: int
    phase: str
    status: str
    command: list[str]
    evidence_ids: list[str]
    observation_ids: list[str]
    result_json: dict[str, Any]
    error: str | None
    started_at: datetime
    completed_at: datetime | None


class DynamicExperimentOut(ApiModel):
    id: str
    scan_id: str
    task_id: str | None
    finding_id: str | None
    name: str
    objective: str
    status: str
    preferred_serial: str | None
    device_serial: str | None
    fixture_ids: list[str]
    preconditions: list[str]
    impact_contract: dict[str, Any]
    steps: list[dict[str, Any]]
    cleanup_steps: list[dict[str, Any]]
    state_json: dict[str, Any]
    result_json: dict[str, Any]
    cancel_requested: bool
    error: str | None
    receipts: list[DynamicExperimentReceiptOut] = Field(default_factory=list)
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    updated_at: datetime


class RuntimeArtifactCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_mode: Literal["device_path", "run_as"]
    remote_path: StrictStr = Field(min_length=1, max_length=2048)
    package_name: StrictStr | None = Field(default=None, min_length=3, max_length=512)
    task_id: StrictStr | None = Field(default=None, pattern=r"^[a-f0-9-]{36}$")
    preferred_serial: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    loader_node_id: StrictStr | None = Field(default=None, min_length=1, max_length=2048)
    loader_anchor: dict[str, Any] = Field(default_factory=dict)
    schedule_investigations: StrictBool = True

    @model_validator(mode="after")
    def validate_capture_source(self) -> Self:
        if self.source_mode == "run_as" and self.package_name is None:
            raise ValueError("run_as capture requires package_name")
        return self


class RuntimeArtifactOut(ApiModel):
    id: str
    scan_id: str
    task_id: str | None
    artifact_type: str
    status: str
    sha256: str | None
    stored_path: str
    size_bytes: int
    package_name: str | None
    version_name: str | None
    version_code: str | None
    source_json: dict[str, Any]
    graph_node_id: str | None
    entry_point_ids: list[str]
    investigation_task_ids: list[str]
    result_json: dict[str, Any]
    error: str | None
    created_at: datetime
    completed_at: datetime | None
    updated_at: datetime


class InvestigationCriterionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    criterion: StrictStr = Field(min_length=1, max_length=2000)
    passed: StrictBool
    evidence_ids: list[StrictStr] = Field(default_factory=list, max_length=128)


class InvestigationBriefEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["passed", "failed", "inconclusive"]
    criteria: list[InvestigationCriterionResult] = Field(min_length=1, max_length=64)
    note: StrictStr = Field(min_length=1, max_length=10_000)


class CapabilityObject(BaseModel):
    """A first-class cross-process capability tracked through its lifecycle.

    Replaces raw regex markers for PendingIntent, URI Grant, and other
    Android IPC capabilities with a structured entity that records
    creator identity, escape path, mutability, and use sites.
    """

    model_config = ConfigDict(extra="forbid")

    capability_type: Literal[
        "pending_intent",
        "content_uri_grant",
        "file_provider_uri",
        "binder_handle",
        "clip_data",
    ] = Field(description="Which Android capability object this represents")
    creator_class: str = Field(min_length=1, max_length=500)
    creator_method: str | None = Field(default=None, max_length=300)
    holder_class: str | None = Field(default=None, max_length=500)
    target: str | None = Field(default=None, max_length=500)
    mutable: bool = Field(default=False)
    escape_path: list[str] = Field(default_factory=list, max_length=32)
    use_sites: list[str] = Field(default_factory=list, max_length=32)
    chain_kind: str
    risk_markers: list[str] = Field(default_factory=list)
    guard_markers: list[str] = Field(default_factory=list)
    locations: list[dict[str, Any]] = Field(default_factory=list, max_length=64)


def responses_output_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline and normalize Pydantic definitions for provider tool schemas.

    DeepSeek's Responses endpoint currently accepts ``additionalProperties`` only
    as a boolean and requires every declared object property to appear in
    ``required``. Pydantic emits a nested schema for typed dictionaries and omits
    defaulted fields from ``required``. Keep their wire object shape open, require
    the model to spell out every field, then retain stricter semantic checks in
    ``AgentInvestigationResult.model_validate`` after the turn.
    """
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

        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"$defs", "$schema"}:
                continue
            if key == "additionalProperties" and isinstance(item, dict):
                normalized[key] = True
                continue
            normalized[key] = inline(item, stack)
        properties = normalized.get("properties")
        if isinstance(properties, dict):
            normalized["required"] = list(properties)
        return normalized

    result = inline(schema)
    if not isinstance(result, dict):
        raise TypeError("root JSON Schema must be an object")
    return result


def _agent_result_wire_schema() -> dict[str, Any]:
    schema = responses_output_schema(AgentInvestigationResult.model_json_schema())
    requested_test = schema["properties"]["requested_tests"]["items"]
    requested_test["properties"]["extras"] = {
        "type": "array",
        "maxItems": 16,
        "items": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "pattern": r"^[A-Za-z0-9_.:-]+$",
                },
                "value_type": {
                    "type": "string",
                    "enum": ["string", "integer", "boolean"],
                },
                "string_value": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                "integer_value": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
                "boolean_value": {"anyOf": [{"type": "boolean"}, {"type": "null"}]},
            },
            "required": [
                "key",
                "value_type",
                "string_value",
                "integer_value",
                "boolean_value",
            ],
        },
    }
    return schema


AGENT_RESULT_JSON_SCHEMA = _agent_result_wire_schema()
ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA = responses_output_schema(
    AdaptiveVerificationResult.model_json_schema()
)
