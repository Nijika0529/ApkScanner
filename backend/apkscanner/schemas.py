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
    compatibility_smoke_only: bool
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
    prebuilt_apk_path: str | None = Field(
        default=None,
        pattern=r"^poc/[A-Za-z0-9][A-Za-z0-9._/-]{0,220}\.apk$",
        max_length=256,
    )


class AgentBinderScriptStep(BaseModel):
    """One bounded primitive Parcel write/read performed by the platform Probe."""

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
        if self.kind != "binder_reply" and (
            self.match_mode != "exact" or self.reply_index != 0
        ):
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
            "target_uid_log_contains": {"none", "privileged_action"},
            "target_file_sha256": {"unauthorized_state_change"},
            "process_crash": {"none", "denial_of_service"},
            "binder_reply": {"none", "unauthorized_data_access"},
        }
        if self.impact not in allowed_impacts[self.kind]:
            supported = ", ".join(sorted(allowed_impacts[self.kind]))
            raise ValueError(f"{self.kind} Oracle supports only these impacts: {supported}")
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

    @model_validator(mode="after")
    def validate_action(self) -> Self:
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
                raise ValueError(
                    f"{self.operation} requires binder_transaction_code"
                )
            if self.operation == "binder_transact" and self.binder_reply_type is None:
                raise ValueError("binder_transact requires binder_reply_type")
            if self.operation == "binder_script" and not self.binder_script:
                raise ValueError("binder_script requires at least one script step")
            if self.operation == "binder_script" and self.binder_script:
                _validate_binder_script(self.binder_script)
            if self.operation == "binder_transact" and self.binder_script is not None:
                raise ValueError("binder_script steps require operation=binder_script")
            if self.poc is not None:
                raise ValueError(f"{self.operation} is a platform Probe action and cannot include poc")
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
        """Keep malformed optional actions as auditable feedback for the next turn."""

        if not isinstance(value, dict):
            return handler(value)
        requested_tests = value.get("requested_tests")
        if not isinstance(requested_tests, list):
            return handler(value)
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for index, request in enumerate(requested_tests):
            normalized_request = (
                _normalize_wire_extras(request) if isinstance(request, dict) else request
            )
            if isinstance(normalized_request, dict):
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
        normalized = dict(value)
        normalized["requested_tests"] = accepted
        if not rejected:
            return handler(normalized)
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
        return result

    @property
    def rejected_requested_tests(self) -> list[dict[str, Any]]:
        """Malformed model actions excluded from execution but retained for audit."""

        return [dict(item) for item in self._rejected_requested_tests]

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


def _inline_local_json_schema_refs(schema: dict[str, Any]) -> dict[str, Any]:
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
    schema = _inline_local_json_schema_refs(AgentInvestigationResult.model_json_schema())
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
ADAPTIVE_VERIFIER_RESULT_JSON_SCHEMA = _inline_local_json_schema_refs(
    AdaptiveVerificationResult.model_json_schema()
)
