from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    def fingerprint(self) -> str:
        payload = self.model_dump(mode="json", exclude_none=True)
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class AgentTimeouts(_FrozenContract):
    turn_seconds: int = Field(default=3_600, ge=30, le=24 * 60 * 60)
    no_event_seconds: int = Field(default=900, ge=30, le=3_600)
    task_seconds: int = Field(default=14_400, ge=60, le=7 * 24 * 60 * 60)

    @model_validator(mode="after")
    def validate_ordering(self) -> AgentTimeouts:
        if self.turn_seconds > self.task_seconds:
            raise ValueError("turn timeout cannot exceed the task timeout")
        if self.no_event_seconds > self.turn_seconds:
            raise ValueError("no-event timeout cannot exceed the turn timeout")
        return self


class AgentExecutionProfile(_FrozenContract):
    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(default="codex_full_lab_v1", pattern=r"^[a-z0-9_]+$")
    executor: Literal["docker"] = "docker"
    container_scope: Literal["scan", "task_strict"] = "scan"
    session_isolation: Literal["unix_uid"] = "unix_uid"
    sandbox: Literal["full_access"] = "full_access"
    approval_mode: Literal["deny_all"] = "deny_all"
    workspace_write: Literal[True] = True
    bash: Literal[True] = True
    apply_patch: Literal[True] = True
    web_search: Literal["disabled", "cached", "live"] = "live"
    shell_network: Literal["disabled", "public_egress"] = "public_egress"
    adb: Literal["disabled", "task_gateway"] = "task_gateway"
    proof_replay: Literal["disabled", "task_gateway"] = "task_gateway"
    subagents: Literal[False] = False
    mcp_allowlist: tuple[str, ...] = ()
    container_resource_class: Literal["scan_standard", "scan_large"] = "scan_standard"
    session_resource_class: Literal["agent_light", "agent_standard", "agent_build"] = (
        "agent_standard"
    )
    timeouts: AgentTimeouts = Field(default_factory=AgentTimeouts)


class ProviderProfile(_FrozenContract):
    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(default="deepseek_codex_flash_v1", pattern=r"^[a-z0-9_]+$")
    backend: Literal["codex"] = "codex"
    provider: Literal["deepseek"] = "deepseek"
    model: Literal["deepseek-v4-flash"] = "deepseek-v4-flash"
    wire_api: Literal["responses"] = "responses"
    reasoning_effort: Literal["low", "high", "max"] = "high"
    base_url: str = "https://api.deepseek.com/"
    model_catalog_path: Path
    model_catalog_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    minimum_sdk_version: str = Field(default="0.144.0", pattern=r"^\d+\.\d+\.\d+$")
    credential_mode: Literal["direct_env"] = "direct_env"
    credential_env: Literal["DEEPSEEK_API_KEY"] = "DEEPSEEK_API_KEY"

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("DeepSeek base URL must be an absolute HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("DeepSeek base URL cannot contain credentials, query, or fragment")
        return value.rstrip("/") + "/"

    @model_validator(mode="after")
    def validate_catalog_hash(self) -> ProviderProfile:
        if self.model_catalog_sha256 is None or not self.model_catalog_path.is_file():
            return self
        actual = hashlib.sha256(self.model_catalog_path.read_bytes()).hexdigest()
        if actual != self.model_catalog_sha256:
            raise ValueError("model catalog hash does not match the configured file")
        return self


PHASE_NAMES = frozenset(
    {
        "initial_exploration",
        "static_only",
        "test_planning",
        "exploration_round",
        "adversarial_review",
        "rescue_review",
        "rescue_exploration",
        "adaptive_verification",
        "final_evaluation",
        "recovery_evaluation",
    }
)


class PhaseRoute(_FrozenContract):
    schema_version: Literal["1.0"] = "1.0"
    routes: dict[str, str]

    @field_validator("routes")
    @classmethod
    def validate_routes(cls, routes: dict[str, str]) -> dict[str, str]:
        unknown = set(routes) - PHASE_NAMES
        missing = PHASE_NAMES - set(routes)
        if unknown:
            raise ValueError(f"unknown agent phases: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"missing agent phases: {', '.join(sorted(missing))}")
        for phase, target in routes.items():
            if not target.startswith("codex:") or target.count(":") != 1:
                raise ValueError(f"phase {phase} must route to codex:<provider-profile-id>")
        return routes

    def provider_profile_id(self, phase: str) -> str:
        try:
            return self.routes[phase].split(":", 1)[1]
        except KeyError as exc:
            raise ValueError(f"agent phase is not routed: {phase}") from exc


class WorkspaceMount(_FrozenContract):
    logical_name: str = Field(pattern=r"^[a-z0-9_]+$")
    container_path: str
    access: Literal["ro", "rw"]
    source_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("container_path")
    @classmethod
    def validate_container_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("workspace container paths must be absolute and normalized")
        return value


class WorkspaceManifest(_FrozenContract):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    workspace_key: str
    uid: int = Field(ge=10_000, le=60_000)
    gid: int = Field(ge=10_000, le=60_000)
    mounts: tuple[WorkspaceMount, ...]

    @model_validator(mode="after")
    def validate_unique_mounts(self) -> WorkspaceManifest:
        logical_names = [mount.logical_name for mount in self.mounts]
        paths = [mount.container_path for mount in self.mounts]
        if len(logical_names) != len(set(logical_names)) or len(paths) != len(set(paths)):
            raise ValueError("workspace mounts must have unique names and container paths")
        return self


class FrozenAgentConfiguration(_FrozenContract):
    schema_version: Literal["1.0"] = "1.0"
    execution: AgentExecutionProfile
    provider: ProviderProfile
    phase_route: PhaseRoute

    @model_validator(mode="after")
    def validate_route_profile(self) -> FrozenAgentConfiguration:
        expected = f"codex:{self.provider.id}"
        invalid = {
            phase: target
            for phase, target in self.phase_route.routes.items()
            if target != expected
        }
        if invalid:
            raise ValueError("all active phases must use the frozen provider profile")
        return self


def file_sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def default_phase_route(provider_profile_id: str) -> PhaseRoute:
    target = f"codex:{provider_profile_id}"
    return PhaseRoute(routes={phase: target for phase in sorted(PHASE_NAMES)})


def frozen_agent_configuration(settings: Any) -> FrozenAgentConfiguration:
    catalog_source = Path(settings.codex_model_catalog).resolve()
    execution = AgentExecutionProfile(
        container_scope=settings.codex_container_scope,
        web_search=settings.codex_web_search,
        shell_network=settings.codex_shell_network,
        timeouts=AgentTimeouts(
            turn_seconds=settings.codex_turn_timeout_seconds,
            no_event_seconds=settings.codex_no_event_timeout_seconds,
            task_seconds=settings.task_timeout_seconds,
        ),
    )
    provider = ProviderProfile(
        provider=settings.codex_provider,
        model=settings.codex_model,
        reasoning_effort=settings.codex_reasoning_effort,
        base_url=settings.deepseek_base_url,
        model_catalog_path=Path("/opt/apk-scanner/config/deepseek-models.json"),
        model_catalog_sha256=file_sha256(catalog_source),
    )
    return FrozenAgentConfiguration(
        execution=execution,
        provider=provider,
        phase_route=default_phase_route(provider.id),
    )
