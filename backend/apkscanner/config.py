from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .permissions import ensure_private_directory


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    database_url: str
    max_upload_bytes: int = 512 * 1024 * 1024
    max_zip_entries: int = 100_000
    max_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: int = 200
    tool_timeout_seconds: int = 600
    preliminary_after_seconds: int = 4 * 60 * 60
    scan_deadline_seconds: int = 24 * 60 * 60
    task_timeout_seconds: int = 4 * 60 * 60
    task_max_attempts: int = 2
    adaptive_verifier_enabled: bool = True
    adaptive_verifier_min_severity: str = "info"
    adaptive_verifier_timeout_seconds: int = 3_600
    adaptive_verifier_prompt_max_chars: int = 400_000
    adaptive_verifier_resume_attempts: int = 1
    adaptive_verifier_copy_host_ssh: bool = True
    adaptive_verifier_ssh_source: Path | None = None
    agent_permission_profile: str = "personal_lab"
    investigator_backend: str = "codex"
    codex_enabled: bool = False
    codex_provider: str = "deepseek"
    codex_model: str = "deepseek-v4-flash"
    codex_reasoning_effort: str = "high"
    codex_bin: str | None = None
    codex_isolation: str = "docker"
    codex_allow_host: bool = False
    codex_container_scope: str = "scan"
    codex_docker_image: str = "apk-scanner-codex-worker:0.2.0"
    codex_model_catalog: Path = Path("config/deepseek-models.json")
    codex_web_search: str = "live"
    codex_shell_network: str = "public_egress"
    codex_max_containers: int = 2
    codex_max_sessions: int = 8
    codex_max_sessions_per_scan: int = 6
    agent_analysis_slots: int = 4
    poc_build_slots: int = 2
    agent_initial_phase_seconds: int = 15 * 60
    agent_critic_phase_seconds: int = 5 * 60
    agent_rescue_phase_seconds: int = 8 * 60
    agent_final_phase_seconds: int = 3 * 60
    agent_no_progress_limit: int = 3
    rescue_audit_sample_rate: float = 0.15
    codex_uid_min: int = 21_000
    codex_uid_max: int = 21_999
    codex_cpu_limit: float = 6.0
    codex_memory_limit: str = "12g"
    codex_pids_limit: int = 768
    codex_tmpfs_size: str = "1g"
    codex_turn_timeout_seconds: int = 3_600
    codex_no_event_timeout_seconds: int = 900
    ida_mcp_enabled: bool = False
    ida_mcp_url: str = "http://apkscanner-host:8745/mcp"
    ida_mcp_tool_timeout_seconds: int = 1_800
    deepseek_base_url: str = "https://api.deepseek.com/"
    host_adb_executable: str = "adb"
    adb_serial: str | None = None
    adb_serials: tuple[str, ...] = ()
    android_sdk_root: Path | None = None
    android_build_tools_version: str | None = None
    poc_enabled: bool = True
    poc_build_timeout_seconds: int = 180
    poc_max_source_bytes: int = 512 * 1024
    poc_max_apk_bytes: int = 128 * 1024 * 1024
    device_android_version: str = "16"
    device_android_api: int = 36
    poc_compile_api: int | None = None
    poc_min_api: int = 21
    poc_target_api: int | None = None
    proof_replay_base_url: str = "http://127.0.0.1:8000"
    validation_profile: str = "development"
    device_min_api: int = 26
    device_max_api: int = 99
    allow_legacy_device_smoke: bool = True
    device_install_policy: str = "install_or_reuse"
    device_reset_policy: str = "never"
    frontend_dist: Path | None = None

    @classmethod
    def from_env(cls) -> Settings:
        data_dir = Path(os.getenv("APKSCANNER_DATA_DIR", ".data")).resolve()
        database_url = os.getenv(
            "APKSCANNER_DATABASE_URL", f"sqlite:///{data_dir / 'apkscanner.db'}"
        )
        frontend = os.getenv("APKSCANNER_FRONTEND_DIST")
        configured_serials = tuple(
            dict.fromkeys(
                serial.strip()
                for serial in os.getenv("APKSCANNER_ADB_SERIALS", "").split(",")
                if serial.strip()
            )
        )
        legacy_serial = (os.getenv("APKSCANNER_ADB_SERIAL") or "").strip() or None
        if not configured_serials and legacy_serial:
            configured_serials = (legacy_serial,)
        configured_verifier_ssh = os.getenv("APKSCANNER_ADAPTIVE_VERIFIER_SSH_SOURCE")
        validation_profile = (
            os.getenv("APKSCANNER_VALIDATION_PROFILE", "development").strip().lower()
        )
        if configured_verifier_ssh is None:
            verifier_ssh_source: Path | None = (Path.home() / ".ssh").resolve()
        elif configured_verifier_ssh.strip():
            verifier_ssh_source = Path(configured_verifier_ssh.strip()).expanduser().resolve()
        else:
            verifier_ssh_source = None
        configured_host_adb = os.getenv("APKSCANNER_HOST_ADB")
        if configured_host_adb is None:
            host_adb_executable = "adb"
        else:
            host_adb_path = Path(configured_host_adb.strip()).expanduser()
            if not configured_host_adb.strip() or not host_adb_path.is_absolute():
                raise ValueError("APKSCANNER_HOST_ADB must be an absolute executable path")
            host_adb_executable = str(host_adb_path)
        settings = cls(
            data_dir=data_dir,
            database_url=database_url,
            max_upload_bytes=int(os.getenv("APKSCANNER_MAX_UPLOAD_BYTES", 512 * 1024 * 1024)),
            tool_timeout_seconds=int(os.getenv("APKSCANNER_TOOL_TIMEOUT", 600)),
            preliminary_after_seconds=int(os.getenv("APKSCANNER_PRELIMINARY_AFTER", 14_400)),
            scan_deadline_seconds=int(os.getenv("APKSCANNER_SCAN_DEADLINE", 86_400)),
            task_timeout_seconds=int(os.getenv("APKSCANNER_TASK_TIMEOUT", 14_400)),
            task_max_attempts=int(os.getenv("APKSCANNER_TASK_MAX_ATTEMPTS", 2)),
            adaptive_verifier_enabled=_env_bool("APKSCANNER_ADAPTIVE_VERIFIER_ENABLED", True),
            adaptive_verifier_min_severity=os.getenv(
                "APKSCANNER_ADAPTIVE_VERIFIER_MIN_SEVERITY", "info"
            ).lower(),
            adaptive_verifier_timeout_seconds=max(
                60,
                min(
                    24 * 60 * 60,
                    int(os.getenv("APKSCANNER_ADAPTIVE_VERIFIER_TIMEOUT", 3_600)),
                ),
            ),
            adaptive_verifier_prompt_max_chars=max(
                100_000,
                min(
                    900_000,
                    int(os.getenv("APKSCANNER_ADAPTIVE_VERIFIER_PROMPT_MAX_CHARS", 400_000)),
                ),
            ),
            adaptive_verifier_resume_attempts=max(
                0,
                min(
                    3,
                    int(os.getenv("APKSCANNER_ADAPTIVE_VERIFIER_RESUME_ATTEMPTS", 1)),
                ),
            ),
            adaptive_verifier_copy_host_ssh=_env_bool(
                "APKSCANNER_ADAPTIVE_VERIFIER_COPY_HOST_SSH", True
            ),
            adaptive_verifier_ssh_source=verifier_ssh_source,
            agent_permission_profile=os.getenv(
                "APKSCANNER_AGENT_PERMISSION_PROFILE", "personal_lab"
            ).lower(),
            investigator_backend=os.getenv("APKSCANNER_INVESTIGATOR_BACKEND", "codex").lower(),
            codex_enabled=_env_bool("APKSCANNER_CODEX_ENABLED"),
            codex_provider=os.getenv("APKSCANNER_CODEX_PROVIDER", "deepseek").lower(),
            codex_model=os.getenv("APKSCANNER_CODEX_MODEL", "deepseek-v4-flash"),
            codex_reasoning_effort=os.getenv("APKSCANNER_CODEX_REASONING_EFFORT", "high").lower(),
            codex_bin=os.getenv("APKSCANNER_CODEX_BIN"),
            codex_isolation=os.getenv("APKSCANNER_CODEX_ISOLATION", "docker").lower(),
            codex_allow_host=_env_bool("APKSCANNER_ALLOW_HOST_CODEX"),
            codex_container_scope=os.getenv("APKSCANNER_CODEX_CONTAINER_SCOPE", "scan").lower(),
            codex_docker_image=os.getenv(
                "APKSCANNER_CODEX_DOCKER_IMAGE", "apk-scanner-codex-worker:0.2.0"
            ),
            codex_model_catalog=Path(
                os.getenv("APKSCANNER_CODEX_MODEL_CATALOG", "config/deepseek-models.json")
            ).resolve(),
            codex_web_search=os.getenv("APKSCANNER_CODEX_WEB_SEARCH", "live").lower(),
            codex_shell_network=os.getenv(
                "APKSCANNER_CODEX_SHELL_NETWORK", "public_egress"
            ).lower(),
            codex_max_containers=max(1, int(os.getenv("APKSCANNER_CODEX_MAX_CONTAINERS", 2))),
            codex_max_sessions=max(1, int(os.getenv("APKSCANNER_CODEX_MAX_SESSIONS", 8))),
            codex_max_sessions_per_scan=max(
                1, int(os.getenv("APKSCANNER_CODEX_MAX_SESSIONS_PER_SCAN", 6))
            ),
            agent_analysis_slots=max(1, int(os.getenv("APKSCANNER_AGENT_ANALYSIS_SLOTS", 4))),
            poc_build_slots=max(1, int(os.getenv("APKSCANNER_POC_BUILD_SLOTS", 2))),
            agent_initial_phase_seconds=max(
                60, int(os.getenv("APKSCANNER_AGENT_INITIAL_PHASE_SECONDS", 900))
            ),
            agent_critic_phase_seconds=max(
                60, int(os.getenv("APKSCANNER_AGENT_CRITIC_PHASE_SECONDS", 300))
            ),
            agent_rescue_phase_seconds=max(
                60, int(os.getenv("APKSCANNER_AGENT_RESCUE_PHASE_SECONDS", 480))
            ),
            agent_final_phase_seconds=max(
                60, int(os.getenv("APKSCANNER_AGENT_FINAL_PHASE_SECONDS", 180))
            ),
            agent_no_progress_limit=max(1, int(os.getenv("APKSCANNER_AGENT_NO_PROGRESS_LIMIT", 3))),
            rescue_audit_sample_rate=max(
                0.0,
                min(
                    1.0,
                    float(os.getenv("APKSCANNER_RESCUE_AUDIT_SAMPLE_RATE", 0.15)),
                ),
            ),
            codex_uid_min=int(os.getenv("APKSCANNER_CODEX_UID_MIN", 21_000)),
            codex_uid_max=int(os.getenv("APKSCANNER_CODEX_UID_MAX", 21_999)),
            codex_cpu_limit=float(os.getenv("APKSCANNER_CODEX_CPU_LIMIT", 6)),
            codex_memory_limit=os.getenv("APKSCANNER_CODEX_MEMORY_LIMIT", "12g"),
            codex_pids_limit=max(64, int(os.getenv("APKSCANNER_CODEX_PIDS_LIMIT", 768))),
            codex_tmpfs_size=os.getenv("APKSCANNER_CODEX_TMPFS_SIZE", "1g"),
            codex_turn_timeout_seconds=max(
                30, int(os.getenv("APKSCANNER_CODEX_TURN_TIMEOUT", 3_600))
            ),
            codex_no_event_timeout_seconds=max(
                30, int(os.getenv("APKSCANNER_CODEX_NO_EVENT_TIMEOUT", 900))
            ),
            ida_mcp_enabled=_env_bool("APKSCANNER_IDA_MCP_ENABLED"),
            ida_mcp_url=os.getenv(
                "APKSCANNER_IDA_MCP_URL", "http://apkscanner-host:8745/mcp"
            ).strip(),
            ida_mcp_tool_timeout_seconds=max(
                60,
                min(
                    4 * 60 * 60,
                    int(os.getenv("APKSCANNER_IDA_MCP_TOOL_TIMEOUT", 1_800)),
                ),
            ),
            deepseek_base_url=os.getenv(
                "APKSCANNER_DEEPSEEK_BASE_URL", "https://api.deepseek.com/"
            ),
            host_adb_executable=host_adb_executable,
            adb_serial=configured_serials[0] if configured_serials else legacy_serial,
            adb_serials=configured_serials,
            android_sdk_root=(
                Path(
                    os.environ.get("APKSCANNER_ANDROID_SDK_ROOT")
                    or os.environ.get("ANDROID_SDK_ROOT")
                    or os.environ["ANDROID_HOME"]
                ).resolve()
                if (
                    os.getenv("APKSCANNER_ANDROID_SDK_ROOT")
                    or os.getenv("ANDROID_SDK_ROOT")
                    or os.getenv("ANDROID_HOME")
                )
                else None
            ),
            android_build_tools_version=(
                os.getenv("APKSCANNER_ANDROID_BUILD_TOOLS_VERSION") or None
            ),
            poc_enabled=_env_bool("APKSCANNER_POC_ENABLED", True),
            poc_build_timeout_seconds=max(
                30, min(600, int(os.getenv("APKSCANNER_POC_BUILD_TIMEOUT", 180)))
            ),
            poc_max_source_bytes=max(
                64 * 1024,
                min(
                    16 * 1024 * 1024,
                    int(os.getenv("APKSCANNER_POC_MAX_SOURCE_BYTES", 512 * 1024)),
                ),
            ),
            poc_max_apk_bytes=max(
                1024 * 1024,
                min(
                    512 * 1024 * 1024,
                    int(os.getenv("APKSCANNER_POC_MAX_APK_BYTES", 128 * 1024 * 1024)),
                ),
            ),
            device_android_version=os.getenv("APKSCANNER_ANDROID_VERSION", "16"),
            device_android_api=int(os.getenv("APKSCANNER_ANDROID_API", 36)),
            poc_compile_api=(
                int(os.environ["APKSCANNER_POC_COMPILE_API"])
                if os.getenv("APKSCANNER_POC_COMPILE_API")
                else None
            ),
            poc_min_api=max(1, int(os.getenv("APKSCANNER_POC_MIN_API", 21))),
            poc_target_api=(
                int(os.environ["APKSCANNER_POC_TARGET_API"])
                if os.getenv("APKSCANNER_POC_TARGET_API")
                else None
            ),
            proof_replay_base_url=os.getenv(
                "APKSCANNER_PROOF_REPLAY_BASE_URL",
                "http://127.0.0.1:8000",
            ).rstrip("/"),
            validation_profile=validation_profile,
            device_min_api=max(
                1,
                int(
                    os.getenv(
                        "APKSCANNER_DEVICE_MIN_API",
                        "36" if validation_profile == "android16_release" else "26",
                    )
                ),
            ),
            device_max_api=max(1, int(os.getenv("APKSCANNER_DEVICE_MAX_API", 99))),
            allow_legacy_device_smoke=_env_bool(
                "APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE",
                validation_profile == "development",
            ),
            device_install_policy=os.getenv(
                "APKSCANNER_DEVICE_INSTALL_POLICY", "install_or_reuse"
            ).lower(),
            device_reset_policy=os.getenv("APKSCANNER_DEVICE_RESET_POLICY", "never").lower(),
            frontend_dist=Path(frontend).resolve() if frontend else None,
        )
        settings.validate_codex_configuration()
        return settings

    def validate_codex_configuration(self) -> None:
        from .agent_execution import frozen_agent_configuration

        if self.device_reset_policy not in {"never", "per_round", "per_test"}:
            raise ValueError("APKSCANNER_DEVICE_RESET_POLICY must be never, per_round, or per_test")
        if self.device_android_api < 36:
            raise ValueError("APKScanner PoC target requires Android API 36 or newer")
        if self.validation_profile not in {"development", "android16_release"}:
            raise ValueError(
                "APKSCANNER_VALIDATION_PROFILE must be development or android16_release"
            )
        if self.validation_profile == "android16_release" and self.device_min_api < 36:
            raise ValueError("android16_release requires APKSCANNER_DEVICE_MIN_API=36 or newer")
        if (
            self.validation_profile == "development"
            and self.device_min_api < 36
            and not self.allow_legacy_device_smoke
        ):
            raise ValueError(
                "development devices below API 36 require APKSCANNER_ALLOW_LEGACY_DEVICE_SMOKE=true"
            )
        if self.poc_compile_api is not None and self.poc_compile_api < 36:
            raise ValueError("APKSCANNER_POC_COMPILE_API must be at least 36")
        if self.poc_target_api is not None and self.poc_target_api < 36:
            raise ValueError("APKSCANNER_POC_TARGET_API must be at least 36")

        if self.investigator_backend not in {"codex", "none"}:
            raise ValueError("APKSCANNER_INVESTIGATOR_BACKEND must be codex or none")
        if self.adaptive_verifier_min_severity not in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }:
            raise ValueError("APKSCANNER_ADAPTIVE_VERIFIER_MIN_SEVERITY must be a valid severity")
        if self.codex_isolation not in {"docker", "host"}:
            raise ValueError("APKSCANNER_CODEX_ISOLATION must be docker or host")
        if self.codex_isolation == "host" and not self.codex_allow_host:
            raise ValueError(
                "host Codex is disabled; set APKSCANNER_ALLOW_HOST_CODEX=true only for diagnostics"
            )
        if self.codex_container_scope != "scan":
            raise ValueError(
                "APKSCANNER_CODEX_CONTAINER_SCOPE currently supports only scan; "
                "task_strict is reserved for a future executor"
            )
        if self.codex_uid_min < 10_000 or self.codex_uid_max > 60_000:
            raise ValueError("Codex UID pool must stay within 10000..60000")
        if self.codex_uid_min > self.codex_uid_max:
            raise ValueError("APKSCANNER_CODEX_UID_MIN cannot exceed UID_MAX")
        if self.codex_max_sessions_per_scan > self.codex_max_sessions:
            raise ValueError("per-scan Codex session limit cannot exceed the global limit")
        if self.codex_no_event_timeout_seconds > self.codex_turn_timeout_seconds:
            raise ValueError("Codex no-event timeout cannot exceed the turn timeout")
        if self.codex_turn_timeout_seconds > self.task_timeout_seconds:
            raise ValueError("Codex turn timeout cannot exceed the task timeout")
        if self.ida_mcp_enabled and not self.ida_mcp_url.startswith(("http://", "https://")):
            raise ValueError("APKSCANNER_IDA_MCP_URL must use http:// or https://")
        frozen_agent_configuration(self)

    def frozen_agent_configuration(self):  # noqa: ANN202
        from .agent_execution import frozen_agent_configuration

        return frozen_agent_configuration(self)

    def investigator_enabled(self, backend: str) -> bool:
        return backend == "codex" and self.codex_enabled

    @property
    def configured_adb_serials(self) -> tuple[str, ...]:
        if self.adb_serials:
            return tuple(dict.fromkeys(self.adb_serials))
        return (self.adb_serial,) if self.adb_serial else ()

    def verdict_metadata(self, api_level: int | None) -> dict[str, object]:
        """Return the runtime verdict scope without conflating local and release proof."""

        android16_eligible = api_level is not None and api_level >= 36
        development_legacy = bool(
            api_level is not None
            and api_level < 36
            and self.validation_profile == "development"
            and self.allow_legacy_device_smoke
        )
        dynamic_eligible = android16_eligible or development_legacy
        release_gate_eligible = bool(
            android16_eligible and self.validation_profile == "android16_release"
        )
        return {
            "validation_profile": self.validation_profile,
            "android16_verdict_eligible": android16_eligible,
            "dynamic_verdict_eligible": dynamic_eligible,
            "release_gate_eligible": release_gate_eligible,
            "compatibility_smoke_only": bool(api_level is not None and not dynamic_eligible),
            "verdict_scope": (
                "android16_release"
                if release_gate_eligible
                else "development_android16"
                if android16_eligible
                else "development_legacy"
                if development_legacy
                else "non_verdict_smoke"
            ),
        }

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.data_dir / "artifacts",
            self.data_dir / "static-cache",
            self.data_dir / "workspaces",
            self.data_dir / "evidence",
            self.data_dir / "reports",
        ):
            ensure_private_directory(path)
