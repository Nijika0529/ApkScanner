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
    agent_max_rounds: int = 3
    agent_tests_per_round: int = 8
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
    codex_max_sessions: int = 6
    codex_max_sessions_per_scan: int = 3
    codex_uid_min: int = 21_000
    codex_uid_max: int = 21_999
    codex_cpu_limit: float = 6.0
    codex_memory_limit: str = "12g"
    codex_pids_limit: int = 768
    codex_tmpfs_size: str = "1g"
    codex_turn_timeout_seconds: int = 3_600
    codex_no_event_timeout_seconds: int = 900
    deepseek_base_url: str = "https://api.deepseek.com/"
    adb_serial: str | None = None
    adb_serials: tuple[str, ...] = ()
    probe_apk_path: Path | None = None
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
    device_min_api: int = 36
    device_max_api: int = 99
    device_install_policy: str = "install_or_reuse"
    device_reset_policy: str = "per_round"
    mobsf_url: str | None = None
    mobsf_api_key: str | None = None
    mobsf_timeout_seconds: int = 900
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
        settings = cls(
            data_dir=data_dir,
            database_url=database_url,
            max_upload_bytes=int(os.getenv("APKSCANNER_MAX_UPLOAD_BYTES", 512 * 1024 * 1024)),
            tool_timeout_seconds=int(os.getenv("APKSCANNER_TOOL_TIMEOUT", 600)),
            preliminary_after_seconds=int(os.getenv("APKSCANNER_PRELIMINARY_AFTER", 14_400)),
            scan_deadline_seconds=int(os.getenv("APKSCANNER_SCAN_DEADLINE", 86_400)),
            task_timeout_seconds=int(os.getenv("APKSCANNER_TASK_TIMEOUT", 14_400)),
            task_max_attempts=int(os.getenv("APKSCANNER_TASK_MAX_ATTEMPTS", 2)),
            agent_max_rounds=max(
                1, min(5, int(os.getenv("APKSCANNER_AGENT_MAX_ROUNDS", 3)))
            ),
            agent_tests_per_round=max(
                1, min(1_000, int(os.getenv("APKSCANNER_AGENT_TESTS_PER_ROUND", 8)))
            ),
            agent_permission_profile=os.getenv(
                "APKSCANNER_AGENT_PERMISSION_PROFILE", "personal_lab"
            ).lower(),
            investigator_backend=os.getenv(
                "APKSCANNER_INVESTIGATOR_BACKEND", "codex"
            ).lower(),
            codex_enabled=_env_bool("APKSCANNER_CODEX_ENABLED"),
            codex_provider=os.getenv("APKSCANNER_CODEX_PROVIDER", "deepseek").lower(),
            codex_model=os.getenv("APKSCANNER_CODEX_MODEL", "deepseek-v4-flash"),
            codex_reasoning_effort=os.getenv(
                "APKSCANNER_CODEX_REASONING_EFFORT", "high"
            ).lower(),
            codex_bin=os.getenv("APKSCANNER_CODEX_BIN"),
            codex_isolation=os.getenv("APKSCANNER_CODEX_ISOLATION", "docker").lower(),
            codex_allow_host=_env_bool("APKSCANNER_ALLOW_HOST_CODEX"),
            codex_container_scope=os.getenv(
                "APKSCANNER_CODEX_CONTAINER_SCOPE", "scan"
            ).lower(),
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
            codex_max_containers=max(
                1, int(os.getenv("APKSCANNER_CODEX_MAX_CONTAINERS", 2))
            ),
            codex_max_sessions=max(
                1, int(os.getenv("APKSCANNER_CODEX_MAX_SESSIONS", 6))
            ),
            codex_max_sessions_per_scan=max(
                1, int(os.getenv("APKSCANNER_CODEX_MAX_SESSIONS_PER_SCAN", 3))
            ),
            codex_uid_min=int(os.getenv("APKSCANNER_CODEX_UID_MIN", 21_000)),
            codex_uid_max=int(os.getenv("APKSCANNER_CODEX_UID_MAX", 21_999)),
            codex_cpu_limit=float(os.getenv("APKSCANNER_CODEX_CPU_LIMIT", 6)),
            codex_memory_limit=os.getenv("APKSCANNER_CODEX_MEMORY_LIMIT", "12g"),
            codex_pids_limit=max(
                64, int(os.getenv("APKSCANNER_CODEX_PIDS_LIMIT", 768))
            ),
            codex_tmpfs_size=os.getenv("APKSCANNER_CODEX_TMPFS_SIZE", "1g"),
            codex_turn_timeout_seconds=max(
                30, int(os.getenv("APKSCANNER_CODEX_TURN_TIMEOUT", 3_600))
            ),
            codex_no_event_timeout_seconds=max(
                30, int(os.getenv("APKSCANNER_CODEX_NO_EVENT_TIMEOUT", 900))
            ),
            deepseek_base_url=os.getenv(
                "APKSCANNER_DEEPSEEK_BASE_URL", "https://api.deepseek.com/"
            ),
            adb_serial=configured_serials[0] if configured_serials else legacy_serial,
            adb_serials=configured_serials,
            probe_apk_path=(
                Path(os.environ["APKSCANNER_PROBE_APK"]).resolve()
                if os.getenv("APKSCANNER_PROBE_APK")
                else None
            ),
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
            poc_min_api=max(
                1, int(os.getenv("APKSCANNER_POC_MIN_API", 21))
            ),
            poc_target_api=(
                int(os.environ["APKSCANNER_POC_TARGET_API"])
                if os.getenv("APKSCANNER_POC_TARGET_API")
                else None
            ),
            proof_replay_base_url=os.getenv(
                "APKSCANNER_PROOF_REPLAY_BASE_URL",
                "http://127.0.0.1:8000",
            ).rstrip("/"),
            device_min_api=max(1, int(os.getenv("APKSCANNER_DEVICE_MIN_API", 36))),
            device_max_api=max(1, int(os.getenv("APKSCANNER_DEVICE_MAX_API", 99))),
            device_install_policy=os.getenv(
                "APKSCANNER_DEVICE_INSTALL_POLICY", "install_or_reuse"
            ).lower(),
            device_reset_policy=os.getenv(
                "APKSCANNER_DEVICE_RESET_POLICY", "per_round"
            ).lower(),
            mobsf_url=os.getenv("APKSCANNER_MOBSF_URL"),
            mobsf_api_key=os.getenv("APKSCANNER_MOBSF_API_KEY"),
            mobsf_timeout_seconds=int(os.getenv("APKSCANNER_MOBSF_TIMEOUT", 900)),
            frontend_dist=Path(frontend).resolve() if frontend else None,
        )
        settings.validate_codex_configuration()
        return settings

    def validate_codex_configuration(self) -> None:
        from .agent_execution import frozen_agent_configuration

        if self.investigator_backend not in {"codex", "none"}:
            raise ValueError("APKSCANNER_INVESTIGATOR_BACKEND must be codex or none")
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
