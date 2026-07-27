from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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
    task_timeout_seconds: int = 20 * 60
    task_max_attempts: int = 2
    agent_max_rounds: int = 3
    agent_tests_per_round: int = 100
    investigator_backend: str = "codex"
    codex_enabled: bool = False
    codex_worker_model: str = "gpt-5.6-terra"
    codex_bin: str | None = None
    codex_isolation: str = "docker"
    codex_docker_image: str = "apk-scanner-worker:0.1.0"
    codex_auth_file: Path | None = None
    opencode_enabled: bool = False
    opencode_model: str = "deepseek-v4-pro"
    opencode_node_bin: str | None = None
    opencode_worker_dir: Path | None = None
    opencode_isolation: str = "docker"
    opencode_docker_image: str = "apk-scanner-opencode-worker:0.1.0"
    deepseek_base_url: str | None = None
    adb_serial: str | None = None
    probe_apk_path: Path | None = None
    device_android_version: str = "16"
    device_android_api: int = 36
    auth_flow_path: Path | None = None
    frida_device: str | None = None
    frida_host: str | None = None
    frida_capture_seconds: int = 20
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
        return cls(
            data_dir=data_dir,
            database_url=database_url,
            max_upload_bytes=int(os.getenv("APKSCANNER_MAX_UPLOAD_BYTES", 512 * 1024 * 1024)),
            tool_timeout_seconds=int(os.getenv("APKSCANNER_TOOL_TIMEOUT", 600)),
            preliminary_after_seconds=int(os.getenv("APKSCANNER_PRELIMINARY_AFTER", 14_400)),
            scan_deadline_seconds=int(os.getenv("APKSCANNER_SCAN_DEADLINE", 86_400)),
            task_timeout_seconds=int(os.getenv("APKSCANNER_TASK_TIMEOUT", 1_200)),
            task_max_attempts=int(os.getenv("APKSCANNER_TASK_MAX_ATTEMPTS", 2)),
            agent_max_rounds=max(
                1, min(5, int(os.getenv("APKSCANNER_AGENT_MAX_ROUNDS", 3)))
            ),
            agent_tests_per_round=max(
                1, min(100, int(os.getenv("APKSCANNER_AGENT_TESTS_PER_ROUND", 100)))
            ),
            investigator_backend=os.getenv(
                "APKSCANNER_INVESTIGATOR_BACKEND", "codex"
            ).lower(),
            codex_enabled=_env_bool("APKSCANNER_CODEX_ENABLED"),
            codex_worker_model=os.getenv("APKSCANNER_CODEX_WORKER_MODEL", "gpt-5.6-terra"),
            codex_bin=os.getenv("APKSCANNER_CODEX_BIN"),
            codex_isolation=os.getenv("APKSCANNER_CODEX_ISOLATION", "docker").lower(),
            codex_docker_image=os.getenv(
                "APKSCANNER_CODEX_DOCKER_IMAGE", "apk-scanner-worker:0.1.0"
            ),
            codex_auth_file=(
                Path(os.environ["APKSCANNER_CODEX_AUTH_FILE"]).resolve()
                if os.getenv("APKSCANNER_CODEX_AUTH_FILE")
                else None
            ),
            opencode_enabled=_env_bool("APKSCANNER_OPENCODE_ENABLED"),
            opencode_model=os.getenv(
                "APKSCANNER_OPENCODE_MODEL", "deepseek-v4-pro"
            ),
            opencode_node_bin=os.getenv("APKSCANNER_OPENCODE_NODE_BIN"),
            opencode_worker_dir=(
                Path(os.environ["APKSCANNER_OPENCODE_WORKER_DIR"]).resolve()
                if os.getenv("APKSCANNER_OPENCODE_WORKER_DIR")
                else None
            ),
            opencode_isolation=os.getenv(
                "APKSCANNER_OPENCODE_ISOLATION", "docker"
            ).lower(),
            opencode_docker_image=os.getenv(
                "APKSCANNER_OPENCODE_DOCKER_IMAGE",
                "apk-scanner-opencode-worker:0.1.0",
            ),
            deepseek_base_url=os.getenv("APKSCANNER_DEEPSEEK_BASE_URL"),
            adb_serial=os.getenv("APKSCANNER_ADB_SERIAL"),
            probe_apk_path=(
                Path(os.environ["APKSCANNER_PROBE_APK"]).resolve()
                if os.getenv("APKSCANNER_PROBE_APK")
                else None
            ),
            device_android_version=os.getenv("APKSCANNER_ANDROID_VERSION", "16"),
            device_android_api=int(os.getenv("APKSCANNER_ANDROID_API", 36)),
            auth_flow_path=(
                Path(os.environ["APKSCANNER_AUTH_FLOW"]).resolve()
                if os.getenv("APKSCANNER_AUTH_FLOW")
                else None
            ),
            frida_device=os.getenv("APKSCANNER_FRIDA_DEVICE"),
            frida_host=os.getenv("APKSCANNER_FRIDA_HOST"),
            frida_capture_seconds=int(os.getenv("APKSCANNER_FRIDA_CAPTURE_SECONDS", 20)),
            mobsf_url=os.getenv("APKSCANNER_MOBSF_URL"),
            mobsf_api_key=os.getenv("APKSCANNER_MOBSF_API_KEY"),
            mobsf_timeout_seconds=int(os.getenv("APKSCANNER_MOBSF_TIMEOUT", 900)),
            frontend_dist=Path(frontend).resolve() if frontend else None,
        )

    def investigator_enabled(self, backend: str) -> bool:
        if backend == "codex":
            return self.codex_enabled
        if backend == "opencode":
            return self.opencode_enabled
        return False

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.data_dir / "artifacts",
            self.data_dir / "workspaces",
            self.data_dir / "evidence",
            self.data_dir / "reports",
        ):
            path.mkdir(parents=True, exist_ok=True)
