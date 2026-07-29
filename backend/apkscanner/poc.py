from __future__ import annotations

import io
import json
import os
import re
import shutil
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

from .artifacts import ArtifactStore
from .config import Settings
from .schemas import AgentPocSpec
from .tools import CommandResult, ToolRunner

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
ALLOWED_SOURCE_SUFFIXES = {".java", ".xml"}


@dataclass(slots=True)
class PocBuildResult:
    ok: bool
    commands: list[tuple[str, CommandResult, dict[str, object]]] = field(
        default_factory=list
    )
    error: str | None = None
    apk_sha256: str | None = None
    apk_path: Path | None = None
    source_sha256: str | None = None
    source_path: Path | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    effective_spec: AgentPocSpec | None = None


class PocBuilder:
    """Build a source-only Android PoC without executing Agent-provided build scripts."""

    def __init__(
        self,
        settings: Settings,
        runner: ToolRunner,
        store: ArtifactStore,
    ) -> None:
        self.settings = settings
        self.runner = runner
        self.store = store
        self._keystore_lock = threading.Lock()

    def capability(self) -> dict[str, object]:
        if not self.settings.poc_enabled:
            return {"available": False, "detail": "Agent PoC building is disabled"}
        android_jar = self._android_jar()
        dex_tool = self._dex_tool()
        source_missing = [
            name
            for name, value in {
                "Android SDK platform android.jar": android_jar,
                "d8 or dx": dex_tool,
                "java compiler": shutil.which("javac"),
                "zipalign": shutil.which("zipalign") or self._build_tool("zipalign"),
                "keytool": shutil.which("keytool"),
            }.items()
            if value is None
        ]
        ingest_missing = [
            name
            for name, value in {
                "aapt2": shutil.which("aapt2") or self._build_tool("aapt2"),
                "apksigner": shutil.which("apksigner") or self._build_tool("apksigner"),
            }.items()
            if value is None
        ]
        if ingest_missing:
            return {
                "available": False,
                "detail": f"PoC APK ingestion is missing: {', '.join(ingest_missing)}",
            }
        return {
            "available": True,
            "android_api": self.settings.device_android_api,
            "source_contract": "manifest_and_java_or_prebuilt_apk",
            "source_build_available": not source_missing,
            "source_build_missing": source_missing,
            "max_source_bytes": self.settings.poc_max_source_bytes,
            "max_prebuilt_apk_bytes": self.settings.poc_max_apk_bytes,
            "max_source_files": 64,
        }

    def build(
        self,
        workspace: Path,
        spec: AgentPocSpec,
        *,
        cancel_event: threading.Event | None = None,
    ) -> PocBuildResult:
        capability = self.capability()
        if not capability.get("available"):
            return PocBuildResult(ok=False, error=str(capability.get("detail")))
        if spec.prebuilt_apk_path is not None:
            return self._ingest_prebuilt(
                workspace,
                spec,
                cancel_event=cancel_event,
            )
        if not capability.get("source_build_available"):
            return PocBuildResult(
                ok=False,
                error=(
                    "platform-managed source build is unavailable: "
                    + ", ".join(
                        str(item)
                        for item in capability.get("source_build_missing", [])
                    )
                ),
            )
        try:
            project, sources, manifest, effective_spec = self._validate_project(
                workspace,
                spec,
            )
            effective_project_path = str(project.relative_to(workspace.resolve()))
            effective_spec = effective_spec.model_copy(
                update={"project_path": effective_project_path}
            )
            source_bytes = self._source_archive(project, sources, manifest)
            source_sha256, source_path = self.store.put_bytes(
                "poc_sources", source_bytes, suffix=".zip"
            )
        except (OSError, ValueError, ElementTree.ParseError) as exc:
            return PocBuildResult(ok=False, error=f"PoC source validation failed: {exc}")

        commands: list[tuple[str, CommandResult, dict[str, object]]] = []
        build_root = self.settings.data_dir / "poc-build"
        build_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="build-", dir=build_root) as temporary:
            output = Path(temporary)
            classes = output / "classes"
            dex = output / "dex"
            classes.mkdir()
            dex.mkdir()
            unsigned_apk = output / "unsigned.apk"
            aligned_apk = output / "aligned.apk"
            signed_apk = output / "poc.apk"
            android_jar = self._android_jar()
            dex_tool = self._dex_tool()
            assert android_jar is not None and dex_tool is not None
            dex_tool_name, dex_tool_path = dex_tool

            steps = [
                (
                    "poc.build.aapt2",
                    [
                        self._required_tool("aapt2"),
                        "link",
                        "-o",
                        str(unsigned_apk),
                        "-I",
                        str(android_jar),
                        "--manifest",
                        str(manifest),
                        "--min-sdk-version",
                        str(self.settings.device_android_api),
                        "--target-sdk-version",
                        str(self.settings.device_android_api),
                        "--version-code",
                        "1",
                        "--version-name",
                        "1.0",
                    ],
                ),
                (
                    "poc.build.javac",
                    [
                        self._required_tool("javac"),
                        "-encoding",
                        "UTF-8",
                        "-source",
                        "8",
                        "-target",
                        "8",
                        "-classpath",
                        str(android_jar),
                        "-d",
                        str(classes),
                        *[str(item) for item in sources],
                    ],
                ),
            ]
            for kind, argv in steps:
                result = self.runner.run(
                    argv,
                    cwd=project,
                    timeout=self.settings.poc_build_timeout_seconds,
                    cancel_event=cancel_event,
                )
                commands.append(
                    (
                        kind,
                        result,
                        self._command_metadata(effective_spec, source_sha256),
                    )
                )
                if result.exit_code != 0:
                    return PocBuildResult(
                        ok=False,
                        commands=commands,
                        error=self._command_failure(kind, result),
                        source_sha256=source_sha256,
                        source_path=source_path,
                    )

            class_files = sorted(classes.rglob("*.class"))
            if not class_files:
                return PocBuildResult(
                    ok=False,
                    commands=commands,
                    error="PoC Java compilation produced no class files",
                    source_sha256=source_sha256,
                    source_path=source_path,
                )
            classes_dex = dex / "classes.dex"
            dex_argv = (
                [
                    str(dex_tool_path),
                    "--lib",
                    str(android_jar),
                    "--min-api",
                    str(self.settings.device_android_api),
                    "--output",
                    str(dex),
                    *[str(item) for item in class_files],
                ]
                if dex_tool_name == "d8"
                else [
                    str(dex_tool_path),
                    "--dex",
                    f"--output={classes_dex}",
                    *[str(item.relative_to(classes)) for item in class_files],
                ]
            )
            dex_result = self.runner.run(
                dex_argv,
                cwd=project if dex_tool_name == "d8" else classes,
                timeout=self.settings.poc_build_timeout_seconds,
                env=self._modern_java_environment(),
                cancel_event=cancel_event,
            )
            commands.append(
                (
                    f"poc.build.{dex_tool_name}",
                    dex_result,
                    self._command_metadata(effective_spec, source_sha256),
                )
            )
            if dex_result.exit_code != 0:
                return PocBuildResult(
                    ok=False,
                    commands=commands,
                    error=self._command_failure(
                        f"poc.build.{dex_tool_name}", dex_result
                    ),
                    source_sha256=source_sha256,
                    source_path=source_path,
                )

            if not unsigned_apk.is_file() or not classes_dex.is_file():
                return PocBuildResult(
                    ok=False,
                    commands=commands,
                    error="PoC packaging inputs are incomplete",
                    source_sha256=source_sha256,
                    source_path=source_path,
                )
            with zipfile.ZipFile(unsigned_apk, "a", compression=zipfile.ZIP_DEFLATED) as apk:
                apk.write(classes_dex, "classes.dex")

            keystore = self._ensure_keystore(cancel_event=cancel_event)
            if isinstance(keystore, CommandResult):
                commands.append(
                    (
                        "poc.build.keystore",
                        keystore,
                        self._command_metadata(effective_spec, source_sha256),
                    )
                )
                return PocBuildResult(
                    ok=False,
                    commands=commands,
                    error=self._command_failure("poc.build.keystore", keystore),
                    source_sha256=source_sha256,
                    source_path=source_path,
                )
            final_steps = [
                (
                    "poc.build.zipalign",
                    [
                        self._required_tool("zipalign"),
                        "-f",
                        "4",
                        str(unsigned_apk),
                        str(aligned_apk),
                    ],
                ),
                (
                    "poc.build.sign",
                    [
                        self._required_tool("apksigner"),
                        "sign",
                        "--ks",
                        str(keystore),
                        "--ks-key-alias",
                        "apkscanner-poc",
                        "--ks-pass",
                        "pass:android",
                        "--key-pass",
                        "pass:android",
                        "--out",
                        str(signed_apk),
                        str(aligned_apk),
                    ],
                ),
                (
                    "poc.build.verify",
                    [self._required_tool("apksigner"), "verify", "--verbose", str(signed_apk)],
                ),
            ]
            for kind, argv in final_steps:
                result = self.runner.run(
                    argv,
                    cwd=project,
                    timeout=self.settings.poc_build_timeout_seconds,
                    cancel_event=cancel_event,
                )
                commands.append(
                    (
                        kind,
                        result,
                        self._command_metadata(effective_spec, source_sha256),
                    )
                )
                if result.exit_code != 0:
                    return PocBuildResult(
                        ok=False,
                        commands=commands,
                        error=self._command_failure(kind, result),
                        source_sha256=source_sha256,
                        source_path=source_path,
                    )
            apk_sha256, apk_path = self.store.put_bytes(
                "poc_artifacts", signed_apk.read_bytes(), suffix=".apk"
            )
        return PocBuildResult(
            ok=True,
            commands=commands,
            apk_sha256=apk_sha256,
            apk_path=apk_path,
            source_sha256=source_sha256,
            source_path=source_path,
            metadata={
                **self._command_metadata(effective_spec, source_sha256),
                "apk_sha256": apk_sha256,
                "apk_path": str(apk_path),
                "source_path": str(source_path),
            },
            effective_spec=effective_spec,
        )

    def _ingest_prebuilt(
        self,
        workspace: Path,
        spec: AgentPocSpec,
        *,
        cancel_event: threading.Event | None,
    ) -> PocBuildResult:
        root = workspace.resolve()
        candidate = (root / str(spec.prebuilt_apk_path)).resolve()
        poc_root = (root / "poc").resolve()
        if (
            not candidate.is_relative_to(poc_root)
            or candidate.is_symlink()
            or not candidate.is_file()
            or candidate.suffix.lower() != ".apk"
        ):
            return PocBuildResult(
                ok=False,
                error="prebuilt_apk_path must resolve to a regular APK under poc/",
            )
        size = candidate.stat().st_size
        if size < 1 or size > self.settings.poc_max_apk_bytes:
            return PocBuildResult(
                ok=False,
                error=(
                    f"prebuilt Agent APK must contain between 1 and "
                    f"{self.settings.poc_max_apk_bytes} bytes"
                ),
            )
        metadata = {
            "poc_package": spec.package_name,
            "poc_project_path": spec.project_path,
            "poc_prebuilt_apk_path": spec.prebuilt_apk_path,
            "platform_managed_build": False,
        }
        commands: list[tuple[str, CommandResult, dict[str, object]]] = []
        checks = [
            (
                "poc.prebuilt.verify_signature",
                [self._required_tool("apksigner"), "verify", "--verbose", str(candidate)],
            ),
            (
                "poc.prebuilt.inspect_manifest",
                [self._required_tool("aapt2"), "dump", "badging", str(candidate)],
            ),
        ]
        inspection: CommandResult | None = None
        for kind, argv in checks:
            result = self.runner.run(
                argv,
                cwd=poc_root,
                timeout=self.settings.poc_build_timeout_seconds,
                cancel_event=cancel_event,
            )
            commands.append((kind, result, dict(metadata)))
            if result.exit_code != 0:
                return PocBuildResult(
                    ok=False,
                    commands=commands,
                    error=f"{kind} failed with exit {result.exit_code}",
                )
            if kind == "poc.prebuilt.inspect_manifest":
                inspection = result
        assert inspection is not None
        package_match = re.search(r"package: name='([^']+)'", inspection.stdout)
        if package_match is None or package_match.group(1) != spec.package_name:
            return PocBuildResult(
                ok=False,
                commands=commands,
                error="prebuilt Agent APK package does not match the requested package",
            )
        component = (
            f"{spec.package_name}{spec.launch_component}"
            if spec.launch_component.startswith(".")
            else spec.launch_component
        )
        launchable = {
            value
            for value in re.findall(
                r"launchable-activity: name='([^']+)'",
                inspection.stdout,
            )
        }
        if launchable and component not in launchable:
            return PocBuildResult(
                ok=False,
                commands=commands,
                error="prebuilt Agent APK launch component does not match its manifest",
            )
        apk_sha256, apk_path = self.store.put_bytes(
            "poc_artifacts",
            candidate.read_bytes(),
            suffix=".apk",
        )
        provenance = {
            "schema_version": "1.0",
            "spec": spec.model_dump(mode="json"),
            "apk_sha256": apk_sha256,
            "size": size,
        }
        source_sha256, source_path = self.store.put_bytes(
            "poc_sources",
            json.dumps(provenance, sort_keys=True, indent=2).encode(),
            suffix=".json",
        )
        return PocBuildResult(
            ok=True,
            commands=commands,
            apk_sha256=apk_sha256,
            apk_path=apk_path,
            source_sha256=source_sha256,
            source_path=source_path,
            metadata={
                **metadata,
                "apk_sha256": apk_sha256,
                "apk_path": str(apk_path),
                "source_path": str(source_path),
            },
        )

    def _validate_project(
        self,
        workspace: Path,
        spec: AgentPocSpec,
    ) -> tuple[Path, list[Path], Path, AgentPocSpec]:
        root = workspace.resolve()
        poc_root = (root / "poc").resolve()
        project = self._resolve_source_project(root, poc_root, spec)
        if (
            not project.is_relative_to(poc_root)
            or not project.is_dir()
            or project.is_symlink()
        ):
            raise ValueError("project_path must resolve to a regular directory under poc/")
        manifest = project / "AndroidManifest.xml"
        sources = sorted((project / "src").rglob("*.java"))
        if not manifest.is_file() or not sources:
            raise ValueError("PoC project requires AndroidManifest.xml and src/**/*.java")
        build_inputs = [manifest, *sources]
        if len(build_inputs) > 64:
            raise ValueError("PoC project must contain at most 64 build input files")
        total = 0
        for item in build_inputs:
            if item.is_symlink() or not item.resolve().is_relative_to(project):
                raise ValueError("PoC project contains a symbolic link or escaped path")
            if item.suffix.lower() not in ALLOWED_SOURCE_SUFFIXES:
                raise ValueError(f"unsupported PoC source file: {item.relative_to(project)}")
            total += item.stat().st_size
        if total > self.settings.poc_max_source_bytes:
            raise ValueError(
                f"PoC source exceeds {self.settings.poc_max_source_bytes} bytes"
            )
        tree = ElementTree.parse(manifest)
        root_element = tree.getroot()
        manifest_package = root_element.get("package")
        if root_element.tag != "manifest" or not manifest_package:
            raise ValueError("PoC manifest requires a package")
        effective_spec = AgentPocSpec.model_validate(
            {
                **spec.model_dump(mode="python"),
                "package_name": manifest_package,
            }
        )
        if root_element.get(f"{{{ANDROID_NAMESPACE}}}sharedUserId"):
            raise ValueError("android:sharedUserId is forbidden for Agent PoCs")
        application = root_element.find("application")
        if application is None:
            raise ValueError("PoC manifest requires an application")
        declared = {
            item.get(f"{{{ANDROID_NAMESPACE}}}name")
            for item in application.findall("activity")
        }
        component = (
            f"{effective_spec.package_name}{effective_spec.launch_component}"
            if spec.launch_component.startswith(".")
            else spec.launch_component
        )
        normalized_declared = {
            (
                f"{effective_spec.package_name}{name}"
                if name and name.startswith(".")
                else name
            )
            for name in declared
        }
        if component not in normalized_declared:
            raise ValueError("launch_component is not declared as an activity")
        return project, sources, manifest, effective_spec

    @staticmethod
    def _resolve_source_project(
        root: Path,
        poc_root: Path,
        spec: AgentPocSpec,
    ) -> Path:
        requested = (root / spec.project_path).resolve()
        if (
            requested.is_relative_to(poc_root)
            and requested.is_dir()
            and not requested.is_symlink()
        ):
            return requested
        if not poc_root.is_dir():
            return requested

        matches: list[Path] = []
        for manifest in sorted(poc_root.rglob("AndroidManifest.xml")):
            project = manifest.parent
            if (
                project.is_symlink()
                or not project.resolve().is_relative_to(poc_root)
                or not (project / "src").is_dir()
                or not any((project / "src").rglob("*.java"))
            ):
                continue
            try:
                manifest_root = ElementTree.parse(manifest).getroot()
            except (OSError, ElementTree.ParseError):
                continue
            if (
                manifest_root.tag == "manifest"
                and manifest_root.get("package") == spec.package_name
            ):
                matches.append(project.resolve())
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            relative = ", ".join(str(item.relative_to(root)) for item in matches[:5])
            raise ValueError(
                "project_path is missing and multiple PoC projects match package "
                f"{spec.package_name}: {relative}"
            )
        return requested

    @staticmethod
    def _source_archive(project: Path, sources: list[Path], manifest: Path) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in [manifest, *sources]:
                archive.writestr(
                    str(item.relative_to(project)),
                    item.read_bytes(),
                )
        return stream.getvalue()

    def _android_jar(self) -> Path | None:
        if self.settings.android_sdk_root is None:
            return None
        candidate = (
            self.settings.android_sdk_root
            / "platforms"
            / f"android-{self.settings.device_android_api}"
            / "android.jar"
        )
        return candidate if candidate.is_file() else None

    def _build_tool(self, name: str) -> Path | None:
        if self.settings.android_sdk_root is None:
            return None
        root = self.settings.android_sdk_root / "build-tools"
        if not root.is_dir():
            return None
        candidates = [
            directory / name
            for directory in root.iterdir()
            if directory.is_dir() and (directory / name).is_file()
        ]
        return sorted(candidates)[-1] if candidates else None

    def _dex_tool(self) -> tuple[str, Path] | None:
        for name in ("d8", "dx"):
            candidate = self._build_tool(name)
            if candidate is not None:
                return name, candidate
        return None

    @staticmethod
    def _modern_java_environment() -> dict[str, str] | None:
        for java_home in (
            Path("/usr/lib/jvm/java-17-openjdk-amd64"),
            Path("/usr/lib/jvm/java-21-openjdk-amd64"),
        ):
            if (java_home / "bin" / "java").is_file():
                return {
                    "JAVA_HOME": str(java_home),
                    "PATH": os.pathsep.join(
                        [str(java_home / "bin"), os.environ.get("PATH", "")]
                    ),
                }
        return None

    def _required_tool(self, name: str) -> str:
        value = shutil.which(name) or self._build_tool(name)
        if value is None:
            raise ValueError(f"required PoC build tool is unavailable: {name}")
        return str(value)

    @staticmethod
    def _command_failure(kind: str, result: CommandResult) -> str:
        diagnostic = (result.stderr or result.stdout).strip()
        if len(diagnostic) > 2000:
            diagnostic = diagnostic[-2000:]
        suffix = f": {diagnostic}" if diagnostic else ""
        return f"{kind} failed with exit {result.exit_code}{suffix}"

    def _ensure_keystore(
        self,
        *,
        cancel_event: threading.Event | None,
    ) -> Path | CommandResult:
        keystore = self.settings.data_dir / "poc-signing.jks"
        with self._keystore_lock:
            if keystore.is_file():
                return keystore
            result = self.runner.run(
                [
                    self._required_tool("keytool"),
                    "-genkeypair",
                    "-storetype",
                    "JKS",
                    "-keystore",
                    str(keystore),
                    "-storepass",
                    "android",
                    "-keypass",
                    "android",
                    "-alias",
                    "apkscanner-poc",
                    "-dname",
                    "CN=APKScanner Agent PoC,O=Local Test,C=CN",
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-validity",
                    "3650",
                    "-noprompt",
                ],
                timeout=60,
                cancel_event=cancel_event,
            )
            return keystore if result.exit_code == 0 and keystore.is_file() else result

    @staticmethod
    def _command_metadata(
        spec: AgentPocSpec,
        source_sha256: str,
    ) -> dict[str, object]:
        return {
            "poc_package": spec.package_name,
            "poc_project_path": spec.project_path,
            "poc_source_sha256": source_sha256,
            "platform_managed_build": True,
        }
