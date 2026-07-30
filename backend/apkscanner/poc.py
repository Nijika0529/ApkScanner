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
AAPT2_RESOURCE_TABLE_COMPATIBILITY_ERRORS = (
    "entry offsets overlap actual entry data",
    "loadedarsc.cpp",
    "resources.arsc is corrupt",
    "invalid resource table",
)


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
        self._aapt2_flag_cache: dict[tuple[Path, str], bool] = {}
        self._aapt2_flag_lock = threading.Lock()

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
                "zipalign": self._tool_candidate("zipalign"),
                "keytool": shutil.which("keytool"),
            }.items()
            if value is None
        ]
        ingest_missing = [
            name
            for name, value in {
                "aapt2": self._tool_candidate("aapt2"),
                "apksigner": self._tool_candidate("apksigner"),
            }.items()
            if value is None
        ]
        if ingest_missing:
            return {
                "available": False,
                "detail": f"PoC APK ingestion is missing: {', '.join(ingest_missing)}",
            }
        compile_api = self._compile_api()
        min_api = self._effective_min_api()
        target_api = self._target_api()
        toolchain = {
            name: str(value) if value is not None else None
            for name, value in {
                "aapt2": self._tool_candidate(name="aapt2"),
                "d8_or_dx": (
                    self._dex_tool()[1] if self._dex_tool() is not None else None
                ),
                "zipalign": self._tool_candidate(name="zipalign"),
                "apksigner": self._tool_candidate(name="apksigner"),
            }.items()
        }
        return {
            "available": True,
            "android_api": self.settings.device_android_api,
            "compile_api": compile_api,
            "min_api": min_api,
            "target_api": target_api,
            "build_tools_version": self.settings.android_build_tools_version,
            "toolchain": toolchain,
            "aapt2_fallbacks": [
                str(item) for item in self._tool_candidates("aapt2")[1:]
            ],
            "source_contract": "manifest_and_java_or_prebuilt_apk",
            "source_build_available": not source_missing and compile_api is not None,
            "source_build_missing": [
                *source_missing,
                *(
                    [
                        "Android SDK platform android.jar for compile API "
                        f"{self._requested_compile_api()}"
                    ]
                    if compile_api is None
                    else []
                ),
            ],
            "configuration_warnings": [
                *(
                    [
                        f"compile API {compile_api} is below target API "
                        f"{target_api}; PoC sources cannot reference newer APIs"
                    ]
                    if compile_api is not None and target_api > compile_api
                    else []
                ),
                *(
                    [
                        f"compile API {compile_api} cannot encode Android 11+ "
                        "package-visibility queries; <queries> will be omitted"
                    ]
                    if compile_api is not None and compile_api < 30
                    else []
                ),
            ],
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
            compile_api = self._compile_api()
            min_api = self._effective_min_api()
            target_api = self._target_api()
            assert compile_api is not None
            build_manifest = self._build_manifest(
                manifest,
                output,
                compile_api=compile_api,
                package_name=effective_spec.package_name,
                launch_component=effective_spec.launch_component,
            )
            build_sources = self._build_sources(sources, output)

            aapt2_suffix = [
                "link",
                "-o",
                str(unsigned_apk),
                "-I",
                str(android_jar),
                "--manifest",
                str(build_manifest),
                "--min-sdk-version",
                str(min_api),
                "--target-sdk-version",
                str(target_api),
                "--version-code",
                "1",
                "--version-name",
                "1.0",
            ]
            aapt2_ok = False
            aapt2_candidates = self._tool_candidates("aapt2")
            for attempt, aapt2 in enumerate(aapt2_candidates, start=1):
                compatibility_flags = (
                    ["--no-resource-remapping"]
                    if self._aapt2_supports_flag(
                        aapt2,
                        "--no-resource-remapping",
                        cancel_event=cancel_event,
                    )
                    else []
                )
                result = self.runner.run(
                    [
                        str(aapt2),
                        aapt2_suffix[0],
                        *compatibility_flags,
                        *aapt2_suffix[1:],
                    ],
                    cwd=project,
                    timeout=self.settings.poc_build_timeout_seconds,
                    cancel_event=cancel_event,
                )
                commands.append(
                    (
                        "poc.build.aapt2",
                        result,
                        {
                            **self._command_metadata(
                                effective_spec,
                                source_sha256,
                                compile_api=compile_api,
                                min_api=min_api,
                                target_api=target_api,
                            ),
                            "tool_path": str(aapt2),
                            "tool_attempt": attempt,
                            "compatibility_flags": compatibility_flags,
                        },
                    )
                )
                if result.exit_code == 0:
                    aapt2_ok = True
                    break
                if not self._is_aapt2_resource_table_compatibility_error(result):
                    break
            if not aapt2_ok:
                return PocBuildResult(
                    ok=False,
                    commands=commands,
                    error=self._command_failure("poc.build.aapt2", commands[-1][1]),
                    source_sha256=source_sha256,
                    source_path=source_path,
                )

            steps = [
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
                        *[str(item) for item in build_sources],
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
                        self._command_metadata(
                            effective_spec,
                            source_sha256,
                            compile_api=compile_api,
                            min_api=min_api,
                            target_api=target_api,
                        ),
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
                    # Legacy dx does not desugar Java 8 lambdas. Allow its
                    # invoke-custom output on the modern audit devices where
                    # Agent-authored PoCs execute.
                    f"--min-sdk-version={min_api}",
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
                    self._command_metadata(
                        effective_spec,
                        source_sha256,
                        compile_api=compile_api,
                        min_api=min_api,
                        target_api=target_api,
                    ),
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
                        self._command_metadata(
                            effective_spec,
                            source_sha256,
                            compile_api=compile_api,
                            min_api=min_api,
                            target_api=target_api,
                        ),
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
                **self._command_metadata(
                    effective_spec,
                    source_sha256,
                    compile_api=compile_api,
                    min_api=min_api,
                    target_api=target_api,
                ),
                "apk_sha256": apk_sha256,
                "apk_path": str(apk_path),
                "source_path": str(source_path),
            },
            effective_spec=effective_spec,
        )

    @staticmethod
    def _build_manifest(
        source: Path,
        output: Path,
        *,
        compile_api: int | None = None,
        package_name: str | None = None,
        launch_component: str | None = None,
    ) -> Path:
        tree = ElementTree.parse(source)
        root = tree.getroot()
        if compile_api is not None and compile_api < 30:
            for child in list(root):
                if child.tag == "queries":
                    root.remove(child)
        if package_name and launch_component:
            component = (
                f"{package_name}{launch_component}"
                if launch_component.startswith(".")
                else launch_component
            )
            application = root.find("application")
            if application is not None:
                matched = False
                for activity in application.findall("activity"):
                    name = activity.get(f"{{{ANDROID_NAMESPACE}}}name")
                    normalized = (
                        f"{package_name}{name}"
                        if name and name.startswith(".")
                        else name
                    )
                    if normalized == component:
                        activity.set(
                            f"{{{ANDROID_NAMESPACE}}}exported",
                            "true",
                        )
                        matched = True
                        break
                if not matched:
                    activities = application.findall("activity")
                    launchers = [
                        activity
                        for activity in activities
                        if any(
                            action.get(f"{{{ANDROID_NAMESPACE}}}name")
                            == "android.intent.action.MAIN"
                            for intent_filter in activity.findall("intent-filter")
                            for action in intent_filter.findall("action")
                        )
                    ]
                    candidates = launchers if len(launchers) == 1 else activities
                    if len(candidates) == 1:
                        candidates[0].set(
                            f"{{{ANDROID_NAMESPACE}}}name",
                            component,
                        )
                        candidates[0].set(
                            f"{{{ANDROID_NAMESPACE}}}exported",
                            "true",
                        )
        target = output / "AndroidManifest.xml"
        tree.write(target, encoding="utf-8", xml_declaration=True)
        return target

    @staticmethod
    def _build_sources(sources: list[Path], output: Path) -> list[Path]:
        target_root = output / "src"
        target_root.mkdir()
        normalized: list[Path] = []
        for index, source in enumerate(sources):
            target_dir = target_root / f"{index:03d}"
            target_dir.mkdir()
            target = target_dir / source.name
            text = source.read_text(encoding="utf-8", errors="replace")
            text = re.sub(r"(?m)^[ \t]*@Override[ \t]*\r?\n", "", text)
            text = re.sub(
                r"""
                (?P<indent>^[ \t]*)
                String[ \t]+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=
                (?P<initial>[^;]+);[ \t]*\r?\n
                (?P=indent)if[ \t]*\([ \t]*(?P=name)[ \t]*==[ \t]*null[ \t]*\)
                [ \t]*\{[ \t]*\r?\n
                (?P=indent)[ \t]+(?P=name)[ \t]*=[ \t]*(?P<fallback>[^;]+);[ \t]*\r?\n
                (?P=indent)\}
                """,
                (
                    r"\g<indent>String \g<name>Candidate =\g<initial>;\n"
                    r"\g<indent>if (\g<name>Candidate == null) {\n"
                    r"\g<indent>    \g<name>Candidate = \g<fallback>;\n"
                    r"\g<indent>}\n"
                    r"\g<indent>final String \g<name> = \g<name>Candidate;"
                ),
                text,
                flags=re.MULTILINE | re.VERBOSE,
            )
            target.write_text(text, encoding="utf-8")
            normalized.append(target)
        return normalized

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
        for attempt, aapt2 in enumerate(self._tool_candidates("aapt2"), start=1):
            kind = "poc.prebuilt.inspect_manifest"
            result = self.runner.run(
                [str(aapt2), "dump", "badging", str(candidate)],
                cwd=poc_root,
                timeout=self.settings.poc_build_timeout_seconds,
                cancel_event=cancel_event,
            )
            commands.append(
                (
                    kind,
                    result,
                    {
                        **metadata,
                        "tool_path": str(aapt2),
                        "tool_attempt": attempt,
                    },
                )
            )
            if result.exit_code == 0:
                inspection = result
                break
            if not self._is_aapt2_resource_table_compatibility_error(result):
                break
        if inspection is None:
            return PocBuildResult(
                ok=False,
                commands=commands,
                error=self._command_failure(
                    "poc.prebuilt.inspect_manifest", commands[-1][1]
                ),
            )
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
        activity_elements = application.findall("activity")
        declared = {
            item.get(f"{{{ANDROID_NAMESPACE}}}name")
            for item in activity_elements
        }
        component = (
            f"{effective_spec.package_name}{effective_spec.launch_component}"
            if effective_spec.launch_component.startswith(".")
            else effective_spec.launch_component
        )
        normalized_declared = {
            (
                f"{effective_spec.package_name}{name}"
                if name and name.startswith(".")
                else name
            )
            for name in declared
            if name
        }
        if component not in normalized_declared:
            launcher_candidates: list[str] = []
            for activity in activity_elements:
                name = activity.get(f"{{{ANDROID_NAMESPACE}}}name")
                normalized = (
                    f"{effective_spec.package_name}{name}"
                    if name and name.startswith(".")
                    else name
                )
                if not normalized:
                    continue
                for intent_filter in activity.findall("intent-filter"):
                    actions = {
                        item.get(f"{{{ANDROID_NAMESPACE}}}name")
                        for item in intent_filter.findall("action")
                    }
                    categories = {
                        item.get(f"{{{ANDROID_NAMESPACE}}}name")
                        for item in intent_filter.findall("category")
                    }
                    if (
                        "android.intent.action.MAIN" in actions
                        and "android.intent.category.LAUNCHER" in categories
                    ):
                        launcher_candidates.append(normalized)
                        break
            candidates = (
                launcher_candidates
                if len(launcher_candidates) == 1
                else list(normalized_declared)
                if len(normalized_declared) == 1
                else []
            )
            if len(candidates) != 1 or not candidates[0].startswith(
                "io.apkscanner.poc."
            ):
                raise ValueError("launch_component is not declared as an activity")
            effective_spec = AgentPocSpec.model_validate(
                {
                    **effective_spec.model_dump(mode="python"),
                    "launch_component": candidates[0],
                }
            )
            component = candidates[0]
        java_activities: set[str] = set()
        log_tags: set[str] = set()
        for source in sources:
            text = source.read_text(encoding="utf-8", errors="replace")
            package_match = re.search(
                r"(?m)^\s*package\s+([A-Za-z][A-Za-z0-9_.]*)\s*;",
                text,
            )
            activity_match = re.search(
                r"\bclass\s+([A-Za-z][A-Za-z0-9_]*)\s+extends\s+"
                r"(?:android\.app\.)?Activity\b",
                text,
            )
            if package_match and activity_match:
                java_activities.add(
                    f"{package_match.group(1)}.{activity_match.group(1)}"
                )
            log_tags.update(
                re.findall(
                    r'\b(?:TAG|LOG_TAG)\s*=\s*"([A-Z][A-Z0-9_]{2,31})"',
                    text,
                )
            )
        if component not in java_activities:
            candidates = [
                item
                for item in java_activities
                if item.startswith("io.apkscanner.poc.")
            ]
            if len(candidates) != 1:
                raise ValueError(
                    "PoC launcher activity must match exactly one Java Activity class"
                )
            effective_spec = AgentPocSpec.model_validate(
                {
                    **effective_spec.model_dump(mode="python"),
                    "launch_component": candidates[0],
                }
            )
        if len(log_tags) == 1:
            effective_spec = AgentPocSpec.model_validate(
                {
                    **effective_spec.model_dump(mode="python"),
                    "log_tag": next(iter(log_tags)),
                }
            )
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

    def _requested_compile_api(self) -> int:
        return self.settings.poc_compile_api or self.settings.device_android_api

    def _compile_api(self) -> int | None:
        android_jar = self._android_jar()
        if android_jar is None:
            return None
        match = re.fullmatch(r"android-(\d+)", android_jar.parent.name)
        return int(match.group(1)) if match is not None else None

    def _effective_min_api(self) -> int:
        requested = min(
            self.settings.poc_min_api,
            self._requested_target_api(),
        )
        # Debian/legacy dx does not desugar Java 8 lambdas and emits
        # invoke-custom bytecode, which Android only supports from API 26.
        dex_tool = self._dex_tool()
        return max(requested, 26) if dex_tool and dex_tool[0] == "dx" else requested

    def _requested_target_api(self) -> int:
        return self.settings.poc_target_api or self.settings.device_android_api

    def _target_api(self) -> int:
        return max(self._requested_target_api(), self._effective_min_api())

    def _android_jar(self) -> Path | None:
        if self.settings.android_sdk_root is None:
            return None
        candidate = (
            self.settings.android_sdk_root
            / "platforms"
            / f"android-{self._requested_compile_api()}"
            / "android.jar"
        )
        return candidate if candidate.is_file() else None

    @staticmethod
    def _version_key(
        value: str,
    ) -> tuple[int, tuple[tuple[int, object], ...]]:
        return (
            1 if re.match(r"^\d", value) else 0,
            tuple(
                (1, int(part)) if part.isdigit() else (0, part.lower())
                for part in re.findall(r"\d+|[A-Za-z]+", value)
            ),
        )

    def _build_tools_directories(self) -> list[Path]:
        if self.settings.android_sdk_root is None:
            return []
        root = self.settings.android_sdk_root / "build-tools"
        if not root.is_dir():
            return []
        if self.settings.android_build_tools_version:
            pinned = root / self.settings.android_build_tools_version
            return [pinned] if pinned.is_dir() else []
        return sorted(
            (item for item in root.iterdir() if item.is_dir()),
            key=lambda item: self._version_key(item.name),
            reverse=True,
        )

    def _tool_candidates(self, name: str) -> list[Path]:
        candidates = [
            directory / name
            for directory in self._build_tools_directories()
            if (directory / name).is_file()
        ]
        if not self.settings.android_build_tools_version:
            path_tool = shutil.which(name)
            if path_tool:
                candidates.append(Path(path_tool))
        unique: list[Path] = []
        seen: set[Path] = set()
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                unique.append(candidate)
        return unique

    def _tool_candidate(self, name: str) -> Path | None:
        candidates = self._tool_candidates(name)
        return candidates[0] if candidates else None

    def _build_tool(self, name: str) -> Path | None:
        return self._tool_candidate(name)

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
        value = self._tool_candidate(name)
        if value is None and name in {"javac", "keytool"}:
            path_tool = shutil.which(name)
            value = Path(path_tool) if path_tool else None
        if value is None:
            raise ValueError(f"required PoC build tool is unavailable: {name}")
        return str(value)

    def _aapt2_supports_flag(
        self,
        tool: Path,
        flag: str,
        *,
        cancel_event: threading.Event | None,
    ) -> bool:
        key = (tool.resolve(), flag)
        with self._aapt2_flag_lock:
            cached = self._aapt2_flag_cache.get(key)
        if cached is not None:
            return cached
        help_result = self.runner.run(
            [str(tool), "link", "-h"],
            timeout=15,
            cancel_event=cancel_event,
        )
        supported = flag in f"{help_result.stdout}\n{help_result.stderr}"
        with self._aapt2_flag_lock:
            self._aapt2_flag_cache[key] = supported
        return supported

    @staticmethod
    def _is_aapt2_resource_table_compatibility_error(
        result: CommandResult,
    ) -> bool:
        diagnostic = f"{result.stderr}\n{result.stdout}".lower()
        return any(
            marker in diagnostic
            for marker in AAPT2_RESOURCE_TABLE_COMPATIBILITY_ERRORS
        )

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
        *,
        compile_api: int | None = None,
        min_api: int | None = None,
        target_api: int | None = None,
    ) -> dict[str, object]:
        metadata: dict[str, object] = {
            "poc_package": spec.package_name,
            "poc_project_path": spec.project_path,
            "poc_source_sha256": source_sha256,
            "platform_managed_build": True,
        }
        if compile_api is not None:
            metadata["compile_api"] = compile_api
        if min_api is not None:
            metadata["min_api"] = min_api
        if target_api is not None:
            metadata["target_api"] = target_api
        return metadata
