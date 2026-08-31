from __future__ import annotations

import base64
import hashlib
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

from ..core.config import Settings
from ..core.schemas import AgentOracleSpec, AgentPocSpec, AgentRequestedTest
from ..platform.artifacts import ArtifactStore
from ..platform.tools import CommandResult, ToolRunner

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
ALLOWED_SOURCE_SUFFIXES = {".java", ".xml"}
AAPT2_RESOURCE_TABLE_COMPATIBILITY_ERRORS = (
    "entry offsets overlap actual entry data",
    "loadedarsc.cpp",
    "resources.arsc is corrupt",
    "invalid resource table",
)
PROOF_RECEIPT_FILENAME = "apkscanner-proof-receipt.json"


@dataclass(slots=True)
class PocBuildResult:
    ok: bool
    commands: list[tuple[str, CommandResult, dict[str, object]]] = field(default_factory=list)
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
                "d8": dex_tool,
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
                "d8_or_dx": (self._dex_tool()[1] if self._dex_tool() is not None else None),
                "zipalign": self._tool_candidate(name="zipalign"),
                "apksigner": self._tool_candidate(name="apksigner"),
            }.items()
        }
        return {
            "available": True,
            "android_api": self.settings.device_android_api,
            "runtime_profile": "android16_plus",
            "compile_api": compile_api,
            "min_api": min_api,
            "target_api": target_api,
            "build_tools_version": self.settings.android_build_tools_version,
            "toolchain": toolchain,
            "aapt2_fallbacks": [str(item) for item in self._tool_candidates("aapt2")[1:]],
            "source_contract": "manifest_and_java_or_prebuilt_apk",
            "agent_source_build_contract": {
                "required_inputs": ["AndroidManifest.xml", "src/**/*.java"],
                "agent_must_compile": False,
                "preferred_harness": "platform_generated",
                "platform_generated_attack_signature": (
                    "public static Object runAttack(Activity, Intent)"
                ),
                "platform_generated_result_types": ["Bundle", "Boolean", "String"],
                "platform_manages": [
                    "launcher_activity",
                    "request_correlation",
                    "structured_result_logging",
                    "exception_reporting",
                    "target_sdk_compatibility",
                    "target_package_visibility",
                    "compilation",
                    "signing",
                    "installation",
                    "evidence_capture",
                    "cleanup",
                ],
            },
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
            "configuration_warnings": [],
            "max_source_bytes": self.settings.poc_max_source_bytes,
            "max_prebuilt_apk_bytes": self.settings.poc_max_apk_bytes,
            "max_source_files": 64,
        }

    def materialize_proof_harness(
        self,
        workspace: Path,
        request: AgentRequestedTest,
        *,
        entry_kind: str,
        target_package_name: str,
        target_component: str | None = None,
        default_uri: str | None = None,
        provider_authority: str | None = None,
    ) -> AgentPocSpec:
        """Create one disposable, platform-owned ordinary-app proof project.

        Its action is fixed at build time from an already validated ``AgentRequestedTest``;
        the device only supplies the correlation ID when launching it.
        """

        kind = entry_kind
        component = (target_component or "").strip()
        if component.startswith("."):
            component = f"{target_package_name}{component}"
        uri = request.uri
        if kind in {"activity", "activity_alias"} and uri is not None:
            kind = "deep_link"
        elif kind == "deep_link":
            uri = uri or default_uri
        elif kind == "provider":
            uri = uri or (f"content://{provider_authority}" if provider_authority else None)
        if kind in {"activity", "activity_alias", "service", "receiver"} and not component:
            raise ValueError(f"{kind} proof requires a target component")
        if kind in {"deep_link", "provider"} and not uri:
            raise ValueError(f"{kind} proof requires a target URI")

        proof_request: dict[str, object] = {
            "kind": kind,
            "package": target_package_name,
            "component": component,
            "uri": uri,
            "extras": request.extras,
            "operation": request.operation,
            "method": request.method,
            "argument": request.argument,
            "binder_transaction_code": request.binder_transaction_code,
            "binder_interface_descriptor": request.binder_interface_descriptor,
            "binder_reply_type": request.binder_reply_type,
            "binder_read_exception": request.binder_read_exception,
            "binder_script": (
                [item.model_dump(mode="json") for item in request.binder_script]
                if request.binder_script is not None
                else None
            ),
            "intent_action": request.intent_action,
            "categories": request.categories,
        }
        proof_request = {key: value for key, value in proof_request.items() if value is not None}
        serialized = json.dumps(
            proof_request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(serialized).hexdigest()[:16]
        package_name = f"io.apkscanner.poc.proof_{digest}"
        relative_project = Path("poc") / f"platform-proof-{digest}"
        root = workspace.resolve()
        project = (root / relative_project).resolve()
        poc_root = (root / "poc").resolve()
        if not project.is_relative_to(poc_root):
            raise ValueError("platform proof project escaped the task PoC workspace")
        source_dir = project / "src" / Path(*package_name.split("."))
        source_dir.mkdir(parents=True, exist_ok=True)
        manifest = project / "AndroidManifest.xml"
        manifest.write_text(
            f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NAMESPACE}" package="{package_name}">
  <application android:label="APKScanner Proof" android:debuggable="true" android:theme="@android:style/Theme.DeviceDefault.NoActionBar">
    <activity android:name=".PlatformProofActivity" android:exported="true" />
  </application>
</manifest>
''',
            encoding="utf-8",
        )
        (source_dir / "PlatformProofActivity.java").write_text(
            self._platform_proof_source(
                package_name=package_name,
                encoded_request=base64.b64encode(serialized).decode("ascii"),
            ),
            encoding="utf-8",
        )
        return AgentPocSpec(
            project_path=str(relative_project),
            package_name=package_name,
            launch_component=".PlatformProofActivity",
            log_tag="APKSCANNER_POC",
            timeout_seconds=30,
            harness_mode="custom",
        )

    def build(
        self,
        workspace: Path,
        spec: AgentPocSpec,
        *,
        oracle: AgentOracleSpec | None = None,
        cancel_event: threading.Event | None = None,
        visible_packages: tuple[str, ...] = (),
        visible_provider_authorities: tuple[str, ...] = (),
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
                    + ", ".join(str(item) for item in capability.get("source_build_missing", []))
                ),
            )
        try:
            if spec.harness_mode == "platform_generated":
                spec = self._materialize_platform_harness(workspace, spec)
            project, sources, manifest, effective_spec = self._validate_project(
                workspace,
                spec,
                oracle=oracle,
            )
            durable_receipt_supported = any(
                PROOF_RECEIPT_FILENAME
                in source.read_text(encoding="utf-8", errors="replace")
                for source in sources
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
            supports_package_visibility = compile_api >= 30 and target_api >= 30
            build_manifest = self._build_manifest(
                manifest,
                output,
                package_name=effective_spec.package_name,
                launch_component=effective_spec.launch_component,
                min_api=min_api,
                target_api=target_api,
                visible_packages=(visible_packages if supports_package_visibility else ()),
                visible_provider_authorities=(
                    visible_provider_authorities if supports_package_visibility else ()
                ),
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
                    # D8's min API controls the generated bytecode and
                    # desugaring strategy.  It must match the APK minSdk,
                    # not the API level used for the formal validation
                    # device.  Keeping these values aligned lets a
                    # compileSdk/targetSdk 36 PoC run on development devices
                    # while retaining the Android 16 release contract.
                    str(min_api),
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
                    error=self._command_failure(f"poc.build.{dex_tool_name}", dex_result),
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
                "harness_mode": effective_spec.harness_mode,
                "durable_receipt_supported": durable_receipt_supported,
                "durable_receipt_filename": (
                    PROOF_RECEIPT_FILENAME if durable_receipt_supported else None
                ),
            },
            effective_spec=effective_spec,
        )

    @staticmethod
    def _build_manifest(
        source: Path,
        output: Path,
        *,
        package_name: str | None = None,
        launch_component: str | None = None,
        min_api: int | None = None,
        target_api: int | None = None,
        visible_packages: tuple[str, ...] = (),
        visible_provider_authorities: tuple[str, ...] = (),
    ) -> Path:
        tree = ElementTree.parse(source)
        root = tree.getroot()
        if min_api is not None or target_api is not None:
            uses_sdk = root.find("uses-sdk")
            if uses_sdk is None:
                uses_sdk = ElementTree.Element("uses-sdk")
                root.insert(0, uses_sdk)
            if min_api is not None:
                uses_sdk.set(
                    f"{{{ANDROID_NAMESPACE}}}minSdkVersion",
                    str(min_api),
                )
            if target_api is not None:
                uses_sdk.set(
                    f"{{{ANDROID_NAMESPACE}}}targetSdkVersion",
                    str(target_api),
                )
        queries = root.find("queries")
        if queries is None and (visible_packages or visible_provider_authorities):
            queries = ElementTree.Element("queries")
            application = root.find("application")
            insert_at = (
                list(root).index(application) if application is not None else len(list(root))
            )
            root.insert(insert_at, queries)
        if queries is not None:
            declared_packages = {
                node.get(f"{{{ANDROID_NAMESPACE}}}name") for node in queries.findall("package")
            }
            for visible_package in visible_packages:
                if visible_package and visible_package not in declared_packages:
                    node = ElementTree.SubElement(queries, "package")
                    node.set(
                        f"{{{ANDROID_NAMESPACE}}}name",
                        visible_package,
                    )
            declared_authorities = {
                authority.strip()
                for node in queries.findall("provider")
                for authority in (node.get(f"{{{ANDROID_NAMESPACE}}}authorities") or "").split(";")
                if authority.strip()
            }
            for authority in visible_provider_authorities:
                if authority and authority not in declared_authorities:
                    node = ElementTree.SubElement(queries, "provider")
                    node.set(
                        f"{{{ANDROID_NAMESPACE}}}authorities",
                        authority,
                    )
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
                    normalized = f"{package_name}{name}" if name and name.startswith(".") else name
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
                error=self._command_failure("poc.prebuilt.inspect_manifest", commands[-1][1]),
            )
        assert inspection is not None
        package_match = re.search(r"package: name='([^']+)'", inspection.stdout)
        if package_match is None or package_match.group(1) != spec.package_name:
            return PocBuildResult(
                ok=False,
                commands=commands,
                error="prebuilt Agent APK package does not match the requested package",
            )
        min_sdk_match = re.search(r"sdkVersion:'(\d+)'", inspection.stdout)
        target_sdk_match = re.search(r"targetSdkVersion:'(\d+)'", inspection.stdout)
        if target_sdk_match is None or int(target_sdk_match.group(1)) < 36:
            return PocBuildResult(
                ok=False,
                commands=commands,
                error="prebuilt Agent APK must declare targetSdkVersion 36 or newer",
            )
        min_api = int(min_sdk_match.group(1)) if min_sdk_match is not None else 1
        target_api = int(target_sdk_match.group(1))
        if min_api > self.settings.device_max_api:
            return PocBuildResult(
                ok=False,
                commands=commands,
                error="prebuilt Agent APK minSdkVersion exceeds the supported device range",
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
                "compile_api": None,
                "min_api": min_api,
                "target_api": target_api,
                "apk_sha256": apk_sha256,
                "apk_path": str(apk_path),
                "source_path": str(source_path),
            },
        )

    def _validate_project(
        self,
        workspace: Path,
        spec: AgentPocSpec,
        *,
        oracle: AgentOracleSpec | None = None,
    ) -> tuple[Path, list[Path], Path, AgentPocSpec]:
        root = workspace.resolve()
        poc_root = (root / "poc").resolve()
        project = self._resolve_source_project(root, poc_root, spec)
        if not project.is_relative_to(poc_root) or not project.is_dir() or project.is_symlink():
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
            raise ValueError(f"PoC source exceeds {self.settings.poc_max_source_bytes} bytes")
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
        declared = {item.get(f"{{{ANDROID_NAMESPACE}}}name") for item in activity_elements}
        component = (
            f"{effective_spec.package_name}{effective_spec.launch_component}"
            if effective_spec.launch_component.startswith(".")
            else effective_spec.launch_component
        )
        normalized_declared = {
            (f"{effective_spec.package_name}{name}" if name and name.startswith(".") else name)
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
            if len(candidates) != 1 or not candidates[0].startswith("io.apkscanner.poc."):
                raise ValueError("launch_component is not declared as an activity")
            effective_spec = AgentPocSpec.model_validate(
                {
                    **effective_spec.model_dump(mode="python"),
                    "launch_component": candidates[0],
                }
            )
            component = candidates[0]
        java_activities: set[str] = set()
        java_classes: set[str] = set()
        java_activity_sources: dict[str, str] = {}
        log_tags: set[str] = set()
        for source in sources:
            text = source.read_text(encoding="utf-8", errors="replace")
            if "bindService(" in text and re.search(r"\.\s*wait\s*\(", text):
                raise ValueError(
                    "Binder PoC must not block the Activity main thread after bindService; "
                    "run the transaction from onServiceConnected"
                )
            dex_tool = self._dex_tool()
            if (
                dex_tool is not None
                and dex_tool[0] == "dx"
                and re.search(
                    r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*->",
                    text,
                )
            ):
                raise ValueError(
                    "the available dx toolchain does not support Java lambdas; "
                    "use an anonymous Runnable or callback class"
                )
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
                activity_name = f"{package_match.group(1)}.{activity_match.group(1)}"
                java_activities.add(activity_name)
                java_activity_sources[activity_name] = text
            class_match = re.search(
                r"\b(?:class|interface)\s+([A-Za-z][A-Za-z0-9_$]*)\b",
                text,
            )
            if package_match and class_match:
                java_classes.add(f"{package_match.group(1)}.{class_match.group(1)}")
            log_tags.update(
                re.findall(
                    r'\b(?:TAG|LOG_TAG)\s*=\s*"([A-Z][A-Z0-9_]{2,31})"',
                    text,
                )
            )
        if component not in java_activities:
            candidates = [item for item in java_activities if item.startswith("io.apkscanner.poc.")]
            if len(candidates) != 1:
                raise ValueError("PoC launcher activity must match exactly one Java Activity class")
            effective_spec = AgentPocSpec.model_validate(
                {
                    **effective_spec.model_dump(mode="python"),
                    "launch_component": candidates[0],
                }
            )
            component = candidates[0]
        if (
            effective_spec.harness_mode == "platform_generated"
            and effective_spec.attack_class not in java_classes
        ):
            raise ValueError(
                "platform-generated PoC attack_class does not match a Java source class"
            )
        # A ui_text Oracle is correlated and decided entirely by the platform's
        # target-package UI baseline/observation pair.  Its proof does not rely
        # on model-authored PoC log claims, so a minimal launcher remains valid
        # even when it omits the optional structured result record.  Oracles
        # that consume PoC output keep the strict result protocol below.
        if (
            oracle is not None
            and oracle.kind != "ui_text"
            and effective_spec.harness_mode == "custom"
        ):
            launcher_source = java_activity_sources.get(component, "")
            required_markers = {
                "apkscanner_request_id": "read the injected apkscanner_request_id Intent extra",
                "success": "log a JSON success boolean",
                "security_impact_observed": ("log a JSON security_impact_observed boolean"),
            }
            if oracle.kind == "provider_rows":
                required_markers["row_count"] = "log the measured provider row_count integer"
            missing = [
                description
                for marker, description in required_markers.items()
                if marker not in launcher_source
            ]
            if missing:
                raise ValueError(
                    "PoC launcher must satisfy the platform result protocol: " + "; ".join(missing)
                )
        if len(log_tags) == 1:
            effective_spec = AgentPocSpec.model_validate(
                {
                    **effective_spec.model_dump(mode="python"),
                    "log_tag": next(iter(log_tags)),
                }
            )
        return project, sources, manifest, effective_spec

    def _materialize_platform_harness(
        self,
        workspace: Path,
        spec: AgentPocSpec,
    ) -> AgentPocSpec:
        """Generate the launcher and result protocol around Agent exploit logic."""

        root = workspace.resolve()
        poc_root = (root / "poc").resolve()
        project = self._resolve_source_project(root, poc_root, spec)
        if not project.is_relative_to(poc_root) or not project.is_dir() or project.is_symlink():
            raise ValueError("project_path must resolve to a regular directory under poc/")
        manifest = project / "AndroidManifest.xml"
        if not manifest.is_file():
            raise ValueError("PoC project requires AndroidManifest.xml")
        tree = ElementTree.parse(manifest)
        manifest_root = tree.getroot()
        package_name = manifest_root.get("package")
        if manifest_root.tag != "manifest" or not package_name:
            raise ValueError("PoC manifest requires a package")
        if not package_name.startswith("io.apkscanner.poc"):
            raise ValueError("platform-generated PoC package must start with io.apkscanner.poc")
        application = manifest_root.find("application")
        if application is None:
            raise ValueError("PoC manifest requires an application")
        # The platform owns this short-lived io.apkscanner.poc.* package. Mark it
        # debuggable solely so the host can read its private, request-bound proof
        # receipt with `run-as` before it is uninstalled.
        application.set(f"{{{ANDROID_NAMESPACE}}}debuggable", "true")
        harness_class = f"{package_name}.ApkScannerHarnessActivity"
        activity = next(
            (
                item
                for item in application.findall("activity")
                if item.get(f"{{{ANDROID_NAMESPACE}}}name") == harness_class
            ),
            None,
        )
        if activity is None:
            activity = ElementTree.SubElement(application, "activity")
            activity.set(f"{{{ANDROID_NAMESPACE}}}name", harness_class)
        activity.set(f"{{{ANDROID_NAMESPACE}}}exported", "true")
        for intent_filter in list(activity.findall("intent-filter")):
            activity.remove(intent_filter)
        intent_filter = ElementTree.SubElement(activity, "intent-filter")
        action = ElementTree.SubElement(intent_filter, "action")
        action.set(f"{{{ANDROID_NAMESPACE}}}name", "android.intent.action.MAIN")
        category = ElementTree.SubElement(intent_filter, "category")
        category.set(f"{{{ANDROID_NAMESPACE}}}name", "android.intent.category.LAUNCHER")
        tree.write(manifest, encoding="utf-8", xml_declaration=True)

        source_dir = project / "src" / Path(*package_name.split("."))
        source_dir.mkdir(parents=True, exist_ok=True)
        harness_source = source_dir / "ApkScannerHarnessActivity.java"
        harness_source.write_text(
            self._platform_harness_source(
                package_name=package_name,
                attack_class=str(spec.attack_class),
                attack_method=spec.attack_method,
                log_tag=spec.log_tag,
            ),
            encoding="utf-8",
        )
        return AgentPocSpec.model_validate(
            {
                **spec.model_dump(mode="python"),
                "package_name": package_name,
                "launch_component": harness_class,
            }
        )

    @staticmethod
    def _platform_harness_source(
        *,
        package_name: str,
        attack_class: str,
        attack_method: str,
        log_tag: str,
    ) -> str:
        return f'''package {package_name};

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

public final class ApkScannerHarnessActivity extends Activity {{
  private static final String TAG = "{log_tag}";
  private static final String RECEIPT_FILENAME = "{PROOF_RECEIPT_FILENAME}";

  @Override public void onCreate(Bundle state) {{
    super.onCreate(state);
    Intent launch = getIntent();
    String requestId = launch.getStringExtra("apkscanner_request_id");
    JSONObject record = new JSONObject();
    boolean success = false;
    try {{
      record.put("apkscanner_request_id", requestId);
    }} catch (Throwable ignored) {{ }}
    persistReceipt(record, "started", false);
    try {{
      Class<?> attack = Class.forName("{attack_class}");
      Method method = attack.getMethod("{attack_method}", Activity.class, Intent.class);
      Object value = method.invoke(null, this, launch);
      success = true;
      if (value instanceof Bundle) {{
        Bundle result = (Bundle) value;
        success = result.getBoolean("success", true);
        if (result.containsKey("row_count")) {{
          record.put("row_count", result.getInt("row_count"));
        }}
        if (result.containsKey("result_summary")) {{
          record.put("result_summary", result.getString("result_summary"));
        }}
      }} else if (value instanceof Boolean) {{
        success = ((Boolean) value).booleanValue();
      }} else if (value != null) {{
        record.put("result_summary", String.valueOf(value));
      }}
      record.put("success", success);
    }} catch (Throwable error) {{
      success = false;
      Throwable cause = error instanceof InvocationTargetException
          && error.getCause() != null ? error.getCause() : error;
      try {{
        record.put("apkscanner_request_id", requestId);
        record.put("success", false);
        record.put("error_type", cause.getClass().getName());
        record.put("error", String.valueOf(cause.getMessage()));
      }} catch (Throwable ignored) {{ }}
    }}
    persistReceipt(record, success ? "completed" : "failed", true);
    Log.i(TAG, record.toString());
    finish();
  }}

  private void persistReceipt(JSONObject record, String stage, boolean terminal) {{
    try {{
      JSONObject receipt = new JSONObject(record.toString());
      receipt.put("receipt_schema_version", "1.0");
      receipt.put("receipt_stage", stage);
      receipt.put("receipt_terminal", terminal);
      byte[] payload = receipt.toString().getBytes(StandardCharsets.UTF_8);
      File receiptFile = new File(getFilesDir(), RECEIPT_FILENAME);
      File tempFile = new File(getFilesDir(), RECEIPT_FILENAME + ".tmp");
      FileOutputStream stream = new FileOutputStream(tempFile, false);
      try {{
        stream.write(payload);
        stream.getFD().sync();
      }} finally {{
        stream.close();
      }}
      if (!tempFile.renameTo(receiptFile)) {{
        FileOutputStream direct = new FileOutputStream(receiptFile, false);
        try {{
          direct.write(payload);
          direct.getFD().sync();
        }} finally {{
          direct.close();
        }}
        tempFile.delete();
      }}
    }} catch (Throwable ignored) {{ }}
  }}
}}
'''

    @staticmethod
    def _platform_proof_source(*, package_name: str, encoded_request: str) -> str:
        """Return the platform-owned one-shot Activity used for deterministic proofs."""

        template = r'''package __PACKAGE__;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.util.Base64;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

public final class PlatformProofActivity extends Activity {
  private static final String TAG = "APKSCANNER_POC";
  private static final String REQUEST_BASE64 = "__REQUEST_BASE64__";
  private static final String RECEIPT_FILENAME = "__RECEIPT_FILENAME__";
  private static final long BINDER_TIMEOUT_MILLIS = 8000L;
  private final AtomicBoolean finished = new AtomicBoolean(false);
  private final AtomicBoolean proofStarted = new AtomicBoolean(false);
  private final Handler handler = new Handler(Looper.getMainLooper());
  private JSONObject request;
  private JSONObject result;
  private ServiceConnection connection;
  private boolean bound;

  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    try {
      request = new JSONObject(new String(
          Base64.decode(REQUEST_BASE64, Base64.DEFAULT), StandardCharsets.UTF_8));
      result = new JSONObject();
      String requestId = getIntent().getStringExtra("apkscanner_request_id");
      result.put("apkscanner_request_id", requestId);
      result.put("requestId", requestId);
      result.put("kind", request.getString("kind"));
      result.put("targetPackage", request.getString("package"));
      persistReceipt("started", false);
    } catch (Throwable error) {
      fail(error);
    }
  }

  @Override protected void onResume() {
    super.onResume();
    if (!proofStarted.compareAndSet(false, true)) return;
    // A bind performed while Activity.onCreate is still running can be treated
    // as a background launch on Android 13+. Wait for the first frame so the
    // temporary PoC has ordinary foreground caller identity.
    handler.postDelayed(new Runnable() {
      @Override public void run() {
        if (finished.get()) return;
        try {
          runProof();
        } catch (Throwable error) {
          fail(error);
        }
      }
    }, 150L);
  }

  private void runProof() throws Exception {
    String kind = request.getString("kind");
    String packageName = request.getString("package");
    String component = request.optString("component", "");
    if ("activity".equals(kind) || "activity_alias".equals(kind)) {
      Intent target = newIntent();
      target.setComponent(new ComponentName(packageName, component));
      applyExtras(target, request.optJSONObject("extras"));
      applyCategories(target, request.optJSONArray("categories"));
      startActivity(target);
      result.put("delivered", true);
      succeed();
      return;
    }
    if ("deep_link".equals(kind)) {
      Uri uri = Uri.parse(request.getString("uri"));
      Intent target = new Intent(Intent.ACTION_VIEW, uri);
      target.setPackage(packageName);
      applyExtras(target, request.optJSONObject("extras"));
      applyCategories(target, request.optJSONArray("categories"));
      ComponentName resolved = target.resolveActivity(getPackageManager());
      result.put("packageResolvedComponent",
          resolved == null ? JSONObject.NULL : resolved.flattenToShortString());
      if (!component.isEmpty()) {
        ComponentName expected = new ComponentName(packageName, component);
        result.put("expectedComponent", expected.flattenToShortString());
        boolean matched = expected.equals(resolved);
        result.put("targetMatched", matched);
        if (!matched) {
          throw new SecurityException("deep link did not resolve to expected component");
        }
      }
      startActivity(target);
      result.put("delivered", true);
      succeed();
      return;
    }
    if ("receiver".equals(kind)) {
      Intent target = newIntent();
      target.setComponent(new ComponentName(packageName, component));
      applyExtras(target, request.optJSONObject("extras"));
      applyCategories(target, request.optJSONArray("categories"));
      sendBroadcast(target);
      result.put("delivered", true);
      succeed();
      return;
    }
    if ("service".equals(kind)) {
      Intent target = newIntent();
      target.setComponent(new ComponentName(packageName, component));
      applyExtras(target, request.optJSONObject("extras"));
      applyCategories(target, request.optJSONArray("categories"));
      String operation = request.optString("operation", "auto");
      if ("binder_transact".equals(operation) || "binder_script".equals(operation)) {
        startBinderProof(target);
        return;
      }
      ComponentName started = startService(target);
      result.put("delivered", started != null);
      succeed();
      return;
    }
    if ("provider".equals(kind)) {
      runProviderProof(Uri.parse(request.getString("uri")));
      succeed();
      return;
    }
    throw new IllegalArgumentException("unsupported proof kind: " + kind);
  }

  private void runProviderProof(Uri uri) throws Exception {
    String operation = request.optString("operation", "query");
    if ("auto".equals(operation) || "query".equals(operation)) {
      Cursor cursor = getContentResolver().query(uri, null, null, null, null);
      try {
        result.put("delivered", true);
        result.put("rowCount", cursor == null ? -1 : cursor.getCount());
        if (cursor != null) {
          result.put("columns", join(cursor.getColumnNames()));
        }
      } finally {
        if (cursor != null) cursor.close();
      }
      return;
    }
    if ("call".equals(operation)) {
      Bundle returned = getContentResolver().call(
          uri, request.getString("method"), request.optString("argument", null),
          toBundle(request.optJSONObject("extras")));
      result.put("delivered", true);
      result.put("bundleKeyCount", returned == null ? -1 : returned.keySet().size());
      return;
    }
    if ("insert".equals(operation)) {
      Uri inserted = getContentResolver().insert(
          uri, toContentValues(request.optJSONObject("extras")));
      result.put("delivered", true);
      result.put("returnedUri", inserted == null ? JSONObject.NULL : inserted.toString());
      return;
    }
    if ("update".equals(operation)) {
      result.put("affectedRows", getContentResolver().update(
          uri, toContentValues(request.optJSONObject("extras")), null, null));
      result.put("delivered", true);
      return;
    }
    if ("delete".equals(operation)) {
      result.put("affectedRows", getContentResolver().delete(uri, null, null));
      result.put("delivered", true);
      return;
    }
    throw new IllegalArgumentException("unsupported provider operation: " + operation);
  }

  private void startBinderProof(final Intent target) throws Exception {
    connection = new ServiceConnection() {
      @Override public void onServiceConnected(ComponentName name, IBinder service) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
          result.put("boundComponent", name.flattenToShortString());
          String descriptor = request.optString("binder_interface_descriptor", "");
          if (!descriptor.isEmpty()) {
            data.writeInterfaceToken(descriptor);
            result.put("binderInterfaceDescriptor", descriptor);
          }
          JSONArray script = request.optJSONArray("binder_script");
          if (script != null) {
            applyBinderWrites(data, script);
            result.put("binderScriptStepCount", script.length());
          }
          int code = request.getInt("binder_transaction_code");
          String replyType = request.optString("binder_reply_type", "");
          boolean returned = service.transact(code, data, reply, 0);
          result.put("binderTransactionCode", code);
          result.put("binderTransactReturned", returned);
          if (!replyType.isEmpty()) result.put("binderReplyType", replyType);
          if (!returned) throw new IllegalStateException("Binder transact returned false");
          reply.setDataPosition(0);
          if (request.optBoolean("binder_read_exception", true)) reply.readException();
          if (script != null) {
            JSONArray replies = readBinderReplies(reply, script);
            result.put("binderReplies", replies);
            if (replies.length() == 1) result.put("binderReply", replies.get(0));
          } else {
            result.put("binderReply", readBinderValue(reply, replyType));
          }
          result.put("delivered", true);
          succeed();
        } catch (Throwable error) {
          fail(error);
        } finally {
          reply.recycle();
          data.recycle();
        }
      }
      @Override public void onServiceDisconnected(ComponentName name) { }
      @Override public void onBindingDied(ComponentName name) {
        fail(new IllegalStateException("Service binding died: " + name));
      }
      @Override public void onNullBinding(ComponentName name) {
        fail(new IllegalStateException("Service returned a null binding: " + name));
      }
    };
    // Some Android releases retain the ServiceConnection even when package
    // visibility or a policy check makes bindService return false. Mark it for
    // cleanup before the call so finishProof() can always unbind defensively.
    bound = true;
    boolean accepted = bindService(target, connection, Context.BIND_AUTO_CREATE);
    result.put("bound", accepted);
    if (!accepted) throw new SecurityException("bindService returned false");
    handler.postDelayed(new Runnable() {
      @Override public void run() {
        fail(new IllegalStateException("Binder proof timed out"));
      }
    }, BINDER_TIMEOUT_MILLIS);
  }

  private void succeed() {
    try {
      result.put("success", true);
      result.put("security_impact_observed", false);
    } catch (Throwable ignored) { }
    finishProof();
  }

  private void fail(Throwable error) {
    try {
      if (result == null) result = new JSONObject();
      String requestId = getIntent().getStringExtra("apkscanner_request_id");
      result.put("apkscanner_request_id", requestId);
      result.put("requestId", requestId);
      result.put("success", false);
      result.put("security_impact_observed", false);
      result.put("errorType", error.getClass().getName());
      result.put("error", String.valueOf(error.getMessage()));
    } catch (Throwable ignored) { }
    finishProof();
  }

  private void finishProof() {
    if (!finished.compareAndSet(false, true)) return;
    handler.removeCallbacksAndMessages(null);
    if (bound && connection != null) {
      try { unbindService(connection); } catch (Throwable ignored) { }
    }
    persistReceipt(
        result != null && result.optBoolean("success", false) ? "completed" : "failed",
        true);
    Log.i(TAG, result == null ? "{}" : result.toString());
    finish();
  }

  private void persistReceipt(String stage, boolean terminal) {
    try {
      JSONObject receipt = result == null ? new JSONObject() : new JSONObject(result.toString());
      receipt.put("receipt_schema_version", "1.0");
      receipt.put("receipt_stage", stage);
      receipt.put("receipt_terminal", terminal);
      byte[] payload = receipt.toString().getBytes(StandardCharsets.UTF_8);
      File receiptFile = new File(getFilesDir(), RECEIPT_FILENAME);
      File tempFile = new File(getFilesDir(), RECEIPT_FILENAME + ".tmp");
      FileOutputStream stream = new FileOutputStream(tempFile, false);
      try {
        stream.write(payload);
        stream.getFD().sync();
      } finally {
        stream.close();
      }
      if (!tempFile.renameTo(receiptFile)) {
        FileOutputStream direct = new FileOutputStream(receiptFile, false);
        try {
          direct.write(payload);
          direct.getFD().sync();
        } finally {
          direct.close();
        }
        tempFile.delete();
      }
    } catch (Throwable ignored) { }
  }

  private Intent newIntent() {
    Intent intent = new Intent();
    String action = request.optString("intent_action", "");
    if (!action.isEmpty()) intent.setAction(action);
    return intent;
  }

  private static void applyBinderWrites(Parcel data, JSONArray script) throws Exception {
    for (int index = 0; index < script.length(); index++) {
      JSONObject step = script.getJSONObject(index);
      String operation = step.getString("operation");
      if ("write_string".equals(operation)) data.writeString(step.getString("string_value"));
      else if ("write_integer".equals(operation)) data.writeInt(step.getInt("integer_value"));
      else if ("write_long".equals(operation)) data.writeLong(step.getLong("integer_value"));
      else if ("write_boolean".equals(operation)) data.writeInt(step.getBoolean("boolean_value") ? 1 : 0);
      else if ("write_bytes_base64".equals(operation))
        data.writeByteArray(Base64.decode(step.getString("string_value"), Base64.DEFAULT));
      else if (!operation.startsWith("read_"))
        throw new IllegalArgumentException("unsupported Binder operation: " + operation);
    }
  }

  private static JSONArray readBinderReplies(Parcel reply, JSONArray script) throws Exception {
    JSONArray replies = new JSONArray();
    for (int index = 0; index < script.length(); index++) {
      String operation = script.getJSONObject(index).getString("operation");
      if (operation.startsWith("read_"))
        replies.put(readBinderValue(reply, operation.substring("read_".length())));
    }
    if (replies.length() == 0)
      throw new IllegalArgumentException("binder_script requires a read step");
    return replies;
  }

  private static Object readBinderValue(Parcel reply, String type) {
    if ("string".equals(type)) {
      String value = reply.readString();
      return value == null ? JSONObject.NULL : value;
    }
    if ("integer".equals(type)) return reply.readInt();
    if ("long".equals(type)) return reply.readLong();
    if ("boolean".equals(type)) return reply.readInt() != 0;
    if ("bytes_base64".equals(type)) {
      byte[] value = reply.createByteArray();
      return value == null ? JSONObject.NULL : Base64.encodeToString(value, Base64.NO_WRAP);
    }
    throw new IllegalArgumentException("unsupported Binder reply type: " + type);
  }

  private static void applyExtras(Intent intent, JSONObject extras) throws Exception {
    if (extras == null) return;
    Iterator<String> keys = extras.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      Object value = extras.get(key);
      if (value instanceof Boolean) intent.putExtra(key, (Boolean) value);
      else if (value instanceof Integer) intent.putExtra(key, (Integer) value);
      else if (value instanceof Long) intent.putExtra(key, (Long) value);
      else if (value instanceof String) intent.putExtra(key, (String) value);
      else throw new IllegalArgumentException("unsupported extra: " + key);
    }
  }

  private static void applyCategories(Intent intent, JSONArray categories) throws Exception {
    if (categories == null) return;
    for (int index = 0; index < categories.length(); index++)
      intent.addCategory(categories.getString(index));
  }

  private static ContentValues toContentValues(JSONObject extras) throws Exception {
    ContentValues values = new ContentValues();
    if (extras == null) return values;
    Iterator<String> keys = extras.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      Object value = extras.get(key);
      if (value instanceof Boolean) values.put(key, (Boolean) value);
      else if (value instanceof Integer) values.put(key, (Integer) value);
      else if (value instanceof Long) values.put(key, (Long) value);
      else if (value instanceof String) values.put(key, (String) value);
      else throw new IllegalArgumentException("unsupported provider value: " + key);
    }
    return values;
  }

  private static Bundle toBundle(JSONObject extras) throws Exception {
    Bundle values = new Bundle();
    if (extras == null) return values;
    Iterator<String> keys = extras.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      Object value = extras.get(key);
      if (value instanceof Boolean) values.putBoolean(key, (Boolean) value);
      else if (value instanceof Integer) values.putInt(key, (Integer) value);
      else if (value instanceof Long) values.putLong(key, (Long) value);
      else if (value instanceof String) values.putString(key, (String) value);
      else throw new IllegalArgumentException("unsupported bundle value: " + key);
    }
    return values;
  }

  private static String join(String[] values) {
    StringBuilder result = new StringBuilder();
    for (int index = 0; index < values.length; index++) {
      if (index > 0) result.append(',');
      result.append(values[index]);
    }
    return result.toString();
  }
}
'''
        return (
            template.replace("__PACKAGE__", package_name)
            .replace("__REQUEST_BASE64__", encoded_request)
            .replace("__RECEIPT_FILENAME__", PROOF_RECEIPT_FILENAME)
        )

    @staticmethod
    def _resolve_source_project(
        root: Path,
        poc_root: Path,
        spec: AgentPocSpec,
    ) -> Path:
        requested = (root / spec.project_path).resolve()
        if requested.is_relative_to(poc_root) and requested.is_dir() and not requested.is_symlink():
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
        return max(36, self.settings.poc_compile_api or self.settings.device_android_api)

    def _compile_api(self) -> int | None:
        android_jar = self._android_jar()
        if android_jar is None:
            return None
        match = re.fullmatch(r"android-(\d+)", android_jar.parent.name)
        return int(match.group(1)) if match is not None else None

    def _effective_min_api(self) -> int:
        return min(
            self.settings.poc_min_api,
            self._requested_target_api(),
        )

    def _requested_target_api(self) -> int:
        return max(36, self.settings.poc_target_api or self.settings.device_android_api)

    def _target_api(self) -> int:
        return max(36, self._requested_target_api(), self._effective_min_api())

    def _android_jar(self) -> Path | None:
        sdk_root = self._sdk_root()
        if sdk_root is None:
            return None
        candidate = (
            sdk_root / "platforms" / f"android-{self._requested_compile_api()}" / "android.jar"
        )
        if candidate.is_file():
            return candidate
        return None

    def _sdk_root(self) -> Path | None:
        if self.settings.android_sdk_root is not None:
            return self.settings.android_sdk_root
        for candidate in (
            Path("/usr/lib/android-sdk"),
            Path.home() / "Android" / "Sdk",
        ):
            if (candidate / "platforms").is_dir():
                return candidate
        return None

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
        sdk_root = self._sdk_root()
        if sdk_root is None:
            return []
        root = sdk_root / "build-tools"
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
        candidate = self._build_tool("d8")
        return ("d8", candidate) if candidate is not None else None

    @staticmethod
    def _modern_java_environment() -> dict[str, str] | None:
        for java_home in (
            Path("/usr/lib/jvm/java-17-openjdk-amd64"),
            Path("/usr/lib/jvm/java-21-openjdk-amd64"),
        ):
            if (java_home / "bin" / "java").is_file():
                return {
                    "JAVA_HOME": str(java_home),
                    "PATH": os.pathsep.join([str(java_home / "bin"), os.environ.get("PATH", "")]),
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
        return any(marker in diagnostic for marker in AAPT2_RESOURCE_TABLE_COMPATIBILITY_ERRORS)

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
