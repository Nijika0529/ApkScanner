from __future__ import annotations

import io
import os
import re
import stat
import zipfile
from pathlib import Path

import pytest
from apkscanner.analysis import native_analysis as native_analysis_module
from apkscanner.analysis import rules as rules_module
from apkscanner.analysis.manifest import parse_manifest
from apkscanner.analysis.native_analysis import NativeArtifactAnalyzer
from apkscanner.analysis.rules import BuiltinRuleEngine
from apkscanner.analysis.static_analysis import (
    ApkInspector,
    InvalidApkError,
    StaticAnalysisResult,
)
from apkscanner.analysis.target_profiles import target_review_surfaces
from apkscanner.platform.tools import CommandResult, ToolRunner

from .conftest import MANIFEST


def _nested_apk_bytes(package_name: str, entries: dict[str, bytes | str]) -> bytes:
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        f'package="{package_name}"><application /></manifest>'
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 80)
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def test_inspector_falls_back_to_plaintext_manifest(settings, fixture_apk) -> None:  # noqa: ANN001
    settings.ensure_directories()
    result = ApkInspector(settings).inspect(fixture_apk, "scan-fixture")
    assert result.manifest.package_name == "com.example.vulnerable"
    assert result.file_inventory["dex_files"] == ["classes.dex"]
    assert result.file_inventory["native_libraries"] == ["lib/arm64-v8a/libdemo.so"]
    if os.name == "posix":
        assert stat.S_IMODE(result.workspace.stat().st_mode) == 0o700


def test_exact_apk_reuses_content_addressed_static_analysis(settings, fixture_apk) -> None:  # noqa: ANN001
    settings.ensure_directories()

    class NoToolsRunner:
        @staticmethod
        def available(_tool: str) -> bool:
            return False

        @staticmethod
        def version(_tool: str) -> None:
            return None

    inspector = ApkInspector(settings, runner=NoToolsRunner())

    first_progress: list[tuple[str, str, dict]] = []
    cached_progress: list[tuple[str, str, dict]] = []
    first = inspector.inspect(
        fixture_apk,
        "scan-cache-source",
        _progress=lambda phase, status, details: first_progress.append(
            (phase, status, details)
        ),
    )
    second = inspector.inspect(
        fixture_apk,
        "scan-cache-target",
        _progress=lambda phase, status, details: cached_progress.append(
            (phase, status, details)
        ),
    )

    assert first.file_inventory.get("static_cache_hit") is not True
    assert second.file_inventory["static_cache_hit"] is True
    assert second.decompilation["cache_hit"] is True
    assert second.manifest.package_name == first.manifest.package_name
    assert second.code_index == first.code_index
    assert set(second.tool_results) == {"static_cache"}
    assert (second.workspace / "archive").is_dir()
    if os.name == "posix":
        assert (
            (first.workspace / "archive/AndroidManifest.xml").stat().st_ino
            == (second.workspace / "archive/AndroidManifest.xml").stat().st_ino
        )
    assert {phase for phase, status, _details in first_progress if status == "completed"} >= {
        "decompilation",
        "code_index",
        "android_attack_chains",
        "native_analysis",
        "embedded_artifacts",
    }
    assert first.file_inventory["pipeline_timings_seconds"]["code_index"] >= 0
    assert [(phase, status) for phase, status, _details in cached_progress] == [
        ("static_cache", "completed")
    ]
    assert ApkInspector._static_result_cacheable(
        {"jadx": {"timed_out": False}}, {"status": "partial_timeout"}
    ) is False
    assert ApkInspector._static_result_cacheable(
        {"jadx": {"timed_out": False}},
        {"status": "partial_success", "output_usable": True},
    ) is True


def test_streaming_source_prefilters_preserve_native_and_rule_results(
    tmp_path,
    monkeypatch,
) -> None:  # noqa: ANN001
    workspace = tmp_path / "workspace"
    source_root = workspace / "jadx/sources"
    bridge = source_root / "com/example/NativeBridge.java"
    bridge.parent.mkdir(parents=True)
    bridge.write_text(
        """
        package com.example;
        final class NativeBridge {
            static { Runtime.getRuntime().load("/data/local/tmp/libaccount.so"); }
            static native String readAccount();
        }
        """,
        encoding="utf-8",
    )
    risky = source_root / "com/example/RiskyWebView.java"
    risky.write_text(
        "webView.addJavascriptInterface(accountBridge, \"account\");\n",
        encoding="utf-8",
    )
    for index in range(40):
        noise = source_root / f"com/example/noise/Noise{index}.java"
        noise.parent.mkdir(parents=True, exist_ok=True)
        noise.write_text(f"final class Noise{index} {{}}\n", encoding="utf-8")

    optimized_native = NativeArtifactAnalyzer._discover_java_bridges(
        workspace,
        failed_java_classes=set(),
    )
    optimized_rules = BuiltinRuleEngine()._code_rules([source_root], workspace)

    monkeypatch.setattr(native_analysis_module, "files_containing_any", lambda *_a, **_k: None)
    monkeypatch.setattr(rules_module, "files_containing_any", lambda *_a, **_k: None)
    fallback_native = NativeArtifactAnalyzer._discover_java_bridges(
        workspace,
        failed_java_classes=set(),
    )
    fallback_rules = BuiltinRuleEngine()._code_rules([source_root], workspace)

    assert optimized_native == fallback_native
    assert [item.rule_id for item in optimized_rules] == [
        item.rule_id for item in fallback_rules
    ]
    assert [item.locations for item in optimized_rules] == [
        item.locations for item in fallback_rules
    ]


def test_product_bundle_recursively_analyzes_embedded_apks_and_web_assets(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    settings.ensure_directories()

    grandchild = _nested_apk_bytes(
        "com.example.grandchild",
        {
            "assets/grandchild.js": "window.NativeBridge.readAccount();",
            "assets/grandchild.html": "<script src='grandchild.js'></script>",
        },
    )
    child = _nested_apk_bytes(
        "com.example.child",
        {
            "assets/plugin/grandchild.apk": grandchild,
            "assets/child.js": "window.Actor.execute();",
            "assets/child.html": "<script src='child.js'></script>",
        },
    )
    root_apk = tmp_path / "product-bundle.apk"
    root_apk.write_bytes(
        _nested_apk_bytes(
            "com.example.host",
            {
                "assets/actor/child.apk": child,
                "assets/plugin/child-copy.apk": child,
                "assets/main.js": "webView.addJavascriptInterface(bridge, 'native');",
                "assets/main.html": "<script src='main.js'></script>",
            },
        )
    )

    class ProductBundleRunner:
        @staticmethod
        def available(tool: str) -> bool:
            return tool == "jadx"

        @staticmethod
        def version(tool: str) -> str | None:
            return "jadx test" if tool == "jadx" else None

        @staticmethod
        def run(argv, **_kwargs):  # noqa: ANN001
            assert argv[0] == "jadx"
            output = Path(argv[argv.index("--output-dir") + 1])
            input_apk = Path(argv[-1])
            with zipfile.ZipFile(input_apk) as archive:
                manifest = archive.read("AndroidManifest.xml").decode()
            package_name = re.search(r'package="([^"]+)"', manifest).group(1)  # type: ignore[union-attr]
            source = (
                output
                / "sources"
                / Path(*package_name.split("."))
                / "PluginEntry.java"
            )
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                (
                    f"package {package_name}; public final class PluginEntry {{ "
                    + (
                        'String a = "assets/actor/child.apk"; '
                        'String b = "assets/plugin/child-copy.apk"; '
                        "ClassLoader loader;"
                        if package_name == "com.example.host"
                        else 'String nested = "assets/plugin/grandchild.apk"; ClassLoader loader;'
                        if package_name == "com.example.child"
                        else ""
                    )
                    + " }"
                ),
                encoding="utf-8",
            )
            return CommandResult(argv=argv, exit_code=0, stdout="", stderr="")

    inspector = ApkInspector(settings, runner=ProductBundleRunner())
    result = inspector.inspect(root_apk, "product-bundle-source")

    packages = {
        node.get("package_name")
        for node in result.artifact_graph["nodes"]
        if node.get("kind") == "apk"
    }
    assert packages == {
        "com.example.host",
        "com.example.child",
        "com.example.grandchild",
    }
    assert result.file_inventory["product_bundle"] == {
        "schema_version": "1.2",
        "artifact_count": 3,
        "embedded_apk_count": 2,
        "javascript_file_count": 3,
        "html_file_count": 3,
        "native_library_count": 0,
        "java_native_method_count": 0,
        "linked_java_native_method_count": 0,
        "artifact_graph_path": "artifact_graph.json",
    }
    assert {
        edge["archive_path"]
        for edge in result.artifact_graph["edges"]
        if edge.get("relation") == "contains"
    } == {
        "assets/actor/child.apk",
        "assets/plugin/child-copy.apk",
        "assets/plugin/grandchild.apk",
    }
    assert sum(
        1
        for node in result.artifact_graph["nodes"]
        if node.get("package_name") == "com.example.child"
    ) == 1
    summary = result.artifact_graph["summary"]
    assert summary["plugin_loader_count"] == 3
    assert summary["embedded_plugin_entry_count"] == 2
    assert {
        "declares_plugin_loader",
        "loads_embedded_apk",
        "declares_plugin_entry",
        "may_invoke_plugin_entry",
    } <= {edge["relation"] for edge in result.artifact_graph["edges"]}
    assert any(
        (root / "assets/main.js").is_file()
        or (root / "assets/child.js").is_file()
        or (root / "assets/grandchild.js").is_file()
        for root in result.searchable_roots
    )

    findings, _coverage = BuiltinRuleEngine().evaluate(result)
    assert "CODE-WEBVIEW-JS-BRIDGE" in {finding.rule_id for finding in findings}
    surfaces = BuiltinRuleEngine.embedded_artifact_review_surfaces(result)
    assert {surface.artifact["package_name"] for surface in surfaces if surface.artifact} == {
        "com.example.child",
        "com.example.grandchild",
    }
    assert all(surface.locations for surface in surfaces)

    cached = inspector.inspect(root_apk, "product-bundle-cache-target")
    assert cached.file_inventory["static_cache_hit"] is True
    assert cached.file_inventory["product_bundle"] == result.file_inventory["product_bundle"]
    assert cached.artifact_graph["summary"]["apk_count"] == 3
    assert cached.artifact_graph["summary"]["plugin_loader_count"] == 3
    assert any("/artifacts/" in f"/{root}" for root in cached.searchable_roots)


def test_native_artifact_graph_links_java_jni_and_shared_library(
    settings,
    tmp_path,
) -> None:  # noqa: ANN001
    compiler = ToolRunner(30)
    if not compiler.available("gcc"):
        pytest.skip("requires gcc to build the native functional fixture")
    source = tmp_path / "account.c"
    source.write_text(
        """
        __attribute__((visibility("default")))
        long Java_com_example_NativeBridge_readToken(void *env, void *type) {
            (void)env; (void)type; return 7;
        }
        __attribute__((visibility("default")))
        int JNI_OnLoad(void *vm, void *reserved) {
            (void)vm; (void)reserved; return 0x00010006;
        }
        """,
        encoding="utf-8",
    )
    library = tmp_path / "libaccount.so"
    compiled = compiler.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-Wl,-soname,libaccount.so",
            "-o",
            str(library),
            str(source),
        ],
        timeout=30,
    )
    assert compiled.exit_code == 0, compiled.stderr
    apk = tmp_path / "native-product.apk"
    apk.write_bytes(
        _nested_apk_bytes(
            "com.example.nativeproduct",
            {"lib/x86_64/libaccount.so": library.read_bytes()},
        )
    )
    real_runner = ToolRunner(30)

    class NativeFixtureRunner:
        @staticmethod
        def available(tool: str) -> bool:
            return tool == "jadx" or (
                tool in {"readelf", "llvm-readelf"} and real_runner.available(tool)
            )

        @staticmethod
        def version(tool: str) -> str | None:
            return "jadx native fixture" if tool == "jadx" else None

        @staticmethod
        def run(argv, **kwargs):  # noqa: ANN001
            if argv[0] != "jadx":
                return real_runner.run(argv, **kwargs)
            output = Path(argv[argv.index("--output-dir") + 1])
            java = output / "sources/com/example/NativeBridge.java"
            java.parent.mkdir(parents=True, exist_ok=True)
            java.write_text(
                """
                package com.example;
                public final class NativeBridge {
                    static { System.loadLibrary("account"); }
                    public static native long readToken();
                }
                """,
                encoding="utf-8",
            )
            return CommandResult(argv=argv, exit_code=0, stdout="", stderr="")

    inspector = ApkInspector(settings, runner=NativeFixtureRunner())
    result = inspector.inspect(
        apk,
        "native-artifact-graph",
    )

    summary = result.artifact_graph["summary"]
    assert summary["native_library_count"] == 1
    assert summary["java_native_bridge_count"] == 1
    assert summary["java_native_method_count"] == 1
    assert summary["linked_java_native_method_count"] == 1
    assert summary["jni_symbol_count"] == 2
    library_node = next(
        node
        for node in result.artifact_graph["nodes"]
        if node["kind"] == "native_library"
    )
    assert library_node["name"] == "libaccount.so"
    assert library_node["elf"]["valid"] is True
    assert library_node["elf"]["soname"] == "libaccount.so"
    assert library_node["symbols"]["exported_count"] >= 2
    assert library_node["jni"]["has_jni_onload"] is True
    relations = {edge["relation"] for edge in result.artifact_graph["edges"]}
    assert {
        "contains_native_library",
        "declares_native_bridge",
        "loads_native_library",
        "binds_to_jni",
    } <= relations
    assert (result.workspace / "native/index.json").is_file()
    assert (result.workspace / library_node["summary_path"]).is_file()

    cached = inspector.inspect(apk, "native-artifact-graph-cache")
    assert cached.file_inventory["static_cache_hit"] is True
    assert cached.artifact_graph["summary"] == result.artifact_graph["summary"]
    assert (cached.workspace / "native/index.json").is_file()


def test_copilot_profile_routes_runtime_plugin_and_native_subchains(
    tmp_path,
) -> None:
    manifest = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.vivo.ai.copilot"><application /></manifest>"""
    )
    root = tmp_path / "jadx"
    proxy = root / "sources/com/bytedance/openliveplugin/stub/activity/AuthProxy.java"
    proxy.parent.mkdir(parents=True, exist_ok=True)
    proxy.write_text(
        'class AuthProxy { void open() { getPluginClassloader("com.byted.live.lite"); } }',
        encoding="utf-8",
    )
    bridge = root / "sources/com/vivo/ai/copilot/security/WhiteBox.java"
    bridge.parent.mkdir(parents=True, exist_ok=True)
    bridge.write_text(
        'class WhiteBox { static { System.loadLibrary("aes_wb"); } native String decrypt(); }',
        encoding="utf-8",
    )
    native_id = "native/lib/arm64-v8a/libaes_wb.so"
    bridge_id = "java/com.vivo.ai.copilot.security.WhiteBox"
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[root],
        decompilation={"status": "complete"},
        artifact_graph={
            "nodes": [
                {
                    "id": native_id,
                    "path": "native/lib/arm64-v8a/libaes_wb.so",
                    "kind": "native_library",
                    "name": "libaes_wb.so",
                    "abi": "arm64-v8a",
                    "sha256": "a" * 64,
                    "summary_path": "native/summaries/a.json",
                    "jni": {"dynamic_registration": True},
                    "symbols": {"security_relevant": ["JNI_OnLoad"]},
                },
                {
                    "id": bridge_id,
                    "path": "jadx/sources/com/vivo/ai/copilot/security/WhiteBox.java",
                    "kind": "java_native_bridge",
                    "class_name": "com.vivo.ai.copilot.security.WhiteBox",
                },
            ],
            "edges": [
                {
                    "from": bridge_id,
                    "to": native_id,
                    "relation": "loads_native_library",
                }
            ],
        },
    )

    surfaces = target_review_surfaces(result)

    assert {surface.family for surface in surfaces} == {
        "copilot_zeus_runtime_plugin",
        "copilot_native_credential_boundary",
    }
    assert all(surface.investigation_group for surface in surfaces)
    native = next(
        surface
        for surface in surfaces
        if surface.family == "copilot_native_credential_boundary"
    )
    assert native.artifact is not None
    assert native.artifact["java_bridge_classes"] == [
        "com.vivo.ai.copilot.security.WhiteBox"
    ]
    assert native.locations[0]["path"].endswith("WhiteBox.java")


def test_inspector_keeps_smali_and_uses_aapt2_manifest_when_oem_resources_fail(
    settings,
    fixture_apk,
    monkeypatch,
) -> None:  # noqa: ANN001
    settings.ensure_directories()

    class OemFallbackRunner:
        def available(self, tool: str) -> bool:
            return tool in {"apktool", "aapt2"}

        def version(self, tool: str) -> str:
            return f"{tool} test"

        def run(self, argv, **_kwargs):  # noqa: ANN001
            if argv[:2] == ["apktool", "d"] and "--no-res" not in argv:
                return CommandResult(
                    argv=argv,
                    exit_code=1,
                    stdout="",
                    stderr="Can't find framework resources for package of id: 3",
                )
            if argv[:2] == ["apktool", "d"] and "--no-res" in argv:
                output = argv[argv.index("--output") + 1]
                smali = (
                    __import__("pathlib").Path(output)
                    / "smali"
                    / "com"
                    / "example"
                    / "OemService.smali"
                )
                smali.parent.mkdir(parents=True)
                smali.write_text(
                    ".class public Lcom/example/OemService;\n.super Landroid/app/Service;\n",
                    encoding="utf-8",
                )
                return CommandResult(argv=argv, exit_code=0, stdout="", stderr="")
            if argv[:5] == [
                "aapt2",
                "dump",
                "xmltree",
                "--file",
                "AndroidManifest.xml",
            ]:
                return CommandResult(
                    argv=argv,
                    exit_code=0,
                    stdout=(
                        "N: android=http://schemas.android.com/apk/res/android (line=1)\n"
                        "  E: manifest (line=1)\n"
                        '    A: package="com.example" (Raw: "com.example")\n'
                        "      E: uses-sdk (line=2)\n"
                        "        A: http://schemas.android.com/apk/res/android:"
                        "minSdkVersion(0x0101020c)=26\n"
                        "        A: http://schemas.android.com/apk/res/android:"
                        "targetSdkVersion(0x01010270)=36\n"
                        "      E: application (line=3)\n"
                        "          E: service (line=4)\n"
                        "            A: http://schemas.android.com/apk/res/android:"
                        'name(0x01010003)="com.example.OemService" '
                        '(Raw: "com.example.OemService")\n'
                        "            A: http://schemas.android.com/apk/res/android:"
                        "exported(0x01010010)=true\n"
                    ),
                    stderr="",
                )
            if argv[:3] == ["aapt2", "dump", "badging"]:
                return CommandResult(
                    argv=argv,
                    exit_code=0,
                    stdout=(
                        "package: name='com.example' versionCode='1' versionName='1.0'\n"
                        "sdkVersion:'26'\ntargetSdkVersion:'36'\n"
                    ),
                    stderr="",
                )
            raise AssertionError(argv)

    inspector = ApkInspector(settings, runner=OemFallbackRunner())
    monkeypatch.setattr(
        "apkscanner.analysis.static_analysis.discover_tools",
        lambda _runner: {"apktool": "test", "aapt2": "test"},
    )
    result = inspector.inspect(fixture_apk, "scan-oem-fallback")

    assert result.manifest.package_name == "com.example"
    assert result.manifest.target_sdk == 36
    assert result.manifest.entries[0].name == "com.example.OemService"
    assert result.code_index["com.example.OemService"]["status"] == "smali_fallback"
    assert result.tool_results["apktool"]["exit_code"] == 1
    assert result.tool_results["apktool_no_resources"]["exit_code"] == 0
    assert result.tool_results["aapt2_manifest"]["exit_code"] == 0


def test_builtin_rules_emit_candidates_and_coverage(settings, fixture_apk) -> None:  # noqa: ANN001
    settings.ensure_directories()
    result = ApkInspector(settings).inspect(fixture_apk, "scan-rules")
    findings, coverage = BuiltinRuleEngine().evaluate(result)
    rule_ids = {item.rule_id for item in findings}
    assert "MANIFEST-DEBUGGABLE" in rule_ids
    assert "EXPORTED-PROVIDER" in rule_ids
    assert "CODE-WEBVIEW-JS-BRIDGE" in rule_ids
    assert "APK-NATIVE-CODE-INVENTORY" in rule_ids
    assert {item.domain for item in coverage} == {
        "MASVS-STORAGE",
        "MASVS-CRYPTO",
        "MASVS-AUTH",
        "MASVS-NETWORK",
        "MASVS-PLATFORM",
        "MASVS-CODE",
        "MASVS-RESILIENCE",
        "MASVS-PRIVACY",
    }


def test_high_value_code_signals_create_bounded_static_review_surfaces(
    tmp_path,
) -> None:
    manifest = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.agent">
          <uses-sdk android:targetSdkVersion="35" />
          <application />
        </manifest>"""
    )
    root = tmp_path / "apktool"
    sources = {
        "smali_classes2/com/example/agent/HtmlPreviewActivity.smali": (
            "invoke-virtual {v0, v1, v2}, "
            "Landroid/webkit/WebView;->addJavascriptInterface"
            "(Ljava/lang/Object;Ljava/lang/String;)V\n"
            "invoke-virtual {v3, v4}, "
            "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V\n"
        ),
        "smali_classes2/com/example/agent/cli/CliImpl.smali": (
            ".class public Lcom/example/agent/cli/CliImpl;\n"
            "invoke-static {v1}, "
            "Lcom/example/agent/cli/ShellRiskAssessor;->isRisky(Ljava/lang/String;)Z\n"
            "invoke-virtual {v0, v1}, "
            "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;\n"
        ),
        "smali_classes2/com/example/agent/cli/ShellRiskAssessor.smali": (
            'const-string v0, "pm clear"\n'
        ),
        "smali_classes2/com/example/agent/AgentBinder.smali": (
            ".class public Lcom/example/agent/AgentBinder;\n"
            ".super Landroid/os/Binder;\n"
            "invoke-virtual {v0, p1}, "
            "Lcom/example/agent/cli/CliImpl;->execute(Ljava/lang/String;)V\n"
        ),
        "smali_classes2/com/example/agent/AgentService.smali": (
            ".class public Lcom/example/agent/AgentService;\n"
            "new-instance v0, Lcom/example/agent/AgentBinder;\n"
        ),
        "smali_classes2/com/example/agent/AgentApp.smali": (
            ".field private static final APP_SECRET:Ljava/lang/String; = "
            '"0123456789ABCDEF0123456789ABCDEF"\n'
            'const-string v0, "https://gateway-pre.example.test"\n'
        ),
        "smali_classes2/okhttp3/OkHttpClient.smali": (
            "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;\n"
        ),
    }
    for relative, content in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[root],
        decompilation={"status": "not_available"},
        code_index={},
    )

    engine = BuiltinRuleEngine()
    findings, _coverage = engine.evaluate(result)
    surfaces = engine.static_review_surfaces(manifest, findings)

    assert {surface.family for surface in surfaces} == {
        "web_content_boundary",
        "shell_execution_boundary",
        "release_configuration_boundary",
    }
    shell = next(item for item in surfaces if item.family == "shell_execution_boundary")
    assert all("okhttp3" not in item["path"] for item in shell.locations)
    release = next(item for item in surfaces if item.family == "release_configuration_boundary")
    assert set(release.rule_ids) == {
        "CODE-HARDCODED-SECRET",
        "CODE-NONPRODUCTION-ENDPOINT",
    }

    for surface in surfaces:
        ApkInspector.add_static_surface_to_code_index(
            result,
            surface_name=surface.name,
            locations=surface.locations,
        )
        anchors = result.code_index[surface.name]["anchors"]
        assert anchors
        assert all(
            anchor["line_start"] <= anchor["signal_line"] <= anchor["line_end"]
            for anchor in anchors
            if anchor["relationship"] == "signal_source"
        )
    shell_anchors = result.code_index[shell.name]["anchors"]
    assert any(
        Path(anchor["path"]).name == "ShellRiskAssessor.smali"
        and anchor["relationship"] == "outbound_reference"
        for anchor in shell_anchors
    )
    assert any(
        Path(anchor["path"]).name == "AgentBinder.smali"
        and anchor["relationship"] == "inbound_reference"
        for anchor in shell_anchors
    )
    assert any(
        Path(anchor["path"]).name == "AgentService.smali"
        and anchor["relationship"] == "inbound_reference"
        for anchor in shell_anchors
    )


def test_special_attack_classes_seed_semantic_review_surfaces(tmp_path) -> None:
    manifest = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.agent"><application /></manifest>"""
    )
    root = tmp_path / "jadx"
    sources = {
        "com/example/agent/CardWebView.java": (
            "settings.setAllowUniversalAccessFromFileURLs(true);\n"
        ),
        "com/example/agent/ShareImporter.java": (
            "cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);\n"
        ),
        "com/example/agent/BackupRestore.java": (
            "ZipInputStream input; String name = entry.getName();\n"
        ),
        "com/example/agent/RiskPolicyStore.java": (
            "SharedPreferences preferences; String riskRuleVersion;\n"
        ),
        "com/example/agent/ContextCollector.java": (
            "ClipboardManager clipboard; clipboard.getPrimaryClip();\n"
        ),
        "com/example/agent/TraceUploader.java": (
            'String endpoint = "http://trace.example.test/upload";\n'
        ),
    }
    for relative, content in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[root],
        decompilation={"status": "complete_success", "output_usable": True},
        code_index={},
    )

    engine = BuiltinRuleEngine()
    findings, _coverage = engine.evaluate(result)
    rule_ids = {item.rule_id for item in findings}
    assert {
        "CODE-WEBVIEW-UNIVERSAL-FILE-ACCESS",
        "CODE-UNTRUSTED-DISPLAY-NAME",
        "CODE-ARCHIVE-EXTRACTION",
        "CODE-PERSISTED-SECURITY-POLICY",
        "CODE-EXTERNAL-CONTEXT-SOURCE",
        "CODE-CLEARTEXT-ENDPOINT",
    } <= rule_ids
    surfaces = {item.family for item in engine.static_review_surfaces(manifest, findings)}
    assert {
        "web_content_boundary",
        "archive_extraction_boundary",
        "external_file_ingress_boundary",
        "persistent_security_policy_boundary",
        "untrusted_context_boundary",
        "release_configuration_boundary",
    } <= surfaces


def test_inspector_rejects_zip_path_traversal(settings, tmp_path) -> None:  # noqa: ANN001
    apk = tmp_path / "traversal.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("../outside", "unsafe")
    with pytest.raises(InvalidApkError, match="unsafe ZIP path"):
        ApkInspector(settings).inspect(apk, "scan-traversal")


def test_partial_jadx_is_scoped_to_the_target_component(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    jadx_dir = workspace / "jadx"
    source = jadx_dir / "sources" / "com" / "example" / "vulnerable" / "DataProvider.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example.vulnerable;\n"
        "public class DataProvider {\n"
        '  public String query() { return RouteHelper.open("/a"); }\n'
        "}\n",
        encoding="utf-8",
    )
    helper = source.with_name("RouteHelper.java")
    helper.write_text(
        "package com.example.vulnerable;\n"
        "final class RouteHelper {\n"
        "  static String open(String route) { return route; }\n"
        "}\n",
        encoding="utf-8",
    )
    command = CommandResult(
        argv=["jadx", "fixture.apk"],
        exit_code=3,
        stdout="ERROR - finished with errors, count: 322",
        stderr=("ERROR - Failed to decompile class: com.example.unrelated.BrokenClass\n"),
    )
    summary = ApkInspector._jadx_decompilation_summary(command, jadx_dir)
    assert summary["status"] == "partial_success"
    assert summary["generated_java_files"] == 2
    assert summary["reported_error_count"] == 322
    assert summary["failed_classes"] == ["com.example.unrelated.BrokenClass"]

    index = ApkInspector._build_code_index(
        result_entries=parse_manifest(MANIFEST).entries,
        package_name="com.example.vulnerable",
        workspace=workspace,
        jadx_dir=jadx_dir,
        decoded_dir=workspace / "apktool",
        archive_dir=workspace / "archive",
        decompilation=summary,
    )
    provider = index["com.example.vulnerable.DataProvider"]
    assert provider["status"] == "source_available"
    assert provider["target_in_jadx_failure_list"] is False
    assert provider["anchors"][0]["path"].endswith("DataProvider.java")
    assert "public class DataProvider" in provider["anchors"][0]["content"]
    assert any(
        anchor["path"].endswith("RouteHelper.java")
        and anchor["relationship"] == "outbound_reference"
        for anchor in provider["anchors"]
    )


def test_manifest_only_roots_do_not_claim_code_coverage(tmp_path) -> None:
    manifest = parse_manifest(MANIFEST)
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[tmp_path],
        code_index={
            str(entry.owner_component or entry.name): {"status": "source_not_found"}
            for entry in manifest.entries
        },
    )

    _findings, coverage = BuiltinRuleEngine().evaluate(result)
    by_domain = {item.domain: item for item in coverage}

    assert by_domain["MASVS-CRYPTO"].status == "partial"
    assert "No searchable application code" in by_domain["MASVS-CRYPTO"].gap_reason


@pytest.mark.parametrize(
    ("decompilation", "code_index", "expected_gap"),
    [
        (
            {
                "status": "complete",
                "output_usable": True,
                "generated_java_files": 2,
            },
            {
                "com.example.First": {"status": "source_available"},
                "com.example.Second": {"status": "source_not_found"},
            },
            "1 of 2 target component",
        ),
        (
            {
                "status": "partial_success",
                "output_usable": True,
                "generated_java_files": 2,
            },
            {
                "com.example.First": {"status": "source_available"},
                "com.example.Second": {"status": "source_available"},
            },
            "partially successful",
        ),
        (
            {
                "status": "failed",
                "output_usable": False,
                "generated_java_files": 0,
            },
            {
                "com.example.First": {"status": "smali_fallback"},
            },
            "lack complete decompiled source",
        ),
    ],
)
def test_incomplete_code_sources_never_claim_full_coverage(
    tmp_path,
    decompilation: dict,
    code_index: dict,
    expected_gap: str,
) -> None:
    result = StaticAnalysisResult(
        manifest=parse_manifest(MANIFEST),
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[tmp_path],
        decompilation=decompilation,
        code_index=code_index,
    )

    _findings, coverage = BuiltinRuleEngine().evaluate(result)
    by_domain = {item.domain: item for item in coverage}

    assert by_domain["MASVS-CODE"].status == "partial"
    assert expected_gap in str(by_domain["MASVS-CODE"].gap_reason)


def test_complete_global_decompilation_without_components_counts_as_code_coverage(
    tmp_path,
) -> None:
    manifest = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.library"><application /></manifest>"""
    )
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[tmp_path],
        decompilation={
            "status": "complete",
            "output_usable": True,
            "generated_java_files": 10,
        },
        code_index={},
    )

    _findings, coverage = BuiltinRuleEngine().evaluate(result)
    by_domain = {item.domain: item for item in coverage}

    assert by_domain["MASVS-CODE"].status == "covered"
