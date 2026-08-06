from __future__ import annotations

import io
import os
import re
import stat
import zipfile
from pathlib import Path

import pytest
from apkscanner.manifest import parse_manifest
from apkscanner.rules import BuiltinRuleEngine
from apkscanner.static_analysis import (
    ApkInspector,
    InvalidApkError,
    StaticAnalysisResult,
)
from apkscanner.tools import CommandResult

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

    first = inspector.inspect(fixture_apk, "scan-cache-source")
    second = inspector.inspect(fixture_apk, "scan-cache-target")

    assert first.file_inventory.get("static_cache_hit") is not True
    assert second.file_inventory["static_cache_hit"] is True
    assert second.decompilation["cache_hit"] is True
    assert second.manifest.package_name == first.manifest.package_name
    assert second.code_index == first.code_index
    assert set(second.tool_results) == {"static_cache"}
    assert (second.workspace / "archive").is_dir()
    assert ApkInspector._static_result_cacheable(
        {"jadx": {"timed_out": False}}, {"status": "partial_timeout"}
    ) is False


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
                f"package {package_name}; public final class PluginEntry {{}}",
                encoding="utf-8",
            )
            return CommandResult(argv=argv, exit_code=0, stdout="", stderr="")

    inspector = ApkInspector(settings, runner=ProductBundleRunner())
    result = inspector.inspect(root_apk, "product-bundle-source")

    packages = {node.get("package_name") for node in result.artifact_graph["nodes"]}
    assert packages == {
        "com.example.host",
        "com.example.child",
        "com.example.grandchild",
    }
    assert result.file_inventory["product_bundle"] == {
        "schema_version": "1.0",
        "artifact_count": 3,
        "embedded_apk_count": 2,
        "javascript_file_count": 3,
        "html_file_count": 3,
        "artifact_graph_path": "artifact_graph.json",
    }
    assert {
        edge["archive_path"] for edge in result.artifact_graph["edges"]
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
    assert len(cached.artifact_graph["nodes"]) == 3
    assert any("/artifacts/" in f"/{root}" for root in cached.searchable_roots)


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
        "apkscanner.static_analysis.discover_tools",
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
