from __future__ import annotations

import zipfile

import pytest
from apkscanner.manifest import parse_manifest
from apkscanner.rules import BuiltinRuleEngine
from apkscanner.static_analysis import ApkInspector, InvalidApkError
from apkscanner.tools import CommandResult

from .conftest import MANIFEST


def test_inspector_falls_back_to_plaintext_manifest(settings, fixture_apk) -> None:  # noqa: ANN001
    settings.ensure_directories()
    result = ApkInspector(settings).inspect(fixture_apk, "scan-fixture")
    assert result.manifest.package_name == "com.example.vulnerable"
    assert result.file_inventory["dex_files"] == ["classes.dex"]
    assert result.file_inventory["native_libraries"] == ["lib/arm64-v8a/libdemo.so"]


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


def test_inspector_rejects_zip_path_traversal(settings, tmp_path) -> None:  # noqa: ANN001
    apk = tmp_path / "traversal.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("../outside", "unsafe")
    with pytest.raises(InvalidApkError, match="unsafe ZIP path"):
        ApkInspector(settings).inspect(apk, "scan-traversal")


def test_partial_jadx_is_scoped_to_the_target_component(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    jadx_dir = workspace / "jadx"
    source = (
        jadx_dir
        / "sources"
        / "com"
        / "example"
        / "vulnerable"
        / "DataProvider.java"
    )
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example.vulnerable;\n"
        "public class DataProvider { public String query() { return \"ok\"; } }\n",
        encoding="utf-8",
    )
    command = CommandResult(
        argv=["jadx", "fixture.apk"],
        exit_code=3,
        stdout="ERROR - finished with errors, count: 322",
        stderr=(
            "ERROR - Failed to decompile class: "
            "com.example.unrelated.BrokenClass\n"
        ),
    )
    summary = ApkInspector._jadx_decompilation_summary(command, jadx_dir)
    assert summary["status"] == "partial_success"
    assert summary["generated_java_files"] == 1
    assert summary["reported_error_count"] == 322
    assert summary["failed_classes"] == ["com.example.unrelated.BrokenClass"]

    index = ApkInspector._build_code_index(
        result_entries=parse_manifest(MANIFEST).entries,
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
