from __future__ import annotations

import os
import stat
import zipfile

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


def test_inspector_falls_back_to_plaintext_manifest(settings, fixture_apk) -> None:  # noqa: ANN001
    settings.ensure_directories()
    result = ApkInspector(settings).inspect(fixture_apk, "scan-fixture")
    assert result.manifest.package_name == "com.example.vulnerable"
    assert result.file_inventory["dex_files"] == ["classes.dex"]
    assert result.file_inventory["native_libraries"] == ["lib/arm64-v8a/libdemo.so"]
    if os.name == "posix":
        assert stat.S_IMODE(result.workspace.stat().st_mode) == 0o700


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
