from __future__ import annotations

import zipfile

import pytest
from apkscanner.rules import BuiltinRuleEngine
from apkscanner.static_analysis import ApkInspector, InvalidApkError


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
