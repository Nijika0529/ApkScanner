from __future__ import annotations

import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from apkscanner.schemas import BenchmarkSpec

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPOSITORY_ROOT / "testapk"
SOURCE_ROOT = FIXTURE_ROOT / "vulntest-src"


def test_vulntest_apk_and_ground_truth_are_checked_in() -> None:
    apk = FIXTURE_ROOT / "vulntest.apk"
    assert apk.is_file()
    assert apk.stat().st_size < 64 * 1024
    with zipfile.ZipFile(apk) as archive:
        assert {"AndroidManifest.xml", "classes.dex"} <= set(archive.namelist())

    truth = BenchmarkSpec.model_validate(
        json.loads((FIXTURE_ROOT / "vulntest-ground-truth.json").read_text())
    )
    assert len(truth.vulnerabilities) == 6


def test_rescuetest_fixture_contains_a_hidden_cross_component_chain() -> None:
    apk = FIXTURE_ROOT / "rescuetest.apk"
    assert apk.is_file()
    assert apk.stat().st_size < 64 * 1024
    with zipfile.ZipFile(apk) as archive:
        assert {"AndroidManifest.xml", "classes.dex"} <= set(archive.namelist())

    truth = BenchmarkSpec.model_validate(
        json.loads((FIXTURE_ROOT / "rescuetest-ground-truth.json").read_text())
    )
    assert len(truth.vulnerabilities) == 1

    source = FIXTURE_ROOT / "rescuetest-src"
    manifest = ElementTree.parse(source / "AndroidManifest.xml").getroot()
    android = "{http://schemas.android.com/apk/res/android}"
    application = manifest.find("application")
    assert application is not None
    components = {
        item.get(f"{android}name"): item
        for item in application
        if item.tag in {"activity", "receiver"}
    }
    assert components[".EntryActivity"].get(f"{android}exported") == "true"
    assert components[".VaultRelay"].get(f"{android}exported") == "false"

    entry = (
        source / "smali/io/apkscanner/rescuetest/EntryActivity.smali"
    ).read_text()
    route = (
        source / "smali/io/apkscanner/rescuetest/TelemetryRoute.smali"
    ).read_text()
    relay = (
        source / "smali/io/apkscanner/rescuetest/VaultRelay.smali"
    ).read_text()
    assert "TelemetryRoute;->dispatch" in entry
    assert '"delivery_token"' in route
    assert "VaultRelay;" in route
    assert "Landroid/app/PendingIntent;->send" in relay
    assert '"rescue-chain-secret"' in relay


def test_vulntest_source_contains_real_attack_paths_and_safe_control() -> None:
    manifest = ElementTree.parse(SOURCE_ROOT / "AndroidManifest.xml").getroot()
    android = "{http://schemas.android.com/apk/res/android}"
    application = manifest.find("application")
    assert application is not None
    components = {
        item.get(f"{android}name"): item
        for item in application
        for tag in ("activity", "provider", "service", "receiver")
        if item.tag == tag
    }
    assert components[".MainActivity"].get(f"{android}exported") == "true"
    assert components[".SecretActivity"].get(f"{android}exported") == "false"
    assert components[".SecretProvider"].get(f"{android}exported") == "true"
    assert components[".CommandService"].get(f"{android}exported") == "true"
    assert components[".CommandReceiver"].get(f"{android}exported") == "true"
    assert components[".SafeActivity"].get(f"{android}permission") == (
        "io.apkscanner.vulntest.SIGNATURE_ONLY"
    )

    main = (SOURCE_ROOT / "smali/io/apkscanner/vulntest/MainActivity.smali").read_text()
    deep_link = (SOURCE_ROOT / "smali/io/apkscanner/vulntest/DeepLinkActivity.smali").read_text()
    provider = (SOURCE_ROOT / "smali/io/apkscanner/vulntest/SecretProvider.smali").read_text()
    binder = (SOURCE_ROOT / "smali/io/apkscanner/vulntest/SecretBinder.smali").read_text()

    for token in (
        '"target_activity"',
        "Ljava/lang/Class;->forName",
        '"inner_intent"',
        "->getParcelableExtra",
        "Ljava/net/URLDecoder;->decode",
        "->addJavascriptInterface",
        "->loadUrl",
    ):
        assert token in main
    assert "->getQueryParameter" in deep_link
    assert "->addJavascriptInterface" in deep_link
    assert '"password"' in provider and '"hunter2"' in provider
    assert "->onTransact" in binder and '"service-secret=hunter2"' in binder
