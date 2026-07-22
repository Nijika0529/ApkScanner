from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from apkscanner.config import Settings

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerable" android:versionCode="42" android:versionName="2.3.1">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
  <permission android:name="com.example.vulnerable.TRUSTED" android:protectionLevel="signature" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter android:autoVerify="false">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="demo" />
        <data android:scheme="https" />
        <data android:host="example.test" />
        <data android:host="m.example.test" />
        <data android:pathPrefix="/open" />
      </intent-filter>
    </activity>
    <service android:name=".TrustedService" android:exported="true" android:permission="com.example.vulnerable.TRUSTED" />
    <receiver android:name=".RiskReceiver">
      <intent-filter><action android:name="com.example.ACTION" /></intent-filter>
    </receiver>
    <provider android:name=".DataProvider" android:authorities="com.example.vulnerable.data" android:exported="true" />
  </application>
</manifest>
"""


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        tool_timeout_seconds=30,
    )


@pytest.fixture
def fixture_apk(tmp_path: Path) -> Path:
    path = tmp_path / "fixture.apk"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr(
            "smali/com/example/vulnerable/DeepLinkActivity.smali",
            "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V\n",
        )
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 80)
        archive.writestr("lib/arm64-v8a/libdemo.so", b"not-an-elf")
    return path
