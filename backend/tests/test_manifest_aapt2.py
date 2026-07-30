from __future__ import annotations

from apkscanner.manifest import aapt2_xmltree_to_xml, parse_manifest


def test_aapt2_xmltree_manifest_preserves_permissions_and_components() -> None:
    output = """\
N: android=http://schemas.android.com/apk/res/android (line=1)
  E: manifest (line=1)
    A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=40100
    A: package="com.example.agent" (Raw: "com.example.agent")
      E: uses-sdk (line=2)
        A: http://schemas.android.com/apk/res/android:minSdkVersion(0x0101020c)=26
        A: http://schemas.android.com/apk/res/android:targetSdkVersion(0x01010270)=36
      E: permission (line=3)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.STRONG" (Raw: "com.example.STRONG")
        A: http://schemas.android.com/apk/res/android:protectionLevel(0x01010009)=0x00000012
      E: application (line=4)
        A: http://schemas.android.com/apk/res/android:usesCleartextTraffic(0x010104ec)=true
          E: service (line=5)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.agent.OpenService" (Raw: "com.example.agent.OpenService")
            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
          E: receiver (line=6)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.agent.SafeReceiver" (Raw: "com.example.agent.SafeReceiver")
            A: http://schemas.android.com/apk/res/android:permission(0x01010006)="com.example.STRONG" (Raw: "com.example.STRONG")
            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
"""

    manifest = parse_manifest(aapt2_xmltree_to_xml(output))

    assert manifest.package_name == "com.example.agent"
    assert manifest.version_code == "40100"
    assert manifest.min_sdk == 26
    assert manifest.target_sdk == 36
    assert manifest.application["uses_cleartext_traffic"] is True
    assert manifest.permission_declarations["com.example.STRONG"] == "signature|privileged"
    by_name = {entry.name: entry for entry in manifest.entries}
    assert by_name["com.example.agent.OpenService"].permission is None
    assert by_name["com.example.agent.SafeReceiver"].permission_protection == (
        "signature|privileged"
    )
