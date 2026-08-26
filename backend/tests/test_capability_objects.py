from pathlib import Path

from apkscanner.analysis.android_chains import AndroidAttackChainAnalyzer
from apkscanner.analysis.capability_objects import extract_capability_objects
from apkscanner.analysis.manifest import parse_manifest


def _manifest(components: str = ""):
    return parse_manifest(
        f"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.target">
          <uses-sdk android:targetSdkVersion="36" />
          <application>{components}</application>
        </manifest>"""
    )


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _analyze(root: Path, manifest=None):
    if manifest is None:
        manifest = _manifest()
    analyzer = AndroidAttackChainAnalyzer()
    nodes = analyzer._index_nodes(manifest, [root])
    analyzer._inject_manifest_sources(manifest, nodes)
    adjacency = analyzer._build_adjacency(nodes)
    candidates = []
    from apkscanner.analysis.android_chains import CHAIN_SPECS

    for spec in CHAIN_SPECS:
        for item in analyzer._chains_for_spec(manifest, nodes, adjacency, spec):
            item.setdefault("search_direction", "forward")
            candidates.append(item)
    # reverse pass
    forward_fps = {str(item["fingerprint"]): item for item in candidates}
    for spec in CHAIN_SPECS:
        for rc in analyzer._reverse_chains_for_spec(manifest, nodes, adjacency, spec):
            fp = str(rc["fingerprint"])
            existing = forward_fps.get(fp)
            if existing:
                existing["search_direction"] = "bidirectional"
                existing["priority"] = max(100, int(existing.get("priority") or 0) + 3)
            else:
                candidates.append(rc)
                forward_fps[fp] = rc
    return candidates, nodes


def test_pending_intent_capability_extracted_with_mutable_flag(tmp_path) -> None:
    """Mutable PendingIntent creates a capability object with mutable=True."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/PendingIssuer.java",
        """
        package com.example.target;
        class PendingIssuer {
          void issue(Context context) {
            Intent base = new Intent("com.example.DO_WORK");
            PendingIntent pi = PendingIntent.getBroadcast(
                context, 7, base, PendingIntent.FLAG_MUTABLE);
            new NotificationCompat.Builder(context, "c").setContentIntent(pi);
          }
        }
        """,
    )

    candidates, nodes = _analyze(root)
    capabilities = extract_capability_objects(candidates, nodes)

    pending = [c for c in capabilities if c["capability_type"] == "pending_intent"]
    assert pending, "PendingIntent should be extracted as capability object"
    cap = pending[0]
    assert cap["mutable"] is True, "FLAG_MUTABLE PendingIntent should be mutable"
    assert cap["chain_kind"] == "pending_intent_delegation"
    assert len(cap["escape_path"]) >= 1, "should have at least one class in escape_path"
    assert cap["use_sites"], "should have at least one use site"


def test_immutable_pending_intent_not_mutable(tmp_path) -> None:
    """Immutable PendingIntent should have mutable=False due to guard."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ImmutablePending.java",
        """
        package com.example.target;
        class ImmutablePending {
          void issue(Context context) {
            Intent base = new Intent(context, TargetActivity.class);
            PendingIntent pi = PendingIntent.getBroadcast(
                context, 7, base, PendingIntent.FLAG_IMMUTABLE);
            new NotificationCompat.Builder(context, "c").setContentIntent(pi);
          }
        }
        """,
    )

    candidates, nodes = _analyze(root)
    capabilities = extract_capability_objects(candidates, nodes)

    pending = [c for c in capabilities if c["capability_type"] == "pending_intent"]
    if pending:
        cap = pending[0]
        assert cap["mutable"] is False, (
            "FLAG_IMMUTABLE + explicit base should make capability non-mutable"
        )


def test_uri_grant_capability_extracted(tmp_path) -> None:
    """URI grant creates a content_uri_grant capability object."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/GrantRelay.java",
        """
        package com.example.target;
        class GrantRelay {
          void relay(Intent intent, String packageName) {
            Uri uri = intent.getData();
            grantUriPermission(packageName, uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
          }
        }
        """,
    )

    candidates, nodes = _analyze(root)
    capabilities = extract_capability_objects(candidates, nodes)

    uri_grants = [c for c in capabilities if c["capability_type"] == "content_uri_grant"]
    assert uri_grants, "URI grant should be extracted as capability object"
    cap = uri_grants[0]
    assert cap["chain_kind"] == "uri_permission_redelegation"
    assert "uri_grant" in cap["risk_markers"]


def test_no_capabilities_for_non_capability_chains(tmp_path) -> None:
    """Chains that are not capability-related should not produce capability objects."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/WebViewLoader.java",
        """
        package com.example.target;
        class WebViewLoader {
          void loadExternal() {
            String url = getIntent().getStringExtra("url");
            webView.loadUrl(url);
          }
        }
        """,
    )

    manifest = _manifest(
        '<activity android:name=".WebViewLoader" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
        '<category android:name="android.intent.category.DEFAULT"/></intent-filter>'
        "</activity>"
    )
    candidates, nodes = _analyze(root, manifest)
    capabilities = extract_capability_objects(candidates, nodes)

    # WebView chains should not produce capability objects
    assert not any(
        c["chain_kind"] == "external_input_to_webview" for c in capabilities
    ), "non-capability chains should not produce capability objects"


def test_capability_objects_are_validatable(tmp_path) -> None:
    """Every extracted capability object should validate against the schema."""
    from apkscanner.core.schemas import CapabilityObject

    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/PendingIssuer.java",
        """
        package com.example.target;
        class PendingIssuer {
          void issue(Context context) {
            Intent base = new Intent("com.example.DO_WORK");
            PendingIntent pi = PendingIntent.getBroadcast(
                context, 7, base, PendingIntent.FLAG_MUTABLE);
            new NotificationCompat.Builder(context, "c").setContentIntent(pi);
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/GrantRelay.java",
        """
        package com.example.target;
        class GrantRelay {
          void relay(Intent intent, String packageName) {
            Uri uri = intent.getData();
            grantUriPermission(packageName, uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
          }
        }
        """,
    )

    candidates, nodes = _analyze(root)
    capabilities = extract_capability_objects(candidates, nodes)

    assert len(capabilities) >= 1, "should extract at least one capability object"
    for cap_dict in capabilities:
        validated = CapabilityObject.model_validate(cap_dict)
        assert validated.capability_type in {
            "pending_intent",
            "content_uri_grant",
        }