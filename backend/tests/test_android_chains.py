from pathlib import Path

from apkscanner.android_chains import AndroidAttackChainAnalyzer
from apkscanner.manifest import parse_manifest
from apkscanner.rules import BuiltinRuleEngine
from apkscanner.static_analysis import StaticAnalysisResult


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _manifest(components: str = ""):
    return parse_manifest(
        f"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.target">
          <uses-sdk android:targetSdkVersion="36" />
          <application>{components}</application>
        </manifest>"""
    )


def test_capability_analyzer_joins_pending_nested_intent_and_uri_grant(tmp_path) -> None:
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
        "sources/com/example/target/RedirectActivity.java",
        """
        package com.example.target;
        class RedirectActivity {
          void relay(Intent intent) {
            Intent nested = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            startActivity(nested);
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

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert {
        "pending_intent_delegation",
        "nested_intent_redirection",
        "uri_permission_redelegation",
    } <= set(by_kind)
    pending = by_kind["pending_intent_delegation"]
    assert "pending_intent_mutable" in pending["risk_markers"]
    assert pending["review_required"] is True
    assert "immutable_flag_not_observed_in_bounded_path" in pending["inferred_risks"]
    nested = by_kind["nested_intent_redirection"]
    assert nested["hop_count"] == 0
    assert "intent_sanitizer" not in nested["guard_markers"]


def test_file_ingress_joins_manifest_send_saf_archive_and_fileprovider(tmp_path) -> None:
    root = tmp_path / "jadx"
    decoded = tmp_path / "apktool"
    manifest = _manifest(
        """
        <activity android:name=".ShareImportActivity" android:exported="true">
          <intent-filter>
            <action android:name="android.intent.action.SEND" />
            <category android:name="android.intent.category.DEFAULT" />
            <data android:mimeType="application/zip" />
          </intent-filter>
        </activity>
        <provider android:name="androidx.core.content.FileProvider"
            android:authorities="com.example.target.files"
            android:exported="false" android:grantUriPermissions="true">
          <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
              android:resource="@xml/file_paths" />
        </provider>
        """
    )
    _write(
        root,
        "sources/com/example/target/ShareImportActivity.java",
        """
        package com.example.target;
        class ShareImportActivity {
          void importArchive(Intent intent) {
            Uri uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            InputStream stream = getContentResolver().openInputStream(uri);
            ZipInputStream zip = new ZipInputStream(stream);
            ZipEntry entry = zip.getNextEntry();
            String name = entry.getName();
            File target = new File(getFilesDir(), name);
            String checked = target.getCanonicalPath();
            FileOutputStream output = new FileOutputStream(target);
          }
        }
        """,
    )
    _write(
        decoded,
        "res/xml/file_paths.xml",
        '<paths xmlns:android="http://schemas.android.com/apk/res/android">'
        '<root-path name="device" path="." /></paths>',
    )

    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root, decoded])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert "external_content_to_private_file" in by_kind
    assert "external_archive_extraction" in by_kind
    assert "path_containment_guard" in by_kind["external_archive_extraction"]["guard_markers"]
    assert "broad_fileprovider_configuration" in by_kind
    provider = by_kind["broad_fileprovider_configuration"]
    assert provider["providers"][0]["authorities"] == "com.example.target.files"


def test_runtime_receiver_and_local_socket_are_discovered_with_guards(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/RuntimeHost.java",
        """
        package com.example.target;
        class RuntimeHost {
          RuntimeReceiver receiver = new RuntimeReceiver();
          void start(Context context) {
            context.registerReceiver(receiver, new IntentFilter("com.example.RUN"),
                Context.RECEIVER_NOT_EXPORTED);
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/RuntimeReceiver.java",
        """
        package com.example.target;
        class RuntimeReceiver extends BroadcastReceiver {
          public void onReceive(Context context, Intent intent) {
            context.startService(new Intent(context, WorkService.class));
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/LocalApi.java",
        """
        package com.example.target;
        class LocalApi {
          void run() throws Exception {
            LocalServerSocket server = new LocalServerSocket("agent-api");
            LocalSocket client = server.accept();
          }
        }
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    receiver = by_kind["dynamic_broadcast_receiver"]
    assert receiver["hop_count"] == 1
    assert "receiver_not_exported" in receiver["guard_markers"]
    assert "receiver_sender_restriction_not_observed_in_bounded_path" not in receiver[
        "inferred_risks"
    ]
    assert receiver["review_required"] is False
    assert receiver["disposition"] == "non_exported_receiver_inventory"
    socket = by_kind["local_tcp_or_unix_server"]
    assert "peer_authentication_not_observed_in_bounded_path" in socket["inferred_risks"]


def test_webview_chain_requires_a_bounded_reference_path(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/EntryActivity.java",
        """
        package com.example.target;
        class EntryActivity {
          void show() {
            String url = getIntent().getStringExtra("url");
            new WebPane().render(url);
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/WebPane.java",
        """
        package com.example.target;
        class WebPane {
          void render(String url) {
            webView.addJavascriptInterface(new NativeApi(), "native");
            webView.loadUrl(url);
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/UnrelatedInput.java",
        """
        package com.example.target;
        class UnrelatedInput { String read() { return getIntent().getStringExtra("x"); } }
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    web = [item for item in chains if item["chain_kind"] == "external_input_to_webview"]

    assert len(web) == 1
    assert [item["class_name"] for item in web[0]["path"]] == [
        "com.example.target.EntryActivity",
        "com.example.target.WebPane",
    ]
    assert "webview_bridge" in web[0]["risk_markers"]
    assert "strict_origin_validation_not_observed_in_bounded_path" in web[0][
        "inferred_risks"
    ]


def test_chain_findings_create_surfaces_and_preserve_candidate_metadata(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/Relay.java",
        """
        package com.example.target;
        class Relay {
          void run(Intent intent) {
            Intent nested = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            startActivity(nested);
          }
        }
        """,
    )
    manifest = _manifest()
    attack_chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[root],
        decompilation={"status": "complete_success", "output_usable": True},
        attack_chains=attack_chains,
    )

    engine = BuiltinRuleEngine()
    findings, _coverage = engine.evaluate(result)
    chain_finding = next(
        item for item in findings if item.rule_id == "CHAIN-ANDROID-CAPABILITY-DELEGATION"
    )
    surfaces = engine.static_review_surfaces(manifest, findings)
    surface = next(item for item in surfaces if item.family == "capability_delegation_boundary")

    assert chain_finding.metadata["candidate_only"] is True
    assert surface.attack_chains
    assert surface.attack_chains[0]["fingerprint"]


def test_smali_flag_recovery_distinguishes_guards_and_capability_bits(tmp_path) -> None:
    root = tmp_path / "apktool"
    _write(
        root,
        "smali_classes2/com/example/target/SmaliCapabilities.smali",
        """
        .class public Lcom/example/target/SmaliCapabilities;
        .method public issue(Landroid/content/Context;Landroid/content/Intent;)V
            new-instance v1, Landroid/content/Intent;
            const-class v2, Lcom/example/target/SmaliCapabilities;
            invoke-direct {v1, p1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
            const/high16 v3, 0xc000000
            invoke-static {p1, v0, v1, v3}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
            move-result-object v4
            invoke-virtual {v5, v6, v4}, Landroid/widget/RemoteViews;->setOnClickPendingIntent(ILandroid/app/PendingIntent;)V
            invoke-virtual {p2}, Landroid/content/Intent;->getData()Landroid/net/Uri;
            const/4 v7, 0x3
            invoke-virtual {p2, v7}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;
            return-void
        .end method
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    pending = by_kind["pending_intent_delegation"]
    assert "pending_intent_immutable" in pending["guard_markers"]
    assert "pending_base_explicit" in pending["guard_markers"]
    assert "immutable_flag_not_observed_in_bounded_path" not in pending["inferred_risks"]
    assert "explicit_base_intent_not_observed_in_bounded_path" not in pending[
        "inferred_risks"
    ]
    assert pending["review_required"] is False
    assert pending["disposition"] == "guarded_capability_inventory"
    assert "uri_grant" in by_kind["uri_permission_redelegation"]["sink_markers"]


def test_guarded_inventory_does_not_create_a_review_finding(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/SafeIssuer.java",
        """
        package com.example.target;
        class SafeIssuer {
          void issue(Context context) {
            Intent base = new Intent(context, SafeReceiver.class);
            PendingIntent pi = PendingIntent.getBroadcast(
                context, 7, base, PendingIntent.FLAG_IMMUTABLE);
            new NotificationCompat.Builder(context, "c").setContentIntent(pi);
          }
        }
        """,
    )
    manifest = _manifest()
    attack_chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[root],
        decompilation={"status": "complete_success", "output_usable": True},
        attack_chains=attack_chains,
    )

    findings, _coverage = BuiltinRuleEngine().evaluate(result)

    assert attack_chains[0]["review_required"] is False
    assert not [
        item
        for item in findings
        if item.rule_id == "CHAIN-ANDROID-CAPABILITY-DELEGATION"
    ]


def test_unrelated_methods_in_the_same_class_do_not_form_a_chain(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/UnrelatedMethods.java",
        """
        package com.example.target;
        class UnrelatedMethods {
          String readExternal() {
            return getIntent().getStringExtra("url");
          }
          void showTrustedHelp() {
            webView.loadUrl("https://help.example.test/");
          }
        }
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])

    assert not [item for item in chains if item["chain_kind"] == "external_input_to_webview"]
