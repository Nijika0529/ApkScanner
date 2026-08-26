from pathlib import Path

from apkscanner.analysis.android_chains import AndroidAttackChainAnalyzer
from apkscanner.analysis.manifest import parse_manifest
from apkscanner.analysis.rules import BuiltinRuleEngine
from apkscanner.analysis.static_analysis import StaticAnalysisResult


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
    assert nested["method_dataflow"]["slices"]
    assert nested["method_dataflow"]["edges"][0]["method"] == "relay"
    assert nested["method_dataflow"]["edges"][0]["kind"] == "local_alias_supported"


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
    assert (
        "receiver_sender_restriction_not_observed_in_bounded_path" not in receiver["inferred_risks"]
    )
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
    assert "strict_origin_validation_not_observed_in_bounded_path" in web[0]["inferred_risks"]


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
    assert "explicit_base_intent_not_observed_in_bounded_path" not in pending["inferred_risks"]
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
    assert not [item for item in findings if item.rule_id == "CHAIN-ANDROID-CAPABILITY-DELEGATION"]


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


def test_sensitive_implicit_ipc_egress_is_a_capability_candidate(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/AccountRelay.java",
        """
        package com.example.target;
        class AccountRelay {
          void share(Context context, String token) {
            Intent intent = new Intent("com.example.account.EXPORT");
            intent.putExtra("access_token", token);
            context.startActivity(intent);
          }
        }
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    chain = next(item for item in chains if item["chain_kind"] == "implicit_ipc_sensitive_egress")

    assert chain["family"] == "capability_delegation_boundary"
    assert "sensitive_ipc_payload" in chain["source_markers"]
    assert "implicit_intent_candidate" in chain["risk_markers"]
    assert (
        "explicit_destination_or_receiver_permission_not_observed_in_bounded_path"
        in chain["inferred_risks"]
    )


def test_sensitive_ipc_with_an_explicit_destination_stays_inventory_only(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ScopedRelay.java",
        """
        package com.example.target;
        class ScopedRelay {
          void share(Context context, String token) {
            Intent intent = new Intent("com.example.account.EXPORT");
            intent.setPackage("com.example.trusted");
            intent.putExtra("access_token", token);
            context.startActivity(intent);
          }
        }
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    chain = next(item for item in chains if item["chain_kind"] == "implicit_ipc_sensitive_egress")

    assert "explicit_intent_target" in chain["guard_markers"]
    assert chain["review_required"] is False
    assert chain["disposition"] == "scoped_ipc_destination_inventory"


def test_sensitive_implicit_ipc_egress_is_recovered_from_smali(tmp_path) -> None:
    root = tmp_path / "apktool"
    _write(
        root,
        "smali/com/example/target/TokenRelay.smali",
        """
        .class public Lcom/example/target/TokenRelay;
        .method public send(Landroid/content/Context;Ljava/lang/String;)V
            new-instance v0, Landroid/content/Intent;
            const-string v1, "com.example.account.EXPORT"
            invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
            const-string v2, "access_token"
            invoke-virtual {v0, v2, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
            invoke-virtual {p1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
            return-void
        .end method
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])

    assert any(item["chain_kind"] == "implicit_ipc_sensitive_egress" for item in chains)


def test_activity_result_to_content_resolver_and_set_result_is_linked(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/PickerProxyActivity.java",
        """
        package com.example.target;
        class PickerProxyActivity extends Activity {
          protected void onActivityResult(int requestCode, int resultCode, Intent data) {
            Uri uri = data.getData();
            Cursor cursor = getContentResolver().query(uri, null, null, null, null);
            Intent reply = new Intent().setData(uri);
            reply.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            setResult(RESULT_OK, reply);
          }
        }
        """,
    )

    chains = AndroidAttackChainAnalyzer().analyze(_manifest(), [root])
    chain = next(item for item in chains if item["chain_kind"] == "activity_result_content_proxy")

    assert {"privileged_content_access", "activity_result_return"} <= set(chain["sink_markers"])
    assert "external_uri_input" in chain["risk_markers"]
    assert "content_authority_validation_not_observed_in_bounded_path" in chain["inferred_risks"]
    assert chain["method_dataflow"]["edges"]


def test_binder_claimed_package_authorization_requires_calling_uid_binding(tmp_path) -> None:
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ExportBinder.java",
        """
        package com.example.target;
        class ExportBinder extends IExportService.Stub {
          boolean authorize(String callerPackage) {
            return allowedPackages.contains(callerPackage);
          }
        }
        """,
    )

    manifest = _manifest()
    attack_chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    chain = next(
        item
        for item in attack_chains
        if item["chain_kind"] == "binder_claimed_identity_authorization"
    )

    assert chain["family"] == "runtime_ipc_boundary"
    assert "caller_supplied_identity" in chain["sink_markers"]
    assert "caller_identity_authorization" in chain["risk_markers"]
    assert "calling_uid_binding_not_observed_in_bounded_path" in chain["inferred_risks"]

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
    surfaces = engine.static_review_surfaces(manifest, findings)

    assert any(item.rule_id == "CHAIN-ANDROID-RUNTIME-IPC" for item in findings)
    assert [item.family for item in surfaces].count("runtime_ipc_boundary") == 1


def test_service_manager_identity_bypass_detects_multi_service_no_auth(tmp_path) -> None:
    """ServiceManager.getService + self-reported caller identity + no getCallingUid."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ExportBinder.java",
        """
        package com.example.target;
        import android.os.ServiceManager;
        class ExportBinder extends IExportService.Stub {
          boolean authorize(String callerPackage) {
            IBinder peer = ServiceManager.getService("another_service");
            return allowedPackages.contains(callerPackage);
          }
        }
        """,
    )

    manifest = _manifest()
    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert "service_manager_identity_bypass" in by_kind
    chain = by_kind["service_manager_identity_bypass"]
    assert chain["family"] == "runtime_ipc_boundary"
    assert "caller_supplied_identity" in chain["sink_markers"]
    assert "caller_identity_authorization" in chain["risk_markers"]
    assert "calling_uid_binding_not_observed_in_bounded_path" in chain["inferred_risks"]

    result = StaticAnalysisResult(
        manifest=manifest,
        workspace=tmp_path,
        tool_versions={},
        tool_results={},
        signing={},
        file_inventory={},
        searchable_roots=[root],
        decompilation={"status": "complete_success", "output_usable": True},
        attack_chains=chains,
    )
    engine = BuiltinRuleEngine()
    findings, _coverage = engine.evaluate(result)
    surfaces = engine.static_review_surfaces(manifest, findings)
    assert any(item.rule_id == "CHAIN-ANDROID-RUNTIME-IPC" for item in findings)
    assert any(
        s.family == "runtime_ipc_boundary"
        for s in surfaces
    ), "runtime_ipc_boundary surface should appear in static review"


def test_self_reported_identity_from_extras_flagged_as_risk(tmp_path) -> None:
    """Identity from Intent extras ('pkg' key) without callingUid check."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/IntentIdentityService.java",
        """
        package com.example.target;
        import android.os.Binder;
        class IntentIdentityService extends IAuthService.Stub {
          boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            Intent intent = (Intent) data.readParcelable(null);
            String callerIdentity = intent.getStringExtra("pkg");
            return allowedPackages.contains(callerIdentity);
          }
        }
        """,
    )

    manifest = _manifest()
    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert "binder_claimed_identity_authorization" in by_kind
    chain = by_kind["binder_claimed_identity_authorization"]
    assert "self_reported_identity" in chain["sink_markers"], (
        "self_reported_identity marker should be detected from getStringExtra('pkg')"
    )
    assert "calling_uid_binding_not_observed_in_bounded_path" in chain["inferred_risks"]


def test_plugin_archive_trust_without_signature_check(tmp_path) -> None:
    """Plugin loaded via getPackageArchiveInfo without signature verification."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ExportBinder.java",
        """
        package com.example.target;
        class ExportBinder extends IExportService.Stub {
          boolean authorize(String callerPackage) {
            android.content.pm.PackageInfo info =
                pm.getPackageArchiveInfo(apkPath, 0);
            return allowedPackages.contains(callerPackage);
          }
        }
        """,
    )

    manifest = _manifest()
    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert "binder_claimed_identity_authorization" in by_kind
    chain = by_kind["binder_claimed_identity_authorization"]
    assert "plugin_archive_trust" in chain["risk_markers"], (
        "plugin_archive_trust should be detected from getPackageArchiveInfo without signature flags"
    )
    assert "caller_identity_authorization" in chain["risk_markers"]


def test_reverse_search_finds_path_missed_by_forward(tmp_path) -> None:
    """Reverse (sink→source) search on reversed adjacency catches paths forward missed."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ExportBinder.java",
        """
        package com.example.target;
        class ExportBinder extends IExportService.Stub {
          void onTransact(int code, Parcel data, Parcel reply, int flags) {
            // no reference to helper — forward search from here won't find the sink
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/IdentityHelper.java",
        """
        package com.example.target;
        class IdentityHelper {
          void checkCaller() {
            String callerPackage = getCallingPackage();
            // references ExportBinder → reverse edge B→A makes this reachable
            com.example.target.ExportBinder svc = null;
          }
        }
        """,
    )

    manifest = _manifest()
    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert "binder_claimed_identity_authorization" in by_kind
    chain = by_kind["binder_claimed_identity_authorization"]
    assert chain["search_direction"] == "reverse", (
        "reverse search should find this path that forward search missed"
    )
    assert "caller_supplied_identity" in chain["sink_markers"]
    assert "binder_entrypoint" in chain["source_markers"]


def test_bidirectional_confluence_boosts_priority(tmp_path) -> None:
    """When both forward and reverse find the same path, mark bidirectional + boost."""
    root = tmp_path / "jadx"
    _write(
        root,
        "sources/com/example/target/ExportBinder.java",
        """
        package com.example.target;
        class ExportBinder extends IExportService.Stub {
          boolean authorize(String callerPackage) {
            com.example.target.IdentityHelper helper = new com.example.target.IdentityHelper();
            return allowedPackages.contains(callerPackage);
          }
        }
        """,
    )
    _write(
        root,
        "sources/com/example/target/IdentityHelper.java",
        """
        package com.example.target;
        class IdentityHelper {
          // references ExportBinder → reverse edge
          com.example.target.ExportBinder parent;
        }
        """,
    )

    manifest = _manifest()
    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    by_kind = {item["chain_kind"]: item for item in chains}

    assert "binder_claimed_identity_authorization" in by_kind
    chain = by_kind["binder_claimed_identity_authorization"]
    assert chain["search_direction"] == "bidirectional", (
        "same path found by forward and reverse should be bidirectional"
    )
    assert chain["priority"] >= 100, (
        "bidirectional confluence should boost priority to at least 100"
    )


def test_forward_search_direction_tagged_on_all_chains(tmp_path) -> None:
    """Every forward-discovered chain should have search_direction set."""
    root = tmp_path / "jadx"
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

    manifest = _manifest()
    chains = AndroidAttackChainAnalyzer().analyze(manifest, [root])
    for chain in chains:
        assert "search_direction" in chain, (
            f"chain {chain['chain_kind']} should have search_direction"
        )
        assert chain["search_direction"] in {"forward", "reverse", "bidirectional"}
