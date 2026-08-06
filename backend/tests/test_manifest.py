from __future__ import annotations

from apkscanner.manifest import parse_manifest
from apkscanner.models import EntryPoint
from apkscanner.planner import InvestigationPlanner
from apkscanner.rules import BuiltinRuleEngine

from .conftest import MANIFEST


def test_manifest_effective_exports_and_deep_link_cartesian_product() -> None:
    document = parse_manifest(MANIFEST)
    components = {entry.name: entry for entry in document.entries if entry.kind != "deep_link"}
    assert document.package_name == "com.example.vulnerable"
    assert document.target_sdk == 35
    assert components["com.example.vulnerable.DeepLinkActivity"].exported is True
    assert components["com.example.vulnerable.TrustedService"].permission_protection == "signature"
    assert components["com.example.vulnerable.RiskReceiver"].exported is True
    assert components["com.example.vulnerable.RiskReceiver"].exported_reason == "missing_required_attribute_with_filter"
    links = [entry for entry in document.entries if entry.kind == "deep_link"]
    assert len(links) == 4
    assert {entry.name for entry in links} == {
        "demo://example.test/open",
        "demo://m.example.test/open",
        "https://example.test/open",
        "https://m.example.test/open",
    }


def test_signature_permission_is_inherited_by_component() -> None:
    document = parse_manifest(MANIFEST)
    service = next(entry for entry in document.entries if entry.kind == "service")
    assert service.permission == "com.example.vulnerable.TRUSTED"
    assert service.permission_protection == "signature"


def test_planner_statically_closes_signature_guarded_component() -> None:
    entry = EntryPoint(
        id="00000000-0000-0000-0000-000000000010",
        scan_id="scan",
        kind="service",
        name="com.example.TrustedService",
        owner_component="com.example.TrustedService",
        exported=True,
        permission="com.example.TRUSTED",
        permission_protection="signature|privileged",
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [entry])

    assert plan.tasks == []
    assert len(plan.static_closures) == 1
    closure = plan.static_closures[0]
    assert closure.reason_code == "strong_permission_guard"
    assert closure.permission == "com.example.TRUSTED"
    assert closure.permission_protection == "signature|privileged"
    assert closure.resolution_source == "manifest_declaration"

    unguarded = EntryPoint(
        id="00000000-0000-0000-0000-000000000016",
        scan_id="scan",
        kind="activity",
        name="com.example.PublicActivity",
        owner_component="com.example.PublicActivity",
        exported=True,
    )
    task = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan("scan", [unguarded])[0]
    assert any(
        "Attacker-controlled data from this assigned entry" in hypothesis
        for hypothesis in task.hypotheses
    )


def test_planner_coalesces_only_explicit_attack_chain_variants() -> None:
    group = {
        "key": "copilot:web_external_content",
        "strategy": "vivo_copilot_7x_v1",
        "reason": "same external content chain",
    }
    activity = EntryPoint(
        id="00000000-0000-0000-0000-000000000101",
        scan_id="scan",
        kind="activity",
        name="com.vivo.ai.copilot.transfer.EmptyLauncherActivity",
        owner_component="com.vivo.ai.copilot.transfer.EmptyLauncherActivity",
        exported=True,
        metadata_json={"investigation_group": group},
    )
    surface = EntryPoint(
        id="00000000-0000-0000-0000-000000000102",
        scan_id="scan",
        kind="static_surface",
        name="static://web_content_boundary",
        owner_component="static://web_content_boundary",
        exported=False,
        metadata_json={
            "investigation_group": group,
            "static_review_family": "web_content_boundary",
            "static_review_hypotheses": ["Trace every bridge exposed to external content."],
        },
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [activity, surface])

    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.task_type == "component"
    assert task.target_entry_ids == [activity.id, surface.id]
    assert "build_agent_poc_apk" in task.allowed_side_effects
    assert task.preconditions["coalescing"]["group_key"] == group["key"]
    assert task.preconditions["coalescing"]["source_task_count"] == 2
    assert len(plan.coalescing_decisions) == 1
    assert plan.coalescing_decisions[0]["avoided_task_count"] == 1


def test_planner_dispatches_internal_static_surface_without_device_side_effects() -> None:
    entry = EntryPoint(
        id="00000000-0000-0000-0000-000000000019",
        scan_id="scan",
        kind="static_surface",
        name="static://shell_execution_boundary",
        owner_component="static://shell_execution_boundary",
        exported=False,
        exported_reason="static_semantic_seed",
        metadata_json={
            "effective_enabled": True,
            "static_review_family": "shell_execution_boundary",
            "static_review_priority": 96,
            "static_review_rule_ids": ["CODE-COMMAND-EXEC"],
            "static_review_hypotheses": [
                "Untrusted tool input reaches the shell execution sink."
            ],
        },
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [entry])

    assert plan.static_closures == []
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.task_type == "static_review"
    assert task.priority == 96
    assert task.target_entry_ids == [entry.id]
    assert task.hypotheses == [
        "Untrusted tool input reaches the shell execution sink."
    ]
    assert task.allowed_side_effects == []
    assert task.device_profile["static_review"] is True


def test_planner_groups_deep_links_with_their_owner_activity() -> None:
    activity = EntryPoint(
        id="00000000-0000-0000-0000-000000000017",
        scan_id="scan",
        kind="activity",
        name="com.example.DeepLinkActivity",
        owner_component="com.example.DeepLinkActivity",
        exported=True,
    )
    deep_link = EntryPoint(
        id="00000000-0000-0000-0000-000000000018",
        scan_id="scan",
        kind="deep_link",
        name="demo://example.test/open",
        owner_component=activity.name,
        exported=True,
    )

    tasks = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan("scan", [activity, deep_link])

    assert len(tasks) == 1
    assert tasks[0].task_type == "component"
    assert tasks[0].target_entry_ids == [activity.id, deep_link.id]
    assert any("callback provenance" in item for item in tasks[0].hypotheses)
    assert not any("Deep links handled by" in item for item in tasks[0].hypotheses)


def test_planner_resolves_framework_signature_binding_permission() -> None:
    entry = EntryPoint(
        id="00000000-0000-0000-0000-000000000011",
        scan_id="scan",
        kind="service",
        name="com.example.AutofillService",
        owner_component="com.example.AutofillService",
        exported=True,
        permission="android.permission.BIND_AUTOFILL_SERVICE",
        permission_protection=None,
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [entry])

    assert plan.tasks == []
    assert len(plan.static_closures) == 1
    assert plan.static_closures[0].permission_protection == "signature"
    assert (
        plan.static_closures[0].resolution_source
        == "android_framework_catalog"
    )


def test_planner_keeps_unknown_permission_and_provider_uri_grants_for_review() -> None:
    unresolved = EntryPoint(
        id="00000000-0000-0000-0000-000000000012",
        scan_id="scan",
        kind="receiver",
        name="com.example.UnknownReceiver",
        owner_component="com.example.UnknownReceiver",
        exported=True,
        permission="com.vendor.UNKNOWN",
        permission_protection=None,
    )
    grantable_provider = EntryPoint(
        id="00000000-0000-0000-0000-000000000013",
        scan_id="scan",
        kind="provider",
        name="com.example.GrantableProvider",
        owner_component="com.example.GrantableProvider",
        exported=True,
        permission="com.example.TRUSTED",
        permission_protection="signature",
        metadata_json={
            "grant_uri_permission_paths": [{"pathPrefix": "/shared"}],
        },
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [unresolved, grantable_provider])

    assert {task.target_entry_ids[0] for task in plan.tasks} == {
        unresolved.id,
        grantable_provider.id,
    }
    assert plan.static_closures == []


def test_planner_does_not_close_provider_with_one_unresolved_boundary() -> None:
    provider = EntryPoint(
        id="00000000-0000-0000-0000-000000000014",
        scan_id="scan",
        kind="provider",
        name="com.example.MixedProvider",
        owner_component="com.example.MixedProvider",
        exported=True,
        permission="android.permission.BIND_AUTOFILL_SERVICE",
        permission_protection=None,
        metadata_json={
            "effective_read_permission": (
                "android.permission.BIND_AUTOFILL_SERVICE"
            ),
            "effective_read_permission_protection": None,
            "effective_write_permission": "com.vendor.UNKNOWN",
            "effective_write_permission_protection": None,
            "path_permissions": [],
        },
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [provider])

    assert len(plan.tasks) == 1
    assert plan.static_closures == []


def test_planner_closes_provider_only_when_every_boundary_is_strong() -> None:
    provider = EntryPoint(
        id="00000000-0000-0000-0000-000000000015",
        scan_id="scan",
        kind="provider",
        name="com.example.StrongProvider",
        owner_component="com.example.StrongProvider",
        exported=True,
        permission="com.example.TRUSTED",
        permission_protection="signature",
        metadata_json={
            "effective_read_permission": "com.example.TRUSTED",
            "effective_read_permission_protection": "signature",
            "effective_write_permission": "com.example.TRUSTED",
            "effective_write_permission_protection": "signature",
            "path_permissions": [],
            "grant_uri_permission_paths": [],
            "grant_uri_permissions": "false",
        },
    )

    plan = InvestigationPlanner(
        android_version="16",
        adb_configured=True,
    ).plan_with_decisions("scan", [provider])

    assert plan.tasks == []
    assert len(plan.static_closures) == 1
    assert plan.static_closures[0].reason_code == "strong_permission_guard"


def test_manifest_defaults_use_effective_target_sdk() -> None:
    modern = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.modern">
          <uses-sdk android:minSdkVersion="28" />
          <application>
            <provider android:name=".Data" android:authorities="com.example.modern.data" />
          </application>
        </manifest>"""
    )
    modern_provider = next(entry for entry in modern.entries if entry.kind == "provider")
    assert modern.target_sdk is None
    assert modern.application["effective_target_sdk"] == 28
    assert modern.application["uses_cleartext_traffic"] is False
    assert modern_provider.exported is False

    legacy = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.legacy">
          <application>
            <provider android:name=".Data" android:authorities="com.example.legacy.data" />
          </application>
        </manifest>"""
    )
    legacy_provider = next(entry for entry in legacy.entries if entry.kind == "provider")
    assert legacy.application["effective_target_sdk"] == 1
    assert legacy.application["uses_cleartext_traffic"] is True
    assert legacy_provider.exported is True
    assert legacy_provider.exported_reason == "legacy_provider_default"


def test_alias_and_provider_permission_precedence_is_preserved() -> None:
    document = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.permissions">
          <uses-sdk android:targetSdkVersion="35" />
          <permission android:name="com.example.SIGNATURE"
              android:protectionLevel="signature" />
          <permission android:name="com.example.NORMAL"
              android:protectionLevel="normal" />
          <application android:permission="com.example.SIGNATURE">
            <activity android:name=".Target" android:exported="false" />
            <activity-alias android:name=".PublicAlias" android:targetActivity=".Target"
                android:exported="true" />
            <provider android:name=".Data" android:authorities="com.example.permissions.data"
                android:exported="true"
                android:readPermission="com.example.NORMAL"
                android:writePermission="com.example.SIGNATURE" />
          </application>
        </manifest>"""
    )
    entries = {entry.name: entry for entry in document.entries}
    alias = entries["com.example.permissions.PublicAlias"]
    provider = entries["com.example.permissions.Data"]

    # An alias without its own permission is public even when the application
    # or target activity has a default permission.
    assert alias.permission is None
    assert alias.permission_protection is None

    # Provider read/write permissions override the common provider/application
    # permission. The exposed boundary reports the weakest effective access.
    assert provider.permission == "com.example.NORMAL"
    assert provider.permission_protection == "normal"
    assert provider.metadata["effective_read_permission"] == "com.example.NORMAL"
    assert provider.metadata["effective_write_permission"] == "com.example.SIGNATURE"


def test_provider_path_permission_contributes_weakest_access_boundary() -> None:
    document = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.pathpermissions">
          <uses-sdk android:targetSdkVersion="35" />
          <permission android:name="com.example.SIGNATURE"
              android:protectionLevel="signature" />
          <permission android:name="com.example.NORMAL"
              android:protectionLevel="normal" />
          <application>
            <provider android:name=".Data"
                android:authorities="com.example.pathpermissions.data"
                android:exported="true"
                android:readPermission="com.example.SIGNATURE"
                android:writePermission="com.example.SIGNATURE">
              <path-permission android:pathPrefix="/public"
                  android:readPermission="com.example.NORMAL" />
            </provider>
          </application>
        </manifest>"""
    )
    provider = next(entry for entry in document.entries if entry.kind == "provider")

    assert provider.permission == "com.example.NORMAL"
    assert provider.permission_protection == "normal"
    assert provider.metadata["path_permissions"] == [
        {
            "path_kind": "pathPrefix",
            "path": "/public",
            "permission": None,
            "effective_read_permission": "com.example.NORMAL",
            "effective_read_permission_protection": "normal",
            "effective_write_permission": "com.example.SIGNATURE",
            "effective_write_permission_protection": "signature",
        }
    ]
    findings = BuiltinRuleEngine()._manifest_rules(document)
    assert any(item.rule_id == "EXPORTED-PROVIDER" for item in findings)


def test_provider_grant_uri_permission_paths_are_preserved() -> None:
    document = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.grants">
          <uses-sdk android:targetSdkVersion="35" />
          <permission android:name="com.example.SIGNATURE"
              android:protectionLevel="signature" />
          <application>
            <provider android:name=".Data"
                android:authorities="com.example.grants.data"
                android:exported="true"
                android:readPermission="com.example.SIGNATURE"
                android:writePermission="com.example.SIGNATURE">
              <grant-uri-permission android:pathPrefix="/shared" />
            </provider>
          </application>
        </manifest>"""
    )
    provider = next(entry for entry in document.entries if entry.kind == "provider")

    assert provider.metadata["grant_uri_permission_paths"] == [
        {"pathPrefix": "/shared"}
    ]


def test_private_or_disabled_deep_links_are_not_reported_or_scheduled() -> None:
    document = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.links">
          <uses-sdk android:targetSdkVersion="35" />
          <application>
            <activity android:name=".Private" android:exported="false">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="private-demo" android:host="example.test" />
              </intent-filter>
            </activity>
            <activity android:name=".Disabled" android:enabled="false"
                android:exported="true">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="disabled-demo" android:host="example.test" />
              </intent-filter>
            </activity>
          </application>
        </manifest>"""
    )
    deep_links = [entry for entry in document.entries if entry.kind == "deep_link"]
    assert len(deep_links) == 2
    assert {entry.exported for entry in deep_links} == {False, True}
    assert any(entry.metadata["effective_enabled"] is False for entry in deep_links)

    findings = BuiltinRuleEngine()._manifest_rules(document)
    assert not any(item.rule_id.startswith("DEEPLINK-") for item in findings)

    persisted = [
        EntryPoint(
            id=f"00000000-0000-0000-0000-00000000000{index}",
            scan_id="scan",
            kind=entry.kind,
            name=entry.name,
            owner_component=entry.owner_component,
            exported=entry.exported,
            exported_reason=entry.exported_reason,
            metadata_json=entry.metadata,
        )
        for index, entry in enumerate(deep_links, start=1)
    ]
    tasks = InvestigationPlanner(
        android_version="16",
        adb_configured=False,
    ).plan("scan", persisted)
    assert tasks == []


def test_non_activity_intent_filters_do_not_create_deep_link_entries() -> None:
    document = parse_manifest(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.service">
          <uses-sdk android:targetSdkVersion="35" />
          <application>
            <service android:name=".ViewService" android:exported="true">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="service-demo" android:host="example.test" />
              </intent-filter>
            </service>
          </application>
        </manifest>"""
    )

    assert [entry.kind for entry in document.entries] == ["service"]
