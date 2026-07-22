from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from defusedxml import ElementTree

from .enums import EntryPointKind

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def android_attr(element: ElementTree.Element, name: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{name}")


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() == "true"


def normalize_class_name(package_name: str, name: str) -> str:
    if name.startswith("."):
        return f"{package_name}{name}"
    if "." not in name:
        return f"{package_name}.{name}"
    return name


@dataclass(slots=True)
class ParsedEntryPoint:
    kind: str
    name: str
    owner_component: str | None
    exported: bool
    exported_reason: str
    permission: str | None
    permission_protection: str | None
    intent_filters: list[dict[str, Any]] = field(default_factory=list)
    deep_links: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ManifestDocument:
    package_name: str
    version_name: str | None
    version_code: str | None
    min_sdk: int | None
    target_sdk: int | None
    application: dict[str, Any]
    permissions: list[str]
    permission_declarations: dict[str, str]
    entries: list[ParsedEntryPoint]
    raw_xml: str


def _int_attr(element: ElementTree.Element | None, name: str) -> int | None:
    if element is None:
        return None
    value = android_attr(element, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _effective_exported(
    tag: str,
    explicit: str | None,
    has_intent_filter: bool,
    target_sdk: int | None,
) -> tuple[bool, str]:
    if explicit is not None:
        value = parse_bool(explicit)
        return value, f"explicit_{str(value).lower()}"
    if tag == "provider":
        value = target_sdk is not None and target_sdk <= 16
        return value, "legacy_provider_default" if value else "provider_default_false"
    value = has_intent_filter
    if value and target_sdk is not None and target_sdk >= 31:
        return value, "missing_required_attribute_with_filter"
    return value, "intent_filter_default" if value else "component_default_false"


def _intent_filter(filter_element: ElementTree.Element) -> dict[str, Any]:
    actions = [android_attr(item, "name") for item in filter_element.findall("action")]
    categories = [android_attr(item, "name") for item in filter_element.findall("category")]
    data_items: list[dict[str, str]] = []
    for data in filter_element.findall("data"):
        item = {
            key: value
            for key in (
                "scheme",
                "host",
                "port",
                "path",
                "pathPrefix",
                "pathPattern",
                "pathAdvancedPattern",
                "mimeType",
            )
            if (value := android_attr(data, key)) is not None
        }
        data_items.append(item)
    return {
        "actions": [item for item in actions if item],
        "categories": [item for item in categories if item],
        "data": data_items,
        "auto_verify": parse_bool(android_attr(filter_element, "autoVerify")),
        "priority": android_attr(filter_element, "priority"),
    }


def _values(data_items: list[dict[str, str]], key: str) -> list[str | None]:
    found = list(dict.fromkeys(item[key] for item in data_items if key in item))
    return found or [None]


def _expand_deep_links(intent_filter: dict[str, Any], limit: int = 256) -> list[dict[str, Any]]:
    actions = set(intent_filter["actions"])
    categories = set(intent_filter["categories"])
    data_items = intent_filter["data"]
    if "android.intent.action.VIEW" not in actions or not data_items:
        return []
    if "android.intent.category.BROWSABLE" not in categories:
        return []
    schemes = _values(data_items, "scheme")
    if schemes == [None]:
        return []
    hosts = _values(data_items, "host")
    ports = _values(data_items, "port")
    path_variants: list[tuple[str | None, str | None]] = []
    for key in ("path", "pathPrefix", "pathPattern", "pathAdvancedPattern"):
        path_variants.extend((key, value) for value in _values(data_items, key) if value is not None)
    if not path_variants:
        path_variants = [(None, None)]
    links: list[dict[str, Any]] = []
    combinations = itertools.product(schemes, hosts, ports, path_variants)
    for index, (scheme, host, port, path_info) in enumerate(combinations):
        if index >= limit:
            links.append({"truncated": True, "combination_limit": limit})
            break
        path_kind, path_value = path_info
        authority = host or ""
        if port and host:
            authority = f"{host}:{port}"
        rendered_path = path_value or "/"
        uri_template = f"{scheme}://{authority}{rendered_path}"
        links.append(
            {
                "scheme": scheme,
                "host": host,
                "port": port,
                "path_kind": path_kind,
                "path": path_value,
                "uri_template": uri_template,
                "auto_verify": bool(intent_filter["auto_verify"]),
                "verified_scheme": scheme in {"http", "https"},
            }
        )
    return links


def parse_manifest(xml_text: str) -> ManifestDocument:
    root = ElementTree.fromstring(xml_text)
    if root.tag != "manifest":
        raise ValueError("decoded AndroidManifest.xml does not contain a manifest root")
    package_name = root.get("package") or "unknown.package"
    uses_sdk = root.find("uses-sdk")
    min_sdk = _int_attr(uses_sdk, "minSdkVersion")
    target_sdk = _int_attr(uses_sdk, "targetSdkVersion")
    version_name = android_attr(root, "versionName")
    version_code = android_attr(root, "versionCode")
    permission_declarations: dict[str, str] = {}
    for element in root.findall("permission"):
        name = android_attr(element, "name")
        if name:
            permission_declarations[name] = android_attr(element, "protectionLevel") or "normal"
    permissions = [
        value
        for item in root.findall("uses-permission") + root.findall("uses-permission-sdk-23")
        if (value := android_attr(item, "name"))
    ]
    application_element = root.find("application")
    if application_element is None:
        raise ValueError("AndroidManifest.xml is missing the application element")
    application_permission = android_attr(application_element, "permission")
    cleartext_attribute = android_attr(application_element, "usesCleartextTraffic")
    cleartext_default = target_sdk is None or target_sdk <= 27
    application = {
        "name": android_attr(application_element, "name"),
        "debuggable": parse_bool(android_attr(application_element, "debuggable")),
        "allow_backup": parse_bool(android_attr(application_element, "allowBackup"), True),
        "uses_cleartext_traffic": parse_bool(cleartext_attribute, cleartext_default),
        "uses_cleartext_traffic_explicit": cleartext_attribute is not None,
        "network_security_config": android_attr(application_element, "networkSecurityConfig"),
        "test_only": parse_bool(android_attr(application_element, "testOnly")),
        "extract_native_libs": android_attr(application_element, "extractNativeLibs"),
        "permission": application_permission,
    }
    entries: list[ParsedEntryPoint] = []
    tag_kinds = {
        "activity": EntryPointKind.ACTIVITY,
        "activity-alias": EntryPointKind.ACTIVITY_ALIAS,
        "service": EntryPointKind.SERVICE,
        "receiver": EntryPointKind.RECEIVER,
        "provider": EntryPointKind.PROVIDER,
    }
    for tag, kind in tag_kinds.items():
        for component in application_element.findall(tag):
            raw_name = android_attr(component, "name")
            if not raw_name:
                continue
            name = normalize_class_name(package_name, raw_name)
            owner = name
            if tag == "activity-alias":
                target = android_attr(component, "targetActivity")
                owner = normalize_class_name(package_name, target) if target else name
            filters = [_intent_filter(item) for item in component.findall("intent-filter")]
            exported, reason = _effective_exported(
                tag, android_attr(component, "exported"), bool(filters), target_sdk
            )
            permission = android_attr(component, "permission") or application_permission
            if tag == "provider":
                permission = permission or android_attr(component, "readPermission")
            protection = permission_declarations.get(permission) if permission else None
            deep_links = [link for item in filters for link in _expand_deep_links(item)]
            metadata: dict[str, Any] = {
                "enabled": android_attr(component, "enabled"),
                "process": android_attr(component, "process"),
            }
            if tag == "provider":
                metadata.update(
                    {
                        "authorities": android_attr(component, "authorities"),
                        "read_permission": android_attr(component, "readPermission"),
                        "write_permission": android_attr(component, "writePermission"),
                        "grant_uri_permissions": android_attr(component, "grantUriPermissions"),
                    }
                )
            entries.append(
                ParsedEntryPoint(
                    kind=kind.value,
                    name=name,
                    owner_component=owner,
                    exported=exported,
                    exported_reason=reason,
                    permission=permission,
                    permission_protection=protection,
                    intent_filters=filters,
                    deep_links=deep_links,
                    metadata=metadata,
                )
            )
            for filter_index, link in enumerate(deep_links):
                if link.get("truncated"):
                    continue
                entries.append(
                    ParsedEntryPoint(
                        kind=EntryPointKind.DEEP_LINK.value,
                        name=link["uri_template"],
                        owner_component=owner,
                        exported=exported,
                        exported_reason=reason,
                        permission=permission,
                        permission_protection=protection,
                        intent_filters=filters,
                        deep_links=[link],
                        metadata={"filter_link_index": filter_index},
                    )
                )
    return ManifestDocument(
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        application=application,
        permissions=permissions,
        permission_declarations=permission_declarations,
        entries=entries,
        raw_xml=xml_text,
    )
