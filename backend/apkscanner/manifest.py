from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as StdElementTree

from defusedxml import ElementTree

from .enums import EntryPointKind

ANDROID_NS = "http://schemas.android.com/apk/res/android"

_AAPT2_ELEMENT = re.compile(r"^(?P<indent>\s*)E:\s+(?P<tag>[^\s]+)(?:\s+\(line=\d+\))?$")
_AAPT2_ATTRIBUTE = re.compile(
    r"^(?P<indent>\s*)A:\s+(?P<name>.+?)(?:\(0x[0-9a-fA-F]+\))?=(?P<value>.*)$"
)
_AAPT2_RAW_VALUE = re.compile(r'\s+\(Raw:\s+"(?P<value>(?:[^"\\]|\\.)*)"\)\s*$')


def android_attr(element: ElementTree.Element, name: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{name}")


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return default


def normalize_class_name(package_name: str, name: str) -> str:
    if name.startswith("."):
        return f"{package_name}{name}"
    if "." not in name:
        return f"{package_name}.{name}"
    return name


def _decode_aapt2_quoted(value: str) -> str:
    try:
        return str(json.loads(f'"{value}"'))
    except (json.JSONDecodeError, TypeError):
        return value.replace(r"\"", '"').replace(r"\\", "\\")


def _decode_aapt2_protection_level(value: str) -> str:
    try:
        numeric = int(value, 0)
    except ValueError:
        return value
    base = {
        0: "normal",
        1: "dangerous",
        2: "signature",
        3: "signatureOrSystem",
    }.get(numeric & 0xF, str(numeric & 0xF))
    flags = [
        name
        for bit, name in (
            (0x10, "privileged"),
            (0x20, "development"),
            (0x40, "appop"),
            (0x80, "pre23"),
            (0x100, "installer"),
            (0x200, "verifier"),
            (0x400, "preinstalled"),
            (0x800, "setup"),
            (0x1000, "instant"),
            (0x2000, "runtime"),
            (0x4000, "oem"),
            (0x8000, "vendorPrivileged"),
        )
        if numeric & bit
    ]
    return "|".join([base, *flags])


def _decode_aapt2_attribute_value(name: str, value: str) -> str:
    raw_match = _AAPT2_RAW_VALUE.search(value)
    if raw_match:
        return _decode_aapt2_quoted(raw_match.group("value"))
    normalized = value.strip()
    if len(normalized) >= 2 and normalized[0] == normalized[-1] == '"':
        return _decode_aapt2_quoted(normalized[1:-1])
    local_name = name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]
    if local_name == "protectionLevel":
        return _decode_aapt2_protection_level(normalized)
    return normalized


def aapt2_xmltree_to_xml(text: str) -> str:
    """Convert ``aapt2 dump xmltree`` output into parseable manifest XML.

    This is intentionally limited to the element/attribute records needed by
    AndroidManifest parsing. It provides a framework-independent fallback for
    OEM APKs whose resources require vendor framework packages that Apktool
    does not have installed.
    """

    root: StdElementTree.Element | None = None
    stack: list[tuple[int, StdElementTree.Element]] = []
    for raw_line in text.splitlines():
        element_match = _AAPT2_ELEMENT.match(raw_line)
        if element_match:
            indent = len(element_match.group("indent"))
            element = StdElementTree.Element(element_match.group("tag"))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1].append(element)
            elif root is None:
                root = element
            else:
                raise ValueError("aapt2 xmltree contains multiple root elements")
            stack.append((indent, element))
            continue

        attribute_match = _AAPT2_ATTRIBUTE.match(raw_line)
        if attribute_match is None or not stack:
            continue
        name = attribute_match.group("name")
        if name.startswith(f"{ANDROID_NS}:"):
            name = f"{{{ANDROID_NS}}}{name[len(ANDROID_NS) + 1:]}"
        value = _decode_aapt2_attribute_value(
            name,
            attribute_match.group("value"),
        )
        stack[-1][1].set(name, value)

    if root is None or root.tag != "manifest":
        raise ValueError("aapt2 xmltree output does not contain a manifest root")
    StdElementTree.register_namespace("android", ANDROID_NS)
    return StdElementTree.tostring(root, encoding="unicode")


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
    target_sdk_attribute = (
        android_attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    )
    effective_target_sdk = (
        target_sdk
        if target_sdk is not None
        else (min_sdk if min_sdk is not None else 1)
        if target_sdk_attribute is None
        else None
    )
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
    application_enabled = parse_bool(
        android_attr(application_element, "enabled"),
        True,
    )
    cleartext_attribute = android_attr(application_element, "usesCleartextTraffic")
    cleartext_default = effective_target_sdk is None or effective_target_sdk <= 27
    application = {
        "name": android_attr(application_element, "name"),
        "enabled": application_enabled,
        "debuggable": parse_bool(android_attr(application_element, "debuggable")),
        "allow_backup": parse_bool(android_attr(application_element, "allowBackup"), True),
        "uses_cleartext_traffic": parse_bool(cleartext_attribute, cleartext_default),
        "uses_cleartext_traffic_explicit": cleartext_attribute is not None,
        "network_security_config": android_attr(application_element, "networkSecurityConfig"),
        "test_only": parse_bool(android_attr(application_element, "testOnly")),
        "extract_native_libs": android_attr(application_element, "extractNativeLibs"),
        "permission": application_permission,
        "effective_target_sdk": effective_target_sdk,
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
                tag,
                android_attr(component, "exported"),
                bool(filters),
                effective_target_sdk,
            )
            declared_permission = android_attr(component, "permission")
            permission = (
                declared_permission
                if tag == "activity-alias"
                else declared_permission or application_permission
            )
            provider_permissions: dict[str, Any] = {}
            if tag == "provider":
                read_permission = android_attr(component, "readPermission") or permission
                write_permission = android_attr(component, "writePermission") or permission
                read_protection = (
                    permission_declarations.get(read_permission)
                    if read_permission
                    else None
                )
                write_protection = (
                    permission_declarations.get(write_permission)
                    if write_permission
                    else None
                )
                provider_permissions = {
                    "effective_read_permission": read_permission,
                    "effective_read_permission_protection": read_protection,
                    "effective_write_permission": write_permission,
                    "effective_write_permission_protection": write_protection,
                }
                path_permissions: list[dict[str, str | None]] = []
                path_access_boundaries: list[tuple[str | None, str | None]] = []
                for path_permission in component.findall("path-permission"):
                    common_path_permission = android_attr(path_permission, "permission")
                    path_read_permission = (
                        android_attr(path_permission, "readPermission")
                        or common_path_permission
                        or read_permission
                    )
                    path_write_permission = (
                        android_attr(path_permission, "writePermission")
                        or common_path_permission
                        or write_permission
                    )
                    path_read_protection = (
                        permission_declarations.get(path_read_permission)
                        if path_read_permission
                        else None
                    )
                    path_write_protection = (
                        permission_declarations.get(path_write_permission)
                        if path_write_permission
                        else None
                    )
                    path_match = next(
                        (
                            (key, value)
                            for key in (
                                "path",
                                "pathPrefix",
                                "pathPattern",
                                "pathAdvancedPattern",
                            )
                            if (value := android_attr(path_permission, key)) is not None
                        ),
                        (None, None),
                    )
                    path_permissions.append(
                        {
                            "path_kind": path_match[0],
                            "path": path_match[1],
                            "permission": common_path_permission,
                            "effective_read_permission": path_read_permission,
                            "effective_read_permission_protection": path_read_protection,
                            "effective_write_permission": path_write_permission,
                            "effective_write_permission_protection": path_write_protection,
                        }
                    )
                    path_access_boundaries.extend(
                        (
                            (path_read_permission, path_read_protection),
                            (path_write_permission, path_write_protection),
                        )
                    )
                provider_permissions["path_permissions"] = path_permissions
                provider_permissions["grant_uri_permission_paths"] = [
                    {
                        key: value
                        for key in (
                            "path",
                            "pathPrefix",
                            "pathPattern",
                        )
                        if (value := android_attr(grant, key)) is not None
                    }
                    for grant in component.findall("grant-uri-permission")
                ]
                access_boundaries = (
                    (read_permission, read_protection),
                    (write_permission, write_protection),
                    *path_access_boundaries,
                )
                permission, protection = next(
                    (
                        (candidate_permission, candidate_protection)
                        for candidate_permission, candidate_protection in access_boundaries
                        if candidate_permission is None
                        or "signature" not in (candidate_protection or "").lower()
                    ),
                    access_boundaries[0],
                )
            else:
                protection = (
                    permission_declarations.get(permission) if permission else None
                )
            deep_links = (
                [link for item in filters for link in _expand_deep_links(item)]
                if tag in {"activity", "activity-alias"}
                else []
            )
            component_enabled = parse_bool(android_attr(component, "enabled"), True)
            metadata: dict[str, Any] = {
                "enabled": android_attr(component, "enabled"),
                "application_enabled": application_enabled,
                "effective_enabled": application_enabled and component_enabled,
                "process": android_attr(component, "process"),
                **provider_permissions,
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
                        metadata={
                            **metadata,
                            "filter_link_index": filter_index,
                        },
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
