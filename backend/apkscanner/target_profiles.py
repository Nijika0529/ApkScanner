from __future__ import annotations

from pathlib import Path
from typing import Any

from .enums import Severity
from .rules import StaticReviewSurfaceDraft
from .static_analysis import StaticAnalysisResult

COPILOT_PACKAGE = "com.vivo.ai.copilot"
COPILOT_PROFILE_ID = "vivo_copilot_7x_v1"

_COPILOT_NATIVE_CREDENTIAL_LIBRARIES = {
    "libEncryptorP.so",
    "libaes_wb.so",
    "libsqlcipher.so",
    "libvivoseckey.so",
}
_COPILOT_ZEUS_LIBRARIES = {
    "libzeus_direct_dex.so",
    "libzeusflipped.so",
}

_COPILOT_GROUPS: tuple[tuple[str, set[str], str], ...] = (
    (
        "copilot:web_external_content",
        {"com.vivo.ai.copilot.transfer.EmptyLauncherActivity"},
        "The external route and WebView/JSBridge seed converge on the same externally supplied content chain.",
    ),
    (
        "copilot:wakeup_query_injection",
        {
            "com.vivo.ai.copilot.floating.service.TriggerService",
            "com.vivo.ai.copilot.floating.service.FloatService",
        },
        "Both exported service variants inherit the same wake-up implementation and query trust boundary.",
    ),
    (
        "copilot:zeus_authorization_plugin",
        {
            "com.bytedance.android.dy.sdk.stub.VideoAuthorizeActivityProxy",
            "com.bytedance.android.openlive.broadcast.stub.activity.DouyinAuthorizeActivityProxy",
            "com.bytedance.android.openliveplugin.stub.activity.DouyinAuthorizeActivityLiveProcessProxy",
            "com.bytedance.android.openliveplugin.stub.activity.DouyinAuthorizeActivityProxy",
        },
        "The exported authorization proxies are process variants of the same runtime Zeus plugin authorization boundary.",
    ),
)


def active_profile_id(package_name: str) -> str | None:
    return COPILOT_PROFILE_ID if package_name == COPILOT_PACKAGE else None


def investigation_group(
    *,
    package_name: str,
    name: str,
    owner_component: str | None = None,
    static_family: str | None = None,
    artifact: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if package_name != COPILOT_PACKAGE:
        return None
    candidates = {name}
    if owner_component:
        candidates.add(owner_component)
    for key, members, reason in _COPILOT_GROUPS:
        if candidates & members:
            return _group(key, reason)
    if static_family == "web_content_boundary":
        return _group(
            "copilot:web_external_content",
            "The WebView/JSBridge static seed is analyzed with the exported content-routing entry instead of as a duplicate task.",
        )
    if static_family == "copilot_zeus_runtime_plugin":
        return _group(
            "copilot:zeus_authorization_plugin",
            "Runtime plugin loader evidence is analyzed with its exported authorization proxy variants.",
        )
    if static_family == "copilot_native_credential_boundary":
        return _group(
            "copilot:native_credentials",
            "Credential-related JNI and SO subchains form one bounded Native investigation.",
        )
    if static_family == "embedded_apk":
        origin = (artifact or {}).get("origin") or {}
        archive_path = str(origin.get("archive_path") or "")
        if archive_path.endswith("assets/plugin/entityplugin.apk"):
            return _group(
                "copilot:awareengine_entity_plugin",
                "The preset entity plugin, its host loader, and its plugin entrance are one cross-artifact investigation.",
            )
    return None


def target_review_surfaces(
    result: StaticAnalysisResult,
) -> list[StaticReviewSurfaceDraft]:
    if result.manifest.package_name != COPILOT_PACKAGE:
        return []
    surfaces: list[StaticReviewSurfaceDraft] = []
    zeus = _zeus_surface(result)
    if zeus is not None:
        surfaces.append(zeus)
    native = _native_credential_surface(result)
    if native is not None:
        surfaces.append(native)
    return surfaces


def _group(key: str, reason: str) -> dict[str, Any]:
    return {
        "key": key,
        "strategy": COPILOT_PROFILE_ID,
        "reason": reason,
    }


def _zeus_surface(result: StaticAnalysisResult) -> StaticReviewSurfaceDraft | None:
    nodes = list(result.artifact_graph.get("nodes") or [])
    libraries = [
        node
        for node in nodes
        if node.get("kind") == "native_library"
        and node.get("name") in _COPILOT_ZEUS_LIBRARIES
    ]
    locations = _find_locations(
        result,
        (
            "getPluginClassloader",
            "com.byted.live.lite",
            "LiveAuthCallStub",
        ),
        preferred_path_tokens=("stub/activity", "reflectfacade", "zeusplatformutils"),
    )
    if not libraries and not locations:
        return None
    compact_libraries = _compact_native_assets(libraries)
    return StaticReviewSurfaceDraft(
        name="static://copilot/runtime_plugin/zeus_authorization",
        family="copilot_zeus_runtime_plugin",
        title="Copilot runtime Zeus authorization plugin boundary",
        severity=Severity.HIGH.value,
        priority=96,
        rule_ids=[],
        hypotheses=[
            (
                "An exported authorization proxy forwards attacker-controlled Intent, callback, "
                "or transaction state across a Zeus runtime plugin ClassLoader boundary."
            ),
            (
                "Resolve the downloaded plugin class and callback contract on the device when the "
                "packaged APK cannot close the chain; do not treat the proxy shell as the sink."
            ),
            (
                "Verify authorization state, caller binding, redirect/callback provenance, and "
                "token delivery consistently across main, live-process, and broadcast variants."
            ),
        ],
        locations=locations,
        artifact={
            "kind": "runtime_plugin_boundary",
            "framework": "Zeus",
            "runtime_plugin_packages": ["com.byted.live.lite"],
            "availability": "downloaded_at_runtime",
            "native_assets": compact_libraries,
        },
        investigation_group=_group(
            "copilot:zeus_authorization_plugin",
            "Runtime plugin loader evidence is analyzed with its exported authorization proxy variants.",
        ),
    )


def _native_credential_surface(
    result: StaticAnalysisResult,
) -> StaticReviewSurfaceDraft | None:
    nodes = list(result.artifact_graph.get("nodes") or [])
    node_by_id = {str(node.get("id")): node for node in nodes}
    libraries = [
        node
        for node in nodes
        if node.get("kind") == "native_library"
        and node.get("name") in _COPILOT_NATIVE_CREDENTIAL_LIBRARIES
    ]
    if not libraries:
        return None
    selected_ids = {str(node.get("id")) for node in libraries}
    related_edges = [
        edge
        for edge in result.artifact_graph.get("edges", [])
        if str(edge.get("to")) in selected_ids
        and edge.get("relation")
        in {"loads_native_library", "binds_to_jni", "possible_dynamic_registration"}
    ]
    bridge_nodes = [
        node_by_id[str(edge.get("from"))]
        for edge in related_edges
        if str(edge.get("from")) in node_by_id
        and node_by_id[str(edge.get("from"))].get("kind") == "java_native_bridge"
    ]
    locations: list[dict[str, Any]] = []
    for bridge in bridge_nodes:
        location = _workspace_location(
            result,
            str(bridge.get("path") or ""),
        )
        if location is not None:
            locations.append(location)
    if not locations:
        locations = _find_locations(
            result,
            tuple(
                sorted(
                    {
                        str(node.get("name") or "").removeprefix("lib").removesuffix(".so")
                        for node in libraries
                    }
                )
            ),
            preferred_path_tokens=("whitebox", "cipher", "encrypt", "security", "token"),
        )
    compact_edges = [
        {
            key: edge.get(key)
            for key in (
                "from",
                "to",
                "relation",
                "method_name",
                "jni_symbol",
                "confidence",
            )
            if edge.get(key) is not None
        }
        for edge in related_edges[:30]
    ]
    return StaticReviewSurfaceDraft(
        name="static://copilot/native_credential_boundary",
        family="copilot_native_credential_boundary",
        title="Copilot Native credential and signing boundary",
        severity=Severity.HIGH.value,
        priority=94,
        rule_ids=[],
        hypotheses=[
            (
                "Java/JNI callers can obtain reusable credential, signing, encryption, or database "
                "key material from the selected Native libraries without a caller- or session-bound guarantee."
            ),
            (
                "Trace real release call sites and data consumers before treating hardcoded tables, "
                "weak primitives, or exported symbols as impact; prefer an end-to-end replay or data-access proof."
            ),
            (
                "When static ELF analysis stops at dynamic registration or a packed implementation, "
                "produce an exact device observation plan around the resolved Java bridge instead of "
                "starting unrelated SO investigations."
            ),
        ],
        locations=list(
            {
                (str(item.get("root")), str(item.get("path")), int(item.get("line") or 0)): item
                for item in locations
            }.values()
        )[:12],
        artifact={
            "kind": "native_subchain",
            "native_assets": _compact_native_assets(libraries),
            "java_bridge_classes": sorted(
                {
                    str(node.get("class_name") or node.get("name"))
                    for node in bridge_nodes
                }
            ),
            "graph_edges": compact_edges,
            "artifact_graph_path": "artifact_graph.json",
        },
        investigation_group=_group(
            "copilot:native_credentials",
            "Credential-related JNI and SO subchains form one bounded Native investigation.",
        ),
    )


def _compact_native_assets(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for node in nodes:
        key = (str(node.get("name") or ""), str(node.get("abi") or ""))
        unique[key] = {
            "id": node.get("id"),
            "name": node.get("name"),
            "abi": node.get("abi"),
            "sha256": node.get("sha256"),
            "summary_path": node.get("summary_path"),
            "jni": node.get("jni"),
            "security_relevant_symbols": (node.get("symbols") or {}).get(
                "security_relevant"
            ),
        }
    return list(unique.values())[:24]


def _find_locations(
    result: StaticAnalysisResult,
    needles: tuple[str, ...],
    *,
    preferred_path_tokens: tuple[str, ...],
) -> list[dict[str, Any]]:
    matches: list[tuple[int, dict[str, Any]]] = []
    lowered_needles = tuple(needle.lower() for needle in needles if needle)
    if not lowered_needles:
        return []
    for root in result.searchable_roots:
        if not root.is_dir():
            continue
        for source in sorted(root.rglob("*")):
            if not source.is_file() or source.suffix.lower() not in {
                ".java",
                ".kt",
                ".smali",
                ".json",
                ".js",
            }:
                continue
            try:
                if source.stat().st_size > 4 * 1024 * 1024:
                    continue
                text = source.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lowered = text.lower()
            found = next((needle for needle in lowered_needles if needle in lowered), None)
            if found is None:
                continue
            offset = lowered.find(found)
            path = str(source.relative_to(root))
            score = sum(
                10 for token in preferred_path_tokens if token in path.lower()
            )
            matches.append(
                (
                    score,
                    {
                        "root": _root_label(root, result.workspace),
                        "path": path,
                        "line": text.count("\n", 0, offset) + 1,
                    },
                )
            )
    matches.sort(key=lambda item: (-item[0], str(item[1]["path"])))
    return [item for _score, item in matches[:12]]


def _workspace_location(
    result: StaticAnalysisResult,
    workspace_path: str,
) -> dict[str, Any] | None:
    source = result.workspace / workspace_path
    for root in result.searchable_roots:
        try:
            relative = source.resolve().relative_to(root.resolve())
        except ValueError:
            continue
        return {
            "root": _root_label(root, result.workspace),
            "path": str(relative),
            "line": 1,
        }
    return None


def _root_label(root: Path, workspace: Path) -> str:
    try:
        return str(root.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return root.name
