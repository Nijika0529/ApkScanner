from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .enums import EntryPointKind, Severity
from .manifest import ManifestDocument

ANALYSIS_SCHEMA_VERSION = "1.0"
ANALYSIS_ENGINE_VERSION = "bounded-android-chain-v2"


@dataclass(frozen=True, slots=True)
class MarkerPattern:
    name: str
    patterns: tuple[re.Pattern[str], ...]


@dataclass(slots=True)
class CodeNode:
    class_name: str
    root: str
    path: str
    content: str
    references: set[str] = field(default_factory=set)
    markers: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ChainSpec:
    family: str
    chain_kind: str
    title: str
    severity: str
    priority: int
    sources: frozenset[str]
    sinks: frozenset[str]
    risks: frozenset[str]
    guards: frozenset[str]
    max_hops: int = 3
    endpoint_discovery: bool = False


def _patterns(*values: str, flags: int = 0) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, flags) for value in values)


MARKERS = (
    MarkerPattern(
        "pending_intent_create",
        _patterns(
            r"\bPendingIntent\s*\.\s*get(?:Activity|Activities|Service|ForegroundService|Broadcast)\s*\(",
            r"Landroid/app/PendingIntent;->get(?:Activity|Activities|Service|ForegroundService|Broadcast)\(",
        ),
    ),
    MarkerPattern(
        "pending_intent_mutable",
        _patterns(r"\bFLAG_MUTABLE\b", r"PendingIntent;->FLAG_MUTABLE"),
    ),
    MarkerPattern(
        "pending_intent_immutable",
        _patterns(r"\bFLAG_IMMUTABLE\b", r"PendingIntent;->FLAG_IMMUTABLE"),
    ),
    MarkerPattern("pending_intent_one_shot", _patterns(r"\bFLAG_ONE_SHOT\b")),
    MarkerPattern(
        "pending_allow_unsafe_implicit",
        _patterns(r"\bFLAG_ALLOW_UNSAFE_IMPLICIT_INTENT\b"),
    ),
    MarkerPattern(
        "pending_intent_creator_identity",
        _patterns(r"\bgetCreator(?:Package|Uid|UserHandle)\s*\(", r"->getCreator(?:Package|Uid|UserHandle)\("),
    ),
    MarkerPattern(
        "pending_base_implicit",
        _patterns(
            r"(?s)new\s+Intent\s*\(\s*[\"'].{0,800}?"
            r"PendingIntent\s*\.\s*get(?:Activity|Activities|Service|ForegroundService|Broadcast)\s*\(",
        ),
    ),
    MarkerPattern(
        "pending_base_explicit",
        _patterns(
            r"(?s)new\s+Intent\s*\(.{0,240}\.(?:class|javaClass)"
            r".{0,800}?PendingIntent\s*\.\s*get"
            r"(?:Activity|Activities|Service|ForegroundService|Broadcast)\s*\(",
        ),
    ),
    MarkerPattern(
        "implicit_intent_candidate",
        _patterns(
            r"new\s+Intent\s*\(\s*(?:[\"']|[A-Za-z_$][\w$]*\s*\))",
            r"\.setAction\s*\(",
            r"Landroid/content/Intent;-><init>\(Ljava/lang/String;\)",
        ),
    ),
    MarkerPattern(
        "explicit_intent_target",
        _patterns(
            r"new\s+Intent\s*\([^\n;]{0,180}\.(?:class|javaClass)",
            r"\.(?:setClass|setClassName|setComponent|setPackage)\s*\(",
            r"Landroid/content/Intent;->set(?:Class|ClassName|Component|Package)\(",
        ),
    ),
    MarkerPattern(
        "pending_intent_escape",
        _patterns(
            r"\.(?:setContentIntent|setDeleteIntent|addAction|setPendingIntentTemplate|setOnClickPendingIntent)\s*\(",
            r"\.(?:putExtra|putParcelable|setResult)\s*\([^\n;]{0,180}(?:pendingIntent|intentSender)",
            r"Landroid/(?:app/Notification|widget/RemoteViews)[^;]*;->(?:set|add)[A-Za-z]+Intent",
        ),
    ),
    MarkerPattern(
        "pending_intent_send",
        _patterns(r"\bPendingIntent[^\n]{0,120}\.send\s*\(", r"Landroid/app/PendingIntent;->send\("),
    ),
    MarkerPattern(
        "nested_intent_input",
        _patterns(
            r"\b(?:EXTRA_INTENT|EXTRA_INITIAL_INTENTS)\b",
            r"getParcelableExtra\s*<\s*Intent\s*>\s*\(",
            r"getParcelable\s*<\s*Intent\s*>\s*\(",
            r"getParcelableExtra\s*\([^\n,]+,\s*Intent\s*\.\s*class\s*\)",
            r"(?:\(\s*Intent\s*\)|Intent\s+[A-Za-z_$][\w$]*\s*=)"
            r"[^\n;]{0,240}getParcelable(?:Extra)?\s*\(",
            r"Intent\s*\.\s*parseUri\s*\(",
            r"Landroid/content/Intent;->parseUri\(",
        ),
    ),
    MarkerPattern(
        "intent_sanitizer",
        _patterns(
            r"\bIntentSanitizer\b",
            r"\.allow(?:Component|Package|Action|Data|Type|Extra)",
            r"(?:getComponent|getPackage)\s*\(\)[^\n]{0,160}(?:equals|contains|matches)",
        ),
    ),
    MarkerPattern(
        "intent_dispatch",
        _patterns(
            r"\bstart(?:Activity|Activities|Service|ForegroundService)\s*\(",
            r"\bsend(?:Ordered|Sticky)?Broadcast\s*\(",
            r"Landroid/content/Context[^;]*;->(?:startActivity|startActivities|startService|startForegroundService|sendBroadcast|sendOrderedBroadcast)\(",
        ),
    ),
    MarkerPattern(
        "external_uri_input",
        _patterns(
            r"\bgetIntent\s*\(\s*\)\s*\.\s*getData",
            r"\b(?:intent|data)\s*\.\s*getData\s*\(",
            r"\bgetClipData\s*\(",
            r"\bEXTRA_STREAM\b",
            r"(?:\(\s*Uri\s*\)|Uri\s+[A-Za-z_$][\w$]*\s*=)"
            r"[^\n;]{0,240}getParcelableExtra\s*\(",
            r"Landroid/content/Intent;->get(?:Data|ClipData)\(",
        ),
    ),
    MarkerPattern(
        "uri_grant",
        _patterns(
            r"\bgrantUriPermission\s*\(",
            r"\bFLAG_GRANT_(?:READ|WRITE)_URI_PERMISSION\b",
            r"Landroid/content/Context[^;]*;->grantUriPermission\(",
        ),
    ),
    MarkerPattern(
        "uri_grant_persisted",
        _patterns(r"\btakePersistableUriPermission\s*\(", r"->takePersistableUriPermission\("),
    ),
    MarkerPattern(
        "uri_clipdata",
        _patterns(r"\bClipData\s*\.\s*new(?:Uri|RawUri)\s*\(", r"\bsetClipData\s*\("),
    ),
    MarkerPattern(
        "action_send_ingress",
        _patterns(r"\bACTION_SEND(?:_MULTIPLE)?\b", r"android\.intent\.action\.SEND(?:_MULTIPLE)?"),
    ),
    MarkerPattern(
        "saf_ingress",
        _patterns(
            r"\bACTION_(?:OPEN_DOCUMENT|OPEN_DOCUMENT_TREE|GET_CONTENT)\b",
            r"ActivityResultContracts\s*\.\s*(?:OpenDocument|OpenMultipleDocuments|GetContent|GetMultipleContents)",
            r"\bDocumentFile\b",
        ),
    ),
    MarkerPattern(
        "content_stream_input",
        _patterns(
            r"\bContentResolver[^\n]{0,120}\.(?:openInputStream|openAssetFileDescriptor|openFileDescriptor|query)\s*\(",
            r"\bopenInputStream\s*\(",
            r"Landroid/content/ContentResolver;->(?:openInputStream|openAssetFileDescriptor|openFileDescriptor|query)\(",
            r"\bOpenableColumns\s*\.\s*DISPLAY_NAME\b",
            r"[\"']_display_name[\"']",
        ),
    ),
    MarkerPattern(
        "fileprovider_usage",
        _patterns(
            r"\bFileProvider\s*\.\s*getUriForFile\s*\(",
            r"Landroidx?/core/content/FileProvider;->getUriForFile\(",
        ),
    ),
    MarkerPattern(
        "archive_entry_input",
        _patterns(
            r"\b(?:ZipInputStream|ZipFile|ZipEntry|TarArchiveInputStream|TarArchiveEntry|SevenZFile|JarInputStream)\b",
            r"Ljava/util/zip/(?:ZipInputStream|ZipFile|ZipEntry);",
        ),
    ),
    MarkerPattern(
        "file_write",
        _patterns(
            r"\b(?:FileOutputStream|FileWriter|RandomAccessFile)\s*\(",
            r"\bFiles\s*\.\s*(?:copy|move|write)\s*\(",
            r"\b(?:copyTo|writeBytes|writeText|renameTo)\s*\(",
            r"Ljava/io/(?:FileOutputStream|FileWriter|RandomAccessFile);-><init>",
            r"Ljava/nio/file/Files;->(?:copy|move|write)\(",
        ),
    ),
    MarkerPattern(
        "path_containment_guard",
        _patterns(
            r"\b(?:getCanonicalPath|getCanonicalFile|toRealPath|normalize)\s*\(",
            r"\bisChild(?:Path|File)\s*\(",
            r"NOFOLLOW_LINKS",
        ),
    ),
    MarkerPattern(
        "dynamic_receiver_register",
        _patterns(
            r"\b(?:ContextCompat\s*\.\s*)?registerReceiver\s*\(",
            r"Landroid/content/Context[^;]*;->registerReceiver\(",
            r"Landroidx/core/content/ContextCompat;->registerReceiver\(",
        ),
    ),
    MarkerPattern("receiver_exported", _patterns(r"\bRECEIVER_EXPORTED\b")),
    MarkerPattern("receiver_not_exported", _patterns(r"\bRECEIVER_NOT_EXPORTED\b")),
    MarkerPattern(
        "receiver_callback",
        _patterns(r"\bvoid\s+onReceive\s*\(", r"\bfun\s+onReceive\s*\(", r"->onReceive\("),
    ),
    MarkerPattern(
        "receiver_permission_guard",
        _patterns(
            r"registerReceiver\s*\([^;\n]{0,360}[\"'][A-Za-z0-9_.]+\.(?:permission|PERMISSION)[A-Za-z0-9_.]*[\"']",
            r"\b(?:check|enforce)Calling(?:OrSelf)?Permission\s*\(",
        ),
    ),
    MarkerPattern(
        "local_server",
        _patterns(
            r"\b(?:new\s+)?ServerSocket\s*\(",
            r"\bLocalServerSocket\s*\(",
            r"\bNanoHTTPD\s*\(",
            r"\bembeddedServer\s*\(",
            r"\bLocalSocketAddress\s*\(",
            r"\bAF_UNIX\b",
            r"\bStructSockaddrUnix\b",
            r"Ljava/net/ServerSocket;-><init>",
            r"Landroid/net/LocalServerSocket;-><init>",
        ),
    ),
    MarkerPattern(
        "local_server_accept",
        _patterns(r"\baccept\s*\(\s*\)", r"->accept\(\)", r"\bserve\s*\(", r"\bchannelRead\s*\("),
    ),
    MarkerPattern(
        "local_server_broad_bind",
        _patterns(r"[\"']0\.0\.0\.0[\"']", r"\bInetAddress\s*\.\s*getByName\s*\(\s*[\"']0\.0\.0\.0"),
    ),
    MarkerPattern(
        "socket_peer_guard",
        _patterns(
            r"\b(?:getPeerCredentials|SO_PEERCRED|StructUcred|PeerCredentials)\b",
            r"\b(?:Authorization|authenticate|verifyToken|checkToken|HmacSHA)\b",
        ),
    ),
    MarkerPattern(
        "web_external_input",
        _patterns(
            r"\bgetIntent\s*\(\s*\)\s*\.\s*(?:getData|getStringExtra|getExtras)",
            r"\b(?:intent|data)\s*\.\s*(?:getData|getStringExtra|getExtras)\s*\(",
            r"\bshouldOverrideUrlLoading\s*\(",
            r"\bWebResourceRequest[^\n]{0,120}\.getUrl\s*\(",
            r"Landroid/content/Intent;->get(?:Data|StringExtra|Extras)\(",
            r"Landroid/webkit/WebResourceRequest;->getUrl\(",
        ),
    ),
    MarkerPattern(
        "webview_load",
        _patterns(
            r"\b(?:loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript|postWebMessage)\s*\(",
            r"Landroid/webkit/WebView;->(?:loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript|postWebMessage)\(",
        ),
    ),
    MarkerPattern(
        "webview_bridge",
        _patterns(r"\baddJavascriptInterface\s*\(", r"Landroid/webkit/WebView;->addJavascriptInterface\("),
    ),
    MarkerPattern(
        "webview_unsafe_setting",
        _patterns(
            r"\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true",
            r"\bsetAllowFileAccessFromFileURLs\s*\(\s*true",
            r"\bsetMixedContentMode\s*\([^\n]*(?:MIXED_CONTENT_ALWAYS_ALLOW|0)\s*\)",
            r"\bsetWebContentsDebuggingEnabled\s*\(\s*true",
        ),
    ),
    MarkerPattern(
        "web_origin_guard",
        _patterns(
            r"\bWebViewAssetLoader\b",
            r"\bUri[^\n]{0,160}\.(?:getScheme|getHost)\s*\(",
            r"\b(?:uri|url|host|origin)[^\n]{0,160}\.(?:equals|matches)\s*\(",
            r"\b(?:allowlist|allowedHosts|trustedOrigins)\b",
        ),
    ),
)


MARKER_NEEDLES: dict[str, tuple[str, ...]] = {
    "pending_intent_create": ("PendingIntent",),
    "pending_intent_mutable": ("FLAG_MUTABLE",),
    "pending_intent_immutable": ("FLAG_IMMUTABLE",),
    "pending_intent_one_shot": ("FLAG_ONE_SHOT",),
    "pending_allow_unsafe_implicit": ("FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT",),
    "pending_intent_creator_identity": ("getCreator",),
    "pending_base_implicit": ("PendingIntent",),
    "pending_base_explicit": ("PendingIntent",),
    "implicit_intent_candidate": ("Intent",),
    "explicit_intent_target": ("Intent", "setComponent", "setPackage"),
    "pending_intent_escape": ("PendingIntent", "ContentIntent", "IntentTemplate"),
    "pending_intent_send": ("PendingIntent",),
    "nested_intent_input": ("EXTRA_INTENT", "Parcelable", "parseUri"),
    "intent_sanitizer": ("IntentSanitizer", "getComponent", "getPackage"),
    "intent_dispatch": ("startActivity", "startService", "sendBroadcast"),
    "external_uri_input": ("getData", "getClipData", "EXTRA_STREAM", "Parcelable"),
    "uri_grant": ("grantUriPermission", "FLAG_GRANT_"),
    "uri_grant_persisted": ("takePersistableUriPermission",),
    "uri_clipdata": ("ClipData", "setClipData"),
    "action_send_ingress": ("ACTION_SEND", "android.intent.action.SEND"),
    "saf_ingress": ("OPEN_DOCUMENT", "GET_CONTENT", "DocumentFile", "OpenDocument"),
    "content_stream_input": (
        "ContentResolver",
        "openInputStream",
        "openFileDescriptor",
        "OpenableColumns",
        "_display_name",
    ),
    "fileprovider_usage": ("FileProvider",),
    "archive_entry_input": ("Zip", "TarArchive", "SevenZ", "JarInputStream"),
    "file_write": (
        "FileOutputStream",
        "FileWriter",
        "RandomAccessFile",
        "Files;->",
        "Files.",
        "copyTo",
        "writeBytes",
        "writeText",
        "renameTo",
    ),
    "path_containment_guard": (
        "Canonical",
        "canonical",
        "toRealPath",
        "normalize",
        "NOFOLLOW_LINKS",
    ),
    "dynamic_receiver_register": ("registerReceiver",),
    "receiver_exported": ("RECEIVER_EXPORTED",),
    "receiver_not_exported": ("RECEIVER_NOT_EXPORTED",),
    "receiver_callback": ("onReceive",),
    "receiver_permission_guard": ("Permission", "permission"),
    "local_server": (
        "ServerSocket",
        "LocalServerSocket",
        "NanoHTTPD",
        "embeddedServer",
        "AF_UNIX",
        "StructSockaddrUnix",
    ),
    "local_server_accept": ("accept", "serve", "channelRead"),
    "local_server_broad_bind": ("0.0.0.0",),
    "socket_peer_guard": (
        "PeerCredentials",
        "PEERCRED",
        "Authorization",
        "authenticate",
        "verifyToken",
        "checkToken",
        "HmacSHA",
    ),
    "web_external_input": (
        "getIntent",
        "getStringExtra",
        "shouldOverrideUrlLoading",
        "WebResourceRequest",
    ),
    "webview_load": (
        "loadUrl",
        "loadData",
        "evaluateJavascript",
        "postWebMessage",
    ),
    "webview_bridge": ("addJavascriptInterface",),
    "webview_unsafe_setting": (
        "setAllowUniversalAccessFromFileURLs",
        "setAllowFileAccessFromFileURLs",
        "setMixedContentMode",
        "setWebContentsDebuggingEnabled",
    ),
    "web_origin_guard": (
        "WebViewAssetLoader",
        "getScheme",
        "getHost",
        "allowlist",
        "allowedHosts",
        "trustedOrigins",
    ),
}


CHAIN_SPECS = (
    ChainSpec(
        family="capability_delegation_boundary",
        chain_kind="pending_intent_delegation",
        title="PendingIntent capability delegation",
        severity=Severity.HIGH.value,
        priority=97,
        sources=frozenset({"pending_intent_create"}),
        sinks=frozenset({"pending_intent_escape", "pending_intent_send"}),
        risks=frozenset(
            {
                "pending_intent_mutable",
                "pending_base_implicit",
                "pending_allow_unsafe_implicit",
                "pending_intent_creator_identity",
            }
        ),
        guards=frozenset(
            {
                "pending_intent_immutable",
                "pending_intent_one_shot",
                "pending_base_explicit",
            }
        ),
    ),
    ChainSpec(
        family="capability_delegation_boundary",
        chain_kind="nested_intent_redirection",
        title="Nested Intent redirection",
        severity=Severity.HIGH.value,
        priority=98,
        sources=frozenset({"nested_intent_input"}),
        sinks=frozenset({"intent_dispatch"}),
        risks=frozenset({"implicit_intent_candidate", "uri_grant"}),
        guards=frozenset({"intent_sanitizer", "explicit_intent_target"}),
    ),
    ChainSpec(
        family="capability_delegation_boundary",
        chain_kind="uri_permission_redelegation",
        title="Content URI permission propagation",
        severity=Severity.HIGH.value,
        priority=97,
        sources=frozenset({"external_uri_input", "uri_clipdata"}),
        sinks=frozenset({"uri_grant", "uri_grant_persisted"}),
        risks=frozenset({"uri_grant", "uri_grant_persisted", "uri_clipdata"}),
        guards=frozenset({"explicit_intent_target"}),
    ),
    ChainSpec(
        family="external_file_ingress_boundary",
        chain_kind="external_content_to_private_file",
        title="External content stream to filesystem",
        severity=Severity.HIGH.value,
        priority=96,
        sources=frozenset(
            {"action_send_ingress", "saf_ingress", "content_stream_input", "external_uri_input"}
        ),
        sinks=frozenset({"file_write"}),
        risks=frozenset({"archive_entry_input", "fileprovider_usage"}),
        guards=frozenset({"path_containment_guard"}),
    ),
    ChainSpec(
        family="external_file_ingress_boundary",
        chain_kind="external_archive_extraction",
        title="External archive extraction",
        severity=Severity.HIGH.value,
        priority=97,
        sources=frozenset(
            {"action_send_ingress", "saf_ingress", "content_stream_input", "external_uri_input"}
        ),
        sinks=frozenset({"archive_entry_input"}),
        risks=frozenset({"file_write"}),
        guards=frozenset({"path_containment_guard"}),
    ),
    ChainSpec(
        family="runtime_ipc_boundary",
        chain_kind="dynamic_broadcast_receiver",
        title="Context-registered broadcast receiver",
        severity=Severity.MEDIUM.value,
        priority=93,
        sources=frozenset({"dynamic_receiver_register"}),
        sinks=frozenset({"receiver_callback"}),
        risks=frozenset({"receiver_exported", "intent_dispatch", "file_write"}),
        guards=frozenset({"receiver_not_exported", "receiver_permission_guard"}),
        endpoint_discovery=True,
    ),
    ChainSpec(
        family="runtime_ipc_boundary",
        chain_kind="local_tcp_or_unix_server",
        title="Local TCP or Unix-domain server",
        severity=Severity.HIGH.value,
        priority=95,
        sources=frozenset({"local_server"}),
        sinks=frozenset({"local_server_accept"}),
        risks=frozenset({"local_server_broad_bind", "intent_dispatch", "file_write"}),
        guards=frozenset({"socket_peer_guard"}),
        endpoint_discovery=True,
    ),
    ChainSpec(
        family="web_content_boundary",
        chain_kind="external_input_to_webview",
        title="External input to WebView content",
        severity=Severity.HIGH.value,
        priority=97,
        sources=frozenset(
            {"web_external_input", "external_uri_input", "content_stream_input", "action_send_ingress"}
        ),
        sinks=frozenset({"webview_load", "webview_bridge"}),
        risks=frozenset({"webview_bridge", "webview_unsafe_setting"}),
        guards=frozenset({"web_origin_guard"}),
    ),
)


class AndroidAttackChainAnalyzer:
    """Build bounded, explainable candidate chains over app-owned decompiled code.

    This is deliberately a candidate generator rather than a vulnerability verdict. It
    combines semantic markers with exact app-class references and records both risky
    operations and nearby guards for the later Codex investigation.
    """

    def __init__(self, *, max_nodes: int = 12_000, max_bytes: int = 250_000_000):
        self.max_nodes = max_nodes
        self.max_bytes = max_bytes

    def analyze(
        self,
        manifest: ManifestDocument,
        roots: Iterable[Path],
    ) -> list[dict[str, Any]]:
        root_list = list(roots)
        nodes = self._index_nodes(manifest, root_list)
        if not nodes:
            return self._fileprovider_configuration_chains(manifest, root_list)
        self._inject_manifest_sources(manifest, nodes)
        adjacency = self._build_adjacency(nodes)
        candidates: list[dict[str, Any]] = []
        for spec in CHAIN_SPECS:
            candidates.extend(self._chains_for_spec(manifest, nodes, adjacency, spec))
        candidates.extend(self._fileprovider_configuration_chains(manifest, root_list))
        unique = {str(item["fingerprint"]): item for item in candidates}
        return sorted(
            unique.values(),
            key=lambda item: (
                -int(item.get("priority") or 0),
                str(item.get("family") or ""),
                str(item.get("chain_kind") or ""),
                str(item.get("fingerprint") or ""),
            ),
        )[:80]

    def _index_nodes(
        self,
        manifest: ManifestDocument,
        roots: Iterable[Path],
    ) -> dict[str, CodeNode]:
        package_name = manifest.package_name
        package_parts = package_name.split(".")
        owned_prefixes = {package_name}
        if len(package_parts) >= 4:
            owned_prefixes.add(".".join(package_parts[:3]))
        component_names = {
            str(entry.owner_component or entry.name).split("$", 1)[0]
            for entry in manifest.entries
            if entry.owner_component or entry.name
        }
        nodes: dict[str, CodeNode] = {}
        total_bytes = 0
        for root in roots:
            if not root.is_dir():
                continue
            for path in self._candidate_code_paths(
                root,
                owned_prefixes=owned_prefixes,
                component_names=component_names,
            ):
                if len(nodes) >= self.max_nodes or total_bytes >= self.max_bytes:
                    return nodes
                if not path.is_file() or path.suffix.lower() not in {".java", ".kt", ".smali"}:
                    continue
                try:
                    relative = path.relative_to(root)
                    size = path.stat().st_size
                except OSError:
                    continue
                if size > 2_000_000:
                    continue
                logical = self._logical_class(relative)
                if logical is None or not self._belongs_to_app(
                    logical,
                    owned_prefixes,
                    component_names,
                ):
                    continue
                # Prefer JADX Java/Kotlin over duplicate Apktool/archive Smali.
                if logical in nodes:
                    continue
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                total_bytes += size
                node = CodeNode(
                    class_name=logical,
                    root=root.name,
                    path=str(PurePosixPath(*relative.parts)),
                    content=content,
                )
                node.markers = self._find_markers(node)
                self._augment_smali_markers(node)
                nodes[logical] = node
        return nodes

    @staticmethod
    def _candidate_code_paths(
        root: Path,
        *,
        owned_prefixes: set[str],
        component_names: set[str],
    ) -> list[Path]:
        search_bases = [root]
        sources = root / "sources"
        if sources.is_dir():
            search_bases.insert(0, sources)
        search_bases.extend(
            path for path in sorted(root.glob("smali*")) if path.is_dir()
        )
        candidates: set[Path] = set()
        for base in search_bases:
            for prefix in owned_prefixes:
                directory = base.joinpath(*prefix.split("."))
                if not directory.is_dir():
                    continue
                for suffix in ("*.java", "*.kt", "*.smali"):
                    candidates.update(directory.rglob(suffix))
            for component in component_names:
                descriptor = Path(*component.split("."))
                for suffix in (".java", ".kt", ".smali"):
                    candidate = base / descriptor.with_suffix(suffix)
                    if candidate.is_file():
                        candidates.add(candidate)
                parent = base / descriptor.parent
                if parent.is_dir():
                    candidates.update(parent.glob(f"{descriptor.name}$*.smali"))
        return sorted(candidates)

    @staticmethod
    def _logical_class(relative: Path) -> str | None:
        parts = list(relative.with_suffix("").parts)
        if parts and parts[0] == "sources":
            parts.pop(0)
        if parts and parts[0].startswith("smali"):
            parts.pop(0)
        if not parts:
            return None
        return ".".join(parts)

    @staticmethod
    def _belongs_to_app(
        logical: str,
        owned_prefixes: set[str],
        component_names: set[str],
    ) -> bool:
        outer = logical.split("$", 1)[0]
        return outer in component_names or any(
            logical == prefix or logical.startswith(f"{prefix}.")
            for prefix in owned_prefixes
        )

    @staticmethod
    def _find_markers(node: CodeNode) -> dict[str, list[dict[str, Any]]]:
        markers: dict[str, list[dict[str, Any]]] = {}
        for marker in MARKERS:
            needles = MARKER_NEEDLES.get(marker.name, ())
            if needles and not any(needle in node.content for needle in needles):
                continue
            evidence: list[dict[str, Any]] = []
            for pattern in marker.patterns:
                for match in pattern.finditer(node.content):
                    if marker.name == "dynamic_receiver_register":
                        line_start = node.content.rfind("\n", 0, match.start()) + 1
                        line_end = node.content.find("\n", match.end())
                        line_end = len(node.content) if line_end < 0 else line_end
                        if "LocalBroadcastManager" in node.content[line_start:line_end]:
                            continue
                    evidence.append(
                        {
                            "role": "code",
                            "marker": marker.name,
                            "root": node.root,
                            "path": node.path,
                            "line": node.content.count("\n", 0, match.start()) + 1,
                            "class_name": node.class_name,
                            "method": AndroidAttackChainAnalyzer._method_at(
                                node.content,
                                match.start(),
                                node.path,
                            ),
                            "analysis_scope": "app_code",
                        }
                    )
                    if len(evidence) >= 3:
                        break
                if len(evidence) >= 3:
                    break
            if evidence:
                markers[marker.name] = evidence
        return markers

    @staticmethod
    def _method_at(content: str, position: int, path: str) -> str | None:
        if path.endswith(".smali"):
            method_start = content.rfind("\n.method", 0, position)
            method_end = content.find("\n", method_start + 1)
            if method_start >= 0 and method_end > method_start:
                return content[method_start + 1 : method_end].strip()
            return None
        method_pattern = re.compile(
            r"(?m)^\s*(?:(?:public|private|protected|internal|static|final|open|"
            r"override|suspend|abstract|synchronized)\s+)*(?:fun\s+)?"
            r"(?:[A-Za-z_$][\w$<>,.?\[\] ]*\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}]*\)"
            r"\s*(?:throws\s+[^\{]+)?\{"
        )
        matches = list(method_pattern.finditer(content, 0, position))
        return matches[-1].group(1) if matches else None

    @staticmethod
    def _method_slice(content: str, position: int, path: str) -> str:
        if path.endswith(".smali"):
            start = content.rfind("\n.method", 0, position)
            end = content.find("\n.end method", position)
            return content[max(start, 0) : len(content) if end < 0 else end]
        # Decompiled Java/Kotlin braces are not always balanced after failures. A bounded
        # window around the marker is safer than claiming a whole-class data-flow edge.
        return content[max(0, position - 1_000) : position + 4_000]

    @staticmethod
    def _add_smali_marker(node: CodeNode, name: str, position: int) -> None:
        if name in node.markers:
            return
        node.markers[name] = [
            {
                "role": "code",
                "marker": name,
                "root": node.root,
                "path": node.path,
                "line": node.content.count("\n", 0, position) + 1,
                "class_name": node.class_name,
                "method": AndroidAttackChainAnalyzer._method_at(
                    node.content,
                    position,
                    node.path,
                ),
                "analysis_scope": "app_code",
            }
        ]

    @staticmethod
    def _smali_constant_before(content: str, register: str, position: int) -> int | None:
        method_start = content.rfind("\n.method", 0, position)
        start = max(method_start, position - 2_000, 0)
        pattern = re.compile(
            rf"(?m)^\s*const(?:/(?:4|16|high16))?\s+{re.escape(register)},\s*"
            r"(-?0x[0-9a-fA-F]+|-?\d+)\b"
        )
        matches = list(pattern.finditer(content, start, position))
        if not matches:
            return None
        try:
            return int(matches[-1].group(1), 0)
        except ValueError:
            return None

    @classmethod
    def _augment_smali_markers(cls, node: CodeNode) -> None:
        if not node.path.endswith(".smali"):
            return
        content = node.content
        pending_calls = (
            re.compile(
                r"invoke-static(?:/range)?\s+\{([^}]*)\},\s*"
                r"Landroid/app/PendingIntent;->get"
                r"(?:Activity|Activities|Service|ForegroundService|Broadcast)\("
            ).finditer(content)
            if "Landroid/app/PendingIntent;->get" in content
            else ()
        )
        for match in pending_calls:
            registers = [item.strip() for item in match.group(1).split(",")]
            if len(registers) < 4 or ".." in match.group(1):
                continue
            flag_register = registers[-1]
            intent_register = registers[-2]
            flags = cls._smali_constant_before(content, flag_register, match.start())
            if flags is not None:
                if flags & 0x04000000:
                    cls._add_smali_marker(node, "pending_intent_immutable", match.start())
                if flags & 0x02000000:
                    cls._add_smali_marker(node, "pending_intent_mutable", match.start())
                if flags & 0x40000000:
                    cls._add_smali_marker(node, "pending_intent_one_shot", match.start())
                if flags & 0x01000000:
                    cls._add_smali_marker(
                        node,
                        "pending_allow_unsafe_implicit",
                        match.start(),
                    )
            method_start = max(content.rfind("\n.method", 0, match.start()), 0)
            construction = content[method_start : match.start()]
            escaped_intent = re.escape(intent_register)
            if re.search(
                rf"invoke-direct\s+\{{{escaped_intent},[^}}]+\}},\s*"
                r"Landroid/content/Intent;-><init>\(Landroid/content/Context;Ljava/lang/Class;\)V",
                construction,
            ) or re.search(
                rf"invoke-virtual\s+\{{{escaped_intent},[^}}]+\}},\s*"
                r"Landroid/content/Intent;->set(?:Class|ClassName|Component|Package)\(",
                construction,
            ):
                cls._add_smali_marker(node, "pending_base_explicit", match.start())
            elif re.search(
                rf"invoke-direct\s+\{{{escaped_intent},[^}}]+\}},\s*"
                r"Landroid/content/Intent;-><init>\(Ljava/lang/String;\)V",
                construction,
            ):
                cls._add_smali_marker(node, "pending_base_implicit", match.start())

        register_calls = (
            re.compile(
                r"invoke-(?:virtual|static)(?:/range)?\s+\{([^}]*)\},\s*"
                r"L(?:android/content/Context[^;]*|androidx/core/content/ContextCompat);"
                r"->registerReceiver\([^\n]*;I\)Landroid/content/Intent;"
            ).finditer(content)
            if "registerReceiver" in content
            else ()
        )
        for match in register_calls:
            registers = [item.strip() for item in match.group(1).split(",")]
            if not registers or ".." in match.group(1):
                continue
            flags = cls._smali_constant_before(content, registers[-1], match.start())
            if flags is None:
                continue
            if flags & 0x2:
                cls._add_smali_marker(node, "receiver_exported", match.start())
            if flags & 0x4:
                cls._add_smali_marker(node, "receiver_not_exported", match.start())

        uri_flag_calls = (
            re.compile(
                r"invoke-virtual\s+\{([^}]*)\},\s*"
                r"Landroid/content/Intent;->(?:addFlags|setFlags)\(I\)"
            ).finditer(content)
            if "Intent;->addFlags" in content or "Intent;->setFlags" in content
            else ()
        )
        for match in uri_flag_calls:
            registers = [item.strip() for item in match.group(1).split(",")]
            if len(registers) < 2:
                continue
            flags = cls._smali_constant_before(content, registers[-1], match.start())
            if flags is not None and flags & 0x3:
                cls._add_smali_marker(node, "uri_grant", match.start())

        parcel_calls = (
            re.compile(r"->getParcelable(?:Extra)?\([^\n]*\)").finditer(content)
            if "getParcelable" in content
            else ()
        )
        for match in parcel_calls:
            following = content[match.end() : match.end() + 600]
            if re.search(r"check-cast\s+[vp]\d+,\s*Landroid/content/Intent;", following):
                cls._add_smali_marker(node, "nested_intent_input", match.start())
            if re.search(r"check-cast\s+[vp]\d+,\s*Landroid/net/Uri;", following):
                cls._add_smali_marker(node, "external_uri_input", match.start())

        web_setting_calls = (
            re.compile(
                r"invoke-virtual\s+\{([^}]*)\},\s*"
                r"L(?:android|com/vivo/ic)/webkit/WebSettings;"
                r"->(setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|"
                r"setWebContentsDebuggingEnabled|setMixedContentMode)\(([ZI])\)"
            ).finditer(content)
            if any(
                name in content
                for name in (
                    "setAllowUniversalAccessFromFileURLs",
                    "setAllowFileAccessFromFileURLs",
                    "setWebContentsDebuggingEnabled",
                    "setMixedContentMode",
                )
            )
            else ()
        )
        for match in web_setting_calls:
            registers = [item.strip() for item in match.group(1).split(",")]
            if len(registers) < 2:
                continue
            value = cls._smali_constant_before(content, registers[-1], match.start())
            method = match.group(2)
            if value is not None and (
                (method == "setMixedContentMode" and value == 0)
                or (method != "setMixedContentMode" and value != 0)
            ):
                cls._add_smali_marker(node, "webview_unsafe_setting", match.start())

    @staticmethod
    def _inject_manifest_sources(
        manifest: ManifestDocument,
        nodes: dict[str, CodeNode],
    ) -> None:
        for entry in manifest.entries:
            if entry.kind == EntryPointKind.DEEP_LINK.value:
                continue
            owner = str(entry.owner_component or entry.name)
            node = nodes.get(owner) or nodes.get(owner.split("$", 1)[0])
            if node is None:
                continue
            component_evidence = {
                "role": "manifest_component",
                "marker": "manifest_component",
                "root": "",
                "path": "AndroidManifest.xml",
                "line": 0,
                "class_name": owner,
                "component": entry.name,
                "exported": entry.exported,
                "analysis_scope": "manifest",
            }
            node.markers.setdefault("manifest_component", []).append(component_evidence)
            if entry.exported:
                node.markers.setdefault("manifest_externally_reachable", []).append(
                    {
                        **component_evidence,
                        "marker": "manifest_externally_reachable",
                    }
                )
            actions = {
                str(action)
                for intent_filter in entry.intent_filters
                for action in intent_filter.get("actions", [])
                if action
            }
            if actions & {
                "android.intent.action.SEND",
                "android.intent.action.SEND_MULTIPLE",
            }:
                node.markers.setdefault("action_send_ingress", []).append(
                    {
                        "role": "manifest_source",
                        "marker": "action_send_ingress",
                        "root": "",
                        "path": "AndroidManifest.xml",
                        "line": 0,
                        "class_name": owner,
                        "component": entry.name,
                        "actions": sorted(actions),
                        "analysis_scope": "manifest",
                    }
                )

    @classmethod
    def _build_adjacency(cls, nodes: dict[str, CodeNode]) -> dict[str, set[str]]:
        descriptor_map = {name.replace(".", "/"): name for name in nodes}
        simple_map: dict[str, list[str]] = {}
        for name in nodes:
            simple_map.setdefault(name.rsplit(".", 1)[-1].split("$", 1)[0], []).append(name)
        adjacency = {name: set() for name in nodes}
        for name, node in nodes.items():
            references: set[str] = set()
            for descriptor in re.findall(r"L([A-Za-z0-9_/$]+);", node.content):
                target = descriptor_map.get(descriptor)
                if target is None:
                    target = descriptor_map.get(descriptor.split("$", 1)[0])
                if target:
                    references.add(target)
            if node.path.endswith(".smali"):
                references.discard(name)
                node.references = references
                adjacency[name].update(references)
                continue
            for qualified in re.findall(
                r"\b(?:[a-z_$][\w$]*\.){2,}[A-Z_$][\w$]*(?:\$[A-Za-z_$][\w$]*)?\b",
                node.content,
            ):
                candidate = qualified
                if candidate in nodes:
                    references.add(candidate)
                elif qualified.split("$", 1)[0] in nodes:
                    references.add(qualified.split("$", 1)[0])
            for simple in set(re.findall(r"\b[A-Z_$][A-Za-z0-9_$]{2,}\b", node.content)):
                matches = simple_map.get(simple.split("$", 1)[0], [])
                if len(matches) == 1:
                    references.add(matches[0])
            references.discard(name)
            node.references = references
            adjacency[name].update(references)
        return adjacency

    def _chains_for_spec(
        self,
        manifest: ManifestDocument,
        nodes: dict[str, CodeNode],
        adjacency: dict[str, set[str]],
        spec: ChainSpec,
    ) -> list[dict[str, Any]]:
        source_nodes = [
            name for name, node in nodes.items() if set(node.markers) & spec.sources
        ]
        sink_nodes = {
            name for name, node in nodes.items() if set(node.markers) & spec.sinks
        }
        candidates: list[dict[str, Any]] = []
        for source_name in sorted(
            source_nodes,
            key=lambda name: (
                "manifest_externally_reachable" not in nodes[name].markers,
                "manifest_component" not in nodes[name].markers,
                name,
            ),
        )[:80]:
            source_node = nodes[source_name]
            effective_sinks = set(sink_nodes)
            if source_name in effective_sinks and not self._markers_share_context(
                source_node,
                spec.sources,
                spec.sinks,
            ):
                effective_sinks.remove(source_name)
            paths = self._bounded_paths(
                source_name,
                effective_sinks,
                adjacency,
                max_hops=spec.max_hops,
            )
            if not paths and spec.endpoint_discovery:
                paths = [[source_name]]
            for path in paths[:2]:
                if len(path) > 1 and not self._source_references_first_hop(
                    source_node,
                    spec.sources,
                    path[1],
                ):
                    continue
                candidate = self._candidate(manifest, nodes, path, spec)
                candidates.append(candidate)
                if len(candidates) >= 12:
                    return candidates
        return candidates

    @staticmethod
    def _markers_share_context(
        node: CodeNode,
        sources: frozenset[str],
        sinks: frozenset[str],
    ) -> bool:
        source_evidence = [
            item
            for marker in sources
            for item in node.markers.get(marker, [])
        ]
        sink_evidence = [
            item
            for marker in sinks
            for item in node.markers.get(marker, [])
        ]
        if any(item.get("analysis_scope") == "manifest" for item in source_evidence):
            return True
        source_methods = {str(item["method"]) for item in source_evidence if item.get("method")}
        sink_methods = {str(item["method"]) for item in sink_evidence if item.get("method")}
        if source_methods and sink_methods:
            return bool(source_methods & sink_methods)
        return any(
            abs(int(source.get("line") or 0) - int(sink.get("line") or 0)) <= 300
            for source in source_evidence
            for sink in sink_evidence
            if source.get("line") and sink.get("line")
        )

    @classmethod
    def _source_references_first_hop(
        cls,
        node: CodeNode,
        sources: frozenset[str],
        target_class: str,
    ) -> bool:
        descriptor = f"L{target_class.replace('.', '/')};"
        outer_descriptor = f"L{target_class.split('$', 1)[0].replace('.', '/')};"
        simple_name = target_class.rsplit(".", 1)[-1].split("$", 1)[0]
        for marker in sources:
            for evidence in node.markers.get(marker, []):
                if evidence.get("analysis_scope") == "manifest":
                    return True
                line = int(evidence.get("line") or 0)
                if line <= 0:
                    continue
                lines = node.content.splitlines(keepends=True)
                position = sum(len(value) for value in lines[: line - 1])
                scope = cls._method_slice(node.content, position, node.path)
                if descriptor in scope or outer_descriptor in scope:
                    return True
                if not node.path.endswith(".smali") and re.search(
                    rf"\b{re.escape(simple_name)}\b",
                    scope,
                ):
                    return True
        return False

    @staticmethod
    def _bounded_paths(
        source: str,
        sinks: set[str],
        adjacency: dict[str, set[str]],
        *,
        max_hops: int,
    ) -> list[list[str]]:
        queue: deque[list[str]] = deque([[source]])
        found: list[list[str]] = []
        best_depth: dict[str, int] = {source: 0}
        while queue and len(found) < 6:
            path = queue.popleft()
            current = path[-1]
            hops = len(path) - 1
            if current in sinks:
                found.append(path)
                continue
            if hops >= max_hops:
                continue
            for neighbor in sorted(
                adjacency.get(current, set()),
                key=lambda value: (value not in sinks, value),
            ):
                if neighbor in path:
                    continue
                next_depth = hops + 1
                if best_depth.get(neighbor, max_hops + 1) < next_depth:
                    continue
                best_depth[neighbor] = next_depth
                queue.append([*path, neighbor])
        return found

    @staticmethod
    def _candidate(
        manifest: ManifestDocument,
        nodes: dict[str, CodeNode],
        path: list[str],
        spec: ChainSpec,
    ) -> dict[str, Any]:
        path_nodes = [nodes[name] for name in path]
        locations: list[dict[str, Any]] = []
        source_markers: set[str] = set()
        sink_markers: set[str] = set()
        risk_markers: set[str] = set()
        guard_markers: set[str] = set()
        for node in path_nodes:
            present = set(node.markers)
            source_markers.update(present & spec.sources)
            sink_markers.update(present & spec.sinks)
            risk_markers.update(present & spec.risks)
            guard_markers.update(present & spec.guards)
            relevant = present & (spec.sources | spec.sinks | spec.risks | spec.guards)
            for marker in sorted(relevant):
                locations.extend(node.markers[marker][:1])

        inferred_risks: list[str] = []
        if spec.chain_kind == "pending_intent_delegation":
            if "pending_intent_immutable" not in guard_markers:
                inferred_risks.append("immutable_flag_not_observed_in_bounded_path")
            if "pending_intent_one_shot" not in guard_markers:
                inferred_risks.append("one_shot_flag_not_observed_in_bounded_path")
            if "pending_base_explicit" not in guard_markers:
                inferred_risks.append("explicit_base_intent_not_observed_in_bounded_path")
        elif spec.chain_kind == "dynamic_broadcast_receiver":
            if not ({"receiver_not_exported", "receiver_permission_guard"} & guard_markers):
                inferred_risks.append("receiver_sender_restriction_not_observed_in_bounded_path")
        elif spec.chain_kind == "local_tcp_or_unix_server":
            if "socket_peer_guard" not in guard_markers:
                inferred_risks.append("peer_authentication_not_observed_in_bounded_path")
        elif spec.chain_kind == "external_input_to_webview":
            if "web_origin_guard" not in guard_markers:
                inferred_risks.append("strict_origin_validation_not_observed_in_bounded_path")
        elif spec.chain_kind in {
            "external_content_to_private_file",
            "external_archive_extraction",
        }:
            if "path_containment_guard" not in guard_markers:
                inferred_risks.append("canonical_path_containment_not_observed_in_bounded_path")

        review_required = True
        disposition = "review_required"
        if (
            spec.chain_kind == "pending_intent_delegation"
            and {"pending_base_explicit", "pending_intent_immutable"}
            <= guard_markers
            and not risk_markers
        ):
            # FLAG_ONE_SHOT is a useful hardening option, but its absence alone does
            # not make an explicit immutable PendingIntent an actionable finding.
            review_required = False
            disposition = "guarded_capability_inventory"
        elif (
            spec.chain_kind == "dynamic_broadcast_receiver"
            and "receiver_not_exported" in guard_markers
            and "receiver_exported" not in risk_markers
        ):
            review_required = False
            disposition = "non_exported_receiver_inventory"

        stable = {
            "engine": ANALYSIS_ENGINE_VERSION,
            "family": spec.family,
            "chain_kind": spec.chain_kind,
            "classes": path,
            "sources": sorted(source_markers),
            "sinks": sorted(sink_markers),
            "risks": sorted(risk_markers),
            "guards": sorted(guard_markers),
            "inferred_risks": inferred_risks,
        }
        fingerprint = hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "engine_version": ANALYSIS_ENGINE_VERSION,
            "family": spec.family,
            "chain_kind": spec.chain_kind,
            "title": spec.title,
            "severity": spec.severity,
            "priority": spec.priority,
            "confidence": "medium" if len(path) == 1 else "low",
            "candidate_only": True,
            "review_required": review_required,
            "disposition": disposition,
            "target_sdk": manifest.target_sdk,
            "hop_count": len(path) - 1,
            "path": [
                {
                    "class_name": node.class_name,
                    "root": node.root,
                    "path": node.path,
                }
                for node in path_nodes
            ],
            "source_markers": sorted(source_markers),
            "sink_markers": sorted(sink_markers),
            "risk_markers": sorted(risk_markers),
            "guard_markers": sorted(guard_markers),
            "inferred_risks": inferred_risks,
            "locations": AndroidAttackChainAnalyzer._unique_locations(locations)[:16],
            "fingerprint": fingerprint,
        }

    def _fileprovider_configuration_chains(
        self,
        manifest: ManifestDocument,
        roots: Iterable[Path],
    ) -> list[dict[str, Any]]:
        providers = [
            entry
            for entry in manifest.entries
            if entry.kind == EntryPointKind.PROVIDER.value
            and (
                "fileprovider" in entry.name.lower()
                or str(entry.metadata.get("grant_uri_permissions") or "").lower() == "true"
                or bool(entry.metadata.get("grant_uri_permission_paths"))
            )
        ]
        if not providers:
            return []
        risky_path = re.compile(
            r"<(?:root-path)\b|"
            r"<(?:external-path|external-files-path|files-path|cache-path)\b[^>]*"
            r"(?:android:)?path\s*=\s*[\"'](?:\.?/?)[\"']",
            re.IGNORECASE,
        )
        locations: list[dict[str, Any]] = []
        for root in roots:
            if not root.is_dir():
                continue
            resource_roots = [
                candidate
                for candidate in (
                    root / "res" / "xml",
                    root / "resources" / "res" / "xml",
                    root / "apktool" / "res" / "xml",
                )
                if candidate.is_dir()
            ]
            xml_paths = sorted(
                {
                    path
                    for resource_root in resource_roots
                    for path in resource_root.glob("*.xml")
                }
            )
            for path in xml_paths:
                try:
                    relative = path.relative_to(root)
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "<paths" not in text or not risky_path.search(text):
                    continue
                match = risky_path.search(text)
                assert match is not None
                locations.append(
                    {
                        "role": "resource_config",
                        "marker": "broad_fileprovider_path",
                        "root": root.name,
                        "path": str(PurePosixPath(*relative.parts)),
                        "line": text.count("\n", 0, match.start()) + 1,
                        "analysis_scope": "resource_config",
                    }
                )
                if len(locations) >= 8:
                    break
            if len(locations) >= 8:
                break
        if not locations:
            return []
        provider_facts = [
            {
                "name": item.name,
                "authorities": item.metadata.get("authorities"),
                "exported": item.exported,
                "grant_uri_permissions": item.metadata.get("grant_uri_permissions"),
            }
            for item in providers
        ]
        stable = {
            "engine": ANALYSIS_ENGINE_VERSION,
            "family": "external_file_ingress_boundary",
            "chain_kind": "broad_fileprovider_configuration",
            "providers": provider_facts,
            "paths": sorted(str(item["path"]) for item in locations),
        }
        fingerprint = hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return [
            {
                "schema_version": ANALYSIS_SCHEMA_VERSION,
                "engine_version": ANALYSIS_ENGINE_VERSION,
                "family": "external_file_ingress_boundary",
                "chain_kind": "broad_fileprovider_configuration",
                "title": "Broad FileProvider path capability",
                "severity": Severity.HIGH.value,
                "priority": 95,
                "confidence": "medium",
                "candidate_only": True,
                "review_required": True,
                "disposition": "review_required",
                "target_sdk": manifest.target_sdk,
                "hop_count": 0,
                "path": [],
                "source_markers": ["fileprovider_manifest"],
                "sink_markers": ["broad_fileprovider_path"],
                "risk_markers": ["grantable_broad_path"],
                "guard_markers": [],
                "inferred_risks": ["narrow_path_scope_not_observed"],
                "providers": provider_facts,
                "locations": locations,
                "fingerprint": fingerprint,
            }
        ]

    @staticmethod
    def _unique_locations(locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[tuple[str, str, int, str], dict[str, Any]] = {}
        for item in locations:
            key = (
                str(item.get("root") or ""),
                str(item.get("path") or ""),
                int(item.get("line") or 0),
                str(item.get("marker") or ""),
            )
            unique[key] = item
        return [unique[key] for key in sorted(unique)]
