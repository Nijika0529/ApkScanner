from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..core.enums import Confidence, CoverageStatus, EntryPointKind, Severity
from .fast_text_search import files_containing_any
from .manifest import ManifestDocument, ParsedEntryPoint
from .static_analysis import StaticAnalysisResult


@dataclass(slots=True)
class FindingDraft:
    rule_id: str
    title: str
    description: str
    remediation: str
    masvs: str
    severity: str
    confidence: str = Confidence.MEDIUM.value
    cwe: str | None = None
    entry_names: list[str] = field(default_factory=list)
    locations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = "builtin"

    @property
    def dedupe_key(self) -> str:
        material = "|".join([self.rule_id, *sorted(self.entry_names), str(self.locations[:3])])
        return hashlib.sha256(material.encode()).hexdigest()


@dataclass(slots=True)
class CoverageDraft:
    control_id: str
    domain: str
    title: str
    status: str
    stages: dict[str, Any]
    gap_reason: str | None = None


@dataclass(slots=True)
class StaticReviewSurfaceDraft:
    name: str
    family: str
    title: str
    severity: str
    priority: int
    rule_ids: list[str]
    hypotheses: list[str]
    locations: list[dict[str, Any]]
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    artifact: dict[str, Any] | None = None
    investigation_group: dict[str, Any] | None = None


CODE_RULES = (
    (
        "CODE-WEBVIEW-JS-BRIDGE",
        re.compile(r"addJavascriptInterface\s*\(|->addJavascriptInterface\("),
        "WebView exposes a JavaScript bridge",
        "Review every bridge method, restrict loaded origins, and avoid exposing sensitive native APIs.",
        "MASVS-PLATFORM",
        Severity.HIGH,
        "CWE-749",
    ),
    (
        "CODE-WEBVIEW-FILE-ACCESS",
        re.compile(r"setAllowFileAccess\s*\(\s*(true|0x1)|->setAllowFileAccess\(Z\)V"),
        "WebView file access is enabled",
        "Disable file access unless required and use WebViewAssetLoader for local content.",
        "MASVS-PLATFORM",
        Severity.MEDIUM,
        "CWE-200",
    ),
    (
        "CODE-WEBVIEW-UNIVERSAL-FILE-ACCESS",
        re.compile(
            r"setAllowUniversalAccessFromFileURLs\s*\(\s*true|"
            r"->setAllowUniversalAccessFromFileURLs\(Z\)V"
        ),
        "WebView permits universal access from file URLs",
        "Disable universal file URL access and load local content through WebViewAssetLoader.",
        "MASVS-PLATFORM",
        Severity.HIGH,
        "CWE-200",
    ),
    (
        "CODE-TRUST-ALL-TLS",
        re.compile(r"X509TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier"),
        "Potential custom TLS trust or hostname verification",
        "Confirm the implementation fails closed and delegates to platform trust validation.",
        "MASVS-NETWORK",
        Severity.HIGH,
        "CWE-295",
    ),
    (
        "CODE-WEAK-CRYPTO",
        re.compile(
            r"Cipher\.getInstance\s*\([^\n]*(ECB|DES)|MessageDigest\.getInstance\s*\([^\n]*(MD5|SHA-?1)"
        ),
        "Potential weak cryptographic primitive",
        "Use modern authenticated encryption and collision-resistant hashes appropriate to the use case.",
        "MASVS-CRYPTO",
        Severity.MEDIUM,
        "CWE-327",
    ),
    (
        "CODE-DYNAMIC-LOAD",
        re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader"),
        "Application dynamically loads executable code",
        "Verify loaded code integrity, provenance, storage location, and update channel authentication.",
        "MASVS-CODE",
        Severity.MEDIUM,
        "CWE-494",
    ),
    (
        "CODE-COMMAND-EXEC",
        re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Ljava/lang/Runtime;->exec"),
        "Application invokes operating-system commands",
        "Avoid shell construction with untrusted values and strictly validate any required command arguments.",
        "MASVS-CODE",
        Severity.MEDIUM,
        "CWE-78",
    ),
    (
        "CODE-ARCHIVE-EXTRACTION",
        re.compile(r"ZipInputStream|ZipEntry;->getName|java\.util\.zip\.ZipEntry"),
        "Archive entry names reach an extraction workflow",
        "Resolve every output path canonically beneath a dedicated extraction root before writing.",
        "MASVS-CODE",
        Severity.MEDIUM,
        "CWE-22",
    ),
    (
        "CODE-UNTRUSTED-DISPLAY-NAME",
        re.compile(r"OpenableColumns\.DISPLAY_NAME|[\"']_display_name[\"']"),
        "External content display names enter a file workflow",
        "Discard directory components, generate server-side names, and enforce canonical containment.",
        "MASVS-STORAGE",
        Severity.MEDIUM,
        "CWE-22",
    ),
    (
        "CODE-PERSISTED-SECURITY-POLICY",
        re.compile(
            r"(?is)(?:risk|policy|rule|grant|approval).{0,240}"
            r"(?:SharedPreferences|SQLiteDatabase|RoomDatabase)|"
            r"(?:SharedPreferences|SQLiteDatabase|RoomDatabase).{0,240}"
            r"(?:risk|policy|rule|grant|approval)"
        ),
        "Security policy or approval state is persisted client-side",
        "Authenticate policy updates, bind approval records to caller and operation fingerprints, and prevent rollback or version lockout.",
        "MASVS-AUTH",
        Severity.MEDIUM,
        "CWE-354",
    ),
    (
        "CODE-EXTERNAL-CONTEXT-SOURCE",
        re.compile(r"ClipboardManager|->getPrimaryClip\(|WifiInfo;->getSSID\("),
        "Externally influenced context enters application logic",
        "Label source trust and prevent clipboard, network labels, files, or notifications from becoming executable instructions.",
        "MASVS-PLATFORM",
        Severity.MEDIUM,
        "CWE-74",
    ),
    (
        "CODE-CLEARTEXT-ENDPOINT",
        re.compile(
            r"(?i)(?:http|ws)://"
            r"(?!127\.0\.0\.1|localhost|schemas\.android\.com|www\.w3\.org)"
            r"[^\s\"']+"
        ),
        "Code contains a non-local cleartext service endpoint",
        "Require TLS for production traffic and reject cleartext endpoints in release configuration.",
        "MASVS-NETWORK",
        Severity.HIGH,
        "CWE-319",
    ),
    (
        "CODE-DYNAMIC-RECEIVER",
        re.compile(r"registerReceiver\s*\(|->registerReceiver\("),
        "Application registers broadcast receivers dynamically",
        "Ensure receivers that do not require external callers use RECEIVER_NOT_EXPORTED.",
        "MASVS-PLATFORM",
        Severity.LOW,
        "CWE-926",
    ),
    (
        "CODE-NONPRODUCTION-ENDPOINT",
        re.compile(r"(?i)(?:https?|wss?)://[^\s\"']*(?:pre|test|staging|dev)[^\s\"']*"),
        "Release code references a non-production service endpoint",
        "Use environment-bound release configuration and reject pre, test, staging, or development endpoints in production artifacts.",
        "MASVS-NETWORK",
        Severity.HIGH,
        "CWE-16",
    ),
    (
        "CODE-HARDCODED-SECRET",
        re.compile(
            r"\.field[^\n]*(?:app[_-]?secret|app[_-]?key|client[_-]?secret|"
            r'api[_-]?key)[^\n]*=\s*"[A-Za-z0-9+/=_-]{12,}"|'
            r"(?:app[_-]?secret|app[_-]?key|client[_-]?secret|api[_-]?key)"
            r'\s*[=:]\s*["\'][A-Za-z0-9+/=_-]{12,}["\']',
            re.IGNORECASE,
        ),
        "Potential client-side hardcoded service credential",
        "Remove privileged shared secrets from the APK, rotate exposed credentials, and perform signing or privileged authorization on a trusted service.",
        "MASVS-AUTH",
        Severity.HIGH,
        "CWE-798",
    ),
)

CODE_RULE_PREFILTER_LITERALS = (
    "addJavascriptInterface",
    "setAllowFileAccess",
    "setAllowUniversalAccessFromFileURLs",
    "X509TrustManager",
    "ALLOW_ALL_HOSTNAME_VERIFIER",
    "setHostnameVerifier",
    "Cipher.getInstance",
    "MessageDigest.getInstance",
    "DexClassLoader",
    "PathClassLoader",
    "InMemoryDexClassLoader",
    "Runtime.getRuntime",
    "ProcessBuilder",
    "Ljava/lang/Runtime;->exec",
    "ZipInputStream",
    "ZipEntry",
    "OpenableColumns.DISPLAY_NAME",
    "_display_name",
    "SharedPreferences",
    "SQLiteDatabase",
    "RoomDatabase",
    "ClipboardManager",
    "getPrimaryClip",
    "getSSID",
    "http://",
    "https://",
    "ws://",
    "wss://",
    "registerReceiver",
    "appsecret",
    "app_secret",
    "app-secret",
    "appkey",
    "app_key",
    "app-key",
    "clientsecret",
    "client_secret",
    "client-secret",
    "apikey",
    "api_key",
    "api-key",
)


STATIC_REVIEW_FAMILIES: dict[str, dict[str, Any]] = {
    "web_content_boundary": {
        "rule_ids": {
            "CHAIN-ANDROID-WEBVIEW-DATAFLOW",
            "CODE-WEBVIEW-JS-BRIDGE",
            "CODE-WEBVIEW-FILE-ACCESS",
            "CODE-WEBVIEW-UNIVERSAL-FILE-ACCESS",
        },
        "title": "WebView content and native bridge trust boundary",
        "severity": Severity.HIGH.value,
        "priority": 94,
        "path_hints": ("htmlpreview", "webview", "html"),
        "preferred_only": True,
        "hypotheses": [
            (
                "Attacker-controlled URL or generated HTML can reach this WebView through a "
                "concrete report, card, message, deep-link, or IPC path."
            ),
            (
                "JavaScript, file-origin, or navigation privileges expose sensitive native data "
                "or actions without strict origin authorization."
            ),
            (
                "The source-to-WebView-to-bridge chain crosses an application trust boundary and "
                "has concrete confidentiality, integrity, or privileged-action impact."
            ),
        ],
    },
    "shell_execution_boundary": {
        "rule_ids": {"CODE-COMMAND-EXEC"},
        "title": "Shell execution and command-risk policy boundary",
        "severity": Severity.HIGH.value,
        "priority": 96,
        "path_hints": ("/cli/", "cliexecutor", "shell", "command"),
        "preferred_only": True,
        "hypotheses": [
            (
                "Untrusted user, model, tool, file, or IPC input can reach a shell execution sink "
                "under the application's privileges."
            ),
            (
                "The command-risk policy disagrees with real shell semantics for substitution, "
                "pipelines, xargs, glob expansion, relative paths, wrappers, or multi-step flows."
            ),
            (
                "A policy bypass can read protected data, alter another package or persistent "
                "security state, or execute attacker-controlled script content."
            ),
        ],
    },
    "archive_extraction_boundary": {
        "rule_ids": {"CODE-ARCHIVE-EXTRACTION"},
        "title": "Archive extraction and canonical path boundary",
        "severity": Severity.HIGH.value,
        "priority": 93,
        "path_hints": ("zip", "archive", "migration", "transfer", "backup"),
        "preferred_only": True,
        "hypotheses": [
            "An attacker-controlled archive entry name reaches a filesystem output path.",
            "Canonical containment is absent, incomplete, or checked before a later path transformation.",
            "A crafted archive can overwrite application-private configuration, code, or another sensitive file.",
        ],
    },
    "external_file_ingress_boundary": {
        "rule_ids": {
            "CHAIN-ANDROID-FILE-INGRESS",
            "CODE-UNTRUSTED-DISPLAY-NAME",
        },
        "title": "External file metadata and destination path boundary",
        "severity": Severity.HIGH.value,
        "priority": 95,
        "path_hints": ("share", "file", "attachment", "import", "provider"),
        "preferred_only": True,
        "hypotheses": [
            "An untrusted ContentProvider controls the display name or relative destination of an imported file.",
            "Path normalization permits traversal, absolute paths, symlink escape, or overwrite of an existing private file.",
            "The resulting write can alter sensitive state or feed a later executable/plugin loading path.",
        ],
    },
    "capability_delegation_boundary": {
        "rule_ids": {"CHAIN-ANDROID-CAPABILITY-DELEGATION"},
        "title": "Intent, Activity result, and URI capability boundary",
        "severity": Severity.HIGH.value,
        "priority": 98,
        "path_hints": (
            "pendingintent",
            "notification",
            "intent",
            "router",
            "provider",
            "share",
        ),
        "preferred_only": False,
        "hypotheses": [
            "A PendingIntent delegates more mutable, replayable, or redirectable authority than its intended recipient requires.",
            "A nested or serialized Intent reaches an internal component launch without complete destination and flag sanitization.",
            "An attacker-controlled content URI or ClipData item gains or propagates read, write, prefix, or persisted access across an unintended trust boundary.",
            "Sensitive extras leave through an implicit Activity, Service, or broadcast destination that another app can intercept.",
            "An untrusted Activity result is consumed with the caller's ContentResolver authority or returned with URI grants without validating its provider.",
        ],
    },
    "runtime_ipc_boundary": {
        "rule_ids": {
            "CHAIN-ANDROID-RUNTIME-IPC",
            "CODE-DYNAMIC-RECEIVER",
        },
        "title": "Runtime receiver, local socket, and Binder identity boundary",
        "severity": Severity.HIGH.value,
        "priority": 95,
        "path_hints": (
            "receiver",
            "broadcast",
            "socket",
            "server",
            "http",
            "ipc",
            "binder",
            "aidl",
        ),
        "preferred_only": False,
        "hypotheses": [
            "A context-registered receiver accepts broadcasts from an ordinary third-party app without a non-exported flag or strong sender permission.",
            "Receiver-controlled extras can cross into a persistent, privileged, filesystem, component-launch, or WebView sink.",
            "A TCP loopback or Unix-domain listener is reachable without binding its peer to an authenticated application identity and exposes sensitive commands or data.",
            "A Binder/AIDL authorization decision trusts a package name or identity supplied by the caller instead of binding it to Binder.getCallingUid().",
        ],
    },
    "persistent_security_policy_boundary": {
        "rule_ids": {"CODE-PERSISTED-SECURITY-POLICY"},
        "title": "Persisted security policy and approval integrity boundary",
        "severity": Severity.HIGH.value,
        "priority": 95,
        "path_hints": ("risk", "policy", "rule", "grant", "approval", "auth"),
        "preferred_only": True,
        "hypotheses": [
            "Locally persisted risk rules, approvals, or authorization state can be replaced without authenticity or rollback protection.",
            "Caller, tool, arguments, version, and expiry are not cryptographically bound to the persisted decision.",
            "Tampering can persistently disable enforcement, forge approval, or prevent a legitimate policy update.",
        ],
    },
    "untrusted_context_boundary": {
        "rule_ids": {"CODE-EXTERNAL-CONTEXT-SOURCE"},
        "title": "External context trust and agent instruction boundary",
        "severity": Severity.HIGH.value,
        "priority": 91,
        "path_hints": ("clipboard", "context", "wifi", "notification", "agent", "tool"),
        "preferred_only": True,
        "hypotheses": [
            "Clipboard, notification, network label, external file, or remote content enters an Agent context without a trustworthy source label.",
            "Untrusted context can select or parameterize a more privileged tool outside the initiating request scope.",
            "The composed flow can disclose private data, create automation, or execute a privileged action without confirmation.",
        ],
    },
    "release_configuration_boundary": {
        "rule_ids": {
            "CODE-CLEARTEXT-ENDPOINT",
            "CODE-NONPRODUCTION-ENDPOINT",
            "CODE-HARDCODED-SECRET",
        },
        "title": "Release endpoint and embedded credential boundary",
        "severity": Severity.HIGH.value,
        "priority": 92,
        "path_hints": ("application", "app.smali", "uploader", "remote", "provider"),
        "preferred_only": True,
        "hypotheses": [
            (
                "Production startup or request code can select a pre, test, staging, development, "
                "or cleartext endpoint for user content, credentials, traces, or model traffic."
            ),
            (
                "A credential embedded in the APK is used for privileged request authentication, "
                "security-policy signing, or access to a reusable backend capability."
            ),
            (
                "The active release configuration creates a concrete interception, data exposure, "
                "environment-confusion, or server-impersonation impact."
            ),
        ],
    },
}


class BuiltinRuleEngine:
    def evaluate(
        self, result: StaticAnalysisResult
    ) -> tuple[list[FindingDraft], list[CoverageDraft]]:
        findings = self._manifest_rules(result.manifest)
        findings.extend(self._file_rules(result))
        findings.extend(self._code_rules(result.searchable_roots, result.workspace))
        findings.extend(self._attack_chain_rules(result.attack_chains))
        coverage = self._coverage(result, findings)
        return findings, coverage

    def static_review_surfaces(
        self,
        manifest: ManifestDocument,
        findings: list[FindingDraft],
    ) -> list[StaticReviewSurfaceDraft]:
        package_prefix = manifest.package_name.replace(".", "/") + "/"
        by_rule = {finding.rule_id: finding for finding in findings}
        surfaces: list[StaticReviewSurfaceDraft] = []
        for family, config in STATIC_REVIEW_FAMILIES.items():
            locations: list[dict[str, Any]] = []
            present_rule_ids: list[str] = []
            attack_chains: list[dict[str, Any]] = []
            for rule_id in sorted(config["rule_ids"]):
                finding = by_rule.get(rule_id)
                if finding is None:
                    continue
                is_chain_finding = bool(finding.metadata.get("attack_chains"))
                accepted = [
                    location
                    for location in finding.locations
                    if self._location_belongs_to_package(location, package_prefix)
                    or (
                        is_chain_finding
                        and location.get("analysis_scope") in {"manifest", "resource_config"}
                    )
                ]
                if not accepted:
                    continue
                present_rule_ids.append(rule_id)
                locations.extend(accepted)
                attack_chains.extend(
                    item
                    for item in finding.metadata.get("attack_chains", [])
                    if isinstance(item, dict)
                )
            if not locations:
                continue
            unique_locations = list(
                {
                    (
                        str(item.get("root") or ""),
                        str(item.get("path") or ""),
                        int(item.get("line") or 0),
                    ): item
                    for item in locations
                }.values()
            )
            hints = tuple(str(value).lower() for value in config["path_hints"])
            preferred = [
                item
                for item in unique_locations
                if any(hint in str(item.get("path") or "").lower() for hint in hints)
            ]
            if config.get("preferred_only") and preferred:
                unique_locations = preferred
            unique_locations.sort(
                key=lambda item: (
                    0 if any(hint in str(item.get("path") or "").lower() for hint in hints) else 1,
                    str(item.get("path") or ""),
                    int(item.get("line") or 0),
                )
            )
            surfaces.append(
                StaticReviewSurfaceDraft(
                    name=f"static://{family}",
                    family=family,
                    title=str(config["title"]),
                    severity=str(config["severity"]),
                    priority=int(config["priority"]),
                    rule_ids=present_rule_ids,
                    hypotheses=list(config["hypotheses"]),
                    locations=unique_locations[:12],
                    attack_chains=list(
                        {
                            str(item.get("fingerprint") or index): item
                            for index, item in enumerate(attack_chains)
                        }.values()
                    ),
                )
            )
        return surfaces

    @staticmethod
    def embedded_artifact_review_surfaces(
        result: StaticAnalysisResult,
    ) -> list[StaticReviewSurfaceDraft]:
        surfaces: list[StaticReviewSurfaceDraft] = []
        graph_nodes = {str(node.get("id")): node for node in result.artifact_graph.get("nodes", [])}
        graph_edges = list(result.artifact_graph.get("edges", []))
        for node in result.artifact_graph.get("nodes", []):
            origin = node.get("origin") or {}
            if node.get("kind") != "apk" or origin.get("kind") != "embedded_apk":
                continue
            analysis_root = result.workspace / str(node.get("analysis_root") or "")
            jadx_root = analysis_root / "jadx"
            source_root = jadx_root / "sources" if (jadx_root / "sources").is_dir() else jadx_root
            locations: list[dict[str, Any]] = []
            if source_root.is_dir():
                for source in sorted(source_root.rglob("*.java"))[:3]:
                    locations.append(
                        {
                            "root": BuiltinRuleEngine._search_root_label(
                                jadx_root,
                                result.workspace,
                            ),
                            "path": str(source.relative_to(jadx_root)),
                            "line": 1,
                            "artifact_id": node.get("id"),
                        }
                    )
            loader_nodes = [
                graph_nodes.get(str(edge.get("from")))
                for edge in graph_edges
                if edge.get("relation") == "loads_embedded_apk" and edge.get("to") == node.get("id")
            ]
            loader_nodes = [item for item in loader_nodes if item is not None]
            for loader in loader_nodes:
                for reference in loader.get("references") or []:
                    if not isinstance(reference, dict):
                        continue
                    locations.append(
                        {
                            "root": reference.get("root"),
                            "path": reference.get("path"),
                            "line": reference.get("line"),
                            "artifact_id": node.get("id"),
                            "relationship": "host_loader_reference",
                        }
                    )
            plugin_entry_nodes = [
                graph_nodes.get(str(edge.get("to")))
                for edge in graph_edges
                if edge.get("relation") == "declares_plugin_entry"
                and edge.get("from") == node.get("id")
            ]
            plugin_entry_nodes = [item for item in plugin_entry_nodes if item is not None]
            for entry_node in plugin_entry_nodes:
                source = result.workspace / str(entry_node.get("path") or "")
                for searchable_root in result.searchable_roots:
                    try:
                        relative = source.resolve().relative_to(searchable_root.resolve())
                    except ValueError:
                        continue
                    locations.append(
                        {
                            "root": BuiltinRuleEngine._search_root_label(
                                searchable_root,
                                result.workspace,
                            ),
                            "path": str(relative),
                            "line": int(entry_node.get("line") or 1),
                            "artifact_id": node.get("id"),
                            "relationship": "plugin_entry_candidate",
                        }
                    )
                    break
            package_name = str(node.get("package_name") or "unknown")
            sha256 = str(node.get("sha256") or "")
            archive_path = str(origin.get("archive_path") or node.get("path") or "")
            entry_names = [
                str(item.get("class_name") or item.get("name"))
                for item in plugin_entry_nodes
                if item.get("class_name") or item.get("name")
            ]
            surfaces.append(
                StaticReviewSurfaceDraft(
                    name=f"static://embedded_apk/{package_name}:{sha256[:12]}",
                    family="embedded_apk",
                    title=f"Embedded APK: {package_name}",
                    severity=Severity.HIGH.value,
                    priority=90,
                    rule_ids=[],
                    hypotheses=[
                        (
                            f"The host loads {archive_path} into its process, and plugin-specific "
                            "code reaches an Android IPC, WebView, file, account, or cross-app "
                            "operation that is security-sensitive."
                        ),
                        (
                            "The plugin receives caller-controlled or remotely supplied data from "
                            "the host without preserving the Android caller and authorization context."
                        ),
                        (
                            "Trace the concrete host loader and plugin entry contract before deciding "
                            "whether the embedded code is reachable from an untrusted Android entry. "
                            + (
                                f"Current entry candidates: {', '.join(entry_names[:6])}."
                                if entry_names
                                else "No plugin entry class has been resolved yet."
                            )
                        ),
                    ],
                    locations=list(
                        {
                            (
                                str(item.get("root") or ""),
                                str(item.get("path") or ""),
                                int(item.get("line") or 0),
                            ): item
                            for item in locations
                        }.values()
                    )[:12],
                    artifact={
                        **dict(node),
                        "host_loader_nodes": [dict(item) for item in loader_nodes],
                        "plugin_entry_nodes": [dict(item) for item in plugin_entry_nodes],
                    },
                )
            )
        return surfaces

    @staticmethod
    def _location_belongs_to_package(
        location: dict[str, Any],
        package_prefix: str,
    ) -> bool:
        path = PurePosixPath(str(location.get("path") or ""))
        normalized = "/".join(path.parts)
        return package_prefix in f"{normalized}/"

    def _manifest_rules(self, manifest: ManifestDocument) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        app = manifest.application
        if app["debuggable"]:
            findings.append(
                FindingDraft(
                    rule_id="MANIFEST-DEBUGGABLE",
                    title="Release APK is debuggable",
                    description="android:debuggable is enabled, allowing debugger attachment and inspection.",
                    remediation="Disable debuggable in every release build variant.",
                    masvs="MASVS-RESILIENCE",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    cwe="CWE-489",
                    locations=[{"path": "AndroidManifest.xml", "attribute": "android:debuggable"}],
                )
            )
        if app["test_only"]:
            findings.append(
                FindingDraft(
                    rule_id="MANIFEST-TEST-ONLY",
                    title="APK is marked testOnly",
                    description="The application manifest marks this artifact as test-only.",
                    remediation="Produce the release artifact without android:testOnly.",
                    masvs="MASVS-RESILIENCE",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    locations=[{"path": "AndroidManifest.xml", "attribute": "android:testOnly"}],
                )
            )
        if app["allow_backup"]:
            findings.append(
                FindingDraft(
                    rule_id="MANIFEST-ALLOW-BACKUP",
                    title="Application data backup is permitted",
                    description="Backup behavior may expose application data depending on Android version and data extraction rules.",
                    remediation="Explicitly define backup/data-extraction rules and exclude sensitive data.",
                    masvs="MASVS-STORAGE",
                    severity=Severity.LOW.value,
                    confidence=Confidence.MEDIUM.value,
                    cwe="CWE-530",
                    locations=[{"path": "AndroidManifest.xml", "attribute": "android:allowBackup"}],
                )
            )
        if app["uses_cleartext_traffic"]:
            findings.append(
                FindingDraft(
                    rule_id="MANIFEST-CLEARTEXT",
                    title="Cleartext network traffic may be permitted",
                    description="The manifest or target-SDK defaults allow cleartext traffic; active endpoints require runtime validation.",
                    remediation="Disable cleartext traffic and narrowly scope any required exceptions.",
                    masvs="MASVS-NETWORK",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.MEDIUM.value,
                    cwe="CWE-319",
                    locations=[
                        {"path": "AndroidManifest.xml", "attribute": "android:usesCleartextTraffic"}
                    ],
                )
            )
        for entry in manifest.entries:
            if entry.metadata.get("effective_enabled") is False:
                continue
            if entry.kind == EntryPointKind.DEEP_LINK.value:
                if not entry.exported:
                    continue
                findings.extend(self._deep_link_rules(entry))
                continue
            if not entry.exported:
                continue
            protection = (entry.permission_protection or "").lower()
            strongly_protected = "signature" in protection
            if entry.permission is None or not strongly_protected:
                severity = (
                    Severity.HIGH.value
                    if entry.kind in {EntryPointKind.PROVIDER.value, EntryPointKind.SERVICE.value}
                    else Severity.MEDIUM.value
                )
                findings.append(
                    FindingDraft(
                        rule_id=f"EXPORTED-{entry.kind.upper().replace('_', '-')}",
                        title=f"Exported {entry.kind.replace('_', ' ')} requires authorization review",
                        description=(
                            f"{entry.name} is externally reachable and is not protected by a signature-level permission. "
                            "Exported status alone is not a vulnerability; the handler's sensitive behavior must be validated."
                        ),
                        remediation="Keep the component private or enforce caller authorization appropriate to intended integrations.",
                        masvs="MASVS-PLATFORM",
                        severity=severity,
                        confidence=Confidence.HIGH.value,
                        cwe="CWE-926",
                        entry_names=[entry.name],
                        locations=[{"path": "AndroidManifest.xml", "component": entry.name}],
                        metadata={"exported_reason": entry.exported_reason},
                    )
                )
        return findings

    @staticmethod
    def _deep_link_rules(entry: ParsedEntryPoint) -> list[FindingDraft]:
        link = entry.deep_links[0]
        scheme = link.get("scheme")
        if scheme not in {"http", "https"}:
            return [
                FindingDraft(
                    rule_id="DEEPLINK-CUSTOM-SCHEME",
                    title="Sensitive behavior may rely on an unverified custom URL scheme",
                    description=f"{entry.name} uses a custom scheme that any installed application can claim.",
                    remediation="Use verified Android App Links for sensitive flows and treat every parameter as untrusted.",
                    masvs="MASVS-PLATFORM",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    cwe="CWE-939",
                    entry_names=[entry.name],
                    locations=[{"path": "AndroidManifest.xml", "component": entry.owner_component}],
                )
            ]
        if not link.get("auto_verify"):
            return [
                FindingDraft(
                    rule_id="DEEPLINK-UNVERIFIED-APP-LINK",
                    title="HTTP(S) deep link does not request App Link verification",
                    description=f"{entry.name} can be intercepted or resolved unexpectedly because autoVerify is absent.",
                    remediation="Set autoVerify and publish a valid Digital Asset Links statement for every host.",
                    masvs="MASVS-PLATFORM",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    cwe="CWE-939",
                    entry_names=[entry.name],
                    locations=[{"path": "AndroidManifest.xml", "component": entry.owner_component}],
                )
            ]
        return []

    @staticmethod
    def _file_rules(result: StaticAnalysisResult) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        if result.signing and not result.signing.get("verified"):
            findings.append(
                FindingDraft(
                    rule_id="APK-SIGNATURE-INVALID",
                    title="APK signature verification failed",
                    description="apksigner could not verify the uploaded artifact as a valid signed APK.",
                    remediation="Reject the artifact and rebuild/sign it through the controlled release pipeline.",
                    masvs="MASVS-CODE",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    cwe="CWE-353",
                )
            )
        schemes = result.signing.get("schemes", {}) if result.signing else {}
        if (
            result.signing.get("verified")
            and schemes.get("v1")
            and not any(schemes.get(version) for version in ("v2", "v3", "v3.1", "v4"))
        ):
            findings.append(
                FindingDraft(
                    rule_id="APK-SIGNATURE-V1-ONLY",
                    title="APK uses only the legacy v1 signature scheme",
                    description="The artifact verifies with JAR signing but no modern whole-file APK signature was reported.",
                    remediation="Enable a modern APK Signature Scheme supported by the deployment baseline.",
                    masvs="MASVS-CODE",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    cwe="CWE-347",
                )
            )
        duplicates = result.file_inventory.get("duplicate_names", [])
        if duplicates:
            findings.append(
                FindingDraft(
                    rule_id="APK-DUPLICATE-ZIP-ENTRIES",
                    title="APK contains duplicate ZIP entries",
                    description="Different APK parsers may interpret duplicate paths inconsistently.",
                    remediation="Produce a canonical APK without duplicate archive paths.",
                    masvs="MASVS-CODE",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.HIGH.value,
                    cwe="CWE-436",
                    metadata={"paths": duplicates},
                )
            )
        if result.file_inventory.get("native_libraries"):
            graph_summary = dict(result.artifact_graph.get("summary") or {})
            findings.append(
                FindingDraft(
                    rule_id="APK-NATIVE-CODE-INVENTORY",
                    title="APK contains native code requiring separate review",
                    description=(
                        "Native libraries cross the Java decompiler boundary. The ArtifactGraph "
                        "contains normalized ELF, dynamic-symbol, JNI and Java loading links for "
                        "targeted follow-up."
                    ),
                    remediation=(
                        "Follow linked Java/JNI/SO boundaries and review the concrete native "
                        "operation reached from application input."
                    ),
                    masvs="MASVS-CODE",
                    severity=Severity.INFO.value,
                    confidence=Confidence.HIGH.value,
                    metadata={
                        "libraries": result.file_inventory["native_libraries"],
                        "artifact_graph_path": "artifact_graph.json",
                        "native_summary": {
                            key: graph_summary.get(key)
                            for key in (
                                "native_library_count",
                                "java_native_bridge_count",
                                "java_native_method_count",
                                "linked_java_native_method_count",
                                "jni_symbol_count",
                                "native_libraries_by_abi",
                            )
                        },
                    },
                )
            )
        return findings

    def _code_rules(self, roots: list[Path], workspace: Path) -> list[FindingDraft]:
        matches: dict[str, list[dict[str, Any]]] = {rule[0]: [] for rule in CODE_RULES}
        for root in roots:
            optimized_paths = files_containing_any(
                root,
                literals=CODE_RULE_PREFILTER_LITERALS,
                suffixes=(
                    ".java",
                    ".kt",
                    ".smali",
                    ".xml",
                    ".js",
                    ".mjs",
                    ".cjs",
                    ".html",
                    ".htm",
                ),
                ignore_case=True,
            )
            paths = (
                self._iter_code_files(root)
                if optimized_paths is None
                else self._bounded_code_files(optimized_paths)
            )
            for path in paths:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for rule_id, pattern, *_rest in CODE_RULES:
                    match_limit = (
                        100
                        if rule_id == "CODE-NONPRODUCTION-ENDPOINT"
                        else 50
                        if rule_id == "CODE-HARDCODED-SECRET"
                        else 25
                    )
                    if len(matches[rule_id]) >= match_limit:
                        continue
                    for accepted_for_file, match in enumerate(
                        pattern.finditer(text),
                        start=1,
                    ):
                        line = text.count("\n", 0, match.start()) + 1
                        matches[rule_id].append(
                            {
                                "path": str(path.relative_to(root)),
                                "line": line,
                                "root": self._search_root_label(root, workspace),
                            }
                        )
                        if len(matches[rule_id]) >= match_limit:
                            break
                        if accepted_for_file >= 3:
                            break
        findings: list[FindingDraft] = []
        for rule_id, _pattern, title, remediation, masvs, severity, cwe in CODE_RULES:
            locations = matches[rule_id]
            if not locations:
                continue
            findings.append(
                FindingDraft(
                    rule_id=rule_id,
                    title=title,
                    description="A security-sensitive API pattern was found in decompiled code and requires semantic review.",
                    remediation=remediation,
                    masvs=masvs,
                    severity=severity.value,
                    confidence=Confidence.LOW.value,
                    cwe=cwe,
                    locations=locations,
                )
            )
        return findings

    @staticmethod
    def _attack_chain_rules(
        attack_chains: list[dict[str, Any]],
    ) -> list[FindingDraft]:
        configs = {
            "capability_delegation_boundary": {
                "rule_id": "CHAIN-ANDROID-CAPABILITY-DELEGATION",
                "title": "Android capability delegation chain requires review",
                "description": (
                    "A bounded app-class reference path connects PendingIntent, nested Intent, "
                    "Activity result, sensitive implicit IPC, or content-URI capability handling "
                    "to delegation, privileged content access, or dispatch behavior. This is an "
                    "explainable investigation seed, not an exploitation verdict."
                ),
                "remediation": (
                    "Use explicit immutable PendingIntents, sanitize nested Intents, narrowly "
                    "scope URI grants, validate result-provider authority, and make sensitive IPC "
                    "destinations explicit or permission protected."
                ),
                "cwe": "CWE-926",
            },
            "external_file_ingress_boundary": {
                "rule_id": "CHAIN-ANDROID-FILE-INGRESS",
                "title": "External file ingress reaches a filesystem or archive boundary",
                "description": (
                    "A bounded app-class reference path connects ACTION_SEND, SAF, content URI, "
                    "or FileProvider input to file writing or archive processing. The path and "
                    "provider behavior require semantic and ordinary-app validation."
                ),
                "remediation": (
                    "Ignore provider-controlled filenames, generate private destinations, reject "
                    "links, and verify canonical containment for every extracted or copied item."
                ),
                "cwe": "CWE-22",
            },
            "runtime_ipc_boundary": {
                "rule_id": "CHAIN-ANDROID-RUNTIME-IPC",
                "title": "Runtime IPC surface requires caller and peer validation",
                "description": (
                    "The APK contains a context-registered receiver or local TCP/Unix-domain "
                    "server, or a Binder authorization path involving caller-provided package "
                    "identity. Export flags, sender permissions, peer authentication, calling UID "
                    "binding, and reachable privileged handlers require validation."
                ),
                "remediation": (
                    "Keep receivers non-exported unless required, enforce signature permissions, "
                    "authenticate local socket peers, and derive Binder caller identity from "
                    "Binder.getCallingUid() before parsing commands or returning data."
                ),
                "cwe": "CWE-306",
            },
            "web_content_boundary": {
                "rule_id": "CHAIN-ANDROID-WEBVIEW-DATAFLOW",
                "title": "External Android input reaches a WebView boundary",
                "description": (
                    "A bounded app-class reference path connects Intent, URI, shared content, or "
                    "WebView navigation input to WebView content or native bridge APIs. Origin "
                    "checks and runtime navigation must be verified."
                ),
                "remediation": (
                    "Parse and compare complete trusted origins, reject local and active-content "
                    "schemes, minimize bridges, and authorize every native bridge method."
                ),
                "cwe": "CWE-749",
            },
        }
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in attack_chains:
            if item.get("review_required") is False:
                continue
            family = str(item.get("family") or "")
            if family in configs:
                grouped.setdefault(family, []).append(item)
        findings: list[FindingDraft] = []
        for family, candidates in grouped.items():
            config = configs[family]
            locations: list[dict[str, Any]] = []
            for candidate in candidates:
                locations.extend(
                    item for item in candidate.get("locations", []) if isinstance(item, dict)
                )
            unique_locations = list(
                {
                    (
                        str(item.get("root") or ""),
                        str(item.get("path") or ""),
                        int(item.get("line") or 0),
                        str(item.get("marker") or ""),
                    ): item
                    for item in locations
                }.values()
            )
            severity = max(
                (str(item.get("severity") or Severity.MEDIUM.value) for item in candidates),
                key=lambda value: {
                    Severity.INFO.value: 0,
                    Severity.LOW.value: 1,
                    Severity.MEDIUM.value: 2,
                    Severity.HIGH.value: 3,
                    Severity.CRITICAL.value: 4,
                }.get(value, 0),
            )
            findings.append(
                FindingDraft(
                    rule_id=str(config["rule_id"]),
                    title=str(config["title"]),
                    description=str(config["description"]),
                    remediation=str(config["remediation"]),
                    masvs="MASVS-PLATFORM",
                    severity=severity,
                    confidence=Confidence.LOW.value,
                    cwe=str(config["cwe"]),
                    locations=unique_locations[:50],
                    metadata={
                        "candidate_only": True,
                        "analysis_engine": str(
                            candidates[0].get("engine_version") or "bounded-android-chain-v1"
                        ),
                        "attack_chains": candidates,
                    },
                )
            )
        return findings

    @staticmethod
    def _iter_code_files(root: Path):  # noqa: ANN205
        return BuiltinRuleEngine._bounded_code_files(root.rglob("*"))

    @staticmethod
    def _bounded_code_files(paths):  # noqa: ANN001, ANN205
        total = 0
        for path in paths:
            if not path.is_file() or path.suffix.lower() not in {
                ".java",
                ".kt",
                ".smali",
                ".xml",
                ".js",
                ".mjs",
                ".cjs",
                ".html",
                ".htm",
            }:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > 2_000_000:
                continue
            total += size
            if total > 250_000_000:
                break
            yield path

    @staticmethod
    def _search_root_label(root: Path, workspace: Path) -> str:
        try:
            return str(root.resolve().relative_to(workspace.resolve()))
        except ValueError:
            return root.name

    @staticmethod
    def _coverage(
        result: StaticAnalysisResult, findings: list[FindingDraft]
    ) -> list[CoverageDraft]:
        domains = {
            "MASVS-STORAGE": "Sensitive data storage",
            "MASVS-CRYPTO": "Cryptographic usage",
            "MASVS-AUTH": "Authentication and authorization",
            "MASVS-NETWORK": "Network communication",
            "MASVS-PLATFORM": "Android platform interaction",
            "MASVS-CODE": "Code and dependency safety",
            "MASVS-RESILIENCE": "Reverse engineering and tamper resilience",
            "MASVS-PRIVACY": "Privacy-related permissions and SDKs",
        }
        component_statuses = [str(item.get("status")) for item in result.code_index.values()]
        component_code_available = any(
            status
            in {
                "source_available",
                "partial_source_available",
                "smali_fallback",
            }
            for status in component_statuses
        )
        global_decompilation_status = str(result.decompilation.get("status") or "")
        global_code_available = bool(
            result.decompilation.get("output_usable")
            or result.decompilation.get("generated_java_files", 0)
            or global_decompilation_status in {"complete", "partial_success"}
        )
        code_available = (
            component_code_available
            or global_code_available
            or any(item.rule_id.startswith("CODE-") for item in findings)
        )
        full_code_coverage = (
            global_decompilation_status == "complete"
            and global_code_available
            and all(status == "source_available" for status in component_statuses)
        )
        incomplete_components = sum(status != "source_available" for status in component_statuses)
        coverage: list[CoverageDraft] = []
        for domain, title in domains.items():
            partial = domain in {"MASVS-AUTH", "MASVS-PRIVACY"} or not full_code_coverage
            gap = None
            if domain == "MASVS-AUTH":
                gap = (
                    "APK-only analysis and one test account cannot prove server-side authorization."
                )
            elif domain == "MASVS-PRIVACY":
                gap = "Runtime data collection and declared privacy policy are not available from the APK alone."
            elif not code_available:
                gap = "No searchable application code was available; manifest and archive checks only."
            elif global_decompilation_status == "partial_success":
                gap = (
                    "Decompiler output was only partially successful; code coverage cannot "
                    "be considered complete."
                )
            elif incomplete_components:
                gap = (
                    f"{incomplete_components} of {len(component_statuses)} target component(s) "
                    "lack complete decompiled source."
                )
            elif not full_code_coverage:
                gap = (
                    "Searchable code was available only through a degraded or fallback path; "
                    "code coverage is partial."
                )
            coverage.append(
                CoverageDraft(
                    control_id=f"{domain}-BASELINE",
                    domain=domain,
                    title=title,
                    status=(CoverageStatus.PARTIAL if partial else CoverageStatus.COVERED).value,
                    stages={
                        "static": "completed",
                        "deterministic_dynamic": "pending",
                        "agent": "pending",
                        "blackbox": "pending",
                        "finding_count": sum(item.masvs == domain for item in findings),
                    },
                    gap_reason=gap,
                )
            )
        return coverage
