from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .enums import Confidence, CoverageStatus, EntryPointKind, Severity
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
        re.compile(r"Cipher\.getInstance\s*\([^\n]*(ECB|DES)|MessageDigest\.getInstance\s*\([^\n]*(MD5|SHA-?1)"),
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
        re.compile(r"(?i)(?:http|ws)://(?!127\.0\.0\.1|localhost)[^\s\"']+"),
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
        re.compile(
            r"(?i)(?:https?|wss?)://[^\s\"']*(?:pre|test|staging|dev)[^\s\"']*"
        ),
        "Release code references a non-production service endpoint",
        "Use environment-bound release configuration and reject pre, test, staging, or development endpoints in production artifacts.",
        "MASVS-NETWORK",
        Severity.HIGH,
        "CWE-16",
    ),
    (
        "CODE-HARDCODED-SECRET",
        re.compile(
            r'\.field[^\n]*(?:app[_-]?secret|app[_-]?key|client[_-]?secret|'
            r'api[_-]?key)[^\n]*=\s*"[A-Za-z0-9+/=_-]{12,}"|'
            r'(?:app[_-]?secret|app[_-]?key|client[_-]?secret|api[_-]?key)'
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


STATIC_REVIEW_FAMILIES: dict[str, dict[str, Any]] = {
    "web_content_boundary": {
        "rule_ids": {
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
        "rule_ids": {"CODE-UNTRUSTED-DISPLAY-NAME"},
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
        findings.extend(self._code_rules(result.searchable_roots))
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
            for rule_id in sorted(config["rule_ids"]):
                finding = by_rule.get(rule_id)
                if finding is None:
                    continue
                accepted = [
                    location
                    for location in finding.locations
                    if self._location_belongs_to_package(location, package_prefix)
                ]
                if not accepted:
                    continue
                present_rule_ids.append(rule_id)
                locations.extend(accepted)
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
                if any(
                    hint in str(item.get("path") or "").lower()
                    for hint in hints
                )
            ]
            if config.get("preferred_only") and preferred:
                unique_locations = preferred
            unique_locations.sort(
                key=lambda item: (
                    0
                    if any(hint in str(item.get("path") or "").lower() for hint in hints)
                    else 1,
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
                    locations=[{"path": "AndroidManifest.xml", "attribute": "android:usesCleartextTraffic"}],
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
        if result.signing.get("verified") and schemes.get("v1") and not any(
            schemes.get(version) for version in ("v2", "v3", "v3.1", "v4")
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
            findings.append(
                FindingDraft(
                    rule_id="APK-NATIVE-CODE-INVENTORY",
                    title="APK contains native code requiring separate review",
                    description="Native libraries are outside the high-level decompiler's complete coverage.",
                    remediation="Run native hardening and memory-safety checks for the listed libraries.",
                    masvs="MASVS-CODE",
                    severity=Severity.INFO.value,
                    confidence=Confidence.HIGH.value,
                    metadata={"libraries": result.file_inventory["native_libraries"]},
                )
            )
        return findings

    def _code_rules(self, roots: list[Path]) -> list[FindingDraft]:
        matches: dict[str, list[dict[str, Any]]] = {rule[0]: [] for rule in CODE_RULES}
        for root in roots:
            for path in self._iter_code_files(root):
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
                                "root": root.name,
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
    def _iter_code_files(root: Path):  # noqa: ANN205
        total = 0
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".java", ".kt", ".smali", ".xml"}:
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
        component_statuses = [
            str(item.get("status")) for item in result.code_index.values()
        ]
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
        code_available = component_code_available or global_code_available or any(
            item.rule_id.startswith("CODE-") for item in findings
        )
        full_code_coverage = (
            global_decompilation_status == "complete"
            and global_code_available
            and all(status == "source_available" for status in component_statuses)
        )
        incomplete_components = sum(
            status != "source_available" for status in component_statuses
        )
        coverage: list[CoverageDraft] = []
        for domain, title in domains.items():
            partial = (
                domain in {"MASVS-AUTH", "MASVS-PRIVACY"}
                or not full_code_coverage
            )
            gap = None
            if domain == "MASVS-AUTH":
                gap = "APK-only analysis and one test account cannot prove server-side authorization."
            elif domain == "MASVS-PRIVACY":
                gap = "Runtime data collection and declared privacy policy are not available from the APK alone."
            elif not code_available:
                gap = (
                    "No searchable application code was available; manifest and archive checks only."
                )
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
