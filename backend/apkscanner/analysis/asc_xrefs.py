"""Optional ASC (``droidasc``) bytecode-level cross-reference extraction.

ASC answers "who references this string / type / method / field" by scanning the
DEX directly instead of decompiling the APK first.  That is the one static fact
our own pipeline approximates with regexes over decompiled text, so the result is
recorded as a platform-issued ``static.droidasc`` Evidence artifact and projected
into each task's bounded agent context as ``xrefs.json``.

The integration is optional and failure-isolated: a missing package, a sandbox
that forbids ``multiprocessing`` (the CLI transport uses a process pool), or a
tool error only marks the extraction unusable and lets the scan continue.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
import threading
import zipfile
from collections import defaultdict
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..core.config import Settings
from ..infrastructure.tools import TimeBudget, ToolRunner

QueryKind = Literal["string", "type", "method", "field"]

# ``<dex> | <Lclass;-><method> | matched=(<hit>; <hit>)`` as emitted by
# ``AscHandler.findrefs`` and the ``droidasc findrefs`` CLI.
_REFERENCE_LINE = re.compile(
    r"^(?P<dex>[^|]+?)\s*\|\s*(?P<member>[^|]+?)\s*\|\s*matched=\((?P<matched>.*)\)\s*$"
)
_MEMBER = re.compile(r"^(?P<class>L[^;]+;)->(?P<method>.+)$")
_DEX_ENTRY = re.compile(r"^classes\d*\.dex$")
_ASC_VERSION: str | None = None
_ASC_VERSION_LOCK = threading.Lock()


def _asc_package_version() -> str | None:
    global _ASC_VERSION
    with _ASC_VERSION_LOCK:
        if _ASC_VERSION is None:
            try:
                _ASC_VERSION = importlib.metadata.version("droidasc")
            except importlib.metadata.PackageNotFoundError:
                _ASC_VERSION = ""
        return _ASC_VERSION or None


def _normalize_class(name: str) -> str:
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    normalized = name.replace(".", "/")
    if not normalized.startswith("L"):
        normalized = f"L{normalized}"
    if not normalized.endswith(";"):
        normalized = f"{normalized};"
    return normalized


def _normalize_class_query(name: str, fuzzy: bool) -> str:
    if fuzzy:
        return name.replace(".", "/") if "." in name and "/" not in name else name
    return _normalize_class(name)


@dataclass(frozen=True, slots=True)
class AscQuery:
    """One inbound-reference question for ASC."""

    kind: QueryKind
    value: str
    class_name: str | None = None
    fuzzy_class: bool = False
    reason: str = ""

    @property
    def key(self) -> str:
        suffix = f"@{self.class_name}" if self.class_name else ""
        return f"{self.kind}:{self.value}{suffix}"

    def find_payload(self) -> dict[str, Any]:
        """Mirror ``droidasc.cli._get_find_query`` so the library and CLI agree."""

        if self.kind in {"string", "type"}:
            return {self.kind: self.value}
        if self.class_name is None:
            return {self.kind: {"class": None, self.kind: self.value}}
        return {
            self.kind: {
                "class": [
                    _normalize_class_query(self.class_name, self.fuzzy_class),
                    not self.fuzzy_class,
                ],
                self.kind: self.value,
            }
        }


@dataclass(slots=True)
class AscExtraction:
    """Structured, bounded result of one APK's cross-reference extraction."""

    apk_sha256: str
    tool_version: str | None
    transport: str
    queries: list[dict[str, str]]
    references: list[dict[str, Any]]
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        """A clean run is usable even when no query matched (zero hits is a fact)."""

        return not self.errors

    def as_evidence_payload(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "tool": "droidasc",
            "tool_version": self.tool_version,
            "transport": self.transport,
            "apk_sha256": self.apk_sha256,
            "queries": self.queries,
            "reference_count": len(self.references),
            "references": self.references,
            "stats": self.stats,
            "errors": self.errors,
        }


def parse_reference_lines(
    lines: Sequence[str],
    *,
    query: AscQuery,
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    """Parse ASC's text output; returns ``(references, dropped)``."""

    references: list[dict[str, Any]] = []
    dropped = 0
    for line in lines:
        match = _REFERENCE_LINE.match(line.strip())
        if match is None:
            continue
        member = _MEMBER.match(match.group("member").strip())
        if member is None:
            continue
        if len(references) >= limit:
            dropped += 1
            continue
        matched = tuple(
            value.strip()
            for value in match.group("matched").split("; ")
            if value.strip()
        )
        references.append(
            {
                "query": query.key,
                "query_kind": query.kind,
                "query_value": query.value,
                "reason": query.reason,
                "dex": match.group("dex").strip(),
                "class": member.group("class"),
                "method": member.group("method"),
                "matched": list(matched),
            }
        )
    return references, dropped


class AscXrefExtractor:
    """Run inbound cross-reference queries against an APK, library or CLI."""

    def __init__(self, settings: Settings, runner: ToolRunner | None = None):
        self.settings = settings
        self.runner = runner or ToolRunner(settings.tool_timeout_seconds)
        self._backend_lock = threading.Lock()
        self._library_error: str | None = None
        self._library_handler: Any = None

    # ── availability ────────────────────────────────────────────────────────

    def _library_handler_or_error(self) -> tuple[Any, str | None]:
        with self._backend_lock:
            if self._library_handler is not None:
                return self._library_handler, None
            if self._library_error is not None:
                return None, self._library_error
            try:
                from droidasc.asc_client.asc_handler import AscHandler

                self._library_handler = AscHandler()
            except Exception as exc:  # pragma: no cover - depends on install
                self._library_error = f"{type(exc).__name__}: {exc}"
                return None, self._library_error
            return self._library_handler, None

    def available(self) -> tuple[bool, str | None]:
        """Return ``(available, detail)`` without raising."""

        transport = self.settings.asc_transport
        if transport in {"auto", "library"}:
            _handler, error = self._library_handler_or_error()
            if error is None:
                return True, "library"
            if transport == "library":
                return False, f"droidasc library unavailable ({error})"
        executable = self.runner.available(self.settings.asc_path)
        if executable:
            return True, "cli"
        return False, "droidasc is neither importable nor on PATH"

    def version(self) -> str | None:
        return _asc_package_version()

    # ── extraction ──────────────────────────────────────────────────────────

    def extract(
        self,
        apk_path: Path,
        queries: Sequence[AscQuery],
        *,
        budget: TimeBudget | None = None,
        max_references: int | None = None,
    ) -> AscExtraction:
        apk_path = Path(apk_path)
        apk_sha256 = _file_sha256(apk_path)
        selected = list(dict.fromkeys(queries))[: max(1, int(self.settings.asc_max_queries))]
        reference_limit = max_references or self.settings.asc_max_results_per_query
        query_payload = [
            {"kind": item.kind, "value": item.value, "class": item.class_name or "",
             "reason": item.reason}
            for item in selected
        ]
        stats: dict[str, Any] = {
            "apk_bytes": apk_path.stat().st_size if apk_path.is_file() else 0,
            "query_count": len(selected),
            "dex_entry_count": 0,
            "per_query": {},
        }
        errors: list[str] = []
        references: list[dict[str, Any]] = []
        available, transport = self.available()
        if not available:
            return AscExtraction(
                apk_sha256=apk_sha256,
                tool_version=self.version(),
                transport=self.settings.asc_transport,
                queries=query_payload,
                references=[],
                stats=stats,
                errors=[str(transport)],
            )
        transport = str(transport)
        if budget is not None and budget.expired:
            errors.append("task budget exhausted before ASC extraction")
            return AscExtraction(
                apk_sha256=apk_sha256,
                tool_version=self.version(),
                transport=transport,
                queries=query_payload,
                references=[],
                stats=stats,
                errors=errors,
            )
        try:
            if transport == "library":
                references, stats, errors = self._extract_library(
                    apk_path, selected, reference_limit, stats, budget
                )
            else:
                references, stats, errors = self._extract_cli(
                    apk_path, selected, reference_limit, stats, budget
                )
        except Exception as exc:  # failure isolation: never break the scan
            errors.append(f"{type(exc).__name__}: {exc}")
        return AscExtraction(
            apk_sha256=apk_sha256,
            tool_version=self.version(),
            transport=transport,
            queries=query_payload,
            references=references,
            stats=stats,
            errors=errors,
        )

    # ── library transport ───────────────────────────────────────────────────

    def _iter_dex_entries(self, apk_path: Path) -> Iterator[tuple[str, bytes]]:
        """Yield ``(entry_name, dex_bytes)`` one DEX at a time.

        Streaming keeps peak RSS at roughly one DEX instead of every
        ``classes*.dex`` in the APK.
        """

        with zipfile.ZipFile(apk_path) as archive:
            names = [
                name
                for name in archive.namelist()
                if _DEX_ENTRY.match(Path(name).name) and not name.endswith("/")
            ]
            # ``classes.dex`` first, then numeric order, matching the CLI.
            names.sort(key=lambda value: (Path(value).name != "classes.dex", Path(value).name))
            for name in names:
                info = archive.getinfo(name)
                if info.file_size <= 0:
                    continue
                yield name, archive.read(info)

    def _extract_library(
        self,
        apk_path: Path,
        queries: list[AscQuery],
        reference_limit: int,
        stats: dict[str, Any],
        budget: TimeBudget | None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
        handler, error = self._library_handler_or_error()
        if handler is None:
            return [], stats, [f"droidasc library unavailable ({error})"]
        errors: list[str] = []
        references: list[dict[str, Any]] = []
        per_query: dict[str, int] = defaultdict(int)
        dropped: dict[str, int] = defaultdict(int)
        workers = max(1, min(int(self.settings.asc_workers), len(queries) or 1))
        dex_count = 0

        def run_one(
            dex_name: str, dex_bytes: bytes, query: AscQuery
        ) -> tuple[AscQuery, list[str], str | None]:
            try:
                lines = handler.findrefs(dex_name, dex_bytes, query.kind, query.find_payload())
            except Exception as exc:
                return query, [], f"{dex_name}: {type(exc).__name__}: {exc}"
            return query, list(lines or []), None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            # Streamed: only the current DEX is resident.
            for dex_name, dex_bytes in self._iter_dex_entries(apk_path):
                dex_count += 1
                if budget is not None and budget.expired:
                    errors.append("task budget exhausted during ASC extraction")
                    break
                futures = [
                    pool.submit(run_one, dex_name, dex_bytes, query) for query in queries
                ]
                for future in futures:
                    query, lines, failure = future.result()
                    if failure is not None:
                        if failure not in errors:
                            errors.append(failure)
                        continue
                    parsed, overflow = parse_reference_lines(
                        lines, query=query, limit=reference_limit
                    )
                    references.extend(parsed)
                    per_query[query.key] += len(parsed)
                    dropped[query.key] += overflow
                    if len(errors) > 32:
                        break
        stats["dex_entry_count"] = dex_count
        stats["per_query"] = dict(per_query)
        stats["dropped_per_query"] = {key: value for key, value in dropped.items() if value}
        stats["reference_count"] = len(references)
        return references, stats, errors

    # ── CLI transport ───────────────────────────────────────────────────────

    def _extract_cli(
        self,
        apk_path: Path,
        queries: list[AscQuery],
        reference_limit: int,
        stats: dict[str, Any],
        budget: TimeBudget | None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
        errors: list[str] = []
        references: list[dict[str, Any]] = []
        per_query: dict[str, int] = defaultdict(int)
        timeout = max(1, int(self.settings.asc_timeout_seconds))
        for query in queries:
            if budget is not None and budget.expired:
                errors.append("task budget exhausted during ASC extraction")
                break
            args = [
                self.settings.asc_path,
                "findrefs",
                str(apk_path),
                "--threads",
                str(max(1, int(self.settings.asc_workers))),
                query.kind,
            ]
            if query.kind == "string" or query.kind == "type":
                args.append(query.value)
            else:
                if query.value:
                    args.append(query.value)
                if query.class_name:
                    args.extend(["--class", query.class_name])
                    if query.fuzzy_class:
                        args.append("--fuzzy-class")
            result = self.runner.run(args, timeout=timeout)
            if result.exit_code != 0:
                detail = (result.stderr or result.stdout or "").strip().splitlines()
                errors.append(
                    f"{query.key}: exit={result.exit_code} {detail[0] if detail else 'no diagnostic'}"
                )
                continue
            parsed, overflow = parse_reference_lines(
                result.stdout.splitlines(), query=query, limit=reference_limit
            )
            references.extend(parsed)
            per_query[query.key] += len(parsed)
        stats["per_query"] = dict(per_query)
        stats["reference_count"] = len(references)
        return references, stats, errors


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


# High-value, scan-wide inbound-reference anchors.  Every entry is a query ASC
# answers from the DEX directly, so it is cheap compared with decompiling.
_SCAN_WIDE_QUERIES: tuple[AscQuery, ...] = (
    AscQuery("method", "addJavascriptInterface", reason="webview_bridge"),
    AscQuery("method", "setJavaScriptEnabled", reason="webview_settings"),
    AscQuery("method", "shouldOverrideUrlLoading", reason="webview_navigation"),
    AscQuery("method", "getCallingPackage", reason="caller_identity"),
    AscQuery("method", "getCallingUid", reason="caller_identity"),
    AscQuery("method", "checkCallingPermission", reason="caller_permission_check"),
    AscQuery("method", "enforceCallingPermission", reason="caller_permission_check"),
    AscQuery("method", "openFile", reason="provider_file_access"),
    AscQuery("method", "getParcelableExtra", reason="nested_intent"),
    AscQuery("method", "getSerializableExtra", reason="nested_intent"),
    AscQuery("method", "loadLibrary", reason="native_load"),
    AscQuery("method", "DexClassLoader", reason="dynamic_code_load"),
    AscQuery("method", "startService", reason="service_dispatch"),
    AscQuery("method", "sendBroadcast", reason="broadcast_dispatch"),
    AscQuery("method", "startActivity", reason="intent_dispatch"),
    AscQuery("type", "Landroid/webkit/WebView;", reason="webview_type"),
    AscQuery("type", "Landroid/content/Intent;", reason="intent_type"),
    AscQuery("type", "Ldalvik/system/DexClassLoader;", reason="dynamic_loader_type"),
    AscQuery("string", "javascript:", reason="javascript_url"),
    AscQuery("string", "file://", reason="file_url"),
    AscQuery("string", "content://", reason="content_uri"),
)


def build_asc_queries(
    entries: Sequence[Any],
    *,
    max_queries: int,
    include_scan_wide: bool = True,
) -> list[AscQuery]:
    """Derive bounded, security-relevant inbound-reference queries.

    Per entry we ask about the component class itself (who references it, i.e.
    possible cross-component chains) plus the concrete data it exposes
    (deep-link URIs, provider authorities).  Scan-wide anchors cover the
    dangerous sinks even when the entry set is small.
    """

    queries: list[AscQuery] = []

    def add(query: AscQuery) -> None:
        if query.value:
            queries.append(query)

    for entry in entries:
        kind = str(getattr(entry, "kind", "") or "")
        name = str(getattr(entry, "name", "") or "")
        owner = str(getattr(entry, "owner_component", "") or "") or name
        metadata = getattr(entry, "metadata_json", None) or {}
        if owner and kind in {
            "activity",
            "activity_alias",
            "service",
            "receiver",
            "provider",
            "deep_link",
        }:
            add(AscQuery("type", _normalize_class(owner), reason=f"entry_owner:{kind}"))
        if kind == "deep_link" and name:
            add(AscQuery("string", name, reason="deeplink_uri_template"))
            if "://" in name:
                scheme = name.split("://", 1)[0]
                add(AscQuery("string", f"{scheme}://", reason="deeplink_scheme"))
        if kind == "provider":
            authorities = str(metadata.get("authorities") or "")
            for authority in authorities.split(";"):
                authority = authority.strip()
                if authority:
                    add(AscQuery("string", f"content://{authority}", reason="provider_authority"))
        for item in getattr(entry, "deep_links", None) or []:
            if isinstance(item, dict):
                uri = str(item.get("uri_template") or "")
                if uri:
                    add(AscQuery("string", uri, reason="deeplink_uri_template"))
    def dedupe(candidates: Sequence[AscQuery], cap: int) -> list[AscQuery]:
        unique: list[AscQuery] = []
        seen: set[str] = set()
        for query in candidates:
            if query.key in seen:
                continue
            seen.add(query.key)
            unique.append(query)
            if len(unique) >= cap:
                break
        return unique

    budget = max(1, int(max_queries))
    scan_wide = dedupe(_SCAN_WIDE_QUERIES, budget) if include_scan_wide else []
    # Reserve room for the scan-wide sinks so a scan with many entries cannot
    # crowd out e.g. addJavascriptInterface or content:// coverage.
    entry_budget = max(0, budget - len(scan_wide))
    entry_queries = dedupe(queries, entry_budget) if entry_budget else []
    return dedupe([*entry_queries, *scan_wide], budget)


def relevance_filter(
    references: Sequence[dict[str, Any]],
    entries: Sequence[Any],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Keep the references that matter for this task's entries, then scan anchors.

    Entry-specific hits come first so a bounded projection keeps the edges that
    connect the assigned components to the rest of the APK.
    """

    entry_terms: set[str] = set()
    for entry in entries:
        name = str(getattr(entry, "name", "") or "")
        owner = str(getattr(entry, "owner_component", "") or "") or name
        if owner:
            entry_terms.add(_normalize_class(owner))
            entry_terms.add(owner)
        if name:
            entry_terms.add(name)
        metadata = getattr(entry, "metadata_json", None) or {}
        for authority in str(metadata.get("authorities") or "").split(";"):
            authority = authority.strip()
            if authority:
                entry_terms.add(authority)
                entry_terms.add(f"content://{authority}")

    def score(reference: dict[str, Any]) -> tuple[int, str, str, str]:
        blob = " ".join(
            [
                str(reference.get("class") or ""),
                str(reference.get("query_value") or ""),
                " ".join(str(value) for value in reference.get("matched") or []),
            ]
        )
        entry_specific = any(term and term in blob for term in entry_terms)
        return (
            0 if entry_specific else 1,
            str(reference.get("query") or ""),
            str(reference.get("class") or ""),
            str(reference.get("method") or ""),
        )

    ordered = sorted(references, key=score)
    return ordered[: max(1, int(limit))]


def evidence_summary(payload: dict[str, Any]) -> str:
    """Short evidence summary line for the evidence index."""

    stats = payload.get("stats") or {}
    return (
        f"ASC inbound xrefs: {payload.get('reference_count', 0)} refs "
        f"for {len(payload.get('queries') or [])} queries "
        f"({stats.get('dex_entry_count', 0)} dex, transport={payload.get('transport')})"
    )


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
