from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from pathlib import Path

from apkscanner.analysis.asc_xrefs import (
    AscQuery,
    AscXrefExtractor,
    build_asc_queries,
    evidence_summary,
    parse_reference_lines,
    relevance_filter,
)
from apkscanner.core.db import Database
from apkscanner.core.models import EntryPoint, Evidence, Scan
from apkscanner.platform.artifacts import ArtifactStore
from apkscanner.runtime.orchestrator import ScanOrchestrator


class _FakeAscHandler:
    """Minimal stand-in for ``droidasc.asc_client.asc_handler.AscHandler``."""

    def __init__(self, lines_by_query: dict[str, list[str]] | None = None, error: Exception | None = None):
        self.lines_by_query = lines_by_query or {}
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    def findrefs(self, dex_name: str, dex_buf, find_type: str, find: dict, aggregate: bool = True):  # noqa: ANN001, ANN202
        self.calls.append((dex_name, find_type, json.dumps(find, sort_keys=True)))
        if self.error is not None:
            raise self.error
        key = find[find_type]
        if isinstance(key, dict):
            key = key.get(find_type)
        # Only report the lines that belong to this DEX, like the real tool.
        return [
            line
            for line in self.lines_by_query.get(str(key), [])
            if line.startswith(f"{dex_name} |")
        ]


def _apk_with_dex(tmp_path: Path, count: int = 2) -> Path:
    path = tmp_path / "asc.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        for index in range(2, count + 1):
            archive.writestr(f"classes{index}.dex", b"dex\n035\x00" + b"\x00" * 32)
    return path


def _extractor(settings, handler: _FakeAscHandler) -> AscXrefExtractor:  # noqa: ANN001
    extractor = AscXrefExtractor(settings)
    extractor._library_handler = handler  # noqa: SLF001 - test seam
    extractor._library_error = None  # noqa: SLF001
    return extractor


# ── query building ──────────────────────────────────────────────────────────


def test_build_asc_queries_covers_entries_and_scan_wide_anchors(settings) -> None:  # noqa: ANN001
    entries = [
        EntryPoint(
            id="e1",
            scan_id="s",
            kind="deep_link",
            name="demo://example.test/open",
            owner_component="com.example.DeepLinkActivity",
            exported=True,
        ),
        EntryPoint(
            id="e2",
            scan_id="s",
            kind="provider",
            name="com.example.DataProvider",
            owner_component="com.example.DataProvider",
            exported=True,
            metadata_json={"authorities": "com.example.data; com.example.other"},
        ),
    ]
    queries = build_asc_queries(entries, max_queries=64)
    keys = {query.key for query in queries}

    assert "type:Lcom/example/DeepLinkActivity;" in keys
    assert "string:demo://example.test/open" in keys
    assert "string:content://com.example.data" in keys
    assert "string:content://com.example.other" in keys
    assert any(query.key == "method:addJavascriptInterface" for query in queries)


def test_build_asc_queries_dedupes_and_caps(settings) -> None:  # noqa: ANN001
    entries = [
        EntryPoint(
            id="e1",
            scan_id="s",
            kind="provider",
            name="com.example.P",
            owner_component="com.example.P",
            metadata_json={"authorities": "a; a"},
            exported=True,
        )
    ]
    queries = build_asc_queries(entries, max_queries=5)
    assert len(queries) == 5
    assert len({query.key for query in queries}) == 5


def test_asc_query_payload_mirrors_cli_shapes() -> None:
    assert AscQuery("string", "token").find_payload() == {"string": "token"}
    assert AscQuery("type", "Lcom/x/Y;").find_payload() == {"type": "Lcom/x/Y;"}
    assert AscQuery("method", "onCreate").find_payload() == {
        "method": {"class": None, "method": "onCreate"}
    }
    assert AscQuery("method", "onCreate", class_name="com.x.Main").find_payload() == {
        "method": {"class": ["Lcom/x/Main;", True], "method": "onCreate"}
    }
    assert AscQuery(
        "field", "apiKey", class_name="com.x.Main", fuzzy_class=True
    ).find_payload() == {"field": {"class": ["com/x/Main", False], "field": "apiKey"}}


# ── parsing ─────────────────────────────────────────────────────────────────


def test_parse_reference_lines_handles_multiple_and_unknown_lines() -> None:
    query = AscQuery("string", "content://", reason="content_uri")
    lines = [
        "classes.dex | Lcom/x/A;->a | matched=(content://a; content://b)",
        "not a reference line",
        "classes2.dex | Lcom/x/B;-><init> | matched=(Landroid/content/Intent;)",
    ]
    references, dropped = parse_reference_lines(lines, query=query, limit=10)

    assert dropped == 0
    assert [item["class"] for item in references] == ["Lcom/x/A;", "Lcom/x/B;"]
    assert references[0]["matched"] == ["content://a", "content://b"]
    assert references[0]["query"] == "string:content://"


def test_parse_reference_lines_caps_results() -> None:
    query = AscQuery("type", "Lcom/x/Y;")
    lines = [f"classes.dex | Lcom/x/C{i};->a | matched=(Lcom/x/Y;)" for i in range(5)]
    references, dropped = parse_reference_lines(lines, query=query, limit=2)
    assert len(references) == 2
    assert dropped == 3


# ── extraction ──────────────────────────────────────────────────────────────


def test_extract_uses_library_transport_and_records_stats(settings, tmp_path) -> None:  # noqa: ANN001
    apk = _apk_with_dex(tmp_path, count=2)
    handler = _FakeAscHandler(
        {"content://": ["classes.dex | Lcom/x/A;->a | matched=(content://hit)"]}
    )
    extractor = _extractor(settings, handler)

    result = extractor.extract(apk, [AscQuery("string", "content://")])

    assert result.transport == "library"
    assert result.usable is True
    assert len(result.references) == 1
    assert result.stats["dex_entry_count"] == 2
    assert result.stats["per_query"] == {"string:content://": 1}
    # One call per (dex, query) pair.
    assert len(handler.calls) == 2
    assert result.apk_sha256


def test_extract_isolates_tool_errors(settings, tmp_path) -> None:  # noqa: ANN001
    apk = _apk_with_dex(tmp_path, count=1)
    handler = _FakeAscHandler(error=RuntimeError("multiprocessing denied"))
    extractor = _extractor(settings, handler)

    result = extractor.extract(apk, [AscQuery("string", "content://")])

    assert result.usable is False
    assert result.references == []
    assert any("multiprocessing denied" in error for error in result.errors)


def test_available_reports_missing_tool(settings) -> None:  # noqa: ANN001
    configured = replace(settings, asc_transport="cli", asc_path="definitely-not-a-real-tool")
    extractor = AscXrefExtractor(configured)
    # No library and no CLI: the integration must report a reason, not raise.
    extractor._library_error = "not installed"  # noqa: SLF001
    available, detail = extractor.available()
    assert available is False
    assert detail


# ── projection ──────────────────────────────────────────────────────────────


def test_relevance_filter_puts_entry_specific_hits_first() -> None:
    entries = [
        EntryPoint(
            id="e1",
            scan_id="s",
            kind="provider",
            name="com.example.DataProvider",
            owner_component="com.example.DataProvider",
            metadata_json={"authorities": "com.example.data"},
            exported=True,
        )
    ]
    references = [
        {"query": "method:addJavascriptInterface", "class": "Lcom/x/Other;", "method": "a", "matched": []},
        {
            "query": "string:content://com.example.data",
            "class": "Lcom/example/Client;",
            "method": "b",
            "matched": ["content://com.example.data"],
        },
    ]
    selected = relevance_filter(references, entries, limit=1)
    assert selected[0]["class"] == "Lcom/example/Client;"


def test_evidence_summary_is_stable() -> None:
    payload = {
        "reference_count": 7,
        "queries": [{"kind": "string", "value": "x"}],
        "stats": {"dex_entry_count": 3},
        "transport": "library",
    }
    assert "7 refs" in evidence_summary(payload)


# ── orchestrator integration ────────────────────────────────────────────────


def test_run_asc_xrefs_records_evidence_when_enabled(settings) -> None:  # noqa: ANN001
    configured = replace(settings, asc_enabled=True)
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)
    orchestrator = ScanOrchestrator(configured, database, store)
    handler = _FakeAscHandler(
        {"content://": ["classes.dex | Lcom/x/A;->a | matched=(content://hit)"]}
    )
    orchestrator.asc = _extractor(configured, handler)

    with database.session_factory() as session:
        scan = Scan(
            status="static_running",
            filename="asc.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(_apk_with_dex(Path(configured.data_dir), count=1)),
        )
        session.add(scan)
        session.commit()
        orchestrator._run_asc_xrefs(  # noqa: SLF001
            session,
            scan,
            [
                EntryPoint(
                    id="e1",
                    scan_id=scan.id,
                    kind="provider",
                    name="com.example.DataProvider",
                    owner_component="com.example.DataProvider",
                    metadata_json={"authorities": "com.example.data"},
                    exported=True,
                )
            ],
            None,
        )
        session.commit()
        record = session.query(Evidence).filter_by(kind="static.droidasc").one()
        assert record.metadata_json["static_output_usable"] is True
        assert record.metadata_json["asc_transport"] == "library"
        assert record.metadata_json["static_tool_status"] == "succeeded"


def test_run_asc_xrefs_is_a_noop_when_disabled(settings) -> None:  # noqa: ANN001
    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))

    with database.session_factory() as session:
        scan = Scan(
            status="static_running",
            filename="asc.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(_apk_with_dex(Path(settings.data_dir), count=1)),
        )
        session.add(scan)
        session.commit()
        orchestrator._run_asc_xrefs(session, scan, [], None)  # noqa: SLF001
        session.commit()
        assert session.query(Evidence).filter_by(kind="static.droidasc").count() == 0


def test_target_xrefs_context_projects_recorded_evidence(settings) -> None:  # noqa: ANN001
    configured = replace(settings, asc_enabled=True)
    configured.ensure_directories()
    database = Database(configured)
    database.create_all()
    store = ArtifactStore(configured)
    orchestrator = ScanOrchestrator(configured, database, store)
    handler = _FakeAscHandler(
        {"content://": ["classes.dex | Lcom/x/A;->a | matched=(content://hit)"]}
    )
    orchestrator.asc = _extractor(configured, handler)
    entry = EntryPoint(
        id="e1",
        scan_id="s",
        kind="provider",
        name="com.example.DataProvider",
        owner_component="com.example.DataProvider",
        metadata_json={"authorities": "com.example.data"},
        exported=True,
    )
    with database.session_factory() as session:
        scan = Scan(
            status="static_running",
            filename="asc.apk",
            artifact_sha256="b" * 64,
            artifact_path=str(_apk_with_dex(Path(configured.data_dir), count=1)),
        )
        session.add(scan)
        session.commit()
        entry.scan_id = scan.id
        orchestrator._run_asc_xrefs(session, scan, [entry], None)  # noqa: SLF001
        session.commit()
        scan_id = scan.id

    # The projection only keeps entry-relevant hits; a scan-wide-only hit is dropped.
    projection = orchestrator._target_xrefs_context(scan_id, [entry])  # noqa: SLF001
    assert projection is not None
    assert projection["source_evidence_id"]
    assert projection["references"][0]["class"] == "Lcom/x/A;"


def test_materialize_agent_evidence_writes_xrefs_document(settings) -> None:  # noqa: ANN001
    """② The bounded context must expose xrefs.json and index it in the manifest."""

    settings.ensure_directories()
    database = Database(settings)
    database.create_all()
    orchestrator = ScanOrchestrator(settings, database, ArtifactStore(settings))
    platform_context = {
        "phase": "test_planning",
        "target_xrefs": {
            "schema_version": "1.0",
            "source_evidence_id": "ev-1",
            "reference_count": 1,
            "references": [
                {
                    "query": "type:Lcom/example/DataProvider;",
                    "class": "Lcom/example/Client;",
                    "method": "call",
                }
            ],
        },
    }

    task_root = orchestrator._materialize_agent_evidence(  # noqa: SLF001
        "00000000-0000-0000-0000-0000000000aa",
        "00000000-0000-0000-0000-0000000000bb",
        1,
        [],
        platform_context=platform_context,
    )

    xrefs = task_root / "xrefs.json"
    assert xrefs.is_file()
    manifest = json.loads((task_root / "context-manifest.json").read_text(encoding="utf-8"))
    assert "xrefs" in manifest["read_order"]
    assert manifest["documents"]["xrefs"]["path"] == "xrefs.json"
    # It is a dedicated document, not duplicated into the stable/round context.
    stable = json.loads((task_root / "stable-context.json").read_text(encoding="utf-8"))
    assert "target_xrefs" not in (stable.get("platform_context") or {})
