#!/usr/bin/env python3
"""Benchmark ASC (droidasc) bytecode xrefs against our regex-over-text adjacency.

What this measures
------------------
``AndroidAttackChainAnalyzer._build_adjacency`` infers *app-class* to *app-class*
references by regexing decompiled Java/Smali inside a bounded node/byte budget.
ASC answers exactly that question from the DEX.  Using ASC as the fact baseline,
per APK we report:

* app-class recall/precision - for app targets the regex graph already models,
  how many ASC-confirmed referencing classes it finds, and how many of its edges
  ASC does not confirm (fabrication / over-approximation)
* coverage - classes the bounded regex index considers vs classes ASC answers for
* capture  - framework/string anchors ASC resolves that the regex graph cannot
  model at all (it only indexes app-owned classes)
* cost     - wall time and peak RSS for ASC xrefs vs decompile + regex indexing

Usage
-----
    python benchmarks/asc_xref_bench.py --apk a.apk --apk b.apk \
        --decompile apktool --out benchmarks/results

``--decompile`` is optional; ASC-only runs (the fast path) skip decompilation.
"""

from __future__ import annotations

import argparse
import json
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from apkscanner.analysis.android_chains import AndroidAttackChainAnalyzer  # noqa: E402
from apkscanner.analysis.asc_xrefs import AscQuery, AscXrefExtractor  # noqa: E402
from apkscanner.analysis.manifest import aapt2_xmltree_to_xml, parse_manifest  # noqa: E402
from apkscanner.core.config import Settings  # noqa: E402

# Framework/string anchors that ASC resolves but our app-only regex adjacency
# structurally cannot model; tracked as capture, not as recall.
BENCH_FRAMEWORK_TYPES: tuple[str, ...] = (
    "Landroid/content/Intent;",
    "Landroid/content/ComponentName;",
    "Landroid/webkit/WebView;",
    "Landroid/content/ContentProvider;",
    "Landroid/database/sqlite/SQLiteDatabase;",
    "Ldalvik/system/DexClassLoader;",
    "Ljava/lang/Runtime;",
    "Ljavax/crypto/Cipher;",
)
BENCH_STRING_QUERIES: tuple[str, ...] = (
    "content://",
    "javascript:",
    "file://",
    "BEGIN RSA PRIVATE KEY",
)
APP_TARGET_SAMPLE = 40


def _current_rss_kb() -> int:
    try:
        with open("/proc/self/status", encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return 0
    return 0


class RssSampler:
    """Sample this process's RSS while a block runs (ru_maxrss never decreases)."""

    def __init__(self) -> None:
        self.peak_kb = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> RssSampler:
        self.peak_kb = _current_rss_kb()

        def sample() -> None:
            while not self._stop.is_set():
                self.peak_kb = max(self.peak_kb, _current_rss_kb())
                self._stop.wait(0.05)

        self._thread = threading.Thread(target=sample, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)


def _to_descriptor(class_name: str) -> str:
    if class_name.startswith("L") and class_name.endswith(";"):
        return class_name
    return f"L{class_name.replace('.', '/')};"


def _bench_settings(transport: str, query_count: int) -> Settings:
    tmp = Path(tempfile.mkdtemp(prefix="asc-bench-"))
    settings = Settings(
        data_dir=tmp,
        database_url=f"sqlite:///{tmp / 'bench.db'}",
        sqlite_synchronous="OFF",
        asc_enabled=True,
        asc_transport=transport,
        asc_workers=8,
        asc_max_queries=max(1, query_count),
        asc_max_results_per_query=20000,
        asc_context_max_references=20000,
    )
    settings.ensure_directories()
    return settings


def run_asc(apk: Path, queries: list[AscQuery], *, transport: str) -> dict[str, Any]:
    extractor = AscXrefExtractor(_bench_settings(transport, len(queries)))
    with RssSampler() as sampler:
        started = time.perf_counter()
        extraction = extractor.extract(apk, queries, max_references=20000)
        elapsed = time.perf_counter() - started
    return {
        "transport": extraction.transport,
        "seconds": round(elapsed, 3),
        "peak_rss_mb": round(sampler.peak_kb / 1024, 1),
        "references": extraction.references,
        "reference_count": len(extraction.references),
        "dex_entry_count": int(extraction.stats.get("dex_entry_count") or 0),
        "usable": extraction.usable,
        "errors": extraction.errors[:5],
        "tool_version": extraction.tool_version,
    }


def decompile(apk: Path, out_dir: Path, tool: str, timeout: int) -> dict[str, Any]:
    if shutil.which(tool) is None:
        return {"tool": tool, "available": False}
    out_dir.mkdir(parents=True, exist_ok=True)
    if tool == "apktool":
        command = [tool, "d", "-f", "--no-res", "-o", str(out_dir), str(apk)]
    elif tool == "jadx":
        command = [tool, "--no-res", "-d", str(out_dir), str(apk)]
    else:
        raise ValueError(f"unsupported decompiler {tool}")
    before_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    started = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = completed.returncode
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-3:]
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = 124
        tail = [f"timeout after {timeout}s"]
    elapsed = time.perf_counter() - started
    after_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return {
        "tool": tool,
        "available": True,
        "seconds": round(elapsed, 3),
        # ru_maxrss for children is a running maximum; report the growth.
        "peak_rss_mb": round(max(after_kb - before_kb, 0) / 1024, 1),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "output_tail": tail,
    }


def _decoded_manifest_text(apk: Path, root: Path, work_dir: Path) -> str | None:
    """Text AXML for the app manifest (apktool --no-res copies the binary one)."""

    for candidate in (root / "AndroidManifest.xml", work_dir / "AndroidManifest.xml"):
        if not candidate.is_file():
            continue
        raw = candidate.read_bytes()
        if raw.lstrip().startswith(b"<"):
            return raw.decode("utf-8", errors="replace")
    if shutil.which("aapt2") is None:
        return None
    completed = subprocess.run(
        ["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        return None
    try:
        return aapt2_xmltree_to_xml(completed.stdout)
    except (ValueError, TypeError):
        return None


def regex_graph(apk: Path, root: Path, work_dir: Path) -> dict[str, Any]:
    """Reproduce our own bounded index + regex adjacency over decompiled output."""

    manifest_text = _decoded_manifest_text(apk, root, work_dir)
    if manifest_text is None:
        return {"error": "no decoded AndroidManifest.xml"}
    try:
        manifest = parse_manifest(manifest_text)
    except (ValueError, SyntaxError) as exc:
        return {"error": f"manifest parse failed: {type(exc).__name__}: {exc}"}

    analyzer = AndroidAttackChainAnalyzer()
    with RssSampler() as sampler:
        started = time.perf_counter()
        nodes = analyzer._index_nodes(manifest, [root])  # noqa: SLF001
        adjacency = analyzer._build_adjacency(nodes)  # noqa: SLF001
        elapsed = time.perf_counter() - started
    return {
        "node_names": sorted(nodes),
        "node_count": len(nodes),
        "edge_count": sum(len(targets) for targets in adjacency.values()),
        "seconds": round(elapsed, 3),
        "peak_rss_mb": round(sampler.peak_kb / 1024, 1),
        "adjacency": adjacency,
    }


def compare_app_types(
    adjacency: dict[str, set[str]],
    asc_references: list[dict[str, Any]],
    targets: dict[str, str],
    universe: set[str],
) -> list[dict[str, Any]]:
    """Compare app-class targets only: the regex graph models app classes exclusively."""

    regex_by_target: dict[str, set[str]] = {descriptor: set() for descriptor in targets.values()}
    for class_name, references in adjacency.items():
        source = _to_descriptor(class_name)
        for target in references:
            descriptor = _to_descriptor(target)
            if descriptor in regex_by_target:
                regex_by_target[descriptor].add(source)

    asc_by_target: dict[str, set[str]] = {descriptor: set() for descriptor in targets.values()}
    for reference in asc_references:
        if reference.get("query_kind") != "type":
            continue
        descriptor = str(reference.get("query_value") or "")
        if descriptor in asc_by_target:
            asc_by_target[descriptor].add(_to_descriptor(str(reference.get("class") or "")))

    rows: list[dict[str, Any]] = []
    for dotted, descriptor in targets.items():
        asc_classes = asc_by_target[descriptor] & universe
        regex_classes = regex_by_target[descriptor] & universe
        confirmed = asc_classes & regex_classes
        rows.append(
            {
                "target": dotted,
                "asc_classes": len(asc_classes),
                "regex_classes": len(regex_classes),
                "confirmed": len(confirmed),
                "missed": len(asc_classes - regex_classes),
                "fabricated": len(regex_classes - asc_classes),
                "recall": round(len(confirmed) / len(asc_classes), 4) if asc_classes else None,
                "precision": (
                    round(len(confirmed) / len(regex_classes), 4) if regex_classes else None
                ),
            }
        )
    return rows


def _totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        key: sum(row[key] for row in rows)
        for key in ("asc_classes", "regex_classes", "confirmed", "missed", "fabricated")
    }
    totals["recall"] = (
        round(totals["confirmed"] / totals["asc_classes"], 4) if totals["asc_classes"] else None
    )
    totals["precision"] = (
        round(totals["confirmed"] / totals["regex_classes"], 4)
        if totals["regex_classes"]
        else None
    )
    return totals


def benchmark_apk(
    apk: Path,
    *,
    transport: str,
    decompile_tool: str | None,
    decompile_timeout: int,
    work_root: Path,
    seed: int,
) -> dict[str, Any]:
    fixed_queries = [
        AscQuery("type", value, reason="bench_framework_type") for value in BENCH_FRAMEWORK_TYPES
    ] + [AscQuery("string", value, reason="bench_string") for value in BENCH_STRING_QUERIES]
    result: dict[str, Any] = {
        "apk": str(apk),
        "size_mb": round(apk.stat().st_size / (1024 * 1024), 1),
    }
    asc = run_asc(apk, fixed_queries, transport=transport)
    result["asc"] = {key: value for key, value in asc.items() if key != "references"}
    result["asc_capture"] = {
        "referencing_classes": len({item["class"] for item in asc["references"]}),
        "framework_type_hits": sum(
            1 for item in asc["references"] if item["query_kind"] == "type"
        ),
        "string_hits": sum(
            1 for item in asc["references"] if item["query_kind"] == "string"
        ),
    }
    if decompile_tool is None:
        return result

    work_dir = work_root / apk.stem
    work_dir.mkdir(parents=True, exist_ok=True)
    decompiled_dir = work_dir / decompile_tool
    result["decompile"] = decompile(apk, decompiled_dir, decompile_tool, decompile_timeout)
    if not result["decompile"].get("available") or result["decompile"].get("exit_code") != 0:
        return result

    graph = regex_graph(apk, decompiled_dir, work_dir)
    result["regex_graph"] = {
        key: value for key, value in graph.items() if key not in {"adjacency", "node_names"}
    }
    if "adjacency" not in graph:
        return result

    node_names = graph["node_names"]
    universe = {_to_descriptor(name) for name in node_names}
    sample = random.Random(seed).sample(node_names, min(APP_TARGET_SAMPLE, len(node_names)))
    targets = {name: _to_descriptor(name) for name in sample}
    asc_app = run_asc(
        apk,
        [AscQuery("type", descriptor, reason="bench_app_type") for descriptor in targets.values()],
        transport=transport,
    )
    result["asc_app_types"] = {
        "seconds": asc_app["seconds"],
        "peak_rss_mb": asc_app["peak_rss_mb"],
        "reference_count": asc_app["reference_count"],
    }
    rows = compare_app_types(graph["adjacency"], asc_app["references"], targets, universe)
    result["app_type_comparison"] = rows
    result["app_type_totals"] = _totals(rows)
    result["app_targets_with_hits"] = sum(1 for row in rows if row["asc_classes"])
    return result


def render_markdown(results: list[dict[str, Any]]) -> str:
    lines = ["# ASC xref benchmark", ""]
    lines.append(
        "| APK | MB | dex | ASC refs | ASC s | ASC MB | decompile | dec s | "
        "nodes | app targets | recall | precision | fabricated |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for item in results:
        asc = item.get("asc") or {}
        node = item.get("regex_graph") or {}
        totals = item.get("app_type_totals") or {}
        decomp = item.get("decompile") or {}
        lines.append(
            "| {apk} | {mb} | {dex} | {refs} | {secs} | {rss} | {tool} | {dsecs} | "
            "{nodes} | {targets} | {recall} | {precision} | {fab} |".format(
                apk=Path(item["apk"]).name,
                mb=item.get("size_mb"),
                dex=asc.get("dex_entry_count"),
                refs=asc.get("reference_count"),
                secs=asc.get("seconds"),
                rss=asc.get("peak_rss_mb"),
                tool=decomp.get("tool", "-") if decomp.get("available") else "-",
                dsecs=decomp.get("seconds", "-") if decomp.get("available") else "-",
                nodes=node.get("node_count", "-"),
                targets=item.get("app_targets_with_hits", "-"),
                recall=totals.get("recall", "-"),
                precision=totals.get("precision", "-"),
                fab=totals.get("fabricated", "-"),
            )
        )
    lines.append("")
    lines.append(
        "recall/precision are restricted to app-owned classes and app-class targets "
        "(the only edges our regex adjacency models). The ASC refs column is the fixed "
        "framework/string query set, which the regex graph cannot model at all."
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", action="append", required=True, help="APK path (repeatable)")
    parser.add_argument("--out", default=str(REPO_ROOT / "benchmarks" / "results"))
    parser.add_argument("--transport", default="library", choices=("library", "cli", "auto"))
    parser.add_argument("--decompile", default=None, choices=("apktool", "jadx"))
    parser.add_argument("--decompile-timeout", type=int, default=1800)
    parser.add_argument("--seed", type=int, default=20260916)
    args = parser.parse_args()

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    work_root = out_root / "work"
    results = [
        benchmark_apk(
            Path(apk).resolve(),
            transport=args.transport,
            decompile_tool=args.decompile,
            decompile_timeout=args.decompile_timeout,
            work_root=work_root,
            seed=args.seed,
        )
        for apk in args.apk
    ]
    report = {"schema_version": "1.0", "results": results}
    (out_root / "asc_xref_bench.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_root / "asc_xref_bench.md").write_text(render_markdown(results), encoding="utf-8")
    print(render_markdown(results))
    print(f"\nwrote {out_root / 'asc_xref_bench.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
