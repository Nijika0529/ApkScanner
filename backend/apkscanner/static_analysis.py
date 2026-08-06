from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .android_chains import AndroidAttackChainAnalyzer
from .config import Settings
from .manifest import ManifestDocument, aapt2_xmltree_to_xml, parse_manifest
from .native_analysis import NativeArtifactAnalyzer
from .permissions import ensure_private_directory
from .tools import CommandResult, TimeBudget, ToolRunner, discover_tools

CODE_INDEX_CONTEXT_VERSION = "component-one-hop-android-chains-v7-cross-artifact-loaders"

_LOADER_REFERENCE_SUFFIXES = {
    ".java",
    ".kt",
    ".smali",
    ".xml",
    ".json",
    ".js",
    ".properties",
    ".txt",
}


class InvalidApkError(ValueError):
    pass


@dataclass(slots=True)
class StaticAnalysisResult:
    manifest: ManifestDocument
    workspace: Path
    tool_versions: dict[str, str | None]
    tool_results: dict[str, dict[str, Any]]
    signing: dict[str, Any]
    file_inventory: dict[str, Any]
    searchable_roots: list[Path] = field(default_factory=list)
    decompilation: dict[str, Any] = field(default_factory=dict)
    code_index: dict[str, dict[str, Any]] = field(default_factory=dict)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    artifact_graph: dict[str, Any] = field(default_factory=dict)


class ApkInspector:
    def __init__(self, settings: Settings, runner: ToolRunner | None = None):
        self.settings = settings
        self.runner = runner or ToolRunner(settings.tool_timeout_seconds)

    def inspect(
        self,
        apk_path: Path,
        scan_id: str,
        budget: TimeBudget | None = None,
        *,
        _workspace: Path | None = None,
        _artifact_origin: str = "target.apk",
        _ancestry: tuple[str, ...] = (),
    ) -> StaticAnalysisResult:
        file_inventory = self._validate_zip(apk_path)
        workspace = _workspace or self.settings.data_dir / "workspaces" / scan_id
        ensure_private_directory(workspace)
        tool_versions = discover_tools(self.runner)
        artifact_sha256 = self._file_sha256(apk_path)
        analysis_profile = self._analysis_profile(tool_versions)
        file_inventory = {
            **file_inventory,
            "static_cache_hit": False,
            "analysis_profile": analysis_profile,
        }
        cache_dir = (
            self.settings.data_dir
            / "static-cache"
            / artifact_sha256[:2]
            / artifact_sha256
            / analysis_profile
        )
        cached = self._restore_static_cache(
            cache_dir=cache_dir,
            workspace=workspace,
            artifact_sha256=artifact_sha256,
            analysis_profile=analysis_profile,
            file_inventory=file_inventory,
        )
        if cached is not None:
            return cached
        tool_results: dict[str, dict[str, Any]] = {}
        decoded_dir = workspace / "apktool"
        jadx_dir = workspace / "jadx"
        manifest_path: Path | None = None
        searchable_roots: list[Path] = []
        decompilation: dict[str, Any] = {
            "status": "not_available",
            "exit_code": None,
            "generated_java_files": 0,
            "reported_error_count": 0,
            "failed_classes": [],
        }

        if self.runner.available("apktool"):
            result = self._run(
                ["apktool", "d", "--force", "--output", str(decoded_dir), str(apk_path)],
                budget,
                self.settings.tool_timeout_seconds,
            )
            tool_results["apktool"] = self._serialize_result(result)
            candidate = decoded_dir / "AndroidManifest.xml"
            if (
                result.exit_code == 0
                and candidate.is_file()
                and candidate.stat().st_size > 0
                and candidate.read_bytes().lstrip().startswith(b"<")
            ):
                manifest_path = candidate
                searchable_roots.append(decoded_dir)
            elif self.runner.available("apktool"):
                fallback = self._run(
                    [
                        "apktool",
                        "d",
                        "--force",
                        "--no-res",
                        "--output",
                        str(decoded_dir),
                        str(apk_path),
                    ],
                    budget,
                    self.settings.tool_timeout_seconds,
                )
                tool_results["apktool_no_resources"] = self._serialize_result(fallback)
                if fallback.exit_code == 0 and decoded_dir.is_dir():
                    searchable_roots.append(decoded_dir)

        if manifest_path is None and self.runner.available("aapt2"):
            result = self._run(
                [
                    "aapt2",
                    "dump",
                    "xmltree",
                    "--file",
                    "AndroidManifest.xml",
                    str(apk_path),
                ],
                budget,
                120,
            )
            tool_results["aapt2_manifest"] = self._serialize_result(result)
            if result.exit_code == 0:
                try:
                    decoded_manifest = aapt2_xmltree_to_xml(result.stdout)
                    parse_manifest(decoded_manifest)
                except (ValueError, TypeError):
                    pass
                else:
                    manifest_path = workspace / "AndroidManifest.xml"
                    manifest_path.write_text(decoded_manifest, encoding="utf-8")

        if manifest_path is None:
            plaintext = self._plaintext_manifest(apk_path)
            if plaintext is not None:
                manifest_path = workspace / "AndroidManifest.xml"
                manifest_path.write_text(plaintext, encoding="utf-8")

        if manifest_path is None:
            raise InvalidApkError(
                "AndroidManifest.xml could not be decoded; install apktool or provide a valid APK"
            )
        manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
        manifest = parse_manifest(manifest_text)
        archive_dir = workspace / "archive"
        self._extract_searchable_files(apk_path, archive_dir)
        searchable_roots.append(archive_dir)

        if self.runner.available("jadx"):
            result = self._run(
                [
                    "jadx",
                    "--no-res",
                    "--deobf",
                    "--show-bad-code",
                    "--rename-flags",
                    "valid",
                    "--output-dir",
                    str(jadx_dir),
                    str(apk_path),
                ],
                budget,
                self.settings.tool_timeout_seconds,
            )
            decompilation = self._jadx_decompilation_summary(result, jadx_dir)
            tool_results["jadx"] = {
                **self._serialize_result(result),
                "decompilation": decompilation,
            }
            if jadx_dir.exists():
                searchable_roots.insert(0, jadx_dir)

        if self.runner.available("aapt2"):
            result = self._run(["aapt2", "dump", "badging", str(apk_path)], budget, 120)
            tool_results["aapt2"] = self._serialize_result(result)
            self._merge_badging(manifest, result.stdout)

        signing: dict[str, Any] = {}
        if self.runner.available("apksigner"):
            result = self._run(
                ["apksigner", "verify", "--verbose", "--print-certs", str(apk_path)],
                budget,
                120,
            )
            tool_results["apksigner"] = self._serialize_result(result)
            signing = self._parse_signing(result)

        code_index = self._build_code_index(
            result_entries=manifest.entries,
            package_name=manifest.package_name,
            workspace=workspace,
            jadx_dir=jadx_dir,
            decoded_dir=decoded_dir,
            archive_dir=archive_dir,
            decompilation=decompilation,
        )
        attack_chains = AndroidAttackChainAnalyzer().analyze(
            manifest,
            searchable_roots,
        )
        (workspace / "code_index.json").write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "context_version": CODE_INDEX_CONTEXT_VERSION,
                    "decompilation": decompilation,
                    "components": code_index,
                    "attack_chains": attack_chains,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        decompilation = {
            **decompilation,
            "cache_hit": False,
            "analysis_profile": analysis_profile,
        }
        artifact_root_id = "target.apk" if _artifact_origin == "target.apk" else "artifact.apk"
        native_index = NativeArtifactAnalyzer(self.runner).analyze(
            apk_path=apk_path,
            workspace=workspace,
            artifact_id=artifact_root_id,
            artifact_sha256=artifact_sha256,
            package_name=manifest.package_name,
            native_libraries=list(file_inventory.get("native_libraries") or []),
            failed_java_classes={
                str(value) for value in decompilation.get("failed_classes", [])
            },
            budget=budget,
        )
        tool_results["native_analysis"] = {
            "argv": [],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "summary": native_index["summary"],
        }
        artifact_graph = self._analyze_embedded_apks(
            apk_path=apk_path,
            scan_id=scan_id,
            workspace=workspace,
            artifact_sha256=artifact_sha256,
            artifact_origin=_artifact_origin,
            manifest=manifest,
            file_inventory=file_inventory,
            decompilation=decompilation,
            native_index=native_index,
            budget=budget,
            ancestry=(*_ancestry, artifact_sha256),
        )
        (workspace / "artifact_graph.json").write_text(
            json.dumps(artifact_graph, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        searchable_roots = self._workspace_searchable_roots(workspace)
        artifact_nodes = list(artifact_graph.get("nodes") or [])
        artifact_summary = dict(artifact_graph.get("summary") or {})
        file_inventory = {
            **file_inventory,
            "product_bundle": {
                "schema_version": artifact_graph.get("schema_version", "1.0"),
                "artifact_count": int(artifact_summary.get("apk_count") or 0),
                "embedded_apk_count": max(
                    0,
                    int(artifact_summary.get("apk_count") or 0) - 1,
                ),
                "javascript_file_count": sum(
                    len((node.get("inventory") or {}).get("javascript_files") or [])
                    for node in artifact_nodes
                ),
                "html_file_count": sum(
                    len((node.get("inventory") or {}).get("html_files") or [])
                    for node in artifact_nodes
                ),
                "native_library_count": int(
                    artifact_summary.get("native_library_count") or 0
                ),
                "java_native_method_count": int(
                    artifact_summary.get("java_native_method_count") or 0
                ),
                "linked_java_native_method_count": int(
                    artifact_summary.get("linked_java_native_method_count")
                    or 0
                ),
                "artifact_graph_path": "artifact_graph.json",
            },
        }
        if self._static_result_cacheable(tool_results, decompilation):
            self._publish_static_cache(
                cache_dir=cache_dir,
                workspace=workspace,
                artifact_sha256=artifact_sha256,
                analysis_profile=analysis_profile,
                manifest_path=manifest_path,
                tool_versions=tool_versions,
                signing=signing,
                decompilation=decompilation,
            )

        return StaticAnalysisResult(
            manifest=manifest,
            workspace=workspace,
            tool_versions=tool_versions,
            tool_results=tool_results,
            signing=signing,
            file_inventory=file_inventory,
            searchable_roots=searchable_roots,
            decompilation=decompilation,
            code_index=code_index,
            attack_chains=attack_chains,
            artifact_graph=artifact_graph,
        )

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _analysis_profile(tool_versions: dict[str, str | None]) -> str:
        payload = {
            "schema_version": "1.0",
            "code_index_context_version": CODE_INDEX_CONTEXT_VERSION,
            "tool_versions": {
                key: value for key, value in tool_versions.items() if key != "adb"
            },
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _restore_static_cache(
        self,
        *,
        cache_dir: Path,
        workspace: Path,
        artifact_sha256: str,
        analysis_profile: str,
        file_inventory: dict[str, Any],
    ) -> StaticAnalysisResult | None:
        metadata_path = cache_dir / "metadata.json"
        index_path = cache_dir / "code_index.json"
        graph_path = cache_dir / "artifact_graph.json"
        if not metadata_path.is_file() or not index_path.is_file() or not graph_path.is_file():
            return None
        if any(
            (workspace / name).exists()
            for name in ("jadx", "apktool", "archive", "native", "artifacts")
        ):
            return None
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            index_payload = json.loads(index_path.read_text(encoding="utf-8"))
            artifact_graph = json.loads(graph_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if (
            metadata.get("artifact_sha256") != artifact_sha256
            or metadata.get("analysis_profile") != analysis_profile
            or index_payload.get("context_version") != CODE_INDEX_CONTEXT_VERSION
            or not isinstance(index_payload.get("components"), dict)
            or not isinstance(index_payload.get("attack_chains"), list)
            or not isinstance(artifact_graph.get("nodes"), list)
            or not isinstance(artifact_graph.get("edges"), list)
        ):
            return None
        manifest_relative = metadata.get("manifest_relative_path")
        if not isinstance(manifest_relative, str):
            return None
        cached_manifest = (cache_dir / manifest_relative).resolve()
        if not cached_manifest.is_relative_to(cache_dir.resolve()) or not cached_manifest.is_file():
            return None
        for name in ("jadx", "apktool", "archive", "native", "artifacts"):
            source = cache_dir / name
            if source.is_dir():
                shutil.copytree(source, workspace / name)
        top_manifest = cache_dir / "AndroidManifest.xml"
        if top_manifest.is_file():
            shutil.copy2(top_manifest, workspace / "AndroidManifest.xml")
        shutil.copy2(index_path, workspace / "code_index.json")
        shutil.copy2(graph_path, workspace / "artifact_graph.json")
        workspace_manifest = workspace / manifest_relative
        if not workspace_manifest.is_file():
            return None
        manifest = parse_manifest(workspace_manifest.read_text(encoding="utf-8", errors="replace"))
        decompilation = {
            **dict(metadata.get("decompilation") or {}),
            "cache_hit": True,
            "analysis_profile": analysis_profile,
        }
        searchable_roots = self._workspace_searchable_roots(workspace)
        artifact_nodes = list(artifact_graph.get("nodes") or [])
        artifact_summary = dict(artifact_graph.get("summary") or {})
        return StaticAnalysisResult(
            manifest=manifest,
            workspace=workspace,
            tool_versions=dict(metadata.get("tool_versions") or {}),
            tool_results={
                "static_cache": {
                    "argv": [],
                    "exit_code": 0,
                    "stdout": "",
                    "stderr": "",
                    "timed_out": False,
                    "cache_key": f"{artifact_sha256}:{analysis_profile}",
                }
            },
            signing=dict(metadata.get("signing") or {}),
            file_inventory={
                **file_inventory,
                "static_cache_hit": True,
                "analysis_profile": analysis_profile,
                "product_bundle": {
                    "schema_version": artifact_graph.get("schema_version", "1.0"),
                    "artifact_count": int(artifact_summary.get("apk_count") or 0),
                    "embedded_apk_count": max(
                        0,
                        int(artifact_summary.get("apk_count") or 0) - 1,
                    ),
                    "javascript_file_count": sum(
                        len((node.get("inventory") or {}).get("javascript_files") or [])
                        for node in artifact_nodes
                    ),
                    "html_file_count": sum(
                        len((node.get("inventory") or {}).get("html_files") or [])
                        for node in artifact_nodes
                    ),
                    "native_library_count": int(
                        artifact_summary.get("native_library_count") or 0
                    ),
                    "java_native_method_count": int(
                        artifact_summary.get("java_native_method_count") or 0
                    ),
                    "linked_java_native_method_count": int(
                        artifact_summary.get("linked_java_native_method_count")
                        or 0
                    ),
                    "artifact_graph_path": "artifact_graph.json",
                },
            },
            searchable_roots=searchable_roots,
            decompilation=decompilation,
            code_index=dict(index_payload["components"]),
            attack_chains=list(index_payload["attack_chains"]),
            artifact_graph=artifact_graph,
        )

    @staticmethod
    def _static_result_cacheable(
        tool_results: dict[str, dict[str, Any]],
        decompilation: dict[str, Any],
    ) -> bool:
        if any(bool(item.get("timed_out")) for item in tool_results.values()):
            return False
        return str(decompilation.get("status")) in {
            "complete_success",
            "completed_without_java",
            "not_available",
        }

    @staticmethod
    def _publish_static_cache(
        *,
        cache_dir: Path,
        workspace: Path,
        artifact_sha256: str,
        analysis_profile: str,
        manifest_path: Path,
        tool_versions: dict[str, str | None],
        signing: dict[str, Any],
        decompilation: dict[str, Any],
    ) -> None:
        if (cache_dir / "metadata.json").is_file():
            return
        cache_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix="static-cache-", dir=cache_dir.parent))
        try:
            for name in ("jadx", "apktool", "archive", "native", "artifacts"):
                source = workspace / name
                if source.is_dir():
                    shutil.copytree(source, temporary / name)
            top_manifest = workspace / "AndroidManifest.xml"
            if top_manifest.is_file():
                shutil.copy2(top_manifest, temporary / "AndroidManifest.xml")
            shutil.copy2(workspace / "code_index.json", temporary / "code_index.json")
            shutil.copy2(
                workspace / "artifact_graph.json",
                temporary / "artifact_graph.json",
            )
            relative_manifest = str(manifest_path.relative_to(workspace))
            metadata = {
                "schema_version": "1.0",
                "artifact_sha256": artifact_sha256,
                "analysis_profile": analysis_profile,
                "manifest_relative_path": relative_manifest,
                "tool_versions": tool_versions,
                "signing": signing,
                "decompilation": decompilation,
            }
            (temporary / "metadata.json").write_text(
                json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2),
                encoding="utf-8",
            )
            try:
                os.replace(temporary, cache_dir)
            except OSError:
                if not (cache_dir / "metadata.json").is_file():
                    raise
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    @staticmethod
    def _workspace_searchable_roots(workspace: Path) -> list[Path]:
        roots: list[Path] = []
        seen: set[Path] = set()
        for name in ("jadx", "apktool", "archive"):
            direct = workspace / name
            if direct.is_dir():
                resolved = direct.resolve()
                seen.add(resolved)
                roots.append(direct)
            artifacts = workspace / "artifacts"
            if not artifacts.is_dir():
                continue
            for candidate in sorted(artifacts.rglob(name)):
                if not candidate.is_dir():
                    continue
                resolved = candidate.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                roots.append(candidate)
        return roots

    def _analyze_embedded_apks(
        self,
        *,
        apk_path: Path,
        scan_id: str,
        workspace: Path,
        artifact_sha256: str,
        artifact_origin: str,
        manifest: ManifestDocument,
        file_inventory: dict[str, Any],
        decompilation: dict[str, Any],
        native_index: dict[str, Any],
        budget: TimeBudget | None,
        ancestry: tuple[str, ...],
    ) -> dict[str, Any]:
        root_id = "target.apk" if artifact_origin == "target.apk" else "artifact.apk"
        root_node = {
            "id": root_id,
            "path": root_id,
            "kind": "apk",
            "sha256": artifact_sha256,
            "origin": {
                "kind": "scan_input" if artifact_origin == "target.apk" else "embedded_apk",
                "archive_path": None if artifact_origin == "target.apk" else artifact_origin,
            },
            "package_name": manifest.package_name,
            "application_class": manifest.application.get("name"),
            "version_name": manifest.version_name,
            "version_code": manifest.version_code,
            "analysis_root": ".",
            "native_index_path": "native/index.json",
            "decompilation": {
                "status": decompilation.get("status"),
                "generated_java_files": decompilation.get("generated_java_files", 0),
                "cache_hit": bool(decompilation.get("cache_hit")),
            },
            "inventory": {
                "dex_files": list(file_inventory.get("dex_files") or []),
                "native_libraries": list(file_inventory.get("native_libraries") or []),
                "embedded_apk_files": list(file_inventory.get("embedded_apk_files") or []),
                "javascript_files": list(file_inventory.get("javascript_files") or []),
                "html_files": list(file_inventory.get("html_files") or []),
            },
        }
        graph: dict[str, Any] = {
            "schema_version": "1.2",
            "root_id": root_id,
            "nodes": [root_node, *list((native_index.get("graph") or {}).get("nodes") or [])],
            "edges": list((native_index.get("graph") or {}).get("edges") or []),
        }
        embedded_names = list(file_inventory.get("embedded_apk_files") or [])
        if not embedded_names:
            graph["summary"] = self._artifact_graph_summary(graph)
            return graph

        artifacts_root = workspace / "artifacts"
        ensure_private_directory(artifacts_root)
        host_loader_references = self._embedded_loader_references(
            workspace,
            embedded_names,
        )
        analyzed: dict[
            str,
            tuple[dict[str, Any], str, str, list[str]],
        ] = {}
        with zipfile.ZipFile(apk_path) as archive:
            for archive_path in embedded_names:
                raw = archive.read(archive_path)
                child_sha256 = hashlib.sha256(raw).hexdigest()
                child_prefix = f"artifacts/{child_sha256}"
                if child_sha256 not in analyzed:
                    child_workspace = workspace / child_prefix
                    ensure_private_directory(child_workspace)
                    child_apk = child_workspace / "artifact.apk"
                    child_apk.write_bytes(raw)
                    child_result = self.inspect(
                        child_apk,
                        scan_id,
                        budget,
                        _workspace=child_workspace,
                        _artifact_origin=archive_path,
                        _ancestry=ancestry,
                    )
                    child_graph = self._rebase_artifact_graph(
                        child_result.artifact_graph,
                        child_prefix,
                    )
                    child_root_id = str(child_graph["root_id"])
                    child_root = next(
                        node
                        for node in child_graph["nodes"]
                        if node["id"] == child_root_id
                    )
                    plugin_entry_nodes = self._embedded_plugin_entries(
                        workspace=workspace,
                        analysis_root=workspace / child_prefix,
                        graph_analysis_root=str(child_root.get("analysis_root") or child_prefix),
                        child_root_id=child_root_id,
                        package_name=str(child_root.get("package_name") or ""),
                        application_class=(
                            str(child_root.get("application_class"))
                            if child_root.get("application_class")
                            else None
                        ),
                    )
                    for entry_node in plugin_entry_nodes:
                        child_graph["nodes"].append(entry_node)
                        child_graph["edges"].append(
                            {
                                "from": child_root_id,
                                "to": entry_node["id"],
                                "relation": "declares_plugin_entry",
                                "confidence": entry_node["confidence"],
                            }
                        )
                    analyzed[child_sha256] = (
                        child_graph,
                        child_prefix,
                        child_root_id,
                        [str(node["id"]) for node in plugin_entry_nodes],
                    )
                    graph["nodes"].extend(child_graph["nodes"])
                    graph["edges"].extend(child_graph["edges"])
                child_graph, _prefix, child_root_id, plugin_entry_ids = analyzed[
                    child_sha256
                ]
                graph["edges"].append(
                    {
                        "from": root_id,
                        "to": child_root_id,
                        "relation": "contains",
                        "archive_path": archive_path,
                        "sha256": child_sha256,
                    }
                )
                child_root = next(
                    node for node in child_graph["nodes"] if node["id"] == child_root_id
                )
                origins = child_root.setdefault("embedded_at", [])
                if archive_path not in origins:
                    origins.append(archive_path)
                references = host_loader_references.get(archive_path, [])
                if references:
                    loader_id = (
                        "plugin_loaders/"
                        + hashlib.sha256(archive_path.encode()).hexdigest()[:16]
                    )
                    mechanisms = sorted(
                        {
                            mechanism
                            for reference in references
                            for mechanism in reference.get("mechanisms", [])
                        }
                    )
                    graph["nodes"].append(
                        {
                            "id": loader_id,
                            "path": references[0]["workspace_path"],
                            "kind": "plugin_loader_reference",
                            "name": PurePosixPath(archive_path).name,
                            "embedded_apk_id": child_root_id,
                            "archive_path": archive_path,
                            "mechanisms": mechanisms,
                            "references": references,
                        }
                    )
                    graph["edges"].extend(
                        [
                            {
                                "from": root_id,
                                "to": loader_id,
                                "relation": "declares_plugin_loader",
                                "archive_path": archive_path,
                            },
                            {
                                "from": loader_id,
                                "to": child_root_id,
                                "relation": "loads_embedded_apk",
                                "archive_path": archive_path,
                                "confidence": "high",
                            },
                        ]
                    )
                    graph["edges"].extend(
                        {
                            "from": loader_id,
                            "to": entry_id,
                            "relation": "may_invoke_plugin_entry",
                            "archive_path": archive_path,
                            "confidence": "medium",
                        }
                        for entry_id in plugin_entry_ids
                    )
        graph["summary"] = self._artifact_graph_summary(graph)
        return graph

    @staticmethod
    def _embedded_loader_references(
        workspace: Path,
        archive_paths: list[str],
    ) -> dict[str, list[dict[str, Any]]]:
        """Index exact host references once, even when a bundle has many plugins."""

        aliases: dict[str, set[str]] = {
            archive_path: {
                archive_path,
                PurePosixPath(archive_path).name,
            }
            for archive_path in archive_paths
        }
        alias_to_archives: dict[str, set[str]] = {}
        for archive_path, values in aliases.items():
            for value in values:
                alias_to_archives.setdefault(value, set()).add(archive_path)
        if not alias_to_archives:
            return {}
        pattern = re.compile(
            "|".join(
                re.escape(value)
                for value in sorted(alias_to_archives, key=len, reverse=True)
            )
        )
        found: dict[str, list[dict[str, Any]]] = {
            archive_path: [] for archive_path in archive_paths
        }
        seen: dict[str, set[tuple[str, int]]] = {
            archive_path: set() for archive_path in archive_paths
        }
        for root_name in ("jadx", "apktool", "archive"):
            root = workspace / root_name
            if not root.is_dir():
                continue
            for candidate in sorted(root.rglob("*")):
                if (
                    not candidate.is_file()
                    or candidate.suffix.lower() not in _LOADER_REFERENCE_SUFFIXES
                ):
                    continue
                try:
                    if candidate.stat().st_size > 4 * 1024 * 1024:
                        continue
                    text = candidate.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                matches = list(pattern.finditer(text))
                if not matches:
                    continue
                lines = text.splitlines()
                mechanisms = [
                    token
                    for token, marker in (
                        ("dex_class_loader", "DexClassLoader"),
                        ("path_class_loader", "PathClassLoader"),
                        ("in_memory_dex_loader", "InMemoryDexClassLoader"),
                        ("class_loader", "ClassLoader"),
                        ("reflective_entry", "loadClass"),
                        ("plugin_descriptor", "PluginInfo"),
                        ("plugin_config", "plugin_config"),
                    )
                    if marker in text
                ]
                for match in matches:
                    alias = match.group(0)
                    line = text.count("\n", 0, match.start()) + 1
                    for archive_path in alias_to_archives[alias]:
                        key = (str(candidate), line)
                        if key in seen[archive_path] or len(found[archive_path]) >= 12:
                            continue
                        seen[archive_path].add(key)
                        found[archive_path].append(
                            {
                                "root": root_name,
                                "path": str(candidate.relative_to(root)),
                                "workspace_path": str(candidate.relative_to(workspace)),
                                "line": line,
                                "matched_value": alias,
                                "mechanisms": mechanisms or ["asset_reference"],
                                "excerpt": lines[line - 1].strip()[:500],
                            }
                        )
        return {key: value for key, value in found.items() if value}

    @staticmethod
    def _embedded_plugin_entries(
        *,
        workspace: Path,
        analysis_root: Path,
        graph_analysis_root: str,
        child_root_id: str,
        package_name: str,
        application_class: str | None,
    ) -> list[dict[str, Any]]:
        candidates: dict[str, dict[str, Any]] = {}
        roots = [analysis_root / "jadx", analysis_root / "apktool"]
        for root in roots:
            if not root.is_dir():
                continue
            suffix = ".java" if root.name == "jadx" else ".smali"
            for source in sorted(root.rglob(f"*{suffix}")):
                try:
                    text = source.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if suffix == ".java":
                    package_match = re.search(
                        r"\bpackage\s+([A-Za-z_$][\w.$]*)\s*;",
                        text,
                    )
                    declared_package = package_match.group(1) if package_match else ""
                    class_match = re.search(
                        r"\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)",
                        text,
                    )
                    if class_match is None:
                        continue
                    class_name = (
                        f"{declared_package}.{class_match.group(1)}"
                        if declared_package
                        else class_match.group(1)
                    )
                    line = text.count("\n", 0, class_match.start()) + 1
                    abstract_declaration = bool(
                        re.search(
                            r"\b(?:abstract\s+class|interface)\s+"
                            + re.escape(class_match.group(1))
                            + r"\b",
                            text,
                        )
                    )
                else:
                    class_match = re.search(
                        r"(?m)^\.class[^\n]*\sL([^;]+);",
                        text,
                    )
                    if class_match is None:
                        continue
                    class_name = class_match.group(1).replace("/", ".")
                    line = text.count("\n", 0, class_match.start()) + 1
                    abstract_declaration = bool(
                        re.search(
                            r"(?m)^\.class[^\n]*\b(?:abstract|interface)\b",
                            text,
                        )
                    )
                lowered = class_name.lower()
                score = 0
                reasons: list[str] = []
                if package_name and class_name.startswith(f"{package_name}."):
                    score += 10
                    reasons.append("manifest_package_owned")
                if application_class and class_name == application_class:
                    score += 120
                    reasons.append("manifest_application")
                elif abstract_declaration:
                    continue
                if any(
                    token in lowered
                    for token in ("pluginentrance", "pluginentry", "plugin_entry")
                ):
                    score += 100
                    reasons.append("entry_class_name")
                elif "plugin" in lowered and any(
                    token in lowered for token in ("entry", "entrance", "bootstrap")
                ):
                    score += 70
                    reasons.append("plugin_entry_name")
                if re.search(
                    r"(?:implements|extends|\.implements|\.super)[^\n]{0,200}Plugin",
                    text,
                    re.IGNORECASE,
                ):
                    score += 45
                    reasons.append("plugin_contract")
                if any(
                    marker in text
                    for marker in ("IPluginInvoke", "IHostInvoke", "AbsInstantRecPlugin")
                ):
                    score += 30
                    reasons.append("host_plugin_interface")
                if score < 70:
                    continue
                if suffix == ".smali":
                    score += 5
                    reasons.append("dex_descriptor")
                canonical_name = re.sub(
                    r"\.p\d{3}(?=[a-z])",
                    ".",
                    class_name,
                )
                existing = candidates.get(canonical_name)
                if existing is not None and int(existing["score"]) >= score:
                    continue
                candidates[canonical_name] = {
                    "class_name": class_name,
                    "source_path": str(source.relative_to(workspace)),
                    "line": line,
                    "score": score,
                    "reasons": reasons,
                }
        result: list[dict[str, Any]] = []
        for candidate in sorted(
            candidates.values(),
            key=lambda item: (-int(item["score"]), str(item["class_name"])),
        )[:8]:
            class_name = str(candidate["class_name"])
            result.append(
                {
                    "id": (
                        f"{child_root_id}/plugin_entries/"
                        + hashlib.sha256(class_name.encode()).hexdigest()[:16]
                    ),
                    "path": candidate["source_path"],
                    "analysis_root": graph_analysis_root,
                    "kind": "embedded_plugin_entry",
                    "name": class_name,
                    "class_name": class_name,
                    "source_path": candidate["source_path"],
                    "line": candidate["line"],
                    "confidence": "high" if int(candidate["score"]) >= 100 else "medium",
                    "evidence": candidate["reasons"],
                }
            )
        return result

    @staticmethod
    def _rebase_artifact_graph(graph: dict[str, Any], prefix: str) -> dict[str, Any]:
        def rebase(value: str) -> str:
            if value in {"", "."}:
                return prefix
            return str(PurePosixPath(prefix) / PurePosixPath(value))

        mapping = {
            str(node["id"]): rebase(str(node["id"]))
            for node in graph.get("nodes", [])
        }
        nodes: list[dict[str, Any]] = []
        for source in graph.get("nodes", []):
            node = dict(source)
            node["id"] = mapping[str(source["id"])]
            node["path"] = rebase(str(source.get("path") or source["id"]))
            node["analysis_root"] = rebase(str(source.get("analysis_root") or "."))
            for key in ("native_index_path", "summary_path"):
                if isinstance(source.get(key), str):
                    node[key] = rebase(str(source[key]))
            nodes.append(node)
        edges = [
            {
                **dict(edge),
                "from": mapping[str(edge["from"])],
                "to": mapping[str(edge["to"])],
            }
            for edge in graph.get("edges", [])
        ]
        return {
            "schema_version": graph.get("schema_version", "1.1"),
            "root_id": mapping[str(graph["root_id"])],
            "nodes": nodes,
            "edges": edges,
            "summary": ApkInspector._artifact_graph_summary(
                {"nodes": nodes, "edges": edges}
            ),
        }

    @staticmethod
    def _artifact_graph_summary(graph: dict[str, Any]) -> dict[str, Any]:
        nodes = list(graph.get("nodes") or [])
        edges = list(graph.get("edges") or [])
        kinds: dict[str, int] = {}
        abi_counts: dict[str, int] = {}
        bridge_ownership: dict[str, int] = {}
        for node in nodes:
            kind = str(node.get("kind") or "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1
            if kind == "native_library":
                abi = str(node.get("abi") or "unknown")
                abi_counts[abi] = abi_counts.get(abi, 0) + 1
            elif kind == "java_native_bridge":
                ownership = str(node.get("ownership") or "unknown")
                bridge_ownership[ownership] = bridge_ownership.get(ownership, 0) + 1
        relations: dict[str, int] = {}
        for edge in edges:
            relation = str(edge.get("relation") or "unknown")
            relations[relation] = relations.get(relation, 0) + 1
        linked_methods = {
            (
                str(edge.get("from")),
                str(edge.get("method_name")),
                str(edge.get("argument_descriptor")),
            )
            for edge in edges
            if edge.get("relation") in {"binds_to_jni", "possible_dynamic_registration"}
        }
        java_native_method_count = sum(
            int(node.get("native_method_count") or 0)
            for node in nodes
            if node.get("kind") == "java_native_bridge"
        )
        jni_symbol_count = sum(
            int((node.get("jni") or {}).get("export_count") or 0)
            for node in nodes
            if node.get("kind") == "native_library"
        )
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_kinds": kinds,
            "edge_relations": relations,
            "apk_count": kinds.get("apk", 0),
            "native_library_count": kinds.get("native_library", 0),
            "java_native_bridge_count": kinds.get("java_native_bridge", 0),
            "java_native_method_count": java_native_method_count,
            "linked_java_native_method_count": len(linked_methods),
            "jni_symbol_count": jni_symbol_count,
            "native_libraries_by_abi": abi_counts,
            "java_bridges_by_ownership": bridge_ownership,
            "plugin_loader_count": kinds.get("plugin_loader_reference", 0),
            "embedded_plugin_entry_count": kinds.get("embedded_plugin_entry", 0),
        }

    def _run(self, argv: list[str], budget: TimeBudget | None, timeout_cap: int) -> CommandResult:
        timeout = timeout_cap if budget is None else budget.remaining(timeout_cap)
        if timeout <= 0:
            return CommandResult(
                argv=argv,
                exit_code=124,
                stdout="",
                stderr="preliminary-report time budget exhausted",
                timed_out=True,
            )
        return self.runner.run(argv, timeout=timeout)

    def _validate_zip(self, apk_path: Path) -> dict[str, Any]:
        if not zipfile.is_zipfile(apk_path):
            raise InvalidApkError("file is not a valid ZIP/APK container")
        total_uncompressed = 0
        native_libraries: list[str] = []
        dex_files: list[str] = []
        embedded_apk_files: list[str] = []
        javascript_files: list[str] = []
        html_files: list[str] = []
        duplicate_names: list[str] = []
        names_seen: set[str] = set()
        archive_facts: list[dict[str, Any]] = []
        security_resources: list[dict[str, Any]] = []
        security_hash_budget = 128 * 1024 * 1024
        security_hashed_bytes = 0
        with zipfile.ZipFile(apk_path) as archive:
            infos = archive.infolist()
            if len(infos) > self.settings.max_zip_entries:
                raise InvalidApkError("APK contains too many ZIP entries")
            for item in infos:
                if "\x00" in item.filename:
                    raise InvalidApkError("APK contains a NUL byte in a ZIP path")
                normalized = PurePosixPath(item.filename.replace("\\", "/"))
                if normalized.is_absolute() or ".." in normalized.parts:
                    raise InvalidApkError(f"unsafe ZIP path: {item.filename}")
                if item.filename in names_seen:
                    duplicate_names.append(item.filename)
                names_seen.add(item.filename)
                total_uncompressed += item.file_size
                if total_uncompressed > self.settings.max_uncompressed_bytes:
                    raise InvalidApkError("APK uncompressed size exceeds the configured limit")
                if (
                    item.compress_size
                    and item.file_size / item.compress_size > self.settings.max_compression_ratio
                ):
                    raise InvalidApkError(f"suspicious compression ratio for {item.filename}")
                if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                    native_libraries.append(item.filename)
                if re.fullmatch(r"classes\d*\.dex", PurePosixPath(item.filename).name):
                    dex_files.append(item.filename)
                suffix = PurePosixPath(item.filename).suffix.lower()
                if suffix == ".apk":
                    embedded_apk_files.append(item.filename)
                elif suffix in {".js", ".mjs", ".cjs"}:
                    javascript_files.append(item.filename)
                elif suffix in {".html", ".htm"}:
                    html_files.append(item.filename)
                archive_facts.append(
                    {
                        "path": item.filename,
                        "crc32": f"{item.CRC:08x}",
                        "size": item.file_size,
                        "compressed_size": item.compress_size,
                    }
                )
            for item in infos:
                if item.is_dir() or not self._is_security_resource(item.filename):
                    continue
                fact: dict[str, Any] = {
                    "path": item.filename,
                    "crc32": f"{item.CRC:08x}",
                    "size": item.file_size,
                    "compressed_size": item.compress_size,
                    "content_sha256": None,
                }
                if (
                    item.file_size <= 16 * 1024 * 1024
                    and security_hashed_bytes + item.file_size <= security_hash_budget
                ):
                    digest = hashlib.sha256()
                    with archive.open(item) as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            digest.update(chunk)
                    fact["content_sha256"] = digest.hexdigest()
                    security_hashed_bytes += item.file_size
                security_resources.append(fact)
                if len(security_resources) >= 4000:
                    break
            archive_fingerprint = hashlib.sha256(
                json.dumps(
                    sorted(archive_facts, key=lambda value: value["path"]),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            return {
                "entry_count": len(infos),
                "compressed_bytes": apk_path.stat().st_size,
                "uncompressed_bytes": total_uncompressed,
                "dex_files": sorted(dex_files),
                "native_libraries": sorted(native_libraries),
                "embedded_apk_files": sorted(embedded_apk_files),
                "javascript_files": sorted(javascript_files),
                "html_files": sorted(html_files),
                "duplicate_names": sorted(set(duplicate_names))[:200],
                "has_assets": any(name.startswith("assets/") for name in names_seen),
                "archive_fingerprint": archive_fingerprint,
                "security_resources": sorted(
                    security_resources,
                    key=lambda value: value["path"],
                ),
                "security_resource_hash_bytes": security_hashed_bytes,
            }

    @staticmethod
    def _is_security_resource(name: str) -> bool:
        path = PurePosixPath(name)
        suffix = path.suffix.lower()
        if name == "AndroidManifest.xml" or re.fullmatch(r"classes\d*\.dex", path.name):
            return True
        if name.startswith("lib/") and suffix == ".so":
            return True
        if name.startswith("res/xml/") or name.startswith("res/raw/"):
            return True
        return name.startswith("assets/") and suffix in {
            ".conf",
            ".cjs",
            ".html",
            ".htm",
            ".ini",
            ".js",
            ".json",
            ".mjs",
            ".properties",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
        }

    @staticmethod
    def _plaintext_manifest(apk_path: Path) -> str | None:
        with zipfile.ZipFile(apk_path) as archive:
            try:
                content = archive.read("AndroidManifest.xml")
            except KeyError:
                return None
        if content.lstrip().startswith(b"<"):
            return content.decode("utf-8", errors="replace")
        return None

    @staticmethod
    def _extract_searchable_files(apk_path: Path, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        allowed_suffixes = {
            ".xml",
            ".smali",
            ".java",
            ".kt",
            ".json",
            ".properties",
            ".js",
            ".mjs",
            ".cjs",
            ".html",
            ".htm",
        }
        total = 0
        with zipfile.ZipFile(apk_path) as archive:
            for item in archive.infolist():
                if (
                    item.is_dir()
                    or PurePosixPath(item.filename).suffix.lower() not in allowed_suffixes
                ):
                    continue
                if item.file_size > 2_000_000:
                    continue
                total += item.file_size
                if total > 250_000_000:
                    break
                target = destination.joinpath(*PurePosixPath(item.filename).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(item))

    @staticmethod
    def _serialize_result(result: CommandResult) -> dict[str, Any]:
        return {
            "argv": result.argv,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
        }

    @classmethod
    def _jadx_decompilation_summary(
        cls,
        result: CommandResult,
        jadx_dir: Path,
    ) -> dict[str, Any]:
        generated = sum(1 for _path in jadx_dir.rglob("*.java")) if jadx_dir.is_dir() else 0
        combined_output = f"{result.stdout}\n{result.stderr}"
        failed_classes = cls._failed_jadx_classes(combined_output)
        error_count_match = re.search(
            r"finished with errors,\s*count:\s*(\d+)",
            combined_output,
            flags=re.IGNORECASE,
        )
        reported_error_count = (
            int(error_count_match.group(1)) if error_count_match else len(failed_classes)
        )
        if result.timed_out:
            status = "partial_timeout" if generated else "timed_out"
        elif result.exit_code == 0:
            status = "complete_success" if generated else "completed_without_java"
        elif generated:
            status = "partial_success"
        else:
            status = "tool_failed"
        return {
            "status": status,
            "exit_code": result.exit_code,
            "generated_java_files": generated,
            "reported_error_count": reported_error_count,
            "identified_failed_class_count": len(failed_classes),
            "failed_classes": failed_classes[:2000],
            "output_usable": generated > 0,
        }

    @staticmethod
    def _failed_jadx_classes(output: str) -> list[str]:
        patterns = (
            r"failed to (?:decompile|process|load) (?:class\s*)?:?\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)",
            r"error processing class\s*:?\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)",
            r"in method:\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\.[A-Za-z_$<][\w$<>]*\(",
        )
        found: set[str] = set()
        for pattern in patterns:
            found.update(re.findall(pattern, output, flags=re.IGNORECASE))
        return sorted(found)

    @classmethod
    def _build_code_index(
        cls,
        *,
        result_entries: list[Any],
        package_name: str,
        workspace: Path,
        jadx_dir: Path,
        decoded_dir: Path,
        archive_dir: Path,
        decompilation: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        java_root = jadx_dir / "sources" if (jadx_dir / "sources").is_dir() else jadx_dir
        java_files = cls._class_file_map([java_root], ".java")
        smali_roots = [
            path
            for parent in (decoded_dir, archive_dir)
            if parent.is_dir()
            for path in parent.glob("smali*")
            if path.is_dir()
        ]
        smali_files = cls._class_file_map(smali_roots, ".smali")
        java_by_simple: dict[str, list[Path]] = {}
        for paths in java_files.values():
            for path in paths:
                java_by_simple.setdefault(path.stem, []).append(path)

        failed_classes = {str(value) for value in decompilation.get("failed_classes", [])}
        component_names = {
            str(entry.owner_component or entry.name)
            for entry in result_entries
            if entry.owner_component or entry.name
        }
        index: dict[str, dict[str, Any]] = {}
        for component in sorted(component_names):
            candidates = [component]
            if "$" in component:
                candidates.append(component.split("$", 1)[0])
            java_matches = cls._unique_paths(
                path for candidate in candidates for path in java_files.get(candidate, [])
            )
            if not java_matches:
                simple_name = candidates[-1].rsplit(".", 1)[-1]
                simple_matches = cls._unique_paths(java_by_simple.get(simple_name, []))
                if len(simple_matches) == 1:
                    java_matches = simple_matches
            smali_matches = cls._unique_paths(
                path for candidate in candidates for path in smali_files.get(candidate, [])
            )
            failed = any(
                value == component
                or value.startswith(f"{component}.")
                or component.startswith(f"{value}$")
                for value in failed_classes
            )
            source_matches = java_matches or smali_matches
            anchors = [
                cls._source_anchor(path, workspace, include_content=True)
                for path in source_matches[:3]
            ]
            seen_anchor_paths = {path.resolve() for path in source_matches[:3]}
            package_path = (package_name or "").replace(".", "/")
            if package_path:
                for path, relationship in cls._one_hop_app_references(
                    source_matches[:3],
                    [jadx_dir, decoded_dir, archive_dir],
                    package_path=package_path,
                    depth_limits=(6,),
                    include_inbound=False,
                ):
                    resolved = path.resolve()
                    if resolved in seen_anchor_paths:
                        continue
                    seen_anchor_paths.add(resolved)
                    anchor = cls._source_anchor(path, workspace, include_content=True)
                    anchor["relationship"] = relationship
                    anchors.append(anchor)
            source_has_errors = any(
                bool(anchor.get("decompiler_error_markers"))
                for anchor in anchors
                if anchor.get("language") == "java"
            )
            if java_matches and (failed or source_has_errors):
                status = "partial_source_available"
            elif java_matches:
                status = "source_available"
            elif smali_matches:
                status = "smali_fallback"
            elif failed:
                status = "target_decompilation_failed"
            else:
                status = "source_not_found"
            index[component] = {
                "component": component,
                "status": status,
                "target_in_jadx_failure_list": failed,
                "target_source_has_decompiler_errors": source_has_errors,
                "global_decompilation_status": decompilation.get("status"),
                "anchors": anchors,
            }
        return index

    @staticmethod
    def _class_file_map(roots: list[Path], suffix: str) -> dict[str, list[Path]]:
        mapped: dict[str, list[Path]] = {}
        for root in roots:
            if not root.is_dir():
                continue
            for path in root.rglob(f"*{suffix}"):
                try:
                    relative = path.relative_to(root).with_suffix("")
                except ValueError:
                    continue
                class_name = ".".join(relative.parts)
                mapped.setdefault(class_name, []).append(path)
        return mapped

    @staticmethod
    def _unique_paths(paths) -> list[Path]:  # noqa: ANN001
        return list(dict.fromkeys(paths))

    @staticmethod
    def _source_anchor(
        path: Path,
        workspace: Path,
        *,
        include_content: bool,
        max_chars: int = 24_000,
        focus_line: int | None = None,
    ) -> dict[str, Any]:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        line_start = 1
        if focus_line is not None and focus_line > 1:
            lines = text.splitlines(keepends=True)
            start_index = max(0, min(focus_line - 1, len(lines)) - 80)
            excerpt = "".join(lines[start_index:])[:max_chars]
            line_start = start_index + 1
        else:
            excerpt = text[:max_chars]
        anchor: dict[str, Any] = {
            "path": str(path.relative_to(workspace)),
            "language": {
                ".java": "java",
                ".kt": "kotlin",
                ".smali": "smali",
                ".js": "javascript",
                ".mjs": "javascript",
                ".cjs": "javascript",
                ".html": "html",
                ".htm": "html",
                ".xml": "xml",
            }.get(path.suffix.lower(), "text"),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "line_start": line_start,
            "line_end": line_start + excerpt.count("\n"),
            "truncated": len(text) > len(excerpt),
            "source_bytes": len(raw),
            "decompiler_error_markers": [
                marker
                for marker in (
                    "JADX ERROR",
                    "Method not decompiled",
                    "Method dump skipped",
                )
                if marker.lower() in text.lower()
            ],
        }
        if include_content:
            anchor["content"] = excerpt
        return anchor

    @classmethod
    def add_static_surface_to_code_index(
        cls,
        result: StaticAnalysisResult,
        *,
        surface_name: str,
        locations: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]] | None = None,
        package_name: str | None = None,
    ) -> None:
        anchors: list[dict[str, Any]] = []
        seen: set[Path] = set()
        seed_sources: list[Path] = []
        allowed_roots = {
            cls._search_root_label(path, result.workspace): path.resolve()
            for path in result.searchable_roots
            if path.is_dir()
        }
        for location in locations:
            root = allowed_roots.get(str(location.get("root") or ""))
            if root is None:
                continue
            candidate = (root / str(location.get("path") or "")).resolve()
            if candidate in seen or not candidate.is_relative_to(root) or not candidate.is_file():
                continue
            seen.add(candidate)
            seed_sources.append(candidate)
            anchor = cls._source_anchor(
                candidate,
                result.workspace,
                include_content=True,
                focus_line=int(location.get("line") or 0) or None,
            )
            anchor["signal_line"] = int(location.get("line") or 0)
            anchor["relationship"] = "signal_source"
            anchors.append(anchor)
            if len(anchors) >= 8:
                break
        package_path = (package_name or result.manifest.package_name).replace(".", "/")
        for candidate, relationship in cls._one_hop_app_references(
            seed_sources,
            list(allowed_roots.values()),
            package_path=package_path,
        ):
            if candidate in seen:
                continue
            seen.add(candidate)
            anchor = cls._source_anchor(
                candidate,
                result.workspace,
                include_content=True,
            )
            anchor["signal_line"] = 0
            anchor["relationship"] = relationship
            anchors.append(anchor)
            if len(anchors) >= 20:
                break
        result.code_index[surface_name] = {
            "component": surface_name,
            "status": "static_signal_source_available" if anchors else "source_not_found",
            "target_in_jadx_failure_list": False,
            "target_source_has_decompiler_errors": False,
            "global_decompilation_status": result.decompilation.get("status"),
            "anchors": anchors,
            "attack_chains": list(attack_chains or []),
        }

    @staticmethod
    def _search_root_label(root: Path, workspace: Path) -> str:
        try:
            return str(root.resolve().relative_to(workspace.resolve()))
        except ValueError:
            return root.name

    @staticmethod
    def _one_hop_app_references(
        seed_sources: list[Path],
        searchable_roots: list[Path],
        *,
        package_path: str,
        depth_limits: tuple[int, ...] = (6, 4, 4),
        include_inbound: bool = True,
    ) -> list[tuple[Path, str]]:
        """Resolve exact app-owned class references without exposing the whole APK."""

        descriptors: list[str] = []
        seen_descriptors: set[str] = set()
        seed_descriptors: set[str] = set()
        for source in seed_sources:
            try:
                text = source.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            class_match = re.search(r"(?m)^\.class[^\n]* L([^;]+);", text)
            if class_match:
                seed_descriptors.add(class_match.group(1))
            package_match = re.search(
                r"(?m)^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;",
                text,
            )
            if source.suffix == ".java" and package_match:
                seed_descriptors.add(f"{package_match.group(1).replace('.', '/')}/{source.stem}")
            for descriptor in ApkInspector._app_reference_descriptors(
                text,
                package_path=package_path,
                java_package=package_match.group(1) if package_match else None,
            ):
                if descriptor in seed_descriptors or descriptor in seen_descriptors:
                    continue
                seen_descriptors.add(descriptor)
                descriptors.append(descriptor)

        resolved: list[tuple[Path, str]] = []
        seen_paths: set[Path] = set()
        frontier = descriptors
        for depth, depth_limit in enumerate(depth_limits):
            next_frontier: list[str] = []
            added_this_depth = 0
            for descriptor in sorted(
                frontier,
                key=ApkInspector._reference_priority,
                reverse=True,
            ):
                outer_class = descriptor.split("$", 1)[0]
                candidates = ApkInspector._reference_candidates(
                    outer_class,
                    searchable_roots,
                )
                for candidate in candidates:
                    candidate = candidate.resolve()
                    if candidate in seen_paths or not candidate.is_file():
                        continue
                    seen_paths.add(candidate)
                    resolved.append((candidate, "outbound_reference"))
                    added_this_depth += 1
                    if depth + 1 < len(depth_limits):
                        try:
                            linked_text = candidate.read_text(
                                encoding="utf-8",
                                errors="replace",
                            )
                        except OSError:
                            linked_text = ""
                        linked_package = re.search(
                            r"(?m)^\s*package\s+"
                            r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;",
                            linked_text,
                        )
                        for linked in ApkInspector._app_reference_descriptors(
                            linked_text,
                            package_path=package_path,
                            java_package=(linked_package.group(1) if linked_package else None),
                        ):
                            if linked not in seed_descriptors and linked not in seen_descriptors:
                                seen_descriptors.add(linked)
                                next_frontier.append(linked)
                    break
                if added_this_depth >= depth_limit:
                    break
            frontier = next_frontier

        if not include_inbound:
            return resolved

        inbound_frontier = set(seed_descriptors)
        for inbound_limit in (4, 2):
            if not inbound_frontier:
                break
            needles = tuple(f"L{descriptor};" for descriptor in sorted(inbound_frontier))
            next_inbound_frontier: set[str] = set()
            added_this_depth = 0
            for root in searchable_roots:
                for smali_root in sorted(root.glob("smali*")):
                    package_root = smali_root / package_path
                    if not package_root.is_dir():
                        continue
                    for candidate in package_root.rglob("*.smali"):
                        candidate = candidate.resolve()
                        if candidate in seen_paths or candidate in seed_sources:
                            continue
                        try:
                            text = candidate.read_text(
                                encoding="utf-8",
                                errors="replace",
                            )
                        except OSError:
                            continue
                        if not any(needle in text for needle in needles):
                            continue
                        seen_paths.add(candidate)
                        resolved.append((candidate, "inbound_reference"))
                        added_this_depth += 1
                        class_match = re.search(
                            r"(?m)^\.class[^\n]* L([^;]+);",
                            text,
                        )
                        if class_match:
                            next_inbound_frontier.add(class_match.group(1))
                        if added_this_depth >= inbound_limit:
                            break
                    if added_this_depth >= inbound_limit:
                        break
                if added_this_depth >= inbound_limit:
                    break
            inbound_frontier = next_inbound_frontier
        return resolved

    @staticmethod
    def _app_reference_descriptors(
        text: str,
        *,
        package_path: str,
        java_package: str | None,
    ) -> list[str]:
        """Extract exact app-owned class names from Smali and Java source."""

        found = {
            descriptor
            for descriptor in re.findall(r"L([A-Za-z0-9_/$]+);", text)
            if descriptor.startswith(f"{package_path}/")
        }
        package_dot = package_path.replace("/", ".")
        for qualified in re.findall(
            rf"\b({re.escape(package_dot)}(?:\.[A-Za-z_$][\w$]*)+)\b",
            text,
        ):
            found.add(qualified.replace(".", "/"))
        if java_package and (
            java_package == package_dot or java_package.startswith(f"{package_dot}.")
        ):
            for simple_name in re.findall(r"\b[A-Z][A-Za-z0-9_$]*\b", text):
                found.add(f"{java_package.replace('.', '/')}/{simple_name}")
        return sorted(found)

    @staticmethod
    def _reference_candidates(
        descriptor: str,
        searchable_roots: list[Path],
    ) -> list[Path]:
        candidates: list[Path] = []
        seen: set[Path] = set()
        for root in searchable_roots:
            possible = [
                root / "sources" / f"{descriptor}.java",
                root / f"{descriptor}.java",
            ]
            for smali_root in sorted(root.glob("smali*")):
                possible.append(smali_root / f"{descriptor}.smali")
            possible.append(root / f"{descriptor}.smali")
            for candidate in possible:
                resolved = candidate.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                candidates.append(resolved)
        return candidates

    @staticmethod
    def _reference_priority(descriptor: str) -> tuple[int, int, str]:
        lowered = descriptor.lower()
        security_terms = (
            "risk",
            "assess",
            "policy",
            "permission",
            "auth",
            "bridge",
            "web",
            "javascript",
            "h5",
            "url",
            "uri",
            "route",
            "router",
            "handler",
            "controller",
            "jump",
            "launch",
            "shell",
            "command",
            "path",
            "binder",
            "service",
            "receiver",
            "activity",
            "config",
            "source",
        )
        score = sum(term in lowered for term in security_terms)
        return score, -lowered.count("$"), descriptor

    @staticmethod
    def persist_code_index(result: StaticAnalysisResult) -> None:
        (result.workspace / "code_index.json").write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "context_version": CODE_INDEX_CONTEXT_VERSION,
                    "decompilation": result.decompilation,
                    "components": result.code_index,
                    "attack_chains": result.attack_chains,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _merge_badging(manifest: ManifestDocument, text: str) -> None:
        package_match = re.search(
            r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", text
        )
        if package_match:
            manifest.package_name = package_match.group(1)
            manifest.version_code = package_match.group(2) or manifest.version_code
            manifest.version_name = package_match.group(3) or manifest.version_name
        min_match = re.search(r"sdkVersion:'(\d+)'", text)
        target_match = re.search(r"targetSdkVersion:'(\d+)'", text)
        if min_match:
            manifest.min_sdk = int(min_match.group(1))
        if target_match:
            manifest.target_sdk = int(target_match.group(1))

    @staticmethod
    def _parse_signing(result: CommandResult) -> dict[str, Any]:
        text = f"{result.stdout}\n{result.stderr}"
        schemes: dict[str, bool] = {}
        for version in ("v1", "v2", "v3", "v3.1", "v4"):
            match = re.search(
                rf"Verified using {re.escape(version)} scheme[^:]*:\s*(true|false)", text, re.I
            )
            if match:
                schemes[version] = match.group(1).lower() == "true"
        certificates = re.findall(r"Signer #[0-9]+ certificate SHA-256 digest:\s*([^\s]+)", text)
        return {
            "verified": result.exit_code == 0,
            "schemes": schemes,
            "certificate_sha256": certificates,
            "diagnostic_sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
