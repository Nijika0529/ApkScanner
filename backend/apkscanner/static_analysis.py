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
from .permissions import ensure_private_directory
from .tools import CommandResult, TimeBudget, ToolRunner, discover_tools

CODE_INDEX_CONTEXT_VERSION = "component-one-hop-android-chains-v3"


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


class ApkInspector:
    def __init__(self, settings: Settings, runner: ToolRunner | None = None):
        self.settings = settings
        self.runner = runner or ToolRunner(settings.tool_timeout_seconds)

    def inspect(
        self, apk_path: Path, scan_id: str, budget: TimeBudget | None = None
    ) -> StaticAnalysisResult:
        file_inventory = self._validate_zip(apk_path)
        workspace = self.settings.data_dir / "workspaces" / scan_id
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
        if not metadata_path.is_file() or not index_path.is_file():
            return None
        if any((workspace / name).exists() for name in ("jadx", "apktool", "archive")):
            return None
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            index_payload = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if (
            metadata.get("artifact_sha256") != artifact_sha256
            or metadata.get("analysis_profile") != analysis_profile
            or index_payload.get("context_version") != CODE_INDEX_CONTEXT_VERSION
            or not isinstance(index_payload.get("components"), dict)
            or not isinstance(index_payload.get("attack_chains"), list)
        ):
            return None
        manifest_relative = metadata.get("manifest_relative_path")
        if not isinstance(manifest_relative, str):
            return None
        cached_manifest = (cache_dir / manifest_relative).resolve()
        if not cached_manifest.is_relative_to(cache_dir.resolve()) or not cached_manifest.is_file():
            return None
        for name in ("jadx", "apktool", "archive"):
            source = cache_dir / name
            if source.is_dir():
                shutil.copytree(source, workspace / name)
        top_manifest = cache_dir / "AndroidManifest.xml"
        if top_manifest.is_file():
            shutil.copy2(top_manifest, workspace / "AndroidManifest.xml")
        shutil.copy2(index_path, workspace / "code_index.json")
        workspace_manifest = workspace / manifest_relative
        if not workspace_manifest.is_file():
            return None
        manifest = parse_manifest(workspace_manifest.read_text(encoding="utf-8", errors="replace"))
        decompilation = {
            **dict(metadata.get("decompilation") or {}),
            "cache_hit": True,
            "analysis_profile": analysis_profile,
        }
        searchable_roots = [
            path
            for path in (workspace / "jadx", workspace / "apktool", workspace / "archive")
            if path.is_dir()
        ]
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
            },
            searchable_roots=searchable_roots,
            decompilation=decompilation,
            code_index=dict(index_payload["components"]),
            attack_chains=list(index_payload["attack_chains"]),
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
            for name in ("jadx", "apktool", "archive"):
                source = workspace / name
                if source.is_dir():
                    shutil.copytree(source, temporary / name)
            top_manifest = workspace / "AndroidManifest.xml"
            if top_manifest.is_file():
                shutil.copy2(top_manifest, temporary / "AndroidManifest.xml")
            shutil.copy2(workspace / "code_index.json", temporary / "code_index.json")
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
            ".html",
            ".ini",
            ".js",
            ".json",
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
        allowed_suffixes = {".xml", ".smali", ".java", ".kt", ".json", ".properties"}
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
            "language": "java" if path.suffix == ".java" else "smali",
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
    ) -> None:
        anchors: list[dict[str, Any]] = []
        seen: set[Path] = set()
        seed_sources: list[Path] = []
        allowed_roots = {
            path.name: path.resolve() for path in result.searchable_roots if path.is_dir()
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
        package_path = result.manifest.package_name.replace(".", "/")
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
