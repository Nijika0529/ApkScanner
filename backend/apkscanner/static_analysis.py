from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .config import Settings
from .manifest import ManifestDocument, parse_manifest
from .tools import CommandResult, TimeBudget, ToolRunner, discover_tools


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


class ApkInspector:
    def __init__(self, settings: Settings, runner: ToolRunner | None = None):
        self.settings = settings
        self.runner = runner or ToolRunner(settings.tool_timeout_seconds)

    def inspect(
        self, apk_path: Path, scan_id: str, budget: TimeBudget | None = None
    ) -> StaticAnalysisResult:
        file_inventory = self._validate_zip(apk_path)
        workspace = self.settings.data_dir / "workspaces" / scan_id
        workspace.mkdir(parents=True, exist_ok=True)
        tool_versions = discover_tools(self.runner)
        tool_results: dict[str, dict[str, Any]] = {}
        decoded_dir = workspace / "apktool"
        manifest_path: Path | None = None
        searchable_roots: list[Path] = []

        if self.runner.available("apktool"):
            result = self._run(
                ["apktool", "d", "--force", "--output", str(decoded_dir), str(apk_path)],
                budget,
                self.settings.tool_timeout_seconds,
            )
            tool_results["apktool"] = self._serialize_result(result)
            candidate = decoded_dir / "AndroidManifest.xml"
            if candidate.exists():
                manifest_path = candidate
                searchable_roots.append(decoded_dir)

        if manifest_path is None and self.runner.available("apkanalyzer"):
            result = self._run(
                ["apkanalyzer", "manifest", "print", str(apk_path)], budget, 120
            )
            tool_results["apkanalyzer"] = self._serialize_result(result)
            if result.exit_code == 0 and result.stdout.lstrip().startswith("<"):
                manifest_path = workspace / "AndroidManifest.xml"
                manifest_path.write_text(result.stdout, encoding="utf-8")
                searchable_roots.append(workspace)

        if manifest_path is None:
            plaintext = self._plaintext_manifest(apk_path)
            if plaintext is not None:
                manifest_path = workspace / "AndroidManifest.xml"
                manifest_path.write_text(plaintext, encoding="utf-8")
                searchable_roots.append(workspace)

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
            jadx_dir = workspace / "jadx"
            result = self._run(
                [
                    "jadx",
                    "--no-res",
                    "--deobf",
                    "--output-dir",
                    str(jadx_dir),
                    str(apk_path),
                ],
                budget,
                self.settings.tool_timeout_seconds,
            )
            tool_results["jadx"] = self._serialize_result(result)
            if jadx_dir.exists():
                searchable_roots.insert(0, jadx_dir)

        if self.runner.available("aapt2"):
            result = self._run(
                ["aapt2", "dump", "badging", str(apk_path)], budget, 120
            )
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

        return StaticAnalysisResult(
            manifest=manifest,
            workspace=workspace,
            tool_versions=tool_versions,
            tool_results=tool_results,
            signing=signing,
            file_inventory=file_inventory,
            searchable_roots=searchable_roots,
        )

    def _run(
        self, argv: list[str], budget: TimeBudget | None, timeout_cap: int
    ) -> CommandResult:
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
                if item.compress_size and item.file_size / item.compress_size > self.settings.max_compression_ratio:
                    raise InvalidApkError(f"suspicious compression ratio for {item.filename}")
                if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                    native_libraries.append(item.filename)
                if re.fullmatch(r"classes\d*\.dex", PurePosixPath(item.filename).name):
                    dex_files.append(item.filename)
            return {
                "entry_count": len(infos),
                "compressed_bytes": apk_path.stat().st_size,
                "uncompressed_bytes": total_uncompressed,
                "dex_files": sorted(dex_files),
                "native_libraries": sorted(native_libraries),
                "duplicate_names": sorted(set(duplicate_names))[:200],
                "has_assets": any(name.startswith("assets/") for name in names_seen),
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
                if item.is_dir() or PurePosixPath(item.filename).suffix.lower() not in allowed_suffixes:
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
