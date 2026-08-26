from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import AsyncIterator
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

from fastapi import UploadFile

from ..core.config import Settings
from ..core.permissions import (
    PRIVATE_FILE_MODE,
    ensure_private_directory,
    ensure_private_file,
)


class ArtifactTooLargeError(ValueError):
    pass


class ArtifactStore:
    _CONTENT_CATEGORIES = {
        "artifacts",
        "evidence",
        "poc_artifacts",
        "poc_sources",
        "reports",
        "operator_artifacts",
    }

    def __init__(self, settings: Settings):
        self.settings = settings
        self._harden_existing_paths()

    async def save_upload(self, upload: UploadFile) -> tuple[str, Path, int]:
        artifact_root = self._category_root("artifacts")
        temporary = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="wb", prefix="upload-", suffix=".part", dir=artifact_root, delete=False
        )
        temp_path = Path(temporary.name)
        ensure_private_file(temp_path)
        digest = hashlib.sha256()
        total = 0
        try:
            with temporary as destination:
                async for chunk in self._read_chunks(upload):
                    total += len(chunk)
                    if total > self.settings.max_upload_bytes:
                        raise ArtifactTooLargeError(
                            f"APK exceeds {self.settings.max_upload_bytes} byte upload limit"
                        )
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
            sha256 = digest.hexdigest()
            final_dir = artifact_root / sha256[:2]
            ensure_private_directory(final_dir)
            self._verify_directory(final_dir, artifact_root)
            final_path = final_dir / f"{sha256}.apk"
            if final_path.exists() or final_path.is_symlink():
                self._verify_existing(final_path, sha256)
                temp_path.unlink(missing_ok=True)
            else:
                temp_path.replace(final_path)
            ensure_private_file(final_path)
            return sha256, final_path, total
        except Exception:
            temporary.close()
            temp_path.unlink(missing_ok=True)
            raise

    @staticmethod
    async def _read_chunks(upload: UploadFile) -> AsyncIterator[bytes]:
        while chunk := await upload.read(1024 * 1024):
            yield chunk

    def put_bytes(
        self,
        category: str,
        content: bytes,
        *,
        suffix: str = ".bin",
    ) -> tuple[str, Path]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", category):
            raise ValueError("artifact category is invalid")
        if not re.fullmatch(r"\.[A-Za-z0-9]{1,10}", suffix):
            raise ValueError("artifact suffix is invalid")
        digest = hashlib.sha256(content).hexdigest()
        root = self._category_root(category)
        directory = root / digest[:2]
        ensure_private_directory(directory)
        self._verify_directory(directory, root)
        path = directory / f"{digest}{suffix}"
        if path.exists() or path.is_symlink():
            self._verify_existing(path, digest)
        else:
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    PRIVATE_FILE_MODE,
                )
            except FileExistsError:
                self._verify_existing(path, digest)
            else:
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(content)
                except Exception:
                    path.unlink(missing_ok=True)
                    raise
        ensure_private_file(path)
        return digest, path

    def put_json(self, category: str, value: Any) -> tuple[str, Path]:
        content = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode()
        return self.put_bytes(category, content, suffix=".json")

    def put_file(
        self,
        category: str,
        source: str | Path,
        *,
        suffix: str | None = None,
    ) -> tuple[str, Path, int]:
        """Stream a local file into the content-addressed store without loading it in memory."""

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", category):
            raise ValueError("artifact category is invalid")
        source_path = Path(source)
        if source_path.is_symlink() or not source_path.is_file():
            raise ValueError("artifact source is not a regular file")
        actual_suffix = suffix or source_path.suffix.lower() or ".bin"
        if not re.fullmatch(r"\.[A-Za-z0-9]{1,10}", actual_suffix):
            actual_suffix = ".bin"
        root = self._category_root(category)
        temporary = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="wb", prefix="import-", suffix=".part", dir=root, delete=False
        )
        temp_path = Path(temporary.name)
        ensure_private_file(temp_path)
        digest = hashlib.sha256()
        total = 0
        try:
            with source_path.open("rb") as input_stream, temporary as output_stream:
                while chunk := input_stream.read(1024 * 1024):
                    digest.update(chunk)
                    total += len(chunk)
                    output_stream.write(chunk)
                output_stream.flush()
            sha256 = digest.hexdigest()
            directory = root / sha256[:2]
            ensure_private_directory(directory)
            self._verify_directory(directory, root)
            path = directory / f"{sha256}{actual_suffix}"
            if path.exists() or path.is_symlink():
                self._verify_existing(path, sha256)
                temp_path.unlink(missing_ok=True)
            else:
                temp_path.replace(path)
            ensure_private_file(path)
            return sha256, path, total
        except Exception:
            temporary.close()
            temp_path.unlink(missing_ok=True)
            raise

    @staticmethod
    def stream_file(path: Path, chunk_size: int = 1024 * 1024) -> BinaryIO:
        del chunk_size
        return path.open("rb")

    def read_json_artifact(
        self,
        category: str,
        path: str | Path,
        expected_sha256: str,
    ) -> Any:
        candidate = self.verify_content_addressed(category, path, expected_sha256)
        return json.loads(candidate.read_text(encoding="utf-8"))

    def verify_content_addressed(
        self,
        category: str,
        path: str | Path,
        expected_sha256: str,
    ) -> Path:
        candidate = Path(path)
        root = self._category_root(category)
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("content-addressed artifact is unavailable")
        if not candidate.resolve().is_relative_to(root.resolve()):
            raise ValueError("content-addressed artifact escapes its configured root")
        self._verify_existing(candidate, expected_sha256)
        ensure_private_file(candidate)
        return candidate

    def delete_content_addressed(
        self,
        category: str,
        path: str | Path,
        expected_sha256: str,
    ) -> bool:
        candidate = Path(path)
        root = self._category_root(category)
        if candidate.is_symlink():
            raise ValueError("refusing to delete a symbolic-link artifact")
        if not candidate.exists():
            return False
        if not candidate.is_file() or not candidate.resolve().is_relative_to(root.resolve()):
            raise ValueError("refusing to delete an artifact outside its configured root")
        if candidate.stem != expected_sha256:
            raise ValueError("refusing to delete an artifact with an unexpected filename")
        candidate.unlink()
        if candidate.parent != root:
            with suppress(OSError):
                candidate.parent.rmdir()
        return True

    def delete_scan_workspace(self, scan_id: str) -> bool:
        if not re.fullmatch(r"[a-f0-9-]{36}", scan_id):
            raise ValueError("scan ID is unsafe for workspace deletion")
        root = self._category_root("workspaces")
        workspace = root / scan_id
        if workspace.is_symlink():
            raise ValueError("refusing to delete a symbolic-link workspace")
        if not workspace.exists():
            return False
        if not workspace.is_dir() or not workspace.resolve().is_relative_to(root.resolve()):
            raise ValueError("refusing to delete a workspace outside its configured root")
        shutil.rmtree(workspace)
        return True

    @staticmethod
    def _verify_existing(path: Path, expected_sha256: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"content-addressed artifact is not a regular file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise ValueError(f"content-addressed artifact digest mismatch: {path}")

    def _category_root(self, category: str) -> Path:
        data_root = self.settings.data_dir.resolve()
        root = data_root / category
        if root.is_symlink():
            raise ValueError(f"artifact category must not be a symbolic link: {root}")
        ensure_private_directory(root)
        self._verify_directory(root, data_root)
        return root

    def _harden_existing_paths(self) -> None:
        data_root = self.settings.data_dir.resolve()
        for category in self._CONTENT_CATEGORIES:
            root = data_root / category
            if root.is_symlink() or not root.is_dir():
                continue
            ensure_private_directory(root)
            for entry in root.iterdir():
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    ensure_private_directory(entry)
                    for candidate in entry.iterdir():
                        ensure_private_file(candidate)
                else:
                    ensure_private_file(entry)

        workspace_root = data_root / "workspaces"
        if workspace_root.is_symlink() or not workspace_root.is_dir():
            return
        ensure_private_directory(workspace_root)
        for workspace in workspace_root.iterdir():
            if not workspace.is_symlink() and workspace.is_dir():
                ensure_private_directory(workspace)

    @staticmethod
    def _verify_directory(path: Path, allowed_root: Path) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"artifact path is not a regular directory: {path}")
        if not path.resolve().is_relative_to(allowed_root.resolve()):
            raise ValueError(f"artifact path escapes its configured root: {path}")
