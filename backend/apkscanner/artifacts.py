from __future__ import annotations

import hashlib
import json
import re
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, BinaryIO

from fastapi import UploadFile

from .config import Settings


class ArtifactTooLargeError(ValueError):
    pass


class ArtifactStore:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def save_upload(self, upload: UploadFile) -> tuple[str, Path, int]:
        artifact_root = self._category_root("artifacts")
        temporary = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="wb", prefix="upload-", suffix=".part", dir=artifact_root, delete=False
        )
        temp_path = Path(temporary.name)
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
            final_dir.mkdir(parents=True, exist_ok=True)
            self._verify_directory(final_dir, artifact_root)
            final_path = final_dir / f"{sha256}.apk"
            if final_path.exists() or final_path.is_symlink():
                self._verify_existing(final_path, sha256)
                temp_path.unlink(missing_ok=True)
            else:
                temp_path.replace(final_path)
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
        directory.mkdir(parents=True, exist_ok=True)
        self._verify_directory(directory, root)
        path = directory / f"{digest}{suffix}"
        if path.exists() or path.is_symlink():
            self._verify_existing(path, digest)
        else:
            try:
                with path.open("xb") as stream:
                    stream.write(content)
            except FileExistsError:
                self._verify_existing(path, digest)
        return digest, path

    def put_json(self, category: str, value: Any) -> tuple[str, Path]:
        content = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode()
        return self.put_bytes(category, content, suffix=".json")

    @staticmethod
    def stream_file(path: Path, chunk_size: int = 1024 * 1024) -> BinaryIO:
        del chunk_size
        return path.open("rb")

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
        root.mkdir(parents=True, exist_ok=True)
        self._verify_directory(root, data_root)
        return root

    @staticmethod
    def _verify_directory(path: Path, allowed_root: Path) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"artifact path is not a regular directory: {path}")
        if not path.resolve().is_relative_to(allowed_root.resolve()):
            raise ValueError(f"artifact path escapes its configured root: {path}")
