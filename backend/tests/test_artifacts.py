from __future__ import annotations

import asyncio
import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from io import BytesIO

import pytest
from apkscanner.platform.artifacts import ArtifactStore
from fastapi import UploadFile


def test_evidence_store_rejects_symlinked_digest_directory(settings, tmp_path) -> None:  # noqa: ANN001
    settings.ensure_directories()
    content = b"immutable evidence"
    prefix = hashlib.sha256(content).hexdigest()[:2]
    outside = tmp_path / "outside"
    outside.mkdir()
    (settings.data_dir / "evidence" / prefix).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="regular directory"):
        ArtifactStore(settings).put_bytes("evidence", content, suffix=".json")


def test_concurrent_identical_evidence_writes_publish_only_complete_content(
    settings, monkeypatch,
) -> None:
    store = ArtifactStore(settings)
    content = b"concurrent immutable evidence"
    writing = threading.Event()
    release = threading.Event()
    original_fdopen = os.fdopen

    @contextmanager
    def paused_fdopen(*args, **kwargs):
        with original_fdopen(*args, **kwargs) as stream:
            if threading.current_thread().name.startswith("paused-writer"):
                writing.set()
                assert release.wait(5)
            yield stream

    monkeypatch.setattr(os, "fdopen", paused_fdopen)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="paused-writer") as pool:
        first = pool.submit(store.put_bytes, "evidence", content, suffix=".json")
        try:
            assert writing.wait(5)
            second = store.put_bytes("evidence", content, suffix=".json")
        finally:
            release.set()
        assert first.result(timeout=5) == second
    digest, path = second
    assert store.verify_content_addressed("evidence", path, digest).read_bytes() == content
    assert not list((settings.data_dir / "evidence").rglob("*.part"))


@pytest.mark.asyncio
async def test_cancelled_upload_removes_partial_file(settings) -> None:
    store = ArtifactStore(settings)

    class CancelledUpload:
        reads = 0

        async def read(self, size):
            self.reads += 1
            if self.reads == 1:
                return b"partial apk"
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await store.save_upload(CancelledUpload())
    assert not list((settings.data_dir / "artifacts").rglob("*.part"))


@pytest.mark.asyncio
@pytest.mark.parametrize("writer", ["bytes", "file", "upload"])
async def test_publication_rejects_a_conflicting_artifact_without_overwriting_it(
    settings, tmp_path, monkeypatch, writer,
) -> None:
    store = ArtifactStore(settings)
    content = b"expected artifact"
    conflict = b"conflicting content"
    real_link = os.link
    destinations = []

    def conflicting_link(source, destination):
        destination.write_bytes(conflict)
        destinations.append(destination)
        return real_link(source, destination)

    monkeypatch.setattr(os, "link", conflicting_link)
    with pytest.raises(ValueError, match="digest mismatch"):
        if writer == "bytes":
            store.put_bytes("artifacts", content, suffix=".apk")
        elif writer == "file":
            source = tmp_path / "source.apk"
            source.write_bytes(content)
            store.put_file("artifacts", source)
        else:
            await store.save_upload(UploadFile(file=BytesIO(content), filename="source.apk"))
    assert len(destinations) == 1
    assert destinations[0].read_bytes() == conflict
    assert not list((settings.data_dir / "artifacts").rglob("*.part"))
