from __future__ import annotations

import hashlib

import pytest
from apkscanner.artifacts import ArtifactStore


def test_evidence_store_rejects_symlinked_digest_directory(settings, tmp_path) -> None:  # noqa: ANN001
    settings.ensure_directories()
    content = b"immutable evidence"
    prefix = hashlib.sha256(content).hexdigest()[:2]
    outside = tmp_path / "outside"
    outside.mkdir()
    (settings.data_dir / "evidence" / prefix).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="regular directory"):
        ArtifactStore(settings).put_bytes("evidence", content, suffix=".json")
