from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

_SOURCE_SUFFIXES = frozenset({".java", ".kt", ".smali"})
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_EXCERPT_LINES = 100
_MAX_EXCERPT_CHARS = 16_000
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


@dataclass(frozen=True, slots=True)
class StaticSourceExcerpt:
    relative_path: str
    source_sha256: str
    line_start: int
    line_end: int
    text: str
    truncated: bool


def capture_static_source_excerpt(
    *,
    scan_workspace: Path,
    relative_path: str,
    line_start: int,
    line_end: int | None = None,
    expected_sha256: str | None = None,
) -> StaticSourceExcerpt | None:
    """Read exact target code lines from a scan-owned decompiler workspace."""

    if not isinstance(relative_path, str) or len(relative_path) > 600:
        return None
    candidate = Path(relative_path)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or candidate.parts[0] not in {"jadx", "apktool"}
        or ".." in candidate.parts
        or candidate.suffix.lower() not in _SOURCE_SUFFIXES
        or not isinstance(line_start, int)
        or isinstance(line_start, bool)
        or line_start < 1
        or line_start > 1_000_000
        or (
            line_end is not None
            and (
                not isinstance(line_end, int) or isinstance(line_end, bool) or line_end < line_start
            )
        )
        or (expected_sha256 is not None and _SHA256.fullmatch(expected_sha256) is None)
    ):
        return None
    root = scan_workspace.resolve()
    path = root.joinpath(*candidate.parts)
    if any(
        root.joinpath(*candidate.parts[:index]).is_symlink()
        for index in range(1, len(candidate.parts) + 1)
    ):
        return None
    try:
        if not path.is_file() or path.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            return None
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            return None
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError, ValueError):
        return None
    if line_start > len(lines):
        return None
    focus_end = min(line_end or line_start, len(lines))
    first = max(1, line_start - 12)
    last = min(len(lines), max(focus_end + 24, first + 1), first + _MAX_EXCERPT_LINES - 1)
    selected = "\n".join(lines[first - 1 : last])
    truncated = len(selected) > _MAX_EXCERPT_CHARS or first > 1 or last < len(lines)
    if len(selected) > _MAX_EXCERPT_CHARS:
        selected = selected[:_MAX_EXCERPT_CHARS]
        last = first + selected.count("\n")
    return StaticSourceExcerpt(
        relative_path=candidate.as_posix(),
        source_sha256=digest,
        line_start=first,
        line_end=last,
        text=selected,
        truncated=truncated,
    )
