from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def files_containing_any(
    root: Path,
    *,
    literals: tuple[str, ...] | list[str] | set[str],
    suffixes: tuple[str, ...] | list[str] | set[str],
    ignore_case: bool = False,
) -> list[Path] | None:
    """Return files containing any literal using ripgrep's streaming scanner.

    ``None`` means the optimized scanner was unavailable or failed, so callers
    can preserve the existing Python traversal as a compatibility fallback.
    An empty list is a complete successful search with no matches.
    """

    executable = shutil.which("rg")
    normalized_literals = tuple(
        dict.fromkeys(value for value in literals if isinstance(value, str) and value)
    )
    normalized_suffixes = tuple(
        dict.fromkeys(
            value if value.startswith(".") else f".{value}"
            for value in suffixes
            if isinstance(value, str) and value
        )
    )
    if executable is None or not root.is_dir() or not normalized_literals:
        return None
    command = [
        executable,
        "--files-with-matches",
        "--null",
        "--fixed-strings",
        "--no-messages",
        "--no-ignore",
    ]
    if ignore_case:
        command.append("--ignore-case")
    for suffix in normalized_suffixes:
        command.extend(["--glob", f"*{suffix}"])
    for literal in normalized_literals:
        command.extend(["-e", literal])
    command.append(".")
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode == 1:
        return []
    if completed.returncode != 0:
        return None
    paths: list[Path] = []
    seen: set[Path] = set()
    resolved_root = root.resolve()
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        candidate = (resolved_root / relative).resolve()
        if candidate in seen or not candidate.is_relative_to(resolved_root):
            continue
        seen.add(candidate)
        paths.append(candidate)
    return sorted(paths)
