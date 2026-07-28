from __future__ import annotations

import os
from pathlib import Path

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def harden_permissions(path: Path, mode: int) -> None:
    """Best-effort permission hardening without following symbolic links."""
    if os.name != "posix":
        return
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (NotImplementedError, OSError, TypeError):
        # Some mounted filesystems and non-POSIX platforms cannot represent these
        # mode bits. Newly created paths still request restrictive modes, while
        # existing paths retain their current platform ACLs.
        return


def ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(
            f"private directory is not a regular directory because it is a symbolic link: {path}"
        )
    path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"private directory is not a regular directory: {path}")
    harden_permissions(path, PRIVATE_DIRECTORY_MODE)


def ensure_private_file(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"private file must not be a symbolic link: {path}")
    if not path.exists():
        return
    if not path.is_file():
        raise ValueError(f"private file is not a regular file: {path}")
    harden_permissions(path, PRIVATE_FILE_MODE)


def create_private_file(path: Path) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            PRIVATE_FILE_MODE,
        )
    except FileExistsError:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"private file is not a regular file: {path}") from None
    else:
        os.close(descriptor)
    ensure_private_file(path)
