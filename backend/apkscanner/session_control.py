from __future__ import annotations

import argparse
import os
import signal
from pathlib import Path


def kill_uid(uid: int) -> int:
    if os.geteuid() != 0:
        raise PermissionError("session-control requires container root")
    if uid < 10_000 or uid > 60_000:
        raise ValueError("session UID is outside the configured safety range")
    killed = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            os.kill(int(entry.name), signal.SIGKILL)
            killed += 1
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return killed


def main() -> None:
    parser = argparse.ArgumentParser(prog="session-control")
    subparsers = parser.add_subparsers(dest="action", required=True)
    kill = subparsers.add_parser("kill")
    kill.add_argument("--uid", type=int, required=True)
    args = parser.parse_args()
    if args.action == "kill":
        print(kill_uid(args.uid))


if __name__ == "__main__":
    main()
