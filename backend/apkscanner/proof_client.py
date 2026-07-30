from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apkscanner-proof <proof-replay.json>")
    task_id = os.getenv("APKSCANNER_PROOF_TASK_ID")
    endpoint = os.getenv("APKSCANNER_PROOF_REPLAY_URL")
    token = os.getenv("APKSCANNER_PROOF_TOKEN")
    if not task_id or not endpoint or not token:
        raise SystemExit(
            "live proof replay is unavailable outside an active APKScanner Agent task"
        )
    source = Path(sys.argv[1]).resolve()
    workspace = Path.cwd().resolve()
    if not source.is_file() or not source.is_relative_to(workspace):
        raise SystemExit("proof replay JSON must be a regular file under the task workspace")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid proof replay JSON: {exc}") from exc
    request = Request(
        f"{endpoint}/api/v1/internal/tasks/{task_id}/proof-replay",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Content-Type": "application/json",
            "X-APKScanner-Proof-Token": token,
            "X-APKScanner-Request": "console",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=None) as response:  # noqa: S310
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"proof replay rejected ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise SystemExit(f"proof replay service unavailable: {exc.reason}") from exc
    try:
        receipt = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SystemExit("proof replay service returned an invalid receipt") from exc
    if not isinstance(receipt, dict) or not isinstance(
        receipt.get("receipt_signature"),
        str,
    ):
        raise SystemExit("proof replay service returned an unsigned receipt")
    receipt_path = workspace / ".apkscanner-proof-receipts.jsonl"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(receipt_path, flags, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(receipt, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise SystemExit(f"could not persist the platform proof receipt: {exc}") from exc
    print(body)


if __name__ == "__main__":
    main()
