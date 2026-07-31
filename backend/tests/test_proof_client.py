from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import Request

from apkscanner import proof_client


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @staticmethod
    def read() -> bytes:
        return b'{"receipt_signature":"signed"}'


def test_proof_client_calls_the_complete_task_endpoint(
    tmp_path: Path,
    monkeypatch,
) -> None:  # noqa: ANN001
    endpoint = (
        "http://apkscanner-host:54321/api/v1/internal/tasks/task-1/proof-replay"
    )
    source = tmp_path / "proof-replay.json"
    source.write_text(json.dumps({"hypothesis_id": "hypothesis-1"}), encoding="utf-8")
    captured: list[Request] = []

    def fake_urlopen(request: Request, *, timeout):  # noqa: ANN001, ANN202
        captured.append(request)
        assert timeout is None
        return _Response()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APKSCANNER_PROOF_TASK_ID", "task-1")
    monkeypatch.setenv("APKSCANNER_PROOF_REPLAY_URL", endpoint)
    monkeypatch.setenv("APKSCANNER_PROOF_TOKEN", "proof-token")
    monkeypatch.setattr(proof_client, "urlopen", fake_urlopen)
    monkeypatch.setattr(sys, "argv", ["apkscanner-proof", source.name])

    proof_client.main()

    assert len(captured) == 1
    assert captured[0].full_url == endpoint
    assert captured[0].get_header("X-apkscanner-proof-token") == "proof-token"
    receipt = tmp_path / ".apkscanner-proof-receipts.jsonl"
    assert json.loads(receipt.read_text(encoding="utf-8")) == {
        "receipt_signature": "signed"
    }
